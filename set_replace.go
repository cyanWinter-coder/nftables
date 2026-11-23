// Copyright 2026 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"

	"github.com/mdlayher/netlink"
)

// setLockStripes is the number of striped per-set locks used to serialize
// whole-set operations. Striping keeps the memory footprint of a Conn
// constant regardless of how many distinct sets are managed through it.
const setLockStripes = 64

const (
	// DefaultMaxReplaceElements is the default limit on the number of
	// non-interval elements accepted by a single SetReplaceElements call.
	DefaultMaxReplaceElements = 1 << 16
	// DefaultMaxReplaceIntervalElements is the default limit on the number of
	// interval (range) elements accepted by a single SetReplaceElements call,
	// counted after overlapping intervals have been merged.
	DefaultMaxReplaceIntervalElements = 1 << 14
)

// SetReplaceConfig configures the limits enforced by Conn.SetReplaceElements.
// The limits are checked before anything is sent to the kernel, so an
// over-limit replace fails without any side effects.
type SetReplaceConfig struct {
	// MaxElements limits the number of non-interval elements accepted in a
	// single replace. Zero selects DefaultMaxReplaceElements; a negative
	// value disables the limit.
	MaxElements int
	// MaxIntervalElements limits the number of interval (range) elements
	// accepted in a single replace, counted after overlapping intervals have
	// been merged. Zero selects DefaultMaxReplaceIntervalElements; a negative
	// value disables the limit.
	MaxIntervalElements int
}

// SetElementError is returned by Conn.SetReplaceElements when the kernel
// rejects (part of) the replacement batch.
type SetElementError struct {
	// Table and Set identify the set being replaced.
	Table string
	Set   string
	// Indices holds the positions of the failed elements within the element
	// list as it was sent to the kernel, that is, after interval merging.
	// Indices is nil when the failure cannot be attributed to individual
	// elements, for example when the delete-all message of the replace was
	// rejected.
	Indices []int
	// Elements holds a copy of the failed elements, in the same order as
	// Indices.
	Elements []SetElement
	// Err is the underlying error reported by the kernel.
	Err error
}

func (e *SetElementError) Error() string {
	if len(e.Indices) == 0 {
		return fmt.Sprintf("replacing elements of set %s/%s: %v", e.Table, e.Set, e.Err)
	}
	return fmt.Sprintf("replacing elements of set %s/%s: %d element(s) failed at positions %v: %v",
		e.Table, e.Set, len(e.Indices), e.Indices, e.Err)
}

func (e *SetElementError) Unwrap() error { return e.Err }

// setKey returns the identity of a set, used for per-set locking and for the
// local mirror of set contents.
func setKey(s *Set) string {
	return fmt.Sprintf("%d\x00%s\x00%s", s.Table.Family, s.Table.Name, s.Name)
}

// lockSet acquires the striped per-set lock for s and returns the unlock
// function. It must be acquired before cc.mu, never the other way round.
func (cc *Conn) lockSet(s *Set) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(setKey(s)))
	mu := &cc.setLocks[h.Sum32()%setLockStripes]
	mu.Lock()
	return mu.Unlock
}

// SetReplaceElements atomically replaces the entire contents of the named set
// s with vals. Unlike SetAddElements, the replacement is sent to the kernel
// immediately as a single transaction (a delete-all message followed by the
// new elements, split into batches bounded by maxElemBatchSize), so the
// kernel either applies the whole replacement or none of it. Commands
// buffered for a later Flush are not part of the transaction and stay
// pending.
//
// Before anything is sent, the elements are validated against the set
// definition (flags, timeouts and element types), overlapping interval
// elements are merged, and the limits of cfg (defaults apply when cfg is nil)
// are enforced. Any violation fails the call without side effects.
//
// Replaces and deletes of the same set are serialized against each other, so
// a concurrent SetDeleteElements cannot interleave with the replacement.
//
// On success, the Conn keeps a local mirror of the committed contents (see
// MirroredSetElements). If the kernel rejects the batch, the mirror is rolled
// back to the last successfully committed contents and the returned error is
// a *SetElementError reporting the positions of the failed elements.
func (cc *Conn) SetReplaceElements(s *Set, vals []SetElement, cfg *SetReplaceConfig) error {
	if s.Anonymous {
		return errors.New("anonymous sets cannot be updated")
	}
	if s.Table == nil {
		return errors.New("set must be associated with a table")
	}
	for i := range vals {
		if err := validateSetElement(s, &vals[i]); err != nil {
			return fmt.Errorf("invalid set element %d: %w", i, err)
		}
	}

	effective := vals
	if s.Interval {
		merged, err := mergeIntervalElements(vals)
		if err != nil {
			return err
		}
		effective = merged
	}

	if err := checkReplaceLimits(effective, cfg); err != nil {
		return err
	}

	// Serialize against concurrent replaces and deletes of the same set for
	// the whole validate-send-commit section.
	unlock := cc.lockSet(s)
	defer unlock()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	msgs := make([]netlinkMessage, 0, 2)
	msgs = append(msgs, cc.delAllSetElemsMessage(s))
	elemMsgs, ranges, err := cc.elemListMessages(s, effective, nftMsgNewSetElem)
	if err != nil {
		return err
	}
	msgs = append(msgs, elemMsgs...)

	conn, closer, err := cc.netlinkConnUnderLock()
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	// The enlarge*Buffer helpers operate on cc.messages; temporarily lend
	// them our messages so the socket buffers fit this batch. Buffered user
	// commands are restored afterwards and stay pending for a later Flush.
	saved := cc.messages
	cc.messages = msgs
	err = cc.enlargeWriteBuffer(conn)
	if err == nil {
		err = cc.enlargeReadBuffer(conn)
	}
	cc.messages = saved
	if err != nil {
		return err
	}

	failedMsg, err := cc.sendMessagesLocked(conn, msgs)
	if err != nil {
		// The local mirror is left untouched, effectively rolling it back to
		// the last successfully committed contents.
		repErr := &SetElementError{Table: s.Table.Name, Set: s.Name, Err: err}
		if failedMsg > 0 && failedMsg-1 < len(ranges) {
			start, end := ranges[failedMsg-1][0], ranges[failedMsg-1][1]
			repErr.Indices = make([]int, 0, end-start)
			for i := start; i < end; i++ {
				repErr.Indices = append(repErr.Indices, i)
			}
			repErr.Elements = slices.Clone(effective[start:end])
		}
		return repErr
	}

	cc.mirrorsMu.Lock()
	if cc.mirrors == nil {
		cc.mirrors = make(map[string][]SetElement)
	}
	cc.mirrors[setKey(s)] = slices.Clone(effective)
	cc.mirrorsMu.Unlock()
	return nil
}

// MirroredSetElements returns a copy of the local mirror of the contents of
// s as committed by the last successful SetReplaceElements call, or nil if
// the set has never been replaced through this Conn.
func (cc *Conn) MirroredSetElements(s *Set) []SetElement {
	cc.mirrorsMu.RLock()
	defer cc.mirrorsMu.RUnlock()
	return slices.Clone(cc.mirrors[setKey(s)])
}

// sendMessagesLocked sends msgs as a single netlink batch and collects the
// replies. It returns the index of the first failed message within msgs, or
// -1 when the failure cannot be attributed to a specific message. cc.mu must
// be held.
func (cc *Conn) sendMessagesLocked(conn *netlink.Conn, msgs []netlinkMessage) (int, error) {
	batchMsgs, err := batch(msgs, 0)
	if err != nil {
		return -1, err
	}
	sent, err := conn.SendMessages(batchMsgs)
	if err != nil {
		return -1, fmt.Errorf("SendMessages: %w", err)
	}

	seqToIdx := make(map[uint32]int, len(msgs))
	for i, msg := range sent {
		if i == 0 || i == len(sent)-1 {
			// Skip batch begin and end messages.
			continue
		}
		seqToIdx[msg.Header.Sequence] = i - 1
	}

	failed := -1
	var firstErr error
	for _, rerr := range cc.receiveSeq(conn) {
		if rerr == nil || firstErr != nil {
			continue
		}
		firstErr = rerr
		var opErr *netlink.OpError
		if errors.As(rerr, &opErr) {
			if idx, ok := seqToIdx[opErr.Sequence]; ok {
				failed = idx
			}
		}
	}
	if firstErr != nil {
		return failed, firstErr
	}
	return -1, nil
}

// validateSetElement checks a single element for conflicts with the set
// definition: interval flags on non-interval sets (and vice versa), timeouts
// on sets without timeout support, and conflicting element types (value vs.
// verdict data, map data on plain sets, key length mismatches).
func validateSetElement(s *Set, e *SetElement) error {
	if !s.Interval {
		if e.IntervalEnd {
			return errors.New("interval end flag set on non-interval set")
		}
		if len(e.KeyEnd) > 0 {
			return errors.New("key end set on non-interval set")
		}
		if e.IntervalOpen {
			return errors.New("open interval flag set on non-interval set")
		}
	}
	if e.IntervalEnd && len(e.KeyEnd) > 0 {
		return errors.New("element is both an interval end marker and a range")
	}
	if e.Timeout < 0 {
		return errors.New("negative element timeout")
	}
	if e.Timeout != 0 && !s.HasTimeout {
		return errors.New("element timeout set on set without timeout support")
	}
	if e.VerdictData != nil && len(e.Val) > 0 {
		return errors.New("element has both verdict and value data")
	}
	if e.VerdictData != nil && !s.IsMap {
		return errors.New("verdict data on non-map set")
	}
	if len(e.Val) > 0 && !s.IsMap {
		return errors.New("value data on non-map set")
	}
	if n := int(s.KeyType.Bytes); n > 0 {
		if len(e.Key) != n {
			return fmt.Errorf("key length %d does not match set key type length %d", len(e.Key), n)
		}
		if len(e.KeyEnd) > 0 && len(e.KeyEnd) != n {
			return fmt.Errorf("key end length %d does not match set key type length %d", len(e.KeyEnd), n)
		}
	}
	return nil
}

// mergeIntervalElements merges overlapping interval (range) elements that
// carry identical metadata. Overlapping ranges with conflicting flags,
// timeouts, values or verdicts are rejected with an error naming the
// conflicting positions in vals. Non-range elements (plain keys and interval
// end markers) pass through unmodified, ahead of the merged ranges, which are
// sorted by start key.
func mergeIntervalElements(vals []SetElement) ([]SetElement, error) {
	type indexedRange struct {
		elem SetElement
		pos  int
	}
	var points []SetElement
	var ranges []indexedRange
	for i, v := range vals {
		if len(v.KeyEnd) > 0 {
			ranges = append(ranges, indexedRange{elem: v, pos: i})
		} else {
			points = append(points, v)
		}
	}
	if len(ranges) < 2 {
		return vals, nil
	}
	slices.SortFunc(ranges, func(a, b indexedRange) int {
		if c := bytes.Compare(a.elem.Key, b.elem.Key); c != 0 {
			return c
		}
		return bytes.Compare(a.elem.KeyEnd, b.elem.KeyEnd)
	})

	merged := make([]indexedRange, 0, len(ranges))
	cur := ranges[0]
	for _, next := range ranges[1:] {
		if bytes.Compare(next.elem.Key, cur.elem.KeyEnd) > 0 {
			// Disjoint: next starts after cur ends.
			merged = append(merged, cur)
			cur = next
			continue
		}
		// Overlapping or duplicate ranges are only mergeable when all
		// per-element metadata agrees.
		if !sameElementMeta(&cur.elem, &next.elem) {
			return nil, fmt.Errorf("set elements %d and %d: overlapping intervals with conflicting metadata", cur.pos, next.pos)
		}
		if bytes.Compare(next.elem.KeyEnd, cur.elem.KeyEnd) > 0 {
			cur.elem.KeyEnd = next.elem.KeyEnd
		}
	}
	merged = append(merged, cur)

	out := make([]SetElement, 0, len(points)+len(merged))
	out = append(out, points...)
	for _, r := range merged {
		out = append(out, r.elem)
	}
	return out, nil
}

// sameElementMeta reports whether two elements carry identical metadata
// (everything except the key range itself), making them safe to merge.
func sameElementMeta(a, b *SetElement) bool {
	if a.IntervalEnd != b.IntervalEnd ||
		a.IntervalOpen != b.IntervalOpen ||
		a.Timeout != b.Timeout ||
		a.Comment != b.Comment ||
		!bytes.Equal(a.Val, b.Val) ||
		(a.Counter == nil) != (b.Counter == nil) {
		return false
	}
	if (a.VerdictData == nil) != (b.VerdictData == nil) {
		return false
	}
	if a.VerdictData != nil && *a.VerdictData != *b.VerdictData {
		return false
	}
	return true
}

// checkReplaceLimits enforces the element count limits of cfg on the
// (already merged) element list. Interval and non-interval elements are
// counted and limited separately.
func checkReplaceLimits(vals []SetElement, cfg *SetReplaceConfig) error {
	maxElements := DefaultMaxReplaceElements
	maxInterval := DefaultMaxReplaceIntervalElements
	if cfg != nil {
		if cfg.MaxElements != 0 {
			maxElements = cfg.MaxElements
		}
		if cfg.MaxIntervalElements != 0 {
			maxInterval = cfg.MaxIntervalElements
		}
	}
	var elements, intervals int
	for i := range vals {
		if len(vals[i].KeyEnd) > 0 || vals[i].IntervalEnd {
			intervals++
		} else {
			elements++
		}
	}
	if maxElements >= 0 && elements > maxElements {
		return fmt.Errorf("too many set elements: %d exceeds configured limit %d", elements, maxElements)
	}
	if maxInterval >= 0 && intervals > maxInterval {
		return fmt.Errorf("too many interval set elements: %d exceeds configured limit %d", intervals, maxInterval)
	}
	return nil
}
