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
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/mdlayher/netlink"
)

// BatchState describes the lifecycle state of a Batch.
type BatchState string

const (
	// BatchOpen accepts object operations and has not sent a netlink batch.
	BatchOpen BatchState = "open"
	// BatchCommitting is the short state in which the batch is sending and
	// receiving ACKs. Conn.mu is held throughout this state.
	BatchCommitting BatchState = "committing"
	// BatchCommitted means the kernel accepted the whole batch and local IDs
	// have been published.
	BatchCommitted BatchState = "committed"
	// BatchFailed means submission failed and local optimistic state was
	// rolled back. Commit must not be called again.
	BatchFailed BatchState = "failed"
	// BatchCanceled means the caller discarded the batch and its resources.
	BatchCanceled BatchState = "canceled"
)

var (
	// ErrBatchActive is returned when Begin is called while another explicit
	// batch is open.
	ErrBatchActive = errors.New("nftables: batch already active")
	// ErrNoActiveBatch is returned by Conn.Commit/Rollback without Begin.
	ErrNoActiveBatch = errors.New("nftables: no active batch")
	// ErrNestedCommit is returned when the legacy Flush path is used while an
	// explicit Batch owns submission, or when Commit is called more than once.
	ErrNestedCommit = errors.New("nftables: nested or duplicate batch commit")
	// ErrDuplicateCommit is an alternate name for ErrNestedCommit.
	ErrDuplicateCommit = ErrNestedCommit
	// ErrBatchAlreadyCommitted is an alternate name for ErrNestedCommit.
	ErrBatchAlreadyCommitted = ErrNestedCommit
	// ErrBatchState is returned when a batch operation is invalid in its
	// current state.
	ErrBatchState = errors.New("nftables: invalid batch state")
	// ErrBatchCanceled is wrapped when Commit is called after Cancel.
	ErrBatchCanceled = errors.New("nftables: batch canceled")
	// ErrBatchFailed is wrapped when Commit is called after a failed commit.
	ErrBatchFailed = errors.New("nftables: batch commit failed")
)

// Batch is an explicitly bounded group of nftables operations.
//
// Object methods are promoted from the embedded Conn, so callers can write
// b.AddTable(...), b.AddChain(...) and b.AddRule(...) between Begin and Commit.
// All submission goes through Commit; Flush on the originating Conn is rejected
// while the batch is open.
type Batch struct {
	*Conn

	id    uint64
	genID uint32
	state BatchState
	err   error

	ackErrors []*BatchACKError

	handle *netlink.Conn
	closer netlinkCloser
	// built retains the marshalled batch only until submission finishes or
	// Cancel releases it.
	built []netlink.Message
}

// ID returns the connection-local batch identifier. It is useful for mapping
// ACK errors to the batch that produced them.
func (b *Batch) ID() uint64 { return b.id }

// State returns the current batch lifecycle state.
func (b *Batch) State() BatchState {
	b.Conn.mu.Lock()
	defer b.Conn.mu.Unlock()
	return b.state
}

// Err returns the terminal commit error, if any.
func (b *Batch) Err() error {
	b.Conn.mu.Lock()
	defer b.Conn.mu.Unlock()
	return b.err
}

// ACKErrors returns the ACK errors collected from the most recent commit,
// sorted in the original operation order.
func (b *Batch) ACKErrors() []*BatchACKError {
	b.Conn.mu.Lock()
	defer b.Conn.mu.Unlock()
	return append([]*BatchACKError(nil), b.ackErrors...)
}

// Begin starts an explicit batch. Only one explicit batch may be open on a
// Conn at a time; the returned error wraps ErrBatchActive for nested begins.
//
// The batch acquires its netlink handle immediately when the Conn is not
// lasting. Commit or Cancel releases that handle.
func (cc *Conn) Begin() (*Batch, error) {
	if owner := cc.commitOwner.Load(); owner != 0 && owner == currentGoroutineIDUID447() {
		return nil, fmt.Errorf("%w: cannot begin while commit is in progress", ErrNestedCommit)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.activeBatch != nil && cc.activeBatch.state == BatchOpen {
		return nil, fmt.Errorf("%w: batch %d", ErrBatchActive, cc.activeBatch.id)
	}

	cc.nextBatchID++
	b := &Batch{
		Conn:  cc,
		id:    cc.nextBatchID,
		state: BatchOpen,
	}
	cc.activeBatch = b

	if err := b.ensureHandleLocked(); err != nil {
		cc.activeBatch = nil
		b.state = BatchFailed
		b.err = err
		return nil, err
	}

	return b, nil
}

// BeginBatch is an alias for Begin for callers who prefer the explicit name.
func (cc *Conn) BeginBatch() (*Batch, error) { return cc.Begin() }

// Commit sends the batch and publishes kernel identities only after every ACK
// has been successfully processed. A repeated or concurrent Commit returns an
// error wrapping ErrNestedCommit and sends no additional netlink messages.
func (b *Batch) Commit() error {
	cc := b.Conn
	if owner := cc.commitOwner.Load(); owner != 0 && owner == currentGoroutineIDUID447() {
		return fmt.Errorf("%w: batch %d is committing", ErrNestedCommit, b.id)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if b.state != BatchOpen {
		switch b.state {
		case BatchCanceled:
			return fmt.Errorf("%w: %w: batch %d", ErrNestedCommit, ErrBatchCanceled, b.id)
		case BatchFailed:
			return fmt.Errorf("%w: %w: batch %d", ErrNestedCommit, ErrBatchFailed, b.id)
		default:
			return fmt.Errorf("%w: batch %d already %s", ErrNestedCommit, b.id, b.state)
		}
	}
	if cc.activeBatch != b {
		return fmt.Errorf("%w: batch %d is not the active batch", ErrBatchState, b.id)
	}

	b.state = BatchCommitting
	return cc.commitBatchLocked(b)
}

// Flush is the batch-specific name for Commit. It prevents the promoted
// Conn.Flush method from bypassing batch state.
func (b *Batch) Flush() error { return b.Commit() }

// Submit is an alias for Commit.
func (b *Batch) Submit() error { return b.Commit() }

// Do is an alias for Commit.
func (b *Batch) Do() error { return b.Commit() }

// Cancel discards an open or failed batch, rolls back local optimistic state,
// and releases the batch handle and marshalled buffers. Cancelling a terminal
// batch is idempotent and only releases retained resources.
func (b *Batch) Cancel() error {
	cc := b.Conn
	if owner := cc.commitOwner.Load(); owner != 0 && owner == currentGoroutineIDUID447() {
		return fmt.Errorf("%w: cannot cancel batch %d while commit is in progress", ErrBatchState, b.id)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.activeBatch == b {
		cc.rollbackChangesLocked()
		cc.activeBatch = nil
	}

	b.releaseHandleLocked()
	b.releaseBuffersLocked()
	if b.state == BatchOpen || b.state == BatchCommitting {
		b.state = BatchCanceled
	}
	return nil
}

// Rollback is an alias for Cancel.
func (b *Batch) Rollback() error { return b.Cancel() }

// Close makes Batch satisfy io.Closer and is an alias for Cancel.
func (b *Batch) Close() error { return b.Cancel() }

// Commit commits the currently active explicit batch.
func (cc *Conn) Commit() error {
	if owner := cc.commitOwner.Load(); owner != 0 && owner == currentGoroutineIDUID447() {
		return fmt.Errorf("%w: commit is already in progress", ErrNestedCommit)
	}
	cc.mu.Lock()
	b := cc.activeBatch
	cc.mu.Unlock()
	if b == nil {
		return ErrNoActiveBatch
	}
	return b.Commit()
}

// Rollback cancels the currently active explicit batch.
func (cc *Conn) Rollback() error {
	if owner := cc.commitOwner.Load(); owner != 0 && owner == currentGoroutineIDUID447() {
		return fmt.Errorf("%w: rollback while commit is in progress", ErrBatchState)
	}
	cc.mu.Lock()
	b := cc.activeBatch
	cc.mu.Unlock()
	if b == nil {
		return ErrNoActiveBatch
	}
	return b.Cancel()
}

// CancelBatch cancels the currently active explicit batch.
func (cc *Conn) CancelBatch() error { return cc.Rollback() }

// Cancel is an alias for CancelBatch.
func (cc *Conn) Cancel() error { return cc.Rollback() }

// BeginWithGenID starts an explicit batch whose commit includes genID.
func (cc *Conn) BeginWithGenID(genID uint32) (*Batch, error) {
	b, err := cc.Begin()
	if err != nil {
		return nil, err
	}
	b.genID = genID
	return b, nil
}

// Tx is the conventional transaction alias for Batch.
type Tx = Batch

// Transaction is an alternate descriptive name for Batch.
type Transaction = Batch

// BeginTx is an alias for Begin.
func (cc *Conn) BeginTx() (*Tx, error) { return cc.Begin() }

// BeginTransaction is an alias for Begin.
func (cc *Conn) BeginTransaction() (*Transaction, error) { return cc.Begin() }

// Batch runs fn inside a Begin/Commit block. If fn returns an error or Commit
// fails, the batch is cancelled/rolled back.
func (cc *Conn) Batch(fn func(*Batch) error) error {
	b, err := cc.Begin()
	if err != nil {
		return err
	}
	if err := fn(b); err != nil {
		_ = b.Cancel()
		return err
	}
	return b.Commit()
}

func (b *Batch) ensureHandleLocked() error {
	if b.handle != nil {
		return nil
	}
	handle, closer, err := b.Conn.netlinkConnUnderLock()
	if err != nil {
		return err
	}
	b.handle = handle
	b.closer = closer
	return nil
}

func (b *Batch) releaseHandleLocked() {
	if b.closer != nil {
		_ = b.closer()
		b.closer = nil
	}
	b.handle = nil
}

func (b *Batch) releaseBuffersLocked() {
	b.built = nil
}

// BatchACKError identifies the concrete operation and batch behind a netlink
// ACK error.
type BatchACKError struct {
	// BatchID is the local batch identifier.
	BatchID uint64
	// Index is the zero-based operation index among buffered object messages,
	// excluding batch begin/end. -1 means the ACK could not be mapped.
	Index int
	// Sequence is the netlink sequence number from the error message.
	Sequence uint32
	// MessageType is the nftables message type, when known.
	MessageType string
	// Err contains the formatted receive error and the netlink cause chain.
	Err error
}

func (e *BatchACKError) Error() string {
	if e == nil || e.Err == nil {
		return "nftables: batch ACK error"
	}
	return e.Err.Error()
}

func (e *BatchACKError) Unwrap() error { return e.Err }

// BatchError is the historical name used for a mapped ACK failure.
type BatchError = BatchACKError

// ACKError and AckError are alternate spellings used by callers and tests.
type ACKError = BatchACKError
type AckError = BatchACKError

// CommitError contains every ACK error collected during a batch commit.
// Errors and ACKs are sorted in original buffered-operation order.
type CommitError struct {
	BatchID uint64
	Errors  []error
	ACKs    []*BatchACKError
}

// BatchCommitError is an alias for CommitError.
type BatchCommitError = CommitError

func (e *CommitError) Error() string {
	if e == nil {
		return "nftables: batch commit failed"
	}
	if len(e.Errors) == 0 {
		return fmt.Sprintf("nftables: batch %d commit failed", e.BatchID)
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}
	var out strings.Builder
	for i, err := range e.Errors {
		if i > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(err.Error())
	}
	return out.String()
}

// Unwrap enables errors.Is/As across all ordered ACK failures.
func (e *CommitError) Unwrap() []error { return e.Errors }

// commitBatchLocked is the only implementation that sends a buffered batch.
// The caller must hold cc.mu.
func (cc *Conn) commitBatchLocked(b *Batch) (retErr error) {
	if b == nil {
		b = cc.activeBatch
	}
	if b == nil {
		return ErrNoActiveBatch
	}

	cc.commitOwner.Store(currentGoroutineIDUID447())
	defer cc.commitOwner.Store(0)

	defer func() {
		cc.messages = nil
		cc.allocatedIDs = 0
		cc.err = nil
		b.releaseBuffersLocked()

		if retErr != nil {
			b.err = retErr
			b.state = BatchFailed
			cc.rollbackChangesLocked()
		} else {
			b.state = BatchCommitted
			cc.commitLocalChangesLocked()
		}

		b.releaseHandleLocked()
		if cc.activeBatch == b {
			cc.activeBatch = nil
		}
	}()

	if cc.err != nil {
		return cc.err
	}
	if len(cc.messages) == 0 {
		// An empty batch is a successful no-op. The deferred cleanup resets
		// sticky marshal state exactly like the historical Flush path.
		return nil
	}

	if err := b.ensureHandleLocked(); err != nil {
		return err
	}
	conn := b.handle

	if err := cc.enlargeWriteBuffer(conn); err != nil {
		return err
	}
	if err := cc.enlargeReadBuffer(conn); err != nil {
		return err
	}

	built, err := batch(cc.messages, b.genID)
	if err != nil {
		return err
	}
	b.built = built

	sentMsgs, err := conn.SendMessages(built)
	if err != nil {
		return fmt.Errorf("SendMessages: %w", err)
	}

	seqToMsgMap := cc.getSeqToMsgMap(sentMsgs, b.id)
	var ackErrs []*BatchACKError

	for reply, recvErr := range cc.receiveSeq(conn) {
		if recvErr != nil {
			if mapped := cc.handleReceiveError(seqToMsgMap, b.id, recvErr); mapped != nil {
				if ack, ok := mapped.(*BatchACKError); ok {
					ackErrs = append(ackErrs, ack)
				} else {
					ackErrs = append(ackErrs, &BatchACKError{BatchID: b.id, Index: -1, Err: mapped})
				}
			}
			// Continue receiving further messages even after an error so the
			// socket is drained and all ACK failures are collected.
			continue
		}

		if echoErr := cc.handleEchoReply(seqToMsgMap, reply); echoErr != nil {
			info := findReplyInfo(seqToMsgMap, reply.Header.Sequence)
			ack := &BatchACKError{
				BatchID: b.id,
				Index:   -1,
				Err:     fmt.Errorf("receive: %w", echoErr),
			}
			if info != nil {
				ack.Index = info.index
				ack.Sequence = reply.Header.Sequence
				if msgType, parseErr := parseNftMsgType(info.message.Header.Type); parseErr == nil {
					ack.MessageType = msgType.String()
				}
			}
			ackErrs = append(ackErrs, ack)
		}
	}

	if len(ackErrs) > 0 {
		sort.SliceStable(ackErrs, func(i, j int) bool {
			return ackErrs[i].Index < ackErrs[j].Index
		})
		errs := make([]error, len(ackErrs))
		for i, ack := range ackErrs {
			errs[i] = ack
		}
		b.ackErrors = ackErrs
		return &CommitError{BatchID: b.id, Errors: errs, ACKs: ackErrs}
	}

	// Kernel identities are published only after all ACKs indicate success.
	for i := range cc.messages {
		msg := &cc.messages[i]
		if msg.rule != nil && msg.echoHandle != 0 {
			msg.rule.Handle = msg.echoHandle
			msg.rule.ID = 0
		}
	}

	return nil
}

func findReplyInfo(m map[uint32]sentMessageInfo, seq uint32) *sentMessageInfo {
	if info, ok := m[seq]; ok {
		return &info
	}
	return nil
}

// currentGoroutineIDUID447 parses the goroutine ID from a stack header. It is
// used only to reject same-goroutine re-entrant batch submission; ordinary
// cross-goroutine serialization continues through Conn.mu.
func currentGoroutineIDUID447() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	text := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	if space := strings.IndexByte(text, ' '); space >= 0 {
		text = text[:space]
	}
	id, _ := strconv.ParseInt(text, 10, 64)
	return id
}
