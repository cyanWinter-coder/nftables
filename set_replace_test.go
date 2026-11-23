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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

// failOnSendDial returns a nltest.Func that fails the test when any netlink
// message is sent, used to prove that validation and limit errors are
// detected before anything reaches the kernel.
func failOnSendDial(t *testing.T) nltest.Func {
	t.Helper()
	return func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 {
			t.Errorf("unexpected netlink send of %d message(s)", len(req))
		}
		return nil, nil
	}
}

func TestSetReplaceElementsValidation(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	plainSet := &Set{Name: "s", ID: 1, Table: tbl, KeyType: TypeIPAddr}
	intervalSet := &Set{Name: "si", ID: 2, Table: tbl, KeyType: TypeIPAddr, Interval: true}
	timeoutSet := &Set{Name: "st", ID: 3, Table: tbl, KeyType: TypeIPAddr, HasTimeout: true}
	mapSet := &Set{Name: "m", ID: 4, Table: tbl, KeyType: TypeIPAddr, DataType: TypeIPAddr, IsMap: true}

	tests := []struct {
		name    string
		set     *Set
		elem    SetElement
		wantErr string
	}{
		{
			name:    "interval end flag on non-interval set",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, IntervalEnd: true},
			wantErr: "interval end flag",
		},
		{
			name:    "key end on non-interval set",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, KeyEnd: []byte{10, 0, 0, 5}},
			wantErr: "key end set on non-interval set",
		},
		{
			name:    "open interval on non-interval set",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, IntervalOpen: true},
			wantErr: "open interval flag",
		},
		{
			name:    "end marker and range at once",
			set:     intervalSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, KeyEnd: []byte{10, 0, 0, 5}, IntervalEnd: true},
			wantErr: "both an interval end marker and a range",
		},
		{
			name:    "negative timeout",
			set:     timeoutSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, Timeout: -time.Second},
			wantErr: "negative element timeout",
		},
		{
			name:    "timeout on set without timeout support",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, Timeout: time.Second},
			wantErr: "without timeout support",
		},
		{
			name:    "verdict and value data",
			set:     mapSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, Val: []byte{1, 2, 3, 4}, VerdictData: &expr.Verdict{Kind: expr.VerdictAccept}},
			wantErr: "both verdict and value data",
		},
		{
			name:    "verdict on non-map set",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, VerdictData: &expr.Verdict{Kind: expr.VerdictAccept}},
			wantErr: "verdict data on non-map set",
		},
		{
			name:    "value on non-map set",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, Val: []byte{1, 2, 3, 4}},
			wantErr: "value data on non-map set",
		},
		{
			name:    "key length mismatch",
			set:     plainSet,
			elem:    SetElement{Key: []byte{10, 0, 1}},
			wantErr: "key length 3 does not match",
		},
		{
			name:    "key end length mismatch",
			set:     intervalSet,
			elem:    SetElement{Key: []byte{10, 0, 0, 1}, KeyEnd: []byte{10, 0, 5}},
			wantErr: "key end length 3 does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(WithTestDial(failOnSendDial(t)))
			if err != nil {
				t.Fatal(err)
			}
			err = c.SetReplaceElements(tt.set, []SetElement{tt.elem}, nil)
			if err == nil {
				t.Fatalf("SetReplaceElements() succeeded, want error containing %q", tt.wantErr)
			}
			if got := err.Error(); !bytes.Contains([]byte(got), []byte(tt.wantErr)) {
				t.Fatalf("SetReplaceElements() error %q, want substring %q", got, tt.wantErr)
			}
			// The error must be reported with the element position.
			if got := err.Error(); !bytes.Contains([]byte(got), []byte("element 0")) {
				t.Fatalf("SetReplaceElements() error %q, want element position", got)
			}
		})
	}
}

func TestMergeIntervalElements(t *testing.T) {
	t.Parallel()

	ip := func(a, b, c, d byte) []byte { return []byte{a, b, c, d} }

	t.Run("overlapping ranges with identical metadata merge", func(t *testing.T) {
		got, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20)},
			{Key: ip(10, 0, 0, 15), KeyEnd: ip(10, 0, 0, 30)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d elements, want 1 merged", len(got))
		}
		if !bytes.Equal(got[0].Key, ip(10, 0, 0, 10)) || !bytes.Equal(got[0].KeyEnd, ip(10, 0, 0, 30)) {
			t.Fatalf("merged range [%v, %v), want [%v, %v)", got[0].Key, got[0].KeyEnd, ip(10, 0, 0, 10), ip(10, 0, 0, 30))
		}
	})

	t.Run("duplicate ranges merge", func(t *testing.T) {
		got, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20)},
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d elements, want 1 merged", len(got))
		}
	})

	t.Run("contained range merges into outer", func(t *testing.T) {
		got, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 15), KeyEnd: ip(10, 0, 0, 18)},
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !bytes.Equal(got[0].Key, ip(10, 0, 0, 10)) || !bytes.Equal(got[0].KeyEnd, ip(10, 0, 0, 20)) {
			t.Fatalf("got %+v, want single range [10.0.0.10, 10.0.0.20)", got)
		}
	})

	t.Run("overlapping ranges with conflicting values are rejected", func(t *testing.T) {
		_, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20), Val: []byte{1}},
			{Key: ip(10, 0, 0, 15), KeyEnd: ip(10, 0, 0, 30), Val: []byte{2}},
		})
		if err == nil {
			t.Fatal("conflicting overlapping ranges merged without error")
		}
		// The error must name the conflicting positions in the input.
		if got := err.Error(); !bytes.Contains([]byte(got), []byte("elements 0 and 1")) {
			t.Fatalf("error %q, want conflicting positions", got)
		}
	})

	t.Run("overlapping ranges with conflicting timeouts are rejected", func(t *testing.T) {
		_, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20), Timeout: time.Second},
			{Key: ip(10, 0, 0, 15), KeyEnd: ip(10, 0, 0, 30), Timeout: time.Minute},
		})
		if err == nil {
			t.Fatal("conflicting overlapping ranges merged without error")
		}
	})

	t.Run("disjoint ranges stay separate and sorted", func(t *testing.T) {
		got, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 30), KeyEnd: ip(10, 0, 0, 40)},
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d elements, want 2", len(got))
		}
		if !bytes.Equal(got[0].Key, ip(10, 0, 0, 10)) || !bytes.Equal(got[1].Key, ip(10, 0, 0, 30)) {
			t.Fatalf("ranges not sorted by start key: %+v", got)
		}
	})

	t.Run("point elements pass through ahead of merged ranges", func(t *testing.T) {
		got, err := mergeIntervalElements([]SetElement{
			{Key: ip(10, 0, 0, 1)},
			{Key: ip(10, 0, 0, 10), KeyEnd: ip(10, 0, 0, 20)},
			{Key: ip(10, 0, 0, 15), KeyEnd: ip(10, 0, 0, 30)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d elements, want 2", len(got))
		}
		if !bytes.Equal(got[0].Key, ip(10, 0, 0, 1)) || len(got[0].KeyEnd) != 0 {
			t.Fatalf("point element not preserved: %+v", got[0])
		}
		if !bytes.Equal(got[1].Key, ip(10, 0, 0, 10)) || !bytes.Equal(got[1].KeyEnd, ip(10, 0, 0, 30)) {
			t.Fatalf("merged range wrong: %+v", got[1])
		}
	})
}

func TestSetReplaceElementsLimits(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	plainSet := &Set{Name: "s", ID: 1, Table: tbl, KeyType: TypeIPAddr}
	intervalSet := &Set{Name: "si", ID: 2, Table: tbl, KeyType: TypeIPAddr, Interval: true}
	cfg := &SetReplaceConfig{MaxElements: 2, MaxIntervalElements: 1}

	t.Run("too many plain elements fails before sending", func(t *testing.T) {
		c, err := New(WithTestDial(failOnSendDial(t)))
		if err != nil {
			t.Fatal(err)
		}
		err = c.SetReplaceElements(plainSet, []SetElement{
			{Key: []byte{10, 0, 0, 1}},
			{Key: []byte{10, 0, 0, 2}},
			{Key: []byte{10, 0, 0, 3}},
		}, cfg)
		if err == nil {
			t.Fatal("over-limit replace succeeded")
		}
		if got := err.Error(); !bytes.Contains([]byte(got), []byte("too many set elements: 3 exceeds configured limit 2")) {
			t.Fatalf("unexpected error: %q", got)
		}
	})

	t.Run("too many interval elements fails before sending", func(t *testing.T) {
		c, err := New(WithTestDial(failOnSendDial(t)))
		if err != nil {
			t.Fatal(err)
		}
		err = c.SetReplaceElements(intervalSet, []SetElement{
			{Key: []byte{10, 0, 0, 1}, KeyEnd: []byte{10, 0, 0, 5}},
			{Key: []byte{10, 0, 0, 9}, KeyEnd: []byte{10, 0, 0, 12}},
		}, cfg)
		if err == nil {
			t.Fatal("over-limit replace succeeded")
		}
		if got := err.Error(); !bytes.Contains([]byte(got), []byte("too many interval set elements: 2 exceeds configured limit 1")) {
			t.Fatalf("unexpected error: %q", got)
		}
	})

	t.Run("interval limit is counted after merging", func(t *testing.T) {
		c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			return nil, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		// Two overlapping ranges merge into one, fitting the limit of 1.
		err = c.SetReplaceElements(intervalSet, []SetElement{
			{Key: []byte{10, 0, 0, 1}, KeyEnd: []byte{10, 0, 0, 5}},
			{Key: []byte{10, 0, 0, 3}, KeyEnd: []byte{10, 0, 0, 9}},
		}, cfg)
		if err != nil {
			t.Fatalf("SetReplaceElements() failed: %v", err)
		}
		if got := c.MirroredSetElements(intervalSet); len(got) != 1 {
			t.Fatalf("mirror holds %d elements, want 1 merged", len(got))
		}
	})

	t.Run("plain and interval elements are limited separately", func(t *testing.T) {
		c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			return nil, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		// Two plain elements plus one interval element: each class within
		// its own limit, so the replace must succeed.
		err = c.SetReplaceElements(intervalSet, []SetElement{
			{Key: []byte{10, 0, 0, 1}},
			{Key: []byte{10, 0, 0, 2}},
			{Key: []byte{10, 0, 0, 9}, KeyEnd: []byte{10, 0, 0, 12}},
		}, cfg)
		if err != nil {
			t.Fatalf("SetReplaceElements() failed: %v", err)
		}
	})
}

func TestSetReplaceElements(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	set := &Set{Name: "si", ID: 7, Table: tbl, KeyType: TypeIPAddr, Interval: true}

	var batches [][]netlink.Message
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 {
			batches = append(batches, req)
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	vals := []SetElement{
		{Key: []byte{10, 0, 0, 1}},
		{Key: []byte{10, 0, 0, 10}, KeyEnd: []byte{10, 0, 0, 20}},
		{Key: []byte{10, 0, 0, 15}, KeyEnd: []byte{10, 0, 0, 30}},
	}
	if err := c.SetReplaceElements(set, vals, nil); err != nil {
		t.Fatalf("SetReplaceElements() failed: %v", err)
	}

	// The replace must be sent immediately as its own transaction: batch
	// begin, delete-all, one element-list message, batch end.
	if len(batches) != 1 {
		t.Fatalf("got %d netlink batches, want 1", len(batches))
	}
	batch := batches[0]
	if len(batch) != 4 {
		t.Fatalf("got %d messages in batch, want 4", len(batch))
	}
	if got, want := batch[1].Header.Type, nftMsgDelSetElem.HeaderType(); got != want {
		t.Fatalf("message 1 type %v, want delete-all %v", got, want)
	}
	if got, want := batch[2].Header.Type, nftMsgNewSetElem.HeaderType(); got != want {
		t.Fatalf("message 2 type %v, want new-set-elem %v", got, want)
	}

	// The mirror holds the merged contents: one point element and the merged
	// range [10.0.0.10, 10.0.0.30).
	mirror := c.MirroredSetElements(set)
	if len(mirror) != 2 {
		t.Fatalf("mirror holds %d elements, want 2", len(mirror))
	}
	if !bytes.Equal(mirror[1].Key, []byte{10, 0, 0, 10}) || !bytes.Equal(mirror[1].KeyEnd, []byte{10, 0, 0, 30}) {
		t.Fatalf("mirrored range [%v, %v), want [10.0.0.10, 10.0.0.30)", mirror[1].Key, mirror[1].KeyEnd)
	}

	// A set never replaced has no mirror.
	if got := c.MirroredSetElements(&Set{Name: "other", Table: tbl}); got != nil {
		t.Fatalf("unexpected mirror for untouched set: %+v", got)
	}
}

func TestSetReplaceElementsKernelError(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	set := &Set{Name: "s", ID: 9, Table: tbl, KeyType: TypeIPAddr}

	failNext := false
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, nil
		}
		if !failNext {
			return nil, nil
		}
		// Fail the element-list message (batch begin, delete-all, elements,
		// batch end), simulating a partial kernel failure.
		return nltest.Error(int(syscall.EEXIST), []netlink.Message{req[2]})
	}))
	if err != nil {
		t.Fatal(err)
	}

	first := []SetElement{{Key: []byte{10, 0, 0, 1}}}
	if err := c.SetReplaceElements(set, first, nil); err != nil {
		t.Fatalf("first SetReplaceElements() failed: %v", err)
	}

	failNext = true
	second := []SetElement{{Key: []byte{10, 0, 0, 2}}, {Key: []byte{10, 0, 0, 3}}}
	err = c.SetReplaceElements(set, second, nil)
	if err == nil {
		t.Fatal("second SetReplaceElements() succeeded, want kernel error")
	}

	// The error must identify the failed element positions.
	var seErr *SetElementError
	if !errors.As(err, &seErr) {
		t.Fatalf("error is %T, want *SetElementError", err)
	}
	if !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("error %v does not wrap EEXIST", err)
	}
	if len(seErr.Indices) != 2 || seErr.Indices[0] != 0 || seErr.Indices[1] != 1 {
		t.Fatalf("failed indices %v, want [0 1]", seErr.Indices)
	}
	if len(seErr.Elements) != 2 || !bytes.Equal(seErr.Elements[0].Key, []byte{10, 0, 0, 2}) {
		t.Fatalf("failed elements %+v, want the second batch", seErr.Elements)
	}

	// The local mirror must be rolled back to the first replace.
	mirror := c.MirroredSetElements(set)
	if len(mirror) != 1 || !bytes.Equal(mirror[0].Key, []byte{10, 0, 0, 1}) {
		t.Fatalf("mirror %+v, want rolled back contents of first replace", mirror)
	}

	// A subsequent good replace commits again.
	failNext = false
	if err := c.SetReplaceElements(set, second, nil); err != nil {
		t.Fatalf("third SetReplaceElements() failed: %v", err)
	}
	if got := c.MirroredSetElements(set); len(got) != 2 {
		t.Fatalf("mirror holds %d elements, want 2", len(got))
	}
}

func TestSetReplaceElementsConcurrent(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	set := &Set{Name: "s", ID: 11, Table: tbl, KeyType: TypeIPAddr}

	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	// Each replacer owns a disjoint first key byte, so any interleaving of
	// concurrent replaces would show up as a mixed-generation mirror.
	const replacers = 8
	const iterations = 20
	var wg sync.WaitGroup
	for g := 0; g < replacers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			vals := []SetElement{
				{Key: []byte{byte(g), 0, 0, 1}},
				{Key: []byte{byte(g), 0, 0, 2}},
			}
			for i := 0; i < iterations; i++ {
				if err := c.SetReplaceElements(set, vals, nil); err != nil {
					t.Errorf("SetReplaceElements() failed: %v", err)
					return
				}
			}
		}(g)
	}

	// Concurrent deletes of the same set must not interleave with the
	// replaces either.
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := c.SetDeleteElements(set, []SetElement{{Key: []byte{byte(g), 0, 0, 1}}}); err != nil {
					t.Errorf("SetDeleteElements() failed: %v", err)
					return
				}
				if err := c.Flush(); err != nil {
					t.Errorf("Flush() failed: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	mirror := c.MirroredSetElements(set)
	if len(mirror) != 2 {
		t.Fatalf("mirror holds %d elements, want 2", len(mirror))
	}
	if mirror[0].Key[0] != mirror[1].Key[0] {
		t.Fatalf("mirror mixes generations %d and %d: concurrent replaces interleaved",
			mirror[0].Key[0], mirror[1].Key[0])
	}
}

// TestSetReplaceElementsSmallBatchCompat ensures the plain buffered update
// path (SetAddElements/SetDeleteElements + Flush) is unaffected by the
// replace machinery for small batches.
func TestSetReplaceElementsSmallBatchCompat(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	set := &Set{Name: "s", ID: 13, Table: tbl, KeyType: TypeIPAddr}

	var batches int
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 {
			batches++
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.SetAddElements(set, []SetElement{{Key: []byte{10, 0, 0, 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeleteElements(set, []SetElement{{Key: []byte{10, 0, 0, 2}}}); err != nil {
		t.Fatal(err)
	}
	// Nothing is sent before Flush.
	if batches != 0 {
		t.Fatalf("%d batches sent before Flush", batches)
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("Flush() failed: %v", err)
	}
	if batches != 1 {
		t.Fatalf("%d batches sent, want 1", batches)
	}
	// Buffered updates do not populate the replace mirror.
	if got := c.MirroredSetElements(set); got != nil {
		t.Fatalf("unexpected mirror after buffered updates: %+v", got)
	}
}

// TestSetReplaceElementsMessageRanges checks that a replace split into
// multiple element-list messages maps a kernel failure back to the positions
// of the elements carried by the failed message.
func TestSetReplaceElementsMessageRanges(t *testing.T) {
	t.Parallel()

	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	set := &Set{Name: "s", ID: 15, Table: tbl, KeyType: TypeIPAddr}

	// Build enough elements to require more than one element-list message:
	// each IPv4 element encodes to well over 16 bytes, and maxElemBatchSize
	// is just under 64KiB.
	const n = 6000
	vals := make([]SetElement, n)
	for i := range vals {
		vals[i] = SetElement{Key: []byte{10, byte(i >> 16), byte(i >> 8), byte(i)}}
	}

	var sent []netlink.Message
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, nil
		}
		sent = req
		// Fail the last element-list message.
		return nltest.Error(int(syscall.EINVAL), []netlink.Message{req[len(req)-2]})
	}))
	if err != nil {
		t.Fatal(err)
	}

	err = c.SetReplaceElements(set, vals, nil)
	var seErr *SetElementError
	if !errors.As(err, &seErr) {
		t.Fatalf("error is %v (%T), want *SetElementError", err, err)
	}
	if len(seErr.Indices) == 0 || len(seErr.Indices) >= n {
		t.Fatalf("failed indices cover %d of %d elements, want a proper non-empty suffix", len(seErr.Indices), n)
	}
	// The failed positions must be a contiguous suffix of the element list.
	for i, idx := range seErr.Indices {
		if idx != seErr.Indices[0]+i {
			t.Fatalf("failed indices %v... not contiguous", seErr.Indices[:4])
		}
	}
	if seErr.Indices[len(seErr.Indices)-1] != n-1 {
		t.Fatalf("last failed index %d, want %d (last element)", seErr.Indices[len(seErr.Indices)-1], n-1)
	}
	if len(seErr.Elements) != len(seErr.Indices) {
		t.Fatalf("got %d failed elements for %d failed indices", len(seErr.Elements), len(seErr.Indices))
	}
	// Sanity check: the batch really was split into multiple element
	// messages (batch begin, delete-all, elements..., batch end).
	if len(sent) < 5 {
		t.Fatalf("batch holds %d messages, want at least 5 (split element list)", len(sent))
	}
	if got := c.MirroredSetElements(set); got != nil {
		t.Fatalf("mirror holds %d elements after failed replace, want rollback to nil", len(got))
	}
}

func ExampleConn_SetReplaceElements() {
	c, _ := New()
	tbl := &Table{Name: "filter", Family: TableFamilyIPv4}
	set := &Set{Name: "blocklist", Table: tbl, KeyType: TypeIPAddr, Interval: true}

	err := c.SetReplaceElements(set, []SetElement{
		{Key: []byte{10, 0, 0, 0}, KeyEnd: []byte{10, 0, 0, 128}},
		{Key: []byte{10, 0, 0, 64}, KeyEnd: []byte{10, 0, 1, 0}}, // overlaps, merged above
	}, nil)
	if err != nil {
		var seErr *SetElementError
		if errors.As(err, &seErr) {
			fmt.Println("failed element positions:", seErr.Indices)
		}
	}
}
