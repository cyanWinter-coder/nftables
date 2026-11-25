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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func uid447OKDial(req []netlink.Message) ([]netlink.Message, error) {
	if len(req) == 0 {
		return nil, nil
	}
	return nil, nil
}

func uid447FailRuleDial(t *testing.T, errno int) nltest.Func {
	t.Helper()
	return func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, nil
		}
		for _, msg := range req {
			if msg.Header.Type == newRuleHeaderType {
				return nltest.Error(errno, []netlink.Message{msg})
			}
		}
		return nil, nil
	}
}

func TestUID447FailedCommitRollsBackTemporaryRuleIdentity(t *testing.T) {
	c, err := New(WithTestDial(uid447FailRuleDial(t, int(unix.ENOENT))))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	table := &Table{Name: "uid447_t", Family: TableFamilyIPv4}
	chain := &Chain{Name: "uid447_c", Table: table}
	rule := &Rule{Table: table, Chain: chain}

	b.AddTable(table)
	b.AddChain(chain)
	b.AddRule(rule)

	if rule.ID == 0 {
		t.Fatal("AddRule did not assign a temporary in-batch ID")
	}
	tempID := rule.ID

	err = b.Commit()
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("Commit error = %v, want ENOENT", err)
	}
	if want := "receive: NFT_MSG_NEWRULE: netlink receive: no such file or directory"; err.Error() != want {
		t.Fatalf("Commit error string = %q, want %q", err.Error(), want)
	}
	if rule.ID != 0 {
		t.Fatalf("rule.ID after failed commit = %d (temp %d), want 0", rule.ID, tempID)
	}
	if rule.Handle != 0 {
		t.Fatalf("rule.Handle after failed commit = %d, want 0", rule.Handle)
	}
	if got := b.State(); got != BatchFailed {
		t.Fatalf("batch state = %q, want %q", got, BatchFailed)
	}
	if b.handle != nil {
		t.Fatal("failed Commit did not release the batch netlink handle")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.messages) != 0 {
		t.Fatalf("failed Commit left %d buffered messages", len(c.messages))
	}
	if c.activeBatch != nil {
		t.Fatal("failed Commit left an active batch")
	}
	if len(c.localIndex.objects) != 0 {
		t.Fatalf("rollback left %d local index objects", len(c.localIndex.objects))
	}
	if len(c.pendingDeletes) != 0 {
		t.Fatalf("rollback left %d pending deletions", len(c.pendingDeletes))
	}
}

func TestUID447FailedFlushRestoresExistingIndexAndPendingDelete(t *testing.T) {
	dial := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, nil
		}
		for _, msg := range req {
			if msg.Header.Type == delTableHeaderType {
				return nltest.Error(int(unix.EPERM), []netlink.Message{msg})
			}
		}
		return nil, nil
	}
	c, err := New(WithTestDial(dial))
	if err != nil {
		t.Fatal(err)
	}

	existing := &Table{Name: "uid447_existing", Family: TableFamilyIPv4}
	key := tableLocalKey(existing)
	c.mu.Lock()
	c.localIndex = newLocalObjectIndex()
	c.localIndex.objects[key] = existing
	c.mu.Unlock()

	c.DelTable(existing)

	c.mu.Lock()
	if _, ok := c.localIndex.objects[key]; ok {
		c.mu.Unlock()
		t.Fatal("Delete did not optimistically remove the table from the local index")
	}
	if len(c.pendingDeletes) != 1 {
		c.mu.Unlock()
		t.Fatalf("pending deletes = %d, want 1", len(c.pendingDeletes))
	}
	c.mu.Unlock()

	if err := c.Flush(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("Flush error = %v, want EPERM", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	restored, ok := c.localIndex.objects[key]
	if !ok {
		t.Fatal("failed Flush did not restore the existing table to the local index")
	}
	if restored != existing {
		t.Fatalf("restored object = %p, want original %p", restored, existing)
	}
	if len(c.pendingDeletes) != 0 {
		t.Fatalf("pending deletes after rollback = %d, want 0", len(c.pendingDeletes))
	}
	if existing.Name != "uid447_existing" || existing.Family != TableFamilyIPv4 {
		t.Fatalf("existing object was mutated: %#v", existing)
	}
}

func TestUID447CancelReleasesHandleAndBuffersAndRestoresIdentity(t *testing.T) {
	c, err := New(WithTestDial(uid447OKDial))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if b.handle == nil {
		t.Fatal("Begin did not acquire a batch handle")
	}

	table := &Table{Name: "uid447_cancel", Family: TableFamilyIPv4}
	chain := &Chain{Name: "c", Table: table}
	rule := &Rule{Table: table, Chain: chain}
	b.AddTable(table)
	b.AddChain(chain)
	b.AddRule(rule)
	if rule.ID == 0 {
		t.Fatal("expected temporary rule ID")
	}

	if err := b.Cancel(); err != nil {
		t.Fatalf("first Cancel: %v", err)
	}
	if err := b.Cancel(); err != nil {
		t.Fatalf("idempotent Cancel: %v", err)
	}
	if got := b.State(); got != BatchCanceled {
		t.Fatalf("state = %q, want %q", got, BatchCanceled)
	}
	if b.handle != nil {
		t.Fatal("Cancel retained the netlink handle")
	}
	if b.built != nil {
		t.Fatal("Cancel retained marshalled buffers")
	}
	if rule.ID != 0 {
		t.Fatalf("Cancel left temporary rule ID %d", rule.ID)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeBatch != nil {
		t.Fatal("Cancel left active batch")
	}
	if c.messages != nil {
		t.Fatal("Cancel retained buffered messages")
	}
}

func TestUID447NestedBeginAndFlushAreRejected(t *testing.T) {
	var sends atomic.Int32
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 {
			sends.Add(1)
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	b, err := c.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := c.Begin(); !errors.Is(err, ErrBatchActive) {
		t.Fatalf("nested Begin error = %v, want %v", err, ErrBatchActive)
	}

	b.AddTable(&Table{Name: "uid447_nested", Family: TableFamilyIPv4})
	if err := c.Flush(); !errors.Is(err, ErrNestedCommit) {
		t.Fatalf("Conn.Flush during Batch error = %v, want %v", err, ErrNestedCommit)
	}

	c.mu.Lock()
	buffered := len(c.messages)
	c.mu.Unlock()
	if buffered != 1 {
		t.Fatalf("rejected Flush changed buffer length to %d, want 1", buffered)
	}

	if err := b.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := sends.Load(); got != 1 {
		t.Fatalf("send count = %d, want 1", got)
	}
	if err := b.Commit(); !errors.Is(err, ErrNestedCommit) {
		t.Fatalf("repeat Commit error = %v, want %v", err, ErrNestedCommit)
	}
	if got := sends.Load(); got != 1 {
		t.Fatalf("repeat Commit sent again: send count = %d", got)
	}
}

func TestUID447ReentrantCommitIsRejectedWithoutDeadlock(t *testing.T) {
	var b *Batch
	var nestedErr error
	var attempts atomic.Int32
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 && attempts.Add(1) == 1 {
			nestedErr = b.Commit()
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	b, err = c.Begin()
	if err != nil {
		t.Fatal(err)
	}
	b.AddTable(&Table{Name: "uid447_reentrant", Family: TableFamilyIPv4})

	done := make(chan error, 1)
	go func() { done <- b.Commit() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("outer Commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reentrant Commit deadlocked")
	}
	if !errors.Is(nestedErr, ErrNestedCommit) {
		t.Fatalf("nested Commit error = %v, want %v", nestedErr, ErrNestedCommit)
	}
}

func TestUID447ConcurrentDuplicateCommitSendsOnce(t *testing.T) {
	var sends atomic.Int32
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 {
			sends.Add(1)
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Begin()
	if err != nil {
		t.Fatal(err)
	}
	b.AddTable(&Table{Name: "uid447_concurrent_commit", Family: TableFamilyIPv4})

	const goroutines = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = b.Commit()
		}(i)
	}
	close(start)
	wg.Wait()

	var successes, duplicates int
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrNestedCommit):
			duplicates++
		default:
			t.Errorf("unexpected Commit error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful commits = %d, want 1", successes)
	}
	if duplicates != goroutines-1 {
		t.Fatalf("duplicate commit errors = %d, want %d", duplicates, goroutines-1)
	}
	if got := sends.Load(); got != 1 {
		t.Fatalf("send count = %d, want 1", got)
	}
	if got := b.State(); got != BatchCommitted {
		t.Fatalf("state = %q, want %q", got, BatchCommitted)
	}
}

func TestUID447ACKErrorsMapToBatchInOriginalOrder(t *testing.T) {
	var nilCalls atomic.Int32
	var inner []netlink.Message
	dial := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) > 0 {
			inner = append([]netlink.Message(nil), req[1:len(req)-1]...)
			// Arrival order is operation 2, then 0, then 1.
			return nltest.Error(int(unix.ENOENT), []netlink.Message{inner[2]})
		}

		call := int(nilCalls.Add(1))
		switch call {
		case 1:
			return nltest.Error(int(unix.EPERM), []netlink.Message{inner[0]})
		case 2:
			return nltest.Error(int(unix.EINVAL), []netlink.Message{inner[1]})
		default:
			return nil, nil
		}
	}

	c, err := New(WithTestDial(dial))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		b.AddTable(&Table{Name: fmt.Sprintf("uid447_ack_%d", i), Family: TableFamilyIPv4})
	}

	commitErr := b.Commit()
	if commitErr == nil {
		t.Fatal("Commit succeeded, want ACK errors")
	}
	var ordered *CommitError
	if !errors.As(commitErr, &ordered) {
		t.Fatalf("error %T does not contain *CommitError", commitErr)
	}
	if ordered.BatchID != b.ID() {
		t.Fatalf("CommitError batch = %d, want %d", ordered.BatchID, b.ID())
	}
	if len(ordered.ACKs) != 3 {
		t.Fatalf("ACK count = %d, want 3: %v", len(ordered.ACKs), commitErr)
	}
	wantIndices := []int{0, 1, 2}
	wantErrnos := []error{unix.EPERM, unix.EINVAL, unix.ENOENT}
	for i, ack := range ordered.ACKs {
		if ack.Index != wantIndices[i] {
			t.Fatalf("ACK %d index = %d, want %d (all: %+v)", i, ack.Index, wantIndices[i], ordered.ACKs)
		}
		if ack.BatchID != b.ID() {
			t.Fatalf("ACK %d BatchID = %d, want %d", i, ack.BatchID, b.ID())
		}
		if !errors.Is(ack, wantErrnos[i]) {
			t.Fatalf("ACK index %d error = %v, want %v", ack.Index, ack.Err, wantErrnos[i])
		}
	}
}

func TestUID447ImplicitFlushFailureAlsoRollsBackIdentity(t *testing.T) {
	c, err := New(WithTestDial(uid447FailRuleDial(t, int(unix.EACCES))))
	if err != nil {
		t.Fatal(err)
	}
	table := &Table{Name: "uid447_implicit", Family: TableFamilyIPv4}
	chain := &Chain{Name: "c", Table: table}
	rule := &Rule{Table: table, Chain: chain}
	c.AddTable(table)
	c.AddChain(chain)
	c.AddRule(rule)
	if rule.ID == 0 {
		t.Fatal("expected temporary ID")
	}
	if err := c.Flush(); !errors.Is(err, unix.EACCES) {
		t.Fatalf("Flush error = %v, want EACCES", err)
	}
	if rule.ID != 0 || rule.Handle != 0 {
		t.Fatalf("rule identity after failed Flush = ID %d Handle %d, want zero", rule.ID, rule.Handle)
	}
	c.mu.Lock()
	active := c.activeBatch
	messages := len(c.messages)
	c.mu.Unlock()
	if active != nil || messages != 0 {
		t.Fatalf("state after Flush: active=%v messages=%d", active, messages)
	}
}

func TestUID447SuccessfulCommitPublishesRuleHandleOnce(t *testing.T) {
	dial := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, nil
		}
		var replies []netlink.Message
		for _, msg := range req {
			if msg.Header.Flags&netlink.Echo == 0 || msg.Header.Type != newRuleHeaderType {
				continue
			}
			attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(42)},
			})
			if err != nil {
				t.Fatal(err)
			}
			data := append(append([]byte{}, msg.Data...), attrs...)
			replies = append(replies, netlink.Message{Header: msg.Header, Data: data})
		}
		return replies, nil
	}

	c, err := New(WithTestDial(dial))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Begin()
	if err != nil {
		t.Fatal(err)
	}
	table := &Table{Name: "uid447_publish", Family: TableFamilyIPv4}
	chain := &Chain{Name: "c", Table: table}
	rule := &Rule{Table: table, Chain: chain}
	b.AddRule(rule)
	if rule.Handle != 0 {
		t.Fatalf("kernel handle published before Commit: %d", rule.Handle)
	}
	if err := b.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if rule.Handle != 42 {
		t.Fatalf("rule.Handle = %d, want 42", rule.Handle)
	}
	if rule.ID != 0 {
		t.Fatalf("rule.ID = %d after publish, want 0", rule.ID)
	}
}

func TestUID447ConcurrentBeginCancelCommitCycles(t *testing.T) {
	c, err := New(WithTestDial(uid447OKDial))
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 12
	const iterations = 10
	var wg sync.WaitGroup
	var unexpected atomic.Int32
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range iterations {
				b, err := c.Begin()
				if errors.Is(err, ErrBatchActive) {
					continue
				}
				if err != nil {
					t.Errorf("Begin: %v", err)
					unexpected.Add(1)
					return
				}
				b.AddTable(&Table{
					Name:   fmt.Sprintf("uid447_race_%d_%d", g, i),
					Family: TableFamilyIPv4,
				})
				if (g+i)%2 == 0 {
					if err := b.Commit(); err != nil {
						t.Errorf("Commit: %v", err)
						unexpected.Add(1)
						return
					}
				} else {
					if err := b.Cancel(); err != nil {
						t.Errorf("Cancel: %v", err)
						unexpected.Add(1)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if unexpected.Load() != 0 {
		t.Fatalf("%d unexpected errors", unexpected.Load())
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeBatch != nil {
		t.Fatal("active batch remains after concurrent cycles")
	}
}
