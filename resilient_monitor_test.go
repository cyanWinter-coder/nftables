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
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// --- test fakes -------------------------------------------------------------

// fakeConn is a scripted monitorConn. Each Receive call returns the next script
// entry (messages or an error). Close records that it was called and unblocks a
// Receive waiting on an empty script.
type fakeConn struct {
	mu      sync.Mutex
	script  []fakeReceive
	closed  bool
	closeCh chan struct{}
	dialGen int
}

type fakeReceive struct {
	msgs []netlink.Message
	err  error
}

func (f *fakeConn) Receive() ([]netlink.Message, error) {
	for {
		f.mu.Lock()
		if len(f.script) > 0 {
			next := f.script[0]
			f.script = f.script[1:]
			f.mu.Unlock()
			return next.msgs, next.err
		}
		if f.closed {
			f.mu.Unlock()
			return nil, errors.New("use of closed file")
		}
		f.mu.Unlock()

		select {
		case <-f.closeCh:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.closeCh)
	}
	return nil
}

func (f *fakeConn) wasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// fakeDialer hands out conns from a queue in dial order.
type fakeDialer struct {
	mu    sync.Mutex
	conns []*fakeConn
	dials int
}

func (d *fakeDialer) dialMonitor() (monitorConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) == 0 {
		return nil, errors.New("fakeDialer: no more conns")
	}
	c := d.conns[0]
	d.conns = d.conns[1:]
	d.dials++
	c.dialGen = d.dials
	return c, nil
}

func (d *fakeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// fakeSnapshot serves a scripted snapshot per call. Each call blocks on the
// corresponding gate (if any) until it is closed or the context is canceled.
type fakeSnapshot struct {
	mu    sync.Mutex
	snaps []map[monitorKey]monitorObject
	calls int
	gates []chan struct{}
}

func (s *fakeSnapshot) readSnapshot(ctx context.Context) (map[monitorKey]monitorObject, error) {
	s.mu.Lock()
	idx := s.calls
	s.calls++
	var gate chan struct{}
	if idx < len(s.gates) {
		gate = s.gates[idx]
	}
	s.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if idx >= len(s.snaps) {
		return map[monitorKey]monitorObject{}, nil
	}
	return cloneSnapshot(s.snaps[idx]), nil
}

// --- message builders -------------------------------------------------------

func nftHeader(subsystem, typ uint8) netlink.HeaderType {
	return netlink.HeaderType(uint16(subsystem)<<8 | uint16(typ))
}

func newTableMsg(fam TableFamily, name string, del bool) netlink.Message {
	typ := unix.NFT_MSG_NEWTABLE
	if del {
		typ = unix.NFT_MSG_DELTABLE
	}
	attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: append([]byte(name), 0)},
	})
	return netlink.Message{
		Header: netlink.Header{Type: nftHeader(unix.NFNL_SUBSYS_NFTABLES, uint8(typ))},
		Data:   append(extraHeader(uint8(fam), 0), attrs...),
	}
}

func newGenMsg(genID uint32) netlink.Message {
	id := uint32Bytes(genID)
	attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_GEN_ID, Data: id},
		{Type: unix.NFTA_GEN_PROC_NAME, Data: append([]byte("test"), 0)},
	})
	return netlink.Message{
		Header: netlink.Header{Type: nftHeader(unix.NFNL_SUBSYS_NFTABLES, uint8(unix.NFT_MSG_NEWGEN))},
		Data:   append(extraHeader(0, 0), attrs...),
	}
}

func uint32Bytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func tableSnap(fam TableFamily, name string) monitorObject {
	t := &Table{Family: fam, Name: name}
	return monitorObject{kind: MonitorEventTypeNewTable, key: tableKey(t), data: t}
}

func newTestMonitor(d dialerAndSnapshot, opts ...ResilientMonitorOption) *ResilientMonitor {
	m := NewResilientMonitor(append(opts, WithReconnectBackoff(time.Millisecond))...)
	m.dialer = d.dialer
	m.snapshot = d.snap
	return m
}

type dialerAndSnapshot struct {
	dialer *fakeDialer
	snap   *fakeSnapshot
}

// collect drains the event channel into a slice.
func collect(ch <-chan *MonitorEvents, timeout time.Duration) []*MonitorEvents {
	var out []*MonitorEvents
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

func eventTypes(evs []*MonitorEvents) []MonitorEventType {
	var out []MonitorEventType
	for _, ev := range evs {
		for _, c := range ev.Changes {
			out = append(out, c.Type)
		}
	}
	return out
}

func containsType(types []MonitorEventType, want MonitorEventType) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// --- tests ------------------------------------------------------------------

// TestResilientMonitorReconnect verifies requirement 2/3: after a connection
// loss, the missed delete is recovered from the snapshot, objects present in
// both the snapshot and the buffered increment are published once, and the
// connection generation advances.
func TestResilientMonitorReconnect(t *testing.T) {
	tableA := tableSnap(TableFamilyIPv4, "a")

	// Generation 1 socket: initial resync reads an empty snapshot, then one
	// committed NewTable("a") is delivered before the socket dies with EIO.
	conn1 := &fakeConn{
		closeCh: make(chan struct{}),
		script: []fakeReceive{
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(1)}},
			{err: errors.New("recvmsg: input/output error")},
		},
	}
	// Generation 2 socket: a NewTable("a") increment identical to the snapshot
	// object arrives while the reconnect snapshot dump is in flight. The merge
	// must collapse both views into a single final state, not a duplicate New.
	conn2 := &fakeConn{
		closeCh: make(chan struct{}),
		script: []fakeReceive{
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(2)}},
		},
	}
	dialer := &fakeDialer{conns: []*fakeConn{conn1, conn2}}
	// Each snapshot call blocks on its own gate, so increments queued by the
	// reader are guaranteed to be buffered during the corresponding dump.
	block1 := make(chan struct{})
	block2 := make(chan struct{})
	snap := &fakeSnapshot{
		snaps: []map[monitorKey]monitorObject{
			{},                   // initial snapshot: empty
			{tableA.key: tableA}, // reconnect snapshot: contains a
		},
		gates: []chan struct{}{block1, block2},
	}

	m := newTestMonitor(dialerAndSnapshot{dialer, snap}, WithResilientEventBuffer(16))
	ch, err := newMonitorStarted(m)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Unblock initial resync; gen1 NewTable("a") then flows, and conn1 dies.
	close(block1)

	// Wait for the reconnect generation to start and block on its snapshot.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && dialer.dialCount() < 2 {
		time.Sleep(2 * time.Millisecond)
	}
	if dialer.dialCount() < 2 {
		t.Fatalf("expected reconnect dial, got %d dials", dialer.dialCount())
	}
	// Give conn2's reader time to enqueue its buffered increment.
	time.Sleep(30 * time.Millisecond)
	close(block2)

	evs := collect(ch, 300*time.Millisecond)
	types := eventTypes(evs)

	if !containsType(types, MonitorEventTypeResync) {
		t.Errorf("expected at least one Resync OOB, got types: %v", types)
	}
	if !containsType(types, MonitorEventTypeReconnect) {
		t.Errorf("expected a Reconnect OOB after EIO, got types: %v", types)
	}

	// Requirement 3: table "a" appears in both the reconnect snapshot and the
	// buffered increment, so the resync diff must publish it at most once.
	var newA int
	for _, ev := range evs {
		for _, c := range ev.Changes {
			if c.Type == MonitorEventTypeNewTable {
				if tb, ok := c.Data.(*Table); ok && tb.Name == "a" {
					newA++
				}
			}
		}
	}
	if newA > 1 {
		t.Errorf("table a present in both snapshot and increment published %d times, want <=1", newA)
	}

	if m.sessionGeneration() < 2 {
		t.Errorf("connection generation did not advance: %d", m.sessionGeneration())
	}
	if dialer.dialCount() < 2 {
		t.Errorf("expected at least 2 dial attempts, got %d", dialer.dialCount())
	}
}

// TestResilientMonitorMissedDeleteRecovered verifies the headline failure:
// a delete missed while the socket is down is reconstructed from the snapshot
// as a single Del event.
func TestResilientMonitorMissedDeleteRecovered(t *testing.T) {
	tableA := tableSnap(TableFamilyIPv4, "a")
	tableB := tableSnap(TableFamilyIPv4, "b")

	conn1 := &fakeConn{
		closeCh: make(chan struct{}),
		script: []fakeReceive{
			// Steady state: a and b exist (published via initial resync).
			{err: errors.New("recvmsg: connection reset by peer")},
		},
	}
	conn2 := &fakeConn{closeCh: make(chan struct{}), script: []fakeReceive{}}
	dialer := &fakeDialer{conns: []*fakeConn{conn1, conn2}}
	snap := &fakeSnapshot{
		snaps: []map[monitorKey]monitorObject{
			{tableA.key: tableA, tableB.key: tableB}, // initial: both present
			{tableA.key: tableA},                     // after reconnect: b deleted
		},
	}

	m := newTestMonitor(dialerAndSnapshot{dialer, snap}, WithResilientEventBuffer(16))
	ch, _ := newMonitorStarted(m)
	defer m.Close()

	evs := collect(ch, 250*time.Millisecond)

	var delB int
	for _, ev := range evs {
		for _, c := range ev.Changes {
			if c.Type == MonitorEventTypeDelTable {
				if tb, ok := c.Data.(*Table); ok && tb.Name == "b" {
					delB++
				}
			}
		}
	}
	if delB != 1 {
		t.Errorf("expected exactly 1 DelTable(b) recovered from snapshot, got %d", delB)
	}
}

// TestResilientMonitorOutOfOrder verifies requirement 1: batches whose genID
// is not newer than lastGenID are skipped and surfaced as Stale.
func TestResilientMonitorOutOfOrder(t *testing.T) {
	conn1 := &fakeConn{
		closeCh: make(chan struct{}),
		script: []fakeReceive{
			// gen 5 applied, then a replayed/duplicate gen 3, then gen 6.
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(5)}},
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", true), newGenMsg(3)}},
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(6)}},
		},
	}
	dialer := &fakeDialer{conns: []*fakeConn{conn1}}
	snap := &fakeSnapshot{snaps: []map[monitorKey]monitorObject{{}}}

	m := newTestMonitor(dialerAndSnapshot{dialer, snap}, WithResilientEventBuffer(16))
	ch, _ := newMonitorStarted(m)
	defer m.Close()

	evs := collect(ch, 200*time.Millisecond)
	types := eventTypes(evs)
	if !containsType(types, MonitorEventTypeStale) {
		t.Errorf("expected a Stale OOB for genID regression, got %v", types)
	}
	if last, _ := m.lastEventSeq(); last != 6 {
		t.Errorf("lastGenID must advance to 6 and never regress, got %d", last)
	}
}

// TestResilientMonitorTruncation verifies requirement 4: overflowing the replay
// buffer raises a Truncated marker; the following resync restores consistency
// without duplicate publishes.
func TestResilientMonitorTruncation(t *testing.T) {
	tableA := tableSnap(TableFamilyIPv4, "a")

	// Tiny replay limit (1) and a reader that queues two batches before the
	// first resync drains them: the second enqueue must truncate.
	conn1 := &fakeConn{
		closeCh: make(chan struct{}),
		script: []fakeReceive{
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(1)}},
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(2)}},
		},
	}
	dialer := &fakeDialer{conns: []*fakeConn{conn1}}
	// Block the first snapshot until the batches are already queued.
	block := make(chan struct{})
	snap := &fakeSnapshot{
		snaps: []map[monitorKey]monitorObject{{tableA.key: tableA}},
		gates: []chan struct{}{block},
	}

	m := newTestMonitor(dialerAndSnapshot{dialer, snap},
		WithResilientEventBuffer(16), WithResyncBufferLimit(1))
	ch, _ := newMonitorStarted(m)
	defer m.Close()

	// Give the reader time to enqueue both batches against the blocked snapshot.
	time.Sleep(50 * time.Millisecond)
	close(block)

	evs := collect(ch, 250*time.Millisecond)
	types := eventTypes(evs)
	if !containsType(types, MonitorEventTypeTruncated) {
		t.Errorf("expected Truncated OOB on replay overflow, got %v", types)
	}
	if !containsType(types, MonitorEventTypeResync) {
		t.Errorf("expected resync to complete after truncation, got %v", types)
	}
	// After resync the single snapshot object must appear at most once.
	var newA int
	for _, ev := range evs {
		for _, c := range ev.Changes {
			if c.Type == MonitorEventTypeNewTable {
				if tb, ok := c.Data.(*Table); ok && tb.Name == "a" {
					newA++
				}
			}
		}
	}
	if newA > 1 {
		t.Errorf("table a published %d times after truncation+resync, want <=1", newA)
	}
}

// TestResilientMonitorCloseClosesSocket verifies requirement 5: Close shuts the
// underlying socket, no reconnect happens, and the event channel closes.
func TestResilientMonitorCloseClosesSocket(t *testing.T) {
	conn1 := &fakeConn{closeCh: make(chan struct{}), script: []fakeReceive{}}
	dialer := &fakeDialer{conns: []*fakeConn{conn1}}
	snap := &fakeSnapshot{snaps: []map[monitorKey]monitorObject{{}}}

	m := newTestMonitor(dialerAndSnapshot{dialer, snap}, WithResilientEventBuffer(4))
	ch, _ := newMonitorStarted(m)

	// Wait until the first connection is active before closing.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && dialer.dialCount() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Channel must close; drain any buffered events first.
	deadlineCh := time.After(200 * time.Millisecond)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				goto closed
			}
		case <-deadlineCh:
			t.Fatal("event channel did not close in time")
		}
	}
closed:

	if !conn1.wasClosed() {
		t.Error("underlying socket was not closed by Close")
	}
	// Allow any stray reconnect to surface.
	time.Sleep(50 * time.Millisecond)
	if dialer.dialCount() != 1 {
		t.Errorf("Close must not trigger reconnects, got %d dials", dialer.dialCount())
	}
}

// TestResilientMonitorBackpressure verifies that a non-draining subscriber
// applies backpressure and eventually the overflow path marks truncation
// rather than dropping silently.
func TestResilientMonitorBackpressure(t *testing.T) {
	tableA := tableSnap(TableFamilyIPv4, "a")
	// Unbuffered subscriber channel + replay limit 1.
	conn1 := &fakeConn{
		closeCh: make(chan struct{}),
		script: []fakeReceive{
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(1)}},
			{msgs: []netlink.Message{newTableMsg(TableFamilyIPv4, "a", false), newGenMsg(2)}},
		},
	}
	dialer := &fakeDialer{conns: []*fakeConn{conn1}}
	block := make(chan struct{})
	snap := &fakeSnapshot{
		snaps: []map[monitorKey]monitorObject{{tableA.key: tableA}},
		gates: []chan struct{}{block},
	}
	m := newTestMonitor(dialerAndSnapshot{dialer, snap},
		WithResyncBufferLimit(1))
	ch, _ := newMonitorStarted(m)
	_ = ch // intentionally never drained

	time.Sleep(50 * time.Millisecond)
	close(block)

	// The monitor must still be alive and eventually reach resync even though
	// nobody reads; drain now and confirm truncation was signaled.
	evs := collect(ch, 250*time.Millisecond)
	types := eventTypes(evs)
	if !containsType(types, MonitorEventTypeTruncated) {
		t.Errorf("expected Truncated under backpressure, got %v", types)
	}
}

// TestResilientMonitorDialRetry verifies that a failed dial surfaces a
// Reconnect OOB and the supervisor retries until a dial succeeds.
func TestResilientMonitorDialRetry(t *testing.T) {
	conn1 := &fakeConn{closeCh: make(chan struct{}), script: []fakeReceive{}}
	// First dial fails, second one hands out a usable conn.
	dialer := &retryDialer{failFirst: true, good: conn1}
	snap := &fakeSnapshot{snaps: []map[monitorKey]monitorObject{{}}}

	m := newTestMonitor(dialerAndSnapshot{dialer: nil, snap: snap}, WithResilientEventBuffer(8))
	m.dialer = dialer
	ch, _ := newMonitorStarted(m)
	defer m.Close()

	evs := collect(ch, 250*time.Millisecond)
	types := eventTypes(evs)
	if !containsType(types, MonitorEventTypeReconnect) {
		t.Errorf("expected Reconnect OOB after failed dial, got %v", types)
	}
	if !containsType(types, MonitorEventTypeResync) {
		t.Errorf("expected Resync once a dial succeeded, got %v", types)
	}
	if dialer.dialCount() < 2 {
		t.Errorf("expected a retry after dial failure, got %d dials", dialer.dialCount())
	}
	if m.sessionGeneration() != 1 {
		t.Errorf("generation counts successful dials only, got %d", m.sessionGeneration())
	}
}

// retryDialer fails its first dial and returns good on subsequent calls.
type retryDialer struct {
	mu        sync.Mutex
	failFirst bool
	good      *fakeConn
	calls     int
}

func (d *retryDialer) dialMonitor() (monitorConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.failFirst {
		d.failFirst = false
		return nil, errors.New("dial: operation not permitted")
	}
	return d.good, nil
}

func (d *retryDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// newMonitorStarted mirrors AddResilientMonitor's wiring without a real Conn.
func newMonitorStarted(m *ResilientMonitor) (chan *MonitorEvents, error) {
	if m.dialer == nil || m.snapshot == nil {
		return nil, fmt.Errorf("test monitor requires dialer and snapshot")
	}
	go m.run()
	return m.eventCh, nil
}
