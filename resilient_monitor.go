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
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// defaultReplayBufferLimit bounds the number of event batches buffered
	// between a reconnect and the completion of the next resynchronization.
	defaultReplayBufferLimit = 4096
	// defaultReconnectBackoff is the initial wait before redialing. It doubles
	// on consecutive failures up to maxReconnectBackoff.
	defaultReconnectBackoff = time.Second
	maxReconnectBackoff     = 30 * time.Second
)

// monitorObject is the uniform representation used by the materialized state
// cache. Every ruleset object (table, chain, rule, set, set element, stateful
// object) is reduced to a key plus the original typed pointer and a kind tag.
type monitorObject struct {
	kind MonitorEventType
	key  monitorKey
	data any
}

// monitorKey uniquely identifies a ruleset object within the state cache.
type monitorKey struct {
	kind MonitorEventType
	fam  TableFamily
	// table/chain/set/obj names, rule handle and raw element identity.
	table string
	chain string
	set   string
	obj   string
	rule  uint64
	elem  string
}

func tableKey(t *Table) monitorKey {
	return monitorKey{kind: MonitorEventTypeNewTable, fam: t.Family, table: t.Name}
}

func chainKey(c *Chain) monitorKey {
	return monitorKey{kind: MonitorEventTypeNewChain, fam: c.Table.Family,
		table: c.Table.Name, chain: c.Name}
}

func ruleKey(r *Rule) monitorKey {
	return monitorKey{kind: MonitorEventTypeNewRule, fam: r.Table.Family,
		table: r.Table.Name, chain: r.Chain.Name, rule: r.Handle}
}

func setKey(s *Set) monitorKey {
	return monitorKey{kind: MonitorEventTypeNewSet, fam: s.Table.Family,
		table: s.Table.Name, set: s.Name}
}

func setElemKey(s *Set, e SetElement) monitorKey {
	return monitorKey{
		kind: MonitorEventTypeNewSetElem, fam: s.Table.Family,
		table: s.Table.Name, set: s.Name,
		elem: elemIdentity(e),
	}
}

func elemIdentity(e SetElement) string {
	return hex.EncodeToString(e.Key) + "/" + hex.EncodeToString(e.KeyEnd) +
		fmt.Sprintf("/%v", e.IntervalEnd)
}

func objKey(o *NamedObj) monitorKey {
	return monitorKey{kind: MonitorEventTypeNewObj, fam: o.Table.Family,
		table: o.Table.Name, obj: fmt.Sprintf("%d/%s", o.Type, o.Name)}
}

// eventBatch is one committed transaction: the NEWGEN boundary event plus all
// changes delivered before it. touched[i] is the cache key for changes[i]
// (nil-key entries for parse failures are skipped during replay).
type eventBatch struct {
	genID   uint32
	gen     *MonitorEvent
	changes []*MonitorEvent
	touched []monitorKey
}

// monitorConn is the netlink connection surface the resilient monitor needs.
// *netlink.Conn satisfies it; tests inject a fake.
type monitorConn interface {
	Receive() ([]netlink.Message, error)
	Close() error
}

// monitorDialer opens a fresh netlink connection joined to the nftables
// multicast group.
type monitorDialer interface {
	dialMonitor() (monitorConn, error)
}

// snapshotReader returns the full current ruleset as a cache-shaped map.
type snapshotReader interface {
	readSnapshot(ctx context.Context) (map[monitorKey]monitorObject, error)
}

// ResilientMonitor is a [Monitor] that survives netlink connection losses.
//
// On disconnect it reconnects, reads a fresh ruleset snapshot, merges the
// buffered incremental events against it, and publishes only the resulting
// diff: an object that appears in both the snapshot and the increments is
// published at most once with its final state. Each session tracks a
// connection generation (incremented on every successful dial) and the last
// applied ruleset generation ID (the NFT_MSG_NEWGEN sequence), so out-of-order
// batches can be detected and skipped.
//
// If the internal replay buffer overflows, a MonitorEventTypeTruncated
// out-of-band event is published; the monitor keeps running and restores
// guaranteed consistency at the next full MonitorEventTypeResync.
type ResilientMonitor struct {
	action       MonitorAction
	object       MonitorObject
	monitorFlags uint32

	// mu covers status, closeCh and activeConn.
	mu         sync.Mutex
	status     int
	closeCh    chan struct{}
	activeConn monitorConn

	eventCh chan *MonitorEvents

	replayLimit int
	backoff     time.Duration

	// Injectable dependencies; production wiring is set by AddResilientMonitor.
	dialer   monitorDialer
	snapshot snapshotReader

	// Session bookkeeping (requirement 1).
	generation uint64 // connection generation, starts at 1
	lastGenID  uint32 // last applied ruleset generation ID
	hasGenID   bool

	// Materialized state caches.
	published map[monitorKey]monitorObject
	live      map[monitorKey]monitorObject

	// truncation is set when the reader's bounded batch queue overflows; it
	// stays on until the next resync rebuilds state from a snapshot
	// (requirement 4).
	truncated bool
}

// ResilientMonitorOption configures a [ResilientMonitor].
type ResilientMonitorOption func(*ResilientMonitor)

// WithResyncBufferLimit bounds the internal replay buffer (in event batches).
// When the buffer overflows the monitor publishes a MonitorEventTypeTruncated
// event and waits for the next full resynchronization before guaranteeing
// continuous increments again.
func WithResyncBufferLimit(size int) ResilientMonitorOption {
	return func(m *ResilientMonitor) {
		if size > 0 {
			m.replayLimit = size
		}
	}
}

// WithReconnectBackoff sets the initial delay between reconnect attempts. The
// delay doubles on consecutive failures up to a 30s ceiling.
func WithReconnectBackoff(d time.Duration) ResilientMonitorOption {
	return func(m *ResilientMonitor) {
		if d > 0 {
			m.backoff = d
		}
	}
}

// WithResilientEventBuffer gives the subscriber-facing channel an output
// buffer of the given size.
func WithResilientEventBuffer(size int) ResilientMonitorOption {
	return func(m *ResilientMonitor) {
		if size > 0 {
			m.eventCh = make(chan *MonitorEvents, size)
		}
	}
}

// WithResilientAction sets monitor actions like new, del or any.
func WithResilientAction(action MonitorAction) ResilientMonitorOption {
	return func(m *ResilientMonitor) { m.action = action }
}

// WithResilientObject sets the monitored object classes.
func WithResilientObject(object MonitorObject) ResilientMonitorOption {
	return func(m *ResilientMonitor) { m.object = object }
}

// NewResilientMonitor prepares a ResilientMonitor. Install it with
// [Conn.AddResilientMonitor].
func NewResilientMonitor(opts ...ResilientMonitorOption) *ResilientMonitor {
	m := &ResilientMonitor{
		status:      monitorOK,
		closeCh:     make(chan struct{}),
		replayLimit: defaultReplayBufferLimit,
		backoff:     defaultReconnectBackoff,
		published:   make(map[monitorKey]monitorObject),
		live:        make(map[monitorKey]monitorObject),
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.eventCh == nil {
		m.eventCh = make(chan *MonitorEvents)
	}
	objects, ok := monitorFlags[m.action]
	if !ok {
		objects = monitorFlags[MonitorActionAny]
	}
	flags, ok := objects[m.object]
	if !ok {
		flags = objects[MonitorObjectAny]
	}
	m.monitorFlags = flags
	return m
}

// Close terminates the monitor. The underlying netlink socket is closed, which
// unblocks the receive loop; the loop then exits without reconnecting and the
// event channel is closed.
func (m *ResilientMonitor) Close() error {
	m.mu.Lock()
	if m.status == monitorClosed {
		m.mu.Unlock()
		return nil
	}
	m.status = monitorClosed
	close(m.closeCh)
	conn := m.activeConn
	m.mu.Unlock()

	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (m *ResilientMonitor) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status == monitorClosed
}

// sessionGeneration returns the current connection generation (number of
// successful dial attempts since the monitor started).
func (m *ResilientMonitor) sessionGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation
}

// lastEventSeq returns the last applied ruleset generation ID and whether any
// has been observed.
func (m *ResilientMonitor) lastEventSeq() (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastGenID, m.hasGenID
}

// seqState is the run-goroutine view of the last event sequence. All session
// sequence fields are guarded by mu.
func (m *ResilientMonitor) seqState() (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastGenID, m.hasGenID
}

// noteSeq records that a batch with the given ruleset generation ID has been
// applied.
func (m *ResilientMonitor) noteSeq(genID uint32) {
	if genID == 0 {
		return
	}
	m.mu.Lock()
	m.lastGenID = genID
	m.hasGenID = true
	m.mu.Unlock()
}

// run is the top-level supervisor: dial, stream, reconnect on error until
// Close.
func (m *ResilientMonitor) run() {
	defer close(m.eventCh)

	backoff := m.backoff
	for {
		if m.isClosed() {
			return
		}
		conn, err := m.dialer.dialMonitor()
		if err != nil {
			if m.isClosed() {
				return
			}
			m.publishOOB(MonitorEventTypeReconnect, err)
			if !m.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		// A successful dial resets the failure backoff.
		backoff = m.backoff
		conn = &onceCloseConn{monitorConn: conn}

		m.mu.Lock()
		m.generation++
		m.activeConn = conn
		m.mu.Unlock()

		// Requirement 2: on every generation, take a snapshot first while the
		// fresh socket is already subscribed, buffering increments that arrive
		// during the dump, then merge both views. stream() owns conn and closes
		// it (including the reader teardown) before returning.
		streamErr := m.stream(conn)

		m.mu.Lock()
		m.activeConn = nil
		m.mu.Unlock()

		if m.isClosed() {
			return
		}
		if streamErr != nil {
			m.publishOOB(MonitorEventTypeReconnect, streamErr)
			// Wait before redialing and grow the backoff across repeated
			// in-stream failures.
			if !m.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
		}
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > maxReconnectBackoff {
		return maxReconnectBackoff
	}
	return d
}

// sleep waits for d or until Close. It returns false when the monitor is shut
// down.
func (m *ResilientMonitor) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-m.closeCh:
		return false
	case <-t.C:
		return !m.isClosed()
	}
}

// stream owns one socket: it starts the reader, performs the snapshot+replay
// resynchronization, then drains steady-state batches until the reader fails
// or the monitor is closed. It always tears the reader and socket down before
// returning, so callers must not close conn themselves.
func (m *ResilientMonitor) stream(conn monitorConn) error {
	reader := newBatchReader(conn, m)

	var streamErr error
	// resync consumes the snapshot plus whatever the reader buffered meanwhile.
	if err := m.resync(reader); err != nil {
		streamErr = err
	} else {
		streamErr = m.drainLoop(reader)
	}

	// Teardown ordering matters: signal the reader first, then close the socket
	// so a Receive blocked in the reader is unblocked and the goroutine can
	// actually exit. Closing first from Close() races this path, hence the
	// idempotent reader stop and conn close below.
	reader.signalStop()
	_ = conn.Close()
	reader.wait()
	return streamErr
}

// onceCloseConn makes Close idempotent: both the supervisor teardown and an
// external [ResilientMonitor.Close] may race to close the same socket, but the
// underlying Close runs at most once.
type onceCloseConn struct {
	monitorConn
	once sync.Once
	err  error
}

func (c *onceCloseConn) Close() error {
	c.once.Do(func() { c.err = c.monitorConn.Close() })
	return c.err
}

// drainLoop consumes committed batches until the reader reports an error or
// the monitor is shut down.
func (m *ResilientMonitor) drainLoop(reader *batchReader) error {
	for {
		select {
		case <-m.closeCh:
			return nil
		case err := <-reader.errCh:
			return err
		case batch := <-reader.batchCh:
			m.handleBatch(batch)
		}
	}
}

// resync reads the current snapshot, drains increments buffered during the
// dump, replays those newer than lastGenID onto the snapshot, and publishes a
// single diff per object (requirements 2 and 3).
func (m *ResilientMonitor) resync(reader *batchReader) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopCancel := make(chan struct{})
	defer close(stopCancel)
	go func() {
		select {
		case <-m.closeCh:
			cancel()
		case <-stopCancel:
		}
	}()

	snap, err := m.snapshot.readSnapshot(ctx)
	if err != nil {
		if m.isClosed() {
			return nil
		}
		return fmt.Errorf("snapshot: %w", err)
	}

	// Collect every batch that arrived while the snapshot dump was running.
	buffered := reader.drainBuffered()

	base := cloneSnapshot(snap)
	lastSeq, hasSeq := m.seqState()
	for _, b := range buffered {
		// Requirement 1: skip batches already applied on an earlier generation.
		if hasSeq && b.genID != 0 && b.genID <= lastSeq {
			m.publishOOB(MonitorEventTypeStale,
				fmt.Errorf("skipping stale batch genID=%d (last=%d)", b.genID, lastSeq))
			continue
		}
		applyBatchToState(base, b)
		if b.genID != 0 {
			lastSeq = b.genID
			hasSeq = true
			m.noteSeq(b.genID)
		}
	}
	m.live = base

	// Full key-space diff: deletions that happened during the disconnect window
	// are recovered from the snapshot, and objects present in both views are
	// emitted at most once with their final state.
	m.publishDiff(allKeys(base, m.published))
	m.published = cloneSnapshot(base)
	m.mu.Lock()
	m.truncated = false
	m.mu.Unlock()
	m.publishOOB(MonitorEventTypeResync, nil)
	return nil
}

// handleBatch is the steady-state path for a committed transaction.
func (m *ResilientMonitor) handleBatch(b eventBatch) {
	// Requirement 1: ordering check against the last event sequence.
	lastSeq, hasSeq := m.seqState()
	if hasSeq && b.genID != 0 && b.genID <= lastSeq {
		m.publishOOB(MonitorEventTypeStale,
			fmt.Errorf("out-of-order batch genID=%d (last=%d)", b.genID, lastSeq))
		return
	}

	for i, ev := range b.changes {
		if ev.Error != nil {
			m.publishOOB(MonitorEventTypeOOB, ev.Error)
			continue
		}
		key := b.touched[i]
		switch {
		case isNewEvent(ev.Type):
			m.live[key] = monitorObject{kind: ev.Type, key: key, data: ev.Data}
		case isDelEvent(ev.Type):
			delete(m.live, key)
		}
	}

	// While truncated we only keep live state warm; increments are not
	// published until a resync restores the baseline.
	if !m.isTruncated() {
		m.publishDiff(b.touched)
	}

	m.noteSeq(b.genID)
}

// publishDiff compares live and published for the given keys and emits at most
// one final New/Del event per key, then advances published to match live.
func (m *ResilientMonitor) publishDiff(keys []monitorKey) {
	var changes []*MonitorEvent
	seen := make(map[monitorKey]struct{}, len(keys))
	for _, key := range keys {
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		cur, inLive := m.live[key]
		prev, inPublished := m.published[key]

		var ev *MonitorEvent
		switch {
		case inLive && !inPublished:
			ev = &MonitorEvent{Type: cur.kind, Data: cur.data}
		case !inLive && inPublished:
			ev = &MonitorEvent{Type: delCounterpart(prev.kind), Data: prev.data}
		case inLive && inPublished && !objectsEqual(prev, cur):
			ev = &MonitorEvent{Type: cur.kind, Data: cur.data}
		default:
			// Identical or both absent: suppress duplicates (requirement 3).
			continue
		}
		changes = append(changes, ev)
		if inLive {
			m.published[key] = cur
		} else {
			delete(m.published, key)
		}
	}

	if len(changes) > 0 {
		m.deliver(&MonitorEvents{Changes: changes})
	}
}

// publishOOB sends a standalone out-of-band event.
func (m *ResilientMonitor) publishOOB(t MonitorEventType, err error) {
	ev := &MonitorEvent{Type: t, Error: err}
	m.deliver(&MonitorEvents{GeneratedBy: ev, Changes: []*MonitorEvent{ev}})
}

// deliver applies backpressure: a slow subscriber blocks the stream loop here,
// which is the intended flow-control point.
func (m *ResilientMonitor) deliver(ev *MonitorEvents) {
	if m.isClosed() {
		return
	}
	m.eventCh <- ev
}

// batchReader turns raw netlink messages into committed eventBatch values,
// buffering batches that arrive while a resynchronization is in progress. The
// queue is bounded by the replay limit; when it fills up the monitor is marked
// truncated and the reader keeps draining the socket without queuing.
type batchReader struct {
	conn    monitorConn
	monitor *ResilientMonitor

	batchCh chan eventBatch
	errCh   chan error
	stopCh  chan struct{}
	stopped chan struct{}
}

func newBatchReader(conn monitorConn, m *ResilientMonitor) *batchReader {
	r := &batchReader{
		conn:    conn,
		monitor: m,
		batchCh: make(chan eventBatch, m.replayLimit),
		errCh:   make(chan error, 1),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go r.loop()
	return r
}

// signalStop asks the reader goroutine to exit. It is idempotent and does not
// wait for the goroutine; pair it with wait after closing the socket so the
// blocked Receive is released.
func (r *batchReader) signalStop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

// wait blocks until the reader goroutine has exited.
func (r *batchReader) wait() { <-r.stopped }

// drainBuffered returns all queued batches and leaves the queue empty.
func (r *batchReader) drainBuffered() []eventBatch {
	var out []eventBatch
	for {
		select {
		case b := <-r.batchCh:
			out = append(out, b)
		default:
			return out
		}
	}
}

func (r *batchReader) loop() {
	defer close(r.stopped)

	var changes []*MonitorEvent
	var touched []monitorKey
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		msgs, err := r.conn.Receive()
		if err != nil {
			if isClosedConnErr(err) && r.monitor.isClosed() {
				return
			}
			select {
			case r.errCh <- err:
			default:
			}
			return
		}
		for _, msg := range msgs {
			if msg.Header.Type&0xff00>>8 != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES) {
				continue
			}
			msgType := msg.Header.Type & 0x00ff
			if r.monitor.monitorFlags&1<<msgType == 0 {
				continue
			}
			if msgType == unix.NFT_MSG_NEWGEN {
				ev, genID, perr := genEventFromMsg(msg)
				if perr != nil {
					r.monitor.publishOOB(MonitorEventTypeOOB, perr)
					continue
				}
				b := eventBatch{genID: genID, gen: ev, changes: changes, touched: touched}
				changes = nil
				touched = nil
				r.enqueue(b)
				continue
			}
			ev, key, perr := r.monitor.changeEventFromMsg(msgType, msg)
			if perr != nil {
				// Parse errors are surfaced once, out of band, and do not take
				// part in the state cache.
				r.monitor.publishOOB(MonitorEventTypeOOB, perr)
				continue
			}
			changes = append(changes, ev)
			touched = append(touched, key)
		}
	}
}

// enqueue applies the bounded-buffer policy. A full queue triggers
// truncation: subsequent batches are dropped on the floor until the next
// resync rebuilds state from a snapshot.
func (r *batchReader) enqueue(b eventBatch) {
	if r.monitor.isTruncated() {
		return
	}
	select {
	case r.batchCh <- b:
	default:
		r.monitor.markTruncated()
	}
}

func (m *ResilientMonitor) isTruncated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.truncated
}

func (m *ResilientMonitor) markTruncated() {
	m.mu.Lock()
	already := m.truncated
	m.truncated = true
	m.mu.Unlock()
	if !already {
		m.publishOOB(MonitorEventTypeTruncated,
			fmt.Errorf("replay buffer limit %d exceeded; waiting for full resync", m.replayLimit))
	}
}

// changeEventFromMsg parses one non-NEWGEN message into a MonitorEvent and its
// cache key.
func (m *ResilientMonitor) changeEventFromMsg(msgType netlink.HeaderType, msg netlink.Message) (*MonitorEvent, monitorKey, error) {
	ev := &MonitorEvent{Type: MonitorEventType(msgType), Header: msg.Header}
	switch msgType {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
		t, err := tableFromMsg(msg)
		if err != nil {
			return ev, monitorKey{}, err
		}
		ev.Data = t
		return ev, tableKey(t), nil
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
		c, err := chainFromMsg(msg)
		if err != nil {
			return ev, monitorKey{}, err
		}
		ev.Data = c
		return ev, chainKey(c), nil
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		r, err := parseRuleFromMsg(msg)
		if err != nil {
			return ev, monitorKey{}, err
		}
		ev.Data = r
		return ev, ruleKey(r), nil
	case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:
		s, err := setsFromMsg(msg)
		if err != nil {
			return ev, monitorKey{}, err
		}
		ev.Data = s
		return ev, setKey(s), nil
	case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
		elems, err := elementsFromMsg(uint8(TableFamilyUnspecified), msg)
		if err != nil {
			return ev, monitorKey{}, err
		}
		ev.Data = elems
		if len(elems) == 0 {
			return ev, monitorKey{}, nil
		}
		return ev, m.elemKeyFromMsg(msg, elems[0]), nil
	case unix.NFT_MSG_NEWOBJ, unix.NFT_MSG_DELOBJ:
		o, err := objFromMsg(msg, true)
		if err != nil {
			return ev, monitorKey{}, err
		}
		named, ok := o.(*NamedObj)
		if !ok {
			return ev, monitorKey{}, fmt.Errorf("unexpected obj type %T", o)
		}
		ev.Data = named
		return ev, objKey(named), nil
	default:
		return ev, monitorKey{}, fmt.Errorf("unsupported monitored message type %d", msgType)
	}
}

func (m *ResilientMonitor) elemKeyFromMsg(msg netlink.Message, e SetElement) monitorKey {
	return monitorKey{
		kind: MonitorEventTypeNewSetElem,
		fam:  TableFamily(msg.Data[0]),
		elem: elemIdentity(e),
	}
}

func genEventFromMsg(msg netlink.Message) (*MonitorEvent, uint32, error) {
	g, err := genFromMsg(msg)
	if err != nil {
		return nil, 0, err
	}
	return &MonitorEvent{
		Type:   MonitorEventTypeNewGen,
		Data:   g,
		Header: msg.Header,
	}, g.ID, nil
}

// applyBatchToState replays one batch onto an arbitrary state map.
func applyBatchToState(state map[monitorKey]monitorObject, b eventBatch) {
	for i, ev := range b.changes {
		if ev.Error != nil || i >= len(b.touched) {
			continue
		}
		key := b.touched[i]
		if key == (monitorKey{}) {
			continue
		}
		switch {
		case isNewEvent(ev.Type):
			state[key] = monitorObject{kind: ev.Type, key: key, data: ev.Data}
		case isDelEvent(ev.Type):
			delete(state, key)
		}
	}
}

func isNewEvent(t MonitorEventType) bool {
	switch t {
	case MonitorEventTypeNewTable, MonitorEventTypeNewChain, MonitorEventTypeNewRule,
		MonitorEventTypeNewSet, MonitorEventTypeNewSetElem, MonitorEventTypeNewObj:
		return true
	}
	return false
}

func isDelEvent(t MonitorEventType) bool {
	switch t {
	case MonitorEventTypeDelTable, MonitorEventTypeDelChain, MonitorEventTypeDelRule,
		MonitorEventTypeDelSet, MonitorEventTypeDelSetElem, MonitorEventTypeDelObj:
		return true
	}
	return false
}

// delCounterpart maps a New event kind to its matching Del kind. Snapshot
// objects are stored under their New kind.
func delCounterpart(t MonitorEventType) MonitorEventType {
	switch t {
	case MonitorEventTypeNewTable:
		return MonitorEventTypeDelTable
	case MonitorEventTypeNewChain:
		return MonitorEventTypeDelChain
	case MonitorEventTypeNewRule:
		return MonitorEventTypeDelRule
	case MonitorEventTypeNewSet:
		return MonitorEventTypeDelSet
	case MonitorEventTypeNewSetElem:
		return MonitorEventTypeDelSetElem
	case MonitorEventTypeNewObj:
		return MonitorEventTypeDelObj
	default:
		return t
	}
}

func objectsEqual(a, b monitorObject) bool {
	if a.kind != b.kind || a.key != b.key {
		return false
	}
	return fmt.Sprintf("%#v", a.data) == fmt.Sprintf("%#v", b.data)
}

func cloneSnapshot(in map[monitorKey]monitorObject) map[monitorKey]monitorObject {
	out := make(map[monitorKey]monitorObject, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func allKeys(maps ...map[monitorKey]monitorObject) []monitorKey {
	seen := make(map[monitorKey]struct{})
	var out []monitorKey
	for _, m := range maps {
		for k := range m {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

func isClosedConnErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed file")
}

// AddResilientMonitor installs m on cc and starts the supervised receive loop.
// The returned channel is closed when [ResilientMonitor.Close] is called.
func (cc *Conn) AddResilientMonitor(m *ResilientMonitor) (chan *MonitorEvents, error) {
	if m.dialer == nil {
		m.dialer = &netlinkMonitorDialer{cc: cc}
	}
	if m.snapshot == nil {
		m.snapshot = &connSnapshotReader{cc: cc}
	}
	go m.run()
	return m.eventCh, nil
}

// connSnapshotReader reads a full ruleset snapshot through the Conn's public
// List/Get APIs and shapes it into the monitor cache.
type connSnapshotReader struct {
	cc *Conn
}

func (r *connSnapshotReader) readSnapshot(ctx context.Context) (map[monitorKey]monitorObject, error) {
	out := make(map[monitorKey]monitorObject)

	tables, err := r.cc.ListTables()
	if err != nil {
		return nil, fmt.Errorf("ListTables: %w", err)
	}
	for _, t := range tables {
		out[tableKey(t)] = monitorObject{kind: MonitorEventTypeNewTable, key: tableKey(t), data: t}
	}

	chains, err := r.cc.ListChains()
	if err != nil {
		return nil, fmt.Errorf("ListChains: %w", err)
	}
	for _, c := range chains {
		out[chainKey(c)] = monitorObject{kind: MonitorEventTypeNewChain, key: chainKey(c), data: c}
	}

	for _, t := range tables {
		// Rules are enumerated per chain: GetRules builds NFTA_RULE_CHAIN from
		// the chain name and does not accept a nil chain.
		for _, c := range chains {
			if c.Table == nil || c.Table.Name != t.Name || c.Table.Family != t.Family {
				continue
			}
			rules, err := r.cc.GetRules(t, c)
			if err != nil {
				return nil, fmt.Errorf("GetRules(%s/%s): %w", t.Name, c.Name, err)
			}
			for _, rule := range rules {
				out[ruleKey(rule)] = monitorObject{kind: MonitorEventTypeNewRule, key: ruleKey(rule), data: rule}
			}
		}

		sets, err := r.cc.GetSets(t)
		if err != nil {
			return nil, fmt.Errorf("GetSets(%s): %w", t.Name, err)
		}
		for _, s := range sets {
			out[setKey(s)] = monitorObject{kind: MonitorEventTypeNewSet, key: setKey(s), data: s}
			elems, err := r.cc.GetSetElements(s)
			if err != nil {
				return nil, fmt.Errorf("GetSetElements(%s/%s): %w", t.Name, s.Name, err)
			}
			for _, e := range elems {
				k := setElemKey(s, e)
				out[k] = monitorObject{kind: MonitorEventTypeNewSetElem, key: k, data: e}
			}
		}

		objs, err := r.cc.GetNamedObjects(t)
		if err != nil {
			return nil, fmt.Errorf("GetNamedObjects(%s): %w", t.Name, err)
		}
		for _, o := range objs {
			named, ok := o.(*NamedObj)
			if !ok {
				continue
			}
			out[objKey(named)] = monitorObject{kind: MonitorEventTypeNewObj, key: objKey(named), data: named}
		}
	}

	_ = ctx // snapshot APIs are synchronous; Close cancels them via socket close
	return out, nil
}

// netlinkMonitorDialer opens a fresh netlink.Conn joined to the nftables group.
type netlinkMonitorDialer struct {
	cc *Conn
}

func (d *netlinkMonitorDialer) dialMonitor() (monitorConn, error) {
	conn, closer, err := d.cc.netlinkConn()
	if err != nil {
		return nil, err
	}
	if err := conn.JoinGroup(uint32(unix.NFNLGRP_NFTABLES)); err != nil {
		_ = closer()
		return nil, err
	}
	return &wrappedMonitorConn{Conn: conn, closer: closer}, nil
}

type wrappedMonitorConn struct {
	*netlink.Conn
	closer netlinkCloser
}

func (w *wrappedMonitorConn) Close() error { return w.closer() }
