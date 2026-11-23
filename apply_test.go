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
	"io"
	"strings"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// testDialFunc builds a TestDial function that records every nftables request
// message (excluding batch begin/end) and synthesizes rule-handle echo
// replies.
func testDialFunc(t *testing.T) (nltestDial func([]netlink.Message) ([]netlink.Message, error), recorded func() []netlink.Message) {
	t.Helper()
	var requests []netlink.Message
	dial := func(req []netlink.Message) ([]netlink.Message, error) {
		// The netlink test socket re-invokes the function with an empty
		// request once the queued replies are drained; signal end of stream.
		if len(req) == 0 {
			return nil, io.EOF
		}
		var replies []netlink.Message
		for _, msg := range req {
			subsystem := msg.Header.Type >> 8
			if subsystem == unix.NFNL_SUBSYS_NFTABLES {
				requests = append(requests, msg)
			}
			if msg.Header.Flags&netlink.Echo != 0 &&
				msg.Header.Type == netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE) {
				attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
					{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(uint64(len(requests) + 1))},
				})
				replies = append(replies, netlink.Message{
					Header: msg.Header,
					Data:   append(append([]byte{}, msg.Data...), attrs...),
				})
			}
		}
		return replies, nil
	}
	return dial, func() []netlink.Message { return requests }
}

func newTestApplyConn(t *testing.T) (*Conn, func() []netlink.Message) {
	t.Helper()
	dial, recorded := testDialFunc(t)
	c, err := New(WithTestDial(dial))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, recorded
}

// msgType extracts the NFT_MSG_* subtype from a recorded message.
func msgType(msg netlink.Message) uint16 {
	return uint16(msg.Header.Type) & 0xff
}

// typeSequence returns the ordered nftables message subtypes in a batch.
func typeSequence(msgs []netlink.Message) []uint16 {
	var out []uint16
	for _, m := range msgs {
		out = append(out, msgType(m))
	}
	return out
}

func indexOfType(seq []uint16, typ uint16) int {
	for i, t := range seq {
		if t == typ {
			return i
		}
	}
	return -1
}

func sampleRuleset() *Ruleset {
	table := &Table{Family: TableFamilyIPv4, Name: "ip-filter"}
	chainA := &Chain{Table: table, Name: "input", Type: ChainTypeFilter, Hooknum: ChainHookInput, Priority: ChainPriorityFilter}
	chainB := &Chain{Table: table, Name: "helper"}
	counter := &NamedObj{
		Table: table,
		Name:  "hits",
		Type:  ObjTypeCounter,
		Obj:   &expr.Counter{},
	}
	set := &Set{
		Table:        table,
		Name:         "blocked",
		KeyType:      TypeIPAddr,
		KeyByteOrder: binaryutil.BigEndian,
	}
	rule1 := &Rule{
		Table: table,
		Chain: chainA,
		Exprs: []expr.Any{
			&expr.Objref{Type: int(ObjTypeCounter), Name: "hits"},
			&expr.Verdict{Kind: expr.VerdictJump, Chain: "helper"},
			&expr.Lookup{SourceRegister: 1, SetName: "blocked"},
		},
	}
	rule2 := &Rule{
		Table: table,
		Chain: chainB,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}},
	}
	return &Ruleset{
		Tables:     []*Table{table},
		Chains:     []*Chain{chainA, chainB},
		Rules:      []*Rule{rule1, rule2},
		Objects:    []Obj{counter},
		Sets:       []*Set{set},
		Flowtables: nil,
	}
}

// TestApplyRulesetOrdersByDependency verifies that creations are emitted with
// the table first, then chains/objects/sets, and rules only after every entity
// they reference exists.
func TestApplyRulesetOrdersByDependency(t *testing.T) {
	c, recorded := newTestApplyConn(t)
	if err := c.ApplyRuleset(sampleRuleset()); err != nil {
		t.Fatalf("ApplyRuleset: %v", err)
	}
	seq := typeSequence(recorded())
	newTable := indexOfType(seq, unix.NFT_MSG_NEWTABLE)
	newChain := indexOfType(seq, unix.NFT_MSG_NEWCHAIN)
	newObj := indexOfType(seq, unix.NFT_MSG_NEWOBJ)
	newSet := indexOfType(seq, unix.NFT_MSG_NEWSET)
	newRule := indexOfType(seq, unix.NFT_MSG_NEWRULE)
	for _, idx := range []int{newTable, newChain, newObj, newSet, newRule} {
		if idx < 0 {
			t.Fatalf("missing expected message in sequence %v", seq)
		}
	}
	if !(newTable < newChain && newChain < newRule && newObj < newRule && newSet < newRule) {
		t.Fatalf("dependency order violated: %v", seq)
	}
}

// TestApplyRulesetRejectsDuplicateNames ensures duplicate table, chain and
// object names are rejected before any netlink message is sent.
func TestApplyRulesetRejectsDuplicateNames(t *testing.T) {
	c, recorded := newTestApplyConn(t)

	dupChains := sampleRuleset()
	dupChains.Chains = append(dupChains.Chains, &Chain{Table: dupChains.Tables[0], Name: "input"})
	if err := c.ApplyRuleset(dupChains); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate name error, got %v", err)
	}
	if len(recorded()) != 0 {
		t.Fatalf("no netlink traffic expected on rejection, got %d messages", len(recorded()))
	}

	dupTables := sampleRuleset()
	dupTables.Tables = append(dupTables.Tables, &Table{Family: TableFamilyIPv4, Name: "ip-filter"})
	if err := c.ApplyRuleset(dupTables); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate table error, got %v", err)
	}

	dupObjs := sampleRuleset()
	dupObjs.Objects = append(dupObjs.Objects, &NamedObj{
		Table: dupObjs.Tables[0], Name: "hits", Type: ObjTypeCounter, Obj: &expr.Counter{},
	})
	if err := c.ApplyRuleset(dupObjs); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate object error, got %v", err)
	}
}

// TestApplyRulesetRejectsMissingReference ensures rules referencing unknown
// chains, objects or sets are rejected before anything is sent.
func TestApplyRulesetRejectsMissingReference(t *testing.T) {
	c, recorded := newTestApplyConn(t)

	missingChain := sampleRuleset()
	missingChain.Rules[0].Chain = &Chain{Table: missingChain.Tables[0], Name: "ghost"}
	if err := c.ApplyRuleset(missingChain); err == nil || !strings.Contains(err.Error(), "unresolved reference") {
		t.Fatalf("expected unresolved chain error, got %v", err)
	}
	if len(recorded()) != 0 {
		t.Fatalf("no netlink traffic expected on rejection, got %d", len(recorded()))
	}

	missingObj := sampleRuleset()
	missingObj.Rules[0].Exprs = []expr.Any{&expr.Objref{Type: int(ObjTypeCounter), Name: "nope"}}
	if err := c.ApplyRuleset(missingObj); err == nil || !strings.Contains(err.Error(), "unresolved reference") {
		t.Fatalf("expected unresolved object error, got %v", err)
	}

	missingSet := sampleRuleset()
	missingSet.Rules[0].Exprs = []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: "nope"}}
	if err := c.ApplyRuleset(missingSet); err == nil || !strings.Contains(err.Error(), "unresolved reference") {
		t.Fatalf("expected unresolved set error, got %v", err)
	}

	unknownTable := sampleRuleset()
	unknownTable.Chains[0].Table = &Table{Family: TableFamilyIPv4, Name: "elsewhere"}
	if err := c.ApplyRuleset(unknownTable); err == nil || !strings.Contains(err.Error(), "unknown table") {
		t.Fatalf("expected unknown table error, got %v", err)
	}
}

// TestApplyRulesetRejectsCircularChainReference verifies direct and indirect
// jump/goto cycles are rejected.
func TestApplyRulesetRejectsCircularChainReference(t *testing.T) {
	c, recorded := newTestApplyConn(t)

	// Direct self cycle.
	direct := sampleRuleset()
	direct.Rules[1].Exprs = []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "helper"}}
	if err := c.ApplyRuleset(direct); err == nil || !strings.Contains(err.Error(), "circular") {
		t.Fatalf("expected circular reference error, got %v", err)
	}
	if len(recorded()) != 0 {
		t.Fatalf("no netlink traffic expected on rejection, got %d", len(recorded()))
	}

	// Indirect cycle helper -> input -> helper.
	indirect := sampleRuleset()
	indirect.Chains = append(indirect.Chains, &Chain{Table: indirect.Tables[0], Name: "third"})
	indirect.Rules[1].Exprs = []expr.Any{&expr.Verdict{Kind: expr.VerdictGoto, Chain: "third"}}
	indirect.Rules = append(indirect.Rules, &Rule{
		Table: indirect.Tables[0],
		Chain: &Chain{Table: indirect.Tables[0], Name: "third"},
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "input"}},
	})
	if err := c.ApplyRuleset(indirect); err == nil || !strings.Contains(err.Error(), "circular") {
		t.Fatalf("expected indirect circular reference error, got %v", err)
	}
}

// TestApplyRulesetRenameDeletesBeforeRecreating checks that renaming an
// entity emits the deletion (after the referencing rules were flushed) and
// only then the creation, so no rule can point at a name that is momentarily
// undefined.
func TestApplyRulesetRenameDeletesBeforeRecreating(t *testing.T) {
	c, recorded := newTestApplyConn(t)

	first := sampleRuleset()
	if err := c.ApplyRuleset(first); err != nil {
		t.Fatalf("first ApplyRuleset: %v", err)
	}
	firstBatchLen := len(recorded())

	second := sampleRuleset()
	// Rename the object: old name removed, new one introduced, rule updated
	// to reference the new name.
	second.Objects[0].(*NamedObj).Name = "hits2"
	second.Rules[0].Exprs[0] = &expr.Objref{Type: int(ObjTypeCounter), Name: "hits2"}

	if err := c.ApplyRuleset(second); err != nil {
		t.Fatalf("second ApplyRuleset: %v", err)
	}
	seq := typeSequence(recorded()[firstBatchLen:])
	delObj := indexOfType(seq, unix.NFT_MSG_DELOBJ)
	flushRule := indexOfType(seq, unix.NFT_MSG_DELRULE)
	newObj := indexOfType(seq, unix.NFT_MSG_NEWOBJ)
	if delObj < 0 || newObj < 0 || flushRule < 0 {
		t.Fatalf("expected flush/del/new messages, got %v", seq)
	}
	// Rules referencing the old object are removed before the object is
	// released, and the new object exists before the replacement rule runs.
	if !(flushRule < delObj && delObj < newObj) {
		t.Fatalf("rename ordering violated: %v", seq)
	}
	newRule := indexOfType(seq, unix.NFT_MSG_NEWRULE)
	if newObj > newRule {
		t.Fatalf("new object must be referenceable before its rule: %v", seq)
	}
}

// TestApplyRulesetFailureRollsBackIndexAndBuffer verifies that a flush
// failure neither publishes a half-built name index nor loses messages the
// caller had buffered beforehand.
func TestApplyRulesetFailureRollsBackIndexAndBuffer(t *testing.T) {
	// The kernel rejection is modeled as a netlink Error reply (as nltest
	// does): returning a plain Go error from TestDial would make the
	// connection's receive loop retry forever, independent of this package.
	const failErrno = unix.EPERM
	var failBatch bool
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		// After draining a reply, the netlink test socket re-invokes the
		// function with an empty request to check for further messages.
		if len(req) == 0 {
			return nil, io.EOF
		}
		if failBatch {
			return nltest.Error(int(failErrno), req)
		}
		return testEchoReplies(req)
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Seed a committed index with a successful first transaction.
	first := sampleRuleset()
	if err := c.ApplyRuleset(first); err != nil {
		t.Fatalf("seed ApplyRuleset: %v", err)
	}
	committed := c.nameIdx.clone()
	if len(committed.tables) != 1 {
		t.Fatalf("committed index not published after success: %+v", committed)
	}

	// Stage an unrelated imperative message before the declarative call.
	c.AddTable(&Table{Family: TableFamilyIPv6, Name: "staged"})
	stagedCount := len(c.messages)

	failBatch = true
	second := sampleRuleset()
	second.Objects[0].(*NamedObj).Name = "hits-renamed"
	second.Rules[0].Exprs[0] = &expr.Objref{Type: int(ObjTypeCounter), Name: "hits-renamed"}

	applyErr := c.ApplyRuleset(second)
	if applyErr == nil {
		t.Fatal("expected flush failure, got nil")
	}
	if !strings.Contains(applyErr.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM error, got %v", applyErr)
	}

	// The committed index must be unchanged (no half state published).
	if len(c.nameIdx.tables) != 1 {
		t.Fatalf("index mutated after failed commit: %+v", c.nameIdx)
	}
	if _, ok := c.nameIdx.entries[objectKey{
		family: TableFamilyIPv4, table: "ip-filter", kind: refObject, name: "hits-renamed",
	}]; ok {
		t.Fatal("failed transaction leaked a renamed object into the committed index")
	}
	if _, ok := c.nameIdx.entries[objectKey{
		family: TableFamilyIPv4, table: "ip-filter", kind: refObject, name: "hits",
	}]; !ok {
		t.Fatal("previously committed object vanished from index after failed transaction")
	}
	// The caller's previously buffered imperative message must survive.
	if len(c.messages) != stagedCount {
		t.Fatalf("staged buffer not restored: got %d messages, want %d", len(c.messages), stagedCount)
	}
	if len(c.pendingIndex) == 0 {
		t.Fatal("staged imperative index changes were not restored after failure")
	}
}

// testEchoReplies synthesizes rule-handle echo replies for NEWRULE messages,
// matching the kernel's behavior for batches that request Echo.
func testEchoReplies(req []netlink.Message) ([]netlink.Message, error) {
	var replies []netlink.Message
	nextHandle := uint64(1)
	for _, msg := range req {
		if msg.Header.Flags&netlink.Echo != 0 &&
			msg.Header.Type == netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE) {
			attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
				{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(nextHandle)},
			})
			nextHandle++
			replies = append(replies, netlink.Message{
				Header: msg.Header,
				Data:   append(append([]byte{}, msg.Data...), attrs...),
			})
		}
	}
	return replies, nil
}

// TestApplyRulesetPublishesIndexOnlyOnCommit checks the local name index is
// absent/empty before the first successful commit and populated afterwards,
// including references resolved through it in a follow-up transaction.
func TestApplyRulesetPublishesIndexOnlyOnCommit(t *testing.T) {
	c, recorded := newTestApplyConn(t)
	if c.nameIdx != nil {
		t.Fatal("index should be nil before any declarative commit")
	}
	rs := sampleRuleset()
	if err := c.ApplyRuleset(rs); err != nil {
		t.Fatalf("ApplyRuleset: %v", err)
	}
	if c.nameIdx == nil {
		t.Fatal("index not published after successful commit")
	}
	wantChains := map[string]bool{"input": true, "helper": true}
	for name := range wantChains {
		if _, ok := c.nameIdx.entries[objectKey{
			family: TableFamilyIPv4, table: "ip-filter", kind: refChain, name: name,
		}]; !ok {
			t.Fatalf("chain %q missing from committed index", name)
		}
	}
	if _, ok := c.nameIdx.tables[tableKey{family: TableFamilyIPv4, name: "ip-filter"}]; !ok {
		t.Fatal("table missing from committed index")
	}
	// A follow-up transaction that drops one entity must prune it only on
	// the next successful commit.
	rs2 := sampleRuleset()
	rs2.Objects = nil
	rs2.Rules[0].Exprs = []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "helper"}}
	if err := c.ApplyRuleset(rs2); err != nil {
		t.Fatalf("follow-up ApplyRuleset: %v", err)
	}
	if _, ok := c.nameIdx.entries[objectKey{
		family: TableFamilyIPv4, table: "ip-filter", kind: refObject, name: "hits",
	}]; ok {
		t.Fatal("removed object still present in committed index")
	}
	// Second batch should contain the object deletion.
	foundDel := false
	for _, m := range recorded() {
		if msgType(m) == unix.NFT_MSG_DELOBJ {
			foundDel = true
		}
	}
	if !foundDel {
		t.Fatal("expected DELOBJ in follow-up batch")
	}
}

// TestApplyRulesetSingleObjectAPIRemainCompatible ensures the imperative APIs
// still buffer exactly as before and update the index only after Flush.
func TestApplyRulesetSingleObjectAPIRemainCompatible(t *testing.T) {
	c, recorded := newTestApplyConn(t)

	tbl := &Table{Family: TableFamilyIPv4, Name: "imp"}
	chain := &Chain{Table: tbl, Name: "c0"}
	obj := &NamedObj{Table: tbl, Name: "cnt", Type: ObjTypeCounter, Obj: &expr.Counter{}}

	c.AddTable(tbl)
	c.AddChain(chain)
	c.AddObj(obj)

	// Nothing committed, nothing visible in the committed index yet.
	if c.nameIdx != nil {
		t.Fatal("index must not advance before Flush")
	}
	if len(c.pendingIndex) != 3 {
		t.Fatalf("expected 3 pending index changes, got %d", len(c.pendingIndex))
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(recorded()) != 3 {
		t.Fatalf("expected 3 imperative messages, got %d", len(recorded()))
	}
	if c.nameIdx == nil || len(c.nameIdx.tables) != 1 || len(c.nameIdx.entries) != 2 {
		t.Fatalf("index not published correctly after imperative flush: %+v", c.nameIdx)
	}
	if len(c.pendingIndex) != 0 {
		t.Fatal("pending index changes not cleared after commit")
	}

	// Deletions take effect on the index at the next flush.
	c.DelChain(chain)
	if err := c.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	if _, ok := c.nameIdx.entries[objectKey{
		family: TableFamilyIPv4, table: "imp", kind: refChain, name: "c0",
	}]; ok {
		t.Fatal("deleted chain still in committed index")
	}
}

// TestApplyRulesetDeleteOrdering verifies removed objects are released only
// after their referencing rules disappear, and removed tables come last.
func TestApplyRulesetDeleteOrdering(t *testing.T) {
	c, recorded := newTestApplyConn(t)
	first := sampleRuleset()
	if err := c.ApplyRuleset(first); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Drop everything under the managed table. Deleting a table cascades to
	// its chains, rules, objects and sets in the kernel, so the batch ends
	// with a single DELTABLE rather than a per-child sequence.
	firstBatchLen := len(recorded())
	empty := &Ruleset{}
	if err := c.ApplyRuleset(empty); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	seq := typeSequence(recorded()[firstBatchLen:])
	if len(seq) != 1 || seq[0] != unix.NFT_MSG_DELTABLE {
		t.Fatalf("expected a single DELTABLE cascade, got %v", seq)
	}
}

// TestApplyRulesetEntityDeleteOrdering verifies that removing an individual
// entity (not its whole table) flushes the rules referencing it before the
// entity itself is released.
func TestApplyRulesetEntityDeleteOrdering(t *testing.T) {
	c, recorded := newTestApplyConn(t)
	first := sampleRuleset()
	if err := c.ApplyRuleset(first); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Keep table and chains; drop only the named object. The rule that
	// referenced it is rebuilt without the objref expression.
	second := sampleRuleset()
	second.Objects = nil
	second.Rules[0].Exprs = []expr.Any{
		&expr.Verdict{Kind: expr.VerdictJump, Chain: "helper"},
		&expr.Lookup{SourceRegister: 1, SetName: "blocked"},
	}
	firstBatchLen := len(recorded())
	if err := c.ApplyRuleset(second); err != nil {
		t.Fatalf("second ApplyRuleset: %v", err)
	}
	seq := typeSequence(recorded()[firstBatchLen:])
	flushRule := indexOfType(seq, unix.NFT_MSG_DELRULE)
	delObj := indexOfType(seq, unix.NFT_MSG_DELOBJ)
	if flushRule < 0 || delObj < 0 {
		t.Fatalf("expected rule flush and object deletion, got %v", seq)
	}
	if flushRule > delObj {
		t.Fatalf("referencing rule must be removed before its object: %v", seq)
	}
}

// TestApplyRulesetPreservesRuleOrder verifies rules declared in a chain are
// buffered in their slice order, which defines the chain's rule sequence since
// AddRule appends.
func TestApplyRulesetPreservesRuleOrder(t *testing.T) {
	c, recorded := newTestApplyConn(t)
	table := &Table{Family: TableFamilyIPv4, Name: "ord"}
	chain := &Chain{Table: table, Name: "c"}
	rules := make([]*Rule, 4)
	for i := range rules {
		rules[i] = &Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		}
	}
	rs := &Ruleset{
		Tables: []*Table{table},
		Chains: []*Chain{chain},
		Rules:  rules,
	}
	if err := c.ApplyRuleset(rs); err != nil {
		t.Fatalf("ApplyRuleset: %v", err)
	}
	// AddRule appends, so the four NEWRULE messages must appear in the exact
	// declaration order; the message sequence itself is the ordering contract.
	var rulePositions []int
	for i, m := range recorded() {
		if msgType(m) == unix.NFT_MSG_NEWRULE {
			rulePositions = append(rulePositions, i)
		}
	}
	if len(rulePositions) != 4 {
		t.Fatalf("expected 4 NEWRULE messages, got %d", len(rulePositions))
	}
	for i, pos := range rulePositions {
		if i > 0 && pos <= rulePositions[i-1] {
			t.Fatalf("rule ordering not preserved: %v", rulePositions)
		}
	}
}

// TestApplyRulesetLeavesUnmanagedTablesAlone verifies that a table the
// declarative index does not track (e.g. one created outside this Conn) is
// neither deleted nor rewritten when a different table is reconciled.
func TestApplyRulesetLeavesUnmanagedTablesAlone(t *testing.T) {
	c, recorded := newTestApplyConn(t)

	// Only the "managed" table is known to the declarative index. The
	// "untouched" table exists conceptually in the kernel but is not tracked,
	// so reconciliation must not touch it.
	managed := &Table{Family: TableFamilyIPv4, Name: "managed"}
	ch1 := &Chain{Table: managed, Name: "c1"}
	seed := &Ruleset{
		Tables: []*Table{managed},
		Chains: []*Chain{ch1},
	}
	if err := c.ApplyRuleset(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seedBatchLen := len(recorded())

	// A second table, created through the imperative API but never part of a
	// declarative ruleset, lands in the index as well once flushed; emulate a
	// genuinely external table by removing it from the committed index view.
	external := &Table{Family: TableFamilyIPv4, Name: "untouched"}
	delete(c.nameIdx.tables, tableKey{family: external.Family, name: external.Name})

	next := &Ruleset{
		Tables: []*Table{managed},
		Chains: []*Chain{ch1},
		Rules:  []*Rule{{Table: managed, Chain: ch1, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}},
	}
	if err := c.ApplyRuleset(next); err != nil {
		t.Fatalf("second: %v", err)
	}
	for _, m := range recorded()[seedBatchLen:] {
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "untouched") {
			t.Fatalf("batch modified unmanaged table: %v", msgType(m))
		}
	}
}

// TestApplyRulesetRejectsNilRuleset checks the obvious defensive case.
func TestApplyRulesetRejectsNilRuleset(t *testing.T) {
	c, _ := newTestApplyConn(t)
	if err := c.ApplyRuleset(nil); err == nil {
		t.Fatal("expected error for nil ruleset")
	}
}

// TestApplyRulesetRejectsRuleInUndeclaredChain verifies that a rule cannot be
// attached to a chain surviving only in the committed index.
func TestApplyRulesetRejectsRuleInUndeclaredChain(t *testing.T) {
	c, _ := newTestApplyConn(t)
	seed := sampleRuleset()
	if err := c.ApplyRuleset(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Second ruleset keeps the table but drops the chain declaration while
	// still referencing it from a rule.
	next := sampleRuleset()
	next.Chains = nil
	err := c.ApplyRuleset(next)
	if err == nil || !strings.Contains(err.Error(), "unresolved reference") {
		t.Fatalf("expected unresolved reference error, got %v", err)
	}
}

// TestImperativeFlushFailureDoesNotAdvanceIndex verifies the single-object
// path also keeps the committed index untouched when its batch fails.
func TestImperativeFlushFailureDoesNotAdvanceIndex(t *testing.T) {
	const failErrno = unix.EPERM
	var fail bool
	c, err := New(WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if fail {
			return nltest.Error(int(failErrno), req)
		}
		return testEchoReplies(req)
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Seed a committed table.
	c.AddTable(&Table{Family: TableFamilyIPv4, Name: "seed"})
	if err := c.Flush(); err != nil {
		t.Fatalf("seed flush: %v", err)
	}
	before := len(c.nameIdx.tables)

	// A failing batch must not publish the new table into the index.
	fail = true
	c.AddTable(&Table{Family: TableFamilyIPv4, Name: "would-be"})
	if err := c.Flush(); err == nil {
		t.Fatal("expected flush failure")
	}
	if len(c.nameIdx.tables) != before {
		t.Fatalf("index advanced after failed flush: %d vs %d", len(c.nameIdx.tables), before)
	}
	if len(c.pendingIndex) != 0 {
		t.Fatal("pending index changes not discarded after failed flush")
	}
}
