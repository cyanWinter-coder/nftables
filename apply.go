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

	"github.com/google/nftables/expr"
)

// Ruleset is a declarative description of the complete desired state of the
// tables, chains, rules, named objects, sets and flowtables managed by the
// caller. ApplyRuleset reconciles the kernel state against it.
//
// Every object is identified by its name within a table (and, for tables, by
// the (family, name) pair). Objects that exist in the kernel but are absent
// from the Ruleset are deleted; objects present in both are updated when they
// differ; objects only present in the Ruleset are created.
//
// Names inside the Ruleset must be unique within their scope: tables within a
// family, and chains, objects, sets and flowtables within a table. A rule may
// only reference chains and named objects that exist in the Ruleset or in the
// kernel; references that cannot be resolved, and circular chain references,
// cause ApplyRuleset to reject the whole update before any message is sent.
type Ruleset struct {
	// Tables is the complete set of desired tables.
	Tables []*Table
	// Chains is the complete set of desired chains. Each Chain's Table must
	// refer to one of the Tables declared in this Ruleset.
	Chains []*Chain
	// Rules is the complete set of desired rules. Each Rule's Table and Chain
	// must both be declared in this Ruleset; rules are buffered in slice
	// order and applied in that order within each chain.
	Rules []*Rule
	// Objects is the complete set of desired stateful objects (counters,
	// quotas, ...), each identified by (table, name).
	Objects []Obj
	// Sets is the complete set of desired named sets and maps, each
	// identified by (table, name).
	Sets []*Set
	// Flowtables is the complete set of desired flowtables, each identified
	// by (table, name).
	Flowtables []*Flowtable
}

// ApplyRuleset atomically reconciles the kernel nftables state against the
// desired Ruleset. The reconciliation is performed in a single netlink batch:
// either every change commits or none of them does.
//
// Before touching the kernel, ApplyRuleset:
//
//   - resolves every cross-object reference (rule to chain/table, rule to
//     named object or set, jump/goto to chain), rejecting missing, ambiguous
//     or duplicate names;
//   - rejects circular chain references (a chain that, directly or
//     indirectly, jumps to itself);
//   - orders all operations by dependency, so newly created objects are
//     referenceable before any rule that uses them and deleted objects are
//     only released once the last reference to them is gone.
//
// The package's local name index is updated only after the batch has been
// committed successfully. On any failure the index keeps describing the
// previously committed state, so a half-applied state is never published.
//
// The existing single-object APIs (AddTable, AddChain, AddRule, AddObj, ...)
// keep working unchanged and remain fully compatible. Messages buffered on the
// Conn through those APIs before an ApplyRuleset call are preserved: the
// declarative batch is sent on its own and the previous buffer is restored
// afterwards, whether the batch succeeded or failed.
func (cc *Conn) ApplyRuleset(rs *Ruleset) error {
	if rs == nil {
		return errors.New("ApplyRuleset: ruleset must not be nil")
	}

	cc.mu.Lock()
	// Resolve against a snapshot that includes the committed index plus
	// index changes buffered by single-object calls not yet flushed.
	committed := cc.committedNameIndexLocked()
	savedMessages := cc.snapshotMessagesLocked()
	savedPending := cc.snapshotPendingLocked()
	cc.mu.Unlock()

	plan, err := buildTransactionPlan(rs, committed)
	if err != nil {
		return err
	}

	// Buffer the transaction on a private scratch Conn. Reusing the normal
	// primitives keeps message encoding identical to the imperative API and
	// prevents any half-built message from leaking onto the caller's Conn
	// before the batch is known to be sendable.
	scratch, err := New()
	if err != nil {
		return err
	}
	if err := plan.bufferLocked(scratch); err != nil {
		return err
	}

	cc.mu.Lock()
	cc.messages = scratch.messages
	// The declarative commit publishes the complete resolved index itself;
	// tell flush not to fold imperative index mutations into the committed
	// index and not to clear pending state, which is restored below.
	cc.pendingIndex = nil
	cc.declarativeFlush = true
	cc.err = nil
	cc.mu.Unlock()

	flushErr := cc.flush(0)

	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.declarativeFlush = false
	if flushErr != nil {
		// Restore the pre-transaction buffer and pending index changes; the
		// committed index never moved, so no half state is visible.
		cc.messages = savedMessages
		cc.pendingIndex = savedPending
		cc.err = nil
		return flushErr
	}
	// Batch committed: restore the caller's previous buffer and publish the
	// index describing the new committed state.
	cc.messages = savedMessages
	cc.commitNameIndexLocked(plan.committedIndex)
	return nil
}

// refKind enumerates the kinds of named entities a rule can reference.
type refKind int

const (
	refChain refKind = iota
	refObject
	refSet
	refFlowtable
)

func (k refKind) String() string {
	switch k {
	case refChain:
		return "chain"
	case refObject:
		return "object"
	case refSet:
		return "set"
	case refFlowtable:
		return "flowtable"
	default:
		return "unknown"
	}
}

// objectKey identifies a name-scoped entity within a table.
type objectKey struct {
	family TableFamily
	table  string
	kind   refKind
	name   string
}

func (k objectKey) String() string {
	return fmt.Sprintf("%s %q in table %q (family %d)", k.kind, k.name, k.table, k.family)
}

// nameEntry records where a named entity came from, so the planner can tell
// desired-state definitions apart from entities that only exist in the kernel.
type nameEntry struct {
	key objectKey
	// desired points to the entity definition in the target Ruleset. It is
	// nil for entities that only exist in the committed kernel state.
	desired any
	// committed points to the entity as known from the last successfully
	// committed state. It is nil for entities newly introduced by the
	// Ruleset; entries surviving the reconciliation carry both pointers.
	committed any
}

// nameIndex is the package-local resolution table for named entities. It is
// the only mutable piece of cross-object state and is swapped atomically on
// successful commit.
type nameIndex struct {
	// tables maps (family, name) to *Table.
	tables map[tableKey]*Table
	// entries maps every other named entity to its entry.
	entries map[objectKey]*nameEntry
}

type tableKey struct {
	family TableFamily
	name   string
}

func newNameIndex() *nameIndex {
	return &nameIndex{
		tables:  map[tableKey]*Table{},
		entries: map[objectKey]*nameEntry{},
	}
}

func (idx *nameIndex) clone() *nameIndex {
	cp := newNameIndex()
	for k, v := range idx.tables {
		cp.tables[k] = v
	}
	for k, v := range idx.entries {
		entryCopy := *v
		cp.entries[k] = &entryCopy
	}
	return cp
}

// snapshotMessagesLocked returns a copy of the currently buffered but not yet
// flushed messages so an ApplyRuleset failure can restore the caller's prior
// buffer verbatim.
func (cc *Conn) snapshotMessagesLocked() []netlinkMessage {
	saved := make([]netlinkMessage, len(cc.messages))
	copy(saved, cc.messages)
	return saved
}

// extractRuleReferences walks a rule's expressions and returns the names of
// every cross-object reference it contains. Chain references come from
// jump/goto verdicts; object references from expr.Objref; set and map
// references from expr.Lookup; flowtable references from expr.FlowOffload.
func extractRuleReferences(r *Rule) []objectKey {
	if r.Table == nil {
		return nil
	}
	var refs []objectKey
	add := func(kind refKind, name string) {
		if name == "" {
			return
		}
		refs = append(refs, objectKey{
			family: r.Table.Family,
			table:  r.Table.Name,
			kind:   kind,
			name:   name,
		})
	}
	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Verdict:
			if (v.Kind == expr.VerdictJump || v.Kind == expr.VerdictGoto) && v.Chain != "" {
				add(refChain, v.Chain)
			}
		case *expr.Objref:
			add(refObject, v.Name)
		case *expr.Lookup:
			add(refSet, v.SetName)
		case *expr.FlowOffload:
			add(refFlowtable, v.Name)
		}
	}
	return refs
}
