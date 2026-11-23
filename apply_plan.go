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
	"fmt"
	"sort"
)

// opKind enumerates the buffered operations the planner emits.
type opKind int

const (
	opAddTable opKind = iota
	opDelTable
	opAddChain
	opDelChain
	opFlushChain // remove all rules of a chain that stays
	opAddRule
	opAddObject
	opDelObject
	opAddSet
	opDelSet
	opAddFlowtable
	opDelFlowtable
)

// plannedOp is one ordered, dependency-checked mutation.
type plannedOp struct {
	kind opKind
	// payloads; only the ones relevant for kind are set.
	table     *Table
	chain     *Chain
	rule      *Rule
	obj       Obj
	set       *Set
	flowtable *Flowtable
}

// transactionPlan is the fully resolved, ordered mutation set plus the name
// index that describes the state after a successful commit.
type transactionPlan struct {
	ops            []plannedOp
	committedIndex *nameIndex
}

// buildTransactionPlan performs the pre-commit work: it indexes the desired
// Ruleset on top of the committed index, validates and resolves every
// cross-object reference, rejects cycles and duplicate/missing names, and
// produces a dependency-ordered operation list together with the index to
// publish on success.
func buildTransactionPlan(rs *Ruleset, committed *nameIndex) (*transactionPlan, error) {
	p := &planner{
		rs:        rs,
		committed: committed,
	}
	desired, err := p.indexDesired()
	if err != nil {
		return nil, err
	}
	p.desired = desired
	if err := p.resolveRules(); err != nil {
		return nil, err
	}
	if err := p.detectChainCycles(); err != nil {
		return nil, err
	}
	ops, err := p.orderOps()
	if err != nil {
		return nil, err
	}
	return &transactionPlan{
		ops:            ops,
		committedIndex: p.desired,
	}, nil
}

type planner struct {
	rs        *Ruleset
	committed *nameIndex
	desired   *nameIndex

	// chainEdges maps a chain key to the chain names it jumps/gotos to.
	chainEdges map[objectKey][]string
}

// indexDesired registers every Ruleset entity, rejecting duplicate names and
// references to unknown tables. The resulting index starts from a copy of the
// committed index; entries under managed tables that the Ruleset no longer
// contains are pruned so their absence means deletion.
func (p *planner) indexDesired() (*nameIndex, error) {
	desired := p.committed.clone()

	managedTables := map[tableKey]bool{}
	for _, t := range p.rs.Tables {
		if t == nil || t.Name == "" {
			return nil, fmt.Errorf("ApplyRuleset: table must have a name")
		}
		k := tableKey{family: t.Family, name: t.Name}
		if managedTables[k] {
			return nil, fmt.Errorf("ApplyRuleset: duplicate table %q in family %d", t.Name, t.Family)
		}
		desired.tables[k] = t
		managedTables[k] = true
	}

	register := func(k objectKey, payload any, label string) error {
		if e, ok := desired.entries[k]; ok && e.desired != nil {
			return fmt.Errorf("ApplyRuleset: duplicate %s", label)
		}
		e := &nameEntry{key: k, desired: payload}
		if prev, ok := desired.entries[k]; ok {
			e.committed = prev.committed
		}
		desired.entries[k] = e
		return nil
	}

	for _, c := range p.rs.Chains {
		if c == nil || c.Name == "" {
			return nil, fmt.Errorf("ApplyRuleset: chain must have a name")
		}
		t, err := p.requireTable(desired, c.Table)
		if err != nil {
			return nil, err
		}
		c.Table = t
		k := objectKey{family: t.Family, table: t.Name, kind: refChain, name: c.Name}
		if err := register(k, c, k.String()); err != nil {
			return nil, err
		}
	}

	for _, o := range p.rs.Objects {
		if o == nil || o.name() == "" {
			return nil, fmt.Errorf("ApplyRuleset: object must have a name")
		}
		t, err := p.requireTable(desired, o.table())
		if err != nil {
			return nil, err
		}
		k := objectKey{family: t.Family, table: t.Name, kind: refObject, name: o.name()}
		if err := register(k, o, k.String()); err != nil {
			return nil, err
		}
	}

	for _, s := range p.rs.Sets {
		if s == nil || s.Name == "" {
			return nil, fmt.Errorf("ApplyRuleset: set must have a name")
		}
		t, err := p.requireTable(desired, s.Table)
		if err != nil {
			return nil, err
		}
		s.Table = t
		k := objectKey{family: t.Family, table: t.Name, kind: refSet, name: s.Name}
		if err := register(k, s, k.String()); err != nil {
			return nil, err
		}
	}

	for _, f := range p.rs.Flowtables {
		if f == nil || f.Name == "" {
			return nil, fmt.Errorf("ApplyRuleset: flowtable must have a name")
		}
		t, err := p.requireTable(desired, f.Table)
		if err != nil {
			return nil, err
		}
		f.Table = t
		k := objectKey{family: t.Family, table: t.Name, kind: refFlowtable, name: f.Name}
		if err := register(k, f, k.String()); err != nil {
			return nil, err
		}
	}

	// Prune committed-only entities under managed tables: absence from the
	// Ruleset means they must be deleted. Entities under tables the Ruleset
	// does not manage are left untouched and stay resolvable.
	for k, e := range desired.entries {
		if e.desired != nil {
			continue
		}
		if managedTables[tableKey{family: k.family, name: k.table}] {
			delete(desired.entries, k)
		}
	}
	// desired.tables contains desired tables plus any committed tables the
	// Ruleset does not manage; the latter must remain resolvable, so no
	// pruning is needed here.
	return desired, nil
}

// requireTable resolves a table pointer to the authoritative desired or
// committed *Table, rejecting nil and unknown tables.
func (p *planner) requireTable(idx *nameIndex, t *Table) (*Table, error) {
	if t == nil || t.Name == "" {
		return nil, fmt.Errorf("ApplyRuleset: object references a table without a name")
	}
	k := tableKey{family: t.Family, name: t.Name}
	if resolved, ok := idx.tables[k]; ok {
		return resolved, nil
	}
	return nil, fmt.Errorf("ApplyRuleset: unknown table %q in family %d", t.Name, t.Family)
}

// resolveLink returns the entry for a referenced entity, accepting references
// that resolve to either a desired definition or a surviving committed one.
func (p *planner) resolveLink(k objectKey) (*nameEntry, error) {
	if e, ok := p.desired.entries[k]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("ApplyRuleset: unresolved reference to %s", k.String())
}

// resolveRules validates every rule: its table and chain must exist, and each
// expression-level reference must resolve to exactly one named entity. It also
// records the chain jump/goto graph for cycle detection.
func (p *planner) resolveRules() error {
	p.chainEdges = map[objectKey][]string{}
	for _, r := range p.rs.Rules {
		if r == nil {
			return fmt.Errorf("ApplyRuleset: ruleset contains a nil rule")
		}
		t, err := p.requireTable(p.desired, r.Table)
		if err != nil {
			return err
		}
		r.Table = t
		if r.Chain == nil || r.Chain.Name == "" {
			return fmt.Errorf("ApplyRuleset: rule must reference a chain")
		}
		chainKey := objectKey{family: t.Family, table: t.Name, kind: refChain, name: r.Chain.Name}
		entry, err := p.resolveLink(chainKey)
		if err != nil {
			return err
		}
		if entry.desired == nil {
			// A declarative rule can only live in a chain the Ruleset
			// explicitly manages; attaching rules to a chain that merely
			// survives from the committed state would make its rule list
			// ambiguous across reconciliations.
			return fmt.Errorf("ApplyRuleset: rule references chain %q which is not declared in the ruleset", r.Chain.Name)
		}
		r.Chain = entry.desired.(*Chain)

		for _, ref := range extractRuleReferences(r) {
			if _, err := p.resolveLink(ref); err != nil {
				return err
			}
			if ref.kind == refChain {
				p.chainEdges[chainKey] = append(p.chainEdges[chainKey], ref.name)
			}
		}
	}
	return nil
}

// detectChainCycles runs a DFS over the jump/goto graph and rejects any chain
// that can reach itself.
func (p *planner) detectChainCycles() error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[objectKey]int{}
	var stack []objectKey

	var visit func(k objectKey) error
	visit = func(k objectKey) error {
		switch color[k] {
		case gray:
			return fmt.Errorf("ApplyRuleset: circular chain reference: %s", cycleNames(append(append([]objectKey{}, stack...), k)))
		case black:
			return nil
		}
		color[k] = gray
		stack = append(stack, k)
		for _, name := range p.chainEdges[k] {
			next := objectKey{family: k.family, table: k.table, kind: refChain, name: name}
			if err := visit(next); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		color[k] = black
		return nil
	}

	keys := make([]objectKey, 0, len(p.chainEdges))
	for k := range p.chainEdges {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].table != keys[j].table {
			return keys[i].table < keys[j].table
		}
		return keys[i].name < keys[j].name
	})
	for _, k := range keys {
		if color[k] == white {
			if err := visit(k); err != nil {
				return err
			}
		}
	}
	return nil
}

func cycleNames(cycle []objectKey) string {
	out := ""
	for i, k := range cycle {
		if i > 0 {
			out += " -> "
		}
		out += k.name
	}
	return out
}

// orderOps turns the validated desired state into an ordered operation list.
//
// Deletions are emitted first in reverse dependency order: surviving chains
// lose their old rules, then removed objects/sets/flowtables/chains are
// released (their last reference having just disappeared), then removed
// tables. Creations follow in dependency order: tables, then their chains,
// objects, sets and flowtables, then the rules that reference them.
func (p *planner) orderOps() ([]plannedOp, error) {
	var ops []plannedOp

	managedTables := map[tableKey]bool{}
	for _, t := range p.rs.Tables {
		managedTables[tableKey{family: t.Family, name: t.Name}] = true
	}

	// ---- Phase 1: removals (reverse dependency order) ----

	// 1a. Flush the rules of every committed chain that survives, so its
	// rule list can be rebuilt from the Ruleset. Rules referencing objects
	// that are about to disappear are removed here, before those objects are
	// released in 1b.
	for k, e := range p.committed.entries {
		if k.kind != refChain || e.committed == nil {
			continue
		}
		if desired, ok := p.desired.entries[k]; ok && desired.desired != nil {
			ops = append(ops, plannedOp{kind: opFlushChain, chain: desired.desired.(*Chain)})
		}
	}

	// 1b. Delete committed-only entities under managed tables.
	var removedKeys []objectKey
	for k, e := range p.committed.entries {
		if e.committed == nil {
			continue
		}
		if !managedTables[tableKey{family: k.family, name: k.table}] {
			continue
		}
		if _, kept := p.desired.entries[k]; kept {
			continue
		}
		removedKeys = append(removedKeys, k)
	}
	sortObjectKeys(removedKeys)
	for _, k := range removedKeys {
		payload := p.committed.entries[k].committed
		switch k.kind {
		case refChain:
			ops = append(ops, plannedOp{kind: opDelChain, chain: payload.(*Chain)})
		case refObject:
			ops = append(ops, plannedOp{kind: opDelObject, obj: payload.(Obj)})
		case refSet:
			ops = append(ops, plannedOp{kind: opDelSet, set: payload.(*Set)})
		case refFlowtable:
			ops = append(ops, plannedOp{kind: opDelFlowtable, flowtable: payload.(*Flowtable)})
		}
	}

	// 1c. Delete committed-only tables last among removals.
	var removedTables []tableKey
	for k, t := range p.committed.tables {
		if t == nil || managedTables[k] {
			continue
		}
		removedTables = append(removedTables, k)
	}
	sort.Slice(removedTables, func(i, j int) bool {
		if removedTables[i].family != removedTables[j].family {
			return removedTables[i].family < removedTables[j].family
		}
		return removedTables[i].name < removedTables[j].name
	})
	for _, k := range removedTables {
		ops = append(ops, plannedOp{kind: opDelTable, table: p.committed.tables[k]})
	}

	// ---- Phase 2: creations (dependency order) ----

	// 2a. New tables first.
	for _, t := range p.rs.Tables {
		k := tableKey{family: t.Family, name: t.Name}
		if _, existed := p.committed.tables[k]; !existed {
			ops = append(ops, plannedOp{kind: opAddTable, table: t})
		}
	}

	// 2b. Non-rule entities per table, in chain/object/set/flowtable order
	// and stable name order within a kind. Each exists before the rules that
	// reference it are buffered in 2c.
	for _, t := range p.rs.Tables {
		ops = append(ops, p.entityOps(t, refChain, opAddChain)...)
		ops = append(ops, p.entityOps(t, refObject, opAddObject)...)
		ops = append(ops, p.entityOps(t, refSet, opAddSet)...)
		ops = append(ops, p.entityOps(t, refFlowtable, opAddFlowtable)...)
	}

	// 2c. Rules in slice order; AddRule appends within a chain and every
	// target chain already exists and (if it pre-existed) was flushed in 1a.
	for _, r := range p.rs.Rules {
		ops = append(ops, plannedOp{kind: opAddRule, rule: r})
	}

	return ops, nil
}

// entityOps emits creation operations for desired entities of one kind under
// a table, in name order. Entities already present in the committed index are
// skipped: their identity survives and stateful values (e.g. counter bytes)
// must not be reset by reconciliation; configuration changes to such entities
// go through the existing single-object APIs.
func (p *planner) entityOps(t *Table, kind refKind, addKind opKind) []plannedOp {
	var keys []objectKey
	for k, e := range p.desired.entries {
		if k.kind != kind || k.family != t.Family || k.table != t.Name || e.desired == nil {
			continue
		}
		if e.committed != nil {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })
	var out []plannedOp
	for _, k := range keys {
		payload := p.desired.entries[k].desired
		op := plannedOp{kind: addKind}
		switch kind {
		case refChain:
			op.chain = payload.(*Chain)
		case refObject:
			op.obj = payload.(Obj)
		case refSet:
			op.set = payload.(*Set)
		case refFlowtable:
			op.flowtable = payload.(*Flowtable)
		}
		out = append(out, op)
	}
	return out
}

func sortObjectKeys(keys []objectKey) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.table != b.table {
			return a.table < b.table
		}
		if a.family != b.family {
			return a.family < b.family
		}
		return a.name < b.name
	})
}
