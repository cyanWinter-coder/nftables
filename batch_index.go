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

// localObjectKind identifies the type of an object in Conn's rollback-safe
// local index.
type localObjectKind string

const (
	localObjectTable     localObjectKind = "table"
	localObjectChain     localObjectKind = "chain"
	localObjectRule      localObjectKind = "rule"
	localObjectSet       localObjectKind = "set"
	localObjectObj       localObjectKind = "object"
	localObjectFlowtable localObjectKind = "flowtable"
)

// localObjectKey is the smallest stable identity used by the local index.
// Named kernel objects use family/table/name; rules have no stable name and use
// their caller pointer as ref until a kernel handle is published.
type localObjectKey struct {
	kind   localObjectKind
	family TableFamily
	table  string
	name   string
	ref    any
}

// localObjectIndex stores optimistic local object state. The map is replaced
// with its pre-batch snapshot if commit fails.
type localObjectIndex struct {
	objects map[localObjectKey]any
}

func newLocalObjectIndex() *localObjectIndex {
	return &localObjectIndex{objects: make(map[localObjectKey]any)}
}

func (idx *localObjectIndex) clone() *localObjectIndex {
	cp := newLocalObjectIndex()
	if idx == nil {
		return cp
	}
	for k, v := range idx.objects {
		cp.objects[k] = v
	}
	return cp
}

// rollbackState contains everything needed to undo optimistic local state from
// the beginning of the current implicit or explicit batch.
type rollbackState struct {
	index          *localObjectIndex
	pendingDeletes map[localObjectKey]any
	tracked        map[any]struct{}
	identities     []func()
}

func clonePendingDeletes(in map[localObjectKey]any) map[localObjectKey]any {
	out := make(map[localObjectKey]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (cc *Conn) localIndexLocked() *localObjectIndex {
	if cc.localIndex == nil {
		cc.localIndex = newLocalObjectIndex()
	}
	return cc.localIndex
}

func (cc *Conn) pendingDeletesLocked() map[localObjectKey]any {
	if cc.pendingDeletes == nil {
		cc.pendingDeletes = make(map[localObjectKey]any)
	}
	return cc.pendingDeletes
}

// beginChangeLocked lazily captures the committed-state snapshot before the
// first optimistic mutation in a batch.
func (cc *Conn) beginChangeLocked() *rollbackState {
	if cc.rollback == nil {
		cc.rollback = &rollbackState{
			index:          cc.localIndexLocked().clone(),
			pendingDeletes: clonePendingDeletes(cc.pendingDeletes),
			tracked:        make(map[any]struct{}),
		}
	}
	return cc.rollback
}

// trackIdentityLocked records an undo function for a caller-visible object.
// The same pointer is snapshotted only once per batch, preserving its state
// immediately before the first mutation.
func (cc *Conn) trackIdentityLocked(target any, restore func()) {
	rb := cc.beginChangeLocked()
	if target != nil {
		if _, ok := rb.tracked[target]; ok {
			return
		}
		rb.tracked[target] = struct{}{}
	}
	rb.identities = append(rb.identities, restore)
}

func (cc *Conn) indexUpsertLocked(key localObjectKey, value any) {
	cc.beginChangeLocked()
	cc.localIndexLocked().objects[key] = value
	delete(cc.pendingDeletesLocked(), key)
}

func (cc *Conn) indexDeleteLocked(key localObjectKey, value any) {
	cc.beginChangeLocked()
	idx := cc.localIndexLocked()
	if existing, ok := idx.objects[key]; ok {
		value = existing
	}
	cc.pendingDeletesLocked()[key] = value
	delete(idx.objects, key)
}

// commitLocalChangesLocked drops rollback snapshots and pending deletions
// after a successful kernel commit. Optimistic index entries become committed
// local state.
func (cc *Conn) commitLocalChangesLocked() {
	cc.rollback = nil
	cc.pendingDeletes = nil
}

// rollbackChangesLocked restores the local index, pending deletions and object
// identities captured before the batch. Buffered netlink messages and sticky
// marshal errors are discarded as part of the same rollback.
func (cc *Conn) rollbackChangesLocked() {
	if rb := cc.rollback; rb != nil {
		for i := len(rb.identities) - 1; i >= 0; i-- {
			rb.identities[i]()
		}
		cc.localIndex = rb.index
		cc.pendingDeletes = rb.pendingDeletes
		cc.rollback = nil
	}
	cc.messages = nil
	cc.err = nil
	cc.allocatedIDs = 0
}

func tableLocalKey(t *Table) localObjectKey {
	k := localObjectKey{kind: localObjectTable}
	if t != nil {
		k.family = t.Family
		k.name = t.Name
	}
	return k
}

func chainLocalKey(c *Chain) localObjectKey {
	k := localObjectKey{kind: localObjectChain}
	if c != nil {
		k.name = c.Name
		if c.Table != nil {
			k.family = c.Table.Family
			k.table = c.Table.Name
		}
	}
	return k
}

func ruleLocalKey(r *Rule) localObjectKey {
	k := localObjectKey{kind: localObjectRule, ref: r}
	if r != nil {
		if r.Table != nil {
			k.family = r.Table.Family
			k.table = r.Table.Name
		}
		if r.Chain != nil {
			k.name = r.Chain.Name
		}
	}
	return k
}

func setLocalKey(s *Set) localObjectKey {
	k := localObjectKey{kind: localObjectSet, ref: s}
	if s != nil {
		k.name = s.Name
		if s.Table != nil {
			k.family = s.Table.Family
			k.table = s.Table.Name
		}
	}
	return k
}

func objLocalKey(o Obj) localObjectKey {
	k := localObjectKey{kind: localObjectObj, ref: o}
	if o != nil {
		k.family = o.family()
		k.name = o.name()
		if t := o.table(); t != nil {
			k.table = t.Name
		}
	}
	return k
}

func flowtableLocalKey(f *Flowtable) localObjectKey {
	k := localObjectKey{kind: localObjectFlowtable, ref: f}
	if f != nil {
		k.name = f.Name
		if f.Table != nil {
			k.family = f.Table.Family
			k.table = f.Table.Name
		}
	}
	return k
}
