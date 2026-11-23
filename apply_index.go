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

// indexChangeKind enumerates the deferred name-index mutations that the
// single-object APIs record while buffering messages. They are applied to the
// committed index only after a successful Flush, never while buffering.
type indexChangeKind int

const (
	indexUpsert indexChangeKind = iota
	indexDelete
)

// indexChange is one deferred mutation of the local name index.
type indexChange struct {
	kind    indexChangeKind
	table   tableKey  // set for table changes
	objKey  objectKey // set for non-table entity changes
	isTable bool
	payload any
}

// trackIndexUpsert records that a named entity is being created or replaced.
// It must be called with cc.mu held, from a buffering primitive.
func (cc *Conn) trackIndexUpsert(k objectKey, payload any) {
	cc.pendingIndex = append(cc.pendingIndex, indexChange{
		kind:    indexUpsert,
		objKey:  k,
		payload: payload,
	})
}

// trackIndexTableUpsert records a table creation.
func (cc *Conn) trackIndexTableUpsert(k tableKey, payload *Table) {
	cc.pendingIndex = append(cc.pendingIndex, indexChange{
		kind:    indexUpsert,
		table:   k,
		isTable: true,
		payload: payload,
	})
}

// trackIndexDelete records the deletion of a named entity.
func (cc *Conn) trackIndexDelete(k objectKey) {
	cc.pendingIndex = append(cc.pendingIndex, indexChange{
		kind:   indexDelete,
		objKey: k,
	})
}

// trackIndexTableDelete records a table deletion.
func (cc *Conn) trackIndexTableDelete(k tableKey) {
	cc.pendingIndex = append(cc.pendingIndex, indexChange{
		kind:    indexDelete,
		table:   k,
		isTable: true,
	})
}

// applyPendingIndexLocked folds the deferred single-object mutations into the
// committed index. It must be called with cc.mu held and only once the
// containing batch has been flushed successfully.
func (cc *Conn) applyPendingIndexLocked() {
	if len(cc.pendingIndex) == 0 {
		return
	}
	if cc.nameIdx == nil {
		cc.nameIdx = newNameIndex()
	}
	for _, ch := range cc.pendingIndex {
		switch {
		case ch.isTable:
			if ch.kind == indexDelete {
				delete(cc.nameIdx.tables, ch.table)
				// A table takes every entity it contains with it.
				for k := range cc.nameIdx.entries {
					if k.family == ch.table.family && k.table == ch.table.name {
						delete(cc.nameIdx.entries, k)
					}
				}
				continue
			}
			cc.nameIdx.tables[ch.table] = ch.payload.(*Table)
		default:
			if ch.kind == indexDelete {
				delete(cc.nameIdx.entries, ch.objKey)
				continue
			}
			cc.nameIdx.entries[ch.objKey] = &nameEntry{key: ch.objKey, committed: ch.payload}
		}
	}
	cc.pendingIndex = nil
}

// committedNameIndexLocked returns a snapshot index that includes the last
// committed state and the buffered single-object changes, so a declarative
// transaction resolves against everything the caller has staged so far. It
// must be called with cc.mu held.
func (cc *Conn) committedNameIndexLocked() *nameIndex {
	if cc.nameIdx == nil {
		cc.nameIdx = newNameIndex()
	}
	view := cc.nameIdx.clone()
	for _, ch := range cc.pendingIndex {
		switch {
		case ch.isTable:
			if ch.kind == indexDelete {
				delete(view.tables, ch.table)
				for k := range view.entries {
					if k.family == ch.table.family && k.table == ch.table.name {
						delete(view.entries, k)
					}
				}
				continue
			}
			view.tables[ch.table] = ch.payload.(*Table)
		default:
			if ch.kind == indexDelete {
				delete(view.entries, ch.objKey)
				continue
			}
			view.entries[ch.objKey] = &nameEntry{key: ch.objKey, committed: ch.payload}
		}
	}
	return view
}

// snapshotPendingLocked returns a copy of buffered index changes so a failed
// declarative batch can leave the caller's staged work exactly as it was.
func (cc *Conn) snapshotPendingLocked() []indexChange {
	saved := make([]indexChange, len(cc.pendingIndex))
	copy(saved, cc.pendingIndex)
	return saved
}

// commitNameIndexLocked publishes an index describing freshly committed
// state. It must be called with cc.mu held and only after a successful flush,
// so a half-applied state can never become visible. Desired pointers are
// folded into committed pointers, since a published index only records what
// has actually been committed.
func (cc *Conn) commitNameIndexLocked(idx *nameIndex) {
	for _, e := range idx.entries {
		if e.desired != nil {
			e.committed = e.desired
			e.desired = nil
		}
	}
	cc.nameIdx = idx
	cc.pendingIndex = nil
}
