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

import "fmt"

// bufferLocked translates the dependency-ordered plan into netlink messages on
// the Conn, reusing the existing single-object primitives so message encoding
// stays identical to the imperative API. It must be called with cc.mu held and
// before flush; no message is sent here.
func (plan *transactionPlan) bufferLocked(cc *Conn) error {
	for _, op := range plan.ops {
		switch op.kind {
		case opAddTable:
			cc.AddTable(op.table)
		case opDelTable:
			cc.DelTable(op.table)
		case opAddChain:
			cc.AddChain(op.chain)
		case opDelChain:
			cc.DelChain(op.chain)
		case opFlushChain:
			cc.FlushChain(op.chain)
		case opAddRule:
			// Reset identity fields so the rule is created fresh in this
			// transaction and gets a batch-local ID for any position refs.
			op.rule.Handle = 0
			op.rule.ID = 0
			cc.AddRule(op.rule)
		case opAddObject:
			cc.AddObj(op.obj)
		case opDelObject:
			cc.DeleteObject(op.obj)
		case opAddSet:
			// Set elements are declared separately through AddSet's values;
			// the declarative path creates the set itself here.
			if err := cc.AddSet(op.set, nil); err != nil {
				return fmt.Errorf("ApplyRuleset: adding set %q: %w", op.set.Name, err)
			}
		case opDelSet:
			cc.DelSet(op.set)
		case opAddFlowtable:
			cc.AddFlowtable(op.flowtable)
		case opDelFlowtable:
			cc.DelFlowtable(op.flowtable)
		default:
			return fmt.Errorf("ApplyRuleset: unsupported operation %d", op.kind)
		}
		if cc.err != nil {
			err := cc.err
			return fmt.Errorf("ApplyRuleset: buffering failed: %w", err)
		}
	}
	return nil
}
