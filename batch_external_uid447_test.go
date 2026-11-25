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

package nftables_test

import (
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

func TestUID447ExternalBatchLifecycle(t *testing.T) {
	c, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	b, err := c.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	b.AddTable(&nftables.Table{Name: "uid447_external", Family: nftables.TableFamilyIPv4})

	if err := c.Flush(); !errors.Is(err, nftables.ErrNestedCommit) {
		t.Fatalf("Flush during Begin = %v, want %v", err, nftables.ErrNestedCommit)
	}
	if err := b.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := b.Commit(); !errors.Is(err, nftables.ErrDuplicateCommit) {
		t.Fatalf("second Commit = %v, want duplicate commit error", err)
	}
}
