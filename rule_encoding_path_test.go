package nftables

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
)

func TestNewRuleEncodingErrorHasPathAndNoBufferedMessage(t *testing.T) {
	t.Parallel()

	c := &Conn{}
	rule := &Rule{
		Table: &Table{Family: TableFamilyIPv4, Name: "filter"},
		Chain: &Chain{Name: "input"},
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Generic{
				Name: "broken-generic",
				Nodes: expr.GenericGroup{
					{
						Type: 1,
						Children: []expr.GenericNode{
							{Type: 2, Data: make([]byte, math.MaxUint16)},
						},
					},
				},
			},
		},
	}

	if got := c.AddRule(rule); got != rule {
		t.Fatal("AddRule did not return the rule pointer")
	}

	// The failing expression must not leave a half-assembled netlink message.
	if len(c.messages) != 0 {
		t.Fatalf("buffered %d messages after encoding failure, want 0", len(c.messages))
	}

	err := c.Flush()
	if err == nil {
		t.Fatal("Flush succeeded for an invalid expression")
	}
	for _, want := range []string{
		"rule.exprs[1]",
		"*expr.Generic",
		"broken-generic",
		"attrs[0].children[0]",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}

	var pathErr *expr.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("error %T does not contain *expr.PathError: %v", err, err)
	}
}
