package expr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestMarshalGroupAlignmentAndLengths(t *testing.T) {
	t.Parallel()

	got, err := MarshalGroup(Group{
		{Type: 1, Data: []byte{0xaa}},
		{Type: 2, Data: []byte{0x01, 0x02, 0x03}},
		{Type: 3, Data: []byte{0x01, 0x02, 0x03, 0x04}},
		{Type: 4, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	})
	if err != nil {
		t.Fatalf("MarshalGroup: %v", err)
	}

	want := []byte{
		// nla_len=5 (header + one data byte), followed by three padding bytes.
		0x05, 0x00, 0x01, 0x00, 0xaa, 0x00, 0x00, 0x00,
		// nla_len=7, followed by one padding byte.
		0x07, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x00,
		// nla_len=8, no padding.
		0x08, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
		// nla_len=9, followed by three padding bytes.
		0x09, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("aligned group mismatch:\ngot  % x\nwant % x", got, want)
	}

	ad, err := netlink.NewAttributeDecoder(got)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for ad.Next() {
		count++
		if got, want := len(ad.Bytes()), []int{1, 3, 4, 5}[count-1]; got != want {
			t.Fatalf("attr %d data length = %d, want %d", count, got, want)
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("decoded %d attrs, want 4", count)
	}
}

func TestMarshalGroupNestedLengthIsActualContent(t *testing.T) {
	t.Parallel()

	got, err := MarshalNode(Node{
		Type: 42,
		Children: []Node{
			{Type: 1, Data: []byte{0xaa}},
		},
	})
	if err != nil {
		t.Fatalf("MarshalNode: %v", err)
	}

	// The child has nla_len=5 and three alignment bytes, so its encoded stream
	// occupies eight bytes. The nested attribute's nla_len is header(4)+8=12;
	// it must not add another alignment adjustment to nla_len.
	want := []byte{
		0x0c, 0x00, 0x2a, 0x80,
		0x05, 0x00, 0x01, 0x00, 0xaa, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("nested attr mismatch:\ngot  % x\nwant % x", got, want)
	}
	if binary.NativeEndian.Uint16(got[:2]) != 12 {
		t.Fatalf("nested nla_len = %d, want 12", binary.NativeEndian.Uint16(got[:2]))
	}
	if binary.NativeEndian.Uint16(got[2:4])&unix.NLA_F_NESTED == 0 {
		t.Fatalf("NLA_F_NESTED not set: % x", got[:4])
	}
}

func TestGenericDeepNestingRoundTrip(t *testing.T) {
	t.Parallel()

	const depth = 64
	root := Node{Type: 1, Data: []byte("leaf")}
	path := "attrs[0]"
	for i := 0; i < depth; i++ {
		root = Node{Type: uint16(100 + i), Children: []Node{root}}
		path += ".children[0]"
	}

	b, err := MarshalNode(root)
	if err != nil {
		t.Fatalf("MarshalNode depth %d: %v", depth, err)
	}
	if len(b) == 0 {
		t.Fatal("MarshalNode returned empty bytes")
	}

	decoded, err := UnmarshalGroup(b)
	if err != nil {
		t.Fatalf("UnmarshalGroup: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded %d root nodes, want 1", len(decoded))
	}

	node := decoded[0]
	for i := 0; i < depth; i++ {
		wantType := uint16(100 + (depth - 1 - i))
		if node.Type&^unix.NLA_F_NESTED != wantType {
			t.Fatalf("depth %d type = %#x, want %d", i, node.Type, wantType)
		}
		if len(node.Children) != 1 {
			t.Fatalf("depth %d has %d children, want 1", i, len(node.Children))
		}
		node = node.Children[0]
	}
	if string(node.Data) != "leaf" {
		t.Fatalf("leaf data = %q, want leaf", node.Data)
	}

	// Re-encoding must be deterministic.
	again, err := MarshalNode(decoded[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, again) {
		t.Fatalf("deep nesting re-encoding differs:\nfirst  % x\nsecond % x", b, again)
	}
}

func TestMarshalNilExpressionHasPath(t *testing.T) {
	t.Parallel()

	b, err := Marshal(0, nil)
	if err == nil || b != nil {
		t.Fatalf("Marshal(nil) = %d bytes, %v; want nil and error", len(b), err)
	}
	var pathErr *PathError
	if !errors.As(err, &pathErr) || pathErr.Path != "expr" {
		t.Fatalf("error = %v, want PathError at expr", err)
	}
}

func TestMarshalNodeLengthBoundaries(t *testing.T) {
	t.Parallel()

	maxData := make([]byte, maxNLAData)
	b, err := MarshalNode(Node{Type: 1, Data: maxData})
	if err != nil {
		t.Fatalf("MarshalNode at maximum length: %v", err)
	}
	if got := binary.NativeEndian.Uint16(b[:2]); got != math.MaxUint16 {
		t.Fatalf("maximum nla_len = %d, want %d", got, math.MaxUint16)
	}
	if want := nlaHeaderLen + AlignLen(maxNLAData); len(b) != want {
		t.Fatalf("encoded length = %d, want padded total %d", len(b), want)
	}

	if _, err := MarshalNode(Node{Type: 1, Data: make([]byte, maxNLAData+1)}); err == nil {
		t.Fatal("expected data larger than uint16 attribute length to fail")
	}
}

func TestMarshalGroupErrorPath(t *testing.T) {
	t.Parallel()

	_, err := MarshalGroup(Group{
		{Type: 1, Data: []byte("ok")},
		{
			Type: 2,
			Children: []Node{
				{Type: 3, Data: make([]byte, math.MaxUint16)},
			},
		},
	})
	if err == nil {
		t.Fatal("expected oversized attribute error")
	}

	var pathErr *PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("error type %T, want *PathError: %v", err, err)
	}
	if want := "attrs[1].children[0]"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain path %q", err.Error(), want)
	}
	if pathErr.NodePath != pathErr.Path || pathErr.Path != "attrs[1].children[0]" {
		t.Fatalf("path fields = %q/%q, want attrs[1].children[0]", pathErr.Path, pathErr.NodePath)
	}
	if !errors.Is(err, errAttrTooLarge) {
		t.Fatalf("error %v does not wrap errAttrTooLarge", err)
	}

	// A failed top-level marshal must not return a partially assembled buffer.
	b, err := MarshalNode(Node{Type: 1, Data: make([]byte, math.MaxUint16)})
	if err == nil || b != nil {
		t.Fatalf("MarshalNode = %d bytes, %v; want nil bytes and error", len(b), err)
	}
}

func TestUnknownExpressionPreservesAttributes(t *testing.T) {
	t.Parallel()

	dataAttrs := []netlink.Attribute{
		{Type: 1, Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Type: unix.NLA_F_NESTED | 2, Data: mustMarshalAttrs(t, []netlink.Attribute{
			{Type: 1, Data: []byte{0x01}},
			{Type: 2, Data: []byte("two")},
		})},
		{Type: 3, Data: []byte("tail")},
	}
	data, err := netlink.MarshalAttributes(dataAttrs)
	if err != nil {
		t.Fatal(err)
	}
	exprBytes, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("future-expr\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
	if err != nil {
		t.Fatal(err)
	}
	listElem, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: exprBytes},
	})
	if err != nil {
		t.Fatal(err)
	}

	ad, err := netlink.NewAttributeDecoder(listElem)
	if err != nil {
		t.Fatal(err)
	}
	if !ad.Next() {
		t.Fatalf("no list element: %v", ad.Err())
	}
	parsed, err := exprsFromBytes(unix.NFPROTO_IPV4, ad)
	if err != nil {
		t.Fatalf("exprsFromBytes: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed %d expressions, want 1", len(parsed))
	}
	unknown, ok := parsed[0].(*Unknown)
	if !ok {
		t.Fatalf("parsed expression type %T, want *expr.Unknown", parsed[0])
	}
	if unknown.Name != "future-expr" {
		t.Fatalf("name = %q, want future-expr", unknown.Name)
	}
	if len(unknown.Attrs) != len(dataAttrs) {
		t.Fatalf("got %d attrs, want %d", len(unknown.Attrs), len(dataAttrs))
	}
	for i := range dataAttrs {
		if unknown.Attrs[i].Type != dataAttrs[i].Type {
			t.Fatalf("attr %d type = %#x, want %#x", i, unknown.Attrs[i].Type, dataAttrs[i].Type)
		}
		if !bytes.Equal(unknown.Attrs[i].Data, dataAttrs[i].Data) {
			t.Fatalf("attr %d data = % x, want % x", i, unknown.Attrs[i].Data, dataAttrs[i].Data)
		}
	}
	if len(unknown.Nodes) != 3 || len(unknown.Nodes[1].Children) != 2 {
		t.Fatalf("recursive nodes not preserved: %#v", unknown.Nodes)
	}

	encoded, err := Marshal(unix.NFPROTO_IPV4, unknown)
	if err != nil {
		t.Fatalf("Marshal unknown: %v", err)
	}
	reparsed, err := exprsFromBytes(unix.NFPROTO_IPV4, mustDecoder(t, encodedAsListElem(t, encoded)))
	if err != nil {
		t.Fatalf("reparse encoded unknown: %v", err)
	}
	if len(reparsed) != 1 {
		t.Fatalf("reparsed %d expressions, want 1", len(reparsed))
	}
	reUnknown := reparsed[0].(*Unknown)
	if reUnknown.Name != unknown.Name || !reflect.DeepEqual(reUnknown.Attrs, unknown.Attrs) {
		t.Fatalf("round trip changed unknown expression:\n%#v\n%#v", unknown, reUnknown)
	}
}

func TestKnownExpressionAttributeOrderStable(t *testing.T) {
	t.Parallel()

	cmp := &Cmp{Op: CmpOpEq, Register: 1, Data: []byte{6}}
	bitwise := &Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            4,
		Mask:           []byte{0xff, 0xff, 0xff, 0xff},
		Xor:            []byte{0, 0, 0, 0},
	}
	ct := &Ct{Key: CtKeyMARK, Register: 1}

	wantOrders := [][]uint16{
		{unix.NFTA_CMP_SREG, unix.NFTA_CMP_OP, unix.NFTA_CMP_DATA},
		{unix.NFTA_BITWISE_SREG, unix.NFTA_BITWISE_DREG, unix.NFTA_BITWISE_LEN, unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR},
		{unix.NFTA_CT_KEY, unix.NFTA_CT_DREG},
	}
	for i, e := range []Any{cmp, bitwise, ct} {
		first, err := Marshal(unix.NFPROTO_IPV4, e)
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < 32; n++ {
			next, err := Marshal(unix.NFPROTO_IPV4, e)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, next) {
				t.Fatalf("expression %d marshal iteration %d differs", i, n)
			}
		}
		data := exprDataBytes(t, first)
		if got := attrTypes(t, data); !reflect.DeepEqual(got, wantOrders[i]) {
			t.Fatalf("expression %d attr order = %v, want %v", i, got, wantOrders[i])
		}
	}

	// The order of expressions in a comparison/bitwise/conntrack chain must
	// also remain stable.
	chain := []Any{cmp, bitwise, ct, cmp, ct}
	var first []byte
	for _, e := range chain {
		b, err := Marshal(unix.NFPROTO_IPV4, e)
		if err != nil {
			t.Fatal(err)
		}
		first = append(first, b...)
	}
	for n := 0; n < 32; n++ {
		var next []byte
		for _, e := range chain {
			b, err := Marshal(unix.NFPROTO_IPV4, e)
			if err != nil {
				t.Fatal(err)
			}
			next = append(next, b...)
		}
		if !bytes.Equal(first, next) {
			t.Fatal("expression combination order/bytes are not deterministic")
		}
	}
}

func TestCtTimeoutPolicyOrderDeterministic(t *testing.T) {
	t.Parallel()

	e := &CtTimeout{L4Proto: unix.IPPROTO_TCP}
	first, err := e.marshalData(unix.NFPROTO_IPV4)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		next, err := e.marshalData(unix.NFPROTO_IPV4)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("CtTimeout marshal iteration %d differs:\n%s", i, ctPolicyOrderDiff(first, next))
		}
	}

	var attrs []netlink.Attribute
	ad, err := netlink.NewAttributeDecoder(first)
	if err != nil {
		t.Fatal(err)
	}
	for ad.Next() {
		if ad.Type() == NFTA_CT_TIMEOUT_DATA {
			policyAttrs, err := netlink.UnmarshalAttributes(ad.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			attrs = policyAttrs
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	if len(attrs) != len(CtStateTCPTimeoutDefaults) {
		t.Fatalf("decoded %d policy attrs, want %d", len(attrs), len(CtStateTCPTimeoutDefaults))
	}
	for i := 1; i < len(attrs); i++ {
		if attrs[i-1].Type >= attrs[i].Type {
			t.Fatalf("policy attrs not sorted at %d: types %d then %d", i, attrs[i-1].Type, attrs[i].Type)
		}
	}
}

func TestUnknownMarshalFromAlternativeRepresentations(t *testing.T) {
	t.Parallel()

	attrStream := mustMarshalAttrs(t, []netlink.Attribute{{Type: 1, Data: []byte{0x01}}})

	fromAttributes := &Unknown{Name: "a", Attributes: []netlink.Attribute{{Type: 1, Data: []byte{0x01}}}}
	got, err := fromAttributes.marshalData(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, attrStream) {
		t.Fatalf("Attributes encoding = % x, want % x", got, attrStream)
	}

	fromRaw := &Unknown{Name: "b", Data: attrStream}
	got, err = fromRaw.marshalData(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, attrStream) {
		t.Fatalf("Data encoding = % x, want % x", got, attrStream)
	}

	_, err = Marshal(0, &Unknown{Attrs: []netlink.Attribute{}})
	if err == nil || !strings.Contains(err.Error(), "generic.name") {
		t.Fatalf("empty name error = %v, want generic.name path", err)
	}
}

func TestUnknownMalformedNestedAttributeRetainsRawData(t *testing.T) {
	t.Parallel()

	raw := []byte{0xff, 0x00, 0x01} // fewer than NLA header bytes
	nodes := nodesFromAttributes([]netlink.Attribute{
		{Type: unix.NLA_F_NESTED | 7, Data: raw},
	})
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
	if nodes[0].Children != nil {
		t.Fatalf("malformed node unexpectedly decoded as children: %#v", nodes[0].Children)
	}
	if !bytes.Equal(nodes[0].Data, raw) {
		t.Fatalf("raw nested data = % x, want % x", nodes[0].Data, raw)
	}
}

func TestExprsFromBytesNotrackRemainsSingle(t *testing.T) {
	t.Parallel()

	exprBytes := mustMarshalAttrs(t, []netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("notrack\x00")},
	})
	ad := mustDecoder(t, encodedAsListElem(t, exprBytes))
	parsed, err := exprsFromBytes(unix.NFPROTO_IPV4, ad)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed %d expressions, want 1", len(parsed))
	}
	if _, ok := parsed[0].(*Notrack); !ok {
		t.Fatalf("parsed type %T, want *Notrack", parsed[0])
	}
}

func TestCtTimeoutUnmarshalDoesNotMutateDefaults(t *testing.T) {
	key := uint16(CtStateUDPUNREPLIED)
	originalDefault := CtStateUDPTimeoutDefaults[key]

	e := &CtTimeout{
		L4Proto: unix.IPPROTO_UDP,
		Policy:  CtStatePolicyTimeout{key: originalDefault + 1234},
	}
	b, err := e.marshalData(unix.NFPROTO_IPV4)
	if err != nil {
		t.Fatal(err)
	}

	var got CtTimeout
	if err := got.unmarshal(unix.NFPROTO_IPV4, b); err != nil {
		t.Fatal(err)
	}
	if got.Policy[key] != originalDefault+1234 {
		t.Fatalf("decoded timeout = %d, want %d", got.Policy[key], originalDefault+1234)
	}
	if CtStateUDPTimeoutDefaults[key] != originalDefault {
		t.Fatalf("global default mutated to %d, want %d", CtStateUDPTimeoutDefaults[key], originalDefault)
	}
}

func mustMarshalAttrs(t *testing.T, attrs []netlink.Attribute) []byte {
	t.Helper()
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDecoder(t *testing.T, b []byte) *netlink.AttributeDecoder {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		t.Fatal(err)
	}
	if !ad.Next() {
		t.Fatalf("decoder has no attribute: %v", ad.Err())
	}
	return ad
}

func encodedAsListElem(t *testing.T, exprBytes []byte) []byte {
	t.Helper()
	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: exprBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exprDataBytes(t *testing.T, exprBytes []byte) []byte {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(exprBytes)
	if err != nil {
		t.Fatal(err)
	}
	for ad.Next() {
		if ad.Type() == unix.NFTA_EXPR_DATA {
			return ad.Bytes()
		}
	}
	t.Fatal("NFTA_EXPR_DATA not found")
	return nil
}

func attrTypes(t *testing.T, b []byte) []uint16 {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		t.Fatal(err)
	}
	var types []uint16
	for ad.Next() {
		types = append(types, ad.Type())
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	return types
}

func ctPolicyOrderDiff(a, b []byte) string {
	return fmt.Sprintf("first  % x\nsecond % x", a, b)
}
