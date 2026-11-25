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

package expr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nlaHeaderLen = 4
	nlaAlignTo   = 4
	maxNLAData   = math.MaxUint16 - nlaHeaderLen
)

// PathError describes which node in a generic attribute tree could not be
// encoded. The path uses stable, zero-based indices such as
// attrs[0].children[2].
type PathError struct {
	// Path is the stable path to the failing node.
	Path string
	// NodePath is an alternative name for Path.
	NodePath string
	// Type is the netlink attribute type of the failing node, if known.
	Type uint16
	// Err is the underlying error.
	Err error
}

func (e *PathError) Error() string {
	if e.Type == 0 {
		return fmt.Sprintf("encoding netlink node %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("encoding netlink node %s (type=%#x): %v", e.Path, e.Type, e.Err)
}

func (e *PathError) Unwrap() error { return e.Err }

func newPathError(path string, attrType uint16, err error) *PathError {
	return &PathError{Path: path, NodePath: path, Type: attrType, Err: err}
}

// NodePathError is a descriptive alias for PathError.
type NodePathError = PathError

// Node is an explicitly ordered netlink attribute. Children, when non-nil,
// are encoded as the node's nested payload. The NLA_F_NESTED type flag is
// added automatically in that case.
type Node struct {
	Type     uint16
	Data     []byte
	Children []Node
}

// GenericAttr and GenericNode are descriptive aliases for Node.
type (
	GenericAttr      = Node
	GenericAttribute = Node
	GenericNode      = Node
	UnknownAttr      = Node
	UnknownAttribute = Node
	UnknownNode      = Node
	RawAttr          = Node
	RawAttribute     = Node
)

// Group is an ordered collection of netlink attributes.
type Group []Node

// GenericGroup is a descriptive alias for Group.
type GenericGroup = Group

// Generic is an expression whose concrete nftables type is not implemented by
// this package. It retains the expression name and ordered data attributes so
// that parsing and re-encoding do not silently discard information.
type Generic struct {
	// Name is the NFTA_EXPR_NAME value, without its trailing NUL.
	Name string

	// Attrs contains the raw NFTA_EXPR_DATA attributes in their original order.
	Attrs []netlink.Attribute

	// Attributes and RawAttributes are aliases for Attrs.
	Attributes    []netlink.Attribute
	RawAttributes []netlink.Attribute

	// Nodes is the ordered, recursively decoded representation of Attrs.
	Nodes Group

	// Children is an alias for Nodes.
	Children []Node

	// Group is an alternative name for Nodes.
	Group Group

	// GenericGroup is another alternative name for Nodes.
	GenericGroup Group

	// RawData contains the undecoded NFTA_EXPR_DATA payload.
	RawData []byte

	// Raw and Data are compatibility aliases for RawData.
	Raw  []byte
	Data []byte
}

// Unknown, Opaque and Raw are common alternative names for a generic/unknown
// expression.
type (
	Unknown           = Generic
	Opaque            = Generic
	Raw               = Generic
	UnknownExpr       = Generic
	GenericExpr       = Generic
	OpaqueExpr        = Generic
	RawExpr           = Generic
	UnknownExpression = Generic
	GenericExpression = Generic
	OpaqueExpression  = Generic
	RawExpression     = Generic
)

var (
	// ErrAttributeTooLarge is returned when an attribute payload cannot fit
	// in a uint16 nla_len field.
	ErrAttributeTooLarge = errors.New("netlink attribute data exceeds uint16 length")
	// ErrDataAndChildren is returned when a Node has both raw Data and nested
	// Children.
	ErrDataAndChildren = errors.New("node has both Data and Children")

	errAttrTooLarge    = ErrAttributeTooLarge
	errDataAndChildren = ErrDataAndChildren
)

// AlignLen returns n rounded up to the netlink NLA alignment boundary.
func AlignLen(n int) int {
	return (n + nlaAlignTo - 1) &^ (nlaAlignTo - 1)
}

// MarshalNode encodes one attribute, including its header and alignment
// padding. The returned slice is never partial when err is non-nil.
func MarshalNode(node Node) ([]byte, error) {
	return marshalNode(node, "attrs[0]")
}

// MarshalNodes encodes nodes as a netlink attribute stream.
func MarshalNodes(nodes []Node) ([]byte, error) {
	return marshalNodes(nodes, "attrs")
}

// MarshalGroup encodes an ordered generic group.
func MarshalGroup(group Group) ([]byte, error) {
	return marshalNodes([]Node(group), "attrs")
}

// Marshal encodes the group as a netlink attribute stream.
func (g Group) Marshal() ([]byte, error) {
	return MarshalGroup(g)
}

// Marshal encodes one node, including its netlink header and padding.
func (n Node) Marshal() ([]byte, error) {
	return MarshalNode(n)
}

// Nested wraps g as the payload of a nested attribute of attrType.
func (g Group) Nested(attrType uint16) Node {
	return Node{Type: attrType, Children: []Node(g)}
}

// MarshalGenericGroup is an alias for MarshalGroup.
func MarshalGenericGroup(group GenericGroup) ([]byte, error) {
	return MarshalGroup(group)
}

// MarshalAttributes deterministically encodes ordinary netlink attributes.
// Length fields are recalculated; callers do not need to initialize them.
func MarshalAttributes(attrs []netlink.Attribute) ([]byte, error) {
	nodes := make([]Node, len(attrs))
	for i, attr := range attrs {
		nodes[i] = Node{Type: attr.Type, Data: attr.Data}
	}
	return MarshalNodes(nodes)
}

// UnmarshalGroup decodes a netlink attribute stream into ordered Nodes.
// Attributes carrying NLA_F_NESTED are recursively decoded. If a nested
// attribute is malformed, its original Data is retained instead of losing the
// node.
func UnmarshalGroup(b []byte) (Group, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}
	return nodesFromAttributes(attrs), nil
}

func marshalNodes(nodes []Node, parentPath string) ([]byte, error) {
	var out []byte
	for i, node := range nodes {
		path := fmt.Sprintf("%s[%d]", parentPath, i)
		encoded, err := marshalNode(node, path)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	return out, nil
}

func marshalNode(node Node, path string) ([]byte, error) {
	if node.Children != nil && len(node.Data) != 0 {
		return nil, newPathError(path, node.Type, ErrDataAndChildren)
	}

	payload := node.Data
	attrType := node.Type
	if node.Children != nil {
		childPayload, err := marshalNodes(node.Children, path+".children")
		if err != nil {
			return nil, err
		}
		payload = childPayload
		attrType |= unix.NLA_F_NESTED
	}

	if len(payload) > maxNLAData {
		return nil, newPathError(path, node.Type, ErrAttributeTooLarge)
	}

	length := nlaHeaderLen + len(payload)
	out := make([]byte, 0, nlaHeaderLen+AlignLen(len(payload)))
	hdr := make([]byte, nlaHeaderLen)
	binary.NativeEndian.PutUint16(hdr[0:2], uint16(length))
	binary.NativeEndian.PutUint16(hdr[2:4], attrType)
	out = append(out, hdr...)
	out = append(out, payload...)
	if padding := AlignLen(len(payload)) - len(payload); padding > 0 {
		out = append(out, make([]byte, padding)...)
	}
	return out, nil
}

func nodesFromAttributes(attrs []netlink.Attribute) Group {
	nodes := make(Group, 0, len(attrs))
	for _, attr := range attrs {
		node := Node{Type: attr.Type}
		if attr.Type&unix.NLA_F_NESTED != 0 {
			if children, err := UnmarshalGroup(attr.Data); err == nil {
				node.Children = []Node(children)
			} else {
				node.Data = append([]byte(nil), attr.Data...)
			}
		} else {
			node.Data = append([]byte(nil), attr.Data...)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func (e *Generic) normalizeAttrs() []netlink.Attribute {
	switch {
	case e.Attrs != nil:
		return e.Attrs
	case e.Attributes != nil:
		return e.Attributes
	case e.RawAttributes != nil:
		return e.RawAttributes
	default:
		return nil
	}
}

func (e *Generic) rawPayload() []byte {
	switch {
	case e.RawData != nil:
		return e.RawData
	case e.Raw != nil:
		return e.Raw
	case e.Data != nil:
		return e.Data
	default:
		return nil
	}
}

func (e *Generic) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	if e.Name == "" {
		return nil, newPathError("generic.name", 0, errors.New("expression name is required"))
	}
	name := []byte(e.Name)
	if len(name) == 0 || name[len(name)-1] != 0 {
		name = append(name, 0)
	}
	if len(name) > maxNLAData || len(data) > maxNLAData {
		return nil, newPathError("generic.data", 0, ErrAttributeTooLarge)
	}
	encoded, err := MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: name},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
	if err != nil {
		return nil, fmt.Errorf("generic expression %q: %w", e.Name, err)
	}
	return encoded, nil
}

func (e *Generic) marshalData(fam byte) ([]byte, error) {
	var (
		b     []byte
		err   error
		nodes = e.Nodes
		attrs = e.normalizeAttrs()
	)
	if nodes == nil && e.Children != nil {
		nodes = Group(e.Children)
	}
	if nodes == nil {
		nodes = e.Group
	}
	if nodes == nil {
		nodes = e.GenericGroup
	}
	// Prefer the recursive representation because it carries explicit nesting.
	switch {
	case nodes != nil:
		b, err = MarshalGroup(nodes)
	case attrs != nil:
		b, err = MarshalAttributes(attrs)
	default:
		if raw := e.rawPayload(); raw != nil {
			// RawData is already an NFTA_EXPR_DATA attribute stream.
			b = append([]byte(nil), raw...)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("generic expression %q data: %w", e.Name, err)
	}
	if len(b) > maxNLAData {
		return nil, newPathError(
			"generic.data",
			0,
			fmt.Errorf("%w: NFTA_EXPR_DATA is %d bytes", ErrAttributeTooLarge, len(b)),
		)
	}
	return b, nil
}

func (e *Generic) unmarshal(fam byte, data []byte) error {
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	clonedAttrs := append([]netlink.Attribute(nil), attrs...)
	e.Attrs = clonedAttrs
	e.Attributes = clonedAttrs
	e.RawAttributes = clonedAttrs
	decodedNodes := nodesFromAttributes(attrs)
	e.Nodes = decodedNodes
	e.Children = []Node(decodedNodes)
	e.Group = decodedNodes
	e.GenericGroup = decodedNodes
	raw := append([]byte(nil), data...)
	e.RawData = raw
	e.Raw = raw
	e.Data = raw
	return nil
}
