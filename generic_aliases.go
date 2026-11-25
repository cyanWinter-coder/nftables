package nftables

import "github.com/google/nftables/expr"

// Re-export the deterministic generic attribute API from the expression
// package so callers can discover it alongside Rule encoding.
type (
	PathError     = expr.PathError
	NodePathError = expr.NodePathError

	Node             = expr.Node
	GenericNode      = expr.GenericNode
	GenericAttribute = expr.GenericAttribute
	UnknownNode      = expr.UnknownNode

	Group        = expr.Group
	GenericGroup = expr.GenericGroup

	Generic           = expr.Generic
	Unknown           = expr.Unknown
	Opaque            = expr.Opaque
	Raw               = expr.Raw
	GenericExpr       = expr.GenericExpr
	UnknownExpr       = expr.UnknownExpr
	RawExpr           = expr.RawExpr
	GenericExpression = expr.GenericExpression
	UnknownExpression = expr.UnknownExpression
	OpaqueExpression  = expr.OpaqueExpression
	RawExpression     = expr.RawExpression
)

// MarshalGenericGroup deterministically encodes a generic attribute group.
func MarshalGenericGroup(group GenericGroup) ([]byte, error) {
	return expr.MarshalGenericGroup(group)
}
