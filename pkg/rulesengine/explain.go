package evaluator

import "strings"

// AUX-19 (rules preview): read-only helpers that let the admin console show
// HOW a candidate expression evaluates without duplicating the grammar. The
// authoritative verdict always comes from Snapshot.Evaluate — the traces here
// are descriptive only and never decide anything.

// TermTrace is the per-clause result of one parsed comparison: the clause as
// written, the actual field value it was evaluated against, and whether the
// clause matched. Actual values originate from the caller-supplied sample, so
// echoing them back leaks nothing.
type TermTrace struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Actual   string `json:"actual"`
	Matched  bool   `json:"matched"`
}

// ExprParses reports whether a match expression compiles to an AST, using the
// same parser the gateway snapshot compiler runs. An expression that fails
// this check is stored as a nil AST in a Snapshot: it never matches and never
// panics (RT-01) — preview surfaces it as an explicit machine-readable error
// instead of a silent never-match.
func ExprParses(expr string) bool {
	return parseExpression(expr) != nil
}

// TraceTerms evaluates every comparison clause of expr against ctx and returns
// the per-clause results in evaluation order (left to right, depth first).
// Unknown fields report an empty actual value; a clause-level trace never
// short-circuits, so the operator precedence picture stays complete. Use
// Snapshot.Evaluate for the verdict — this is the explanation, not the ruling.
func TraceTerms(expr string, ctx Context, modelRequested string) []TermTrace {
	n := parseExpression(expr)
	if n == nil {
		return nil
	}
	var terms []TermTrace
	traceNode(n, ctx, modelRequested, &terms)
	return terms
}

func traceNode(n node, ctx Context, modelRequested string, out *[]TermTrace) {
	switch t := n.(type) {
	case *compareNode:
		fm := fieldMap(ctx, modelRequested)
		actual := fm[t.field] // unknown field → "" (compareNode.evaluate never matches it)
		*out = append(*out, TermTrace{
			Field:    t.field,
			Operator: strings.TrimSpace(t.operator),
			Value:    t.value,
			Actual:   actual,
			Matched:  evalCmp(actual, t.operator, t.value),
		})
	case *andNode:
		traceNode(t.left, ctx, modelRequested, out)
		traceNode(t.right, ctx, modelRequested, out)
	case *orNode:
		traceNode(t.left, ctx, modelRequested, out)
		traceNode(t.right, ctx, modelRequested, out)
	}
}
