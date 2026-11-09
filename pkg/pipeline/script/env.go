package script

// This file documents the CONDITION ENVIRONMENT CONTRACT shared by every
// script engine implementation in this package tree (lua, starlark, expr).
// It is the audit-facing vocabulary of `when` conditions: the same intent
// must expressible in every engine, so an OP-7 language switch never forces
// a policy rewrite (plan §2.2 п.2, §3 OP-7).
//
// A condition source is evaluated against exactly three roots — findings,
// steps, meta — and MUST reduce to a boolean. Roots are read-only snapshots
// of the pipeline state at evaluation time (pipeline.ConditionEnv). Every
// engine grants access to these roots ONLY: no I/O, no wall clock, no
// randomness, no global namespaces beyond the safe stdlib subset listed per
// engine. A condition that violates its sandbox fails the evaluation, and
// evaluation errors follow the step's on_error mode (fail-closed default).
//
// # findings — the findings recorded so far in the current run
//
// Record fields (read-only): step, category, severity, span, evidence,
// action (strings; action ∈ deny | mask | flag | allow).
//
//	Collection methods (pred is a predicate over one finding):
//	  any(pred)      → true iff at least one finding matches
//	  all(pred)      → true iff the collection is non-empty and all match
//	  none(pred)     → true iff no finding matches
//	  count([pred])  → number of findings (matching pred when given)
//
// # steps — the trace of steps executed so far in the current run
//
// Record fields (read-only): step (id), duration_ms (number, fractional),
// outcome (ran | skipped | error | timeout), error (string, may be absent).
//
//	Accessors (id is the compiled step id):
//	  get(id)         → the record, or nothing/None when absent
//	  ran(id)         → bool, outcome == ran
//	  skipped(id)     → bool, outcome == skipped
//	  failed(id)      → bool, outcome ∈ {error, timeout}
//	  duration_ms(id) → number, or nil/None/error when the step is absent
//	  outcome(id)     → string, or nil/None/error when the step is absent
//
// # meta — the routing identity of the request (never nil-valued roots)
//
// Fields (read-only): org, key, model, provider (strings), labels
// (string→string map), tags (string collection).
//
//	Helpers:
//	  label(name)  → label value or nil/None when absent
//	  has_tag(tag) → bool
//
// # Canonical policy example
//
// The same "gate the pseudonymize step on a national-PII finding from an
// untrusted org" policy in every engine (see docs/plans/
// OP-7-SCRIPT-SPIKE-DECISION.md for the full side-by-side audit):
//
//	lua:      return findings.any(function(f)
//	              return f.category == 'innsnils'
//	          end) and meta.org ~= 'trusted-int'
//
//	starlark: findings.any(lambda f: f.category == 'innsnils')
//	          and meta.org != 'trusted-int'
//
//	expr:     any(Findings, #.Category == 'innsnils')
//	          and Meta.Org != 'trusted-int'
//
// (expr exposes the roots with capitalised field names to match its
// Go-struct member-access convention.)
