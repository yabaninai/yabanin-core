// drawer imports these, and node --test runs the contract tests directly.

import { EXPR_CMP_OPS, EXPR_LIST_OPS, type ExprIssue } from '../../lib/matchExpr.ts'

/**
 * D-18 (checklist «страница v2» IMP-40 acceptance: «пустое поле не красное»).
 * Validation feedback appears only AFTER the operator typed something — an
 * untouched or emptied field is neutral, never flagged. The submit path
 * re-checks the raw issues, so an empty required expression still cannot be
 * saved; it is just never painted red while empty.
 */
export function visibleIssues(expr: string, issues: ExprIssue[]): ExprIssue[] {
  if (expr.trim() === '') return []
  return issues
}

/** True when the field may show its error styling (non-empty AND invalid). */
export function showsError(expr: string, issues: ExprIssue[]): boolean {
  return visibleIssues(expr, issues).some(i => i.level === 'error')
}

/**
 * Renders one constructor clause in the real grammar (pkg/rulesengine):
 * comparison operators take one quoted value, in/not_in take a bare
 * comma list (their documented value shape).
 */
export function buildClause(field: string, op: string, value: string): string {
  const trimmed = value.trim()
  if ((EXPR_LIST_OPS as readonly string[]).includes(op)) return `${field}${op}${trimmed}`
  return `${field}${op}"${trimmed}"`
}

/**
 * Appends a clause with the documented && join (|| is typed by hand — the
 * builder only ever extends the current conjunction chain).
 */
export function appendClause(expr: string, clause: string): string {
  const base = expr.trim()
  if (base === '') return clause
  return `${base} && ${clause}`
}

const ALL_OPS: readonly string[] = (EXPR_CMP_OPS as readonly string[]).concat(EXPR_LIST_OPS)

/**
 * True when an operator needs its list placeholder (drives the value input's
 * placeholder + datalist choice in the constructor).
 */
export function isListOp(op: string): boolean {
  return (EXPR_LIST_OPS as readonly string[]).includes(op)
}

export { ALL_OPS }
