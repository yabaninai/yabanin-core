/** Match-expression grammar constants, authoring linter, and the pure corpus
 *  evaluator (NEXT-20 parity). Documented gateway semantics (pkg/evaluator):
 *  || binds loosest, && tighter, left-associative, no parentheses; a term
 *  that fails to parse makes the whole expression NEVER match. Since AUX-19
 *  the RulesPage VERDICT comes from the server (POST /api/rules/preview, the
 *  same evaluator.Snapshot the gateway compiles) — the page never
 *  self-evaluates. evaluateMatchExpr stays exported as the client half of the
 *  grammar parity corpus (scripts/quality/rules-parity.mjs): client and
 *  server evaluators must keep agreeing, case by case. No imports: runs in
 *  the browser AND under node via esbuild for the parity check. */

export const EXPR_FIELDS = ['org_id', 'model_requested', 'session_id', 'client_ip', 'user_agent'] as const
export const EXPR_CMP_OPS = [' == ', ' != ', ' contains ', ' starts_with ', ' ends_with '] as const
export const EXPR_LIST_OPS = [' in ', ' not_in '] as const

export interface ExprIssue {
  level: 'error' | 'warning'
  message: string
}

// Structural subset of the i18next TFunction — the linter only ever calls
// t(key, vars?). A brand-free type keeps the default (identity) testable.
type Translator = (key: string, options?: Record<string, unknown>) => string

/** Pure expression linter (no network, no state) — exported for tests.
 *  I18N-01: messages are t() lookups; the second argument defaults to an
 *  identity so existing tests keep working (message === key). */
export function validateMatchExpr(raw: string, t: Translator = (k: string) => k): ExprIssue[] {
  const expr = raw.trim()
  const issues: ExprIssue[] = []
  if (!expr) {
    issues.push({ level: 'error', message: t('rules.exprRequired') })
    return issues
  }
  // Quotes must balance — the parser honors quoting only when balanced.
  const count = (ch: string) => (expr.match(new RegExp(ch, 'g')) ?? []).length
  for (const q of ['"', "'"]) {
    if (count(q) % 2 !== 0) {
      issues.push({ level: 'error', message: t('rules.exprUnbalancedQuote', { quote: q }) })
    }
  }
  // Parentheses are not part of the grammar.
  if (/[()]/.test(expr)) {
    issues.push({ level: 'error', message: t('rules.exprNoParentheses') })
  }
  // Glob wildcards are not part of the grammar.
  if (expr.includes('*')) {
    issues.push({ level: 'error', message: t('rules.exprNoWildcard') })
  }
  // Every comparison must use one of the supported (space-surrounded) operators.
  const hasListOp = EXPR_LIST_OPS.some(op => expr.includes(op))
  const hasCmpOp = EXPR_CMP_OPS.some(op => expr.includes(op))
  if (!hasCmpOp && !hasListOp) {
    issues.push({ level: 'error', message: t('rules.exprNoOperator') })
  }
  // Field names on the left of each operator must be known.
  const parts = expr.split(/\|\||&&/)
  for (const part of parts) {
    const p = part.trim()
    if (!p) continue
    const op = (EXPR_CMP_OPS as readonly string[]).concat(EXPR_LIST_OPS).find(o => p.includes(o))
    const field = op ? p.slice(0, p.indexOf(op)).trim() : p
    if (op && field && !EXPR_FIELDS.includes(field as (typeof EXPR_FIELDS)[number])) {
      issues.push({ level: 'error', message: t('rules.exprUnknownField', { field }) })
    }
  }
  // A glob leftover or bare equality like "model=gpt-4" (no spaces) is a near-miss.
  if (!issues.length && /\w==\w|\w==\s|\s==\w/.test(expr)) {
    issues.push({ level: 'warning', message: t('rules.exprSpacesWarning') })
  }
  return issues
}

/** Pure corpus evaluator (NEXT-20 parity harness, scripts/quality/rules-
 *  parity.mjs). Mirrors the documented gateway semantics: || binds loosest,
 *  && tighter, left-associative, no parentheses; a term that fails to parse
 *  makes the whole expression NEVER match (returns null — parity maps null
 *  to the backend's false). NOT used for the RulesPage verdict: since AUX-19
 *  the page asks POST /api/rules/preview and renders the server's answer.
 *  Exported for the parity harness, not imported by pages. */
export function evaluateMatchExpr(
  raw: string,
  sample: Record<string, string>,
): boolean | null {
  const expr = raw.trim()
  if (!expr) return null
  const evalTerm = (term: string): boolean | null => {
    const t = term.trim()
    if (!t) return null
    const op = (EXPR_CMP_OPS as readonly string[]).concat(EXPR_LIST_OPS).find(o => t.includes(o))
    if (!op) return null
    const field = t.slice(0, t.indexOf(op)).trim()
    const rawValue = t.slice(t.indexOf(op) + op.length).trim()
    if (!field || !rawValue) return null
    if (!(EXPR_FIELDS as readonly string[]).includes(field)) return null
    const unquote = (v: string) =>
      (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'")))
        ? v.slice(1, -1)
        : v
    const actual = sample[field] ?? ''
    if (op === ' in ' || op === ' not_in ') {
      const list = rawValue.split(',').map(v => unquote(v.trim()))
      const member = list.includes(actual)
      return op === ' in ' ? member : !member
    }
    const expected = unquote(rawValue)
    switch (op) {
      case ' == ': return actual === expected
      case ' != ': return actual !== expected
      case ' contains ': return actual.includes(expected)
      case ' starts_with ': return actual.startsWith(expected)
      case ' ends_with ': return actual.endsWith(expected)
      default: return null
    }
  }
  for (const alt of expr.split('||')) {
    let altResult: boolean | null = true
    for (const term of alt.split('&&')) {
      const v = evalTerm(term)
      if (v === null) return null // unparsable term ⇒ never matches
      if (!v) { altResult = false; break }
    }
    if (altResult) return true
  }
  return false
}
