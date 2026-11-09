// AUX-09 — drill-down links to the request explorer. One helper builds the
// `#requests-explorer` hash shared by every drilling screen (Overview, Cost,
// Tasks, Tool calls, Analytics, Dashboards):
//   * the entity filter rides as the committed YQL `query` param — the
//     AUX-05 FilterBar contract renders it as removable chips on arrival;
//   * the applied window rides as the GlobalScope `from`/`to` (AUX-08:
//     a deep link pins its own range, so the drill reproduces the exact
//     window the numbers were computed over — never a drifting preset);
//   * the org rides as `?org=`.
// Pure string building so node:test can cover it without a DOM, mirroring
// lib/inspectUrl.ts / lib/globalScope.ts.

import { quoteYqlValue } from './queryLang.ts'

export interface ExplorerLinkSpec {
  /** Org scope carried into the explorer (blank → the explorer's own scope). */
  org?: string
  /** Applied window start (RFC3339). Both borders must be present to pin. */
  from?: string
  /** Applied window end (RFC3339). */
  to?: string
  /** YQL behind the aggregate/entity — becomes the applied filter chips. */
  yql?: string
}

/**
 * Hash for opening the request explorer on the requests behind one aggregate:
 * `#requests-explorer?org=…&from=…&to=…&query=…`. Absent/blank parts are
 * omitted (a link without borders leaves the explorer's GlobalScope window
 * untouched); the YQL is trimmed and never encoded when blank.
 */
export function explorerLink({ org, from, to, yql }: ExplorerLinkSpec): string {
  const q = new URLSearchParams()
  const o = org?.trim()
  if (o) q.set('org', o)
  const f = from?.trim()
  const t = to?.trim()
  // A window is carried only as a complete pair — a half-pinned range would
  // silently widen the drill to whatever the second border resolves to.
  if (f && t) {
    q.set('from', f)
    q.set('to', t)
  }
  const y = yql?.trim()
  if (y) q.set('query', y)
  const qs = q.toString()
  return `#requests-explorer${qs ? `?${qs}` : ''}`
}

// Values the aggregates use for "no value" buckets are honest labels, not
// entity ids — filtering `model = (none)` would query a literal model named
// "(none)". A drill link carries only expressible filters (AUX-06 rule).
const MUTED_DRILL_VALUES = new Set(['(none)', '(other)', '(untagged)'])

/**
 * One request-side YQL clause behind an entity value — `field = value` —
 * or null when the value is a muted bucket (never invented as a filter).
 */
export function drillClause(field: string, value: string): string | null {
  const v = value.trim()
  if (!v || MUTED_DRILL_VALUES.has(v)) return null
  return `${field} = ${quoteYqlValue(v)}`
}
