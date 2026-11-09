// savings report + Cost screen). Backend contract (pkg/adminstore/savings.go,
// cost_analytics.go): `unpriced_share` is an explicit JSON null when the
// coverage measurement did not run — null is "not measured", never zero
// coverage — and `coverage_status` is absent on pre-AF-07 responses, where an
// absent status must not read as proven full coverage. Zero cost is not free
// (actual_cost_usd = 0 can mean "no model is priced"), so every branch that
// cannot quantify the cost of the window resolves to 'unknown' and the
// screens render n/a + a hint instead of a precise $0.0000.
import type { PricingMetadata } from '../api/client'

export type PricingCoverageDecision =
  | { state: 'ok' }
  // Measured, partially unpriced: numbers stay, labeled as a known subtotal.
  | { state: 'warning'; pct: number }
  // The cost of the window cannot be quantified. all-unpriced: measured,
  // nothing in the price table. unmeasured: the share is null/absent/garbage
  // or the status is missing (pre-AF-07) — absence of evidence is not full
  // coverage.
  | { state: 'unknown'; reason: 'all-unpriced' | 'unmeasured' }

export interface ParsedPricing {
  /** null = absent or unrecognized on the wire (pre-AF-07 / malformed). */
  status: PricingMetadata['coverage_status'] | null
  /** null = not measured (JSON null, absent, or a non-finite value). */
  share: number | null
  models: string[]
}

const STATUSES = new Set(['complete', 'partial', 'unknown', 'empty'])

// Defensive parse of the wire shape: the transport casts JSON without
// validation, so a malformed payload (share as a string, status as a number)
// degrades to "not measured", never to a measured zero.
export function parsePricingMetadata(raw: unknown): ParsedPricing {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { status: null, share: null, models: [] }
  }
  const p = raw as Record<string, unknown>
  const status = typeof p.coverage_status === 'string' && STATUSES.has(p.coverage_status)
    ? p.coverage_status as ParsedPricing['status']
    : null
  const share = typeof p.unpriced_share === 'number' && Number.isFinite(p.unpriced_share)
    ? p.unpriced_share
    : null
  const models = Array.isArray(p.unpriced_models)
    ? p.unpriced_models.filter((m): m is string => typeof m === 'string')
    : []
  return { status, share, models }
}

export function resolvePricingCoverage(raw: unknown): PricingCoverageDecision {
  const p = parsePricingMetadata(raw)
  // Empty window: not a coverage measurement — the screens show their own
  // empty state (the report carries no cost claims to guard).
  if (p.status === 'empty') return { state: 'ok' }
  if (p.status === 'unknown') {
    return p.share === 1
      ? { state: 'unknown', reason: 'all-unpriced' }
      : { state: 'unknown', reason: 'unmeasured' }
  }
  if (p.status === 'partial' && p.share != null) {
    return { state: 'warning', pct: Math.round(p.share * 100) }
  }
  // Pre-AF-07 payload (no usable coverage_status): the share, when measured,
  // is the only evidence.
  if (p.share === 1) return { state: 'unknown', reason: 'all-unpriced' }
  if (p.share != null && p.share > 0) {
    return { state: 'warning', pct: Math.round(p.share * 100) }
  }
  // complete/share=0 → ok; anything else without coverage evidence — a
  // measured 0 under an absent status, a null share, or no pricing at all —
  // must not read as proven full coverage: unknown.
  if (p.status === 'complete' && p.share === 0) return { state: 'ok' }
  return { state: 'unknown', reason: 'unmeasured' }
}

type Translate = (key: string, opts?: Record<string, unknown>) => string

// Base coverage note for a decision, in the screen's copy namespace
// ('cost' | 'overview' — both screens keep their existing keys). Returns ''
// for ok: measured full coverage needs no coverage line. The keys are built
// as plain concatenations (NOT t(`…`) template args) — the i18n key gate's
// scanner cannot see through a template first argument, and these keys must
// stay on its books (via the DYNAMIC_ALLOWLIST entry for this file).
export function pricingCoverageCopy(
  d: PricingCoverageDecision,
  t: Translate,
  ns: 'cost' | 'overview',
): string {
  if (d.state === 'ok') return ''
  if (d.state === 'warning') {
    const key = ns + '.pricingExcludes'
    return t(key, { pct: d.pct })
  }
  const key = ns + (d.reason === 'all-unpriced' ? '.pricingNoModels' : '.pricingCoverageUnknown')
  return t(key)
}
