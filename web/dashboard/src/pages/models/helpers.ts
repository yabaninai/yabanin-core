// validation, pricing-row matching and analytics-query row pivoting.
//
// Pure core (the columnFormat.ts pattern): no React, no i18n runtime, no
// fetch — node:test pins the contract and the page only binds presentation.
// Honesty rules: an unknown chain target is never silently dropped, a model
// without a pricing entry never renders as $0, an analytics result that
// does not carry the model/requests/errors/latency_p95 shape yields null so
// the screen can hide the columns instead of inventing zeros, and the
// working.

// ---------------------------------------------------------------------------
// (the registry row + the last discovery/test evidence), never stored and
// never probed in the background: only the operator's switch marks state
// (D-2), probes are evidence. Honesty rules: only a registry row plus a
// PASSED check may read verified; absence of evidence is never success; a
// model the registry does not know is unavailable with a reason and the
// manual-register hint (D-6) — it never renders as working.
// ---------------------------------------------------------------------------

export type ModelDisplayState = 'verified' | 'configured' | 'discovered' | 'unavailable'

/**
 * Why a model is not usable right now. UI-derived tokens; the discovery
 * refusal taxonomy (providerKeysHelpers CatalogReason, 5 reasons) passes
 * through the probing surface separately and is not redefined here.
 */
export type UnavailableReason =
  | 'operator_disabled'
  | 'check_failed'
  | 'not_registered'
  | 'absent_from_snapshot'

export interface ModelStateFacts {
  /** A registry row exists. */
  registered: boolean
  /** The operator's switch on the row (D-2: the only state marking). */
  enabled: boolean
  /** Last connection test: true = passed, false = failed, undefined = none. */
  testOk?: boolean
  /** true = in the last parsed discovery snapshot; false = a snapshot ran and the id was absent; undefined = no snapshot. */
  discovered?: boolean
}

export interface ModelState {
  state: ModelDisplayState
  reason?: UnavailableReason
}

/**
 * The display-state matrix. Priority for a registry row: the operator's
 * switch first (disabled is unavailable regardless of evidence), then a
 * successful snapshot that lacks the id — the provider's own current list is
 * the strongest "not offered" evidence, so the row never reads verified
 * against a list that does not carry it — then the last test verdict.
 */
export function modelDisplayState(facts: ModelStateFacts): ModelState {
  if (facts.registered) {
    if (!facts.enabled) return { state: 'unavailable', reason: 'operator_disabled' }
    if (facts.discovered === false) return { state: 'unavailable', reason: 'absent_from_snapshot' }
    if (facts.testOk === true) return { state: 'verified' }
    if (facts.testOk === false) return { state: 'unavailable', reason: 'check_failed' }
    return { state: 'configured' }
  }
  if (facts.discovered) return { state: 'discovered' }
  return { state: 'unavailable', reason: 'not_registered' }
}

/** Badge shells for the display-state badges — gated screens carry no class literals. */
export const stateBadgeShell =
  'inline-flex max-w-full items-center gap-1 whitespace-nowrap rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-1.5 py-0.5 text-xs'

/** Ink color per display state (astra tokens only — see lint-design). */
export function stateBadgeColor(state: ModelDisplayState): string {
  switch (state) {
    case 'verified': return 'var(--astra-success)'
    case 'configured': return 'var(--astra-ink)'
    case 'discovered': return 'var(--astra-accent)'
    case 'unavailable': return 'var(--astra-danger)'
  }
}

/** Leading glyph per display state (aria-hidden decoration, existing vocabulary). */
export function stateBadgeGlyph(state: ModelDisplayState): string {
  switch (state) {
    case 'verified': return '✓'
    case 'configured': return '●'
    case 'discovered': return '△'
    case 'unavailable': return '✕'
  }
}

/** One parsed failover/pool target list item (order preserved, no dupes). */
export function parseNameList(raw: string): string[] {
  const out: string[] = []
  for (const part of raw.split(/[\n,]+/)) {
    const name = part.trim()
    if (name && !out.includes(name)) out.push(name)
  }
  return out
}

/** Join a tag list back into the comma-separated form the API layer parses. */
export function joinNameList(names: string[]): string {
  return names.join(', ')
}

/** Chip shell shared by the fallback-chain chips (Tailwind tokens live with
 * the pure helpers so the gated screen file carries no class literals). */
export const chainChipShell =
  'inline-flex max-w-full items-center gap-0.5 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-1.5 py-0.5 text-xs'

export type ChainTargetStatus = 'ok' | 'disabled' | 'unknown'

/**
 * Status of one chain target against the known registry slice:
 * 'ok' = exists and enabled, 'disabled' = exists but switched off,
 * 'unknown' = not in the known slice at all.
 */
export function chainTargetStatus(
  target: string, known: ReadonlyMap<string, boolean>,
): ChainTargetStatus {
  const enabled = known.get(target)
  if (enabled === undefined) return 'unknown'
  return enabled ? 'ok' : 'disabled'
}

export interface ChainValidation {
  ok: boolean
  unknown: string[]
  disabled: string[]
}

/**
 * A chain cannot be saved onto a non-existent (or disabled) model. The UI
 * check runs against the loaded registry slice — the server stays the source
 * of truth and re-checks on save.
 */
export function validateChainTargets(
  targets: readonly string[], known: ReadonlyMap<string, boolean>,
): ChainValidation {
  const unknown: string[] = []
  const disabled: string[] = []
  for (const target of targets) {
    switch (chainTargetStatus(target, known)) {
      case 'unknown': if (!unknown.includes(target)) unknown.push(target); break
      case 'disabled': if (!disabled.includes(target)) disabled.push(target); break
      default: break
    }
  }
  return { ok: unknown.length === 0 && disabled.length === 0, unknown, disabled }
}

/**
 * tier_pool holds TIER names (pkg/router/tier_pool.go buckets models by
 * classifier class: easy/medium/hard), not model names — the check is
 * membership in the tier vocabulary, or the entry would silently never route.
 */
export function validateTierPool(
  targets: readonly string[], allowed: readonly string[],
): { ok: boolean; unknown: string[] } {
  const set = new Set(allowed)
  const unknown = targets.filter(t => !set.has(t))
  return { ok: unknown.length === 0, unknown: [...new Set(unknown)] }
}

/** All chain targets of one model (fallback first, then the failover list). */
export function chainTargetsOf(m: {
  fallback_model?: string
  failover_models?: string[] | null
}): string[] {
  const out: string[] = []
  const fallback = m.fallback_model?.trim()
  if (fallback) out.push(fallback)
  for (const name of m.failover_models ?? []) {
    const trimmed = name.trim()
    if (trimmed && !out.includes(trimmed)) out.push(trimmed)
  }
  return out
}

// ---------------------------------------------------------------------------
// Pricing matching — price in/out per 1M from the pricing registry.
// ---------------------------------------------------------------------------

export interface PricingLike {
  provider: string
  model: string
  input_per_m: number
  output_per_m: number
  effective_from?: string
}

/**
 * The pricing row for one provider+model: the latest effective_from wins when
 * the registry keeps history. No match (including a missing provider on the
 * registry row) → null — the caller renders the honest missing marker.
 */
export function pickPricing<T extends PricingLike>(
  rows: readonly T[] | null | undefined, provider: string | undefined, model: string,
): T | null {
  if (!provider || !model) return null
  let best: T | null = null
  let bestFrom = ''
  for (const row of rows ?? []) {
    if (row.provider !== provider || row.model !== model) continue
    const from = row.effective_from ?? ''
    if (best === null || from >= bestFrom) {
      best = row
      bestFrom = from
    }
  }
  return best
}

// ---------------------------------------------------------------------------
// Analytics pivoting — requests / errors / p95 per model over 7 days.
// ---------------------------------------------------------------------------

export interface ModelUsageStats {
  requests: number
  errors: number
  /** ms; null when the model has no measurable traffic in the window. */
  p95_ms: number | null
}

export interface StatsLike {
  columns: Array<{ name: string; type: string }>
  rows: Array<Array<string | number | null>>
  truncated?: boolean
}

/**
 * Pivot a group_by=model analytics result into per-model usage. Returns null
 * when the result does not carry the expected shape (truncated top, missing
 * metric columns, unexpected body) — the screen hides the columns instead of
 * showing partial data as if it were complete.
 */
export function parseModelStats(result: StatsLike | null | undefined): Map<string, ModelUsageStats> | null {
  if (!result || result.truncated) return null
  const cols = result.columns ?? []
  const modelIdx = cols.findIndex(c => c.name === 'model')
  const requestsIdx = cols.findIndex(c => c.name === 'requests')
  const errorsIdx = cols.findIndex(c => c.name === 'errors')
  const p95Idx = cols.findIndex(c => c.name === 'latency_p95')
  if (modelIdx < 0 || requestsIdx < 0 || errorsIdx < 0 || p95Idx < 0) return null

  const out = new Map<string, ModelUsageStats>()
  for (const row of result.rows ?? []) {
    const model = String(row[modelIdx] ?? '').trim()
    if (!model) continue
    const prev = out.get(model) ?? { requests: 0, errors: 0, p95_ms: null }
    const requests = toNumber(row[requestsIdx])
    const errors = toNumber(row[errorsIdx])
    const p95 = toNumber(row[p95Idx])
    out.set(model, {
      requests: prev.requests + (requests ?? 0),
      errors: prev.errors + (errors ?? 0),
      p95_ms: p95 !== null ? p95 : prev.p95_ms,
    })
  }
  return out
}

function toNumber(v: string | number | null | undefined): number | null {
  if (v == null || v === '') return null
  const n = typeof v === 'number' ? v : Number(v)
  return Number.isFinite(n) ? n : null
}
