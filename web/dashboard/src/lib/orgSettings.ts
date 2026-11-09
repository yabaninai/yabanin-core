// AUX-24: pure helpers for the organization-settings screen. The allowlists
// mirror the server-side validation exactly (services/admin/handlers:
// cache_handlers.go, routing_handlers.go, policy_pack_handlers.go) — the UI
// validates only to fail fast; the server stays the arbiter.

/** Valid per-org cache modes (PATCH /api/organizations/{id}/cache-settings). */
export const CACHE_MODES = ['off', 'exact', 'semantic'] as const
export type CacheMode = (typeof CACHE_MODES)[number]

/** Valid per-org routing modes (PATCH /api/organizations/{id}/routing). */
export const ROUTING_MODES = ['auto', 'aggressive_cost', 'always_premium', 'always_cheap', 'classifier_only'] as const
export type RoutingMode = (typeof ROUTING_MODES)[number]

/** Valid residency regions (PUT /api/organizations/{id}/residency; "" clears). */
export const RESIDENCY_REGIONS = ['SG', 'IN', 'ID'] as const
export type ResidencyRegion = (typeof RESIDENCY_REGIONS)[number]

export function isCacheMode(v: string): v is CacheMode {
  return (CACHE_MODES as readonly string[]).includes(v)
}

export function isRoutingMode(v: string): v is RoutingMode {
  return (ROUTING_MODES as readonly string[]).includes(v)
}

export function isResidencyRegion(v: string): v is ResidencyRegion {
  return (RESIDENCY_REGIONS as readonly string[]).includes(v)
}

/** The classifier cutoff must be a finite number in [0, 1] (server-validated). */
export function isRoutingThreshold(v: number): boolean {
  return Number.isFinite(v) && v >= 0 && v <= 1
}

export interface PricingDraft {
  input_per_m: string
  output_per_m: string
  cache_write_per_m: string
  cache_read_per_m: string
}

/**
 * Parses a pricing draft into a partial PATCH body carrying only the fields
 * the operator actually changed (PUT /api/pricing/{id} is a partial update).
 * A field that is not a finite non-negative number makes the whole draft
 * invalid — the caller shows the honest input error instead of sending.
 */
export function pricingPatch(
  draft: PricingDraft,
  current: Pick<PricingEntryLike, 'input_per_m' | 'output_per_m' | 'cache_write_per_m' | 'cache_read_per_m'>,
): { ok: true; patch: Partial<PricingEntryLike> } | { ok: false } {
  const patch: Partial<PricingEntryLike> = {}
  const fields: Array<{ key: keyof PricingDraft; entryKey: keyof PricingEntryLike }> = [
    { key: 'input_per_m', entryKey: 'input_per_m' },
    { key: 'output_per_m', entryKey: 'output_per_m' },
    { key: 'cache_write_per_m', entryKey: 'cache_write_per_m' },
    { key: 'cache_read_per_m', entryKey: 'cache_read_per_m' },
  ]
  for (const { key, entryKey } of fields) {
    const raw = draft[key].trim()
    if (raw === '') continue // untouched field stays untouched
    const v = Number(raw)
    if (!Number.isFinite(v) || v < 0) return { ok: false }
    if (v !== current[entryKey]) patch[entryKey] = v
  }
  return { ok: true, patch }
}

/** Structural subset of PricingEntry the helpers touch (keeps the lib DOM-free). */
export interface PricingEntryLike {
  input_per_m: number
  output_per_m: number
  cache_write_per_m: number
  cache_read_per_m: number
}
