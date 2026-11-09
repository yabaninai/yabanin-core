// API, services/admin/handlers/routing_map.go / provider_health.go).
//
// Contract notes (yabanin-contracts):
//  - Both endpoints are org-scoped reads; a foreign org or a membership
//    without the permission is answered 404 by the handler (no existence
//    leak), which callers surface as an honest error state.
//  - `warnings` codes are stable machine identifiers (chain_target_missing |
//    chain_target_disabled | chain_cycle | alias_target_missing |
//    alias_target_disabled | rule_target_missing | rule_target_disabled);
//    the UI keys its localized labels on the code and shows the server
//    `message` verbatim as the detail line.
//  - Provider health aggregates carry error_rate as a fraction (0..1) and
//    p50_ms/p95_ms in milliseconds; an empty window serializes as
//    `providers: []` (honest empty), never null.
//  - The health `period` accepts 1h | 24h | 7d | 30d | a Go duration string
//    (capped at 90d server-side). healthPeriodParam maps the shared
//    GlobalScope preset (AUX-08) onto that vocabulary without inventing a
//    second period control on this screen.

import { fetchJSON, type RequestOptions } from './http.ts'

export interface RoutingMapModel {
  model_name: string
  display_name: string
  tier: string
  provider: string
  enabled: boolean
  fallback_model?: string | null
  failover_models: string[]
  tier_pool: string[]
}

export interface RoutingMapAlias {
  alias: string
  target_model: string
}

export interface RoutingMapRule {
  id: string
  match_expr: string
  target_model: string
  priority: number
  enabled: boolean
}

export interface RoutingMapWarning {
  code: string
  scope: string
  source: string
  target?: string
  message: string
}

export interface RoutingMap {
  org_id: string
  models: RoutingMapModel[]
  aliases: RoutingMapAlias[]
  rules: RoutingMapRule[]
  warnings: RoutingMapWarning[]
}

export async function getRoutingMap(orgId: string, opts?: RequestOptions): Promise<RoutingMap> {
  return fetchJSON(`/routing/map?org_id=${encodeURIComponent(orgId)}`, opts)
}

export interface ProviderHealthModel {
  model: string
  requests: number
  errors: number
  error_rate: number
  p50_ms: number
  p95_ms: number
  last_error?: string
  last_error_at?: string | null
}

export interface ProviderHealth {
  provider: string
  requests: number
  errors: number
  error_rate: number
  models: ProviderHealthModel[]
}

export interface ProviderHealthReport {
  org_id: string
  period: string
  from: string
  to: string
  providers: ProviderHealth[]
}

export async function getProviderHealth(orgId: string, period: string, opts?: RequestOptions): Promise<ProviderHealthReport> {
  return fetchJSON(
    `/providers/health?org_id=${encodeURIComponent(orgId)}&period=${encodeURIComponent(period)}`,
    opts,
  )
}

// ===== Pure helpers (unit-tested in ./routing.test.ts) =====

/** The GlobalScope period presets this screen can express. */
export type HealthPreset = '24h' | '7d' | '30d' | '90d' | 'custom'

/**
 * Map the shared scope preset onto the health API's `period` vocabulary.
 * Direct presets pass through; 90d goes as its exact hour duration (the
 * server caps at 90d anyway); a custom window becomes its whole-span hour
 * duration, rounded — a window shorter than an hour still asks for 1h, and
 * an unusable window (unparseable/empty/inverted bounds) falls back to the
 * API default of 24h instead of a 400.
 */
export function healthPeriodParam(period: HealthPreset, from: string, to: string): string {
  if (period === '24h' || period === '7d' || period === '30d') return period
  if (period === '90d') return '2160h'
  const f = Date.parse(from)
  const t = Date.parse(to)
  if (!Number.isFinite(f) || !Number.isFinite(t) || t <= f) return '24h'
  const hours = Math.max(1, Math.round((t - f) / 3_600_000))
  return `${hours}h`
}

/**
 * The failover chain of one model exactly as the gateway assembles attempts
 * (pkg/router buildChain): the model itself, then its fallback, then its
 * failover models. Blank entries are dropped; a repeated hop stays in the
 * list — the cycle is a computed warning, not something the map silently
 * rewrites.
 */
export function chainSteps(m: Pick<RoutingMapModel, 'model_name' | 'fallback_model' | 'failover_models'>): string[] {
  const steps = [m.model_name]
  if (m.fallback_model && m.fallback_model.trim() !== '') steps.push(m.fallback_model)
  for (const f of m.failover_models ?? []) {
    if (f && f.trim() !== '') steps.push(f)
  }
  return steps
}
