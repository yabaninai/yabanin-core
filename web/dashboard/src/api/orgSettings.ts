// NEXT-18f: org budget settings — the Credits/Budgets section's API surface.
//
// One GET returns the whole settings block plus the balance context the
// section displays; each mutation is a focused PUT with a MANDATORY operator
// reason (the server 400s an empty one) — sent both in the body and as
// X-Audit-Reason so the journal records it either way. AF-01 honesty rules:
// grace_floor_cents: null means "platform default" and an explicit 0 is a
// real value ("no overdraft") — the client never turns one into the other.
//
// reserved (SUM of active reservations) is NOT returned by the org credits
// API yet (NEXT-18a not merged) — the UI shows "—" until the API provides it.

import { readJSON, sendMutation } from './transport.ts'
import type { RequestOptions } from './transport.ts'
import { fetchJSON, postJSON } from './http.ts'

export const RESERVATIONS_MODES = ['off', 'shadow', 'enforce'] as const
export type ReservationsMode = (typeof RESERVATIONS_MODES)[number]

export const GRACE_FLOOR_MIN_CENTS = -100_000 // -$1000.00
export const GRACE_FLOOR_MAX_CENTS = 0

export function isReservationsMode(v: string): v is ReservationsMode {
  return (RESERVATIONS_MODES as readonly string[]).includes(v)
}

/** A settable grace floor: null (platform default) or [min..max]. */
export function isValidGraceFloorCents(v: number | null): boolean {
  if (v === null) return true
  return Number.isInteger(v) && v >= GRACE_FLOOR_MIN_CENTS && v <= GRACE_FLOOR_MAX_CENTS
}

export interface OrgBudgetSettings {
  org_id: string
  /** Per-org grace floor in cents; null = platform default (server-side). */
  grace_floor_cents: number | null
  /** The floor actually in force (per-org override or the platform default). */
  effective_grace_floor_cents: number
  reservations_mode: ReservationsMode
  /** Explicit saved value; retained separately from runtime enforcement. */
  saved_reservations_mode: ReservationsMode
  /** Organization mode after applying the deployment rollout ceiling. */
  effective_reservations_mode: ReservationsMode
  default_output_cap_tokens: number | null
  /** Wallet balance in cents; null when the credits store is not wired. */
  balance_cents: number | null
  /** §8 root signal: wallet below -$100. */
  deep_overdraft: boolean
}

export async function getOrgBudgetSettings(orgId: string, opts?: RequestOptions): Promise<OrgBudgetSettings> {
  return readJSON<OrgBudgetSettings>(`/api/orgs/${encodeURIComponent(orgId)}/credits/grace`, opts)
}

interface AuditReasoned {
  reason: string
}

async function putOrgSetting<T>(orgId: string, path: string, body: T & AuditReasoned, opts?: RequestOptions): Promise<OrgBudgetSettings> {
  const outcome = await sendMutation<OrgBudgetSettings>(
    `/api/orgs/${encodeURIComponent(orgId)}/${path}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Audit-Reason': body.reason },
      body: JSON.stringify(body),
    },
    opts,
  )
  if (!outcome.ok) throw outcome.error
  return outcome.body as OrgBudgetSettings
}

/** PUT grace floor. Pass null to reset to the platform default. */
export function updateOrgGraceFloor(
  orgId: string, graceFloorCents: number | null, reason: string, opts?: RequestOptions,
): Promise<OrgBudgetSettings> {
  return putOrgSetting(orgId, 'credits/grace', { grace_floor_cents: graceFloorCents, reason }, opts)
}

/** PUT reservations mode (root-only server-side). */
export function updateOrgReservationsMode(
  orgId: string, mode: ReservationsMode, reason: string, opts?: RequestOptions,
): Promise<OrgBudgetSettings> {
  return putOrgSetting(orgId, 'reservations-mode', { mode, reason }, opts)
}

/** PUT default output cap override. Pass null to clear. */
export function updateOrgDefaultOutputCap(
  orgId: string, defaultOutputCapTokens: number | null, reason: string, opts?: RequestOptions,
): Promise<OrgBudgetSettings> {
  return putOrgSetting(orgId, 'output-cap', { default_output_cap_tokens: defaultOutputCapTokens, reason }, opts)
}

// ===== AUX-24: organization settings (one screen over EXISTING endpoints) =====
//
// Every endpoint here is a root-only route today (services/admin/handlers/
// router.go: the cache-settings, routing, residency/policy-packs, spend-alert,
// MCP/A2A and pricing families all sit under MustBeRoot). The client adds no
// new contracts. Two PATCH contracts overwrite BOTH fields server-side, so
// callers must always send the full pair (same honesty rule as the AUX-15
// spend-alert PATCH):
//   - PUT/PATCH cache-settings: {cache_enabled, cache_mode} — an absent
//     cache_enabled would decode to false and silently disable caching;
//   - PATCH routing: {routing_mode, routing_threshold_confidence} — an absent
//     threshold decodes to 0 and would silently drop the classifier cutoff.
// Mutations accept opts.headers (X-Audit-Reason, AUX-14b); the CSRF token is
// still set by the client.

export interface OrgCacheSettings {
  cache_enabled: boolean
  cache_mode: 'off' | 'exact' | 'semantic'
}

export async function getOrgCacheSettings(orgId: string, opts?: RequestOptions): Promise<OrgCacheSettings> {
  return fetchJSON<OrgCacheSettings>(`/organizations/${encodeURIComponent(orgId)}/cache-settings`, opts)
}

export async function updateOrgCacheSettings(
  orgId: string, body: OrgCacheSettings, opts?: RequestOptions,
): Promise<void> {
  const outcome = await sendMutation(
    `/api/organizations/${encodeURIComponent(orgId)}/cache-settings`,
    { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    opts)
  if (!outcome.ok) throw outcome.error
}

export interface OrgOriginalRetention {
  org_id: string
  enabled: boolean | null
  effective_enabled: boolean
  inherited: boolean
}

export async function getOrgOriginalRetention(orgId: string, opts?: RequestOptions): Promise<OrgOriginalRetention> {
  return fetchJSON<OrgOriginalRetention>(`/organizations/${encodeURIComponent(orgId)}/original-retention`, opts)
}

export async function updateOrgOriginalRetention(
  orgId: string, enabled: boolean | null, opts?: RequestOptions,
): Promise<void> {
  const outcome = await sendMutation(
    `/api/organizations/${encodeURIComponent(orgId)}/original-retention`,
    { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) }, opts)
  if (!outcome.ok) throw outcome.error
}

export interface OrgRoutingSettings {
  routing_mode: string
  routing_threshold_confidence: number
}

export async function getOrgRoutingSettings(orgId: string, opts?: RequestOptions): Promise<OrgRoutingSettings> {
  return fetchJSON<OrgRoutingSettings>(`/organizations/${encodeURIComponent(orgId)}/routing`, opts)
}

export async function updateOrgRoutingSettings(
  orgId: string, body: OrgRoutingSettings, opts?: RequestOptions,
): Promise<void> {
  const outcome = await sendMutation(
    `/api/organizations/${encodeURIComponent(orgId)}/routing`,
    { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    opts)
  if (!outcome.ok) throw outcome.error
}

// Residency region: "" clears enforcement; valid values are SG/IN/ID.
export interface OrgResidency {
  org_id: string
  residency_region: string
}

export async function getOrgResidency(orgId: string, opts?: RequestOptions): Promise<OrgResidency> {
  return fetchJSON<OrgResidency>(`/organizations/${encodeURIComponent(orgId)}/residency`, opts)
}

export async function updateOrgResidency(
  orgId: string, residencyRegion: string, opts?: RequestOptions,
): Promise<void> {
  await postJSON(
    `/organizations/${encodeURIComponent(orgId)}/residency`,
    { residency_region: residencyRegion }, 'PUT', opts)
}

// PolicyPackConfig mirrors policystore.PackConfig (only fields the UI shows).
export interface OrgPolicyPack {
  id?: string
  org_id?: string
  region: string
  pack_id: string
  config?: unknown
  version?: number
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export async function listPolicyPacks(orgId: string, opts?: RequestOptions): Promise<OrgPolicyPack[]> {
  const rows = await fetchJSON<OrgPolicyPack[] | null>(
    `/organizations/${encodeURIComponent(orgId)}/policy-packs`, opts)
  return Array.isArray(rows) ? rows : []
}

/** PUT upsert for one region. Wire contract (pkfix1, review 98613b94):
    `config` is REQUIRED and must be non-null JSON (missing/null → 400 before
    the store is touched — it used to surface as a 500 SQLSTATE 23502);
    `pack_id` may be omitted and the server defaults it per region; the body
    is strict-decoded, so send exactly pack_id/config/enabled and nothing
    else. `config: {}` is the honest "pack defaults, no overrides" document
    (PA.6 override loading reads it later). */
export async function upsertPolicyPack(
  orgId: string, region: string, body: { pack_id?: string; config: unknown; enabled?: boolean }, opts?: RequestOptions,
): Promise<OrgPolicyPack> {
  return postJSON<OrgPolicyPack>(
    `/organizations/${encodeURIComponent(orgId)}/policy-packs/${encodeURIComponent(region)}`,
    body, 'PUT', opts)
}

export async function deletePolicyPack(orgId: string, packId: string, opts?: RequestOptions): Promise<void> {
  await postJSON(
    `/organizations/${encodeURIComponent(orgId)}/policy-packs/${encodeURIComponent(packId)}`,
    {}, 'DELETE', opts)
}

// PB2.7 org home-region assignment. The routes are mounted only when the
// region handler is wired — a 404 means "not available on this deployment"
// and renders as an honest partial note, never as fake data.
export interface OrgRegionAssignment {
  org_id?: string
  home_region: string
  residency_pinned: boolean
}

export async function getOrgRegion(orgId: string, opts?: RequestOptions): Promise<OrgRegionAssignment> {
  return fetchJSON<OrgRegionAssignment>(`/organizations/${encodeURIComponent(orgId)}/region`, opts)
}

export async function updateOrgRegion(
  orgId: string, body: { home_region: string; residency_pinned: boolean }, opts?: RequestOptions,
): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(orgId)}/region`, body, 'PUT', opts)
}
