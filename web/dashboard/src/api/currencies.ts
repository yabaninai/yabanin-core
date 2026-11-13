// Typed client for the currencies endpoints. All are mounted on the
// session+CSRF admin group; the rights gates live IN THE HANDLERS, so the
// OpenAPI `x-permission: session` understates the matrix — this module
// documents the real gate per call and the pages gate controls the same way.
//
// Honest-data rules (brief §2, carried by wire types):
//  - every money payload carries `credits_scale` (adminstore.WalletUnitScale);
//    pages render it VERBATIM near amounts and never re-derive a scale.
//  - `Measure.amount` is a pointer BY CONTRACT: null means unknown — never a
//    fabricated zero. Budgets render a null carbon limit as "not configured",
//    not "0 g".
//  - 403 = the caller belongs to the org but lacks the permission; 404 = the
//    org is not theirs (invisible — a page must never render "no access to
//    org X" from a 404). 501 = this deployment's store predates the
//    currencies program: "not available in this deployment", not "broken".

import { fetchJSON, postJSON } from './http.ts'
import { ApiError } from './transport.ts'
import type { RequestOptions } from './transport.ts'

/** Verbatim scale caption from the server; never built client-side. */
export type CreditsScale = string

/** One measured quantity (adminstore.Measure). amount null = unknown. */
export interface Measure {
  amount: number | null
  unit: string
  family: string
  fidelity: string
  provenance?: string
}

/** GET /api/units/spend (gate: analytics.read org member, or root). */
export interface UnitSpendLine extends Measure {
  note?: string
}

export interface SpendWindow {
  from: string
  to: string
}

export interface UnitSpendRollup {
  org_id: string
  window: SpendWindow
  requests: number
  lines: UnitSpendLine[]
  /** Provenance of the prices used to build this report (catalog citation). */
  pricing: { pricing_as_of: string; pricing_catalog?: { version: string; generated_at: string; digest: string } }
  credits_scale: CreditsScale
  unknown_usage_rows: number
  unmodeled_carbon_rows: number
  legacy_cost_rows: number
}

/** GET /api/budgets (gate: budgets.manage org member, or root). */
export interface BudgetCapLine {
  id: string
  used: Measure
  /** null = not configured (carbon cap unknown ≠ 0). */
  limit: number | null
  status: string
  note?: string
}

export interface BudgetCapsStatus {
  org_id: string
  window: SpendWindow
  caps: BudgetCapLine[]
  credits_scale: CreditsScale
}

/** GET /api/credits/ledger (gate: budgets.manage org member, or root). */
export interface LedgerWallet {
  balance_cents: number
  updated_at: string
}

export interface LedgerStarterGrant {
  configured_cents: number
  claimed_cents: number
  claimed: boolean
}

export interface LedgerTransaction {
  id: number
  type: string
  amount_cents: number
  balance_after: number
  request_id?: string | null
  invoice_ref?: string | null
  created_at: string
  amount_micro_usd?: number | null
}

export interface CreditsLedgerView {
  org_id: string
  wallet?: LedgerWallet | null
  starter_grant?: LedgerStarterGrant | null
  transactions: LedgerTransaction[]
  ledger_sum_cents: number
  transaction_count: number
  ledger_consistent?: boolean | null
  credits_scale: CreditsScale
}

/** GET /api/rates/catalog (gate: any admin session — no org scope). */
export interface RatesCatalogRef {
  version: string
  digest: string
  generated_at: string
  review_sla_days: number
  pack_digest: string
  notices: string[]
  provenance: string
}

/** One priced axis of a RefModelEntry (adminstore→pricing.RefRate): amount
    null = explicitly unpriced (known axis, no verified price — never free). */
export interface RefRateAxis {
  axis: string
  unit: string
  amount: number | null
  evidence?: unknown[]
  [k: string]: unknown
}

export interface RefModelEntry {
  provider: string
  model: string
  aliases?: string[]
  region?: string
  tier?: string
  context_band?: string
  currency: string
  rates?: RefRateAxis[]
  effective_from?: string
  effective_to?: string
  verified_at?: string
  sources?: unknown[]
  [k: string]: unknown
}

export interface RatesCatalogBody {
  schema_version: number
  version: string
  generated_at: string
  supersedes?: string
  digest?: string
  source: string
  reviewer?: string
  review_sla_days?: number
  models: RefModelEntry[]
  [k: string]: unknown
}

export interface RatesCatalog {
  ref: RatesCatalogRef
  catalog: RatesCatalogBody
}

/** POST /api/rates/diff (gate: root session; reason optional). */
export interface RatesDiffFlag {
  kind: string
  entry: string
  [k: string]: unknown
}

export interface RatesDiffReport {
  from: RatesCatalogRef
  to: RatesCatalogRef
  rendered: string
  added: number
  removed: number
  changed: number
  review_needed: boolean
  flags: RatesDiffFlag[]
  refused: boolean
  refusal_reason?: string
}

/** POST /api/rates/promote (gate: root session + MANDATORY reason). 200
    returns {before, after, diff, applied}; 422 refusal carries the full
    report as DATA (refused=true + refusal_reason) — surface it whole.
    With durable promotion (AUDIT-P1-04) `persisted` marks that the
    active-of-record row and the priced models were written in one
    transaction, and `materialization` counts that write (optional for
    older deployments that promoted in memory only). */
export interface RatesPromotion {
  before: RatesCatalogRef
  after: RatesCatalogRef
  diff?: RatesDiffReport | null
  applied: boolean
  persisted?: boolean
  materialization?: {
    added: number
    updated: number
    skipped: number
    removed: number
  } | null
}

export interface RatesWindow {
  from?: string
  to?: string
}

export async function getBudgetCaps(orgId: string, opts?: RequestOptions): Promise<BudgetCapsStatus> {
  return fetchJSON<BudgetCapsStatus>(`/budgets?org_id=${encodeURIComponent(orgId)}`, opts)
}

export async function getCreditsLedger(
  orgId: string, limit?: number, opts?: RequestOptions,
): Promise<CreditsLedgerView> {
  const params = new URLSearchParams({ org_id: orgId })
  if (limit != null) params.set('limit', String(limit))
  return fetchJSON<CreditsLedgerView>(`/credits/ledger?${params.toString()}`, opts)
}

export async function getRatesCatalog(opts?: RequestOptions): Promise<RatesCatalog> {
  return fetchJSON<RatesCatalog>('/rates/catalog', opts)
}

/**
 * GET /api/units/spend (gate: analytics.read org member, or root; non-member
 * 404 = org invisible). `window` echoes the REQUESTED bounds; the response
 * carries the SERVED window — pages display the response's, never the input.
 */
export async function getUnitSpendRollup(
  orgId: string, window?: RatesWindow, opts?: RequestOptions,
): Promise<UnitSpendRollup> {
  const params = new URLSearchParams({ org_id: orgId })
  if (window?.from) params.set('from', window.from)
  if (window?.to) params.set('to', window.to)
  return fetchJSON<UnitSpendRollup>(`/units/spend?${params.toString()}`, opts)
}

/**
 * POST /api/rates/diff (gate: root session; reason optional). Returns the
 * render plan; a refusal comes back as HTTP 422 whose body is
 * RatesRefusalEnvelope — the transport surfaces that as ApiError, so callers
 * catch and pass it to parseRatesRefusal (never re-request).
 */
export async function diffRatesPack(
  pack: string, reason?: string, opts?: RequestOptions,
): Promise<RatesDiffReport> {
  return postJSON<RatesDiffReport>('/rates/diff', { pack, reason }, 'POST', opts)
}

/**
 * POST /api/rates/promote (gate: root session + MANDATORY reason). The swap
 * is process-local: after a server restart the pricer falls back to the
 * committed pack — surfaces state this next to the result.
 */
export async function promoteRatesPack(
  pack: string, reason: string, opts?: RequestOptions,
): Promise<RatesPromotion> {
  return postJSON<RatesPromotion>('/rates/promote', { pack, reason }, 'POST', opts)
}

/** 422 body of diff/promote: the refusal WITH the full report as data. */
export interface RatesRefusalEnvelope {
  refused: true
  refusal_reason: string
  report: RatesDiffReport
}

/**
 * Extracts the 422 refusal envelope from a transport ApiError (the body is
 * carried verbatim). Returns null for anything that is not a refusal —
 * callers fall through to their generic error handling.
 */
export function parseRatesRefusal(err: unknown): RatesRefusalEnvelope | null {
  if (!(err instanceof ApiError) || err.status !== 422 || !err.body) return null
  try {
    const parsed = JSON.parse(err.body) as Partial<RatesRefusalEnvelope>
    if (parsed.refused !== true || typeof parsed.refusal_reason !== 'string') return null
    if (!parsed.report || typeof parsed.report !== 'object') return null
    return parsed as RatesRefusalEnvelope
  } catch {
    return null
  }
}
