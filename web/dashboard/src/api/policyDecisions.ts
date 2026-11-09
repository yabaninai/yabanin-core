// OP-9: policy decision log endpoints (read-only view of what the policy
// pipeline did — one row per evaluation attached to a request event;
// content-free findings, 90d retention).
//
// CORE-TRACE-01 contract: `findings` is ALWAYS a JSON array of content-free
// finding objects on the wire (never a base64 string or null). When
// `findings_valid` is false the stored findings were malformed/legacy
// non-array and are served as [] — such a row must never be presented as a
// clean "nothing found" verdict.

import { fetchJSON, DEFAULT_PAGE_SIZE, type Paginated, type RequestOptions } from './http.ts'

/** One sanitized, content-free finding (writer contract: step/category/severity/span/action only). */
export interface PolicyDecisionFinding {
  step?: string
  category?: string
  severity?: string
  span?: string
  action?: string
}

export interface PolicyDecision {
  id: string
  org_id: string
  request_id: string
  policy_id: string
  policy_version: number
  mode: 'shadow' | 'enforce'
  verdict: string
  /** Content-free findings array — always an array; see findings_valid. */
  findings: PolicyDecisionFinding[]
  /** false = stored findings were malformed (null/non-array/junk) and are served as [] — degraded record, not a clean verdict. */
  findings_valid: boolean
  duration_ms: number
  created_at: string
}

export interface PolicyDecisionFilters {
  verdict?: string
  mode?: string
  policyId?: string
  /** Exact evaluated pipeline version — 0 is a real value (unknown legacy), not "no filter". */
  policyVersion?: number
  /** Exact request id — one request's evaluations. */
  requestId?: string
  /** Decisions whose findings carry a finding with this step. */
  step?: string
  /** Inclusive window bounds, RFC3339. */
  createdFrom?: string
  createdTo?: string
}

/**
 * Which side of the rule↔request relation the list answers:
 *  - `decisions` (default): one row per stored policy evaluation;
 *  - `requests`: one row per DISTINCT request behind the filtered decisions —
 *    totals and pagination count unique requests.
 */
export type PolicyDecisionEntity = 'decisions' | 'requests'

/** One entry of the requests view (CORE-TRACE-02). */
export interface PolicyDecisionRequestSummary {
  request_id: string
  evaluations: number
  first_seen_at: string
  last_seen_at: string
}

export interface PolicyDecisionPage {
  rows: PolicyDecision[]
  total: number
  totalPages: number
}

export interface PolicyDecisionRequestPage {
  rows: PolicyDecisionRequestSummary[]
  total: number
  totalPages: number
}

/** Builds the org-scoped list URL: shared filters + entity + pagination. */
function policyDecisionsUrl(
  orgId: string,
  page: number,
  pageSize: number,
  filters: PolicyDecisionFilters,
  entity: PolicyDecisionEntity,
): string {
  const q = new URLSearchParams({ page: String(page), page_size: String(pageSize), entity })
  if (filters.verdict) q.set('verdict', filters.verdict)
  if (filters.mode) q.set('mode', filters.mode)
  if (filters.policyId) q.set('policy_id', filters.policyId)
  if (filters.policyVersion !== undefined) q.set('policy_version', String(filters.policyVersion))
  if (filters.requestId) q.set('request_id', filters.requestId)
  if (filters.step) q.set('step', filters.step)
  if (filters.createdFrom) q.set('created_from', filters.createdFrom)
  if (filters.createdTo) q.set('created_to', filters.createdTo)
  return `/organizations/${encodeURIComponent(orgId)}/policy-decisions?${q.toString()}`
}

function unwrapPage<T>(body: Paginated<T> | null, page: number, dataKey: keyof Paginated<T>): { rows: T[]; total: number; totalPages: number } {
  const data = (body?.[dataKey] as T[] | undefined) ?? []
  return {
    rows: data,
    total: body?.pagination.total ?? data.length,
    totalPages: body?.pagination.total_pages ?? (data.length > 0 ? page : 0),
  }
}

/** Lists the decision log (entity=decisions): one row per policy evaluation. */
export async function listPolicyDecisions(
  orgId: string,
  page = 1,
  filters: PolicyDecisionFilters = {},
  pageSize = DEFAULT_PAGE_SIZE,
  opts?: RequestOptions,
): Promise<PolicyDecisionPage> {
  const body = await fetchJSON<Paginated<PolicyDecision> | null>(
    policyDecisionsUrl(orgId, page, pageSize, filters, 'decisions'), opts)
  return unwrapPage(body, page, 'data')
}

/**
 * Lists the REQUEST side (entity=requests, CORE-TRACE-02): distinct requests
 * behind the filtered decisions with their evaluation footprint. A request
 * with three evaluations is one row here, and totals count requests.
 */
export async function listPolicyDecisionRequests(
  orgId: string,
  page = 1,
  filters: PolicyDecisionFilters = {},
  pageSize = DEFAULT_PAGE_SIZE,
  opts?: RequestOptions,
): Promise<PolicyDecisionRequestPage> {
  const body = await fetchJSON<Paginated<PolicyDecisionRequestSummary> | null>(
    policyDecisionsUrl(orgId, page, pageSize, filters, 'requests'), opts)
  return unwrapPage(body, page, 'data')
}
