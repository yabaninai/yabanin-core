
import { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE, type Paginated, type ListSortParams, type RequestOptions } from './http.ts'

export interface RoutingRule {
  id: string
  org_id: string
  match_expr: string
  target_model: string
  priority: number
  enabled: boolean
}

export async function listRoutingRules(orgId: string, page = 1, opts?: RequestOptions & ListSortParams & { pageSize?: number }): Promise<Paginated<RoutingRule>> {
  return fetchJSON(`/rules?org_id=${encodeURIComponent(orgId)}&${listQuery(page, opts?.pageSize ?? DEFAULT_PAGE_SIZE, opts?.sort, opts?.dir)}`, opts)
}

export async function createRoutingRule(orgId: string, matchExpr: string, targetModel: string, priority: number, opts?: RequestOptions): Promise<RoutingRule> {
  return postJSON('/rules', { org_id: orgId, match_expr: matchExpr, target_model: targetModel, priority }, 'POST', opts)
}

/** PUT /api/rules/{id} — partial update (empty fields are ignored server-side). */
export async function updateRoutingRule(
  id: string,
  values: { match_expr?: string; target_model?: string; priority?: number },
  opts?: RequestOptions,
): Promise<void> {
  await postJSON(`/rules/${encodeURIComponent(id)}`, values, 'PUT', opts)
}

/** PUT /api/rules/{id}/enable — toggle a rule without touching its fields. */
export async function setRoutingRuleEnabled(id: string, enabled: boolean, opts?: RequestOptions): Promise<void> {
  await postJSON(`/rules/${encodeURIComponent(id)}/enable`, { enabled }, 'PUT', opts)
}

/** DELETE /api/rules/{id}. */
export async function deleteRoutingRule(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/rules/${encodeURIComponent(id)}`, {}, 'DELETE', opts)
}

// ===== Server-side rules preview (POST /api/rules/preview) =====
//
// The server is the single arbiter: the candidate is compiled and evaluated
// by the same evaluator.Snapshot the gateway uses. org scope is the session's
// trusted scope header — it is deliberately NOT part of the request body.

export interface RulePreviewSample {
  model_requested?: string
  session_id?: string
  client_ip?: string
  user_agent?: string
}

export interface RulePreviewTerm {
  field: string
  operator: string
  value: string
  actual: string
  matched: boolean
}

export interface RulePreviewResult {
  index: number
  requested_model: string
  matched: boolean
  /** Where the request would route: the candidate target on match, else the requested model. */
  effective_model: string
  terms: RulePreviewTerm[]
}

export interface RulePreviewResponse {
  org_id: string
  match_expr: string
  target_model: string
  priority: number
  results: RulePreviewResult[]
  summary: { total: number; matched: number }
}

export interface RulePreviewRequest {
  match_expr: string
  target_model: string
  priority: number
  samples: RulePreviewSample[]
}

/** Evaluate a draft rule against sample requests. Errors are typed
 *  ApiErrors — the server answers 400 {reason: "invalid_match_expression"}
 *  for an expression that would never match, so the UI can say so honestly. */
export async function previewRoutingRule(body: RulePreviewRequest, opts?: RequestOptions): Promise<RulePreviewResponse> {
  return postJSON('/rules/preview', body, 'POST', opts)
}
