// aggregate (extracted from client.ts unchanged).

import { fetchJSON, type Paginated, type RequestOptions } from './http.ts'

// ===== Unified request list (ASTR-09 debt fix) =====

export interface RequestRow {
  request_id: string
  org_id: string
  model_requested?: string
  model_used: string
  status_code: number
  cost_usd: number
  tokens_in: number
  tokens_out: number
  task_id?: string
  duration_ms: number
  cache_hit_type?: string
  // Observability parity (Bifrost attempt trail); absent = unknown/legacy.
  first_token_ms?: number
  attempt_count?: number
  retry_count?: number
  error?: string
  created_at: string
  // Distinct tool/function names recorded for this request (org-scoped,
  // from the tool_calls table via the list endpoint). Absent = none
  // recorded; ids/arguments live in the inspector detail only.
  tool_calls?: string[]
  labels?: Record<string, string>
}

export interface RequestListParams {
  orgId: string
  model?: string
  from?: string
  to?: string
  errorsOnly?: boolean
  taskId?: string
  agentId?: string
  requestId?: string
  minLatencyMs?: number
  maxLatencyMs?: number
  minTokens?: number
  maxTokens?: number
  minCostUsd?: number
  maxCostUsd?: number
  cacheHit?: 'exact' | 'semantic' | 'miss'
  contentSearch?: string
  // YQL (Yabanin Query Language) — a structured filter/order expression parsed
  // server-side (pkg/adminstore/yql.go). AND-combines with the flat filters
  // above; the client validates via lib/queryLang.ts before committing.
  query?: string
  page?: number
  pageSize?: number
}

// Aggregate block over the same filter set as the list (Bifrost-parity
// stats: total, success rate, average latency, tokens, cost, plus p95).
export interface RequestListStats {
  total_requests: number
  success_rate: number
  average_latency_ms: number
  p95_latency_ms: number
  total_tokens_in: number
  total_tokens_out: number
  total_cost_usd: number
}

// A stats payload we cannot fully parse (empty body, shape drift, proxy
// error page served as 200 JSON) must degrade to the honest "failed to load"
// state, never crash the explorer on undefined.toLocaleString().
export function isRequestListStats(v: unknown): v is RequestListStats {
  if (typeof v !== 'object' || v === null) return false
  const s = v as Record<string, unknown>
  return (
    typeof s.total_requests === 'number' &&
    typeof s.success_rate === 'number' &&
    typeof s.average_latency_ms === 'number' &&
    typeof s.p95_latency_ms === 'number' &&
    typeof s.total_tokens_in === 'number' &&
    typeof s.total_tokens_out === 'number' &&
    typeof s.total_cost_usd === 'number'
  )
}

// ToolCallsReport — the cross-request tool-call aggregate (AV-13 card):
// top tools, per-model usage, totals. Calls exist only when parsed from the
// stored sample; absence is absence, never zero-usage.
export interface ToolCallsRow {
  tool_name: string
  calls: number
  share: number
  last_used_at: string
}

export interface ToolModelRow {
  model: string
  calls: number
}

export interface ToolCallsReport {
  total_calls: number
  distinct_tools: number
  top_tools: ToolCallsRow[] | null
  by_model: ToolModelRow[] | null
  requests_using_tools: number
}

export async function getToolCallsReport(orgId: string, days = 30, opts?: RequestOptions): Promise<ToolCallsReport> {
  return fetchJSON<ToolCallsReport>(
    `/organizations/${encodeURIComponent(orgId)}/tool-calls?days=${encodeURIComponent(days)}`, opts)
}

// PO-04: full request detail — the stored (redacted/truncated) response
// snapshot as raw JSON plus prompt_hash and the classifier/cache/routing
// columns. The request body is not stored (PH.1) and is absent by design.
export interface RequestDetail {
  request_id: string
  org_id: string
  model_requested: string
  model_used: string
  upstream_url?: string
  method: string
  status_code: number
  duration_ms: number
  tokens_in: number
  tokens_out: number
  error?: string
  created_at: string
  prompt_hash?: string
  response?: unknown
  cache_hit_type?: string
  counterfactual_cost_usd: number
  cost_in_usd: number
  classifier_class?: string
  classifier_confidence?: number
  classifier_source?: string
  tier_used?: string
  ab_group?: string
  task_id?: string
  agent_id?: string
  routing_decision?: string
  upstream_request?: string | object
  upstream_response?: string | object
  // Tool/function calls recorded for this request (distinct names from the
  // tool_calls table, extracted by loggerd BEFORE the sample is truncated).
  // Authoritative where upstream_response is cut short; always a list —
  // empty means "none recorded".
  tool_calls?: Array<{ tool_name: string }>
  // Per-occurrence tool calls with reassembled arguments (0014; rows exist
  // only for requests logged after that migration). These are the most
  // authoritative source — args recorded pre-truncation at log time.
  tool_call_invocations?: Array<{
    seq: number
    call_id: string | null
    tool_name: string
    arguments: string | null
  }>
  home_region: string
  // Observability parity (Bifrost attempt trail); null = unknown (legacy
  // rows, non-streaming requests).
  first_token_ms?: number | null
  attempt_count?: number | null
  retry_count?: number | null
  labels?: Record<string, string>
  // FIX-20: parsed envelope of the processed, client-facing response
  // (status/reason/model/content/reasoning/tool_calls). Absent for legacy
  // rows and when no processed response was captured — the raw `response`
  // field stays the verbatim column either way.
  response_view?: {
    status: 'complete' | 'partial'
    reason?: string
    model?: string
    content: string
    reasoning_content?: string
    tool_calls?: Array<{
      index: number
      id?: string
      name?: string
      arguments?: string
    }>
    finish_reason?: string
    truncated?: boolean
  }
}

export async function getRequestDetail(orgId: string, requestId: string, opts?: RequestOptions): Promise<RequestDetail> {
  return fetchJSON(`/organizations/${encodeURIComponent(orgId)}/requests/${encodeURIComponent(requestId)}`, opts)
}

export async function listRequests(params: RequestListParams, opts?: RequestOptions): Promise<Paginated<RequestRow>> {
  const qs = new URLSearchParams()
  qs.set('page', String(params.page ?? 1))
  qs.set('page_size', String(params.pageSize ?? 50))
  if (params.model) qs.set('model', params.model)
  if (params.from) qs.set('from', params.from)
  if (params.to) qs.set('to', params.to)
  if (params.errorsOnly) qs.set('errors', 'true')
  if (params.taskId) qs.set('task_id', params.taskId)
  if (params.agentId) qs.set('agent_id', params.agentId)
  if (params.requestId) qs.set('request_id', params.requestId)
  if (params.minLatencyMs) qs.set('min_latency_ms', String(params.minLatencyMs))
  if (params.maxLatencyMs) qs.set('max_latency_ms', String(params.maxLatencyMs))
  if (params.minTokens) qs.set('min_tokens', String(params.minTokens))
  if (params.maxTokens) qs.set('max_tokens', String(params.maxTokens))
  if (params.minCostUsd) qs.set('min_cost_usd', String(params.minCostUsd))
  if (params.maxCostUsd) qs.set('max_cost_usd', String(params.maxCostUsd))
  if (params.cacheHit) qs.set('cache_hit', params.cacheHit)
  if (params.contentSearch) qs.set('q', params.contentSearch)
  if (params.query) qs.set('query', params.query)
  return fetchJSON<Paginated<RequestRow>>(`/organizations/${encodeURIComponent(params.orgId)}/requests?${qs.toString()}`, opts)
}

// Aggregate block over the SAME filters as listRequests — pass the identical
// param object so the stats always describe exactly what the table shows.
export async function requestStats(params: RequestListParams, opts?: RequestOptions): Promise<RequestListStats> {
  const qs = new URLSearchParams()
  if (params.model) qs.set('model', params.model)
  if (params.from) qs.set('from', params.from)
  if (params.to) qs.set('to', params.to)
  if (params.errorsOnly) qs.set('errors', 'true')
  if (params.taskId) qs.set('task_id', params.taskId)
  if (params.agentId) qs.set('agent_id', params.agentId)
  if (params.requestId) qs.set('request_id', params.requestId)
  if (params.minLatencyMs) qs.set('min_latency_ms', String(params.minLatencyMs))
  if (params.maxLatencyMs) qs.set('max_latency_ms', String(params.maxLatencyMs))
  if (params.minTokens) qs.set('min_tokens', String(params.minTokens))
  if (params.maxTokens) qs.set('max_tokens', String(params.maxTokens))
  if (params.minCostUsd) qs.set('min_cost_usd', String(params.minCostUsd))
  if (params.maxCostUsd) qs.set('max_cost_usd', String(params.maxCostUsd))
  if (params.cacheHit) qs.set('cache_hit', params.cacheHit)
  if (params.contentSearch) qs.set('q', params.contentSearch)
  if (params.query) qs.set('query', params.query)
  const suffix = qs.toString()
  return fetchJSON<RequestListStats>(
    `/organizations/${encodeURIComponent(params.orgId)}/requests/stats${suffix ? `?${suffix}` : ''}`,
    opts,
  )
}
