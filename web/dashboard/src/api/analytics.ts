// savings, shadow comparison, latency, quality, task analytics, the analytics
// query engine and its saved views, label-key stats and recent errors.

import { analyticsApiQuery, type AnalyticsParams, type AnalyticsResult, type LabelKeyStat } from '../lib/analyticsQuery.ts'
import { readJSON, type RequestOptions } from './transport.ts'
import { fetchJSON, postJSON } from './http.ts'

// ASTR-09: recent failed requests (GET /api/analytics/recent-errors).
// NOTE: this endpoint exposes request_logs.id (a row id), NOT the gateway
// request_id — a direct link from an error row to a lineage record is
// therefore not possible with the current API (documented explorer gap).
export interface RecentErrorRow {
  id: number
  org_id: string
  model_used: string
  status_code: number
  duration_ms: number
  error?: string
  created_at: string
}

export async function fetchRecentErrors(orgId?: string, limit = 50, opts?: RequestOptions): Promise<RecentErrorRow[]> {
  const qs = new URLSearchParams()
  if (orgId) qs.set('org_id', orgId)
  qs.set('limit', String(limit))
  const result = await fetchJSON<RecentErrorRow[]>(`/analytics/recent-errors?${qs.toString()}`, opts)
  return Array.isArray(result) ? result : []
}

// AF-07 pricing-coverage classification of the cost window (matches
// PricingMetadata in pkg/adminstore/savings.go): complete = every request
// priced, partial = measured, some unpriced, unknown = the cost of the
// window cannot be quantified (measurement failed, or 100% unpriced),
// empty = no requests in the window (not a coverage measurement).
export type PricingCoverageStatus = 'complete' | 'partial' | 'unknown' | 'empty'

export interface PricingMetadata {
  pricing_as_of?: string
  // Structured citation of the served reference catalog (CORE-REF-04):
  // sealed version, generation date, digest. Absent on legacy
  // snapshot-backed reports (savings.go PricingCatalogInfo).
  pricing_catalog?: { version: string; generated_at: string; digest: string }
  // Absent on pre-AF-07 responses — an absent status must not be read as
  // proven full coverage (savings.go).
  coverage_status?: PricingCoverageStatus
  // Explicit JSON null when the coverage measurement did not run — null is
  // "not measured", never zero coverage (zero cost is not free).
  unpriced_share?: number | null
  unpriced_models?: string[]
  // Stable failure marker, kept separate from the pricing_as_of provenance.
  coverage_error?: string
}

export interface CostAnalyticsData {
  period: string
  total_requests: number
  actual_cost_usd: number
  counterfactual_cost_usd: number
  combined_savings_pct: number
  kill_criterion_met: boolean
  cache_hits: number
  cache_savings_pct: number
  routed_requests: number
  routing_savings_pct: number
  top_models_by_cost: Array<{
    model: string
    requests: number
    actual_cost_usd: number
    counterfactual_cost_usd: number
    savings_pct: number
  }>
  daily_breakdown: Array<{
    date: string
    requests: number
    actual_cost_usd: number
    counterfactual_cost_usd: number
    savings_pct: number
  }>
  classifier_distribution: Array<{
    class: string
    count: number
    pct: number
    avg_confidence: number
  }>
  // A01: pricing as-of / completeness context (additive — may be absent on
  // older backends).
  pricing?: PricingMetadata
}

export async function fetchSavingsReport(params: { days?: number; org_id?: string; provider?: string } = {}, opts?: RequestOptions): Promise<CostAnalyticsData> {
  const qs = new URLSearchParams()
  if (params.days) qs.set('days', String(params.days))
  if (params.org_id) qs.set('org_id', params.org_id)
  if (params.provider) qs.set('provider', params.provider)
  return readJSON<CostAnalyticsData>(`/api/analytics/savings?${qs}`, opts)
}

// ===== CMP-01: model comparison (shadow cost + org latency) =====

// One per-(primary, shadow) model pair from the shadow comparison. The verdict
// is "cheaper" / "pricier" / "insufficient_data" (the last also for a delta
// within the noise band or below the overlap threshold — the backend does not
// over-claim).
export interface ShadowModelCompare {
  primary_model: string
  shadow_model: string
  overlap: number
  primary_avg_usd: number
  shadow_avg_usd: number
  delta_pct: number
  verdict: 'cheaper' | 'pricier' | 'insufficient_data'
}

// The task-tag dimension — cost + latency per (task class, primary,
// shadow) triple, from the same shadow join grouped by request_logs.task_id
// (NULL → "(untagged)"). Field names match
// ShadowTaskClassCompare (pkg/adminstore/shadow_compare.go).
export interface ShadowTaskClassCompare {
  task_class: string
  primary_model: string
  shadow_model: string
  overlap: number
  primary_avg_usd: number
  shadow_avg_usd: number
  delta_pct: number
  primary_avg_ms: number
  shadow_avg_ms: number
  verdict: 'cheaper' | 'pricier' | 'insufficient_data'
}

export interface ShadowComparison {
  period: string
  primary_model: string
  shadow_model: string
  overlap: number
  primary_avg_usd: number
  shadow_avg_usd: number
  delta_pct: number
  verdict: 'cheaper' | 'pricier' | 'insufficient_data'
  by_model: ShadowModelCompare[]
  by_task_class: ShadowTaskClassCompare[]
}

// Org-wide latency percentiles in milliseconds (NOT per-model — the backend
// has no per-model latency endpoint; the screen captions this honestly). Field
// names match LatencyPercentile (pkg/adminstore/store.go).
export interface LatencyReport {
  p50: number
  p90: number
  p95: number
  p99: number
}

export async function fetchShadowComparison(params: { days?: number; org_id?: string } = {}, opts?: RequestOptions): Promise<ShadowComparison> {
  const qs = new URLSearchParams()
  if (params.days) qs.set('days', String(params.days))
  if (params.org_id) qs.set('org_id', params.org_id)
  return readJSON<ShadowComparison>(`/api/analytics/shadow?${qs}`, opts)
}

export async function fetchLatency(params: { org_id?: string; since?: string } = {}, opts?: RequestOptions): Promise<LatencyReport> {
  const qs = new URLSearchParams()
  if (params.org_id) qs.set('org_id', params.org_id)
  if (params.since) qs.set('since', params.since)
  return readJSON<LatencyReport>(`/api/analytics/latency?${qs}`, opts)
}

// ===== ADL-04: quality closed-loop (evalgate LLM-as-judge verdicts) =====

// One (primary, shadow) model pair's quality over the window: the average
// cheap-model (primary) and premium-model (shadow) quality the judge assigned,
// plus the upgrade pressure (how often the judge said the premium would have
// been better). Field names match pkg/adminstore/quality_compare.go.
export interface QualityModelScore {
  primary_model: string
  shadow_model: string
  verdicts: number
  cheap_quality: number
  premium_quality: number
  upgrade_rate: number
}

// Quality by task class (request_logs task_id; NULL → "(untagged)"), so the
// screen shows which model serves which class of agentic task well.
export interface QualityTaskClassScore {
  task_class: string
  primary_model: string
  verdicts: number
  cheap_quality: number
  upgrade_rate: number
}

// The human-facing routing suggestion. match_expr / target_model / priority are
// a DRAFT routing rule — applying is human-only (the Rules page pre-fills the
// form with these and does NOT save).
export interface QualityRecommendation {
  has_recommendation: boolean
  primary_model: string
  shadow_model: string
  match_expr: string
  target_model: string
  priority: number
  upgrade_rate: number
  verdicts: number
  justification: string
}

export interface QualityReport {
  org_id: string
  period: string
  from: string
  to: string
  total_verdicts: number
  by_model: QualityModelScore[]
  by_task_class: QualityTaskClassScore[]
  recommendation?: QualityRecommendation
  verdict: 'has_data' | 'insufficient_data'
  sample_scope_note: string
}

export async function fetchQualityScores(params: { days?: number; org_id?: string } = {}, opts?: RequestOptions): Promise<QualityReport> {
  const qs = new URLSearchParams()
  if (params.days) qs.set('days', String(params.days))
  if (params.org_id) qs.set('org_id', params.org_id)
  return readJSON<QualityReport>(`/api/analytics/quality?${qs}`, opts)
}

// ===== ADL-01: CTOR / task cost analytics (the Tasks screen) =====
//
// GET /api/analytics/tasks — per-group cost / counterfactual / savings /
// cache-hits for an org. The backend already exists (G4); ADL-01 adds the
// dashboard screen over it. Field names match TaskAnalyticsReport /
// TaskAnalyticsGroup (pkg/adminstore/task_analytics.go).

export interface TaskAnalyticsGroup {
  group: string
  cost_usd: number
  counterfactual_usd: number
  savings_usd: number
  cache_hits: number
  request_count: number
}

export interface TaskAnalyticsReport {
  org_id: string
  from: string
  to: string
  group_by: string
  groups: TaskAnalyticsGroup[]
  total_cost_usd: number
}

export type TaskGroupBy = 'task' | 'session' | 'agent'

export interface TaskAnalyticsParams {
  orgId: string
  from?: string
  to?: string
  groupBy?: TaskGroupBy
  limit?: number
}

export async function fetchTaskAnalytics(params: TaskAnalyticsParams, opts?: RequestOptions): Promise<TaskAnalyticsReport> {
  const qs = new URLSearchParams()
  qs.set('org_id', params.orgId)
  if (params.from) qs.set('from', params.from)
  if (params.to) qs.set('to', params.to)
  qs.set('group_by', params.groupBy ?? 'task')
  qs.set('limit', String(params.limit ?? 100))
  return readJSON<TaskAnalyticsReport>(`/api/analytics/tasks?${qs}`, opts)
}

export function analyticsCsvUrl(params: AnalyticsParams): string {
  return `/api/analytics/query?${analyticsApiQuery(params, 'csv')}`
}

export async function fetchAnalyticsQuery(params: AnalyticsParams, opts?: RequestOptions): Promise<AnalyticsResult> {
  return fetchJSON<AnalyticsResult>(`/analytics/query?${analyticsApiQuery(params)}`, opts)
}

export interface AnalyticsView {
  id: string
  org_id: string
  owner_id: string
  name: string
  query: Record<string, string>
  shared: boolean
}

export async function listAnalyticsViews(orgId: string, opts?: RequestOptions): Promise<AnalyticsView[]> {
  const rows = await fetchJSON<AnalyticsView[] | null>(`/analytics/views?org_id=${encodeURIComponent(orgId)}`, opts)
  return Array.isArray(rows) ? rows : []
}

export async function createAnalyticsView(orgId: string, body: { name: string; query: Record<string, string>; shared: boolean }, opts?: RequestOptions): Promise<AnalyticsView> {
  return postJSON<AnalyticsView>(`/analytics/views?org_id=${encodeURIComponent(orgId)}`, body, 'POST', opts)
}

export async function updateAnalyticsView(id: string, body: { name: string; query: Record<string, string>; shared: boolean }, opts?: RequestOptions): Promise<AnalyticsView> {
  return postJSON<AnalyticsView>(`/analytics/views/${encodeURIComponent(id)}`, body, 'PUT', opts)
}

export async function deleteAnalyticsView(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/analytics/views/${encodeURIComponent(id)}`, {}, 'DELETE', opts)
}

export async function fetchLabelKeys(orgId: string, from: string, to: string, opts?: RequestOptions): Promise<LabelKeyStat[]> {
  const q = new URLSearchParams({ org_id: orgId, from, to, metrics: 'requests' })
  const rows = await fetchJSON<LabelKeyStat[] | null>(`/analytics/label-keys?${q.toString()}`, opts)
  return rows ?? []
}
