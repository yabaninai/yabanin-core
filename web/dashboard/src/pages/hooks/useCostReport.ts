import { useCallback } from 'react'
import { fetchJSON, type PricingMetadata } from '../../api/client'
import { deriveScreenState, useScopedQuery, type ScreenState } from '../../hooks/useScopedQuery'

// AF-17 domain hook: the Cost screen read (U03 scope + UX-03 window →
// GET /api/analytics/{org}/cost). AUX-04: both scope fields are real — the
// endpoint accepts org_id + provider (+ days); the lifecycle (generation,
// abort, applied-vs-draft, AUX-23 freshness) lives in useScopedQuery.
export interface CostReport {
  total_cost_usd: number
  counterfactual_cost: number
  savings_usd: number
  savings_percent: number
  request_count: number
  avg_cost_per_request: number
  by_model: Array<{ model_name: string; total_cost: number; request_count: number }>
  by_day: Array<{ date: string; total_cost: number; request_count: number }>
  // A01/AF-07 (additive, may be absent on older backends): coverage_status +
  // unpriced_share (null = not measured) + coverage_error — the same contract
  // as the savings report (api/analytics.ts PricingMetadata).
  pricing?: PricingMetadata
}

export function useCostReport(orgId: string, provider: string, days: number): {
  report: CostReport | null
  loading: boolean
  error: string
  state: ScreenState
  load: (opts?: { refresh?: boolean }) => void
} {
  const fetcher = useCallback((signal: AbortSignal) =>
    fetchJSON<CostReport>(
      `/analytics/${encodeURIComponent(orgId)}/cost?days=${days}${provider ? `&provider=${encodeURIComponent(provider)}` : ''}`,
      { signal },
    ), [orgId, days, provider])
  const q = useScopedQuery<CostReport>({
    key: `${orgId}|${days}|${provider}`,
    org: orgId,
    enabled: !!orgId,
    fetcher,
  })
  const state = deriveScreenState({
    error: q.error,
    loading: q.loading,
    hasResult: q.data != null,
    resultHasContent: (q.data?.request_count ?? 0) > 0,
  })
  return { report: q.data, loading: q.loading, error: q.error, state, load: q.load }
}
