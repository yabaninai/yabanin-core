import { useCallback } from 'react'
import {
  fetchLatency,
  fetchQualityScores,
  fetchShadowComparison,
  type LatencyReport,
  type QualityReport,
  type ShadowComparison,
} from '../../api/client'
import { deriveScreenState, useScopedQuery, type ScreenState } from '../../hooks/useScopedQuery'

// The Compare screen read — shadow cost comparison plus the supplementary
// latency percentiles and quality scores. Contract kept from the
// pre-refactor load:
//   * the shadow comparison is the screen's backbone — its failure is the
//     screen error (an aborted fetch stays silence, never an error);
//   * latency + quality are supplementary: a failure there must not blank
//     the shadow comparison (they surface as their "unavailable" cards);
//   * the latency window mirrors the shadow window (since = now - days) so
//     both figures describe the same applied scope.

export interface CompareLoad {
  shadow: ShadowComparison
  latency: LatencyReport | null
  quality: QualityReport | null
  /** The applied scope+window, frozen at load time. */
  applied: { orgId: string; days: number }
}

export function useCompareReports(orgId: string, days: number): {
  shadow: ShadowComparison | null
  latency: LatencyReport | null
  quality: QualityReport | null
  /** The applied scope+window of the shown numbers (applied, not draft). */
  applied: { orgId: string; days: number } | null
  loading: boolean
  error: string
  state: ScreenState
  load: (opts?: { refresh?: boolean }) => void
} {
  const fetcher = useCallback(async (signal: AbortSignal): Promise<CompareLoad> => {
    // The window for the latency percentiles mirrors the shadow window so both
    // figures describe the same applied scope. since = now - days (RFC3339).
    const since = new Date(Date.now() - days * 86_400_000).toISOString()
    const [shadowRes, latencyRes, qualityRes] = await Promise.allSettled([
      fetchShadowComparison({ days, org_id: orgId }, { signal }),
      fetchLatency({ org_id: orgId, since }, { signal }),
      fetchQualityScores({ days, org_id: orgId }, { signal }),
    ])
    if (shadowRes.status === 'rejected') {
      // Rethrow verbatim: the shared lifecycle drops ApiError(0) (aborted)
      // and turns every other rejection into the screen error.
      throw shadowRes.reason
    }
    return {
      shadow: shadowRes.value,
      latency: latencyRes.status === 'fulfilled' ? latencyRes.value : null,
      quality: qualityRes.status === 'fulfilled' ? qualityRes.value : null,
      applied: { orgId, days },
    }
  }, [orgId, days])
  const q = useScopedQuery<CompareLoad>({
    key: `${orgId}|${days}`,
    org: orgId,
    enabled: !!orgId,
    fetcher,
  })
  const state = deriveScreenState({
    error: q.error,
    loading: q.loading,
    hasResult: q.data != null,
    resultHasContent: !!q.data && q.data.shadow.by_model.length > 0,
  })
  return {
    shadow: q.data?.shadow ?? null,
    latency: q.data?.latency ?? null,
    quality: q.data?.quality ?? null,
    applied: q.data?.applied ?? null,
    loading: q.loading,
    error: q.error,
    state,
    load: q.load,
  }
}
