import { useCallback } from 'react'
import { fetchTaskAnalytics, type TaskAnalyticsReport, type TaskGroupBy } from '../../api/client'
import { deriveScreenState, useScopedQuery, type ScreenState } from '../../hooks/useScopedQuery'

// AF-17 domain hook: the Tasks screen read (ADL-01) — CTOR cost per
// task/session/agent over the applied org+window+grouping. The applied
// scope/window/grouping freeze at load time and ride back with the result,
// so the drill links and the applied caption always describe the report the
// shown rows were actually fetched for (AVR-01 applied vs draft) — including
// the stale window while a refetch for a newer scope is in flight.
// The lifecycle (generation, abort, AUX-22-safe table state untouched) lives
// in useScopedQuery.

export interface TaskLoad {
  report: TaskAnalyticsReport
  /** The applied scope+window, frozen at load time. */
  applied: { orgId: string; days: number; groupBy: TaskGroupBy; from: string; to: string }
}

export function useTaskReport(orgId: string, days: number, groupBy: TaskGroupBy): {
  report: TaskAnalyticsReport | null
  /** The applied scope+window of the shown report (null until a load lands). */
  applied: { orgId: string; days: number; groupBy: TaskGroupBy; from: string; to: string } | null
  loading: boolean
  error: string
  state: ScreenState
  load: (opts?: { refresh?: boolean }) => void
} {
  const fetcher = useCallback((signal: AbortSignal): Promise<TaskLoad> => {
    const to = new Date().toISOString()
    const from = new Date(Date.now() - days * 86_400_000).toISOString()
    return fetchTaskAnalytics({ orgId, from, to, groupBy, limit: 500 }, { signal })
      .then(report => ({ report, applied: { orgId, days, groupBy, from, to } }))
  }, [orgId, days, groupBy])
  const q = useScopedQuery<TaskLoad>({
    key: `${orgId}|${days}|${groupBy}`,
    org: orgId,
    enabled: !!orgId,
    fetcher,
  })
  const state = deriveScreenState({
    error: q.error,
    loading: q.loading,
    hasResult: q.data != null,
    resultHasContent: (q.data?.report.groups.length ?? 0) > 0,
  })
  return {
    report: q.data?.report ?? null,
    applied: q.data?.applied ?? null,
    loading: q.loading,
    error: q.error,
    state,
    load: q.load,
  }
}
