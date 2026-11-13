import { useCallback } from 'react'
import { fetchSavingsReport, type CostAnalyticsData } from '../../api/client'
import { deriveScreenState, useScopedQuery, type ScreenState } from '../../hooks/useScopedQuery'

// Savings report over the committed org (the shell's GlobalScope org, no
// page-local scope) and window, with the freshness semantics on top of the
// shared lifecycle:
//   * an org/window change is a NEW load (error resets, data is replaced);
//   * a refresh (manual ⟳ or an auto tick) keeps the last good data on the
//     screen and raises the honest `refreshStale` marker on failure;
//   * `asOf` (the "data as of" clock) is set on every SUCCESSFUL load;
//   * the applied org and window freeze at load time and ride back
//     with the result — captions and drill links always describe the scope
//     the shown numbers were computed over, including in the stale window
//     while a refetch for a newer scope is still in flight, never the live
//     draft (there is no page-local draft any more: the topbar commits).

interface OverviewLoad {
  data: CostAnalyticsData
  /** The org the report was fetched with, frozen at load time ('' = all). */
  applied: { org: string }
  /** The window (day count) the report was fetched with. */
  days: number
}

export function useOverviewReport(org: string, days: number): {
  data: CostAnalyticsData | null
  /** The org the SHOWN data was fetched with (empty until the first load). */
  appliedOrg: string
  /** The window (day count) the shown data was fetched with. */
  loadedDays: number
  loading: boolean
  refreshing: boolean
  refreshStale: boolean
  error: string
  asOf: number | null
  state: ScreenState
  /** A new (screen-replacing) load — the Retry action. */
  load: (opts?: { refresh?: boolean }) => void
  /** Keep-data reload (manual ⟳, auto-refresh ticks). */
  refresh: () => void
} {
  const orgId = org.trim()
  const fetcher = useCallback(
    (signal: AbortSignal): Promise<OverviewLoad> => {
      return fetchSavingsReport(
        { days, org_id: orgId || undefined },
        { signal },
      ).then(data => ({ data, applied: { org: orgId }, days }))
    },
    [days, orgId],
  )
  const q = useScopedQuery<OverviewLoad>({
    key: `${orgId}|${days}`,
    org: orgId,
    fetcher,
  })
  const { load } = q
  const state = deriveScreenState({
    error: q.error,
    // A refresh must not flash the stale/loading notice over data
    // that stays on screen.
    loading: q.loading && !q.refreshing,
    hasResult: q.data != null,
    resultHasContent: !!q.data?.data.total_requests,
  })
  const refresh = useCallback(() => { load({ refresh: true }) }, [load])
  return {
    data: q.data?.data ?? null,
    appliedOrg: q.data?.applied.org ?? '',
    loadedDays: q.data?.days ?? days,
    loading: q.loading,
    refreshing: q.refreshing,
    refreshStale: q.refreshStale,
    error: q.error,
    asOf: q.asOf,
    state,
    load,
    refresh,
  }
}
