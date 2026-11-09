import { useCallback } from 'react'
import { fetchAnalyticsQuery } from '../../api/client'
import type { AnalyticsResult } from '../../lib/analyticsQuery'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import {
  CONSUMER_TOP, mergeConsumers, type ConsumersBoard,
} from './overviewConsumers'

// grouped by team) and per agent key, one analytics query each. Both queries
// ride the shared scoped-read lifecycle (useScopedQuery): a scope/window
// change aborts the in-flight pair and starts a new one, a failed refresh
// keeps the last good board with the honest stale marker.
//
// Partial honesty: the two sources fail independently. One failed source
// still shows the other half with `failures: 1` (the panel renders a partial
// notice); both failing throws the first reason so the screen-level error
// state engages (a board made of nothing must never read as "no consumers").

export function useOverviewConsumers(org: string, from: string, to: string, enabled: boolean): {
  board: ConsumersBoard | null
  loading: boolean
  refreshing: boolean
  refreshStale: boolean
  error: string
  load: (opts?: { refresh?: boolean }) => void
} {
  const fetcher = useCallback(
    async (signal: AbortSignal): Promise<ConsumersBoard> => {
      const base = {
        org,
        from,
        to,
        metrics: ['cost_usd', 'requests'],
        granularity: 'none' as const,
        filter: '',
        top: CONSUMER_TOP,
        compare: false,
        chart: 'bar' as const,
        tz: '',
        period: 'custom' as const,
      }
      const [team, agent] = await Promise.allSettled([
        fetchAnalyticsQuery({ ...base, groupBy: ['team'] }, { signal }),
        fetchAnalyticsQuery({ ...base, groupBy: ['agent'] }, { signal }),
      ])
      const value = (r: PromiseSettledResult<AnalyticsResult>): AnalyticsResult | null =>
        r.status === 'fulfilled' ? r.value : null
      const failures = (team.status === 'rejected' ? 1 : 0) + (agent.status === 'rejected' ? 1 : 0)
      if (failures === 2) {
        throw team.status === 'rejected' ? team.reason : (agent as PromiseRejectedResult).reason
      }
      return mergeConsumers(value(team), value(agent), failures)
    },
    [org, from, to],
  )
  const q = useScopedQuery<ConsumersBoard>({
    key: `${org}|${from}|${to}`,
    org,
    enabled,
    fetcher,
  })
  return {
    board: q.data,
    loading: q.loading,
    refreshing: q.refreshing,
    refreshStale: q.refreshStale,
    error: q.error,
    load: q.load,
  }
}
