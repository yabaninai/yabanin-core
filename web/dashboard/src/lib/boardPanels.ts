// AUX-07 — the shared board-panel loader and drill helper. Dashboards and
// the Overview pinned-panels section (both render the same BoardPanelCard)
// fetch panel results through this one path so both screens obey the same
// reproduction rules: the exact applied window (never a drifting preset),
// abortable loads, chunked requests.

import { fetchAnalyticsQuery } from '../api/client'
import { ApiError } from '../api/client'
import type { AnalyticsResult } from './analyticsQuery.ts'
import { pointDrillYql } from './analyticsQuery.ts'
import { explorerLink } from './explorerLink.ts'
import type { ResolvedPanel } from './boards.ts'

export type PanelPayload = AnalyticsResult | ApiError

export async function loadPanels(
  org: string, from: string, to: string, tz: string,
  panels: ResolvedPanel[], signal: AbortSignal,
): Promise<Map<string, PanelPayload>> {
  const out = new Map<string, PanelPayload>()
  const visible = panels.filter(p => !p.hidden)
  for (let i = 0; i < visible.length; i += 4) {
    const chunk = visible.slice(i, i + 4)
    await Promise.all(chunk.map(async panel => {
      try {
        const res = await fetchAnalyticsQuery({
          org, from, to,
          // The board fetches the operator's exact window — never a
          // drifting preset (AUX-07: a transition reproduces the result).
          period: 'custom',
          metrics: panel.query.metrics,
          groupBy: panel.query.groupBy,
          granularity: panel.query.granularity,
          filter: panel.query.filter,
          top: panel.query.top,
          compare: false,
          chart: panel.query.chart,
          tz,
        }, { signal })
        out.set(panel.id, res)
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return
        out.set(panel.id, err instanceof ApiError ? err : new ApiError(500, 'failed'))
      }
    }))
  }
  return out
}

// AUX-09: a panel point/bar drills into the requests behind that aggregate
// (the same pointDrillYql contract the analytics explorer uses): drillable
// dims + the point's time bucket, over the board's applied window. Values
// without a request-side field (team, status_class) drill by time alone —
// never an invented filter. A failed/absent result never drills (the chart
// that would call this does not render, so this is a belt-and-braces guard).
export function drillPanelPoint(
  panel: ResolvedPanel, result: PanelPayload | undefined,
  org: string, win: { from: string; to: string },
) {
  return (click: { seriesKey: string; x: string }) => {
    if (!result || result instanceof ApiError) return
    const useTime = panel.query.chart !== 'bar' && result.columns.some(c => c.type === 'time')
    window.location.hash = explorerLink({
      org,
      from: win.from,
      to: win.to,
      yql: pointDrillYql(result, click.seriesKey, click.x,
        { from: win.from, to: win.to, granularity: panel.query.granularity }, useTime),
    })
  }
}
