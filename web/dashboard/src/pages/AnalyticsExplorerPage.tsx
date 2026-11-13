import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { analyticsCsvUrl, fetchAnalyticsQuery, fetchLabelKeys, fetchSavingsReport, listAnalyticsViews, createAnalyticsView, updateAnalyticsView, deleteAnalyticsView, type AnalyticsView } from '../api/client'
import { ApiError } from '../api/client'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { MetricStrip, type Metric } from '../components/astra/MetricStrip'
import { MetricHint } from '../components/astra/MetricHint'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { useTablePrefs } from '../hooks/useTablePrefs'
import { TableSettingsMenu } from '../components/astra/TableSettingsMenu'
import { SavedViewsMenu } from '../components/astra/SavedViewsMenu'
import { ChartCard } from '../components/astra/ChartCard'
import { CopyIdButton } from '../components/astra/CopyIdButton'
import { OrgName } from '../components/astra/OrgName'
import { FilterBar } from '../components/astra/FilterBar'
import { GlobalScopeBar } from '../components/GlobalScopeBar'
import { auditReasonOpts } from '../components/astra/ActionDialog'
import { AnalyticsSeriesChart, type AnalyticsSeries } from '../components/LazyCharts'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { formatDate, uiLocale } from '../i18n/format'
import { YQL_FIELDS, type YqlFieldMeta } from '../lib/queryLang'
import { ANALYTICS_QUESTIONS, type AnalyticsQuestion } from '../lib/boards'
import { summarizeQuery, summarySlug } from '../lib/analyticsSummary'
import { readGlobalScope, useGlobalScope } from '../lib/globalScope'
import { explorerLink } from '../lib/explorerLink'
import {
  METRICS, METRIC_GROUPS, STANDARD_DIMS, chartRows, formatMetricValue, formatPercentRatio,
  metricDisplayUnit, metricMeta, parseAnalyticsHash, pointDrillYql, rowDrillYql,
  seriesDisplayName, seriesMetricId, serializeAnalyticsHash,
  type AnalyticsParams, type AnalyticsResult, type ChartKind, type ChartPoint, type Granularity,
  type MetricGroup, type PeriodPreset, type Translate,
} from '../lib/analyticsQuery'

const GRANS: Granularity[] = ['none', 'hour', 'day', 'week', 'month']
const METRIC_LIMIT = 6

function readLocation(): { params: AnalyticsParams; extra: Array<[string, string]> } {
  const q = window.location.hash.split('?')[1] ?? ''
  const src = new URLSearchParams(q)
  const out = parseAnalyticsHash(q)
  // The GlobalScope store is the org/tz owner (hash first, memory
  // fallback). When the arriving link carries no explicit period (neither
  // ?period= nor pinned borders), the remembered preset applies.
  const gs = readGlobalScope()
  out.params.org = gs.org
  out.params.tz = gs.tz
  if (!src.get('period') && !(src.get('from') && src.get('to'))) {
    out.params.period = gs.period
    out.params.from = gs.from
    out.params.to = gs.to
  }
  return out
}

function writeLocation(params: AnalyticsParams) {
  // Unknown params are re-read from the CURRENT hash on every write (not
  // cached): table state (analytics__sort/__page) lives next to these
  // params in the same query and must survive every params rewrite.
  const current = window.location.hash.split('?')[1] ?? ''
  const { extra } = parseAnalyticsHash(current)
  const next = `#analytics?${serializeAnalyticsHash(params, extra)}`
  if (window.location.hash !== next) history.replaceState(null, '', next)
}

function mutedValue(value: string) {
  return value === '(none)' || value === '(other)' || value === '(untagged)'
}

interface QueryChip {
  key: string
  label: string
  hint?: string
  onRemove: () => void
}

interface AnalyticsTableRow {
  id: string
  cells: Array<string | number | null>
  /** Δ vs the same bucket of the previous period, per result column (null = unknown). */
  deltas: Array<number | null>
}

const ROW_KEY_SEP = '\u0000'

function rowKey(cells: Array<string | number | null>, timeIdx: number, dimIdx: number[]): string {
  const dims = dimIdx.map(i => String(cells[i] ?? '')).join(ROW_KEY_SEP)
  const time = timeIdx >= 0 ? String(Date.parse(String(cells[timeIdx] ?? ''))) : ''
  return `${time}${ROW_KEY_SEP}${dims}`
}

function deltaPercent(cur: number | null, prev: number | null): number | null {
  if (cur == null || prev == null || !Number.isFinite(cur) || !Number.isFinite(prev) || prev === 0) return null
  return ((cur - prev) / Math.abs(prev)) * 100
}

export function AnalyticsExplorerPage() {
  const { t } = useTranslation()
  const initial = readLocation()
  const [params, setParams] = useState<AnalyticsParams>(initial.params)
  // collapsible side panel (open by default — it is the page's editor).
  const [configOpen, setConfigOpen] = useState(true)
  // Org/period/tz are owned by the GlobalScope store; the shared bar
  // writes through it and this page follows (the preset select below shows
  // the store's applied period — hand-edited borders read as 'custom').
  const gs = useGlobalScope()
  const scopeSig = `${gs.org}\u0000${gs.tz}\u0000${gs.period}\u0000${gs.period === 'custom' ? `${gs.from}\u0000${gs.to}` : ''}`
  const prevScopeSig = useRef(scopeSig)
  useEffect(() => {
    if (prevScopeSig.current === scopeSig) return
    prevScopeSig.current = scopeSig
    setParams(prev => ({
      ...prev,
      org: gs.org,
      tz: gs.tz,
      period: gs.period,
      from: gs.from,
      to: gs.to,
    }))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-syncs only when the shared scope actually moves
  }, [scopeSig])
  // Metric values render in the applied org's presentation currency
  // (display only, no FX — i18n/money.ts) and the active UI locale.
  const { currency } = useOrgPresentation(params.org || undefined)
  const metricFmt = { locale: uiLocale(), currency }
  const [labelKeys, setLabelKeys] = useState<string[]>([])
  const [modelNames, setModelNames] = useState<string[]>([])
  const [dimQuery, setDimQuery] = useState('')
  const [metricQuery, setMetricQuery] = useState('')
  const [result, setResult] = useState<AnalyticsResult | null>(null)
  // With compare on, the page fetches the same query for the previous
  // window (existing endpoint, no contract change) to draw the dashed previous
  // line and the table's Δ columns. Totals deltas come from result.compare.
  const [prevResult, setPrevResult] = useState<AnalyticsResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  // Sort + page live in the URL (#analytics?analytics__sort=…:…) — a
  // sorted view is a shareable link and survives reload.
  const { page, setPage, sort, setSort } = useTableUrlState('analytics')
  const [views, setViews] = useState<AnalyticsView[]>([])
  // A view may be shared with the organization (server-side flag).
  const [viewShared, setViewShared] = useState(false)
  // Per-table personalization (hidden columns + density) keyed by
  // the table id in localStorage.
  const prefs = useTablePrefs('analytics')

  // The shared FilterBar owns draft/debounce/error-highlight; the page
  // keeps params as the single applied state (the filter commits 300ms
  // after the last parse-ok edit).
  const applyFilter = (next: string) => {
    setParams(prev => (prev.filter === next ? prev : { ...prev, filter: next }))
  }

  // Field registry = the base YQL registry plus the org's live label keys
  // (GET /api/analytics/label-keys), so the builder can add label.<key>
  // clauses without typing raw syntax.
  const filterFields = useMemo<YqlFieldMeta[]>(() => [
    ...YQL_FIELDS,
    ...labelKeys.map(key => ({ name: `label.${key}`, kind: 'text' as const, nullable: true, orderable: false, aliases: [] })),
  ], [labelKeys])

  // Value suggestions from existing endpoints: models from the per-org cost
  // report (analytics.read — the same permission this page already needs).
  const queryValueHints = (field: string): string[] => {
    if (field === 'model' || field === 'model_requested') return modelNames
    return []
  }

  useEffect(() => {
    writeLocation(params)
  }, [params])

  useEffect(() => {
    if (!params.org) return
    const ctrl = new AbortController()
    fetchLabelKeys(params.org, params.from, params.to, { signal: ctrl.signal })
      .then(rows => setLabelKeys(rows.map(r => r.key)))
      .catch(() => setLabelKeys([]))
    return () => ctrl.abort()
  }, [params.org, params.from, params.to])

  // A new applied query resets the local page (the old page may not exist in
  // the new result). The mount fetch is exempt so a URL-restored page
  // survives the initial load.
  const paramsKey = JSON.stringify(params)
  const prevQueryKey = useRef(paramsKey)

  useEffect(() => {
    if (!params.org) return
    const ctrl = new AbortController()
    fetchSavingsReport({ org_id: params.org, days: 30 }, { signal: ctrl.signal })
      .then(rep => setModelNames((rep.top_models_by_cost ?? []).map(m => m.model)))
      .catch(() => setModelNames([]))
    return () => ctrl.abort()
  }, [params.org])

  useEffect(() => {
    if (!params.org || params.metrics.length === 0) return
    const ctrl = new AbortController()
    setLoading(true)
    setError(null)
    fetchAnalyticsQuery(params, { signal: ctrl.signal })
      .then(res => {
        setResult(res)
        if (prevQueryKey.current !== paramsKey) {
          prevQueryKey.current = paramsKey
          setPage(1)
        }
      })
      .catch(err => {
        if (err instanceof DOMException && err.name === 'AbortError') return
        setResult(null)
        setError(err instanceof ApiError ? err : new ApiError(500, t('analytics.errorGeneric')))
      })
      .finally(() => { if (!ctrl.signal.aborted) setLoading(false) })
    return () => ctrl.abort()
  }, [params, paramsKey, t, setPage])

  useEffect(() => {
    if (!params.org || !params.compare || params.metrics.length === 0) { setPrevResult(null); return }
    const span = Date.parse(params.to) - Date.parse(params.from)
    if (!Number.isFinite(span) || span <= 0) { setPrevResult(null); return }
    const ctrl = new AbortController()
    const prevFrom = new Date(Date.parse(params.from) - span).toISOString().replace(/\.\d{3}Z$/, 'Z')
    fetchAnalyticsQuery({ ...params, from: prevFrom, to: params.from, compare: false }, { signal: ctrl.signal })
      .then(res => { if (!ctrl.signal.aborted) setPrevResult(res) })
      .catch(() => { if (!ctrl.signal.aborted) setPrevResult(null) })
    return () => ctrl.abort()
  }, [params, paramsKey])

  useEffect(() => {
    if (!params.org) { setViews([]); return }
    const ctrl = new AbortController()
    listAnalyticsViews(params.org, { signal: ctrl.signal }).then(setViews).catch(() => setViews([]))
    return () => ctrl.abort()
  }, [params.org])

  const update = (patch: Partial<AnalyticsParams>) => setParams(prev => ({ ...prev, ...patch }))

  const queryBody = () => {
    const query: Record<string, string> = {
      org_id: params.org,
      from: params.from,
      to: params.to,
      metrics: params.metrics.join(','),
      granularity: params.granularity,
      top: String(params.top),
    }
    if (params.groupBy.length) query.group_by = params.groupBy.join(',')
    if (params.filter) query.filter = params.filter
    if (params.compare) query.compare = 'previous'
    if (params.tz) query.tz = params.tz
    return query
  }

  // The views menu is the shared SavedViewsMenu component (the same
  // contract as the localStorage pages; storage stays the server registry).
  // Errors surface on the page banner; dialog rejections surface in-dialog.
  const saveView = async (name: string) => {
    if (!params.org) return
    try {
      await createAnalyticsView(params.org, { name, query: queryBody(), shared: viewShared })
      setViews(await listAnalyticsViews(params.org))
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err : new ApiError(500, t('analytics.errorGeneric')))
    }
  }

  const openView = (view: AnalyticsView) => {
    const q = view.query
    const filter = q.filter ?? ''
    // A view's org/period/tz move through the GlobalScope store, so
    // opening a saved view re-scopes every screen, not just this one.
    if (q.org_id && q.org_id !== params.org) gs.setOrg(q.org_id)
    if (q.from && q.to && (q.from !== params.from || q.to !== params.to)) gs.setRange(q.from, q.to)
    if ((q.tz ?? '') !== params.tz) gs.setTz(q.tz ?? '')
    setParams(prev => ({
      ...prev,
      metrics: (q.metrics || 'requests').split(',').filter(Boolean),
      groupBy: (q.group_by || '').split(',').filter(Boolean).slice(0, 2),
      granularity: (q.granularity as Granularity) || prev.granularity,
      filter,
      top: Number(q.top || prev.top),
      compare: q.compare === 'previous',
    }))
  }

  // ActionDialog contract (enforced inside SavedViewsMenu): rename is
  // medium risk (dialog with a prefilled name input + optional reason);
  // delete is high risk (name confirmation + optional reason). The reason
  // rides X-Audit-Reason (server-side reason persistence is not wired yet).
  const refreshViews = () => {
    void listAnalyticsViews(params.org).then(setViews).catch(() => {})
  }

  const renameView = async (id: string, name: string, reason: string) => {
    const view = views.find(v => v.id === id)
    if (!view || !params.org) return
    await updateAnalyticsView(view.id, { name, query: view.query, shared: view.shared }, auditReasonOpts(reason))
    refreshViews()
  }

  const removeView = async (id: string, reason: string) => {
    const view = views.find(v => v.id === id)
    if (!view || !params.org) return
    await deleteAnalyticsView(view.id, auditReasonOpts(reason))
    refreshViews()
  }

  const applySavedView = (item: { id: string }) => {
    const view = views.find(v => v.id === item.id)
    if (view) openView(view)
  }

  // Presets go through the GlobalScope store — the unified presets
  // are one vocabulary, and the choice follows the operator to other screens.
  // 'custom' is a state (hand-pinned borders), never a selectable action.
  const applyPreset = (next: PeriodPreset) => {
    if (next === 'custom') return
    gs.setPeriod(next)
  }

  // A ready question applies the query shape of an existing
  // dashboards panel; period, org and filter stay the operator's.
  const applyQuestion = (question: AnalyticsQuestion) => {
    update({
      metrics: [...question.query.metrics],
      groupBy: [...question.query.groupBy],
      granularity: question.query.granularity,
      filter: question.query.filter,
      chart: question.query.chart,
      top: question.query.top,
    })
  }

  const toggleMetric = (id: string) => {
    setParams(prev => {
      const has = prev.metrics.includes(id)
      if (has) return { ...prev, metrics: prev.metrics.filter(m => m !== id) }
      if (prev.metrics.length >= METRIC_LIMIT) return prev
      return { ...prev, metrics: [...prev.metrics, id] }
    })
  }

  const setGroup = (index: number, value: string) => {
    setParams(prev => {
      const groupBy = [...prev.groupBy]
      if (!value) groupBy.splice(index, 1)
      else groupBy[index] = value
      return { ...prev, groupBy: groupBy.filter(Boolean).slice(0, 2) }
    })
  }

  const dimOptions = useMemo(() => {
    const labels = labelKeys.map(k => `label:${k}`)
    const selected = params.groupBy.filter(d => d.startsWith('label:') && !labels.includes(d))
    const all = [...STANDARD_DIMS, ...selected, ...labels]
    const q = dimQuery.trim().toLowerCase()
    return q ? all.filter(d => d.includes(q)) : all
  }, [labelKeys, dimQuery, params.groupBy])

  // Searchable metric list (name + glossary description).
  const translate = t as Translate
  const visibleMetrics = useMemo(() => {
    const q = metricQuery.trim().toLowerCase()
    if (!q) return METRICS
    return METRICS.filter(m => t(m.labelKey).toLowerCase().includes(q) || t(m.descKey).toLowerCase().includes(q))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-filter on locale change
  }, [metricQuery, t, params.metrics])

  // The applied-query summary heads the result block, titles the
  // chart and names the exported CSV.
  const summary = useMemo(
    () => summarizeQuery(params, { t: translate, formatDate: iso => formatDate(iso, params.tz || undefined) }),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-render on locale change
    [params, t],
  )

  // time buckets compares categories — columns; a time series keeps the
  // requested line/area/stacked shape, and the chart component downgrades a
  // short series to columns while a dashed compare line stays a line (the
  // chart off — the data table below is the whole answer.
  const effectiveChart: ChartKind = params.chart === 'table'
    ? 'table'
    : params.granularity === 'none' ? 'bar' : params.chart

  const useTimeChart = !!result && effectiveChart !== 'bar' && result.columns.some(c => c.type === 'time')
  const chart = result && effectiveChart !== 'table' ? chartRows(result, effectiveChart) : null

  // Previous-window pivot for the dashed line: same chartRows shape, x
  // shifted forward by the applied span onto the current buckets.
  const compareOverlay = useMemo((): { data: ChartPoint[]; series: AnalyticsSeries[] } => {
    if (!chart || !prevResult || !useTimeChart || effectiveChart !== 'line') return { data: chart?.points ?? [], series: [] }
    const span = Date.parse(params.to) - Date.parse(params.from)
    if (!Number.isFinite(span) || span <= 0) return { data: chart.points, series: [] }
    const prevChart = chartRows(prevResult, 'line')
    const byX = new Map<string, ChartPoint>()
    for (const p of prevChart.points) {
      const shifted = Date.parse(p.x) + span
      if (Number.isFinite(shifted)) byX.set(String(shifted), p)
    }
    const series: AnalyticsSeries[] = []
    const data = chart.points.map(point => {
      const prev = byX.get(String(Date.parse(point.x)))
      if (!prev) return point
      const next: ChartPoint = { ...point }
      for (const s of chart.series) {
        const v = prev[s.key]
        next[`cmp:${s.key}`] = typeof v === 'number' ? v : null
      }
      return next
    })
    for (const s of chart.series) {
      if (!data.some(p => p[`cmp:${s.key}`] != null)) continue
      series.push({
        key: `cmp:${s.key}`,
        name: t('analytics.compareSeries', { name: seriesDisplayName(s.key, result, translate) }),
        dashed: true,
      })
    }
    return { data, series }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-derives on locale change
  }, [chart, prevResult, useTimeChart, effectiveChart, params.from, params.to, t])

  // Join previous-window rows onto the current rows (dims + shifted time
  // bucket) for the table's Δ columns. No match → the delta stays unknown.
  const prevRowsByKey = useMemo(() => {
    if (!prevResult) return null
    const span = Date.parse(params.to) - Date.parse(params.from)
    if (!Number.isFinite(span) || span <= 0) return null
    const timeIdx = prevResult.columns.findIndex(c => c.type === 'time')
    const dimIdx = prevResult.columns.map((c, i) => (c.type !== 'time' && c.type !== 'number') ? i : -1).filter(i => i >= 0)
    const map = new Map<string, Array<string | number | null>>()
    for (const row of prevResult.rows) {
      const time = timeIdx >= 0 ? Date.parse(String(row[timeIdx] ?? '')) + span : NaN
      const key = `${Number.isFinite(time) ? String(time) : ''}${ROW_KEY_SEP}${dimIdx.map(i => String(row[i] ?? '')).join(ROW_KEY_SEP)}`
      map.set(key, row)
    }
    return map
  }, [prevResult, params.from, params.to])
  const compareOn = params.compare && prevRowsByKey !== null

  const tableRows = useMemo<AnalyticsTableRow[]>(() => {
    if (!result) return []
    const timeIdx = result.columns.findIndex(c => c.type === 'time')
    const dimIdx = result.columns.map((c, i) => (c.type !== 'time' && c.type !== 'number') ? i : -1).filter(i => i >= 0)
    return result.rows.map((row, i) => {
      const deltas = result.columns.map((col, ci) => {
        if (col.type !== 'number' || !compareOn || !prevRowsByKey) return null
        const prevRow = prevRowsByKey.get(rowKey(row, timeIdx, dimIdx))
        if (!prevRow) return null
        const cur = typeof row[ci] === 'number' ? row[ci] : Number(row[ci])
        const prev = typeof prevRow[ci] === 'number' ? prevRow[ci] : Number(prevRow[ci])
        return deltaPercent(Number.isFinite(cur) ? cur : null, Number.isFinite(prev) ? prev : null)
      })
      return { id: String(i), cells: row, deltas }
    })
  }, [result, compareOn, prevRowsByKey])

  // Metric columns take their header and glossary hint from the
  // registry and render values through the numbers contract (locale-aware
  // money/percent/counts — never a raw String(number)). With compare
  // on, each metric column is followed by its Δ column.
  const columns: DataTableColumn<AnalyticsTableRow>[] = useMemo(() => {
    const out: DataTableColumn<AnalyticsTableRow>[] = []
    ;(result?.columns ?? []).forEach((col, i) => {
      const meta = col.type === 'number' ? metricMeta(col.name) : undefined
      const header = col.type === 'time'
        ? t('analytics.time')
        : col.type === 'number'
          ? (meta ? t(meta.labelKey) : t(`analytics.metric.${col.name}`))
          : (col.name.startsWith('label:') ? t('analytics.labelDim', { key: col.name.slice(6) }) : t(`analytics.dim.${col.name}`))
      out.push({
        key: col.name,
        header,
        headerHint: meta ? t(meta.descKey) : undefined,
        align: col.type === 'number' ? 'right' as const : 'left' as const,
        mono: true,
        type: col.type === 'time' ? 'date' as const : col.type === 'number' ? 'number' as const : 'text' as const,
        unit: col.unit,
        getSortValue: row => row.cells[i],
        render: row => {
          const v = row.cells[i]
          const text = v == null
            ? ''
            : meta
              ? (formatMetricValue(col.name, typeof v === 'number' ? v : Number(v), metricFmt) ?? String(v))
              : String(v)
          const hint = text === '(none)' || text === '(untagged)' ? t('analytics.noneHint') : text === '(other)' ? t('analytics.otherHint') : ''
          return (
            <span className="inline-flex items-center gap-1">
              <span className={mutedValue(text) ? 'text-[color:var(--astra-text-muted)]' : undefined} title={hint}>{text || '—'}</span>
              {text ? <CopyIdButton value={text} label={t('analytics.copy')} /> : null}
            </span>
          )
        },
      })
      if (meta && compareOn) {
        out.push({
          key: `delta:${col.name}`,
          header: t('analytics.deltaCol', { name: t(meta.labelKey) }),
          headerHint: t('analytics.deltaColHint'),
          align: 'right',
          mono: true,
          type: 'number',
          getSortValue: row => row.deltas[i],
          render: row => {
            const d = row.deltas[i]
            if (d == null) return <span className="text-[color:var(--astra-text-muted)]">—</span>
            const text = `${d > 0 ? '+' : ''}${formatPercentRatio(d / 100, uiLocale())}`
            return <span title={t('analytics.deltaColHint')}>{text}</span>
          },
        })
      }
    })
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps -- metricFmt carries locale/currency
  }, [result, compareOn, t, metricFmt.locale, metricFmt.currency])

  // Totals render through the metric registry — localized value,
  // display unit and the glossary tooltip per metric.
  const metrics: Metric[] = (result ? params.metrics : []).map(id => {
    const cur = result?.totals[id]
    const prev = result?.compare?.totals[id]
    let delta = ''
    if (typeof cur === 'number' && typeof prev === 'number' && prev !== 0) {
      const pct = ((cur - prev) / Math.abs(prev)) * 100
      delta = t('analytics.delta', { pct: `${pct > 0 ? '+' : ''}${formatPercentRatio(pct / 100, uiLocale())}` })
    }
    const meta = metricMeta(id)
    return {
      label: meta ? t(meta.labelKey) : t(`analytics.metric.${id}`),
      value: cur == null ? t('states.unknown') : formatMetricValue(id, cur, metricFmt) ?? t('states.unknown'),
      unit: meta ? metricDisplayUnit(id) : undefined,
      source: delta || undefined,
      description: meta ? t(meta.descKey) : undefined,
      state: loading ? 'loading' : 'ok',
    }
  })

  // Drill-down — a row or a chart point opens the request explorer
  // with the YQL behind that aggregate (drillable dims + created range).
  // The link itself is the shared explorerLink helper — the applied
  // org/window ride in the hash (GlobalScope deep-link priority), so the
  // explorer reproduces this screen's exact cut.
  const drillPoint = (click: { seriesKey: string; x: string }) => {
    if (!result) return
    openRequests(pointDrillYql(result, click.seriesKey, click.x, params, useTimeChart))
  }
  function openRequests(yql: string) {
    window.location.hash = explorerLink({ org: params.org, from: params.from, to: params.to, yql })
  }

  const timeout = error?.status === 503 || (error?.code ?? '').includes('analytics_timeout')
  const hasRows = !!result && result.rows.length > 0
  const chartSeries: AnalyticsSeries[] = [
    // chart non-null ⇒ result non-null (chart is derived from it).
    ...(chart?.series ?? []).map(s => ({ key: s.key, name: seriesDisplayName(s.key, result!, translate) })),
    ...compareOverlay.series,
  ]

  // can be dropped with one click; the side panel is where parts are added.
  const chips = useMemo<QueryChip[]>(() => {
    const out: QueryChip[] = []
    for (const id of params.metrics) {
      const meta = metricMeta(id)
      const label = meta ? t(meta.labelKey) : t(`analytics.metric.${id}`)
      out.push({ key: `m:${id}`, label, onRemove: () => toggleMetric(id) })
    }
    params.groupBy.forEach((d, i) => {
      const label = d.startsWith('label:') ? t('analytics.labelDim', { key: d.slice(6) }) : t(`analytics.dim.${d}`)
      out.push({ key: `g:${d}`, label, onRemove: () => setGroup(i, '') })
    })
    const filter = params.filter.trim()
    if (filter) {
      out.push({ key: 'f', label: t('analytics.summaryFilter', { filter }), hint: filter, onRemove: () => applyFilter('') })
    }
    return out
  }, [params.metrics, params.groupBy, params.filter, t])

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('analytics.title')}
        purpose={t('analytics.purpose')}
        appliedScope={params.org ? <OrgName orgId={params.org} /> : undefined}
      />

      {/* the header menus — query configuration (the collapsible side
          panel), saved views (storage stays this page's server registry) and
          the per-table settings. Rename/delete run through dialogs inside
          SavedViewsMenu — no window popups anywhere. */}
      <div className="flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          className="btn-secondary"
          aria-expanded={configOpen}
          aria-controls="analytics-config"
          onClick={() => setConfigOpen(o => !o)}
        >
          {t('analytics.config')}
        </button>
        <SavedViewsMenu
          menuId="analytics-views-menu"
          actionIds={{ rename: 'analytics.views.rename', delete: 'analytics.views.delete' }}
          collectReason
          views={views.map(v => ({ id: v.id, name: v.name, label: v.shared ? t('analytics.viewSharedLabel', { name: v.name }) : v.name }))}
          onApply={applySavedView}
          onSave={saveView}
          onRename={renameView}
          onDelete={removeView}
          saveDisabled={!params.org}
          saveHint={(
            <label className="inline-flex min-h-[44px] items-center gap-2 text-sm">
              <input type="checkbox" checked={viewShared} onChange={e => setViewShared(e.target.checked)} />
              <span>{t('analytics.viewShared')}</span>
            </label>
          )}
          labels={{
            menu: t('analytics.viewsMenu'),
            menuLabel: t('analytics.views'),
            section: t('analytics.views'),
            empty: t('analytics.viewsEmpty'),
            name: t('analytics.viewName'),
            save: t('analytics.saveView'),
            rename: t('analytics.viewRename'),
            delete: t('analytics.viewDelete'),
            deleteImpact: name => t('analytics.viewDeleteConfirm', { name }),
          }}
        />
        {hasRows && (
          <TableSettingsMenu
            columns={columns.map(c => ({ key: c.key, header: c.header }))}
            hiddenColumnIds={prefs.hiddenColumnIds}
            onHiddenChange={prefs.setHiddenColumnIds}
            density={prefs.density}
            onDensityChange={prefs.setDensity}
            onReset={prefs.reset}
          />
        )}
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        {/* Result first: query summary row, chart, totals, table. */}
        <div className="flex min-w-0 flex-col gap-4">
          <section aria-label={t('analytics.results')} className="card flex flex-col gap-2">
            {chips.length > 0 && (
              <ul className="flex flex-wrap items-center gap-1">
                {chips.map(c => (
                  <li
                    key={c.key}
                    className="inline-flex items-center gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface-muted)] px-2 py-1 text-xs"
                  >
                    <span className="max-w-60 truncate" title={c.hint ?? c.label}>{c.label}</span>
                    <button
                      type="button"
                      onClick={c.onRemove}
                      aria-label={t('analytics.removeChip', { what: c.label })}
                      className="inline-flex min-h-[44px] items-center px-1 text-[color:var(--astra-text-muted)] hover:text-[color:var(--astra-ink)]"
                    >
                      ×
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {params.org && (
              <p data-testid="analytics-summary" className="text-sm text-[color:var(--astra-ink)]">
                <span className="me-1 text-[color:var(--astra-text-muted)]">{t('analytics.results')}:</span>
                {summary}
              </p>
            )}
            {/* Ready questions as chips in the query row: one click applies
                the query shape; period/org/filter stay. */}
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-[color:var(--astra-text-muted)]">{t('analytics.readyQuestions')}</span>
              {ANALYTICS_QUESTIONS.map(q => (
                <button key={q.id} type="button" className="btn-secondary min-h-[44px] px-3 text-sm" onClick={() => applyQuestion(q)}>
                  {t(q.titleKey)}
                </button>
              ))}
            </div>
          </section>

          {loading && !result && <StateNotice state="loading" title={t('analytics.loading')} />}
          {timeout && <StateNotice state="error" title={t('analytics.timeoutTitle')} message={t('analytics.timeoutMessage')} />}
          {error && !timeout && (
            <StateNotice state="error" title={t('states.failedToLoad')} message={error.status >= 400 && error.status < 500 ? error.message : t('analytics.errorGeneric')} />
          )}

          {chart && chart.points.length > 0 && effectiveChart !== 'table' && (
            <ChartCard title={summary} data={compareOverlay.data} filename={summarySlug(summary)}
              unit={params.metrics.length === 1 ? metricDisplayUnit(params.metrics[0]) : undefined}
              columns={[
                { key: 'x', label: t('analytics.time') },
                ...chartSeries.map(s => ({ key: s.key, label: s.name, align: 'right' as const })),
              ]}>
              <AnalyticsSeriesChart
                data={compareOverlay.data}
                xKey="x"
                series={chartSeries}
                kind={effectiveChart}
                onPointClick={drillPoint}
                valueFormatter={(seriesKey, value) => formatMetricValue(seriesMetricId(seriesKey), value, metricFmt) ?? String(value)}
                legend
                timezone={params.tz || undefined}
              />
            </ChartCard>
          )}

          {result?.source === 'rollup' && <StateNotice state="partial" title={t('analytics.rollup')} />}
          {result?.truncated && <StateNotice state="partial" title={t('analytics.truncated', { count: params.top })} />}
          {result && result.coverage.unpriced_requests > 0 && (
            <StateNotice state="warning" title={t('analytics.unpriced', { count: result.coverage.unpriced_requests })}
              action={{ label: t('analytics.unpricedLink'), onClick: () => { window.location.hash = 'models' } }} />
          )}

          {result && metrics.length > 0 && <MetricStrip aria-label={t('analytics.title')} metrics={metrics} />}

          {result && result.rows.length === 0 && !loading && (
            // The empty state names the levers to try and offers the
            // single most useful one.
            <StateNotice state="empty" title={t('analytics.emptyTitle')} message={t('analytics.emptyHints')}
              action={params.filter.trim()
                ? { label: t('analytics.emptyClearFilter'), onClick: () => applyFilter('') }
                : { label: t('analytics.emptyWiden'), onClick: () => applyPreset('30d') }} />
          )}

          {hasRows && (
            <DataTable<AnalyticsTableRow>
              columns={columns}
              rows={tableRows}
              getRowId={r => r.id}
              page={page}
              pageSize={50}
              onPageChange={setPage}
              sort={sort}
              onSortChange={setSort}
              hiddenColumnIds={prefs.hiddenColumnIds}
              density={prefs.density}
              caption={summary}
              onRowClick={row => openRequests(rowDrillYql(result!, row.cells, params))}
              renderActions={row => (
                <a
                  href={explorerLink({ org: params.org, from: params.from, to: params.to, yql: rowDrillYql(result!, row.cells, params) })}
                  onClick={e => e.stopPropagation()}
                  aria-label={t('analytics.openRequests')}
                  className="inline-flex min-h-[44px] items-center px-1 text-[color:var(--astra-action)] hover:text-[color:var(--astra-action-hover)]"
                >
                  ↗
                </a>
              )}
            />
          )}

          {params.org ? (
            <a className="inline-flex min-h-[44px] items-center text-sm underline" href={analyticsCsvUrl(params)} data-testid="analytics-csv">
              {t('analytics.csv')}
            </a>
          ) : null}
        </div>

        {/* The query configuration — what to count, how to split,
            which data, comparison — in one collapsible side panel. Open by
            default; on narrow screens it stacks below the result. */}
        <aside
          id="analytics-config"
          hidden={!configOpen}
          aria-label={t('analytics.config')}
          className="card flex flex-col gap-4 xl:sticky xl:top-4 xl:max-h-[calc(100vh-2rem)] xl:overflow-y-auto"
        >
          <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('analytics.config')}</h2>

          {/* What to count (searchable metric multi-select). */}
          <section aria-labelledby="an-metrics" className="flex flex-col gap-3 border-t border-[color:var(--astra-rule)] pt-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h3 id="an-metrics" className="text-sm font-semibold text-[color:var(--astra-ink)]">{t('analytics.whatToCount')}</h3>
              <p className="text-xs text-[color:var(--astra-text-muted)]">
                {t('analytics.metricsCount', { count: params.metrics.length, max: METRIC_LIMIT })}
                {' · '}
                {t('analytics.metricsLimitHint', { max: METRIC_LIMIT })}
              </p>
            </div>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('analytics.metricSearch')}</span>
              <input value={metricQuery} onChange={e => setMetricQuery(e.target.value)} aria-label={t('analytics.metricSearch')}
                className="control" />
            </label>
            <fieldset className="flex flex-col gap-2">
              <legend className="sr-only">{t('analytics.metrics')}</legend>
              {(Object.keys(METRIC_GROUPS) as MetricGroup[]).map(group => {
                const ids = METRIC_GROUPS[group].filter(id => visibleMetrics.some(m => m.id === id))
                if (ids.length === 0) return null
                return (
                  <div key={group} className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-[color:var(--astra-text-muted)]">{t(`analytics.group.${group}`)}</span>
                    {ids.map(id => {
                      const meta = metricMeta(id)
                      const name = t(meta ? meta.labelKey : `analytics.metric.${id}`)
                      const unit = meta ? metricDisplayUnit(id) : undefined
                      return (
                        <div key={id} className="inline-flex items-center gap-1">
                          <label className="inline-flex min-h-[44px] items-center gap-1 text-sm">
                            <input type="checkbox" checked={params.metrics.includes(id)} onChange={() => toggleMetric(id)} disabled={!params.metrics.includes(id) && params.metrics.length >= METRIC_LIMIT} />
                            {name}
                          </label>
                          {unit ? <span className="text-xs text-[color:var(--astra-text-muted)]">{unit}</span> : null}
                          {meta ? <MetricHint label={name} description={t(meta.descKey)} /> : null}
                        </div>
                      )
                    })}
                  </div>
                )
              })}
              {visibleMetrics.length === 0 && (
                <p className="text-sm text-[color:var(--astra-text-muted)]">{t('analytics.metricNoMatch', { query: metricQuery.trim() })}</p>
              )}
            </fieldset>
          </section>

          {/* How to split (up to 2 dims + time step + top). */}
          <section aria-labelledby="an-split" className="flex flex-col gap-3 border-t border-[color:var(--astra-rule)] pt-3">
            <h3 id="an-split" className="text-sm font-semibold text-[color:var(--astra-ink)]">{t('analytics.howToSplit')}</h3>
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('analytics.granularity')}</span>
                <select value={params.granularity} onChange={e => update({ granularity: e.target.value as Granularity })} aria-label={t('analytics.granularity')}
                  className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3">
                  {GRANS.map(g => <option key={g} value={g}>{t(`analytics.gran.${g}`)}</option>)}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('analytics.top')}</span>
                <input type="number" min={1} max={100} value={params.top} onChange={e => update({ top: Math.min(100, Math.max(1, Number(e.target.value) || 1)) })}
                  aria-label={t('analytics.top')}
                  className="w-24 min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3" />
              </label>
            </div>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('analytics.groupSearch')}</span>
              <input value={dimQuery} onChange={e => setDimQuery(e.target.value)} aria-label={t('analytics.groupSearch')}
                className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3" />
            </label>
            {[0, 1].map(index => (
              <label key={index} className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('analytics.grouping')}</span>
                <select aria-label={`${t('analytics.grouping')} ${index + 1}`} value={params.groupBy[index] ?? ''} onChange={e => setGroup(index, e.target.value)}
                  className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3">
                  <option value="">{t('analytics.groupNone')}</option>
                  {dimOptions.map(d => (
                    <option key={d} value={d}>{d.startsWith('label:') ? t('analytics.labelDim', { key: d.slice(6) }) : t(`analytics.dim.${d}`)}</option>
                  ))}
                </select>
              </label>
            ))}
          </section>

          {/* Which data (org · period · tz via the shared
              GlobalScopeBar, pinned borders, and the shared FilterBar). */}
          <section aria-labelledby="an-data" className="flex flex-col gap-3 border-t border-[color:var(--astra-rule)] pt-3">
            <h3 id="an-data" className="text-sm font-semibold text-[color:var(--astra-ink)]">{t('analytics.whichData')}</h3>
            {/* Org · period · tz are the shared GlobalScope controls
                (one scope across screens); the borders below pin a custom window
                and the select shows the unified preset it resolves to. */}
            <div className="flex flex-wrap items-end gap-3">
              <GlobalScopeBar fields={['org', 'period', 'tz']} />
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('analytics.from')}</span>
                <input type="datetime-local" value={params.from.slice(0, 16)} onChange={e => { if (e.target.value) gs.setRange(new Date(e.target.value).toISOString().replace(/\.\d{3}Z$/, 'Z'), params.to) }}
                  className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3" />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('analytics.to')}</span>
                <input type="datetime-local" value={params.to.slice(0, 16)} onChange={e => { if (e.target.value) gs.setRange(params.from, new Date(e.target.value).toISOString().replace(/\.\d{3}Z$/, 'Z')) }}
                  className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3" />
              </label>
            </div>
            {/* The shared FilterBar owns draft/debounce/error-highlight;
                it never applies invalid syntax. */}
            <FilterBar
              id="analytics-filter"
              label={t('analytics.filter')}
              fields={filterFields}
              applied={params.filter}
              onApply={applyFilter}
              debounceMs={300}
              valueHints={queryValueHints}
            />
          </section>

          {/* Comparison. */}
          <section aria-labelledby="an-compare" className="flex flex-col gap-2 border-t border-[color:var(--astra-rule)] pt-3">
            <h3 id="an-compare" className="text-sm font-semibold text-[color:var(--astra-ink)]">{t('analytics.comparison')}</h3>
            <label className="inline-flex min-h-[44px] items-center gap-2 text-sm">
              <input type="checkbox" checked={params.compare} onChange={e => update({ compare: e.target.checked })} />
              {t('analytics.compare')}
            </label>
            <p className="text-xs text-[color:var(--astra-text-muted)]">{t('analytics.compareHint')}</p>
          </section>
        </aside>
      </div>
    </div>
  )
}
