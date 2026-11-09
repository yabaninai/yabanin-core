// URL ⇄ analytics query (AT-20). Hash query keys are short so a shared link
// stays readable; the API query uses the server's parameter names.

import { formatUsdMoney } from '../i18n/money.ts'
import { quoteYqlValue } from './queryLang.ts'

// AUX-10 — the single metric glossary (plan "Глоссарий метрик"). One entry
// per server metric (pkg/adminstore/analytics_query_sql.go `analyticsMetrics`)
// with its group, unit, presentation format and the i18n keys of the display
// name ("what", analytics.metric.*) and the tooltip description ("what does
// it mean", analytics.metricDesc.*). Analytics, Dashboards, MetricStrip,
// table column headers and the future Overview inbox (AUX-18 lib/signals.ts)
// render metric names, units and values ONLY through this registry — a raw
// id or a raw String(number) never reaches the UI, and a missing description
// fails the metricRegistry test in every locale.
export type MetricGroup = 'volume' | 'money' | 'quality' | 'speed'
/** Server aggregate units (AnalyticsColumn.unit from the query endpoint). */
export type MetricUnit = 'count' | 'tokens' | 'usd' | 'ratio' | 'ms'
/** Presentation contract (plan "Числа"): all rendering is locale-aware. */
export type MetricFormat = 'number' | 'money' | 'percent' | 'ms'

export interface MetricMeta {
  readonly id: string
  readonly group: MetricGroup
  readonly unit: MetricUnit
  readonly format: MetricFormat
  /** i18n key of the display name — the id itself is never shown. */
  readonly labelKey: string
  /** i18n key of the "what this means" tooltip (every locale, AUX-10). */
  readonly descKey: string
}

const meta = (id: string, group: MetricGroup, unit: MetricUnit, format: MetricFormat): MetricMeta => ({
  id, group, unit, format,
  labelKey: `analytics.metric.${id}`,
  descKey: `analytics.metricDesc.${id}`,
})

export const METRICS: readonly MetricMeta[] = [
  meta('requests', 'volume', 'count', 'number'),
  meta('tokens_in', 'volume', 'tokens', 'number'),
  meta('tokens_out', 'volume', 'tokens', 'number'),
  meta('cache_read_tokens', 'volume', 'tokens', 'number'),
  meta('sessions', 'volume', 'count', 'number'),
  meta('cost_usd', 'money', 'usd', 'money'),
  meta('unpriced_requests', 'money', 'count', 'number'),
  meta('cost_per_request', 'money', 'usd', 'money'),
  meta('errors', 'quality', 'count', 'number'),
  meta('retried_requests', 'quality', 'count', 'number'),
  meta('fallback_requests', 'quality', 'count', 'number'),
  meta('error_rate', 'quality', 'ratio', 'percent'),
  meta('cache_hit_rate', 'quality', 'ratio', 'percent'),
  meta('prompt_cache_ratio', 'quality', 'ratio', 'percent'),
  meta('latency_p50', 'speed', 'ms', 'ms'),
  meta('latency_p95', 'speed', 'ms', 'ms'),
  meta('ttft_p50', 'speed', 'ms', 'ms'),
  meta('ttft_p95', 'speed', 'ms', 'ms'),
]

const METRIC_BY_ID = new Map(METRICS.map(m => [m.id, m]))

export function metricMeta(id: string): MetricMeta | undefined {
  return METRIC_BY_ID.get(id)
}

export const METRIC_GROUPS: Record<MetricGroup, readonly string[]> = {
  volume: METRICS.filter(m => m.group === 'volume').map(m => m.id),
  money: METRICS.filter(m => m.group === 'money').map(m => m.id),
  quality: METRICS.filter(m => m.group === 'quality').map(m => m.id),
  speed: METRICS.filter(m => m.group === 'speed').map(m => m.id),
}

export const ALL_METRICS: string[] = METRICS.map(m => m.id)

export interface MetricFormatOptions {
  /** BCP-47 tag; defaults to 'en' (this lib stays i18n-free for node tests). */
  locale?: string
  /** Org presentation currency — display only, never an FX (i18n/money.ts). */
  currency?: string
}

function formatIntl(locale: string, options: Intl.NumberFormatOptions, value: number): string {
  try {
    return new Intl.NumberFormat(locale, options).format(value)
  } catch {
    return String(value)
  }
}

/**
 * Locale-aware value for a registry metric: money through the USD money
 * core, ratios as percents, counts grouped, ms rounded to display precision.
 * `null`/unknown stays `null` so callers can render the Unknown state —
 * unknown is never formatted as 0 (plan "Числа").
 */
export function formatMetricValue(id: string, value: number | null | undefined, opts: MetricFormatOptions = {}): string | null {
  if (value == null || !Number.isFinite(value)) return null
  const locale = opts.locale || 'en'
  const format = METRIC_BY_ID.get(id)?.format
  if (format === 'money') return formatUsdMoney(value, opts.currency, locale)
  if (format === 'percent') return formatIntl(locale, { style: 'percent', maximumFractionDigits: 1 }, value)
  if (format === 'ms') return formatIntl(locale, { maximumFractionDigits: value >= 100 ? 0 : 1 }, value)
  return formatIntl(locale, { maximumFractionDigits: 2 }, value)
}

/** Locale-rounded percent for deltas and shares (a ratio 0.123 → "12.3%"). */
export function formatPercentRatio(ratio: number, locale = 'en'): string {
  return formatIntl(locale, { style: 'percent', maximumFractionDigits: 1 }, ratio)
}

/** Unit shown next to the metric name ("Cost · USD"); counts stay unlabeled. */
export function metricDisplayUnit(id: string): string | undefined {
  switch (METRIC_BY_ID.get(id)?.unit) {
    case 'usd': return 'USD'
    case 'ratio': return '%'
    case 'ms': return 'ms'
    case 'tokens': return 'tokens'
    default: return undefined
  }
}

export const STANDARD_DIMS = [
  'model', 'model_requested', 'endpoint', 'team', 'agent', 'task', 'status_class', 'cache',
] as const

export const GAP_NULL = new Set([
  'error_rate', 'cache_hit_rate', 'prompt_cache_ratio', 'cost_per_request',
  'latency_p50', 'latency_p95', 'ttft_p50', 'ttft_p95',
])

export type Granularity = 'none' | 'hour' | 'day' | 'week' | 'month'
export type ChartKind = 'line' | 'area' | 'stacked_bar' | 'bar' | 'table'
export type PeriodPreset = '24h' | '7d' | '30d' | '90d' | 'custom'

/**
 * AUX-08 — the unified period presets (plan «Единые пресеты периода»). One
 * vocabulary for Overview, Requests, Analytics and Dashboards; GlobalScope
 * (lib/globalScope.ts) persists the choice as ?period=<preset> in the hash.
 */
export const PERIOD_PRESETS: Array<Exclude<PeriodPreset, 'custom'>> = ['24h', '7d', '30d', '90d']

export function isPeriodPreset(v: string | null | undefined): v is Exclude<PeriodPreset, 'custom'> {
  return !!v && (PERIOD_PRESETS as readonly string[]).includes(v)
}

export interface AnalyticsParams {
  org: string
  from: string
  to: string
  /**
   * The applied period preset. 'custom' pins the exact from/to above (hand
   * edits, saved views, deep links); any other value resolves from/to at
   * read/fetch time and is serialized as ?period= instead of raw borders.
   */
  period: PeriodPreset
  metrics: string[]
  groupBy: string[]
  granularity: Granularity
  filter: string
  top: number
  compare: boolean
  chart: ChartKind
  tz: string
}

export interface AnalyticsColumn {
  name: string
  type: string
  unit?: string
}

export interface AnalyticsResult {
  query: {
    metrics: string[]
    group_by: string[]
    granularity: string
    from: string
    to: string
    tz: string
    top: number
    filter: string
  }
  source: string
  columns: AnalyticsColumn[]
  rows: Array<Array<string | number | null>>
  totals: Record<string, number | null>
  compare?: { from: string; to: string; totals: Record<string, number | null> }
  coverage: { unpriced_requests: number; unpriced_share: number | null; legacy_rows: number }
  display_names?: Record<string, Record<string, string>>
  truncated: boolean
  generated_at: string
}

export interface LabelKeyStat {
  key: string
  requests: number
  approx_distinct_values: number
}

const GRANS = new Set<Granularity>(['none', 'hour', 'day', 'week', 'month'])
const CHARTS = new Set<ChartKind>(['line', 'area', 'stacked_bar', 'bar', 'table'])
const KNOWN = new Set(['org', 'from', 'to', 'period', 'm', 'g', 'gran', 'f', 'top', 'cmp', 'chart', 'tz'])

const PRESET_SPAN_MS: Record<Exclude<PeriodPreset, 'custom'>, number> = {
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
  '90d': 90 * 86_400_000,
}

export function presetRange(preset: Exclude<PeriodPreset, 'custom'>, now: Date): { from: string; to: string } {
  return {
    from: new Date(now.getTime() - PRESET_SPAN_MS[preset]).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    to: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  }
}

/**
 * AUX-06: the period preset is derived from the applied range, never stored
 * as independent state — hand-edited from/to borders flip back to `custom`
 * automatically. A preset matches when the span is its exact length (the
 * tolerance absorbs second-level rounding from datetime inputs).
 */
export function presetFromRange(from: string, to: string, toleranceMs = 90_000): PeriodPreset {
  const span = Date.parse(to) - Date.parse(from)
  if (!Number.isFinite(span) || span <= 0) return 'custom'
  const presets: Array<Exclude<PeriodPreset, 'custom'>> = ['24h', '7d', '30d', '90d']
  for (const p of presets) {
    if (Math.abs(span - PRESET_SPAN_MS[p]) <= toleranceMs) return p
  }
  return 'custom'
}

export function defaultParams(now = new Date()): AnalyticsParams {
  const range = presetRange('7d', now)
  return {
    org: '',
    from: range.from,
    to: range.to,
    period: '7d',
    metrics: ['cost_usd'],
    groupBy: [],
    granularity: 'day',
    filter: '',
    top: 20,
    compare: false,
    chart: 'line',
    tz: '',
  }
}

function splitList(raw: string | null, limit: number): string[] {
  if (!raw) return []
  const out: string[] = []
  for (const part of raw.split(',')) {
    const item = part.trim()
    if (!item || out.includes(item)) continue
    out.push(item)
    if (out.length >= limit) break
  }
  return out
}

export function parseAnalyticsHash(query: string, now = new Date()): { params: AnalyticsParams; extra: Array<[string, string]> } {
  const base = defaultParams(now)
  const src = new URLSearchParams(query.startsWith('?') ? query.slice(1) : query)
  const extra: Array<[string, string]> = []
  src.forEach((value, key) => {
    if (!KNOWN.has(key)) extra.push([key, value])
  })
  const gran = src.get('gran') as Granularity | null
  const chart = src.get('chart') as ChartKind | null
  const top = Number(src.get('top'))
  const metrics = splitList(src.get('m'), 6)
  // AUX-08: the period param carries the unified preset; explicit from/to
  // borders are a custom window and win over it (deep-link priority).
  const hashFrom = src.get('from') ?? ''
  const hashTo = src.get('to') ?? ''
  const custom = !!(hashFrom && hashTo)
  const hashPeriod = src.get('period')
  const period: PeriodPreset = custom ? 'custom' : isPeriodPreset(hashPeriod) ? hashPeriod : base.period
  const range = period === 'custom' ? { from: hashFrom, to: hashTo } : presetRange(period, now)
  return {
    params: {
      org: src.get('org') ?? base.org,
      from: range.from,
      to: range.to,
      period,
      metrics: metrics.length ? metrics : base.metrics,
      groupBy: splitList(src.get('g'), 2),
      granularity: gran && GRANS.has(gran) ? gran : base.granularity,
      filter: src.get('f') ?? '',
      top: Number.isInteger(top) && top >= 1 && top <= 100 ? top : base.top,
      compare: src.get('cmp') === '1',
      chart: chart && CHARTS.has(chart) ? chart : base.chart,
      tz: src.get('tz') ?? '',
    },
    extra,
  }
}

export function serializeAnalyticsHash(params: AnalyticsParams, extra: Array<[string, string]> = []): string {
  const q = new URLSearchParams()
  if (params.org) q.set('org', params.org)
  // A preset is stored as ?period=…; only a custom window pins raw borders.
  if (params.period !== 'custom') {
    q.set('period', params.period)
  } else {
    q.set('from', params.from)
    q.set('to', params.to)
  }
  q.set('m', params.metrics.join(','))
  if (params.groupBy.length) q.set('g', params.groupBy.join(','))
  q.set('gran', params.granularity)
  if (params.filter) q.set('f', params.filter)
  q.set('top', String(params.top))
  if (params.compare) q.set('cmp', '1')
  q.set('chart', params.chart)
  if (params.tz) q.set('tz', params.tz)
  for (const [k, v] of extra) q.append(k, v)
  return q.toString()
}

export function analyticsApiQuery(params: AnalyticsParams, format: 'json' | 'csv' = 'json'): string {
  const q = new URLSearchParams()
  q.set('org_id', params.org)
  q.set('from', params.from)
  q.set('to', params.to)
  q.set('metrics', params.metrics.join(','))
  if (params.groupBy.length) q.set('group_by', params.groupBy.join(','))
  q.set('granularity', params.granularity)
  if (params.filter) q.set('filter', params.filter)
  q.set('top', String(params.top))
  if (params.compare) q.set('compare', 'previous')
  if (params.tz) q.set('tz', params.tz)
  if (format === 'csv') q.set('format', 'csv')
  return q.toString()
}

export interface ChartPoint {
  x: string
  [series: string]: string | number | null
}

export interface ChartSeries {
  key: string
  name: string
}

function num(v: string | number | null | undefined): number | null {
  if (v == null || v === '') return null
  const n = typeof v === 'number' ? v : Number(v)
  return Number.isFinite(n) ? n : null
}

// Pivot API rows into one point per x (time, or the dimension for a bar of
// totals). Missing buckets become 0 for sums and counts, and null for ratios
// and percentiles so the line breaks instead of inventing a rate.
export function chartRows(result: AnalyticsResult, chart: ChartKind): { points: ChartPoint[]; series: ChartSeries[] } {
  const cols = result.columns
  const timeIdx = cols.findIndex(c => c.type === 'time')
  const metricIdx = cols.map((c, i) => c.type === 'number' ? i : -1).filter(i => i >= 0)
  const dimIdx = cols.map((c, i) => (c.type !== 'time' && c.type !== 'number') ? i : -1).filter(i => i >= 0)
  const useTime = chart !== 'bar' && timeIdx >= 0
  const series: ChartSeries[] = []
  const byX = new Map<string, ChartPoint>()

  const seriesKey = (dim: string, metric: string) => {
    const key = dim ? `${dim} · ${metric}` : metric
    if (!series.some(s => s.key === key)) series.push({ key, name: key })
    return key
  }

  for (const row of result.rows) {
    const dim = dimIdx.map(i => String(row[i] ?? '')).filter(Boolean).join(' / ')
    const x = useTime ? String(row[timeIdx] ?? '') : (dim || 'all')
    let point = byX.get(x)
    if (!point) {
      point = { x }
      byX.set(x, point)
    }
    for (const i of metricIdx) {
      const metric = cols[i].name
      const key = seriesKey(useTime ? dim : dim, metric)
      const value = num(row[i])
      const prev = point[key]
      if (typeof prev === 'number' && value != null && !GAP_NULL.has(metric)) point[key] = prev + value
      else if (prev == null) point[key] = value
    }
  }

  const points = [...byX.values()]
  if (useTime) {
    points.sort((a, b) => a.x.localeCompare(b.x))
    for (const point of points) {
      for (const s of series) {
        if (point[s.key] != null) continue
        const metric = s.key.includes(' · ') ? s.key.slice(s.key.lastIndexOf(' · ') + 3) : s.key
        point[s.key] = GAP_NULL.has(metric) ? null : 0
      }
    }
  }
  return { points, series }
}

// ---------------------------------------------------------------------------
// AUX-06 — human chart labels and request-explorer drill-down helpers.
// The chartRows series KEY stays the raw contract ("<dim> · <metric>"); only
// the displayed name and the drill-down YQL are derived here.

/** Translate function shape (react-i18next `t` is structurally compatible). */
export type Translate = (key: string, opts?: Record<string, unknown>) => string

/**
 * Human label for a chartRows series key ("team / PAY-1 · cost_usd" → "Team = acme / PAY-1 · Cost").
 * The key's dim part holds the row VALUES in column order (chartRows contract,
 * same reading as pointDrillYql) — the dim NAMES come from the result columns.
 * One dim keeps the bare value ("PAY-1 · Cost"); several dims label each
 * value so the legend stays readable.
 */
export function seriesDisplayName(key: string, result: AnalyticsResult, translate: Translate): string {
  const stripped = key.startsWith('cmp:') ? key.slice(4) : key
  const sep = stripped.lastIndexOf(' · ')
  const metricPart = sep >= 0 ? stripped.slice(sep + 3) : stripped
  const valuePart = sep >= 0 ? stripped.slice(0, sep) : ''
  const meta = metricMeta(metricPart)
  const metricName = meta ? translate(meta.labelKey) : translate(`analytics.metric.${metricPart}`)
  if (!valuePart) return metricName
  const dimNames = result.columns.filter(c => c.type !== 'time' && c.type !== 'number').map(c => c.name)
  const values = valuePart.split(' / ')
  const dims = values
    .map((v, i) => {
      const name = dimNames[i]
      if (!name) return v
      const label = name.startsWith('label:')
        ? translate('analytics.labelDim', { key: name.slice(6) })
        : translate(`analytics.dim.${name}`)
      return values.length > 1 ? `${label} = ${v}` : v
    })
    .join(' / ')
  return `${dims} · ${metricName}`
}

/** The metric id of a chartRows series key (compare-prefixed keys included). */
export function seriesMetricId(key: string): string {
  const stripped = key.startsWith('cmp:') ? key.slice(4) : key
  const sep = stripped.lastIndexOf(' · ')
  return sep >= 0 ? stripped.slice(sep + 3) : stripped
}

// Analytics dims that map 1:1 onto request-explorer YQL fields. team,
// endpoint and status_class have no request-side counterpart, so rows
// grouped only by them drill down by time alone (honest, never invented).
const DRILLABLE_DIMS: Record<string, string> = {
  model: 'model',
  model_requested: 'model_requested',
  agent: 'agent',
  task: 'task',
  cache: 'cache',
}

const MUTED_VALUES = new Set(['(none)', '(other)', '(untagged)'])

function dimDrillClause(dim: string, value: string): string | null {
  const field = dim.startsWith('label:') ? `label.${dim.slice(6)}` : DRILLABLE_DIMS[dim]
  if (!field) return null
  const v = value.trim()
  if (!v || MUTED_VALUES.has(v)) return null
  return `${field} = ${quoteYqlValue(v)}`
}

/** End boundary of one granularity bucket starting at `startIso` ('' when unknown). */
function bucketEndIso(startIso: string, gran: Granularity): string {
  const d = new Date(startIso)
  if (Number.isNaN(d.getTime())) return ''
  switch (gran) {
    case 'hour': d.setTime(d.getTime() + 3_600_000); break
    case 'day': d.setTime(d.getTime() + 86_400_000); break
    case 'week': d.setTime(d.getTime() + 7 * 86_400_000); break
    case 'month': d.setUTCMonth(d.getUTCMonth() + 1); break
    default: return ''
  }
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function drillTimeClause(from: string, to: string): string[] {
  if (!from || !to) return []
  return [`created >= ${quoteYqlValue(from)}`, `created < ${quoteYqlValue(to)}`]
}

/**
 * YQL that opens the request explorer on the requests behind one table row:
 * every drillable dimension of the row plus the row's time bucket (or the
 * whole applied period when the table has no time column). Values the
 * explorer cannot express ("(none)", team ids) are skipped, never faked.
 */
export function rowDrillYql(
  result: AnalyticsResult,
  cells: Array<string | number | null>,
  params: Pick<AnalyticsParams, 'from' | 'to' | 'granularity'>,
): string {
  const clauses: string[] = []
  const timeIdx = result.columns.findIndex(c => c.type === 'time')
  result.columns.forEach((c, i) => {
    if (c.type === 'time' || c.type === 'number') return
    const clause = dimDrillClause(c.name, String(cells[i] ?? ''))
    if (clause) clauses.push(clause)
  })
  let from = params.from
  let to = params.to
  if (timeIdx >= 0) {
    const start = String(cells[timeIdx] ?? '')
    const end = bucketEndIso(start, params.granularity)
    if (start && end) { from = start; to = end }
  }
  return [...clauses, ...drillTimeClause(from, to)].join(' and ')
}

/**
 * YQL for one chart point click. `seriesKey` is the raw chartRows key —
 * its dim part holds the row VALUES in column order, so the dim names come
 * from the result columns. `useTime` mirrors chartRows: only time charts
 * carry a bucket in `x`; bar charts drill by the whole applied period.
 */
export function pointDrillYql(
  result: AnalyticsResult,
  seriesKey: string,
  x: string,
  params: Pick<AnalyticsParams, 'from' | 'to' | 'granularity'>,
  useTime: boolean,
): string {
  const dimNames = result.columns.filter(c => c.type !== 'time' && c.type !== 'number').map(c => c.name)
  const stripped = seriesKey.startsWith('cmp:') ? seriesKey.slice(4) : seriesKey
  const sep = stripped.lastIndexOf(' · ')
  const values = sep >= 0 ? stripped.slice(0, sep).split(' / ') : []
  const clauses: string[] = []
  dimNames.forEach((name, i) => {
    const clause = dimDrillClause(name, values[i] ?? '')
    if (clause) clauses.push(clause)
  })
  let from = params.from
  let to = params.to
  if (useTime) {
    const end = bucketEndIso(x, params.granularity)
    if (x && end) { from = x; to = end }
  }
  return [...clauses, ...drillTimeClause(from, to)].join(' and ')
}
