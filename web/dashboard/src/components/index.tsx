import { Bar as RBar, BarChart as RCBarChart, XAxis, YAxis, Tooltip, DefaultTooltipContent, ResponsiveContainer, Cell, Legend, LineChart as RCLineChart, Line, PieChart as RCPieChart, Pie, AreaChart as RCAreaChart, Area } from 'recharts'
import { formatMoney, uiLocale } from '../i18n/format'
import {
  chartDataState, chartLineType, chooseChartKind, compactMoneyLabel, compactNumberLabel,
  detectGranularity, sortByTime, timeTickLabel, timeTooltipLabel, valueDomain,
  type TimeGranularity,
} from '../lib/chartData'

// Astra chart palette: read from the canonical CSS tokens at runtime so the
// chart colors track design/astra-tokens.css (no hardcoded hex in source —
// lint-design). Fallbacks only if :root is unavailable (SSR/tests).
function astraToken(name: string): string {
  if (typeof window === 'undefined' || typeof getComputedStyle !== 'function') return ''
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

// Astra chart palette from the canonical CSS tokens. When a token is missing
// (styles not loaded yet) the entry falls back to a keyword, never a literal.
export function chartColors(): string[] {
  return [
    astraToken('--astra-action') || 'darkslategray',
    astraToken('--astra-info') || 'steelblue',
    astraToken('--astra-accent') || 'sienna',
    astraToken('--astra-warning') || 'darkgoldenrod',
    astraToken('--astra-success') || 'darkolivegreen',
    astraToken('--astra-text-muted') || 'gray',
  ]
}

// X, localized bucket ticks, full-date+timezone tooltips, buckets as columns,
// linear lines from ≥8 points, compact Y ticks, 0-bounded non-negative data,
// legends for multi-series). These wrappers only bind those rules to recharts.
// The reserved Y-axis width keeps tick labels from clipping the plot area.
const Y_AXIS_WIDTH = 56
const CHART_HEIGHT = 280
const MARGIN = { top: 10, right: 20, left: 0, bottom: 0 }

interface TimeAxis {
  granularity: TimeGranularity
  tick: (value: unknown) => string
  tooltip: (value: unknown) => string
}

// Time labels detected from the fed data: bucket timestamps get localized
// ticks and a full-date+timezone tooltip; category labels pass through.
function timeAxis(values: string[], timezone?: string): TimeAxis | null {
  const gran = detectGranularity(values)
  if (!gran) return null
  const locale = uiLocale()
  return {
    granularity: gran,
    tick: v => timeTickLabel(String(v), gran, locale, timezone),
    tooltip: v => timeTooltipLabel(String(v), gran, locale, timezone),
  }
}

// I18N-11: charts accept the org's presentation currency so the Y-axis ticks
// and tooltips render in the org currency (ICU), not a hardcoded "$".
export function BarChart({ data, currency }: { data: Array<{ name: string; cost: number }>; currency?: string }) {
  const locale = uiLocale()
  if (chartDataState(data.length) === 'empty') return null
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <RCBarChart data={data} margin={MARGIN}>
        <XAxis dataKey="name" tick={{ fontSize: 12 }} />
        <YAxis width={Y_AXIS_WIDTH} tick={{ fontSize: 12 }} domain={valueDomain(data.map(d => d.cost))}
          tickFormatter={v => compactMoneyLabel(Number(v), locale, currency)} />
        <Tooltip formatter={(value: number) => [formatMoney(value, currency), 'Cost']} />
        <RBar dataKey="cost" radius={[4, 4, 0, 0]}>
          {data.map((_, i) => (
            <Cell key={i} fill={chartColors()[i % 6]} />
          ))}
        </RBar>
      </RCBarChart>
    </ResponsiveContainer>
  )
}

// Time-bucket money trend (Overview/Cost/Cache daily data). The timeline is
// re-sorted here too (idempotent after the page's sortByTime feed) so the
// reversed axis (D-08) cannot come back through any caller.
export function LineChart({ data, currency, timezone }: { data: Array<{ date: string; cost: number }>; currency?: string; timezone?: string }) {
  const locale = uiLocale()
  const rows = sortByTime(data, r => r.date)
  if (chartDataState(rows.length) === 'empty') return null
  const axis = timeAxis(rows.map(r => r.date), timezone)
  const tick = axis?.tick
  const domain = valueDomain(rows.map(r => r.cost))
  // Daily/hourly buckets render as columns; a line appears only from
  // LINE_MIN_POINTS points and is linear (no invented spline peaks).
  if (chooseChartKind(rows.length) === 'bar') {
    return (
      <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
        <RCBarChart data={rows} margin={MARGIN}>
          <XAxis dataKey="date" tick={{ fontSize: 12 }} tickFormatter={tick} />
          <YAxis width={Y_AXIS_WIDTH} tick={{ fontSize: 12 }} domain={domain}
            tickFormatter={v => compactMoneyLabel(Number(v), locale, currency)} />
          <Tooltip labelFormatter={axis?.tooltip} formatter={(value: number) => [formatMoney(value, currency), 'Cost']} />
          <RBar dataKey="cost" fill="var(--astra-action)" radius={[4, 4, 0, 0]} />
        </RCBarChart>
      </ResponsiveContainer>
    )
  }
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <RCLineChart data={rows} margin={MARGIN}>
        <XAxis dataKey="date" tick={{ fontSize: 12 }} tickFormatter={tick} />
        <YAxis width={Y_AXIS_WIDTH} tick={{ fontSize: 12 }} domain={domain}
          tickFormatter={v => compactMoneyLabel(Number(v), locale, currency)} />
        <Tooltip labelFormatter={axis?.tooltip} formatter={(value: number) => [formatMoney(value, currency), 'Cost']} />
        <Line type={chartLineType()} dataKey="cost" style={{ stroke: "var(--astra-action)" }} strokeWidth={2} dot={{ r: 3 }} connectNulls />
      </RCLineChart>
    </ResponsiveContainer>
  )
}

export interface AnalyticsSeries {
  key: string
  name: string
  /** AUX-06: previous-period series render as a dashed line (line charts). */
  dashed?: boolean
}

export interface AnalyticsPointClick {
  seriesKey: string
  x: string
}

export function AnalyticsSeriesChart({
  data, xKey, series, kind, onPointClick, valueFormatter, legend = true, timezone,
}: {
  data: Array<Record<string, string | number | null>>
  xKey: string
  series: AnalyticsSeries[]
  kind: 'line' | 'area' | 'stacked_bar' | 'bar'
  /** AUX-06: click a series' point/bar to drill into the request explorer. */
  onPointClick?: (click: AnalyticsPointClick) => void
  /** Formats tooltip values per series (metric registry — never a raw number). */
  valueFormatter?: (seriesKey: string, value: number) => string
  legend?: boolean
  /** Org timezone for full-date tooltip labels on time buckets. */
  timezone?: string
}) {
  const colors = chartColors()
  const showLegend = legend && series.length > 1
  if (chartDataState(data.length) === 'empty') return null
  const axis = timeAxis(data.map(d => String(d[xKey] ?? '')), timezone)
  // buckets are counts per period, and a trend needs enough points. A dashed
  // comparison series (AUX-06 2b) only reads as a previous-period line, so a
  // dashed series keeps the line kind even in a short window.
  const hasDashedSeries = series.some(s => s.dashed)
  const effectiveKind =
    kind === 'line' && axis != null && !hasDashedSeries && chooseChartKind(data.length) === 'bar'
      ? 'bar'
      : kind
  const domain = valueDomain(
    data
      .flatMap(d => series.map(s => d[s.key]))
      .filter((v): v is string | number => v != null && v !== '')
      .map(Number)
      .filter(Number.isFinite),
  )
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- recharts payload shapes
  const pointClick = (dataKey: string) => (payload: any) => {
    if (!onPointClick || !payload || !payload.payload) return
    onPointClick({ seriesKey: String(dataKey), x: String(payload.payload[xKey] ?? '') })
  }
  const axes = (
    <>
      <XAxis dataKey={xKey} tick={{ fontSize: 12 }} tickFormatter={axis?.tick} />
      <YAxis width={Y_AXIS_WIDTH} tick={{ fontSize: 12 }} domain={domain}
        tickFormatter={v => compactNumberLabel(Number(v), uiLocale())} />
      <Tooltip
        // Recharts retains inactive labels with visibility:hidden, but only
        // remeasures their box while active. A changed date label can otherwise
        // widen the document using a stale position. Keep inactive content empty.
        content={props => props.active ? <DefaultTooltipContent {...props} /> : null}
        wrapperStyle={{ maxWidth: `calc(100% - ${Y_AXIS_WIDTH + MARGIN.left + MARGIN.right}px)` }}
        contentStyle={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}
        labelFormatter={axis?.tooltip}
        formatter={(value, name, item) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- recharts payload shapes
          const dataKey = String((item as any)?.dataKey ?? name ?? '')
          const n = Number(value)
          return [valueFormatter && Number.isFinite(n) ? valueFormatter(dataKey, n) : String(value), name]
        }}
      />
      {showLegend && <Legend wrapperStyle={{ fontSize: 12 }} />}
    </>
  )
  const dash = (s: AnalyticsSeries) => (s.dashed ? '6 3' : undefined)
  if (effectiveKind === 'area') {
    return (
      <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
        <RCAreaChart data={data} margin={MARGIN}>
          {axes}
          {series.map((s, i) => (
            <Area key={s.key} type={chartLineType()} dataKey={s.key} name={s.name} stackId="a" connectNulls={false}
              stroke={colors[i % colors.length]} fill={colors[i % colors.length]} />
          ))}
        </RCAreaChart>
      </ResponsiveContainer>
    )
  }
  if (effectiveKind === 'stacked_bar' || effectiveKind === 'bar') {
    return (
      <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
        <RCBarChart data={data} margin={MARGIN}>
          {axes}
          {series.map((s, i) => (
            <RBar key={s.key} dataKey={s.key} name={s.name} stackId={effectiveKind === 'stacked_bar' ? 'a' : undefined} fill={colors[i % colors.length]}
              onClick={pointClick(s.key)} className={onPointClick ? 'cursor-pointer' : undefined} />
          ))}
        </RCBarChart>
      </ResponsiveContainer>
    )
  }
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <RCLineChart data={data} margin={MARGIN}>
        {axes}
        {series.map((s, i) => (
          <Line key={s.key} type={chartLineType()} dataKey={s.key} name={s.name} connectNulls={false}
            stroke={colors[i % colors.length]} strokeWidth={2} strokeDasharray={dash(s)} dot={{ r: 2 }}
            onClick={pointClick(s.key)} className={onPointClick ? 'cursor-pointer' : undefined} />
        ))}
      </RCLineChart>
    </ResponsiveContainer>
  )
}

export function PieChartSmall({ data }: { data: Array<{ name: string; value: number }> }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <RCPieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
          {data.map((_, i) => (
            <Cell key={i} fill={chartColors()[i % 6]} />
          ))}
        </Pie>
      </RCPieChart>
    </ResponsiveContainer>
  )
}
