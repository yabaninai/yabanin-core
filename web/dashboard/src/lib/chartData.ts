// chart, as pure functions (no React, no i18n runtime) so `node --test` can
// hold the contract:
//   * the X axis runs forward in time (the cost/savings endpoints return
//     buckets newest-first — D-08 — so every consumer sorts explicitly);
//   * tick labels are localized buckets (day → "29 сен", hour → "14:00"),
//     never raw ISO; the tooltip carries the full date AND the timezone;
//   * daily/hourly buckets render as columns; a line appears only from
//     LINE_MIN_POINTS points and is interpolated `linear` (a monotone spline
//     over few daily buckets invents peaks that never happened — UX-06);
//   * the Y axis uses compact number/money labels (raw "0000000" ticks were
//     truncated) and pins the lower bound at 0 for non-negative data, so a
//     line can never dip below zero;
//   * legends show when a chart has more than one series;
//   * the "one point" and "empty" states are classified explicitly — an
//     empty chart never renders a broken axis frame.

export type TimeGranularity = 'day' | 'hour'
export type TrendChartKind = 'bar' | 'line'
export type ChartDataState = 'empty' | 'single' | 'many'

/** A trend line needs this many points; fewer render as columns. */
export const LINE_MIN_POINTS = 8

/**
 * Sort rows ascending by time (stable; rows whose time label does not parse
 * keep their relative order at the end). Returns a new array — the input is
 * never mutated, so a page can feed the same sorted array to the chart and
 * its accessible data table.
 */
export function sortByTime<T>(rows: readonly T[], time: (row: T) => string): T[] {
  const parsed = rows.map((row, i) => ({ row, t: Date.parse(time(row)), i }))
  const known = parsed.filter(p => Number.isFinite(p.t))
  const unknown = parsed.filter(p => !Number.isFinite(p.t))
  known.sort((a, b) => a.t - b.t || a.i - b.i)
  return [...known, ...unknown].map(p => p.row)
}

/**
 * Bucket granularity of time labels: "2026-09-29" or an all-midnight day
 * series ("2026-09-29T00:00:00Z" — the analytics `date_trunc('day', …)`
 * shape) → 'day'; any value carrying a non-zero time part → 'hour'. An
 * hourly series always has non-midnight buckets, so an all-midnight series
 * can only be day buckets. Non-calendar labels → null (category axis).
 */
export function detectGranularity(values: readonly string[]): TimeGranularity | null {
  const nonEmpty = values.filter(v => typeof v === 'string' && v.length > 0)
  if (nonEmpty.length === 0) return null
  if (!nonEmpty.every(v => /^\d{4}-\d{2}-\d{2}/.test(v))) return null
  const hasClockTime = (v: string): boolean => {
    const m = /T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(v)
    return m != null && (m[1] !== '00' || m[2] !== '00' || (m[3] != null && m[3] !== '00'))
  }
  return nonEmpty.some(hasClockTime) ? 'hour' : 'day'
}

/**
 * X-axis tick label for a time bucket: a day renders as the localized short
 * date ("29 сен" in ru, "Sep 29" in en), an hour as the wall-clock time
 * ("14:00") in `timezone` (default UTC). Unparseable labels pass through.
 */
export function timeTickLabel(
  value: string,
  granularity: TimeGranularity,
  locale: string,
  timezone?: string,
): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  const tz = timezone && timezone.length > 0 ? timezone : 'UTC'
  try {
    if (granularity === 'hour') {
      return new Intl.DateTimeFormat(locale, {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
        timeZone: tz,
      }).format(d)
    }
    return new Intl.DateTimeFormat(locale, {
      day: 'numeric',
      month: 'short',
      timeZone: tz,
    }).format(d)
  } catch {
    return value
  }
}

/**
 * Tooltip label for a time bucket: the full localized date (and time for
 * hourly buckets) plus the timezone name — "29 сентября 2026 г. · UTC".
 */
export function timeTooltipLabel(
  value: string,
  granularity: TimeGranularity,
  locale: string,
  timezone?: string,
): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  const tz = timezone && timezone.length > 0 ? timezone : 'UTC'
  try {
    const text =
      granularity === 'hour'
        ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone: tz }).format(d)
        : new Intl.DateTimeFormat(locale, { dateStyle: 'long', timeZone: tz }).format(d)
    return `${text} · ${tz}`
  } catch {
    return value
  }
}

/** Chart kind for a time-bucket series: columns below LINE_MIN_POINTS. */
export function chooseChartKind(pointCount: number): TrendChartKind {
  return pointCount >= LINE_MIN_POINTS ? 'line' : 'bar'
}

/**
 * Line interpolation for trend series: always `linear`. Replaces the old
 * `monotone` spline — smoothing over few daily buckets invented peaks.
 */
export function chartLineType(): 'linear' {
  return 'linear'
}

/**
 * Recharts YAxis domain: when every value is non-negative the lower bound is
 * pinned to 0 (a line/bar never dips under zero for such data); data with
 * negatives (e.g. negative savings) keeps the automatic domain.
 */
export function valueDomain(values: readonly number[]): [number | 'auto', number | 'auto'] {
  const finite = values.filter(v => Number.isFinite(v))
  if (finite.length === 0 || finite.some(v => v < 0)) return ['auto', 'auto']
  return [0, 'auto']
}

/** Compact Y-axis tick for plain numbers ("12K"). Non-finite passes through. */
export function compactNumberLabel(value: number, locale: string): string {
  if (!Number.isFinite(value)) return String(value)
  try {
    return new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 }).format(value)
  } catch {
    return String(value)
  }
}

/**
 * Compact Y-axis tick for money. Honors the TP-05 contract from i18n/money:
 * everything is USD by origin, a non-USD presentation code is presentation
 * only (no FX), so the compact amount keeps an explicit " USD" suffix instead
 * of a foreign currency symbol.
 */
export function compactMoneyLabel(value: number, locale: string, currency?: string): string {
  if (!Number.isFinite(value)) return String(value)
  const cur = currency && currency.length === 3 ? currency.toUpperCase() : 'USD'
  try {
    if (cur === 'USD') {
      return new Intl.NumberFormat(locale, {
        style: 'currency',
        currency: 'USD',
        notation: 'compact',
        maximumFractionDigits: 1,
      }).format(value)
    }
    return `${new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 }).format(value)} USD`
  } catch {
    return String(value)
  }
}

/** Explicit "one point" and "empty" states so callers can handle them. */
export function chartDataState(pointCount: number): ChartDataState {
  if (pointCount <= 0) return 'empty'
  if (pointCount === 1) return 'single'
  return 'many'
}
