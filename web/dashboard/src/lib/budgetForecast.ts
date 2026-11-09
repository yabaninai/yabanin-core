// AUX-15: pace-based budget forecasts over data that already exists.
//
// Every forecast is an honest estimate or "unknown" — a missing series is
// never invented into a date. The result is one of:
//   exceeded   — the limit is already spent (the bar carries the color);
//   date       — the projected moment the limit is reached at the observed pace;
//   period_ok  — at the observed pace the limit is not reached within the
//                budget period (month for teams, UTC day for agents/alerts);
//   unknown    — not enough data to say anything (rendered as "—").
//
// Pace is linear over the most recent observations (see each function).
// All day boundaries are UTC: team budget periods ("YYYY-MM") and agent
// daily budgets (reset at UTC midnight) are defined in UTC server-side.

export type BudgetForecast =
  | { kind: 'exceeded' }
  | { kind: 'date'; at: Date }
  | { kind: 'period_ok' }
  | { kind: 'unknown' }

const DAY_MS = 86_400_000
/** Pace from a partial day younger than this is noise, not a trend. */
const MIN_ELAPSED_MS = 15 * 60_000

/** UTC calendar day of a timestamp, "YYYY-MM-DD". */
export function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10)
}

/** First millisecond of the UTC day containing `d`. */
export function utcDayStart(d: Date): Date {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()))
}

function mean(values: number[]): number {
  if (values.length === 0) return 0
  return values.reduce((a, b) => a + b, 0) / values.length
}

/**
 * Team monthly budget. `fullDaySpends` — USD spend per elapsed FULL UTC day of
 * the running period (chronological; today's partial day excluded). The pace
 * is the mean of the last three observed full days (a zero day is real pace
 * information, not noise).
 */
export function forecastMonthly(
  limit: number,
  spendToDate: number,
  fullDaySpends: number[],
  now: Date,
): BudgetForecast {
  if (!(limit > 0)) return { kind: 'unknown' }
  if (spendToDate >= limit) return { kind: 'exceeded' }
  if (fullDaySpends.length < 1) return { kind: 'unknown' }
  const pacePerDay = mean(fullDaySpends.slice(-3))
  if (!(pacePerDay > 0)) return { kind: 'period_ok' }
  const remaining = limit - spendToDate
  const at = new Date(now.getTime() + (remaining / pacePerDay) * DAY_MS)
  const periodEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1))
  if (at.getTime() >= periodEnd.getTime()) return { kind: 'period_ok' }
  return { kind: 'date', at }
}

/**
 * Agent daily budget (UTC day). `previousDaysAvg` — mean USD spend of the
 * previous days when today's own pace is not usable yet.
 */
export function forecastDaily(
  limit: number,
  spendToday: number,
  now: Date,
  previousDaysAvg: number | null,
): BudgetForecast {
  if (!(limit > 0)) return { kind: 'unknown' }
  const dayStart = utcDayStart(now).getTime()
  const elapsed = now.getTime() - dayStart
  if (spendToday >= limit) return { kind: 'exceeded' }
  const paceToday = elapsed > 0 ? spendToday / elapsed : 0
  if (spendToday > 0 && elapsed >= MIN_ELAPSED_MS) {
    return atWithinDay(dayStart, limit / paceToday, now)
  }
  if (previousDaysAvg != null && previousDaysAvg > 0) {
    // previousDaysAvg is USD/day → the limit is reached after limit/avg days.
    return atWithinDay(dayStart, (limit / previousDaysAvg) * DAY_MS, now)
  }
  return { kind: 'unknown' }
}

/**
 * Org spend alert: today's (UTC) spend against the daily threshold.
 */
export function forecastAlert(threshold: number, spendToday: number, now: Date): BudgetForecast {
  if (!(threshold > 0)) return { kind: 'unknown' }
  const dayStart = utcDayStart(now).getTime()
  const elapsed = now.getTime() - dayStart
  if (spendToday >= threshold) return { kind: 'exceeded' }
  if (spendToday <= 0 || elapsed < MIN_ELAPSED_MS) return { kind: 'unknown' }
  return atWithinDay(dayStart, threshold / (spendToday / elapsed), now)
}

function atWithinDay(dayStartMs: number, elapsedMsToLimit: number, now: Date): BudgetForecast {
  const at = dayStartMs + elapsedMsToLimit
  const dayEnd = dayStartMs + DAY_MS
  if (at >= dayEnd) return { kind: 'period_ok' }
  if (at <= now.getTime()) return { kind: 'period_ok' }
  return { kind: 'date', at: new Date(at) }
}

// ---------------------------------------------------------------------------
// Parsing the shared analytics time series (AUX-15 consumes /api/analytics/
// query with group_by=team|agent, granularity=day, metrics=cost_usd).
// ---------------------------------------------------------------------------

export interface AnalyticsLite {
  columns: Array<{ name: string; type: string }>
  rows: Array<Array<unknown>>
}

export interface DimDailySeries {
  /** UTC day key → spend. */
  perDay: Map<string, number>
  /** Spend recorded on `todayKey` (a partial day). */
  today: number
  /** Spend over the whole series. */
  total: number
}

/**
 * Per-dimension daily spend series from an analytics result. A result without
 * the requested dimension column (shape drift, other query) yields an empty
 * map — the callers render "—", never a fabricated series.
 */
export function analyticsDailyByDim(
  result: AnalyticsLite,
  dim: 'agent' | 'team',
  todayKey: string,
): Map<string, DimDailySeries> {
  const out = new Map<string, DimDailySeries>()
  const timeIdx = result.columns.findIndex(c => c.type === 'time')
  const dimIdx = result.columns.findIndex(c => c.name === dim)
  let metricIdx = result.columns.findIndex(c => c.name === 'cost_usd' && c.type === 'number')
  if (metricIdx < 0) metricIdx = result.columns.findIndex(c => c.type === 'number')
  if (timeIdx < 0 || dimIdx < 0 || metricIdx < 0) return out
  for (const row of result.rows) {
    const id = row[dimIdx]
    if (typeof id !== 'string' || id === '' || id === '(other)') continue
    const day = String(row[timeIdx] ?? '').slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) continue
    const raw = row[metricIdx]
    const spend = typeof raw === 'number' ? raw : Number(raw)
    if (!Number.isFinite(spend)) continue
    let series = out.get(id)
    if (!series) {
      series = { perDay: new Map(), today: 0, total: 0 }
      out.set(id, series)
    }
    series.perDay.set(day, (series.perDay.get(day) ?? 0) + spend)
    series.total += spend
    if (day === todayKey) series.today += spend
  }
  return out
}

/** Per-id display names from the analytics payload (server-resolved). */
export function analyticsDisplayNames(
  result: AnalyticsLite,
  dim: 'agent' | 'team',
): Record<string, string> {
  const names = (result as { display_names?: Record<string, Record<string, string>> }).display_names
  return names?.[dim] ?? {}
}
