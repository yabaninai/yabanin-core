// kinds: money/number/tokens/date/code/duration/percent).
//
// Pure core (the money.ts / date.ts pattern): no i18n runtime, no DOM, so
// node:test can pin the rendering contract. The React side (DataTable.tsx)
// binds the active UI locale on top.
//
// Honesty rules carried over from the established primitives:
//   * missing/unknown is rendered as an em dash ("—") — unknown never
//   * money keeps 2 decimals in tables; a nonzero sub-cent amount renders
//     as "<$0.01" with the EXACT value in the cell's title hint (FE-07) —
//     the widened-fraction view from money.ts stays for KPI tiles;
//   * token pairs render as "input / output" with locale grouping —
//     never as a single merged sum (the two directions mean different
//     things for pricing);

import { formatUsdMoney } from '../i18n/money.ts'
import { formatDateTimeIn } from '../i18n/date.ts'

/** A formatted cell: visible text plus an optional exact-value hint. */
export interface FormattedCell {
  text: string
  /** Native title hint; set when the visible text is rounded/abbreviated. */
  title?: string
}

export const MISSING_VALUE = '—'

const MISSING_CELL: FormattedCell = { text: MISSING_VALUE }

type CellInput = string | number | null | undefined

/** Finite number from a cell input; null/undefined/empty/unparsable → null. */
function toFinite(value: CellInput): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value)
    return Number.isFinite(n) ? n : null
  }
  return null
}

function localeOf(locale?: string): string {
  return locale && locale.trim() !== '' ? locale : 'en'
}

// ---------------------------------------------------------------------------
// money — dollars, 2 decimals, sub-cent shows "<$0.01" + exact hint (FE-07).
// ---------------------------------------------------------------------------

/**
 * Table money cell. `amount` is in currency units (dollars), USD by origin
 * (TP-05). A `currency` presentation code that is not USD keeps the honest
 * unit form ("12,34 USD") — no FX is invented here (see money.ts).
 */
export function formatMoneyCell(
  amount: CellInput,
  opts?: { locale?: string; currency?: string },
): FormattedCell {
  const value = toFinite(amount)
  if (value === null) return MISSING_CELL
  const abs = Math.abs(value)
  if (abs > 0 && abs < 0.01) {
    return {
      text: `${value < 0 ? '-' : ''}<$0.01`,
      title: fmtMoneyExact(value, opts),
    }
  }
  return { text: fmtMoney(value, opts) }
}

function fmtMoney(value: number, opts?: { locale?: string; currency?: string }): string {
  const locale = localeOf(opts?.locale)
  const currency = opts?.currency && opts.currency.length === 3 ? opts.currency.toUpperCase() : 'USD'
  if (currency === 'USD') {
    try {
      return new Intl.NumberFormat(locale, {
        style: 'currency',
        currency: 'USD',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(value)
    } catch {
      return `$${value.toFixed(2)}`
    }
  }
  // Non-USD presentation: no FX exists, so the amount keeps its USD value
  // with an explicit code suffix (money.ts contract).
  try {
    return `${new Intl.NumberFormat(locale, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(value)} ${currency}`
  } catch {
    return `${value.toFixed(2)} ${currency}`
  }
}

/** The exact amount for the sub-cent hint — widened fractions, never "<$0.01". */
function fmtMoneyExact(value: number, opts?: { locale?: string; currency?: string }): string {
  const locale = localeOf(opts?.locale)
  const currency = opts?.currency && opts.currency.length === 3 ? opts.currency.toUpperCase() : 'USD'
  if (currency === 'USD') return formatUsdMoney(value, undefined, locale)
  return formatUsdMoney(value, currency, locale)
}

// ---------------------------------------------------------------------------
// number — grouped counts; at most 2 fraction digits in tables.
// ---------------------------------------------------------------------------

export function formatNumberCell(
  value: CellInput,
  opts?: { locale?: string; maximumFractionDigits?: number },
): FormattedCell {
  const n = toFinite(value)
  if (n === null) return MISSING_CELL
  try {
    return {
      text: new Intl.NumberFormat(localeOf(opts?.locale), {
        maximumFractionDigits: opts?.maximumFractionDigits ?? 2,
      }).format(n),
    }
  } catch {
    return { text: String(n) }
  }
}

// ---------------------------------------------------------------------------
// tokens — "input / output" pair with grouping; sides stay distinguishable.
// ---------------------------------------------------------------------------

export interface TokenUsage {
  input?: CellInput
  output?: CellInput
}

/**
 * `value` may be a `{input, output}` object (the analytics/API shape), an
 * `[input, output]` pair, or a bare total (rendered alone). A missing side
 * renders as "—" inside the pair — it is never folded into 0.
 */
export function formatTokensCell(
  value: unknown,
  opts?: { locale?: string },
): FormattedCell {
  let input: CellInput
  let output: CellInput
  let single: CellInput
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const pair = value as TokenUsage
    input = pair.input
    output = pair.output
    single = null
  } else if (Array.isArray(value) && value.length === 2) {
    input = value[0] as CellInput
    output = value[1] as CellInput
    single = null
  } else {
    input = null
    output = null
    single = (value ?? null) as CellInput
  }
  if (input === null && output === null && single === null) return MISSING_CELL
  if (input === null && output === null) return formatNumberCell(single, opts)
  const locale = localeOf(opts?.locale)
  const side = (v: CellInput) => {
    const n = toFinite(v)
    if (n === null) return MISSING_VALUE
    try {
      return new Intl.NumberFormat(locale, { maximumFractionDigits: 0 }).format(n)
    } catch {
      return String(Math.round(n))
    }
  }
  return { text: `${side(input)} / ${side(output)}` }
}

// ---------------------------------------------------------------------------
// date — localized date+time; zero/placeholder instants are not dates.
// ---------------------------------------------------------------------------

export function formatDateCell(
  value: string | number | Date | null | undefined,
  opts?: { locale?: string; timezone?: string },
): FormattedCell {
  if (value == null || value === '') return MISSING_CELL
  const instant: string | Date = typeof value === 'number'
    ? new Date(value)
    : value
  return { text: formatDateTimeIn(localeOf(opts?.locale), instant, opts?.timezone) }
}

// ---------------------------------------------------------------------------
// code — verbatim short codes (model names, regions, statuses); mono+nowrap
// styling is the column's business, the text passes through unchanged.
// ---------------------------------------------------------------------------

export function formatCodeCell(value: CellInput): FormattedCell {
  if (value == null || String(value).trim() === '') return MISSING_CELL
  return { text: String(value) }
}

// ---------------------------------------------------------------------------
// duration — milliseconds to a compact human span ("850 ms", "1.4 s",
// "2 m 05 s", "1 h 04 m"); sub-second precision collapses as spans grow.
// ---------------------------------------------------------------------------

export function formatDurationCell(
  ms: CellInput,
  opts?: { locale?: string },
): FormattedCell {
  void opts
  const value = toFinite(ms)
  if (value === null) return MISSING_CELL
  const sign = value < 0 ? '-' : ''
  const abs = Math.abs(value)
  if (abs < 1000) return { text: `${sign}${Math.round(abs)} ms` }
  const totalSeconds = abs / 1000
  if (totalSeconds < 60) {
    return { text: `${sign}${trimNum(totalSeconds)} s` }
  }
  const totalMinutes = Math.floor(totalSeconds / 60)
  if (totalMinutes < 60) {
    const s = Math.round(totalSeconds - totalMinutes * 60)
    // 59.6s rounds to a full minute — carry it instead of "0 m 60 s".
    if (s >= 60) return { text: `${sign}${trimNum(totalMinutes + 1)} m` }
    return { text: `${sign}${totalMinutes} m ${pad2(s)} s` }
  }
  const hours = Math.floor(totalMinutes / 60)
  const m = Math.round(totalMinutes - hours * 60)
  if (m >= 60) return { text: `${sign}${hours + 1} h` }
  return { text: `${sign}${hours} h ${pad2(m)} m` }
}

function trimNum(v: number): string {
  // One fraction digit at most, trailing ".0" trimmed ("1.4 s", "12 s").
  const s = v.toFixed(1)
  return s.endsWith('.0') ? s.slice(0, -2) : s
}

function pad2(v: number): string {
  return v < 10 ? `0${v}` : String(v)
}

// ---------------------------------------------------------------------------
// which is the default scale; pass `scale: 'percent'` for pre-scaled 0..100
// values. Trailing fraction zeros are trimmed ("70%", "12.5%").
// ---------------------------------------------------------------------------

export function formatPercentCell(
  value: CellInput,
  opts?: { locale?: string; scale?: 'ratio' | 'percent'; digits?: number },
): FormattedCell {
  const raw = toFinite(value)
  if (raw === null) return MISSING_CELL
  const scale = opts?.scale ?? 'ratio'
  const ratio = scale === 'percent' ? raw / 100 : raw
  const digits = opts?.digits ?? 1
  const pct = ratio * 100
  const rounded = Number(pct.toFixed(digits))
  try {
    return {
      text: `${new Intl.NumberFormat(localeOf(opts?.locale), {
        maximumFractionDigits: digits,
      }).format(rounded)}%`,
    }
  } catch {
    return { text: `${rounded}%` }
  }
}

// ---------------------------------------------------------------------------
// DataTable dispatch — the column-format registry.
// ---------------------------------------------------------------------------

export type ColumnFormatType =
  | 'money'
  | 'number'
  | 'tokens'
  | 'date'
  | 'code'
  | 'duration'
  | 'percent'

/** Per-column knobs forwarded to the formatters (all optional). */
export interface ColumnFormatOptions {
  locale?: string
  /** Money presentation code (USD default; no FX is applied). */
  currency?: string
  /** Date/timezone rendering (IANA name; UTC fallback). */
  timezone?: string
  /** Percent value scale: 'ratio' (0..1, default) or 'percent' (0..100). */
  percentScale?: 'ratio' | 'percent'
  maximumFractionDigits?: number
}

/** Format a raw cell value under a column format kind. */
export function formatCellByFormat(
  format: ColumnFormatType,
  value: unknown,
  opts?: ColumnFormatOptions,
): FormattedCell {
  switch (format) {
    case 'money':
      return formatMoneyCell(value as CellInput, opts)
    case 'number':
      return formatNumberCell(value as CellInput, opts)
    case 'tokens':
      return formatTokensCell(value, opts)
    case 'date':
      return formatDateCell(value as string | number | Date | null, opts)
    case 'code':
      return formatCodeCell(value as CellInput)
    case 'duration':
      return formatDurationCell(value as CellInput, opts)
    case 'percent':
      return formatPercentCell(value as CellInput, opts)
  }
}

/**
 * Default sort semantics per format (a column's explicit `type` still wins):
 * dates compare chronologically, everything numeric numerically, codes as text.
 */
export const FORMAT_SORT_TYPE: Record<ColumnFormatType, 'money' | 'number' | 'date' | 'text'> = {
  money: 'money',
  number: 'number',
  tokens: 'number',
  date: 'date',
  code: 'text',
  duration: 'number',
  percent: 'number',
}

/** Formats whose cells render mono/tabular (and never wrap for date/code). */
export const FORMAT_MONO: Record<ColumnFormatType, boolean> = {
  money: true,
  number: true,
  tokens: true,
  date: false,
  code: true,
  duration: true,
  percent: true,
}
