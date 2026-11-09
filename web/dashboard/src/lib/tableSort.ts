// AUX-01 (DataTable v2): typed sort comparator and the sort-cycle state
// machine, pure and dependency-free so node:test can cover them without a
// DOM. The React side (DataTable.tsx) delegates all ordering decisions here.

export type SortDir = 'asc' | 'desc'

export interface SortState {
  key: string
  dir: SortDir
}

/**
 * Sort semantic of a column, driving the typed comparator.
 *  - `text`   locale-aware string order (numeric: "9" < "10")
 *  - `number` numeric order over numbers and numeric strings
 *  - `money`  numeric order over money strings ("$1,234.00", "12.34 USD",
 *             "1 234,00 €")
 *  - `date`   chronological order (ISO strings or epoch ms numbers)
 */
export type ColumnSortType = 'text' | 'number' | 'money' | 'date'

export type SortValue = string | number | null | undefined

// nextSortState implements the AUX-01 header-click cycle for one column:
// unsorted → asc → desc → default. A different column always starts at asc.
// The default is `defaultSort` (null when the table has none — i.e. the rows
// as fetched).
export function nextSortState(
  current: SortState | null,
  key: string,
  defaultSort: SortState | null = null,
): SortState | null {
  if (!current || current.key !== key) return { key, dir: 'asc' }
  if (current.dir === 'asc') return { key, dir: 'desc' }
  return defaultSort
}

// toNumber normalizes numeric-ish sort values. Money decorations (currency
// signs/codes, grouping separators, NBSP) are stripped; the rightmost of
// "." / "," decides the decimal separator when both appear, and a lone
// trailing separator followed by 1–2 digits reads as a fraction ("1234,5").
// Anything unparsable is missing (null), never 0.
function toNumber(v: SortValue): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v !== 'string') return null
  const cleaned = v.replace(/[^\d.,-]/g, '')
  if (cleaned === '' || cleaned === '-' || cleaned === '.' || cleaned === ',') return null
  const lastDot = cleaned.lastIndexOf('.')
  const lastComma = cleaned.lastIndexOf(',')
  let decimal = ''
  let grouping = ''
  if (lastDot >= 0 && lastComma >= 0) {
    decimal = lastDot > lastComma ? '.' : ','
    grouping = decimal === '.' ? ',' : '.'
  } else if (lastDot >= 0) {
    decimal = '.'
  } else if (lastComma >= 0) {
    if (/,\d{1,2}$/.test(cleaned)) decimal = ','
    else grouping = ','
  }
  const normalized = grouping ? cleaned.split(grouping).join('') : cleaned
  const withDot = decimal && decimal !== '.' ? normalized.replace(decimal, '.') : normalized
  const n = Number(withDot)
  return Number.isFinite(n) ? n : null
}

// toDate normalizes date values to epoch ms. Numbers are already epochs;
// strings go through Date.parse. Unparsable input is missing, never epoch 0.
function toDate(v: SortValue): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v !== 'string' || v.trim() === '') return null
  const t = Date.parse(v)
  return Number.isNaN(t) ? null : t
}

// toText keeps real values; null/undefined stay missing so they can be
// ordered last by compareSortState instead of becoming the string "null".
function toText(v: SortValue): string | null {
  if (typeof v === 'string') return v
  if (typeof v === 'number' && Number.isFinite(v)) return String(v)
  return null
}

function normalize(v: SortValue, type: ColumnSortType): string | number | null {
  if (type === 'text') return toText(v)
  if (type === 'date') return toDate(v)
  return toNumber(v) // number | money
}

// Locale-aware text collation is cached: DataTable sorts once per render and
// the collator itself is immutable, so one instance per locale is enough.
const collatorCache = new Map<string, Intl.Collator>()

function textCollator(locale: string | undefined): Intl.Collator {
  const key = locale ?? ''
  let c = collatorCache.get(key)
  if (!c) {
    // numeric: digit sequences compare by magnitude ("9" < "10");
    // sensitivity: base ignores case/accents for a stable, human order.
    c = new Intl.Collator(key, { numeric: true, sensitivity: 'base' })
    collatorCache.set(key, c)
  }
  return c
}

// compareSortState orders two raw sort values under one column's semantics.
// Missing/unparsable values (null/undefined/invalid dates/unparsable money)
// sort LAST in both directions — direction flips only the order of present
// values, so an empty cell never jumps to the top on desc.
export function compareSortState(
  a: SortValue,
  b: SortValue,
  type: ColumnSortType,
  dir: SortDir,
  locale?: string,
): number {
  const na = normalize(a, type)
  const nb = normalize(b, type)
  if (na === null && nb === null) return 0
  if (na === null) return 1
  if (nb === null) return -1
  let cmp: number
  if (typeof na === 'string' && typeof nb === 'string') {
    cmp = textCollator(locale).compare(na, nb)
  } else {
    const fa = typeof na === 'string' ? Number(na) : na
    const fb = typeof nb === 'string' ? Number(nb) : nb
    cmp = fa < fb ? -1 : fa > fb ? 1 : 0
  }
  return dir === 'asc' ? cmp : -cmp
}
