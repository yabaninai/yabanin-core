// AUX-01 (DataTable v2): table-scoped URL state (sort + page), pure and
// dependency-free so node:test can cover parse/serialize — the encode/decode
// pair a reload uses to restore the view — without a DOM.
//
// The dashboard routes through the hash (#page?params). Keys are prefixed
// per table so several tables can coexist on one screen without clashing
// with each other or with scope params (org, provider, locale, …). The sort
// value follows the plan-wide contract `sort=<column>:<asc|desc>`:
//   <tableId>__page = "3"
//   <tableId>__sort = "cost_usd:desc"

import type { SortDir, SortState } from './tableSort'

export interface TableUrlState {
  page: number
  sort: SortState | null
}

export interface TableUrlDefaults {
  page?: number
  sort?: SortState | null
}

function keys(tableId: string): { page: string; sort: string } {
  return {
    page: `${tableId}__page`,
    sort: `${tableId}__sort`,
  }
}

// parsePage accepts only integers >= 1; anything else falls back. The URL is
// user-editable, so an out-of-range or garbage value must never poison state.
function parsePage(raw: string | null, fallback: number): number {
  if (!raw) return fallback
  const n = Number.parseInt(raw, 10)
  return Number.isFinite(n) && n >= 1 ? n : fallback
}

// parseSort accepts "<column>:<asc|desc>" (a missing :dir part reads as asc);
// a missing/blank column falls back. Column keys never contain ":".
function parseSort(raw: string | null, fallback: SortState | null): SortState | null {
  if (!raw) return fallback
  const sep = raw.lastIndexOf(':')
  const key = sep < 0 ? raw : raw.slice(0, sep)
  const dirPart = sep < 0 ? '' : raw.slice(sep + 1)
  if (key.trim() === '') return fallback
  const dir: SortDir = dirPart === 'desc' ? 'desc' : 'asc'
  return { key, dir }
}

// readTableUrlState is the reload path: it decodes one table's state from the
// query, falling back to the caller's defaults for absent/invalid values.
export function readTableUrlState(
  query: URLSearchParams | string,
  tableId: string,
  defaults: TableUrlDefaults = {},
): TableUrlState {
  const params = typeof query === 'string' ? new URLSearchParams(query) : query
  const k = keys(tableId)
  return {
    page: parsePage(params.get(k.page), defaults.page ?? 1),
    sort: parseSort(params.get(k.sort), defaults.sort ?? null),
  }
}

// writeTableUrlState encodes one table's state into the query. Default values
// are deleted rather than written so a plain URL stays a plain URL.
export function writeTableUrlState(params: URLSearchParams, tableId: string, state: TableUrlState): void {
  const k = keys(tableId)
  if (state.page > 1) {
    params.set(k.page, String(state.page))
  } else {
    params.delete(k.page)
  }
  if (state.sort) {
    params.set(k.sort, `${state.sort.key}:${state.sort.dir}`)
  } else {
    params.delete(k.sort)
  }
}
