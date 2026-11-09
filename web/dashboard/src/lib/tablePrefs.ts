// AUX-22 — Table personalization, part 1: per-table local preferences.
//
// Every DataTable consumer keyed by a stable tableId ('lineage', 'tasks',
// 'analytics', …) can persist operator preferences in localStorage:
//   * hiddenColumns — column keys the operator switched off (the Columns
//     menu); hidden columns are excluded from render, sort and CSV exports;
//   * density — 'comfortable' (default) or 'compact' row spacing.
//
// Contract (mirrors lib/globalScope.ts persistence rules):
//   * one localStorage key PER TABLE (the tableId is part of the key), so
//     tables never overwrite each other's preferences;
//   * the stored JSON is user-editable, so everything is re-validated on
//     read — a corrupted record degrades to the defaults, never to a crash;
//   * all failures (private mode, quota, tests without a browser) are
//     best-effort: persistence is a convenience, not a contract.

export type TableDensity = 'compact' | 'comfortable'

export interface TablePrefs {
  /** Column keys excluded from render/sort/CSV (order follows the columns). */
  hiddenColumns: string[]
  density: TableDensity
}

export const DEFAULT_TABLE_PREFS: TablePrefs = { hiddenColumns: [], density: 'comfortable' }

const KEY_PREFIX = 'yabanin.tablePrefs.v1:'

export function tablePrefsKey(tableId: string): string {
  return `${KEY_PREFIX}${tableId}`
}

// Boundaries for the untrusted stored record: a bounded column list of
// bounded strings, and nothing else survives a parse.
const MAX_HIDDEN_COLUMNS = 64
const MAX_COLUMN_KEY_LENGTH = 64

/** Validates an untrusted parsed-JSON value into full prefs (defaults fill gaps). */
export function parseTablePrefs(raw: unknown): TablePrefs {
  if (typeof raw !== 'object' || raw === null) return { ...DEFAULT_TABLE_PREFS, hiddenColumns: [] }
  const v = raw as Partial<TablePrefs>
  const hiddenColumns = Array.isArray(v.hiddenColumns)
    ? [...new Set(v.hiddenColumns
        .filter((k): k is string => typeof k === 'string' && k.trim() !== '' && k.length <= MAX_COLUMN_KEY_LENGTH)
        .slice(0, MAX_HIDDEN_COLUMNS))]
    : []
  const density: TableDensity = v.density === 'compact' ? 'compact' : 'comfortable'
  return { hiddenColumns, density }
}

export function readTablePrefs(tableId: string): TablePrefs {
  try {
    const raw = localStorage.getItem(tablePrefsKey(tableId))
    if (!raw) return { ...DEFAULT_TABLE_PREFS, hiddenColumns: [] }
    return parseTablePrefs(JSON.parse(raw))
  } catch {
    return { ...DEFAULT_TABLE_PREFS, hiddenColumns: [] }
  }
}

export function writeTablePrefs(tableId: string, prefs: TablePrefs): void {
  try {
    localStorage.setItem(tablePrefsKey(tableId), JSON.stringify(parseTablePrefs(prefs)))
  } catch {
    // Private mode / tests — persistence is best-effort.
  }
}

/** Removes the table's record entirely (the "Reset to default" action). */
export function clearTablePrefs(tableId: string): void {
  try {
    localStorage.removeItem(tablePrefsKey(tableId))
  } catch {
    // Best-effort.
  }
}
