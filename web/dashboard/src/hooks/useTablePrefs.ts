import { useCallback, useRef, useState } from 'react'
import {
  clearTablePrefs, DEFAULT_TABLE_PREFS, readTablePrefs, writeTablePrefs,
  type TableDensity, type TablePrefs,
} from '../lib/tablePrefs'

// AUX-22 — page-owned table preferences (hidden columns + density). The page
// instance is the single owner: it hands the same state to the DataTable
// (hiddenColumnIds, density), the Columns menu and the CSV export, so the
// three can never disagree. Persistence is per tableId via lib/tablePrefs
// and survives reload; Reset removes the stored record entirely.

export interface TablePrefsApi {
  /** Column keys currently excluded from render/sort/CSV. */
  hiddenColumnIds: string[]
  density: TableDensity
  setHiddenColumnIds: (next: string[]) => void
  setDensity: (next: TableDensity) => void
  /** Clears the stored record and restores the defaults. */
  reset: () => void
}

export function useTablePrefs(tableId: string): TablePrefsApi {
  const [prefs, setPrefs] = useState<TablePrefs>(() => readTablePrefs(tableId))
  // A ref keeps consecutive writes in one handler (hide + compact) consistent
  // without waiting for the re-render — the same pattern as useTableUrlState.
  const ref = useRef(prefs)

  const commit = useCallback((next: TablePrefs) => {
    ref.current = next
    setPrefs(next)
    writeTablePrefs(tableId, next)
  }, [tableId])

  const setHiddenColumnIds = useCallback(
    (hiddenColumns: string[]) => commit({ ...ref.current, hiddenColumns }),
    [commit],
  )
  const setDensity = useCallback(
    (density: TableDensity) => commit({ ...ref.current, density }),
    [commit],
  )
  const reset = useCallback(() => {
    // Reset removes the stored record entirely (clearTablePrefs) and restores
    // the in-memory defaults WITHOUT writing them back — a reset table keeps
    // no localStorage record at all.
    clearTablePrefs(tableId)
    const defaults = { ...DEFAULT_TABLE_PREFS, hiddenColumns: [] }
    ref.current = defaults
    setPrefs(defaults)
  }, [tableId])

  return {
    hiddenColumnIds: prefs.hiddenColumns,
    density: prefs.density,
    setHiddenColumnIds,
    setDensity,
    reset,
  }
}
