import { useCallback, useRef, useState } from 'react'
import { readTableUrlState, writeTableUrlState, type TableUrlState } from '../lib/tableUrl'
import type { SortState } from '../lib/tableSort'

// AUX-01: table-scoped URL state (sort + page) for DataTable consumers.
//
// The app routes via the hash (#page?params) — the hook reads and rewrites
// only the query part, preserving everything else (page id, locale, scope),
// the same contract as useHashParam. State is read once at mount, so a
// reload (or a shared link) restores the encoded view; encode/decode is
// delegated to lib/tableUrl.ts, which node:test covers directly.
//
// setPage/setSort compose through a ref so calling setSort(next) followed by
// setPage(1) in the same handler (the DataTable sort contract) writes one
// consistent snapshot instead of two stale ones.

export interface UseTableUrlStateOptions {
  /** Sort assumed when the URL encodes none. */
  defaultSort?: SortState | null
  /** Page assumed when the URL encodes none. */
  defaultPage?: number
}

export interface TableUrlStateApi {
  page: number
  setPage: (page: number) => void
  sort: SortState | null
  setSort: (sort: SortState | null) => void
}

function readHashQuery(): URLSearchParams {
  const q = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(q)
}

function writeHashQuery(tableId: string, state: TableUrlState): void {
  // location.hash carries the leading '#'; normalize before re-prefixing so
  // repeated writes never grow '#page' into '##page' (a doubled hash parses
  // back as an unknown page after reload). AUX-22 reload regression.
  const path = window.location.hash.split('?')[0].replace(/^#+/, '')
  const params = new URLSearchParams(window.location.hash.split('?')[1] ?? '')
  writeTableUrlState(params, tableId, state)
  const qs = params.toString()
  // replaceState: view-state changes do not spam history; navigation still does.
  window.history.replaceState(
    null, '',
    `${window.location.pathname}${window.location.search}#${path}${qs ? `?${qs}` : ''}`,
  )
}

export function useTableUrlState(tableId: string, options: UseTableUrlStateOptions = {}): TableUrlStateApi {
  const [state, setState] = useState<TableUrlState>(() => {
    try {
      return readTableUrlState(readHashQuery(), tableId, {
        page: options.defaultPage,
        sort: options.defaultSort,
      })
    } catch {
      // Non-browser environment (or unparsable URL) — plain defaults.
      return { page: options.defaultPage ?? 1, sort: options.defaultSort ?? null }
    }
  })

  const ref = useRef(state)

  const apply = useCallback((partial: Partial<TableUrlState>) => {
    const next = { ...ref.current, ...partial }
    ref.current = next
    setState(next)
    try {
      writeHashQuery(tableId, next)
    } catch {
      // Non-browser environment — URL sync is best-effort.
    }
  }, [tableId])

  const setPage = useCallback((page: number) => apply({ page }), [apply])
  const setSort = useCallback((sort: SortState | null) => apply({ sort }), [apply])

  return { page: state.page, setPage, sort: state.sort, setSort }
}
