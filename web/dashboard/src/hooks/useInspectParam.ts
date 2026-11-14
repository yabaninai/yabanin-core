import { useCallback, useState } from 'react'
import { readInspectParam, writeInspectParam } from '../lib/inspectUrl'

// Page-local state for the inspect deep-link (EntityDrawer). Reads
// `?inspect=<id>` from the hash query once at mount (a shared link opens the
// drawer on load) and rewrites only that param on open/close, preserving
// everything else (page id, org scope, locale, sort) — the same contract as
// useHashParam/useTableUrlState.

function readHashQuery(): URLSearchParams {
  const q = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(q)
}

function writeHash(id: string | null): void {
  const [path, q] = window.location.hash.split('?')
  const params = new URLSearchParams(q ?? '')
  writeInspectParam(params, id)
  const qs = params.toString()
  // replaceState: opening/closing an inspector is view state, not navigation.
  window.history.replaceState(
    null, '',
    `${window.location.pathname}${window.location.search}#${path}${qs ? `?${qs}` : ''}`,
  )
}

export function useInspectParam(): [string, (id: string | null) => void] {
  const [value, setValue] = useState(() => {
    try {
      return readInspectParam(readHashQuery()) ?? ''
    } catch {
      // Non-browser environment (or unparsable URL) — no drawer.
      return ''
    }
  })

  const set = useCallback((id: string | null) => {
    const next = id && id.trim() !== '' ? id.trim() : ''
    setValue(next)
    try {
      writeHash(next || null)
    } catch {
      // Non-browser environment — URL sync is best-effort.
    }
  }, [])

  return [value, set]
}
