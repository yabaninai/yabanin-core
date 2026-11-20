import { useCallback, useEffect, useState } from 'react'
import { readInspectParam, writeInspectParam } from '../lib/inspectUrl'

// The URL controls the inspector both at mount and during same-document navigation.

function readHashQuery(): URLSearchParams {
  const q = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(q)
}

function readHashInspect(): string {
  try {
    return readInspectParam(readHashQuery()) ?? ''
  } catch {
    return ''
  }
}

function writeHash(id: string | null): void {
  const [path, q] = window.location.hash.split('?')
  const params = new URLSearchParams(q ?? '')
  writeInspectParam(params, id)
  const qs = params.toString()
  // replaceState: opening/closing an inspector is view state, not navigation.
  window.history.replaceState(
    null, '',
    `${window.location.pathname}${window.location.search}#${path.replace(/^#+/, '')}${qs ? `?${qs}` : ''}`,
  )
}

export function useInspectParam(): [string, (id: string | null) => void] {
  const [value, setValue] = useState(readHashInspect)

  useEffect(() => {
    const adopt = () => setValue(readHashInspect())
    window.addEventListener('hashchange', adopt)
    adopt()
    return () => window.removeEventListener('hashchange', adopt)
  }, [])

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
