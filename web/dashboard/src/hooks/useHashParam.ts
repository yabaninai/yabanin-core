import { useCallback, useState } from 'react'
import { readLastOrg, rememberOrg } from '../lib/orgScope'

// UI-contract #1: org/time scope lives in the URL so a filtered view is a
// shareable link and survives reload/back-forward. The app routes via the
// hash (#page?params) — the hook reads and rewrites only the query part,
// preserving everything else (page id, locale, quality-screen drafts).

function readHashQuery(): URLSearchParams {
  const q = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(q)
}

export function useHashParam(key: string): [string, (v: string) => void] {
  // Cross-tab continuity for the org scope: when the hash carries no org,
  // start from the last committed one; committing an org updates it.
  const [value, setValue] = useState(
    () => readHashQuery().get(key) ?? (key === 'org' ? readLastOrg() : ''))

  const set = useCallback((v: string) => {
    setValue(v)
    if (key === 'org') rememberOrg(v.trim())
    // location.hash carries the leading '#'; normalize before re-prefixing so
    // repeated writes never grow '#page' into '##page' (a doubled hash parses
    // back as an unknown page after reload). AUX-22 reload regression.
    const path = window.location.hash.split('?')[0].replace(/^#+/, '')
    const params = new URLSearchParams(window.location.hash.split('?')[1] ?? '')
    if (v) params.set(key, v)
    else params.delete(key)
    const qs = params.toString()
    // replaceState: scope changes do not spam history; navigation still does.
    window.history.replaceState(
      null, '',
      `${window.location.pathname}${window.location.search}#${path}${qs ? `?${qs}` : ''}`,
    )
  }, [key])

  return [value, set]
}
