import { useCallback, useEffect, useState } from 'react'
import { readLastOrg, rememberOrg } from '../lib/orgScope'
import { subscribeGlobalScope } from '../lib/globalScope'

// UI-contract #1: org/time scope lives in the URL so a filtered view is a
// shareable link and survives reload/back-forward. The app routes via the
// hash (#page?params) — the hook reads and rewrites only the query part,
// preserving everything else (page id, locale, quality-screen drafts).

function readHashQuery(): URLSearchParams {
  const q = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(q)
}

/** The hook's read model: explicit hash param first (deep-link priority),
 *  the remembered org next (org only — same priority as the mount init and
 *  lib/globalScope's hashchange adopter). */
function readParam(key: string): string {
  return readHashQuery().get(key) ?? (key === 'org' ? readLastOrg() : '')
}

export function useHashParam(key: string): [string, (v: string) => void] {
  // Cross-tab continuity for the org scope: when the hash carries no org,
  // start from the last committed one; committing an org updates it.
  const [value, setValue] = useState(() => readParam(key))

  // Same-document synchronization (CUI-01 finding): the hash query is
  // written by more than this hook's setter — the Topbar OrgSwitcher's
  // scope store, deep links, and back/forward across page navigations.
  // Every key re-adopts from the CURRENT hash so org/request/... state can
  // never go stale while the page stays mounted (a forced reload was the
  // old workaround, not a contract).
  //
  // Two real event sources, both verified in Chromium:
  //   * hashchange — link navigation, deep links and back/forward (every
  //     URL this app writes keeps its whole query inside the fragment, so
  //     any history step that changes a param fires hashchange; popstate
  //     would only double-report those and is deliberately NOT bound);
  //   * the shared scope store — its commits (Topbar period/org switches)
  //     rewrite the hash with replaceState, which fires NO hashchange, so
  //     hash-keyed consumers subscribe to the store's existing emit via
  //     subscribeGlobalScope (no competing store, no history writes).
  // The hook's own writes use replaceState too, so adoption cannot loop.
  // Adoption re-reads the CURRENT hash (arriving URLs stay authoritative,
  // memory fallback for a missing org exactly like the mount init) and
  // never rewrites the URL or the remembered org.
  useEffect(() => {
    const adopt = () => {
      const next = readParam(key)
      setValue(prev => (prev === next ? prev : next))
    }
    window.addEventListener('hashchange', adopt)
    const unsubscribe = subscribeGlobalScope(adopt)
    // Adopt once on subscribe too: a hash written between the initial
    // render and this effect must not stay invisible until the NEXT event.
    adopt()
    return () => {
      window.removeEventListener('hashchange', adopt)
      unsubscribe()
    }
  }, [key])

  const set = useCallback((v: string) => {
    setValue(v)
    if (key === 'org') rememberOrg(v.trim())
    // location.hash carries the leading '#'; normalize before re-prefixing so
    // repeated writes never grow '#page' into '##page' (a doubled hash parses
    // back as an unknown page after reload).
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

/** 0028: URLSearchParams.get collapses a multi-valued param to its first
 *  value, so the scalar hook above cannot even OBSERVE selector-only
 *  mutations (row_key=12 -> row_key=12&row_key=99 keeps .get() at '12';
 *  absent -> row_key= keeps it at ''). This variant adopts the COMPLETE
 *  ordered value list as hook state: absent -> [], blank present -> [''],
 *  duplicates preserved in order, so any selector change re-renders. The
 *  setter writes one value (or deletes it) with useHashParam's exact
 *  replaceState semantics, minus the org memory (org-specific by design). */
export function useHashParamValues(key: string): [string[], (v: string) => void] {
  const [values, setValues] = useState<string[]>(() => readHashQuery().getAll(key))

  // Same two adoption sources as useHashParam (hashchange + scope store):
  // a page writing the hash with replaceState fires no hashchange, so a
  // selector rewritten by any other surface still re-adopts here.
  useEffect(() => {
    const adopt = () => {
      const next = readHashQuery().getAll(key)
      setValues(prev => (
        prev.length === next.length && prev.every((v, i) => v === next[i]) ? prev : next
      ))
    }
    window.addEventListener('hashchange', adopt)
    const unsubscribe = subscribeGlobalScope(adopt)
    adopt()
    return () => {
      window.removeEventListener('hashchange', adopt)
      unsubscribe()
    }
  }, [key])

  const set = useCallback((v: string) => {
    const trimmed = v.trim()
    setValues(trimmed ? [trimmed] : [])
    const path = window.location.hash.split('?')[0].replace(/^#+/, '')
    const params = new URLSearchParams(window.location.hash.split('?')[1] ?? '')
    if (trimmed) params.set(key, trimmed)
    else params.delete(key)
    const qs = params.toString()
    window.history.replaceState(
      null, '',
      `${window.location.pathname}${window.location.search}#${path}${qs ? `?${qs}` : ''}`,
    )
  }, [key])

  return [values, set]
}
