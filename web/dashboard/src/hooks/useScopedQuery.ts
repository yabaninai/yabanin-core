import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../api/client'
import { isCurrentScope, type AsyncScope } from '../lib/asyncScope'

// The one scoped read lifecycle shared by the data screens. Every screen
// read (org/provider/period/page/sort/epoch → fetch) needs the same guard
// set: a generation counter, an AbortController, and success/error/finally
// guards that discard a completion when a newer load replaces it. This hook
// is that lifecycle, once:
//
//   * the `key` is the applied-scope identity (org/provider/period/page/sort
//     …); a change aborts the in-flight load and starts a new one — a delayed
//     completion of a superseded scope never lands (asyncScope rule);
//   * the epoch is page-local and bumps exactly once per org switch; a
//     completion applies only while its captured (org, epoch) is still
//     current, mirroring the KeysPage mutation contract for reads;
//   * success guard: stale completions are discarded; a fresh one becomes
//     `data`, records `appliedKey` (the scope the SHOWN data was fetched
//     under — captions describe applied, never the live draft) and `asOf`
//     ("data as of" freshness clock);
//   * error guard: stale completions are discarded; an aborted fetch
//     (ApiError status 0 — unmount or a newer load) is silence, not an error;
//     refresh semantics: a failed refresh keeps the last good data and
//     raises the honest `refreshStale` marker instead of blanking the screen;
//   * finally guard: loading/refreshing clear only when the completing load
//     is still the current one.

export type ScreenState = 'not-loaded' | 'loading' | 'empty' | 'stale' | 'ready' | 'error'

// Derive the analytics screen state so the four states never blur:
// 'not-loaded' = nothing fetched yet; 'empty' = fetched but no records in
// scope; 'stale' = data shown is from a previous scope (a screen-replacing
// refetch is in flight); 'error' = the last fetch failed. `loading` must be
// false while a refresh is in flight — a refresh keeps the screen state
// (no loading/stale flicker over data that stays on screen).
export function deriveScreenState(o: {
  error: string
  loading: boolean
  hasResult: boolean
  resultHasContent: boolean
}): ScreenState {
  if (o.error) return 'error'
  if (o.loading) return o.hasResult ? 'stale' : 'loading'
  if (o.hasResult) return o.resultHasContent ? 'ready' : 'empty'
  return 'not-loaded'
}

export interface UseScopedQueryOptions<T> {
  /** Applied-scope identity. A change aborts the in-flight load and reloads. */
  key: string
  /** The org the read belongs to. Empty = org-less screen. */
  org?: string
  /** False (e.g. no org chosen yet) — no load starts; the in-flight aborts. */
  enabled?: boolean
  /** The read itself. Rejecting with ApiError(0) counts as aborted. */
  fetcher: (signal: AbortSignal) => Promise<T>
}

export interface ScopedQueryApi<T> {
  /** Last successful result (kept across refreshes and failures). */
  data: T | null
  /** True while a load is in flight (including a refresh). */
  loading: boolean
  /** True while a refresh (kept-data reload) is in flight. */
  refreshing: boolean
  /** The last refresh failed — the shown data is honest-stale. */
  refreshStale: boolean
  /** The last screen-replacing failure message ('' when none). */
  error: string
  /** Epoch ms of the last SUCCESSFUL load (freshness clock). */
  asOf: number | null
  /** The key the shown data was fetched under (applied vs draft scope). */
  appliedKey: string | null
  /** Start a load; {refresh:true} keeps the last good data on failure. */
  load: (opts?: { refresh?: boolean }) => void
}

export function useScopedQuery<T>(options: UseScopedQueryOptions<T>): ScopedQueryApi<T> {
  const { key, org = '', enabled = true, fetcher } = options

  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshStale, setRefreshStale] = useState(false)
  const [error, setError] = useState('')
  const [asOf, setAsOf] = useState<number | null>(null)
  const [appliedKey, setAppliedKey] = useState<string | null>(null)

  // The page-local epoch bumps exactly once per org switch (ref
  // bookkeeping during render so a same-commit effect load already sees the
  // bumped epoch).
  const orgEpoch = useRef(0)
  const lastOrg = useRef(org)
  if (lastOrg.current !== org) {
    lastOrg.current = org
    orgEpoch.current += 1
  }
  // Latest-scope mirrors for the completion guards (a completion may arrive
  // after a re-render replaced the closures).
  const orgRef = useRef(org)
  orgRef.current = org

  const seq = useRef(0)
  const inFlight = useRef<AbortController | null>(null)

  const load = useCallback((opts?: { refresh?: boolean }) => {
    if (!enabled) return
    const isRefresh = opts?.refresh === true
    const run = ++seq.current
    const seen: AsyncScope = { org, epoch: orgEpoch.current }
    inFlight.current?.abort()
    const ac = new AbortController()
    inFlight.current = ac
    setLoading(true)
    setRefreshing(isRefresh)
    // A scope/window change is a NEW load — the previous result must not
    // survive it (error state resets, data is replaced). A refresh of the
    // same applied scope is different: a failed refresh never wipes the
    // last good data — it sets the honest stale marker instead
    // (asyncScope: this load captured the current generation; a superseded
    // completion is discarded below).
    if (!isRefresh) { setError(''); setRefreshStale(false) }
    void (async () => {
      try {
        const result = await fetcher(ac.signal)
        if (seq.current !== run) return // a newer load replaced this one
        if (!isCurrentScope(seen, { org: orgRef.current, epoch: orgEpoch.current })) return
        setData(result)
        setAppliedKey(key)
        setAsOf(Date.now())
        setRefreshStale(false)
        // A SUCCESSFUL refresh is also the recovery path — a revived
        // connection clears the earlier load error together with the data.
        setError('')
      } catch (e: unknown) {
        if (seq.current !== run) return
        if (e instanceof ApiError && e.status === 0) return // aborted (unmount/newer load)
        if (isRefresh) setRefreshStale(true)
        else setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (seq.current === run) { setLoading(false); setRefreshing(false) }
      }
    })()
  }, [enabled, key, org, fetcher])

  // Auto-load on mount and whenever the committed scope changes
  // (the fetcher/key identity carries the scope). The cleanup aborts the
  // in-flight load: the fetch rejects with ApiError(0), which the load path
  // already drops.
  useEffect(() => {
    load()
    return () => { inFlight.current?.abort() }
  }, [load])

  return { data, loading, refreshing, refreshStale, error, asOf, appliedKey, load }
}
