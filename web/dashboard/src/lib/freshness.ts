// AUX-23: data freshness — "data as of HH:MM", a manual refresh button and an
// auto-refresh selector (off / 30 s / 1 min / 5 min) on the data screens
// (Overview, Requests, Dashboards).
//
// The interval is a personal, per-browser preference (localStorage) — it never
// enters the URL or the shared GlobalScope (AUX-08: the reporting period stays
// a shared deep-linkable fact; auto-refresh is not).
//
// Auto-refresh is honest and race-free:
//   - a tick landing while a load is in flight is SKIPPED, never queued —
//     no parallel requests (the asyncScope rule applied to refreshes; each
//     screen keeps its own generation guard, so a late response of a
//     superseded load can never land);
//   - it pauses while the tab is hidden or a modal is open (`paused`);
//   - it only runs while the screen holds data worth refreshing (`active`),
//     so an empty screen never polls.

import { useCallback, useEffect, useRef, useState } from 'react'

export const AUTO_REFRESH_KEY = 'yabanin.autoRefresh.v1'

/** The plan's honest intervals: off, or one of three presets. */
export const AUTO_REFRESH_OPTIONS: ReadonlyArray<{ ms: number; labelKey: string }> = [
  { ms: 0, labelKey: 'freshness.off' },
  { ms: 30_000, labelKey: 'freshness.30s' },
  { ms: 60_000, labelKey: 'freshness.1m' },
  { ms: 300_000, labelKey: 'freshness.5m' },
]

const KNOWN_MS = new Set(AUTO_REFRESH_OPTIONS.map(o => o.ms))

/** A stored value outside the preset whitelist reads as off — never a surprise interval. */
export function parseAutoRefreshInterval(raw: string | null | undefined): number {
  if (raw == null) return 0
  const n = Number(raw)
  return KNOWN_MS.has(n) ? n : 0
}

export function readAutoRefreshInterval(): number {
  try {
    return parseAutoRefreshInterval(localStorage.getItem(AUTO_REFRESH_KEY))
  } catch {
    return 0
  }
}

export function writeAutoRefreshInterval(ms: number): void {
  try {
    localStorage.setItem(AUTO_REFRESH_KEY, String(ms))
  } catch {
    // Non-browser environment — the choice stays session-only.
  }
}

/** The «данные на ЧЧ:ММ» clock label, in the active UI locale. */
export function formatAsOfTime(epochMs: number, locale: string): string {
  try {
    return new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit' }).format(new Date(epochMs))
  } catch {
    const d = new Date(epochMs)
    return `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`
  }
}

/** True while the browser tab is hidden (auto-refresh pauses). */
export function useDocumentHidden(): boolean {
  const [hidden, setHidden] = useState(
    () => typeof document !== 'undefined' && document.visibilityState === 'hidden',
  )
  useEffect(() => {
    const onChange = () => setHidden(document.visibilityState === 'hidden')
    document.addEventListener('visibilitychange', onChange)
    return () => document.removeEventListener('visibilitychange', onChange)
  }, [])
  return hidden
}

/** The persisted auto-refresh choice (localStorage, per browser). */
export function useAutoRefreshInterval(): [number, (ms: number) => void] {
  const [ms, setMs] = useState(readAutoRefreshInterval)
  const update = useCallback((next: number) => {
    setMs(next)
    writeAutoRefreshInterval(next)
  }, [])
  return [ms, update]
}

export interface AutoRefreshOptions {
  /** Chosen interval in ms; 0 = off. */
  intervalMs: number
  /** True while the tab is hidden or a modal is open — the timer stops. */
  paused: boolean
  /** True only while the screen holds data worth refreshing. */
  active: boolean
  /** True while a load is in flight — such ticks are skipped, never queued. */
  loading: boolean
  /** The screen's refresh call (idempotent, generation-guarded). */
  onRefresh: () => void
}

/**
 * AUX-23 auto-refresh timer: one interval per screen. Pausing tears the
 * interval down; resuming starts a fresh full interval, so a background tab
 * never fires a burst of missed ticks when the operator returns.
 */
export function useAutoRefresh(opts: AutoRefreshOptions): void {
  const refreshRef = useRef(opts.onRefresh)
  const loadingRef = useRef(opts.loading)
  // Track the latest callback/loading without re-arming the interval.
  useEffect(() => {
    refreshRef.current = opts.onRefresh
    loadingRef.current = opts.loading
  })
  const { intervalMs, paused, active } = opts
  useEffect(() => {
    if (intervalMs <= 0 || paused || !active) return undefined
    const id = setInterval(() => {
      if (loadingRef.current) return // a load is in flight: skip this tick
      refreshRef.current()
    }, intervalMs)
    return () => clearInterval(id)
  }, [intervalMs, paused, active])
}
