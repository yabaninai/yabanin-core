// AUX-08 — GlobalScope: the org · period · timezone triple shared by every
// data screen (plan «Навигация и GlobalScope», page anatomy "GlobalScope").
//
// Contract (UI-contract #1 extended to the whole scope):
//   * The scope lives in the HASH query (?org=…&period=30d&tz=…, plus
//     ?from=&to= for a custom range), so it survives navigation (App.goto
//     preserves the hash query), reloads and is a shareable deep link.
//   * Deep links win: an explicit param in the arriving URL always beats the
//     remembered scope. Memory (localStorage) is only the fallback for links
//     that carry no explicit value — same priority rule as lib/orgScope.ts.
//   * One period vocabulary everywhere: the unified presets below are the
//     only period options the scoped screens offer. A hand-edited from/to
//     range is the "custom" period and is pinned exactly in the hash.
//
// The store is a module singleton: one browser tab holds one scope; React
// bindings subscribe via useSyncExternalStore, so every mounted consumer
// re-renders on a change without a context provider.

import { useSyncExternalStore } from 'react'
import { isPeriodPreset, PERIOD_PRESETS, presetRange, type PeriodPreset } from './analyticsQuery.ts'
import { readLastOrg, rememberOrg } from './orgScope.ts'

/** The unified period presets (plan «Единые пресеты периода»). */
export const GLOBAL_PRESETS = PERIOD_PRESETS

const DEFAULT_PRESET: Exclude<PeriodPreset, 'custom'> = '7d'

/** Whole-day counts for day-granular APIs (GET /api/analytics/savings?days=N). */
export const PRESET_DAYS: Record<Exclude<PeriodPreset, 'custom'>, number> = {
  '24h': 1,
  '7d': 7,
  '30d': 30,
  '90d': 90,
}

export interface GlobalScopeState {
  org: string
  /** Unified preset, or 'custom' when the range was pinned by hand/deep link. */
  period: PeriodPreset
  /** Concrete ISO window (resolved from the preset at read/write time). */
  from: string
  to: string
  tz: string
}

// --- persistence -----------------------------------------------------------

const MEMORY_KEY = 'yabanin.globalScope.v1'

/** Remembered preset/tz (never the org — that stays in lib/orgScope.ts). */
interface MemoryScope { preset?: string; tz?: string }

export function parseMemoryScope(raw: string | null): MemoryScope {
  if (!raw) return {}
  try {
    const v = JSON.parse(raw) as MemoryScope
    const out: MemoryScope = {}
    if (typeof v.preset === 'string') out.preset = v.preset
    if (typeof v.tz === 'string') out.tz = v.tz
    return out
  } catch {
    return {}
  }
}

function readMemory(): MemoryScope {
  try {
    return parseMemoryScope(localStorage.getItem(MEMORY_KEY))
  } catch {
    return {}
  }
}

function writeMemory(scope: GlobalScopeState, previous: MemoryScope): void {
  try {
    // A custom range must not overwrite the last explicit preset: the
    // fallback for a bare link stays the operator's chosen preset.
    const preset = scope.period === 'custom' ? previous.preset : scope.period
    localStorage.setItem(MEMORY_KEY, JSON.stringify({ preset, tz: scope.tz }))
  } catch {
    // Private mode / tests — continuity is best-effort.
  }
}

function isPreset(v: string | undefined | null): v is Exclude<PeriodPreset, 'custom'> {
  return isPeriodPreset(v)
}

/** Hash-query reader shared with the store init and the hashchange adopter. */
function readHashQuery(): URLSearchParams {
  if (typeof window === 'undefined') return new URLSearchParams()
  return new URLSearchParams(window.location.hash.split('?')[1] ?? '')
}

/**
 * Scope for the CURRENT location: explicit hash params first (deep-link
 * priority), remembered preset/tz next, defaults last. `from`/`to` are always
 * concrete: a preset resolves to its window anchored at `now`.
 */
export function readGlobalScope(now = new Date()): GlobalScopeState {
  const q = readHashQuery()
  const mem = readMemory()
  const hashFrom = q.get('from') ?? ''
  const hashTo = q.get('to') ?? ''
  const hashPeriod = q.get('period') ?? ''
  let period: PeriodPreset
  if (hashFrom && hashTo) {
    period = 'custom'
  } else if (isPreset(hashPeriod)) {
    period = hashPeriod
  } else if (isPreset(mem.preset)) {
    period = mem.preset
  } else {
    period = DEFAULT_PRESET
  }
  const range = period === 'custom'
    ? { from: hashFrom, to: hashTo }
    : presetRange(period, now)
  return {
    org: q.get('org') ?? readLastOrg(),
    period,
    from: range.from,
    to: range.to,
    tz: q.get('tz') ?? mem.tz ?? '',
  }
}

/** Stable identity for change detection (preset windows drift with `now`). */
export function scopeKey(s: GlobalScopeState): string {
  const from = s.period === 'custom' ? s.from : ''
  const to = s.period === 'custom' ? s.to : ''
  return `${s.org}\u0000${s.period}\u0000${from}\u0000${to}\u0000${s.tz}`
}

/**
 * Mirror the scope into the hash query (preserving every page-specific param)
 * and the memory fallbacks. replaceState: scope changes do not spam history.
 * The path segment is normalized to a SINGLE '#' — location.hash already
 * carries one, and unlike `location.hash =` assignments replaceState does
 * not normalize, so each scope commit would otherwise grow the fragment
 * («#analytics» → «##analytics» → …) and a reload then resolves the page id
 * to the bare overview.
 */
export function writeGlobalScope(scope: GlobalScopeState): void {
  if (typeof window === 'undefined') return
  try {
    const hash = window.location.hash
    const path = hash.split('?')[0].replace(/^#+/, '')
    const q = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '')
    if (scope.org) q.set('org', scope.org); else q.delete('org')
    if (scope.period === 'custom') {
      q.set('from', scope.from)
      q.set('to', scope.to)
      q.delete('period')
    } else {
      q.set('period', scope.period)
      q.delete('from')
      q.delete('to')
    }
    if (scope.tz) q.set('tz', scope.tz); else q.delete('tz')
    const qs = q.toString()
    window.history.replaceState(
      null, '',
      `${window.location.pathname}${window.location.search}#${path}${qs ? `?${qs}` : ''}`,
    )
  } catch {
    // Non-browser environment — URL sync is best-effort.
  }
  rememberOrg(scope.org.trim())
  writeMemory(scope, readMemory())
}

// --- store -----------------------------------------------------------------

let state: GlobalScopeState = readGlobalScope()
const listeners = new Set<() => void>()
let hashListenerBound = false

function emit(): void {
  for (const l of listeners) l()
}

function setState(next: GlobalScopeState): void {
  state = next
  snapshot = makeSnapshot(next)
  emit()
}

// Back/forward (and same-document hash navigations) re-adopt the scope from
// the URL — the hash stays the single source of truth for deep links. The
// store's own writes use replaceState, which fires no hashchange, so this
// cannot loop.
function bindHashListener(): void {
  if (hashListenerBound || typeof window === 'undefined') return
  hashListenerBound = true
  window.addEventListener('hashchange', () => {
    const next = readGlobalScope()
    if (scopeKey(next) !== scopeKey(state)) setState(next)
  })
}

function subscribe(listener: () => void): () => void {
  bindHashListener()
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export interface GlobalScopeApi extends GlobalScopeState {
  setOrg: (org: string) => void
  setPeriod: (period: Exclude<PeriodPreset, 'custom'>, now?: Date) => void
  /** Pin an exact window (hand-edited borders, saved views, drill-downs). */
  setRange: (from: string, to: string) => void
  setTz: (tz: string) => void
}

function commit(patch: Partial<GlobalScopeState>): void {
  const next: GlobalScopeState = {
    ...state,
    ...patch,
    period: patch.period ?? state.period,
  }
  if (next.period !== 'custom') {
    const range = presetRange(next.period, new Date())
    next.from = range.from
    next.to = range.to
  }
  writeGlobalScope(next)
  setState(next)
}

/** A directory response can finish after navigation changed the URL but
 *  before hashchange adoption/unmount. Only fill a still-unclaimed scope;
 *  current state and explicit URL intent (including ?org=) both take priority.
 *  This guard is deliberately separate from unconditional user selection. */
export function applyOrgFallback(org: string): boolean {
  if (!org || state.org || readHashQuery().has('org')) return false
  commit({ org })
  return true
}

// useSyncExternalStore re-runs getSnapshot after every emit and compares with
// Object.is — the snapshot must be a NEW object per state version (getters on
// a stable singleton would never re-render).
function makeSnapshot(s: GlobalScopeState): GlobalScopeApi {
  return {
    org: s.org,
    period: s.period,
    from: s.from,
    to: s.to,
    tz: s.tz,
    setOrg: org => commit({ org }),
    setPeriod: period => commit({ period }),
    setRange: (from, to) => commit({ period: 'custom', from, to }),
    setTz: tz => commit({ tz }),
  }
}

let snapshot: GlobalScopeApi = makeSnapshot(state)

function getSnapshot(): GlobalScopeApi {
  return snapshot
}

/** React binding: the shared scope with setters that persist to hash+memory. */
export function useGlobalScope(): GlobalScopeApi {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
}

/** Day count of a window for day-granular APIs (savings `days`); a custom
 *  range folds to whole days clamped to the preset span limit. */
export function windowDays(period: PeriodPreset, from: string, to: string): number {
  if (period === 'custom') {
    const span = Date.parse(to) - Date.parse(from)
    if (!Number.isFinite(span) || span <= 0) return PRESET_DAYS[DEFAULT_PRESET]
    return Math.min(90, Math.max(1, Math.round(span / 86_400_000)))
  }
  return PRESET_DAYS[period]
}
