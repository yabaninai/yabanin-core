import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  GLOBAL_PRESETS, PRESET_DAYS, applyOrgFallback, parseMemoryScope, scopeKey, windowDays, writeGlobalScope,
} from './globalScope.ts'
import { presetRange, type PeriodPreset } from './analyticsQuery.ts'

describe('global scope (AUX-08)', () => {
  it('unified presets are the single period vocabulary with day counts', () => {
    assert.deepEqual(GLOBAL_PRESETS, ['24h', '7d', '30d', '90d'])
    assert.deepEqual(PRESET_DAYS, { '24h': 1, '7d': 7, '30d': 30, '90d': 90 })
    for (const p of GLOBAL_PRESETS) assert.equal(windowDays(p, '', ''), PRESET_DAYS[p])
  })

  it('a custom window folds to whole days clamped to the preset limit', () => {
    assert.equal(windowDays('custom', '2026-09-01T00:00:00Z', '2026-10-01T00:00:00Z'), 30)
    assert.equal(windowDays('custom', '2026-09-01T00:00:00Z', '2026-09-01T12:00:00Z'), 1)
    assert.equal(windowDays('custom', '2025-01-01T00:00:00Z', '2026-09-01T00:00:00Z'), 90)
    // A broken/empty window never divides the API by zero or nonsense.
    assert.equal(windowDays('custom', '', ''), PRESET_DAYS['7d'])
  })

  it('memory parsing keeps only preset/tz strings and survives garbage', () => {
    assert.deepEqual(parseMemoryScope(null), {})
    assert.deepEqual(parseMemoryScope(''), {})
    assert.deepEqual(parseMemoryScope('not json'), {})
    assert.deepEqual(parseMemoryScope('{"preset":"30d","tz":"UTC"}'), { preset: '30d', tz: 'UTC' })
    assert.deepEqual(parseMemoryScope('{"preset":42,"tz":[]}'), {})
  })

  it('scope identity ignores preset-resolved windows but pins custom borders', () => {
    const preset = (period: PeriodPreset) => {
      const r = presetRange(period === 'custom' ? '7d' : period, new Date('2026-09-30T00:00:00Z'))
      return { org: 'o', period, from: r.from, to: r.to, tz: '' }
    }
    // The same preset at different anchor times is one scope (no refetch loop).
    const a = preset('7d')
    const b = { ...a, from: '2026-09-01T00:00:00Z', to: '2026-09-08T00:00:00Z' }
    assert.equal(scopeKey(a), scopeKey(b))
    // A custom range is part of the identity.
    const custom = { ...a, period: 'custom' as const, from: '2026-09-01T00:00:00Z', to: '2026-09-08T00:00:00Z' }
    assert.notEqual(scopeKey(a), scopeKey(custom))
    assert.notEqual(scopeKey({ ...custom, tz: 'UTC' }), scopeKey(custom))
  })
})

describe('automatic org fallback during navigation', () => {
  it('checks live URL and current store atomically without restricting manual writes', () => {
    const writes: string[] = []
    const remembered = new Map<string, string>([['yabanin.orgScope.v1', 'remembered-a']])
    const storageWrites: string[] = []
    // The module store is still empty: no hashchange has adopted this newly
    // arrived URL. A previously scheduled picker is about to suggest A.
    // @ts-expect-error — minimal browser stub for the synchronous store action.
    globalThis.window = {
      location: { pathname: '/', search: '', hash: '#lineage?org=org-b' },
      history: { replaceState: (_a: unknown, _b: unknown, url: string) => writes.push(url) },
    }
    // @ts-expect-error — only the guarded storage operations are needed.
    globalThis.localStorage = {
      getItem: (key: string) => remembered.get(key) ?? null,
      setItem: (key: string, value: string) => { remembered.set(key, value); storageWrites.push(key) },
      removeItem: (key: string) => { remembered.delete(key); storageWrites.push(key) },
    }
    try {
      assert.equal(applyOrgFallback('org-a'), false, 'explicit new org wins before hashchange')
      globalThis.window.location.hash = '#lineage?org='
      assert.equal(applyOrgFallback('org-a'), false, 'explicit empty scope also wins')
      assert.deepEqual(writes, [])
      assert.deepEqual(storageWrites, [], 'rejected fallback must not mutate remembered scope')
      assert.equal(remembered.get('yabanin.orgScope.v1'), 'remembered-a')

      globalThis.window.location.hash = '#requests-explorer'
      assert.equal(applyOrgFallback(''), false)
      assert.equal(applyOrgFallback('org-b'), true, 'bare empty scope still accepts the fallback')
      assert.match(writes[0]!, /#requests-explorer\?org=org-b&period=7d$/)
      assert.equal(remembered.get('yabanin.orgScope.v1'), 'org-b')
      const count = writes.length
      assert.equal(applyOrgFallback('org-a'), false, 'current store wins even before URL notification')
      assert.equal(writes.length, count)
      assert.equal(remembered.get('yabanin.orgScope.v1'), 'org-b')

      globalThis.window.location.hash = '#requests-explorer?org=org-b'
      writeGlobalScope({ org: 'org-a', period: '7d', from: '', to: '', tz: '' })
      assert.match(writes.at(-1)!, /org=org-a/, 'explicit manual writes stay unconditional')
      assert.equal(remembered.get('yabanin.orgScope.v1'), 'org-a')
    } finally {
      // @ts-expect-error — test stub cleanup.
      delete globalThis.window
      // @ts-expect-error — test stub cleanup.
      delete globalThis.localStorage
    }
  })
})

describe('writeGlobalScope URL sync (IMP-31)', () => {
  it('the fragment keeps a single leading # across repeated commits', () => {
    const calls: string[] = []
    // @ts-expect-error — a minimal browser stub is enough for the contract.
    globalThis.window = {
      location: { pathname: '/', search: '', hash: '#analytics?org=a&period=7d' },
      history: { replaceState: (_a: unknown, _b: unknown, url: string) => calls.push(url) },
    }
    try {
      // @ts-expect-error — localStorage may be absent in node; the store
      // guards memory writes, so undefined is fine.
      globalThis.localStorage = undefined
      writeGlobalScope({ org: 'org-b', period: '30d', from: '', to: '', tz: '' })
      assert.equal(calls.length, 1)
      assert.match(calls[0]!, /^\/#analytics\?org=org-b&period=30d$/)
      // A damaged multi-# fragment (older commits) heals on the next write.
      globalThis.window = {
        location: { pathname: '/', search: '', hash: '###analytics?org=a' },
        history: { replaceState: (_a: unknown, _b: unknown, url: string) => calls.push(url) },
      }
      writeGlobalScope({ org: '', period: '7d', from: '', to: '', tz: '' })
      assert.match(calls[1]!, /^\/#analytics\?period=7d$/)
      assert.equal(calls[1]!.includes('##'), false, 'never grows the # run')
    } finally {
      // @ts-expect-error — test stub cleanup.
      delete globalThis.window
      // @ts-expect-error — test stub cleanup.
      delete globalThis.localStorage
    }
  })
})
