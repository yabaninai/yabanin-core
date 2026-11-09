// failure half of the contract examples, at the render-decision level the
// finding 2): a transient registry load and a true outage must never share
// failure copy. Also pinned here: a malformed discovery payload never
// renders as a parsed snapshot, the 1/min/org probe-budget throttle (429)
// renders as the honest error it is, and no failure ever invents a taxonomy
// reason (the 5-reason catalog taxonomy stays server-delegated).
//
// The matrix/hints unit pins live in providerKeysHelpers.test.ts and
// models/helpers.test.ts; the regression anchors (broken-vs-fixed) live in
// providerKeysRegression.test.ts. Nothing here duplicates those.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  catalogStateFromError, catalogStateFromResult, crossCheckCatalog,
  registryLoadState, testStateFromError, testStateFromResult, withCheckedAt,
} from './providerKeysHelpers.ts'
import type { ProviderModelCatalog } from '../../api/providerCredentials.ts'
import { ApiError } from '../../api/transport.ts'

// ---------------------------------------------------------------------------
// Review finding 2: transient registry load ≠ true outage.
// ---------------------------------------------------------------------------

test('registryLoadState: the first in-flight load is transient loading, not an outage', () => {
  assert.deepEqual(
    registryLoadState({ hasData: false, loading: true, error: '' }),
    { kind: 'loading' },
    'load in flight, no data yet → transient',
  )
  assert.deepEqual(
    registryLoadState({ hasData: false, loading: false, error: '' }),
    { kind: 'loading' },
    'not loaded yet (or not enabled) → still transient, never failure copy',
  )
})

test('registryLoadState: an error without data is the true outage', () => {
  assert.deepEqual(
    registryLoadState({ hasData: false, loading: false, error: 'API error 503: registry unavailable' }),
    { kind: 'outage' },
  )
})

test('registryLoadState: present data is ready — a refresh (even a failing one) never blanks it', () => {
  assert.deepEqual(
    registryLoadState({ hasData: true, loading: true, error: '' }),
    { kind: 'ready' },
    'refresh in flight over shown data',
  )
  // AUX-23: a failed refresh keeps the last good slice (refreshStale) — the
  // hook surfaces it with error '' and data kept, which stays ready.
  assert.deepEqual(
    registryLoadState({ hasData: true, loading: false, error: '' }),
    { kind: 'ready' },
  )
  // Defensive precedence: data beats a stale error string if one ever
  // coexisted — the hook never produces that shape.
  assert.deepEqual(
    registryLoadState({ hasData: true, loading: false, error: 'stale' }),
    { kind: 'ready' },
  )
})

test('registryLoadState: recovery — the same derivation that suspended states clears them', () => {
  const outage = registryLoadState({ hasData: false, loading: false, error: 'boom' })
  assert.equal(outage.kind, 'outage')
  // The retry (query.load({refresh:true})) succeeds → the next render sees data.
  assert.deepEqual(
    registryLoadState({ hasData: true, loading: false, error: '' }),
    { kind: 'ready' },
    'outage → ready without any code change: the retry is the recovery path',
  )
})

// ---------------------------------------------------------------------------
// Malformed discovery payloads: garbage never renders as a parsed snapshot.
// ---------------------------------------------------------------------------

const malformed: Array<{ name: string, data: unknown }> = [
  { name: 'data is a string', data: 'glm,qwen' },
  { name: 'data is an object', data: { 0: 'glm' } },
  { name: 'data is a number', data: 42 },
  { name: 'data has a non-string entry', data: [1, 'glm'] },
  { name: 'data has an empty id', data: ['glm', ''] },
  { name: 'data has a whitespace-only id', data: ['   '] },
]

test('a malformed discovery payload renders an honest diagnosable fail — never a snapshot', () => {
  for (const { name, data } of malformed) {
    const wire = {
      provider: 'openai-compat', count: 2, discovered: true, data,
    } as unknown as ProviderModelCatalog
    const state = catalogStateFromResult(wire)
    assert.equal(state.phase, 'fail', name)
    assert.equal(state.reason, undefined, `${name}: no taxonomy reason may be invented client-side`)
    assert.ok(state.error !== undefined && state.error.length > 0, `${name}: the fail carries a diagnosable error`)
    assert.equal(state.models, undefined, `${name}: the garbage ids never leak into the state`)
    assert.equal(state.count, undefined, `${name}: the claimed count never rides on a malformed fail`)
  }
})

test('a truthy-but-not-true discovered flag is not a parsed snapshot', () => {
  const wire = { provider: 'openai-compat', count: 1, data: ['glm'], discovered: 1 } as unknown as ProviderModelCatalog
  assert.equal(catalogStateFromResult(wire).phase, 'fail')
})

test('the ok boundary survives the hardening: an empty catalog is still a real snapshot', () => {
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai-compat', count: 0, discovered: true, verified: false }),
    { phase: 'ok', models: [], count: 0 },
    'data omitted, count 0 → the honest empty snapshot (not malformed)',
  )
})

test('crossCheckCatalog: a malformed snapshot (past the parse gate) claims nothing and crashes nothing', () => {
  const registry = new Map([['glm', true]])
  const check = crossCheckCatalog({
    snapshot: 'glm,qwen' as unknown as readonly string[],
    testOk: true,
    registry,
  })
  assert.deepEqual(check.snapshotRows, [], 'garbage input lists no rows')
  assert.deepEqual(check.absentRows, [], 'garbage input makes no absence claims')
})

// ---------------------------------------------------------------------------
// Probe-budget throttle (1/min/org): the 429 renders as the honest error it
// is — never ok, never a taxonomy reason, always carryable into the
// "checked at" badge (the run did happen; it was throttled).
// ---------------------------------------------------------------------------

// The exact client-side error the transport derives from the server's wire
// 429 {error: "credential test rate limit exceeded (1 per minute per
// organization)"} (services/admin/handlers/org_credentials.go).
function throttleError(): ApiError {
  return new ApiError(
    429,
    'API error 429: credential test rate limit exceeded (1 per minute per organization)',
    'credential test rate limit exceeded (1 per minute per organization)',
  )
}

test('a throttled connection test renders the honest 429 error, never success', () => {
  const state = testStateFromError(throttleError())
  assert.equal(state.phase, 'fail')
  assert.equal(
    state.error,
    'API error 429: credential test rate limit exceeded (1 per minute per organization)',
    'the server throttle message is preserved verbatim',
  )
  assert.equal(state.status, undefined, 'a thrown 429 carries no fake upstream status')
})

test('a throttled discovery renders fail with no invented taxonomy reason', () => {
  const state = catalogStateFromError(throttleError())
  assert.deepEqual(state, {
    phase: 'fail',
    error: 'API error 429: credential test rate limit exceeded (1 per minute per organization)',
  })
  assert.equal(state.reason, undefined, '429 is not one of the five catalog reasons')
})

test('a throttle surfaced in the contract test body ({ok:false, status:429}) stays a fail', () => {
  assert.deepEqual(
    testStateFromResult({ ok: false, status: 429, error: 'credential test rate limit exceeded (1 per minute per organization)' }),
    { phase: 'fail', status: 429, error: 'credential test rate limit exceeded (1 per minute per organization)' },
  )
})

test('the checked-at badge stamps a throttled run without changing its verdict', () => {
  const at = '2026-10-14T10:00:00.000Z'
  assert.deepEqual(
    withCheckedAt(testStateFromError(throttleError()), at),
    { phase: 'fail', error: 'API error 429: credential test rate limit exceeded (1 per minute per organization)', checkedAt: at },
  )
  assert.deepEqual(
    withCheckedAt(catalogStateFromError(throttleError()), at),
    { phase: 'fail', error: 'API error 429: credential test rate limit exceeded (1 per minute per organization)', checkedAt: at },
  )
})

// ---------------------------------------------------------------------------
// Transient vs outage copy: both suspend states, but only the outage copy is
// failure copy — every locale must carry both, distinct, non-empty.
// ---------------------------------------------------------------------------

test('every locale distinguishes the loading suspension from the outage failure copy', () => {
  const i18nDir = fileURLToPath(new URL('../../i18n/', import.meta.url))
  const locales = readdirSync(i18nDir).filter((f) => f.endsWith('.json'))
  assert.ok(locales.length >= 8, `expected the full locale set, found ${locales.join(', ')}`)
  for (const locale of locales) {
    const messages = JSON.parse(readFileSync(`${i18nDir}${locale}`, 'utf8')) as {
      providerKeys?: Record<string, unknown>
    }
    const keys = messages.providerKeys ?? {}
    for (const key of ['registryLoading', 'registryOutage', 'stateSuspended', 'stateSuspendedLoading']) {
      const value = keys[key]
      assert.equal(typeof value, 'string', `${locale}: providerKeys.${key} must exist`)
      assert.ok((value as string).length > 0, `${locale}: providerKeys.${key} must be non-empty`)
    }
    // The transient note must not reuse the outage sentence: the two states
    // are different facts about the registry and must read differently.
    assert.notEqual(
      keys.registryLoading, keys.registryOutage,
      `${locale}: loading note must differ from the outage failure copy`,
    )
    assert.notEqual(
      keys.stateSuspendedLoading, keys.stateSuspended,
      `${locale}: the loading suspended label must differ from the outage label`,
    )
  }
})
