// W-BYOK (card W-BYOK-UI) unit tests for the Provider keys section helpers:
// the mask, the create-body validation and the PUT diff (changed fields only,
// an empty key never overwrites), plus the test-result shaping.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  PROVIDER_OPTIONS, buildCreateInput, buildUpdatePatch, catalogStateFromError,
  catalogStateFromResult, crossCheckCatalog, editDraftOf, emptyDraft, maskKeyLast4,
  testStateFromError, testStateFromResult, withCheckedAt,
} from './providerKeysHelpers.ts'
import type { CatalogReason } from './providerKeysHelpers.ts'

test('maskKeyLast4 renders •••• + the last four and never invents a fragment', () => {
  assert.equal(maskKeyLast4('1234'), '••••1234')
  assert.equal(maskKeyLast4(''), '')
  assert.equal(maskKeyLast4(undefined), '')
  assert.equal(maskKeyLast4(null), '')
})

test('PROVIDER_OPTIONS mirrors the server adapter registry', () => {
  for (const p of ['openai', 'openai-compat', 'anthropic', 'zai-coding', 'vllm', 'ollama']) {
    assert.ok(PROVIDER_OPTIONS.includes(p), `missing adapter ${p}`)
  }
  assert.equal(new Set(PROVIDER_OPTIONS).size, PROVIDER_OPTIONS.length, 'options must be unique')
})

test('buildCreateInput validates every contract field and reports the missing ones', () => {
  const base = { name: 'prod', provider: 'openai', baseUrl: 'https://api.example.com/v1', key: 'sk-1' }
  const ok = buildCreateInput(base)
  assert.ok(ok.ok)
  if (ok.ok) {
    assert.deepEqual(ok.input, {
      name: 'prod', provider: 'openai', base_url: 'https://api.example.com/v1', key: 'sk-1',
    })
  }
  for (const field of ['name', 'provider', 'baseUrl', 'key'] as const) {
    const draft = { ...base, [field]: '   ' }
    const parsed = buildCreateInput(draft)
    assert.equal(parsed.ok, false, `${field} must be required`)
    if (!parsed.ok) assert.deepEqual(parsed.missing, [field], `${field} must be reported missing`)
  }
  const blank = buildCreateInput(emptyDraft())
  assert.equal(blank.ok, false)
  // emptyDraft seeds the provider select with the first option — everything
  // else starts blank.
  if (!blank.ok) assert.deepEqual(blank.missing, ['name', 'baseUrl', 'key'])
})

test('buildUpdatePatch sends only changed fields; an empty key never overwrites', () => {
  const cred = { name: 'prod', base_url: 'https://api.example.com/v1', enabled: true }
  assert.deepEqual(buildUpdatePatch(cred, editDraftOf(cred)), {}, 'no changes → empty patch')

  assert.deepEqual(
    buildUpdatePatch(cred, { ...editDraftOf(cred), name: 'renamed', enabled: false }),
    { name: 'renamed', enabled: false },
  )
  assert.deepEqual(
    buildUpdatePatch(cred, { ...editDraftOf(cred), baseUrl: 'https://other.example.com/v1' }),
    { base_url: 'https://other.example.com/v1' },
  )
  assert.deepEqual(
    buildUpdatePatch(cred, { ...editDraftOf(cred), key: 'sk-rotated' }),
    { key: 'sk-rotated' },
  )
  // Whitespace-only or empty key fields are omitted, never sent as "".
  assert.deepEqual(buildUpdatePatch(cred, { ...editDraftOf(cred), key: '  ' }), {})
})

test('testStateFromResult / testStateFromError shape the contract test outcome', () => {
  assert.deepEqual(testStateFromResult({ ok: true, status: 200 }), { phase: 'ok', status: 200 })
  assert.deepEqual(
    testStateFromResult({ ok: false, status: 401, error: 'invalid key' }),
    { phase: 'fail', status: 401, error: 'invalid key' },
  )
  assert.deepEqual(testStateFromError(new Error('boom')), { phase: 'fail', error: 'boom' })
  assert.deepEqual(testStateFromError('str'), { phase: 'fail', error: 'str' })
})

test('emptyDraft seeds the form with the first provider option', () => {
  const draft = emptyDraft()
  assert.equal(draft.name, '')
  assert.equal(draft.key, '')
  assert.equal(draft.provider, PROVIDER_OPTIONS[0])
})

// (discovered=true); every refusal — including a non-JSON 200 — stays an
// honest fail with the machine reason, never a success.
test('catalogStateFromResult / catalogStateFromError shape the discovery outcome', () => {
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai', count: 2, data: ['a', 'b'], discovered: true, verified: false }),
    { phase: 'ok', models: ['a', 'b'], count: 2 },
  )
  // An empty catalog (data omitted by the server, count 0) is still a snapshot.
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai', count: 0, discovered: true, verified: false }),
    { phase: 'ok', models: [], count: 0 },
  )
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai', count: 0, reason: 'key_unauthorized', status: 401 }),
    { phase: 'fail', reason: 'key_unauthorized', status: 401, error: undefined },
  )
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai', count: 0, reason: 'models_list_unavailable', status: 200 }),
    { phase: 'fail', reason: 'models_list_unavailable', status: 200, error: undefined },
  )
  // An unknown reason is not invented into a known one.
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai', count: 0, reason: 'something_new' }),
    { phase: 'fail', reason: undefined, status: undefined, error: undefined },
  )
  assert.deepEqual(catalogStateFromError(new Error('network down')), { phase: 'fail', error: 'network down' })
})

// boundary matrix: every machine reason keeps its diagnosable shape,
// a refusal never smuggles model ids into the state, and the throw path is
// always an honest fail — no exception shape can read as success.
test('catalogStateFromResult keeps every refusal diagnosable and drops catalog data from fail states', () => {
  // The complete refusal matrix: one entry per server reason, exact shape —
  // deepEqual pins that nothing else (provider, base_url, data) leaks in.
  const refusals: Array<{ result: Parameters<typeof catalogStateFromResult>[0], want: Record<string, unknown> }> = [
    {
      result: { provider: 'openai', count: 0, reason: 'models_list_unavailable', status: 404 },
      want: { phase: 'fail', reason: 'models_list_unavailable', status: 404, error: undefined },
    },
    {
      result: { provider: 'openai', count: 0, reason: 'key_forbidden', status: 403 },
      want: { phase: 'fail', reason: 'key_forbidden', status: 403, error: undefined },
    },
    {
      result: { provider: 'openai', count: 0, reason: 'key_unauthorized', status: 401 },
      want: { phase: 'fail', reason: 'key_unauthorized', status: 401, error: undefined },
    },
    {
      result: { provider: 'openai', count: 0, reason: 'key_unavailable' },
      want: { phase: 'fail', reason: 'key_unavailable', status: undefined, error: undefined },
    },
    {
      result: { provider: 'openai', count: 0, reason: 'transport_error', error: 'dial refused' },
      want: { phase: 'fail', reason: 'transport_error', status: undefined, error: 'dial refused' },
    },
  ]
  for (const { result, want } of refusals) {
    assert.deepEqual(catalogStateFromResult(result), want, `reason ${String(result.reason)}`)
  }

  // A malformed server answer (refusal flag + data present) must not leak
  // the ids into the fail state — display-only means data only on ok.
  assert.deepEqual(
    catalogStateFromResult({
      provider: 'openai', count: 3, discovered: false, reason: 'key_unauthorized', status: 401,
      data: ['ghost-model'],
    }),
    { phase: 'fail', reason: 'key_unauthorized', status: 401, error: undefined },
  )

  // The contract keeps status loose (number | string): a string status
  // passes through without crashing or flipping the phase.
  assert.deepEqual(
    catalogStateFromResult({ provider: 'openai', count: 0, reason: 'transport_error', status: 'timeout' }),
    { phase: 'fail', reason: 'transport_error', status: 'timeout', error: undefined },
  )
})

test('catalogStateFromError turns any throw shape into a fail with a string message', () => {
  assert.deepEqual(catalogStateFromError(new Error('network down')), { phase: 'fail', error: 'network down' })
  assert.deepEqual(catalogStateFromError('plain string'), { phase: 'fail', error: 'plain string' })
  // Non-Error throws degrade to String() — still a fail, never a crash or a
  // success, and never structured data copied into the state.
  assert.deepEqual(catalogStateFromError({ code: 500 }), { phase: 'fail', error: '[object Object]' })
  assert.deepEqual(catalogStateFromError(null), { phase: 'fail', error: 'null' })
  assert.deepEqual(catalogStateFromError(undefined), { phase: 'fail', error: 'undefined' })
  // An Error with an empty message falls back to String(err).
  assert.deepEqual(catalogStateFromError(new Error('')), { phase: 'fail', error: 'Error' })
})

// missing key would render the raw reason string to the operator. Record<>
// over CatalogReason makes this compile-fail when the union grows without a
// hint; the loop makes it runtime-fail when a locale drops one.
const CATALOG_REASON_HINTS: Record<CatalogReason, string> = {
  models_list_unavailable: 'reasonListUnavailable',
  key_forbidden: 'reasonKeyForbidden',
  key_unauthorized: 'reasonKeyUnauthorized',
  key_unavailable: 'reasonKeyUnavailable',
  transport_error: 'reasonTransport',
}

test('every catalog reason and the unknown-reason fallback have hints in all locales', () => {
  const i18nDir = fileURLToPath(new URL('../../i18n/', import.meta.url))
  const locales = readdirSync(i18nDir).filter((f) => f.endsWith('.json'))
  assert.ok(locales.length >= 8, `expected the full locale set, found ${locales.join(', ')}`)
  for (const locale of locales) {
    const messages = JSON.parse(readFileSync(`${i18nDir}${locale}`, 'utf8')) as {
      providerKeys?: Record<string, unknown>
    }
    const keys = messages.providerKeys ?? {}
    for (const [, key] of Object.entries(CATALOG_REASON_HINTS)) {
      const hint = keys[key]
      assert.equal(
        typeof hint, 'string', `${locale}: providerKeys.${key} must exist`,
      )
      assert.ok(
        (hint as string).length > 0, `${locale}: providerKeys.${key} must be non-empty`,
      )
    }
    // The fallback hint for unknown reasons without an error text.
    assert.equal(typeof keys.modelsFail, 'string', `${locale}: providerKeys.modelsFail must exist`)
    assert.ok((keys.modelsFail as string).length > 0, `${locale}: providerKeys.modelsFail must be non-empty`)
  }
})

// evidence — the stamp never touches the verdict fields.
test('withCheckedAt stamps the checked-at badge without changing the verdict', () => {
  const base = testStateFromResult({ ok: true, status: 200 })
  assert.deepEqual(withCheckedAt(base, '2026-10-14T10:00:00.000Z'), {
    phase: 'ok', status: 200, checkedAt: '2026-10-14T10:00:00.000Z',
  })
  const fail = catalogStateFromError(new Error('rate limit'))
  assert.deepEqual(withCheckedAt(fail, '2026-10-14T10:01:00.000Z'), {
    phase: 'fail', error: 'rate limit', checkedAt: '2026-10-14T10:01:00.000Z',
  })
})

// slice in the shared matrix; a registry outage suspends the states (never
// "missing"), and an absent registered model reads unavailable, never
// working.
test('crossCheckCatalog: snapshot ids get their display state from the registry slice', () => {
  const registry = new Map([['glm', true], ['qwen', false], ['gone', true]])
  const check = crossCheckCatalog({
    snapshot: ['glm', 'fresh-model'],
    testOk: true,
    registry,
  })
  assert.deepEqual(
    check.snapshotRows,
    [
      { model: 'glm', state: { state: 'verified' } },
      { model: 'fresh-model', state: { state: 'discovered' } },
    ],
    'registered+enabled+passed → verified; unknown id → discovered (no test credit)',
  )
  assert.deepEqual(
    check.absentRows,
    [
      { model: 'qwen', state: { state: 'unavailable', reason: 'operator_disabled' } },
      { model: 'gone', state: { state: 'unavailable', reason: 'absent_from_snapshot' } },
    ],
    'registered but absent → unavailable; absent rows never read verified',
  )
})

test('crossCheckCatalog: a registry outage suspends every state (contract example 3)', () => {
  const check = crossCheckCatalog({ snapshot: ['glm'], registry: null })
  assert.deepEqual(check.snapshotRows, [{ model: 'glm', state: null }])
  assert.deepEqual(check.absentRows, [], 'no absence claims without the slice')
})

test('crossCheckCatalog: without a snapshot there are no absence claims, only registry states', () => {
  const registry = new Map([['glm', true]])
  const check = crossCheckCatalog({ snapshot: undefined, testOk: true, registry })
  assert.deepEqual(check.snapshotRows, [], 'no snapshot → nothing listed as in-snapshot')
  assert.deepEqual(check.absentRows, [], 'absence needs a parsed snapshot')
  // An empty snapshot (parsed, zero ids) is a real absence claim.
  const empty = crossCheckCatalog({ snapshot: [], registry })
  assert.deepEqual(empty.absentRows, [
    { model: 'glm', state: { state: 'unavailable', reason: 'absent_from_snapshot' } },
  ])
})
