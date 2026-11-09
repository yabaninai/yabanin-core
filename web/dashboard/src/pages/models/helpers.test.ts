// validation (the save-blocker acceptance), pricing matching (unknown ≠ $0)
// D-1 display-state matrix pins: verified needs a registry row plus a PASSED
// check, absence of evidence is never success, and an unknown model reads
// unavailable + manual-register hint — never working.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  chainTargetStatus,
  chainTargetsOf,
  joinNameList,
  modelDisplayState,
  parseModelStats,
  parseNameList,
  pickPricing,
  stateBadgeColor,
  stateBadgeGlyph,
  stateBadgeShell,
  validateChainTargets,
  validateTierPool,
} from './helpers.ts'

test('parseNameList splits on commas and newlines, trims and dedupes', () => {
  assert.deepEqual(parseNameList('a, b,,\nc ,b'), ['a', 'b', 'c'])
  assert.deepEqual(parseNameList('  '), [])
  assert.deepEqual(parseNameList('single'), ['single'])
  assert.equal(joinNameList(['a', 'b']), 'a, b')
})

test('chainTargetStatus distinguishes ok, disabled and unknown', () => {
  const known = new Map([['glm', true], ['qwen', false]])
  assert.equal(chainTargetStatus('glm', known), 'ok')
  assert.equal(chainTargetStatus('qwen', known), 'disabled')
  assert.equal(chainTargetStatus('nope', known), 'unknown')
})

// operator's switch marks state (D-2), probe results are evidence, and no
// branch without a PASSED check can read verified.
test('modelDisplayState: a registered enabled model is verified only with a passed test', () => {
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: true, testOk: true }),
    { state: 'verified' },
  )
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: true }),
    { state: 'configured' },
    'no test evidence → configured, never verified',
  )
})

test('modelDisplayState: the operator switch makes a row unavailable (D-2 marking)', () => {
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: false, testOk: true }),
    { state: 'unavailable', reason: 'operator_disabled' },
    'a disabled row is unavailable even with a passed test',
  )
})

test('modelDisplayState: a failed test and a snapshot absence are honest unavailable reasons', () => {
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: true, testOk: false }),
    { state: 'unavailable', reason: 'check_failed' },
  )
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: true, discovered: false }),
    { state: 'unavailable', reason: 'absent_from_snapshot' },
  )
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: true, discovered: false, testOk: true }),
    { state: 'unavailable', reason: 'absent_from_snapshot' },
    'absence from the provider list beats a passed test — never looks working',
  )
  assert.deepEqual(
    modelDisplayState({ registered: true, enabled: true, discovered: true, testOk: true }),
    { state: 'verified' },
    'present in the snapshot plus a passed test → verified',
  )
})

test('modelDisplayState: unknown/absent models read unavailable or discovered, never working (D-6)', () => {
  assert.deepEqual(
    modelDisplayState({ registered: false, enabled: false }),
    { state: 'unavailable', reason: 'not_registered' },
  )
  assert.deepEqual(
    modelDisplayState({ registered: false, enabled: false, discovered: false }),
    { state: 'unavailable', reason: 'not_registered' },
    'a snapshot that lacked the id is still not registered — same hint',
  )
  assert.deepEqual(
    modelDisplayState({ registered: false, enabled: false, discovered: true }),
    { state: 'discovered' },
    'seen in the snapshot but not configured → discovered + register hint',
  )
})

test('state badge shells keep the astra token vocabulary per state', () => {
  assert.equal(stateBadgeColor('verified'), 'var(--astra-success)')
  assert.equal(stateBadgeColor('unavailable'), 'var(--astra-danger)')
  assert.equal(stateBadgeGlyph('discovered'), '△')
  assert.match(stateBadgeShell, /var\(--astra-radius-control\)/)
})

test('validateChainTargets blocks unknown and disabled targets (save blocker)', () => {
  const known = new Map([['glm', true], ['qwen', false]])
  assert.deepEqual(validateChainTargets(['glm'], known), { ok: true, unknown: [], disabled: [] })
  const bad = validateChainTargets(['glm', 'ghost', 'qwen'], known)
  assert.equal(bad.ok, false)
  assert.deepEqual(bad.unknown, ['ghost'])
  assert.deepEqual(bad.disabled, ['qwen'])
  assert.deepEqual(validateChainTargets([], known), { ok: true, unknown: [], disabled: [] })
})

test('validateTierPool checks the tier vocabulary, not model names', () => {
  const tiers = ['easy', 'medium', 'hard', 'premium']
  assert.deepEqual(validateTierPool(['medium', 'easy'], tiers), { ok: true, unknown: [] })
  const bad = validateTierPool(['medium', 'platinum', 'platinum'], tiers)
  assert.equal(bad.ok, false)
  assert.deepEqual(bad.unknown, ['platinum'])
  assert.deepEqual(validateTierPool([], tiers), { ok: true, unknown: [] })
})

test('chainTargetsOf concatenates fallback and failover without dupes', () => {
  assert.deepEqual(
    chainTargetsOf({ fallback_model: ' b ', failover_models: ['b', 'a', ''] }),
    ['b', 'a'],
  )
  assert.deepEqual(chainTargetsOf({}), [])
})

test('pickPricing needs provider+model and prefers the latest effective_from', () => {
  const rows = [
    { provider: 'zai', model: 'glm', input_per_m: 1, output_per_m: 2, effective_from: '2026-01-01' },
    { provider: 'zai', model: 'glm', input_per_m: 3, output_per_m: 4, effective_from: '2026-02-01' },
  ]
  assert.equal(pickPricing(rows, undefined, 'glm'), null, 'no provider on the row → no match')
  assert.equal(pickPricing(rows, 'zai', 'other'), null)
  assert.equal(pickPricing(rows, 'zai', 'glm')?.input_per_m, 3, 'latest effective_from wins')
  assert.equal(pickPricing(null, 'zai', 'glm'), null)
  assert.equal(pickPricing([{ provider: 'zai', model: 'g', input_per_m: 0, output_per_m: 0 }], 'zai', 'g')?.input_per_m, 0, 'a real zero is a match')
})

test('parseModelStats pivots a model-grouped result; unusable shapes → null', () => {
  const ok = {
    columns: [
      { name: 'model', type: 'string' },
      { name: 'requests', type: 'number' },
      { name: 'errors', type: 'number' },
      { name: 'latency_p95', type: 'number' },
    ],
    rows: [
      ['glm', 10, 1, 1200],
      ['qwen', 0, 0, null],
      [null, 5, 0, 10], // a nameless row is skipped, not attributed
    ],
  }
  const stats = parseModelStats(ok)
  assert.ok(stats)
  assert.deepEqual(stats.get('glm'), { requests: 10, errors: 1, p95_ms: 1200 })
  assert.deepEqual(stats.get('qwen'), { requests: 0, errors: 0, p95_ms: null })

  assert.equal(parseModelStats(null), null)
  assert.equal(parseModelStats({ ...ok, truncated: true }), null, 'truncated top → hide, not partial')
  assert.equal(
    parseModelStats({
      columns: [{ name: 'model', type: 'string' }, { name: 'requests', type: 'number' }],
      rows: [['glm', 1]],
    }),
    null,
    'missing metric columns → hide',
  )
})
