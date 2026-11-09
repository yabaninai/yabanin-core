import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  CACHE_MODES,
  RESIDENCY_REGIONS,
  ROUTING_MODES,
  isCacheMode,
  isResidencyRegion,
  isRoutingMode,
  isRoutingThreshold,
  pricingPatch,
  type PricingEntryLike,
} from './orgSettings.ts'

test('allowlists mirror the server validation', () => {
  assert.deepEqual([...CACHE_MODES], ['off', 'exact', 'semantic'])
  assert.deepEqual([...ROUTING_MODES], ['auto', 'aggressive_cost', 'always_premium', 'always_cheap', 'classifier_only'])
  assert.deepEqual([...RESIDENCY_REGIONS], ['SG', 'IN', 'ID'])
  assert.equal(isCacheMode('semantic'), true)
  assert.equal(isCacheMode('SEMANTIC'), false) // server lowercases; the UI sends lowercase only
  assert.equal(isRoutingMode('aggressive_cost'), true)
  assert.equal(isRoutingMode('turbo'), false)
  assert.equal(isResidencyRegion('SG'), true)
  assert.equal(isResidencyRegion('sg'), false) // residency is uppercase (policy packs store 'SG')
  assert.equal(isResidencyRegion(''), false) // clearing is a separate call path, not a region value
})

test('routing threshold accepts only finite values in [0, 1]', () => {
  assert.equal(isRoutingThreshold(0), true)
  assert.equal(isRoutingThreshold(1), true)
  assert.equal(isRoutingThreshold(0.6), true)
  assert.equal(isRoutingThreshold(-0.1), false)
  assert.equal(isRoutingThreshold(1.1), false)
  assert.equal(isRoutingThreshold(Number.NaN), false)
  assert.equal(isRoutingThreshold(Number.POSITIVE_INFINITY), false)
})

const CURRENT: PricingEntryLike = { input_per_m: 1, output_per_m: 2, cache_write_per_m: 0, cache_read_per_m: 0.1 }

test('pricingPatch sends only changed numeric fields', () => {
  const result = pricingPatch(
    { input_per_m: ' 1.5 ', output_per_m: '2', cache_write_per_m: '', cache_read_per_m: '0.1' },
    CURRENT,
  )
  assert.deepEqual(result, { ok: true, patch: { input_per_m: 1.5 } })
})

test('pricingPatch with nothing changed yields an empty patch (no PUT needed)', () => {
  const result = pricingPatch(
    { input_per_m: '1', output_per_m: '2', cache_write_per_m: '0', cache_read_per_m: '0.1' },
    CURRENT,
  )
  assert.deepEqual(result, { ok: true, patch: {} })
})

test('pricingPatch rejects negative, non-numeric and non-finite input', () => {
  assert.equal(pricingPatch({ ...emptyDraft(), input_per_m: '-1' }, CURRENT).ok, false)
  assert.equal(pricingPatch({ ...emptyDraft(), input_per_m: 'abc' }, CURRENT).ok, false)
  assert.equal(pricingPatch({ ...emptyDraft(), output_per_m: 'Infinity' }, CURRENT).ok, false)
  assert.equal(pricingPatch({ ...emptyDraft(), cache_read_per_m: 'NaN' }, CURRENT).ok, false)
})

function emptyDraft() {
  return { input_per_m: '', output_per_m: '', cache_write_per_m: '', cache_read_per_m: '' }
}
