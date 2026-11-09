// contract (pkg/adminstore/savings.go): an unmeasured share (JSON null /
// absent / garbage) and a missing coverage_status must NEVER resolve to the
// ok branch — the screens would render a precise $0.0000 for an unknown
// cost. The fixture shapes mirror the handler test
// (services/admin/handlers/internal_api_test.go TestInternalAPI_PricingCoverageFixture).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  parsePricingMetadata, pricingCoverageCopy, resolvePricingCoverage,
} from './pricingCoverage.ts'

const EN = JSON.parse(readFileSync(new URL('../i18n/en.json', import.meta.url), 'utf8')) as Record<string, Record<string, string>>

function resolveKey(key: string): unknown {
  let v: unknown = EN
  for (const part of key.split('.')) v = (v as Record<string, unknown>)[part]
  return v
}

test('parse: valid payload normalizes; garbage degrades to "not measured"', () => {
  assert.deepEqual(
    parsePricingMetadata({
      pricing_as_of: 'file 2026-09-30 sha256:abc',
      coverage_status: 'partial',
      unpriced_share: 0.4,
      unpriced_models: ['m1', 'm2'],
    }),
    { status: 'partial', share: 0.4, models: ['m1', 'm2'] },
  )
  // The AF-07 wire shape: explicit null share (measurement failed).
  assert.deepEqual(
    parsePricingMetadata({ coverage_status: 'unknown', unpriced_share: null, coverage_error: 'coverage query failed' }),
    { status: 'unknown', share: null, models: [] },
  )
  // Absent fields — additive/older payloads.
  assert.deepEqual(parsePricingMetadata({ pricing_as_of: 'x' }), { status: null, share: null, models: [] })
  // Garbage on the wire: transport casts without validation.
  assert.deepEqual(parsePricingMetadata({ coverage_status: 42, unpriced_share: '0.4' }), { status: null, share: null, models: [] })
  assert.deepEqual(parsePricingMetadata({ unpriced_share: Number.NaN }), { status: null, share: null, models: [] })
  assert.deepEqual(parsePricingMetadata({ unpriced_models: ['ok', 5, null] }), { status: null, share: null, models: ['ok'] })
  // Non-object payloads.
  assert.deepEqual(parsePricingMetadata(null), { status: null, share: null, models: [] })
  assert.deepEqual(parsePricingMetadata(undefined), { status: null, share: null, models: [] })
  assert.deepEqual(parsePricingMetadata('partial'), { status: null, share: null, models: [] })
  assert.deepEqual(parsePricingMetadata([1]), { status: null, share: null, models: [] })
})

test('resolve: measured windows (complete / partial / empty)', () => {
  assert.deepEqual(resolvePricingCoverage({ coverage_status: 'complete', unpriced_share: 0 }), { state: 'ok' })
  assert.deepEqual(resolvePricingCoverage({ coverage_status: 'partial', unpriced_share: 0.4 }), { state: 'warning', pct: 40 })
  // Empty window: not a coverage measurement.
  assert.deepEqual(resolvePricingCoverage({ coverage_status: 'empty', unpriced_share: 0 }), { state: 'ok' })
  // Marked complete but the share contradicts it — never read as fully priced.
  assert.deepEqual(resolvePricingCoverage({ coverage_status: 'complete', unpriced_share: 0.4 }), { state: 'warning', pct: 40 })
})

test('resolve: unknown cost — all-unpriced vs unmeasured', () => {
  // 100% unpriced: measured, but nothing is in the price table.
  assert.deepEqual(
    resolvePricingCoverage({ coverage_status: 'unknown', unpriced_share: 1, unpriced_models: ['m1'] }),
    { state: 'unknown', reason: 'all-unpriced' },
  )
  // The AF-07 wire fixture: failed coverage query — explicit null share.
  assert.deepEqual(
    resolvePricingCoverage({ coverage_status: 'unknown', unpriced_share: null, coverage_error: 'coverage query failed' }),
    { state: 'unknown', reason: 'unmeasured' },
  )
  // partial status without a measurable share is a contradiction → unknown.
  assert.deepEqual(resolvePricingCoverage({ coverage_status: 'partial', unpriced_share: null }), { state: 'unknown', reason: 'unmeasured' })
})

test('resolve: null/undefined ≠ 0 — legacy and malformed payloads never pass as full coverage', () => {
  // The review's finding 2: `unpriced_share: null` with no usable status.
  assert.deepEqual(resolvePricingCoverage({ unpriced_share: null }), { state: 'unknown', reason: 'unmeasured' })
  // Measured 0 WITHOUT a coverage_status: absence of evidence is not proven
  // full coverage (savings.go: an absent status must not be read as such).
  assert.deepEqual(resolvePricingCoverage({ unpriced_share: 0 }), { state: 'unknown', reason: 'unmeasured' })
  // No pricing metadata at all (pre-AF-07 backend).
  assert.deepEqual(resolvePricingCoverage(undefined), { state: 'unknown', reason: 'unmeasured' })
  assert.deepEqual(resolvePricingCoverage(null), { state: 'unknown', reason: 'unmeasured' })
  // Legacy numeric share keeps its measured meaning when it is informative.
  assert.deepEqual(resolvePricingCoverage({ unpriced_share: 0.25 }), { state: 'warning', pct: 25 })
  assert.deepEqual(resolvePricingCoverage({ unpriced_share: 1 }), { state: 'unknown', reason: 'all-unpriced' })
})

test('copy: branch → i18n key, en.json carries the key in both namespaces', () => {
  const calls: Array<{ key: string; opts?: Record<string, unknown> }> = []
  const t = (key: string, opts?: Record<string, unknown>) => {
    calls.push({ key, opts })
    return key
  }

  assert.equal(pricingCoverageCopy({ state: 'ok' }, t, 'cost'), '')
  assert.equal(calls.length, 0)

  assert.equal(
    pricingCoverageCopy({ state: 'warning', pct: 40 }, t, 'cost'),
    'cost.pricingExcludes',
  )
  assert.deepEqual(calls[0], { key: 'cost.pricingExcludes', opts: { pct: 40 } })

  assert.equal(
    pricingCoverageCopy({ state: 'unknown', reason: 'all-unpriced' }, t, 'overview'),
    'overview.pricingNoModels',
  )
  assert.equal(
    pricingCoverageCopy({ state: 'unknown', reason: 'unmeasured' }, t, 'overview'),
    'overview.pricingCoverageUnknown',
  )
  assert.equal(
    pricingCoverageCopy({ state: 'unknown', reason: 'unmeasured' }, t, 'cost'),
    'cost.pricingCoverageUnknown',
  )

  // The new copy key exists (non-empty) in en.json for both screens.
  for (const ns of ['overview', 'cost']) {
    const v = resolveKey(`${ns}.pricingCoverageUnknown`)
    assert.equal(typeof v, 'string')
    assert.ok((v as string).length > 0, `${ns}.pricingCoverageUnknown must be a non-empty string`)
  }
})
