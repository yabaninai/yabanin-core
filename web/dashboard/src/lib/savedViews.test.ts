import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseSavedViews, parseViewQuery, savedViewsKey } from './savedViews.ts'

// AUX-22: saved views are an untrusted localStorage registry — validation
// must drop broken entries without losing the healthy ones, and a snapshot
// must round-trip through URLSearchParams (it is applied by writing it back
// into the hash query).

test('parseSavedViews rejects non-arrays and drops broken entries', () => {
  assert.deepEqual(parseSavedViews(null), [])
  assert.deepEqual(parseSavedViews('views'), [])
  assert.deepEqual(parseSavedViews([42, null, 'x']), [])
  assert.deepEqual(parseSavedViews([
    { id: '', name: 'no id', query: 'a=1' },
    { id: 'v2', name: '   ', query: 'a=1' },
    { id: 'v3', name: 'no query' },
    { id: 'v4', name: 'ok', query: 'a=1' },
  ]), [{ id: 'v4', name: 'ok', query: 'a=1' }])
})

test('parseSavedViews keeps order, caps the list and bounds field sizes', () => {
  const many = Array.from({ length: 60 }, (_, i) => ({ id: `v${i}`, name: `n${i}`, query: '' }))
  assert.equal(parseSavedViews(many).length, 50)
  assert.deepEqual(parseSavedViews([{ id: 'x'.repeat(65), name: 'n', query: '' }]), [])
  assert.deepEqual(parseSavedViews([{ id: 'v', name: 'n'.repeat(121), query: '' }]), [])
  assert.deepEqual(parseSavedViews([{ id: 'v', name: 'n', query: 'q'.repeat(2049) }]), [])
  // Over-long values are dropped as a whole, not truncated silently into a
  // different snapshot: the stored view must apply verbatim or not at all.
})

test('a saved snapshot decodes back into the exact params it captured', () => {
  const query = 'org=org-fixture&lineage__sort=cost_usd%3Adesc&lineage__page=3'
  const params = parseViewQuery(query)
  assert.equal(params.get('org'), 'org-fixture')
  assert.equal(params.get('lineage__sort'), 'cost_usd:desc')
  assert.equal(params.get('lineage__page'), '3')
  // Round-trip is stable for the apply path.
  assert.equal(params.toString(), query)
})

test('the registry key carries the page id (per-page isolation)', () => {
  assert.equal(savedViewsKey('lineage'), 'yabanin.savedViews.v1:lineage')
  assert.equal(savedViewsKey('analytics'), 'yabanin.savedViews.v1:analytics')
})
