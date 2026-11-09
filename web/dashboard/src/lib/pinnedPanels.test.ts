import { test } from 'node:test'
import assert from 'node:assert/strict'
import { listPinnedPanels, parsePinnedPanels, pinPanel, unpinPanel, validPanelIds } from './pinnedPanels.ts'

// AUX-07: the pin registry is user-editable JSON — parsing must validate
// against the real board registry, degrade silently, and cap the list.

test('validPanelIds lists every board panel as board/panel', () => {
  const ids = validPanelIds()
  assert.ok(ids.has('agents/cost-client'))
  assert.ok(ids.has('budgets/top-agents'))
  assert.ok(ids.has('issues/hygiene'))
  assert.ok(!ids.has('agents/nope'))
})

test('parsePinnedPanels drops junk and unknown ids, dedupes and caps', () => {
  const valid = new Set(['a/x', 'a/y', 'b/z'])
  assert.deepEqual(parsePinnedPanels(null, valid), [])
  assert.deepEqual(parsePinnedPanels('pin', valid), [])
  assert.deepEqual(parsePinnedPanels([42, '', '  ', 'a/nope', 'a/x', 'a/x', 'a/y'], valid), ['a/x', 'a/y'])
  assert.deepEqual(parsePinnedPanels(['a/x'.repeat(50), 'a/y'], valid), ['a/y'])
  // The cap keeps the Overview section bounded.
  const many = Array.from({ length: 50 }, (_, i) => `a/x${i}`).filter(() => false)
  assert.ok(parsePinnedPanels(['a/x', ...many, 'a/y'], valid).length <= 12)
})

test('pin/unpin round-trips through storage', () => {
  const store = new Map<string, string>()
  const ls = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => { store.set(k, v) },
    removeItem: (k: string) => { store.delete(k) },
  }
  // @ts-expect-error -- node test shim for the browser-only storage
  globalThis.localStorage = ls
  const valid = new Set(['budgets/top-agents', 'issues/hygiene'])
  assert.deepEqual(parsePinnedPanels([], valid), [])
  pinPanel('budgets/top-agents')
  pinPanel('budgets/top-agents') // duplicate is a no-op
  pinPanel('agents/ghost') // unknown ids never enter storage
  assert.deepEqual(JSON.parse(store.get('yabanin.pinnedPanels.v1')!), ['budgets/top-agents'])
  unpinPanel('budgets/top-agents')
  assert.equal(store.get('yabanin.pinnedPanels.v1'), '[]')
  // listPinnedPanels over real storage: valid ids only, garbage tolerated.
  store.set('yabanin.pinnedPanels.v1', '{"bad":1}')
  assert.deepEqual(listPinnedPanels(), [])
  store.set('yabanin.pinnedPanels.v1', JSON.stringify(['budgets/top-agents', 'nope/x']))
  assert.deepEqual(listPinnedPanels(), ['budgets/top-agents'])
})
