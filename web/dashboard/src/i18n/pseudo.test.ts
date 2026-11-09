// AF-12 unit tests: the QA-only pseudo locale is derived from `en` on demand.
//
// The production entry never builds it (index.ts only calls buildPseudo when
// a QA request selects ?locale=pseudo); these tests pin the derivation
// contract the pseudo gate relies on: deterministic stretch, «…» wrapping,
// non-string values passed through.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildPseudo } from './pseudo.ts'

const EN = {
  nav: { overview: 'Overview', keys: 'API keys' },
  misc: { empty: '', flag: 42 },
}

test('pseudo wraps every string in «…» and stretches it deterministically', () => {
  const a = buildPseudo(EN)
  const b = buildPseudo(EN)
  assert.deepEqual(a, b, 'the stretch must be stable across runs (the gate compares renders)')
  assert.equal(a.nav.overview.startsWith('«'), true)
  assert.equal(a.nav.overview.endsWith('»'), true)
  assert.ok(a.nav.overview.length > '«Overview»'.length, 'strings are stretched, not just wrapped')
  assert.equal(a.nav.keys.startsWith('«'), true)
})

test('pseudo passes non-string values through; every string is wrapped (existing contract)', () => {
  const p = buildPseudo(EN)
  assert.equal(p.misc.empty, '«»')
  assert.equal(p.misc.flag, 42 as unknown as string)
})
