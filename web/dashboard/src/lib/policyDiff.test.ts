
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { diffLines, diffSummary } from './policyDiff.ts'

test('identical documents produce only same lines', () => {
  const lines = diffLines('a\nb\nc', 'a\nb\nc')
  assert.deepEqual(lines.map(l => l.type), ['same', 'same', 'same'])
  assert.deepEqual(diffSummary(lines), { added: 0, removed: 0, unchanged: 3 })
})

test('a pure append marks only the new lines as add', () => {
  const lines = diffLines('apiVersion: ypp/v1\nkind: Policy', 'apiVersion: ypp/v1\nkind: Policy\nsteps: []')
  assert.deepEqual(lines.map(l => l.type), ['same', 'same', 'add'])
  assert.deepEqual(diffSummary(lines), { added: 1, removed: 0, unchanged: 2 })
})

test('a changed line is one del + one add', () => {
  const lines = diffLines('mode: shadow', 'mode: enforce')
  assert.deepEqual(lines, [
    { type: 'del', text: 'mode: shadow' },
    { type: 'add', text: 'mode: enforce' },
  ])
})

test('a deleted middle line is del; surrounding lines stay same', () => {
  const lines = diffLines('a\nb\nc', 'a\nc')
  assert.deepEqual(lines.map(l => `${l.type}:${l.text}`), ['same:a', 'del:b', 'same:c'])
})

test('empty vs document: every real line is an add (the empty line drops)', () => {
  assert.deepEqual(diffLines('', 'x\ny').filter(l => l.text !== '').map(l => l.type), ['add', 'add'])
  assert.deepEqual(diffLines('x\ny', '').filter(l => l.text !== '').map(l => l.type), ['del', 'del'])
})

test('the summary counts add/del/unchanged exactly', () => {
  const s = diffSummary(diffLines('a\nb\nc\nd', 'a\nX\nc\nd\nE'))
  assert.deepEqual(s, { added: 2, removed: 1, unchanged: 3 })
})
