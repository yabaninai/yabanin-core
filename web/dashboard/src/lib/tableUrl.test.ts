import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readTableUrlState, writeTableUrlState } from './tableUrl.ts'

// AUX-01 acceptance: table-scoped URL state restores after a reload. The
// encode/decode pair is tested directly — the hook is a thin wrapper over it.

test('round-trips sort and page', () => {
  const params = new URLSearchParams()
  writeTableUrlState(params, 'tasks', { page: 3, sort: { key: 'cost_usd', dir: 'desc' } })
  assert.equal(params.get('tasks__page'), '3')
  assert.equal(params.get('tasks__sort'), 'cost_usd:desc')
  assert.deepEqual(readTableUrlState(params, 'tasks'), { page: 3, sort: { key: 'cost_usd', dir: 'desc' } })
})

test('defaults are deleted, not written — a plain URL stays plain', () => {
  const params = new URLSearchParams()
  writeTableUrlState(params, 'tasks', { page: 1, sort: null })
  assert.equal(params.size, 0)
  assert.deepEqual(readTableUrlState(params, 'tasks', { page: 1, sort: null }), { page: 1, sort: null })
})

test('tables do not clash with each other or scope params', () => {
  const params = new URLSearchParams('org=org-a&tasks__sort=cost_usd:desc&lineage__sort=timestamp:asc')
  assert.deepEqual(readTableUrlState(params, 'tasks'), { page: 1, sort: { key: 'cost_usd', dir: 'desc' } })
  assert.deepEqual(readTableUrlState(params, 'lineage'), { page: 1, sort: { key: 'timestamp', dir: 'asc' } })
})

test('a user-edited page falls back when not a positive integer', () => {
  assert.equal(readTableUrlState('tasks__page=0', 'tasks').page, 1)
  assert.equal(readTableUrlState('tasks__page=-2', 'tasks').page, 1)
  assert.equal(readTableUrlState('tasks__page=abc', 'tasks').page, 1)
  assert.equal(readTableUrlState('tasks__page=5', 'tasks').page, 5)
})

test('a sort without :dir reads as asc; a blank column falls back', () => {
  assert.deepEqual(readTableUrlState('tasks__sort=created_at', 'tasks').sort, { key: 'created_at', dir: 'asc' })
  assert.deepEqual(readTableUrlState('tasks__sort=:desc', 'tasks').sort, null)
  assert.equal(readTableUrlState('tasks__sort=', 'tasks').sort, null)
})

test('an unknown dir value reads as asc (never poisons state)', () => {
  assert.deepEqual(readTableUrlState('tasks__sort=cost: sideways', 'tasks').sort, { key: 'cost', dir: 'asc' })
})
