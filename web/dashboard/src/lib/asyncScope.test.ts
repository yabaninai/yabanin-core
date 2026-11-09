import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isCurrentScope, type AsyncScope } from './asyncScope.ts'

// TP-06 regression: a completion is applied only under the scope it started.
// Org A's delayed response must never land in org B (org changed), and a
// newer operation in the same org must supersede an older one (epoch bump).
test('isCurrentScope accepts the same org and epoch', () => {
  const seen: AsyncScope = { org: 'org-a', epoch: 3 }
  assert.equal(isCurrentScope(seen, { org: 'org-a', epoch: 3 }), true)
})

test('isCurrentScope rejects an org switch', () => {
  const seen: AsyncScope = { org: 'org-a', epoch: 3 }
  assert.equal(isCurrentScope(seen, { org: 'org-b', epoch: 3 }), false)
})

test('isCurrentScope rejects an epoch bump within the same org', () => {
  const seen: AsyncScope = { org: 'org-a', epoch: 3 }
  assert.equal(isCurrentScope(seen, { org: 'org-a', epoch: 4 }), false)
})

test('isCurrentScope rejects org switch and epoch bump together', () => {
  const seen: AsyncScope = { org: 'org-a', epoch: 3 }
  assert.equal(isCurrentScope(seen, { org: 'org-b', epoch: 4 }), false)
})

test('isCurrentScope treats empty org scope as current only against empty org', () => {
  const seen: AsyncScope = { org: '', epoch: 0 }
  assert.equal(isCurrentScope(seen, { org: '', epoch: 0 }), true)
  assert.equal(isCurrentScope(seen, { org: 'org-a', epoch: 0 }), false)
})
