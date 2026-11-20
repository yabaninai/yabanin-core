import { test } from 'node:test'
import assert from 'node:assert/strict'
import { requestExplorerWindow } from './requestExplorerWindow.ts'

test('live presets use full-precision current bounds instead of a stale minute-truncated snapshot', () => {
  const scope = { period: '7d' as const, from: '2026-11-13T09:00:00Z', to: '2026-11-20T09:00:00Z' }
  const now = new Date('2026-11-20T09:36:20.654Z')
  const actual = requestExplorerWindow(scope, now)
  assert.deepEqual(actual, { from: '2026-11-13T09:36:20.654Z', to: '2026-11-20T09:36:20.654Z' })
  assert.ok(Date.parse(actual.to) >= Date.parse('2026-11-20T09:36:04.625Z'))
  assert.ok(Date.parse(actual.to) < now.getTime() + 1)
})

test('each refresh resolves a new live upper bound while preserving the selected span', () => {
  const scope = { period: '24h' as const, from: '2026-11-20T08:00:00Z', to: '2026-11-21T08:00:00Z' }
  const first = requestExplorerWindow(scope, new Date('2026-11-20T09:36:20.654Z'))
  const next = requestExplorerWindow(scope, new Date('2026-11-20T09:37:20.654Z'))
  assert.equal(Date.parse(next.to) - Date.parse(first.to), 60_000)
  assert.equal(Date.parse(next.to) - Date.parse(next.from), 86_400_000)
})

test('an explicitly pinned custom window is returned byte-for-byte', () => {
  const custom = { period: 'custom' as const, from: '2026-11-20T09:00:01.123Z', to: '2026-11-20T09:59:59.987Z' }
  assert.deepEqual(requestExplorerWindow(custom, new Date('2026-11-21T00:00:00Z')), { from: custom.from, to: custom.to })
})
