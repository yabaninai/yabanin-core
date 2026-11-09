// AUX-21: pure palette helpers — filtering, grouping and action hashes.

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ERRORS_ONLY_YQL, actionHref, filterCommands, groupCommands, type CommandOption } from './commandPalette.ts'

const CMDS: CommandOption[] = [
  { id: 'overview', label: 'Overview', section: 'Overview' },
  { id: 'requests-explorer', label: 'Request explorer', section: 'Explore', keywords: ['requests-explorer'] },
  { id: 'keys', label: 'API Keys', section: 'Limits & access', keywords: ['keys'] },
  { id: 'palette-requests-errors', label: 'Request explorer — errors only', section: 'Actions', href: '#requests-explorer?query=x' },
  { id: 'palette-key-create', label: 'API keys — create a key', section: 'Actions' },
]

test('empty query keeps the full list in order', () => {
  assert.deepEqual(filterCommands('  ', CMDS), CMDS)
})

test('matching covers label, section and keywords, case-insensitively', () => {
  // label
  assert.deepEqual(filterCommands('api', CMDS).map(c => c.id), ['keys', 'palette-key-create'])
  // section: every "Actions" entry matches
  assert.deepEqual(filterCommands('actions', CMDS).map(c => c.id), ['palette-requests-errors', 'palette-key-create'])
  // keyword: the raw page id matches even though the label differs
  assert.deepEqual(filterCommands('requests-explorer', CMDS).map(c => c.id), ['requests-explorer'])
})

test('no match yields an empty list', () => {
  assert.deepEqual(filterCommands('хлеб', CMDS), [])
})

test('grouping preserves first-seen section order and merges by section', () => {
  const groups = groupCommands(CMDS)
  assert.deepEqual(groups.map(g => g.section), ['Overview', 'Explore', 'Limits & access', 'Actions'])
  assert.deepEqual(groups[3].items.map(c => c.id), ['palette-requests-errors', 'palette-key-create'])
})

test('actionHref merges the current query, drops inspect and skips blanks', () => {
  const globals = globalThis as { window?: unknown }
  const originalWindow = globals.window

  // Node's test runner has no window — the helper must degrade to a bare hash.
  assert.equal(actionHref('requests-explorer', { query: ERRORS_ONLY_YQL }), '#requests-explorer?query=status+%3E%3D+400')

  globals.window = { location: { hash: '#overview?org=org-fixture&inspect=key-1&locale=ar' } }
  try {
    assert.equal(
      actionHref('requests-explorer', { query: ERRORS_ONLY_YQL }),
      '#requests-explorer?org=org-fixture&locale=ar&query=status+%3E%3D+400',
    )
    // A blank extra never encodes as `key=`.
    assert.equal(actionHref('keys', { org: '  ' }), '#keys?org=org-fixture&locale=ar')
  } finally {
    globals.window = originalWindow
  }
})
