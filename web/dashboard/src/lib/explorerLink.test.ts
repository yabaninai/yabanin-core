// AUX-09: node:test coverage for the drill-down link builder (the hash every
// drilling screen hands to the request explorer).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { drillClause, explorerLink } from './explorerLink.ts'

test('explorerLink: full spec carries org, window and YQL', () => {
  assert.equal(
    explorerLink({
      org: 'org-fixture',
      from: '2026-09-01T00:00:00Z',
      to: '2026-10-01T00:00:00Z',
      yql: 'model = glm-5.3-flash',
    }),
    '#requests-explorer?org=org-fixture&from=2026-09-01T00%3A00%3A00Z&to=2026-10-01T00%3A00%3A00Z&query=model+%3D+glm-5.3-flash',
  )
  // Round-trip: the explorer parses the hash back to the same values.
  const q = new URLSearchParams(
    explorerLink({ org: 'o', from: 'F', to: 'T', yql: 'task = "a b"' }).split('?')[1],
  )
  assert.equal(q.get('org'), 'o')
  assert.equal(q.get('from'), 'F')
  assert.equal(q.get('to'), 'T')
  assert.equal(q.get('query'), 'task = "a b"')
})

test('explorerLink: blank parts are omitted, half windows never pin', () => {
  assert.equal(explorerLink({}), '#requests-explorer')
  assert.equal(explorerLink({ org: '  ' }), '#requests-explorer')
  assert.equal(explorerLink({ yql: '  ' }), '#requests-explorer')
  // A lone border would resolve the other side at read time — not carried.
  assert.equal(explorerLink({ from: '2026-09-01T00:00:00Z' }), '#requests-explorer')
  assert.equal(explorerLink({ to: '2026-10-01T00:00:00Z' }), '#requests-explorer')
  assert.equal(
    explorerLink({ org: 'acme', yql: 'agent = a-1' }),
    '#requests-explorer?org=acme&query=agent+%3D+a-1',
  )
})

test('drillClause: entity clauses, quoting and muted buckets', () => {
  assert.equal(drillClause('model', 'glm-5.3-flash'), 'model = glm-5.3-flash')
  assert.equal(drillClause('task', '  a142-add-login  '), 'task = a142-add-login')
  // Values with spaces/quotes are YQL-quoted, never raw.
  assert.equal(drillClause('tool', 'get weather'), 'tool = "get weather"')
  assert.equal(drillClause('model', 'say "hi"'), 'model = "say \'hi\'"')
  // "No value" buckets are honest labels, not filters.
  assert.equal(drillClause('model', '(none)'), null)
  assert.equal(drillClause('task', '(untagged)'), null)
  assert.equal(drillClause('agent', '(other)'), null)
  assert.equal(drillClause('model', ''), null)
  assert.equal(drillClause('model', '   '), null)
})
