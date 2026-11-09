import { test } from 'node:test'
import assert from 'node:assert/strict'
import { consumerRows, mergeConsumers, toolBucketRows, CONSUMER_TOP } from './overviewConsumers.ts'
import type { AnalyticsResult } from '../../lib/analyticsQuery.ts'

function board(columns: AnalyticsResult['columns'], rows: AnalyticsResult['rows'], displayNames?: AnalyticsResult['display_names']): AnalyticsResult {
  return {
    query: { metrics: ['cost_usd', 'requests'], group_by: [], granularity: 'none', from: '', to: '', tz: '', top: 10, filter: '' },
    source: 'raw',
    columns,
    rows,
    totals: {},
    coverage: { unpriced_requests: 0, unpriced_share: 0, legacy_rows: 0 },
    display_names: displayNames,
    truncated: false,
    generated_at: '2026-10-03T00:00:00Z',
  }
}

const TEAM_BOARD = board(
  [
    { name: 'team', type: 'string' },
    { name: 'cost_usd', type: 'number', unit: 'usd' },
    { name: 'requests', type: 'number', unit: 'count' },
  ],
  [
    ['team-2', 3, 30],
    ['(none)', 1, 5],
    ['team-1', 10, 100],
  ],
  { team: { 'team-1': 'Platform', 'team-2': 'Billing' } },
)

const AGENT_BOARD = board(
  [
    { name: 'agent', type: 'string' },
    { name: 'cost_usd', type: 'number', unit: 'usd' },
    { name: 'requests', type: 'number', unit: 'count' },
  ],
  [['agent-1', 7, 70]],
  { agent: { 'agent-1': 'ci-agent' } },
)

test('consumerRows: server display names win over raw ids; muted buckets flag unattributed', () => {
  const rows = consumerRows(TEAM_BOARD, 'team')
  assert.deepEqual(
    rows.map(r => [r.id, r.name]),
    [['team-2', 'Billing'], ['(none)', ''], ['team-1', 'Platform']],
  )
  const none = rows.find(r => r.id === '(none)')!
  assert.equal(none.name, '', 'muted bucket has no name (renderer substitutes)')
  assert.equal(none.drillable, false, 'muted bucket never drillable')
  assert.equal(rows[0]!.drillable, false, 'team rows are not drillable (no YQL team field)')
})

test('consumerRows: unknown metric cells stay null (unknown ≠ 0)', () => {
  const partial = board(
    [{ name: 'agent', type: 'string' }, { name: 'requests', type: 'number', unit: 'count' }],
    [['agent-1', 5]],
  )
  const rows = consumerRows(partial, 'agent')
  assert.equal(rows[0]!.costUsd, null)
  assert.equal(rows[0]!.requests, 5)
})

test('consumerRows: non-consumer shapes (time column, garbage) degrade to empty', () => {
  assert.deepEqual(consumerRows(null, 'team'), [])
  const timed = board(
    [
      { name: 'time', type: 'time' },
      { name: 'team', type: 'string' },
      { name: 'cost_usd', type: 'number', unit: 'usd' },
    ],
    [['2026-10-01T00:00:00Z', 'team-1', 1]],
  )
  assert.equal(consumerRows(timed, 'team').length, 1, 'a time column is skipped, the dim still parses')
})

test('mergeConsumers: one spend-descended list, names kept, capped to CONSUMER_TOP', () => {
  const merged = mergeConsumers(TEAM_BOARD, AGENT_BOARD, 0)
  assert.deepEqual(
    merged.rows.map(r => r.name),
    ['Platform', 'ci-agent', 'Billing', ''],
  )
  assert.deepEqual(
    merged.rows.map(r => r.kind),
    ['team', 'agent', 'team', 'team'],
  )
  assert.equal(merged.rows.find(r => r.name === 'ci-agent')!.drillable, true)
  assert.equal(merged.failures, 0)

  const many = mergeConsumers(
    board(
      [{ name: 'team', type: 'string' }],
      Array.from({ length: 30 }, (_, i) => [`t${i}`]),
    ),
    null,
    0,
  )
  assert.equal(many.rows.length, CONSUMER_TOP)
})

test('mergeConsumers: unknown spend sorts last, not first', () => {
  const merged = mergeConsumers(
    board(
      [
        { name: 'team', type: 'string' },
        { name: 'cost_usd', type: 'number', unit: 'usd' },
      ],
      [['team-known', 5], ['team-unknown', 0]],
    ),
    null,
    0,
  )
  assert.deepEqual(merged.rows.map(r => r.id), ['team-known', 'team-unknown'])
})

test('toolBucketRows: a2a/mcp rows split out of the model board, real models stay out', () => {
  const rows = toolBucketRows([
    { model: 'glm-5.3-flash', requests: 80, actual_cost_usd: 0.8 },
    { model: 'mcp:search:web_search', requests: 12, actual_cost_usd: 0 },
    { model: 'a2a:billing-agent', requests: 5, actual_cost_usd: 0.02 },
    { model: 'qwen-local', requests: 40, actual_cost_usd: 0.43 },
  ])
  assert.deepEqual(
    rows.map(r => [r.tool, r.kind]),
    [['a2a:billing-agent', 'a2a'], ['mcp:search:web_search', 'mcp']],
  )
  assert.deepEqual(toolBucketRows([{ model: 'glm-5.3-flash', requests: 1, actual_cost_usd: 1 }]), [])
  assert.deepEqual(toolBucketRows(undefined), [])
})
