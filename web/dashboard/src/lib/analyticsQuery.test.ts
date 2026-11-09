import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  analyticsApiQuery, chartRows, parseAnalyticsHash, pointDrillYql, presetFromRange, presetRange,
  rowDrillYql, seriesDisplayName, seriesMetricId, serializeAnalyticsHash,
  type AnalyticsResult,
} from './analyticsQuery.ts'

describe('analytics hash', () => {
  it('round-trips a shared link and keeps unknown keys', () => {
    const raw = 'org=org-1&from=2026-09-01T00:00:00Z&to=2026-09-08T00:00:00Z&m=cost_usd,tokens_in&g=label:issue,model&gran=day&f=status%20%3E%3D%20400&top=20&cmp=1&chart=line&tz=Europe%2FMoscow&locale=ja'
    const { params, extra } = parseAnalyticsHash(raw, new Date('2026-09-30T00:00:00Z'))
    assert.equal(params.org, 'org-1')
    assert.deepEqual(params.metrics, ['cost_usd', 'tokens_in'])
    assert.deepEqual(params.groupBy, ['label:issue', 'model'])
    assert.equal(params.compare, true)
    assert.equal(params.filter, 'status >= 400')
    assert.deepEqual(extra, [['locale', 'ja']])
    const again = parseAnalyticsHash(serializeAnalyticsHash(params, extra), new Date('2026-09-30T00:00:00Z'))
    assert.deepEqual(again.params, params)
    assert.deepEqual(again.extra, extra)
  })

  it('drops unknown metrics overflow, bad granularity and top', () => {
    const { params } = parseAnalyticsHash('m=a,b,c,d,e,f,g&gran=fortnight&top=0&g=model,team,agent', new Date('2026-09-30T00:00:00Z'))
    assert.equal(params.metrics.length, 6)
    assert.equal(params.granularity, 'day')
    assert.equal(params.top, 20)
    assert.deepEqual(params.groupBy, ['model', 'team'])
  })

  it('AUX-08: a period preset resolves the window and round-trips without borders', () => {
    const now = new Date('2026-09-30T00:00:00Z')
    const { params } = parseAnalyticsHash('org=org-1&period=30d&m=requests', now)
    assert.equal(params.period, '30d')
    const range = presetRange('30d', now)
    assert.equal(params.from, range.from)
    assert.equal(params.to, range.to)
    const again = parseAnalyticsHash(serializeAnalyticsHash(params), now)
    assert.deepEqual(again.params, params)
  })

  it('AUX-08: explicit from/to borders win over a period param (deep-link priority)', () => {
    const now = new Date('2026-09-30T00:00:00Z')
    const { params } = parseAnalyticsHash('period=90d&from=2026-09-01T00%3A00%3A00Z&to=2026-09-08T00%3A00%3A00Z', now)
    assert.equal(params.period, 'custom')
    assert.equal(params.from, '2026-09-01T00:00:00Z')
    assert.equal(params.to, '2026-09-08T00:00:00Z')
  })

  it('preset 24h is one day ending at now', () => {
    const now = new Date('2026-09-30T12:00:00Z')
    const range = presetRange('24h', now)
    assert.equal(range.to, '2026-09-30T12:00:00Z')
    assert.equal(range.from, '2026-09-29T12:00:00Z')
  })

  it('builds the API query with compare and csv', () => {
    const { params } = parseAnalyticsHash('org=org-1&from=2026-09-01T00:00:00Z&to=2026-09-02T00:00:00Z&m=requests&cmp=1', new Date('2026-09-30T00:00:00Z'))
    const q = analyticsApiQuery(params, 'csv')
    assert.match(q, /org_id=org-1/)
    assert.match(q, /compare=previous/)
    assert.match(q, /format=csv/)
    assert.match(q, /metrics=requests/)
  })
})

describe('chart gaps', () => {
  it('fills a missing bucket with 0 for counts and a gap for rates', () => {
    const result: AnalyticsResult = {
      query: { metrics: ['requests', 'error_rate'], group_by: [], granularity: 'day', from: '', to: '', tz: 'UTC', top: 20, filter: '' },
      source: 'raw',
      columns: [
        { name: 'time', type: 'time' },
        { name: 'requests', type: 'number', unit: 'count' },
        { name: 'error_rate', type: 'number', unit: 'ratio' },
      ],
      rows: [
        ['2026-09-01T00:00:00Z', 2, 0.5],
        ['2026-09-03T00:00:00Z', 4, null],
      ],
      totals: { requests: 6, error_rate: 0.5 },
      coverage: { unpriced_requests: 0, unpriced_share: 0, legacy_rows: 0 },
      truncated: false,
      generated_at: '2026-09-30T00:00:00Z',
    }
    const { points } = chartRows(result, 'line')
    assert.equal(points.length, 2)
    assert.equal(points[0].requests, 2)
    assert.equal(points[1].requests, 4)
    assert.equal(points[1].error_rate, null)
    const withGap = chartRows({
      ...result,
      rows: [
        ['2026-09-01T00:00:00Z', 'PAY-1', 2, 0.5],
        ['2026-09-01T00:00:00Z', 'PAY-2', 1, 0],
        ['2026-09-02T00:00:00Z', 'PAY-1', 3, 1],
      ],
      columns: [
        { name: 'time', type: 'time' },
        { name: 'label:issue', type: 'string' },
        { name: 'requests', type: 'number', unit: 'count' },
        { name: 'error_rate', type: 'number', unit: 'ratio' },
      ],
    }, 'line')
    const day2 = withGap.points.find(p => p.x === '2026-09-02T00:00:00Z')
    assert.ok(day2)
    assert.equal(day2['PAY-2 · requests'], 0)
    assert.equal(day2['PAY-2 · error_rate'], null)
  })
})

// AUX-06: preset derived from the applied range.
describe('preset from range', () => {
  it('recognizes the exact preset spans and flips edits to custom', () => {
    assert.equal(presetFromRange('2026-09-01T00:00:00Z', '2026-09-08T00:00:00Z'), '7d')
    assert.equal(presetFromRange('2026-09-29T12:00:00Z', '2026-09-30T12:00:00Z'), '24h')
    assert.equal(presetFromRange('2026-08-31T00:00:00Z', '2026-09-30T00:00:00Z'), '30d')
    assert.equal(presetFromRange('2026-07-02T00:00:00Z', '2026-09-30T00:00:00Z'), '90d')
    // second-level rounding from datetime inputs stays inside the tolerance
    assert.equal(presetFromRange('2026-09-01T00:00:00Z', '2026-09-08T00:00:30Z'), '7d')
    assert.equal(presetFromRange('2026-09-01T00:00:00Z', '2026-09-06T00:00:00Z'), 'custom')
    assert.equal(presetFromRange('2026-09-08T00:00:00Z', '2026-09-01T00:00:00Z'), 'custom')
  })
})

// AUX-06: human chart series labels (display only — the raw keys stay the
// chartRows contract). The dim part of a key holds VALUES; the dim NAMES come
// from the result columns positionally.
describe('series display names', () => {
  const t = (key: string, opts?: Record<string, unknown>) => key + (opts ? `|${JSON.stringify(opts)}` : '')
  const result: AnalyticsResult = {
    query: { metrics: ['cost_usd', 'requests'], group_by: ['label:issue', 'model'], granularity: 'day', from: '', to: '', tz: 'UTC', top: 20, filter: '' },
    source: 'raw',
    columns: [
      { name: 'time', type: 'time' },
      { name: 'label:issue', type: 'string' },
      { name: 'model', type: 'string' },
      { name: 'cost_usd', type: 'number', unit: 'usd' },
      { name: 'requests', type: 'number', unit: 'count' },
    ],
    rows: [],
    totals: {},
    coverage: { unpriced_requests: 0, unpriced_share: null, legacy_rows: 0 },
    truncated: false,
    generated_at: '2026-09-30T00:00:00Z',
  }
  it('translates the metric and reads dim values against the result columns', () => {
    assert.equal(seriesDisplayName('cost_usd', result, t), 'analytics.metric.cost_usd')
    // single dim: the bare value is the legend
    assert.equal(seriesDisplayName('PAY-1 · cost_usd', result, t), 'PAY-1 · analytics.metric.cost_usd')
    // several dims: each value is labelled with its translated dim name
    assert.equal(
      seriesDisplayName('PAY-1 / gpt-x · requests', result, t),
      'analytics.labelDim|{"key":"issue"} = PAY-1 / analytics.dim.model = gpt-x · analytics.metric.requests',
    )
    assert.equal(seriesMetricId('cmp:model · latency_p95'), 'latency_p95')
  })

  // seriesDisplayName — a board-panel legend must never carry the raw key.
  it('composes with chartRows so a board-panel legend carries display names', () => {
    const board: AnalyticsResult = {
      query: { metrics: ['cost_usd', 'requests'], group_by: ['agent'], granularity: 'day', from: '', to: '', tz: 'UTC', top: 20, filter: '' },
      source: 'raw',
      columns: [
        { name: 'time', type: 'time' },
        { name: 'agent', type: 'string' },
        { name: 'cost_usd', type: 'number', unit: 'usd' },
        { name: 'requests', type: 'number', unit: 'count' },
      ],
      rows: [['2026-09-01T00:00:00Z', 'agent-1', 1, 4]],
      totals: { cost_usd: 1, requests: 4 },
      coverage: { unpriced_requests: 0, unpriced_share: null, legacy_rows: 0 },
      truncated: false,
      generated_at: '2026-09-30T00:00:00Z',
    }
    const legend = chartRows(board, 'line').series.map(s => seriesDisplayName(s.key, board, t))
    assert.deepEqual(legend, ['agent-1 · analytics.metric.cost_usd', 'agent-1 · analytics.metric.requests'])
  })
})

// AUX-06: drill-down YQL for the request explorer.
describe('drill-down YQL', () => {
  const result: AnalyticsResult = {
    query: { metrics: ['cost_usd'], group_by: ['label:issue', 'model'], granularity: 'day', from: '', to: '', tz: 'UTC', top: 20, filter: '' },
    source: 'raw',
    columns: [
      { name: 'time', type: 'time' },
      { name: 'label:issue', type: 'string' },
      { name: 'model', type: 'string' },
      { name: 'cost_usd', type: 'number', unit: 'usd' },
    ],
    rows: [],
    totals: {},
    coverage: { unpriced_requests: 0, unpriced_share: null, legacy_rows: 0 },
    truncated: false,
    generated_at: '2026-09-30T00:00:00Z',
  }
  const params = { from: '2026-09-01T00:00:00Z', to: '2026-09-08T00:00:00Z', granularity: 'day' as const }

  it('builds a row YQL from drillable dims plus the row time bucket', () => {
    const yql = rowDrillYql(result, ['2026-09-02T00:00:00Z', 'PAY-1', 'gpt-x', 1.5], params)
    assert.equal(yql, 'label.issue = PAY-1 and model = gpt-x and created >= 2026-09-02T00:00:00Z and created < 2026-09-03T00:00:00Z')
  })

  it('quotes values that are not plain words and skips muted ones', () => {
    const yql = rowDrillYql(result, ['2026-09-02T00:00:00Z', '(none)', 'openai gpt-4', 1.5], params)
    assert.equal(yql, 'model = "openai gpt-4" and created >= 2026-09-02T00:00:00Z and created < 2026-09-03T00:00:00Z')
  })

  it('falls back to the whole applied period for non-time rows', () => {
    const yql = rowDrillYql(result, [null, 'PAY-2', 'gpt-x', 1], params)
    assert.match(yql, /created >= 2026-09-01T00:00:00Z and created < 2026-09-08T00:00:00Z/)
  })

  it('maps chart series keys through the result columns for point clicks', () => {
    const yql = pointDrillYql(result, 'PAY-1 · cost_usd', '2026-09-03T00:00:00Z', params, true)
    assert.equal(yql, 'label.issue = PAY-1 and created >= 2026-09-03T00:00:00Z and created < 2026-09-04T00:00:00Z')
  })

  it('uses the applied period for bar charts and drops undrillable dims', () => {
    const teamResult: AnalyticsResult = {
      ...result,
      columns: [
        { name: 'time', type: 'time' },
        { name: 'team', type: 'string' },
        { name: 'endpoint', type: 'string' },
        { name: 'cost_usd', type: 'number', unit: 'usd' },
      ],
    }
    const yql = pointDrillYql(teamResult, 'team-a / ep-1 · cost_usd', 'team-a', params, false)
    // team and endpoint have no request-side YQL field — time scope only.
    assert.equal(yql, 'created >= 2026-09-01T00:00:00Z and created < 2026-09-08T00:00:00Z')
  })

  it('expands month buckets by calendar month', () => {
    const yql = pointDrillYql(result, 'cost_usd', '2026-09-15T00:00:00Z', { ...params, granularity: 'month' }, true)
    assert.match(yql, /created >= 2026-09-15T00:00:00Z and created < 2026-10-15T00:00:00Z/)
  })
})
