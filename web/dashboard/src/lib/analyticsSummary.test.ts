import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { summarizeQuery, summarySlug } from './analyticsSummary.ts'
import { defaultParams, presetRange } from './analyticsQuery.ts'

// AUX-06: the applied-query summary is one string for the result heading,
// the chart title and the CSV name. i18n and date formatting are injected so
// the node test drives the real assembly logic.
function makeT() {
  return (key: string, opts?: Record<string, unknown>) => {
    let out = key
    if (opts) for (const [k, v] of Object.entries(opts)) out += `|${k}=${String(v)}`
    return out
  }
}

describe('analytics summary', () => {
  const t = makeT()
  const formatDate = (iso: string) => iso.slice(0, 10)

  it('names metrics through the registry and lists split, range and top', () => {
    const range = presetRange('7d', new Date('2026-09-30T00:00:00Z'))
    const summary = summarizeQuery({ ...defaultParams(), from: range.from, to: range.to, metrics: ['cost_usd'], groupBy: ['model'], granularity: 'day', top: 20 }, { t, formatDate })
    assert.match(summary, /analytics\.metric\.cost_usd/) // the fake t echoes the key
    assert.match(summary, /analytics\.summaryBy\|dims=analytics\.dim\.model/)
    assert.match(summary, /analytics\.gran\.day/)
    assert.match(summary, /2026-09-2[23] – 2026-09-30/)
    assert.match(summary, /analytics\.summaryTop\|count=20/)
  })

  it('appends the filter and compare markers, truncating long filters', () => {
    const long = 'model = "x" and label.issue = "very-long-issue-key-that-keeps-going-and-going-and-going"'
    const summary = summarizeQuery({ ...defaultParams(), filter: long, compare: true }, { t, formatDate })
    assert.match(summary, /analytics\.summaryFilter\|filter=.{1,60}/)
    assert.ok(!summary.includes('and-going-and-going"')) // truncated
    assert.match(summary, /analytics\.summaryVsPrev/)
  })

  it('omits the split and granularity words when the query has none', () => {
    const summary = summarizeQuery({ ...defaultParams(), granularity: 'none', groupBy: [] }, { t, formatDate })
    assert.ok(!summary.includes('analytics.summaryBy'))
    assert.ok(!summary.includes('analytics.gran.'))
  })

  it('slugifies the summary into a safe CSV name with a fallback', () => {
    assert.equal(summarySlug('Cost · by Model · Day · 1 Sep – 8 Sep · top 20'), 'cost-by-model-day-1-sep-8-sep-top-20')
    assert.equal(summarySlug('Стоимость · по Модели'), 'стоимость-по-модели')
    assert.equal(summarySlug('   '), 'analytics')
    assert.equal(summarySlug('/*?'), 'analytics')
  })
})
