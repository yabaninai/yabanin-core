import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ANALYTICS_QUESTIONS, explorerHash, hygieneShare, issueURL, mergeYqlClauses, monthForecast, pipelineAverage, resolveBoard } from './boards.ts'

describe('boards', () => {
  const keys = ['issue', 'issue.project', 'ci.system', 'ci.pipeline', 'ci.job_name', 'ci.trigger', 'git.repo']

  it('falls back from client and repo and hides missing dimensions', () => {
    const agents = resolveBoard('agents', keys, { team: '', repo: '', issue: '' })
    const cost = agents.find(p => p.id === 'cost-client')
    assert.ok(cost && !cost.hidden)
    assert.deepEqual(cost.query.groupBy, ['agent'])
    const repos = agents.find(p => p.id === 'repos')
    assert.ok(repos && !repos.hidden)
    assert.deepEqual(repos.query.groupBy, ['label:git.repo'])
    const klass = agents.find(p => p.id === 'request-class')
    assert.ok(klass?.hidden && klass.missing === 'request_class')
    const outcome = resolveBoard('ci', keys, { team: '', repo: '', issue: '' }).find(p => p.id === 'session-outcome')
    assert.ok(outcome?.hidden)
  })

  it('adds board filters and marks the panel slower', () => {
    const [panel] = resolveBoard('reliability', keys, { team: 'payments', repo: 'acme/web', issue: '' })
    assert.match(panel.query.filter, /team = payments/)
    assert.match(panel.query.filter, /label\.git\.repo = acme\/web/)
    assert.equal(panel.slower, true)
  })

  it('builds an explorer link and an issue url', () => {
    const [panel] = resolveBoard('budgets', [], { team: '', repo: '', issue: '' })
    const hash = explorerHash('org-1', '2026-09-01T00:00:00Z', '2026-09-08T00:00:00Z', panel)
    assert.match(hash, /^#analytics\?/)
    assert.match(hash, /org=org-1/)
    assert.equal(issueURL('https://tracker.example/{issue}', 'PAY 1'), 'https://tracker.example/PAY%201')
    assert.equal(issueURL('http://nope/{issue}', 'PAY-1'), null)
  })

  // AUX-07: "Open in Analytics" carries the board's global filter (and the
  // applied tz) so the explorer reproduces the board's cut.
  it('merges the global filter into the explorer link without duplicating clauses', () => {
    assert.equal(mergeYqlClauses('a = 1', 'b = 2'), 'a = 1 and b = 2')
    assert.equal(mergeYqlClauses('a = 1  and  b = 2', 'b = 2'), 'a = 1 and b = 2')
    assert.equal(mergeYqlClauses('', undefined), '')
    const [panel] = resolveBoard('budgets', [], { team: '', repo: 'acme/web', issue: '' })
    assert.match(panel.query.filter, /label\.git\.repo = acme\/web/)
    const hash = explorerHash('org-1', '2026-09-01T00:00:00Z', '2026-09-08T00:00:00Z', panel,
      { extraFilter: 'label.git.repo = acme/web and label.issue = PAY-1', tz: 'Europe/Vienna' })
    const filter = new URLSearchParams(hash.split('?')[1]).get('f') ?? ''
    assert.equal(filter.split(' and ').filter(c => c === 'label.git.repo = acme/web').length, 1)
    assert.ok(filter.includes('label.issue = PAY-1'))
    assert.equal(new URLSearchParams(hash.split('?')[1]).get('tz'), 'Europe/Vienna')
  })

  it('forecasts the month and summarizes hygiene and pipelines', () => {
    const now = new Date('2026-09-15T00:00:00Z')
    const projected = monthForecast(10, now)
    assert.ok(projected > 10)
    assert.equal(hygieneShare([['(none)', 1], ['PAY-1', 3]]), 0.25)
    assert.equal(pipelineAverage([['9001', 4], ['(other)', 100]]), 4)
  })
})

// AUX-06: ready questions reuse board panel shapes and stay within the
// server contract (≤6 metrics, ≤2 dims, a valid granularity, a valid chart).
describe('analytics questions', () => {
  const GRANS = new Set(['none', 'hour', 'day', 'week', 'month'])
  const CHARTS = new Set(['line', 'area', 'stacked_bar', 'bar', 'table'])
  it('derives five valid query shapes', () => {
    assert.equal(ANALYTICS_QUESTIONS.length, 5)
    for (const q of ANALYTICS_QUESTIONS) {
      assert.ok(q.titleKey.startsWith('analytics.question.'), q.id)
      assert.ok(q.query.metrics.length >= 1 && q.query.metrics.length <= 6, q.id)
      assert.ok(q.query.groupBy.length <= 2, q.id)
      assert.ok(GRANS.has(q.query.granularity), q.id)
      assert.ok(CHARTS.has(q.query.chart), q.id)
    }
  })
  it('answers the cost question with cost by model by day', () => {
    const q = ANALYTICS_QUESTIONS.find(x => x.id === 'cost-by-model')
    assert.ok(q)
    assert.deepEqual(q.query, { metrics: ['cost_usd'], groupBy: ['model'], granularity: 'day', filter: '', top: 20, chart: 'line' })
  })
})
