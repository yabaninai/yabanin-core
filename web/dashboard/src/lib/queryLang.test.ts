// Parity tests for the TS mirror of pkg/adminstore/yql.go (YQL).
// Runs on the bare node:test runner with type stripping — the same
// zero-dependency pattern as services/subscription-bridge (`npm test`).
// The file is excluded from `tsc` (build has no DOM/node types for the
// runner); eslint still lints it. If this test and the Go suite ever
// disagree, the Go parser is the authority — fix this mirror.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  appendClause, clauseToString, fieldMeta, flattenAnd, opsForField, orderToString,
  parseYQL, quoteYqlValue, removeLeaf,
} from './queryLang.ts'

describe('parseYQL — valid queries', () => {
  it('simple equality and == normalization', () => {
    const r = parseYQL('model = gpt-4o')
    assert.ok(r.ok)
    assert.equal(r.canonical, 'model = gpt-4o')
    const eq = parseYQL('model == gpt-4o')
    assert.ok(eq.ok)
    assert.equal(eq.canonical, 'model = gpt-4o')
  })

  it('boolean chains, groups, not', () => {
    assert.ok(parseYQL('status >= 400 and cost > 0.01').ok)
    assert.equal(parseYQL('(model = a or model = b) and status = 200').ok &&
      parseYQL('(model = a or model = b) and status = 200').canonical,
    '(model = a OR model = b) AND status = 200')
    assert.equal(parseYQL('not model = a').canonical, 'NOT (model = a)')
    const nested = parseYQL('model = a and not (cost > 1 or cost < 0.1)')
    assert.ok(nested.ok)
  })

  it('lists and emptiness', () => {
    const r = parseYQL('model in (gpt-4o, claude-3)')
    assert.ok(r.ok && r.root?.kind === 'clause' && r.root.values.length === 2)
    assert.ok(parseYQL('model not in (gpt-4o, claude-3)').ok)
    assert.equal(parseYQL('error is not empty').root?.op, 'not empty')
    assert.equal(parseYQL('tool is empty').root?.op, 'empty')
  })

  it('value kinds: cache enum, relative/exact time, numbers, quoted strings', () => {
    assert.ok(parseYQL('cache = miss').ok)
    assert.ok(parseYQL('created >= -24h').ok)
    assert.ok(parseYQL('created >= 2026-09-01').ok)
    assert.ok(parseYQL('created >= 2026-09-01T10:30').ok)
    assert.ok(parseYQL('created >= 2026-09-01T10:30:00Z').ok)
    assert.ok(parseYQL('created >= now').ok)
    assert.ok(parseYQL('cost > 1e-5').ok)
    assert.ok(parseYQL('cost = 0').ok)
    assert.equal(parseYQL('model = "my model"').root?.values[0], 'my model')
  })

  it('field aliases and case-insensitivity', () => {
    assert.equal(parseYQL('model_used = x').root?.field, 'model')
    assert.equal(parseYQL('status_code = 200').root?.field, 'status')
    assert.equal(parseYQL('duration > 1000').root?.field, 'latency')
    assert.equal(parseYQL('cache_hit = miss').root?.field, 'cache')
    assert.equal(parseYQL('request_id = abc-123').root?.field, 'request')
    assert.equal(parseYQL('MODEL = a').root?.field, 'model')
  })

  it('order tail; order-only query', () => {
    const withOrder = parseYQL('model = a order by cost desc')
    assert.ok(withOrder.ok && withOrder.order?.field === 'cost' && withOrder.order.desc)
    const asc = parseYQL('order by cost')
    assert.ok(asc.ok && asc.order?.desc === false) // Jira default ASC
    const only = parseYQL('order by created desc')
    assert.ok(only.ok && only.root === null)
  })

  it('empty and whitespace-only mean "no query"', () => {
    for (const s of ['', '   ']) {
      const r = parseYQL(s)
      assert.ok(r.ok && r.root === null && r.canonical === '')
    }
  })
})

describe('parseYQL — rejected queries', () => {
  const bad = (s: string, frag?: string) => {
    const r = parseYQL(s)
    assert.ok(!r.ok, `expected rejection: ${s}`)
    if (frag) assert.ok(r.error.includes(frag), `${s}: ${r.error}`)
  }

  it('unknown fields, keywords, malformed clauses', () => {
    bad('bogus = 1', 'unknown field')
    bad('model =')
    bad('status = abc', 'expects a number')
    bad('status = -5', 'expects a number')
    bad('cache = nope', 'cache')
    bad('created >= yesterday', 'invalid datetime')
    bad('model in ()', 'empty')
    bad('and model = a')
    bad('model = a and')
    bad('not')
    bad('(model = a')
    bad('model = a)', 'trailing')
    bad('order by bogus', 'unknown field')
    bad('tool = x order by tool', 'ordering')
    bad('order by text', 'ordering')
    bad('order created', "expected 'by'")
    bad('hello world', 'unknown field')
    bad('model = and')
    bad('model in a, b')
    bad('created ~ x', 'not supported')
    bad('error is maybe')
    bad('model is empty', 'cannot be empty')
    bad('model = "abc', 'unterminated')
    bad('model ! a', 'use != or !~')
  })

  it('length limits', () => {
    bad('model = ' + 'a'.repeat(2001), 'too long')
    assert.ok(parseYQL('model = ' + 'a'.repeat(1988)).ok)
    bad('model in (' + Array.from({ length: 41 }, (_, i) => `m${i}`).join(', ') + ')', 'too long')
  })
})

describe('chip helpers', () => {
  it('flattenAnd splits AND leaves, groups the rest', () => {
    const chain = flattenAnd(parseYQL('model = a and status = 200 and cost < 1').ok ? parseYQL('model = a and status = 200 and cost < 1').root : null)
    assert.equal(chain.leaves.length, 3)
    assert.equal(chain.rest, null)

    const or = flattenAnd(parseYQL('model = a or model = b').ok ? parseYQL('model = a or model = b').root : null)
    assert.equal(or.leaves.length, 0)
    assert.notEqual(or.rest, null)

    const mixed = flattenAnd(parseYQL('(model = a or model = b) and status = 200 and (cost < 1 or error !~ x)').root)
    assert.equal(mixed.leaves.length, 1)
    assert.equal(mixed.rest?.kind, 'binary')
  })

  it('removeLeaf rebuilds the chain; last removal empties the query', () => {
    assert.equal(parseYQL(removeLeaf('model = a and status = 200', 0)).canonical, 'status = 200')
    assert.equal(parseYQL(removeLeaf('model = a and status = 200', 1)).canonical, 'model = a')
    assert.equal(removeLeaf('model = a', 0), '')
  })

  it('appendClause ANDs in and preserves the order tail', () => {
    assert.equal(parseYQL(appendClause('', { kind: 'clause', field: 'model', op: '=', values: ['x'] }, null)).canonical, 'model = x')
    assert.equal(
      appendClause('model = a order by cost desc', { kind: 'clause', field: 'status', op: '=', values: ['200'] }, { field: 'cost', desc: true }),
      'model = a AND status = 200 order by cost desc',
    )
  })

  it('labels and quoting', () => {
    assert.equal(orderToString({ field: 'created', desc: true }), 'order by created desc')
    assert.equal(clauseToString({ kind: 'clause', field: 'model', op: 'in', values: ['a', 'b'] }), 'model in (a, b)')
    assert.equal(quoteYqlValue('my model'), '"my model"')
    assert.equal(quoteYqlValue('gpt-4o'), 'gpt-4o')
  })

  it('operator menus follow the field kind', () => {
    const model = fieldMeta('model')
    assert.ok(model && opsForField(model).includes('in'))
    const text = fieldMeta('text')
    assert.ok(text && JSON.stringify(opsForField(text)) === '["~","!~"]')
    const created = fieldMeta('created')
    assert.ok(created && opsForField(created).includes('>=') && !opsForField(created).includes('~'))
    assert.equal(fieldMeta('first_token_ms')?.name, 'ttft')
  })
})

// The canonical string is what the input commits and the server re-parses:
// every canonical output must round-trip to itself.
describe('canonical round-trips', () => {
  const cases = [
    'model = a and status = 200',
    '(model = a OR model = b) AND NOT (cost > 1)',
    'error is not empty and tool ~ search',
    'model in (a, "b c") order by created desc',
    'order by ttft desc',
    // the exact shape the add-filter builder emits
    'model ~ gpt AND status >= 400 order by created desc',
  ]
  for (const s of cases) {
    it(s, () => {
      const one = parseYQL(s)
      assert.ok(one.ok, one.ok ? '' : one.error)
      const two = parseYQL(one.canonical)
      assert.ok(two.ok)
      assert.equal(two.canonical, one.canonical)
    })
  }
})

describe('label filters', () => {
  it('parses label.<key> and refuses order and bad keys', () => {
    const ok = parseYQL('label.issue = "PAY-1"')
    assert.ok(ok.ok)
    if (ok.ok) assert.equal(ok.canonical, 'label.issue = PAY-1')
    const dotted = parseYQL('label.ci.pipeline_url ~ "https"')
    assert.ok(dotted.ok)
    const badKey = parseYQL('label.1abc = x')
    assert.equal(badKey.ok, false)
    if (!badKey.ok) assert.match(badKey.error, /invalid label key/)
    const injected = parseYQL("label.a'b = x")
    assert.equal(injected.ok, false)
    const dropped = parseYQL('label.a;drop = x')
    assert.equal(dropped.ok, false)
    const order = parseYQL('order by label.issue')
    assert.equal(order.ok, false)
    if (!order.ok) assert.match(order.error, /cannot order by label/)
    const unknown = parseYQL('nope = 1')
    assert.equal(unknown.ok, false)
    if (!unknown.ok) assert.match(unknown.error, /label\.<key>/)
  })
})
