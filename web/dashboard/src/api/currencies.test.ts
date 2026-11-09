// Currencies client contract tests: URL building, query params and wire
// passthrough of credits_scale. Runs under `node --test` with a stubbed
// fetch (same pattern as orgSettings.test.ts).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  getBudgetCaps, getCreditsLedger, getRatesCatalog,
  getUnitSpendRollup, diffRatesPack, promoteRatesPack, parseRatesRefusal,
} from './currencies.ts'
import { resetCsrf } from './transport.ts'

interface Call { url: string; init: RequestInit }
type Handler = (call: Call) => { status: number; body: unknown }

const realFetch = globalThis.fetch
const calls: Call[] = []

function installFetch(handler: Handler): void {
  calls.length = 0
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const call = { url: String(url), init: init ?? {} }
    calls.push(call)
    const res = handler(call)
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      statusText: '',
      headers: new Headers({ 'Content-Type': 'application/json' }),
      json: async () => res.body,
      text: async () => JSON.stringify(res.body),
    } as unknown as Response
  }) as typeof fetch
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('getBudgetCaps targets the flat budgets route with org_id', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/budgets?org_id=org-9')
    return {
      status: 200,
      body: {
        org_id: 'org-9', window: { from: 'x', to: 'y' }, credits_scale: '1 credit = 0.01 USD (wallet cents)',
        caps: [
          { id: 'usd_budget', used: { amount: 12.5, unit: 'USD', family: 'money', fidelity: 'metered' }, limit: 100, status: 'ok' },
          { id: 'carbon_cap', used: { amount: null, unit: 'gCO2e', family: 'impact', fidelity: 'unknown' }, limit: null, status: 'unknown' },
        ],
      },
    }
  })
  const caps = await getBudgetCaps('org-9')
  assert.equal(caps.caps[1].limit, null, 'carbon unknown must stay null, never 0')
  assert.equal(caps.caps[1].used.amount, null)
})

test('getCreditsLedger sends limit and reflects the served page', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/credits/ledger?org_id=org-2&limit=500')
    return { status: 200, body: { org_id: 'org-2', transactions: [], transaction_count: 100 } }
  })
  const view = await getCreditsLedger('org-2', 500)
  assert.equal(view.transaction_count, 100, 'the server clamped 500 -> 100; the page reflects the served count')
})

test('getRatesCatalog is session-scoped with no org query', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/rates/catalog')
    return {
      status: 200,
      body: {
        ref: {
          version: 'v2026-11-01.1', digest: 'sha256:abc123', generated_at: '2026-11-01T00:00:00Z',
          review_sla_days: 90, pack_digest: 'sha256:def456', notices: [], provenance: 'reference',
        },
        catalog: { schema_version: 1, version: 'v2026-11-01.1', generated_at: '2026-11-01T00:00:00Z', source: 'tool', models: [] },
      },
    }
  })
  const cat = await getRatesCatalog()
  assert.equal(cat.ref.digest, 'sha256:abc123')
  assert.deepEqual(cat.catalog.models, [])
})

// The three slice-5 call functions (units spend rollup + rates diff/promote)
// shipped together with their UI surfaces and the serving backend
// (ENTRY-AFTER-currencies-be merge order — delivery record slice 5).

test('getUnitSpendRollup builds the window query; empty window sends no from/to', async () => {
  installFetch(call => {
    assert.ok(call.url.startsWith('/api/units/spend?org_id=org-4'), `unexpected route: ${call.url}`)
    return {
      status: 200,
      body: {
        org_id: 'org-4', window: { from: '2026-10-01T00:00:00Z', to: '2026-10-31T00:00:00Z' },
        requests: 42, lines: [], credits_scale: '1 credit = 0.01 USD (wallet cents)',
        pricing: { pricing_as_of: '2026-11-01' },
        unknown_usage_rows: 0, unmodeled_carbon_rows: 0, legacy_cost_rows: 0,
      },
    }
  })
  const rollup = await getUnitSpendRollup('org-4', {
    from: '2026-10-01T00:00:00Z', to: '2026-11-01T00:00:00Z',
  })
  assert.equal(rollup.requests, 42)
  assert.equal(rollup.window.to, '2026-10-31T00:00:00Z', 'the SERVED window wins, not the request')
  await getUnitSpendRollup('org-4')
  assert.equal(calls[0].url, '/api/units/spend?org_id=org-4&from=2026-10-01T00%3A00%3A00Z&to=2026-11-01T00%3A00%3A00Z')
  assert.equal(calls[1].url, '/api/units/spend?org_id=org-4', 'no bounds -> server default window')
})

const mutation = (call: Call): boolean => {
  if (call.url === '/auth/csrf') return false // sendMutation bootstrap, not the action
  return true
}

test('diffRatesPack posts pack+reason as a mutation', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    assert.equal(call.url, '/api/rates/diff')
    assert.equal(call.init.method, 'POST')
    assert.equal(call.init.body, JSON.stringify({ pack: '{"schema_version":1}', reason: 'review' }))
    return {
      status: 200,
      body: {
        from: R_REF, to: R_REF, rendered: '', added: 1, removed: 0, changed: 2,
        review_needed: false, flags: [], refused: false,
      },
    }
  })
  const report = await diffRatesPack('{"schema_version":1}', 'review')
  assert.equal(report.refused, false)
  assert.equal(calls.filter(mutation).length, 1, 'exactly one action request besides the CSRF bootstrap')
})

test('promoteRatesPack posts the mandatory reason verbatim', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    assert.equal(call.url, '/api/rates/promote')
    assert.equal(call.init.body, JSON.stringify({ pack: 'P', reason: 'sla rollover' }))
    return { status: 200, body: { before: R_REF, after: R_REF, applied: true } }
  })
  const promo = await promoteRatesPack('P', 'sla rollover')
  assert.equal(promo.applied, true)
})

test('parseRatesRefusal extracts the 422 envelope only from a real refusal', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    return {
      status: 422,
      body: {
        refused: true, refusal_reason: 'flag:price-dropped',
        report: { from: R_REF, to: R_REF, rendered: '', added: 0, removed: 0, changed: 0, review_needed: true, flags: [], refused: true },
      },
    }
  })
  const err = await diffRatesPack('P').then(() => null, (e: unknown) => e)
  assert.ok(err instanceof Error, 'refusal surfaces as ApiError')
  const env = parseRatesRefusal(err)
  assert.ok(env, 'the 422 body parses as a refusal envelope')
  assert.equal(env?.refusal_reason, 'flag:price-dropped')
  assert.equal(env?.report.review_needed, true)
  // non-422 / non-refusal bodies return null, never a half envelope
  assert.equal(parseRatesRefusal(new Error('x')), null)
  assert.equal(parseRatesRefusal({ status: 422, body: '{"error":"bad pack"}' }), null)
})

const R_REF = {
  version: 'v2026-11-01.1', digest: 'sha256:aaa', generated_at: '2026-11-01T00:00:00Z',
  review_sla_days: 90, pack_digest: 'sha256:bbb', notices: [], provenance: 'reference',
}
