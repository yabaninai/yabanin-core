// This is the endpoint whose typed stub exists BECAUSE the old `{}` catch-all
// put PolicyDecisionsPage on its error path (the client reads
// body.pagination) — that behavior is pinned here, not regressed away: a junk
// body must reach the page as a rejection (honest error notice), never as a
// fabricated empty success. 403 (policies.manage gate) and 5xx must surface
// as typed ApiErrors carrying the server text. Runs under `node --test`
// (prompts.test.ts pattern).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import { listPolicyDecisionRequests, listPolicyDecisions } from './policyDecisions.ts'
import { ApiError } from './transport.ts'

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
    } as Response
  }) as typeof fetch
}

afterEach(() => {
  globalThis.fetch = realFetch
})

test('listPolicyDecisions GETs the org route with page + filters (verdict, mode, policy_id)', async () => {
  installFetch(() => ({ status: 200, body: { data: [], pagination: { page: 1, page_size: 50, total: 0, total_pages: 0 } } }))
  await listPolicyDecisions('org 9', 3, { verdict: 'deny', mode: 'enforce', policyId: 'tp-1' }, 50)
  assert.equal(calls.length, 1)
  const u = new URL(calls[0]!.url, 'http://localhost')
  assert.equal(u.pathname, '/api/organizations/org%209/policy-decisions')
  assert.equal(u.searchParams.get('page'), '3')
  assert.equal(u.searchParams.get('page_size'), '50')
  assert.equal(u.searchParams.get('verdict'), 'deny')
  assert.equal(u.searchParams.get('mode'), 'enforce')
  assert.equal(u.searchParams.get('policy_id'), 'tp-1')
})

test('a typed page unwraps rows/total/totalPages; a null body is an honest zero page', async () => {
  installFetch(() => ({
    status: 200,
    body: { data: [{ id: 'd1' }], pagination: { page: 2, page_size: 50, total: 61, total_pages: 2 } },
  }))
  assert.deepEqual(await listPolicyDecisions('o', 2), {
    rows: [{ id: 'd1' }], total: 61, totalPages: 2,
  })

  installFetch(() => ({ status: 200, body: null }))
  assert.deepEqual(await listPolicyDecisions('o'), { rows: [], total: 0, totalPages: 0 })

  installFetch(() => ({ status: 200, body: { data: [{ id: 'd2' }], pagination: {} } }))
  const fallback = await listPolicyDecisions('o', 4)
  assert.equal(fallback.total, 1, 'nullish pagination fields fall back to the row count')
  assert.equal(fallback.totalPages, 4)
})

test('CORE-TRACE-01: findings arrive as an array and findings_valid passes through untouched', async () => {
  const findings = [{ step: 'in', category: 'pan', severity: 'high', span: 'arg', action: 'deny' }]
  installFetch(() => ({
    status: 200,
    body: {
      data: [{ id: 'd1', findings, findings_valid: true }, { id: 'd2', findings: [], findings_valid: false }],
      pagination: { page: 1, page_size: 50, total: 2, total_pages: 1 },
    },
  }))
  const page = await listPolicyDecisions('o')
  assert.deepEqual(page.rows[0]!.findings, findings, 'the page receives a real array (never a base64 string/null)')
  assert.equal(page.rows[0]!.findings_valid, true)
  assert.deepEqual(page.rows[1]!.findings, [], 'a degraded legacy row is an empty array, never null')
  assert.equal(page.rows[1]!.findings_valid, false)
})

test('CORE-TRACE-02: listPolicyDecisions sends entity=decisions and passes the new filters through', async () => {
  installFetch(() => ({ status: 200, body: { data: [], pagination: { page: 1, page_size: 50, total: 0, total_pages: 0 } } }))
  await listPolicyDecisions('o', 1, {
    policyVersion: 2,
    requestId: 'req-multi',
    step: 'in',
    createdFrom: '2026-11-01T00:00:00Z',
    createdTo: '2026-11-02T00:00:00Z',
  })
  assert.equal(calls.length, 1)
  const u = new URL(calls[0]!.url, 'http://localhost')
  assert.equal(u.searchParams.get('entity'), 'decisions', 'the default entity is explicit on the wire')
  assert.equal(u.searchParams.get('policy_version'), '2')
  assert.equal(u.searchParams.get('request_id'), 'req-multi')
  assert.equal(u.searchParams.get('step'), 'in')
  assert.equal(u.searchParams.get('created_from'), '2026-11-01T00:00:00Z')
  assert.equal(u.searchParams.get('created_to'), '2026-11-02T00:00:00Z')
})

test('CORE-TRACE-02: policy_version 0 reaches the wire (a real legacy value, never dropped)', async () => {
  installFetch(() => ({ status: 200, body: { data: [], pagination: { page: 1, page_size: 50, total: 0, total_pages: 0 } } }))
  await listPolicyDecisions('o', 1, { policyVersion: 0 })
  const u = new URL(calls[0]!.url, 'http://localhost')
  assert.equal(u.searchParams.get('policy_version'), '0')
})

test('CORE-TRACE-02: listPolicyDecisionRequests pages the distinct-request view (entity=requests)', async () => {
  installFetch(() => ({
    status: 200,
    body: {
      data: [
        { request_id: 'req-9', evaluations: 3, first_seen_at: '2026-11-01T10:00:00Z', last_seen_at: '2026-11-01T10:02:00Z' },
      ],
      pagination: { page: 1, page_size: 50, total: 1, total_pages: 1 },
    },
  }))
  const page = await listPolicyDecisionRequests('o', 1, { verdict: 'deny', step: 'redact' }, 50)
  assert.equal(calls.length, 1)
  const u = new URL(calls[0]!.url, 'http://localhost')
  assert.equal(u.pathname, '/api/organizations/o/policy-decisions', 'same shared endpoint')
  assert.equal(u.searchParams.get('entity'), 'requests')
  assert.equal(u.searchParams.get('verdict'), 'deny', 'the shared filters apply to the requests view too')
  assert.equal(u.searchParams.get('step'), 'redact')
  assert.equal(page.total, 1, 'totals count unique REQUESTS (three evaluations, one request)')
  assert.deepEqual(page.rows, [{
    request_id: 'req-9',
    evaluations: 3,
    first_seen_at: '2026-11-01T10:00:00Z',
    last_seen_at: '2026-11-01T10:02:00Z',
  }])
})

test('CORE-TRACE-02: a requests-view server error rejects as ApiError (no silent empty page)', async () => {
  installFetch(() => ({ status: 403, body: { error: 'missing policies.manage' } }))
  await assert.rejects(() => listPolicyDecisionRequests('o'), (e: unknown) => {
    const api = e as ApiError
    return api instanceof ApiError && api.status === 403 && api.message.includes('missing policies.manage')
  })
})

test('403 (policies.manage gate) rejects as ApiError with the server text', async () => {
  installFetch(() => ({ status: 403, body: { error: 'missing policies.manage' } }))
  await assert.rejects(() => listPolicyDecisions('o'), (e: unknown) => {
    const api = e as ApiError
    return api instanceof ApiError && api.status === 403 && api.message.includes('missing policies.manage')
  })
})

test('500 rejects as ApiError carrying the server text (the page notices, not a silent blank)', async () => {
  installFetch(() => ({ status: 500, body: { error: 'decision log unavailable' } }))
  await assert.rejects(() => listPolicyDecisions('o'), (e: unknown) => {
    const api = e as ApiError
    return api instanceof ApiError && api.status === 500 && api.message.includes('decision log unavailable')
  })
})

test('the old {} catch-all body rejects (TypeError) — never a fabricated empty success', () => {
  installFetch(() => ({ status: 200, body: {} }))
  assert.rejects(() => listPolicyDecisions('o'),
    'body.pagination is unreadable on {} — the page must land on its error state; this is why stub-api serves a typed fixture',
  )
})

test('a pagination-less body rejects too (protocol violation → the page error state, not a fake page)', () => {
  installFetch(() => ({ status: 200, body: { data: [{ id: 'd3' }] } }))
  assert.rejects(() => listPolicyDecisions('o'),
    'rows without pagination cannot silently become a page — the honest fallbacks apply only to nullish pagination FIELDS',
  )
})
