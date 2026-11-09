// W-CAPS unit tests for the org caps API client: contract shape (URL,
// method, body, X-Audit-Reason), null-means-beta-default honesty, and typed
// error propagation. Runs under `node --test` with a stubbed fetch (same
// pattern as orgSettings.test.ts).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  getOrgCaps, updateOrgCaps, isValidOrgCapsValue, isValidOrgCapsBudgetCents,
  ORG_CAPS_MAX_VALUE, ORG_CAPS_MAX_BUDGET_CENTS,
} from './orgCaps.ts'
import { ApiError, resetCsrf } from './transport.ts'

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

const betaBlock = {
  org_id: 'org-wcaps',
  rpm: 60,
  tpm: 200_000,
  monthly_budget_cents: 5_000_000,
  input_tokens_per_min: 0,
  output_tokens_per_min: 0,
  key_tokens_per_min: 0,
  month_spend_cents: 4_900_000,
  budget_exceeded: false,
  rpm_override: null,
  tpm_override: null,
  monthly_budget_override_cents: null,
  input_tokens_per_min_override: null,
  output_tokens_per_min_override: null,
  key_tokens_per_min_override: null,
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('getOrgCaps GETs the caps endpoint and parses the effective block', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/orgs/org-wcaps/caps')
    return { status: 200, body: betaBlock }
  })
  const caps = await getOrgCaps('org-wcaps')
  assert.equal(caps.rpm, 60)
  assert.equal(caps.tpm, 200_000)
  assert.equal(caps.monthly_budget_cents, 5_000_000)
  assert.equal(caps.rpm_override, null, 'null = beta default, never "unlimited"')
  assert.equal(caps.input_tokens_per_min, 0, 'OP-19 split dimensions have no beta default — 0 = off')
  assert.equal(caps.input_tokens_per_min_override, null)
  assert.equal(caps.budget_exceeded, false)
})

test('updateOrgCaps PUTs the full sextuple with X-Audit-Reason and returns the new block', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-wcaps' } }
    assert.equal(call.url, '/api/orgs/org-wcaps/caps')
    assert.equal(call.init.method, 'PUT')
    const headers = new Headers(call.init.headers as HeadersInit)
    assert.equal(headers.get('X-Audit-Reason'), 'beta scale-up')
    assert.deepEqual(JSON.parse(String(call.init.body)), {
      rpm: 120,
      tpm: null,
      monthly_budget_cents: 10_000_000,
      input_tokens_per_min: 300_000,
      output_tokens_per_min: null,
      key_tokens_per_min: null,
      reason: 'beta scale-up',
    })
    return {
      status: 200,
      body: {
        ...betaBlock,
        rpm: 120,
        monthly_budget_cents: 10_000_000,
        input_tokens_per_min: 300_000,
        rpm_override: 120,
        monthly_budget_override_cents: 10_000_000,
        input_tokens_per_min_override: 300_000,
      },
    }
  })
  const caps = await updateOrgCaps('org-wcaps', {
    rpm: 120,
    tpm: null,
    monthly_budget_cents: 10_000_000,
    input_tokens_per_min: 300_000,
    output_tokens_per_min: null,
    key_tokens_per_min: null,
    reason: 'beta scale-up',
  })
  assert.equal(caps.rpm, 120)
  assert.equal(caps.tpm, 200_000, 'the cleared override lands back on the beta default')
  assert.equal(caps.input_tokens_per_min, 300_000, 'the set split window is effective')
  assert.equal(caps.output_tokens_per_min, 0, 'a cleared split dimension lands back on off')
})

test('updateOrgCaps propagates typed errors (403/404)', async () => {
  for (const status of [403, 404]) {
    installFetch(call => {
      if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-wcaps' } }
      return { status, body: { error: 'denied' } }
    })
    await assert.rejects(
      updateOrgCaps('org-wcaps', {
        rpm: null, tpm: null, monthly_budget_cents: null,
        input_tokens_per_min: null, output_tokens_per_min: null, key_tokens_per_min: null,
        reason: 'x',
      }),
      (e: unknown) => e instanceof ApiError && e.status === status,
    )
  }
})

test('validators: null passes, integers in range pass, everything else fails', () => {
  assert.equal(isValidOrgCapsValue(null), true)
  assert.equal(isValidOrgCapsValue(1), true)
  assert.equal(isValidOrgCapsValue(ORG_CAPS_MAX_VALUE), true)
  assert.equal(isValidOrgCapsValue(0), false, '0 would mean unlimited-by-omission downstream')
  assert.equal(isValidOrgCapsValue(-1), false)
  assert.equal(isValidOrgCapsValue(ORG_CAPS_MAX_VALUE + 1), false)
  assert.equal(isValidOrgCapsValue(1.5), false)

  assert.equal(isValidOrgCapsBudgetCents(null), true)
  assert.equal(isValidOrgCapsBudgetCents(5_000_000), true)
  assert.equal(isValidOrgCapsBudgetCents(0), false)
  assert.equal(isValidOrgCapsBudgetCents(ORG_CAPS_MAX_BUDGET_CENTS + 1), false)
  assert.equal(isValidOrgCapsBudgetCents(50.5), false)
})
