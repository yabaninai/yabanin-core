// W-WELCOME unit tests for the onboarding-flag client: contract shape (the
// org target rides the ?org_id= query on BOTH verbs), honest degradation
// (any failure → null / false, never a throw) and payload validation (shape
// drift degrades to null instead of trusting a partial object).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import { getOrgOnboarding, markOrgOnboarding } from './onboarding.ts'
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

function csrfAware(handler: Handler): Handler {
  return call => (call.url === '/auth/csrf'
    ? { status: 200, body: { csrf_token: 'tok-welcome' } }
    : handler(call))
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('getOrgOnboarding: GET /api/me/onboarding?org_id=… returns the parsed state', async () => {
  installFetch(csrfAware(() => ({
    status: 200,
    body: { org_id: 'org-welcome', completed: false, skipped: true },
  })))

  const state = await getOrgOnboarding('org-welcome')
  assert.deepEqual(state, { org_id: 'org-welcome', completed: false, skipped: true })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/api/me/onboarding?org_id=org-welcome')
})

test('getOrgOnboarding: failures and shape drift degrade to null', async () => {
  installFetch(csrfAware(() => ({ status: 501, body: { error: 'onboarding persistence not supported' } })))
  assert.equal(await getOrgOnboarding('org-welcome'), null, '501 (capability off) is state-unknown')

  installFetch(csrfAware(() => ({ status: 404, body: { error: 'not found' } })))
  assert.equal(await getOrgOnboarding('org-welcome'), null, '404 (old backend) is state-unknown')

  installFetch(csrfAware(() => ({ status: 200, body: { org_id: 'org-welcome' } })))
  assert.equal(await getOrgOnboarding('org-welcome'), null, 'missing flags must not be trusted')
})

test('markOrgOnboarding: POST carries the org in the query and exactly one flag in the body', async () => {
  installFetch(csrfAware(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-welcome' } }
    assert.equal(call.init.method, 'POST')
    return { status: 200, body: { status: 'ok' } }
  }))
  const onbCalls = () => calls.filter(c => c.url.startsWith('/api/me/onboarding'))

  assert.equal(await markOrgOnboarding('org skip', { skipped: true }), true)
  assert.equal(onbCalls()[0].url, '/api/me/onboarding?org_id=org%20skip')
  assert.deepEqual(JSON.parse(String(onbCalls()[0].init.body)), { completed: false, skipped: true })

  assert.equal(await markOrgOnboarding('org skip', { completed: true }), true)
  assert.deepEqual(JSON.parse(String(onbCalls()[1].init.body)), { completed: true, skipped: false })
})

test('markOrgOnboarding: a failed mark answers false (best-effort persistence)', async () => {
  installFetch(csrfAware(() => ({ status: 403, body: { error: 'insufficient role for this organization' } })))
  assert.equal(await markOrgOnboarding('org-welcome', { completed: true }), false)
})
