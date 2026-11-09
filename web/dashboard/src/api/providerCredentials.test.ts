// W-BYOK (card W-BYOK-UI) unit tests for the provider-credentials client:
// frozen-contract shape (URL, method, body), secret hygiene (the key rides
// the body only — never a URL, never kept by the module) and the test
// endpoint result. Runs under `node --test` with a stubbed fetch (same
// pattern as orgSettings.test.ts / transport.test.ts).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  createProviderCredential, deleteProviderCredential, listProviderCredentials,
  testProviderCredential, updateProviderCredential,
  type ProviderCredential,
} from './providerCredentials.ts'
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
    ? { status: 200, body: { csrf_token: 'tok-wbyok' } }
    : handler(call))
}

const CRED: ProviderCredential = {
  id: 'cred-1', org_id: 'org-wbyok', name: 'prod-openai', provider: 'openai',
  base_url: 'https://api.example.com/v1', key_last4: '1234', enabled: true,
  key_version: 2, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-02T00:00:00Z',
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('listProviderCredentials GETs the contract route and parses a plain array', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/orgs/org-wbyok/provider-credentials')
    assert.equal(call.init.method, undefined) // readJSON defaults to GET
    return { status: 200, body: [CRED] }
  })
  const list = await listProviderCredentials('org-wbyok')
  assert.equal(list.length, 1)
  assert.equal(list[0]?.key_last4, '1234')
})

test('listProviderCredentials tolerates a {data:[…]} envelope and a junk body', async () => {
  installFetch(() => ({ status: 200, body: { data: [CRED] } }))
  assert.equal((await listProviderCredentials('org-wbyok')).length, 1)
  installFetch(() => ({ status: 200, body: {} }))
  assert.deepEqual(await listProviderCredentials('org-wbyok'), [])
})

test('createProviderCredential POSTs {name, provider, base_url, key} — key never in the URL', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/orgs/org-wbyok/provider-credentials')
    assert.equal(call.init.method, 'POST')
    assert.deepEqual(JSON.parse(String(call.init.body)), {
      name: 'prod-openai', provider: 'openai', base_url: 'https://api.example.com/v1', key: 'sk-secret-wbyok',
    })
    return { status: 201, body: CRED }
  }))
  const cred = await createProviderCredential('org-wbyok', {
    name: 'prod-openai', provider: 'openai', base_url: 'https://api.example.com/v1', key: 'sk-secret-wbyok',
  })
  assert.equal(cred.id, 'cred-1')
  for (const call of calls) {
    assert.equal(call.url.includes('sk-secret-wbyok'), false, 'the raw key must never ride the URL')
  }
})

test('updateProviderCredential PUTs only the provided fields (key omitted stays omitted)', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/orgs/org-wbyok/provider-credentials/cred-1')
    assert.equal(call.init.method, 'PUT')
    assert.deepEqual(JSON.parse(String(call.init.body)), { name: 'renamed', enabled: false })
    return { status: 200, body: { ...CRED, name: 'renamed', enabled: false } }
  }))
  await updateProviderCredential('org-wbyok', 'cred-1', { name: 'renamed', enabled: false })
})

test('updateProviderCredential sends a rotated key when present and URL-encodes the cred id', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/orgs/org-wbyok/provider-credentials/cred%2F1')
    assert.equal(call.init.method, 'PUT')
    assert.deepEqual(JSON.parse(String(call.init.body)), { key: 'sk-rotated' })
    return { status: 200, body: { ...CRED, key_version: 3 } }
  }))
  await updateProviderCredential('org-wbyok', 'cred/1', { key: 'sk-rotated' })
})

test('deleteProviderCredential DELETEs the cred route', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/orgs/org-wbyok/provider-credentials/cred-1')
    assert.equal(call.init.method, 'DELETE')
    return { status: 204, body: null }
  }))
  await deleteProviderCredential('org-wbyok', 'cred-1')
})

test('testProviderCredential POSTs …/test and returns {ok, status?, error?}', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/orgs/org-wbyok/provider-credentials/cred-1/test')
    assert.equal(call.init.method, 'POST')
    return { status: 200, body: { ok: true, status: 200 } }
  }))
  const ok = await testProviderCredential('org-wbyok', 'cred-1')
  assert.equal(ok.ok, true)
  assert.equal(ok.status, 200)

  installFetch(csrfAware(() => ({ status: 200, body: { ok: false, status: 401, error: 'invalid key' } })))
  const fail = await testProviderCredential('org-wbyok', 'cred-1')
  assert.equal(fail.ok, false)
  assert.equal(fail.error, 'invalid key')
})

test('the module keeps no state between calls: a second create carries only its own key', async () => {
  const postBodies: string[] = []
  installFetch(csrfAware(call => {
    if (call.init.method === 'POST') postBodies.push(String(call.init.body))
    return { status: 201, body: CRED }
  }))
  await createProviderCredential('org-wbyok', { name: 'a', provider: 'openai', base_url: 'https://x', key: 'sk-first' })
  await createProviderCredential('org-wbyok', { name: 'b', provider: 'openai', base_url: 'https://x', key: 'sk-second' })
  assert.equal(postBodies.length, 2)
  assert.equal((JSON.parse(postBodies[0]) as { key: string }).key, 'sk-first')
  assert.equal(
    (JSON.parse(postBodies[1]) as { key: string }).key,
    'sk-second',
    'the first key must not leak into the second request',
  )
})
