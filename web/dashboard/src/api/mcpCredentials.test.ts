// MC-4 unit tests for the MCP credentials client: frozen-contract shapes
// (URL, method, body), secret hygiene (values ride the body exactly once —
// never a URL, never retained by the module), the masked-read contract and
// the honest `null` for the not-yet-mounted user-credentials list endpoint.
// Runs under `node --test` with a stubbed fetch (providerCredentials.test.ts
// pattern).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  beginMcpUserOAuth, deleteMcpGrant, deleteMcpServerCredential, deleteMcpUserCredential,
  getMcpServerCredential, listMcpGrants, listMcpUserCredentials, putMcpServerCredential,
  submitMcpUserHeaders, type McpServerCredential, type McpUserCredential,
} from './mcpCredentials.ts'
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
    ? { status: 200, body: { csrf_token: 'tok-mc4' } }
    : handler(call))
}

const CRED: McpServerCredential = {
  server_name: 'search', kind: 'headers', secret_last4: 'ab12', has_secret: true,
  enabled: true, version: 3, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-02T00:00:00Z',
}

const USER_CRED: McpUserCredential = {
  id: 'uc-1', org_id: 'org-mc4', server_id: 'srv-1', server_name: 'search',
  agent_key_id: 'agent-9', kind: 'headers', secret_last4: 'xy98', status: 'active',
  version: 1, expires_at: null, created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-03T00:00:00Z', has_secret: true,
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('getMcpServerCredential GETs the masked row; a 404 reads as null (no credential)', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/servers/search/credential')
    assert.equal(call.init.method, undefined)
    return { status: 200, body: CRED }
  })
  const cred = await getMcpServerCredential('org-mc4', 'search')
  assert.equal(cred?.secret_last4, 'ab12')
  assert.equal(cred?.has_secret, true)

  installFetch(() => ({ status: 404, body: { error: 'mcp server or credential not found' } }))
  assert.equal(await getMcpServerCredential('org-mc4', 'search'), null)
})

test('putMcpServerCredential PUTs {kind, secret} with the secret object verbatim in the body — never the URL', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/servers/search/credential')
    assert.equal(call.init.method, 'PUT')
    assert.deepEqual(JSON.parse(String(call.init.body)), {
      kind: 'headers',
      secret: { Authorization: 'Bearer sk-live-secret' },
    })
    return { status: 200, body: CRED }
  }))
  const cred = await putMcpServerCredential('org-mc4', 'search', {
    kind: 'headers', secret: { Authorization: 'Bearer sk-live-secret' },
  })
  assert.equal(cred.server_name, 'search')
  for (const call of calls) {
    assert.equal(call.url.includes('sk-live-secret'), false, 'the secret must never ride the URL')
  }
})

test('putMcpServerCredential URL-encodes the server name', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/servers/web%20search/credential')
    return { status: 200, body: CRED }
  }))
  await putMcpServerCredential('org-mc4', 'web search', { kind: 'headers', secret: { X: '1' } })
})

test('deleteMcpServerCredential DELETEs the credential route', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/servers/search/credential')
    assert.equal(call.init.method, 'DELETE')
    return { status: 200, body: { status: 'deleted' } }
  }))
  await deleteMcpServerCredential('org-mc4', 'search')
})

test('listMcpGrants parses a plain array and tolerates junk bodies as empty', async () => {
  const grant = { id: 'g1', org_id: 'org-mc4', agent_id: 'agent-9', server_name: 'search', allowed_tools: [], enabled: true, created_at: '', updated_at: '' }
  installFetch(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/servers/search/grants')
    return { status: 200, body: [grant] }
  })
  assert.equal((await listMcpGrants('org-mc4', 'search')).length, 1)
  installFetch(() => ({ status: 200, body: {} }))
  assert.deepEqual(await listMcpGrants('org-mc4', 'search'), [])
})

test('deleteMcpGrant DELETEs the per-agent grant route (revoking orphans user creds server-side)', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/servers/search/grants/agent-9')
    assert.equal(call.init.method, 'DELETE')
    return { status: 200, body: {} }
  }))
  await deleteMcpGrant('org-mc4', 'search', 'agent-9')
})

test('listMcpUserCredentials parses the rows; a 404 or a non-array body reads as null (endpoint missing)', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/user-credentials')
    return { status: 200, body: [USER_CRED] }
  })
  const rows = await listMcpUserCredentials('org-mc4')
  assert.equal(rows?.length, 1)
  assert.equal(rows?.[0]?.status, 'active')
  assert.equal(rows?.[0]?.has_secret, true)
  assert.equal(rows?.[0]?.secret_last4, 'xy98')

  installFetch(() => ({ status: 404, body: { error: 'not found' } }))
  assert.equal(await listMcpUserCredentials('org-mc4'), null, 'a backend without the route answers null')

  installFetch(() => ({ status: 200, body: {} }))
  assert.equal(await listMcpUserCredentials('org-mc4'), null, 'the {} stub fallback is null, not a fake empty list')

  installFetch(() => ({ status: 200, body: { data: [USER_CRED] } }))
  assert.equal((await listMcpUserCredentials('org-mc4'))?.length, 1)
})

test('deleteMcpUserCredential DELETEs the proposed per-(server, agent) admin route', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/organizations/org-mc4/mcp/user-credentials/search/agent-9')
    assert.equal(call.init.method, 'DELETE')
    return { status: 200, body: {} }
  }))
  await deleteMcpUserCredential('org-mc4', 'search', 'agent-9')
})

test('submitMcpUserHeaders POSTs the gateway flow route with the headers object once', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/mcp/credentials/search')
    assert.equal(call.init.method, 'POST')
    assert.deepEqual(JSON.parse(String(call.init.body)), { headers: { Authorization: 'Bearer agent-secret' } })
    return { status: 200, body: USER_CRED }
  }))
  const row = await submitMcpUserHeaders('org-mc4', 'search', { Authorization: 'Bearer agent-secret' })
  assert.equal(row.agent_key_id, 'agent-9')
  for (const call of calls) {
    assert.equal(call.url.includes('agent-secret'), false, 'the header value must never ride the URL')
  }
})

test('beginMcpUserOAuth POSTs the begin route and returns {url, state, redirect}', async () => {
  installFetch(csrfAware(call => {
    assert.equal(call.url, '/api/mcp/auth/search/begin')
    assert.equal(call.init.method, 'POST')
    return { status: 200, body: { url: 'https://idp.test/authorize?x=1', state: 'st-1', redirect: 'https://gw.test/api/mcp/auth/search/callback' } }
  }))
  const begin = await beginMcpUserOAuth('org-mc4', 'search')
  assert.equal(begin.state, 'st-1')
  assert.ok(begin.url.startsWith('https://'))
})

test('the module keeps no state between calls: a second submit carries only its own values', async () => {
  const bodies: string[] = []
  installFetch(csrfAware(call => {
    if (call.init.method === 'POST' && call.url.endsWith('/credentials/search')) bodies.push(String(call.init.body))
    return { status: 200, body: USER_CRED }
  }))
  await submitMcpUserHeaders('org-mc4', 'search', { Authorization: 'Bearer first-secret' })
  await submitMcpUserHeaders('org-mc4', 'search', { Authorization: 'Bearer second-secret' })
  assert.equal(bodies.length, 2)
  assert.equal((JSON.parse(bodies[0]) as { headers: { Authorization: string } }).headers.Authorization, 'Bearer first-secret')
  assert.equal(
    (JSON.parse(bodies[1]) as { headers: { Authorization: string } }).headers.Authorization,
    'Bearer second-secret',
    'the first secret must not leak into the second request',
  )
})
