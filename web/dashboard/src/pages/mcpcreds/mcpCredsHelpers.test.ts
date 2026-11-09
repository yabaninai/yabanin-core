// MC-4 unit tests for the MCP credentials page helpers: the mask contract,
// the status→tone/label maps, the secret payload builders (store-parity
// validation, one-shot serialization) and the row assembly. Pure node --test,
// no DOM — the same pattern as providerKeysHelpers.test.ts.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  agentIdsWithoutGrant, assembleServerRows, buildHeadersPayload, buildOauthPayload,
  maskSecretLast4, statusLabelKey, statusTone,
  type HeaderPairDraft, type OauthDraft,
} from './mcpCredsHelpers.ts'
import type { McpGrant, McpServer, McpServerCredential, McpUserCredStatus } from '../../api/mcpCredentials'

test('maskSecretLast4 renders •••• + the fragment and never invents one', () => {
  assert.equal(maskSecretLast4('ab12'), '••••ab12')
  assert.equal(maskSecretLast4(' ab12 '), '••••ab12')
  assert.equal(maskSecretLast4(''), '')
  assert.equal(maskSecretLast4(null), '')
  assert.equal(maskSecretLast4(undefined), '')
})

test('statusTone maps the five statuses to the Astra color semantics', () => {
  assert.equal(statusTone('active'), 'success')
  assert.equal(statusTone('pending'), 'warning')
  assert.equal(statusTone('needs_update'), 'warning')
  assert.equal(statusTone('needs_reauth'), 'danger')
  assert.equal(statusTone('orphaned'), 'muted')
})

test('statusLabelKey returns a static key per status (i18n gate safety)', () => {
  const statuses: McpUserCredStatus[] = ['active', 'pending', 'orphaned', 'needs_reauth', 'needs_update']
  for (const status of statuses) {
    assert.match(statusLabelKey(status), /^mcpCreds\.status[A-Za-z]+$/)
  }
  assert.equal(new Set(statuses.map(statusLabelKey)).size, statuses.length)
})

test('buildHeadersPayload accepts a valid single pair and serializes verbatim', () => {
  const result = buildHeadersPayload([{ name: 'Authorization', value: 'Bearer sk-test-123' }])
  assert.deepEqual(result, { ok: true, payload: { Authorization: 'Bearer sk-test-123' } })
})

test('buildHeadersPayload skips blank rows but rejects half-filled ones', () => {
  assert.equal(buildHeadersPayload([{ name: '', value: '' }]).ok, false)
  assert.equal((buildHeadersPayload([{ name: '', value: '' }]) as { problem: string }).problem, 'empty')
  assert.equal((buildHeadersPayload([{ name: 'X', value: '' }]) as { problem: string }).problem, 'missingValue')
  assert.equal((buildHeadersPayload([{ name: '', value: 'v' }]) as { problem: string }).problem, 'missingName')
})

test('buildHeadersPayload rejects header injection and duplicates (store parity)', () => {
  assert.equal((buildHeadersPayload([{ name: 'X', value: 'a\nb' }]) as { problem: string }).problem, 'crlf')
  assert.equal((buildHeadersPayload([{ name: 'X', value: 'a\rb' }]) as { problem: string }).problem, 'crlf')
  assert.equal((buildHeadersPayload([{ name: 'X', value: 'a\0b' }]) as { problem: string }).problem, 'crlf')
  assert.equal(
    (buildHeadersPayload([{ name: 'X-A', value: '1' }, { name: 'X-A', value: '2' }]) as { problem: string }).problem,
    'duplicate',
  )
  // invalid header name (space, non-token)
  assert.equal((buildHeadersPayload([{ name: 'bad name', value: 'v' }]) as { problem: string }).problem, 'missingName')
})

const SECRET = 'Bearer sk-live-9f8e7d6c5b4a'

test('buildHeadersPayload keeps the full value in the payload only — trimming names, never values', () => {
  const result = buildHeadersPayload([{ name: '  Authorization  ', value: SECRET }])
  assert.ok(result.ok)
  assert.equal(result.payload.Authorization, SECRET)
})

test('buildOauthPayload requires the client config the MC-3 flows read', () => {
  const base: OauthDraft = {
    clientId: 'cid', clientSecret: 'sec', authUrl: 'https://idp.test/auth', tokenUrl: 'https://idp.test/token', scopes: '',
  }
  assert.equal(buildOauthPayload(base).ok, true)
  for (const field of ['clientId', 'clientSecret'] as const) {
    const broken = { ...base, [field]: '' }
    assert.equal(buildOauthPayload(broken).ok, false)
  }
  assert.equal(buildOauthPayload({ ...base, authUrl: 'http://idp.test/auth' }).ok, false)
  assert.equal(buildOauthPayload({ ...base, tokenUrl: 'ftp://x' }).ok, false)
  const withScopes = buildOauthPayload({ ...base, scopes: 'read write' })
  assert.ok(withScopes.ok && withScopes.payload.scopes === 'read write')
})

const SERVER: McpServer = {
  id: 'mcp-1', org_id: 'org-1', name: 'search', url: 'https://mcp.example.test',
  transport: 'http', allowed_tools: [], enabled: true,
}

function cred(name: string): McpServerCredential {
  return {
    server_name: name, kind: 'headers', secret_last4: 'ab12', has_secret: true,
    enabled: true, version: 2, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-02T00:00:00Z',
  }
}

test('assembleServerRows joins servers with their credential; missing stays null', () => {
  const servers = [SERVER, { ...SERVER, id: 'mcp-2', name: 'web' }]
  const rows = assembleServerRows(servers, [cred('web'), null])
  assert.equal(rows[0]?.cred, null)
  assert.equal(rows[1]?.cred?.server_name, 'web')
})

test('assembleServerRows ignores credentials for unknown servers (never invents a row)', () => {
  const rows = assembleServerRows([SERVER], [cred('ghost')])
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.cred, null)
})

test('agentIdsWithoutGrant lists only disabled grants (revoked → orphaned signal)', () => {
  const grants: McpGrant[] = [
    { id: 'g1', org_id: 'o', agent_id: 'agent-1', server_name: 'search', allowed_tools: [], enabled: true, created_at: '', updated_at: '' },
    { id: 'g2', org_id: 'o', agent_id: 'agent-2', server_name: 'search', allowed_tools: [], enabled: false, created_at: '', updated_at: '' },
  ]
  assert.deepEqual([...agentIdsWithoutGrant(grants)], ['agent-2'])
})

test('a headers payload round-trips through JSON.stringify as the PUT body would', () => {
  const pairs: HeaderPairDraft[] = [{ name: 'X-API-Key', value: 'tok_abc123' }]
  const result = buildHeadersPayload(pairs)
  assert.ok(result.ok)
  const body = JSON.stringify({ kind: 'headers', secret: result.payload })
  assert.equal(body, '{"kind":"headers","secret":{"X-API-Key":"tok_abc123"}}')
})
