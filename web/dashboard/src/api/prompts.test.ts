// prompt_studio.go). Runs under `node --test` with a stubbed fetch (same
// pattern as routing.test.ts).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  listPrompts, createPrompt, getPrompt, updatePrompt, promotePromptLabel, deletePrompt,
  listPartials, createPartial, updatePartial, deletePartial,
} from './prompts.ts'

interface Call { url: string; init: RequestInit }
type Handler = (call: Call) => { status: number; body: unknown }

const realFetch = globalThis.fetch
const calls: Call[] = []

function installFetch(handler: Handler): void {
  calls.length = 0
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const call = { url: String(url), init: init ?? {} }
    // Mutations load the CSRF token first (transport contract) — answer it.
    if (call.url === '/auth/csrf') return jsonRes(200, { csrf_token: 'tok-test' })
    calls.push(call)
    const res = handler(call)
    return jsonRes(res.status, res.body)
  }) as typeof fetch
}

function jsonRes(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    headers: new Headers({ 'Content-Type': 'application/json' }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response
}

afterEach(() => {
  globalThis.fetch = realFetch
})

const DETAIL = {
  prompt: { id: 'p1', org_id: 'org-1', name: 'judge-basic', description: 'd', created_at: 't', updated_at: 't' },
  versions: [{ id: 'v1', prompt_id: 'p1', org_id: 'org-1', version: 1, template: 'Hi {{name}}', params: null, created_by: 'root', created_at: 't' }],
  labels: [{ prompt_id: 'p1', org_id: 'org-1', label: 'draft', version: 1, updated_at: 't' }],
}

test('listPrompts GETs /api/organizations/{id}/prompts and unwraps data', async () => {
  installFetch(() => ({ status: 200, body: { data: [DETAIL.prompt], count: 1 } }))
  const rows = await listPrompts('org 1')
  assert.equal(calls.length, 1)
  assert.equal(calls[0]!.url, '/api/organizations/org%201/prompts')
  assert.equal(calls[0]!.init.method, undefined, 'list is a read — no method override')
  assert.deepEqual(rows, [DETAIL.prompt])
})

test('listPrompts tolerates a missing data array', async () => {
  installFetch(() => ({ status: 200, body: {} }))
  assert.deepEqual(await listPrompts('o'), [])
})

test('createPrompt POSTs name/description/template/params and returns the 201 detail', async () => {
  installFetch(() => ({ status: 201, body: DETAIL }))
  const input = { name: 'judge-basic', description: 'd', template: 'Hi {{name}}', params: { model: 'm1' } }
  const detail = await createPrompt('org-1', input)
  assert.equal(calls[0]!.url, '/api/organizations/org-1/prompts')
  assert.equal(calls[0]!.init.method, 'POST')
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), input)
  assert.equal(detail.prompt.id, 'p1')
  assert.equal(detail.labels?.length, 1)
})

test('getPrompt GETs the nested prompt path with the encoded id', async () => {
  installFetch(() => ({ status: 200, body: DETAIL }))
  await getPrompt('org-1', 'p/1')
  assert.equal(calls[0]!.url, '/api/organizations/org-1/prompts/p%2F1')
})

test('updatePrompt PUTs only template/params', async () => {
  installFetch(() => ({ status: 200, body: { ...DETAIL, versions: [] } }))
  await updatePrompt('org-1', 'p1', { version: 1, template: 'v2 {{q}}' })
  assert.equal(calls[0]!.init.method, 'PUT')
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), { version: 1, template: 'v2 {{q}}' })
})

test('promotePromptLabel POSTs the {label, version} binding', async () => {
  installFetch(() => ({ status: 200, body: { label: DETAIL.labels![0] } }))
  const out = await promotePromptLabel('org-1', 'p1', 'active', 2)
  assert.equal(calls[0]!.url, '/api/organizations/org-1/prompts/p1/labels')
  assert.equal(calls[0]!.init.method, 'POST')
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), { label: 'active', version: 2 })
  assert.equal(out.label.version, 1)
})

test('deletePrompt sends DELETE and returns the status body', async () => {
  installFetch(() => ({ status: 200, body: { status: 'deleted' } }))
  const out = await deletePrompt('org-1', 'p1')
  assert.equal(calls[0]!.init.method, 'DELETE')
  assert.deepEqual(out, { status: 'deleted' })
})

test('partials CRUD hits the flat /partials surface (PUT = version+1)', async () => {
  installFetch(() => ({ status: 200, body: {} }))
  await listPartials('org-1')
  assert.equal(calls[0]!.url, '/api/organizations/org-1/partials')

  await createPartial('org-1', { name: 'tone', body: 'Be brief.' })
  assert.equal(calls[1]!.init.method, 'POST')
  assert.deepEqual(JSON.parse(String(calls[1]!.init.body)), { name: 'tone', body: 'Be brief.' })

  await updatePartial('org-1', 'tone', 'Be terse.', 1)
  assert.equal(calls[2]!.url, '/api/organizations/org-1/partials/tone')
  assert.equal(calls[2]!.init.method, 'PUT')
  assert.deepEqual(JSON.parse(String(calls[2]!.init.body)), { body: 'Be terse.', version: 1 })

  await deletePartial('org-1', 'tone')
  assert.equal(calls[3]!.init.method, 'DELETE')
})

test('409 duplicate name surfaces as a thrown ApiError with the server message', async () => {
  installFetch(() => ({ status: 409, body: { error: 'a resource with this name already exists in this organization' } }))
  await assert.rejects(
    () => createPrompt('org-1', { name: 'x', template: 't' }),
    (err: unknown) => err instanceof Error && err.message.includes('409'),
  )
})
