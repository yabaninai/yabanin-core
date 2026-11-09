// failure states the smoke (imp09) only exercises on its happy path. The
// screen is root-only server-side; a member deep link (#feedback) 403s, an
// old backend 404s, a degraded one 5xxs — each must reach the page as a
// typed ApiError carrying the server text (the notice renders it verbatim),
// and a superseded load must land as the AbortError shape the page filters.
// Runs under `node --test` with a stubbed fetch (prompts.test.ts pattern).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import { listFeedback, feedbackExportUrl } from './feedback.ts'
import { ApiError } from './transport.ts'

interface Call { url: string; init: RequestInit }
type Handler = (call: Call) => { status: number; body: unknown } | { status: number; raw: string }

const realFetch = globalThis.fetch
const calls: Call[] = []

function installFetch(handler: Handler): void {
  calls.length = 0
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const call = { url: String(url), init: init ?? {} }
    // The transport rejects an already-aborted scope before the caller's
    // promise matters; simulate the fetch-side abort contract.
    const signal = (init as { signal?: AbortSignal } | undefined)?.signal
    if (signal?.aborted) {
      throw new DOMException('The operation was aborted.', 'AbortError')
    }
    calls.push(call)
    const res = handler(call)
    if ('raw' in res) {
      return {
        ok: res.status >= 200 && res.status < 300,
        status: res.status,
        statusText: '',
        headers: new Headers({ 'Content-Type': 'text/plain' }),
        json: async () => { throw new SyntaxError('Unexpected token') },
        text: async () => res.raw,
      } as Response
    }
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

test('listFeedback GETs /api/feedback with the filter query (org_id, rating, page_size)', async () => {
  installFetch(() => ({ status: 200, body: { feedback: [], total: 0, page: 1, page_size: 50 } }))
  await listFeedback({ orgId: 'org 7', rating: 'thumbs_down', page: 2, pageSize: 50 })
  assert.equal(calls.length, 1)
  const u = new URL(calls[0]!.url, 'http://localhost')
  assert.equal(u.pathname, '/api/feedback')
  assert.equal(u.searchParams.get('org_id'), 'org 7')
  assert.equal(u.searchParams.get('rating'), 'thumbs_down')
  assert.equal(u.searchParams.get('page'), '2')
  assert.equal(u.searchParams.get('page_size'), '50')
})

test('feedbackExportUrl rides the same filters, forces page 1 and stays a plain download link', () => {
  const href = feedbackExportUrl({ orgId: 'org-1', rating: 'regenerate', page: 9 })
  assert.ok(href.startsWith('/api/feedback/export?'), 'export is an href, never a fetch')
  const u = new URL(href, 'http://localhost')
  assert.equal(u.searchParams.get('org_id'), 'org-1')
  assert.equal(u.searchParams.get('rating'), 'regenerate')
  assert.equal(u.searchParams.get('page'), '1', 'the server ignores export pagination')
})

test('403 (member deep link on a root-only route) rejects as ApiError with the server text', async () => {
  installFetch(() => ({ status: 403, body: { error: 'root only' } }))
  const err = await listFeedback({}).then(
    () => { throw new Error('expected rejection') },
    (e: unknown) => e,
  )
  assert.ok(err instanceof ApiError, `expected ApiError, got ${String(err)}`)
  assert.equal((err as ApiError).status, 403)
  assert.match((err as ApiError).message, /root only/,
    'the page notice shows the server reason, not a silent empty table')
})

test('500 carries the server error text; a non-JSON body keeps the status-line message', async () => {
  installFetch(() => ({ status: 500, body: { error: 'db unavailable' } }))
  await assert.rejects(() => listFeedback({}), (e: unknown) => {
    const api = e as ApiError
    return api instanceof ApiError && api.status === 500 && api.message.includes('db unavailable')
  })

  installFetch(() => ({ status: 502, raw: 'bad gateway' }))
  await assert.rejects(() => listFeedback({}), (e: unknown) => {
    const api = e as ApiError
    return api instanceof ApiError && api.status === 502 && /502/.test(api.message)
  })
})

test('a superseded load rejects with the exact AbortError shape the page filters', async () => {
  installFetch(() => ({ status: 200, body: {} }))
  const ctrl = new AbortController()
  ctrl.abort()
  await assert.rejects(
    () => listFeedback({}, { signal: ctrl.signal }),
    (e: unknown) => e instanceof DOMException && e.name === 'AbortError',
    'FeedbackPage must ignore exactly this shape (never render a superseded load as an error)',
  )
})
