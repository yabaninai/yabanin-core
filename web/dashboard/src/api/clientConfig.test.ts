// from GET /api/client-config/{agent}; the byte-parity TS mirror is retired
// (the server handler's own suite pins byte parity against the
// pkg/clientconfig goldens at the HTTP boundary). Pinned here instead:
//
//   - the request shape: path + base_url (required) + optional key_env /
//     model / labels in the canonical k=v,k=v form (sorted, encoded);
//   - the response typing flows through untouched (config/path/format/
//     key_env/dropped_labels);
//   - agentCopyBlock composes the copy block from the SERVER payload only;
//   - the /v1 normalization and the guided vocabulary stay pinned;
//   - the secret rule: no key VALUE rides the request (env NAME only).

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it, afterEach } from 'node:test'

import {
  GUIDED_AGENTS, agentCopyBlock, agentTestAuth, agentTestURL, encodeLabelsQuery, getClientConfig, withV1,
  type ClientConfigResult,
} from './clientConfig.ts'
import { resetCsrf } from './transport.ts'

interface Call { url: string; init: RequestInit }
const realFetch = globalThis.fetch
const calls: Call[] = []

function installFetch(handler: (call: Call) => { status: number; body: unknown }): void {
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

const okBody = (over: Partial<ClientConfigResult> = {}): ClientConfigResult => ({
  agent: 'codex',
  format: 'toml',
  path: '~/.codex/config.toml',
  config: 'model_provider = "yabanin"\n',
  key_env: 'YABANIN_API_KEY',
  ...over,
})

describe('request shape (the server render is the only source)', () => {
  it('builds /client-config/{agent}?base_url=… with the optional params', async () => {
    installFetch(() => ({ status: 200, body: okBody() }))
    await getClientConfig('codex', { baseURL: 'https://gw.example' })
    assert.equal(calls[0].url, '/api/client-config/codex?base_url=https%3A%2F%2Fgw.example',
      'base_url is required and rides the query')

    await getClientConfig('codex', { baseURL: 'https://gw.example', keyEnv: 'TEAM_KEY', model: 'gpt' })
    assert.equal(calls[0].url, '/api/client-config/codex?base_url=https%3A%2F%2Fgw.example')
    const second = calls.find(c => c.url.includes('TEAM_KEY'))
    assert.ok(second, 'the key_env call happened')
    assert.match(second!.url, /key_env=TEAM_KEY/)
    assert.match(second!.url, /model=gpt/)
  })

  it('labels ride the canonical k=v,k=v form (sorted keys, encoded values)', async () => {
    installFetch(() => ({ status: 200, body: okBody() }))
    await getClientConfig('opencode', { baseURL: 'https://gw.example', labels: { b: '2', a: 'x y' } })
    // Two encoding layers, both load-bearing: the value layer is Go
    // url.PathEscape form (encodeURIComponent: ' ' → %20 — the server's
    // NormalizeValue PathUnescapes it back); the query layer then encodes
    // '%' itself (%250 etc.). Wire: labels=a%3Dx%2520y%2Cb%3D2.
    assert.match(calls[0].url, /labels=a%3Dx%2520y%2Cb%3D2/, 'sorted, =-joined, value-encoded')
    assert.equal(encodeLabelsQuery({}), '', 'no labels means no param')
  })

  it('an unknown agent surfaces the server 404 as an error (no invented config)', async () => {
    installFetch(() => ({ status: 404, body: { error: 'unknown agent' } }))
    await assert.rejects(() => getClientConfig('codex', { baseURL: 'https://gw.example' }), /unknown agent|409|404|Error/)
  })

  it('no key VALUE ever rides the request (env NAME only)', async () => {
    installFetch(() => ({ status: 200, body: okBody() }))
    await getClientConfig('claude-code', { baseURL: 'https://gw.example', keyEnv: 'K' })
    for (const marker of ['sk-', 'yb_']) {
      assert.ok(!calls[0].url.includes(marker), `secret-looking ${marker} must not ride the URL`)
    }
  })
})

describe('response handling', () => {
  it('the typed payload flows through untouched', async () => {
    const body = okBody({
      agent: 'opencode', format: 'json', path: 'opencode.json (provider object)',
      config: '{\n  "npm": "@ai-sdk/openai-compatible"\n}\n',
      key_env: 'TEAM_KEY',
      dropped_labels: [{ key: 'BAD KEY', reason: 'invalid_key' }],
    })
    installFetch(() => ({ status: 200, body }))
    const got = await getClientConfig('opencode', { baseURL: 'https://gw.example', keyEnv: 'TEAM_KEY' })
    assert.deepEqual(got, body)
    assert.equal(got.dropped_labels?.[0].reason, 'invalid_key')
  })

  it('agentCopyBlock composes from the server payload only', () => {
    const result = okBody({ config: 'model_provider = "yabanin"\n' })
    const block = agentCopyBlock(result)
    assert.ok(block.startsWith('# ~/.codex/config.toml\n'), 'the path comment leads (server-provided)')
    assert.ok(block.includes('model_provider = "yabanin"'), 'the server config follows verbatim')
    assert.ok(block.includes("export YABANIN_API_KEY='yb_…'"), 'codex carries the env reminder')
    const claude = agentCopyBlock(okBody({ agent: 'claude-code', format: 'shell', path: 'shell profile', config: 'export X=1\n' }))
    assert.ok(claude.endsWith('export X=1\n'), 'claude-code gets no codex env note')
  })
})

describe('browser-side helpers stay pinned', () => {
  it('withV1 mirrors the Go normalization (the /v1/models check rides it)', () => {
    assert.equal(withV1('https://gw.example'), 'https://gw.example/v1')
    assert.equal(withV1('https://gw.example/'), 'https://gw.example/v1')
    assert.equal(withV1('https://gw.example/v1'), 'https://gw.example/v1')
    assert.equal(withV1(' https://gw.example// '), 'https://gw.example/v1')
    assert.equal(withV1('https://gw.example/v1/'), 'https://gw.example/v1')
  })

  it('the test URL is the /v1/models check from docs/clients', () => {
    assert.equal(agentTestURL('https://gw.example'), 'https://gw.example/v1/models')
    assert.equal(agentTestURL('https://gw.example/v1/'), 'https://gw.example/v1/models')
  })

  it('six agents — the full owner-decision (b) set, CLI/API/UI parity', () => {
    assert.deepEqual(
      [...GUIDED_AGENTS],
      ['claude-code', 'codex', 'opencode', 'continue', 'cline', 'aider'])
  })

  it('agentTestAuth: claude-code uses x-api-key, the other five Bearer authorization', () => {
    assert.deepEqual(agentTestAuth('claude-code'), { header: 'x-api-key', extra: { 'anthropic-version': '2023-06-01' } })
    for (const id of ['codex', 'opencode', 'continue', 'cline', 'aider'] as const) {
      assert.deepEqual(agentTestAuth(id), { header: 'authorization' }, `${id} authenticates with a Bearer header`)
    }
  })
})

// Server-handler parity cross-check (belt to the Go suite's suspenders): the
// endpoint's agent vocabulary is the same six ids this client pins.
describe('server/client agent vocabulary parity', () => {
  it('the Go handler serves exactly the guided set', () => {
    const here = dirname(fileURLToPath(import.meta.url))
    const goHandler = readFileSync(join(here, '..', '..', '..', '..', 'services', 'admin', 'handlers', 'client_config_handlers.go'), 'utf8')
    for (const id of GUIDED_AGENTS) {
      assert.ok(goHandler.includes(`"${id}":`), `the Go handler must render ${id}`)
    }
    assert.ok(!goHandler.includes('"cursor"') && !goHandler.includes('"windsurf"'),
      'agents without renderers must not appear server-side (404 by design)')
  })
})
