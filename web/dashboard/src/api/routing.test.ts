// URL + query contract (org_id/period encoding), the shared-scope preset →
// health period mapping, and the chain assembly helper. Runs under
// `node --test` with a stubbed fetch (same pattern as orgSettings.test.ts).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import { getRoutingMap, getProviderHealth, healthPeriodParam, chainSteps } from './routing.ts'

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

test('getRoutingMap requests /api/routing/map with the encoded org_id', async () => {
  installFetch(() => ({
    status: 200,
    body: { org_id: 'org 1', models: [], aliases: [], rules: [], warnings: [] },
  }))
  const map = await getRoutingMap('org 1')
  assert.equal(calls.length, 1)
  assert.equal(calls[0]!.url, '/api/routing/map?org_id=org%201')
  assert.equal(calls[0]!.init.method, undefined, 'routing map is a read — no method override')
  assert.equal(map.warnings.length, 0)
})

test('getProviderHealth requests /api/providers/health with encoded org_id and period', async () => {
  installFetch(() => ({
    status: 200,
    body: { org_id: 'o', period: '7d', from: 'f', to: 't', providers: [] },
  }))
  const rep = await getProviderHealth('o', '7d')
  assert.equal(calls.length, 1)
  assert.equal(calls[0]!.url, '/api/providers/health?org_id=o&period=7d')
  assert.deepEqual(rep.providers, [])
})

test('healthPeriodParam passes direct presets through', () => {
  assert.equal(healthPeriodParam('24h', '', ''), '24h')
  assert.equal(healthPeriodParam('7d', '', ''), '7d')
  assert.equal(healthPeriodParam('30d', '', ''), '30d')
})

test('healthPeriodParam expresses 90d as an exact hour duration', () => {
  assert.equal(healthPeriodParam('90d', '', ''), '2160h')
})

test('healthPeriodParam maps a custom window to its whole-span hours', () => {
  assert.equal(healthPeriodParam('custom', '2026-10-01T00:00:00Z', '2026-10-04T12:00:00Z'), '84h')
})

test('healthPeriodParam floors a sub-hour window at 1h', () => {
  assert.equal(healthPeriodParam('custom', '2026-10-01T00:00:00Z', '2026-10-01T00:10:00Z'), '1h')
})

test('healthPeriodParam falls back to the API default on unusable bounds', () => {
  assert.equal(healthPeriodParam('custom', '', ''), '24h')
  assert.equal(healthPeriodParam('custom', 'not-a-date', '2026-10-01T00:00:00Z'), '24h')
  assert.equal(healthPeriodParam('custom', '2026-10-02T00:00:00Z', '2026-10-01T00:00:00Z'), '24h')
})

test('chainSteps is self → fallback → failovers, dropping blanks, keeping repeats', () => {
  assert.deepEqual(
    chainSteps({ model_name: 'a', fallback_model: 'b', failover_models: ['c', ''] }),
    ['a', 'b', 'c'],
  )
  assert.deepEqual(
    chainSteps({ model_name: 'a', fallback_model: 'a', failover_models: ['a'] }),
    ['a', 'a', 'a'],
    'a configured cycle stays visible — the map warns, it does not rewrite',
  )
  assert.deepEqual(
    chainSteps({ model_name: 'a', fallback_model: null, failover_models: [] }),
    ['a'],
  )
})
