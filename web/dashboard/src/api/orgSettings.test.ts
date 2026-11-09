// NEXT-18f unit tests for the org budget settings API client: contract shape
// (URL, method, body, X-Audit-Reason), NULL-vs-0 honesty, and typed error
// propagation. Runs under `node --test` with a stubbed fetch (same pattern
// as transport.test.ts).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  getOrgBudgetSettings, updateOrgGraceFloor, updateOrgReservationsMode,
  updateOrgDefaultOutputCap, isReservationsMode, isValidGraceFloorCents,
  GRACE_FLOOR_MIN_CENTS, upsertPolicyPack,
} from './orgSettings.ts'
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

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('getOrgBudgetSettings GETs the grace endpoint and parses nulls', async () => {
  installFetch(call => {
    assert.equal(call.url, '/api/orgs/org-18f/credits/grace')
    return {
      status: 200,
      body: {
        org_id: 'org-18f',
        grace_floor_cents: null,
        effective_grace_floor_cents: -100,
        reservations_mode: 'enforce',
        saved_reservations_mode: 'enforce',
        effective_reservations_mode: 'shadow',
        default_output_cap_tokens: null,
        balance_cents: -15000,
        deep_overdraft: true,
      },
    }
  })
  const settings = await getOrgBudgetSettings('org-18f')
  assert.equal(settings.grace_floor_cents, null)
  assert.equal(settings.effective_grace_floor_cents, -100)
  assert.equal(settings.reservations_mode, 'enforce')
  // N06-P03: saved vs effective are distinct — the deployment rollout
  // ceiling clamped the stored enforce to shadow; the UI shows the
  // effective mode and marks the clamped state.
  assert.equal(settings.saved_reservations_mode, 'enforce')
  assert.equal(settings.effective_reservations_mode, 'shadow')
  assert.notEqual(settings.effective_reservations_mode, settings.saved_reservations_mode)
  assert.equal(settings.deep_overdraft, true)
})

test('updateOrgGraceFloor PUTs body + X-Audit-Reason and returns the new block', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    assert.equal(call.url, '/api/orgs/org-18f/credits/grace')
    assert.equal(call.init.method, 'PUT')
    const headers = new Headers(call.init.headers as HeadersInit)
    assert.equal(headers.get('X-Audit-Reason'), 'contract allows overdraft')
    assert.deepEqual(JSON.parse(String(call.init.body)), {
      grace_floor_cents: -500,
      reason: 'contract allows overdraft',
    })
    return {
      status: 200,
      body: {
        org_id: 'org-18f', grace_floor_cents: -500, effective_grace_floor_cents: -500,
        reservations_mode: 'off', default_output_cap_tokens: null,
        balance_cents: 0, deep_overdraft: false,
      },
    }
  })
  const out = await updateOrgGraceFloor('org-18f', -500, 'contract allows overdraft')
  assert.equal(out.grace_floor_cents, -500)
})

test('updateOrgGraceFloor sends null as JSON null, never omits it', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    assert.deepEqual(JSON.parse(String(call.init.body)), { grace_floor_cents: null, reason: 'reset' })
    return { status: 200, body: defaultSettings() }
  })
  await updateOrgGraceFloor('org-18f', null, 'reset')
})

function defaultSettings() {
  return {
    org_id: 'org-18f', grace_floor_cents: null, effective_grace_floor_cents: -100,
    reservations_mode: 'off', saved_reservations_mode: 'off', effective_reservations_mode: 'off',
    default_output_cap_tokens: null,
    balance_cents: null, deep_overdraft: false,
  }
}

test('mutations surface ApiError with the server status', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    return { status: 400, body: { error: 'reason is required' } }
  })
  await assert.rejects(
    updateOrgReservationsMode('org-18f', 'enforce', ''),
    (err: unknown) => err instanceof ApiError && err.status === 400,
  )
})

test('updateOrgReservationsMode PUTs the mode', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    assert.equal(call.url, '/api/orgs/org-18f/reservations-mode')
    assert.deepEqual(JSON.parse(String(call.init.body)), { mode: 'shadow', reason: 'rollout' })
    return { status: 200, body: { ...defaultSettings(), reservations_mode: 'shadow' } }
  })
  const out = await updateOrgReservationsMode('org-18f', 'shadow', 'rollout')
  assert.equal(out.reservations_mode, 'shadow')
})

test('updateOrgDefaultOutputCap PUTs the token cap', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-18f' } }
    assert.equal(call.url, '/api/orgs/org-18f/output-cap')
    assert.deepEqual(JSON.parse(String(call.init.body)), { default_output_cap_tokens: 4096, reason: 'cap' })
    return { status: 200, body: { ...defaultSettings(), default_output_cap_tokens: 4096 } }
  })
  const out = await updateOrgDefaultOutputCap('org-18f', 4096, 'cap')
  assert.equal(out.default_output_cap_tokens, 4096)
})

test('validators: mode set and grace range incl. NULL vs 0', () => {
  assert.equal(isReservationsMode('off'), true)
  assert.equal(isReservationsMode('shadow'), true)
  assert.equal(isReservationsMode('enforce'), true)
  assert.equal(isReservationsMode('enforce_now'), false)
  assert.equal(isReservationsMode(''), false)

  assert.equal(isValidGraceFloorCents(null), true, 'null = platform default is settable')
  assert.equal(isValidGraceFloorCents(0), true, 'explicit 0 is valid (AF-01)')
  assert.equal(isValidGraceFloorCents(GRACE_FLOOR_MIN_CENTS), true)
  assert.equal(isValidGraceFloorCents(GRACE_FLOOR_MIN_CENTS - 1), false)
  assert.equal(isValidGraceFloorCents(1), false)
  assert.equal(isValidGraceFloorCents(-100.5), false, 'cents are integers')
})


// The strict-decode + required-config contract on PUT /api/organizations/{id}/policy-packs/{region}.
// The wizard used to send {} and the settings pack-add {enabled:true} — both
// are 400s ("config is required and must be non-null JSON") on the fixed
// handler, and were silent SQL 500s before it.
test('upsertPolicyPack PUTs a non-null config document (required by pkfix1 contract)', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-pk' } }
    assert.equal(call.url, '/api/organizations/org-pk/policy-packs/SG')
    assert.equal(call.init.method, 'PUT')
    return { status: 200, body: { org_id: 'org-pk', region: 'SG', pack_id: 'sg_pdpa_mas', enabled: true } }
  })
  await upsertPolicyPack('org-pk', 'SG', { pack_id: 'sg_pdpa_mas', config: {} })
  const sent = JSON.parse(String(calls[calls.length - 1].init.body))
  assert.deepEqual(Object.keys(sent).sort(), ['config', 'pack_id'])
  assert.deepEqual(sent.config, {}, 'config must be present non-null JSON ({} = pack defaults)')
  assert.equal(sent.pack_id, 'sg_pdpa_mas')
})

test('upsertPolicyPack keeps enabled and omits absent pack_id (server defaults it)', async () => {
  installFetch(call => {
    if (call.url === '/auth/csrf') return { status: 200, body: { csrf_token: 'tok-pk' } }
    assert.equal(call.url, '/api/organizations/org-pk/policy-packs/ID')
    return { status: 200, body: { org_id: 'org-pk', region: 'ID', pack_id: 'id_pdp', enabled: true } }
  })
  await upsertPolicyPack('org-pk', 'ID', { config: {}, enabled: true })
  const sent = JSON.parse(String(calls[calls.length - 1].init.body))
  assert.deepEqual(Object.keys(sent).sort(), ['config', 'enabled'], 'exactly the three known keys, none extra (strict decode)')
  assert.equal(sent.enabled, true)
})
