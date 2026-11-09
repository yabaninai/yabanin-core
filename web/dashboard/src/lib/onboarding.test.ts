import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ONBOARDING_CLIENTS, allStepsDone, clientConfigBlock, dashboardHomeLink,
  firstRequestState, gatewayKeyState, gatewayKeysLink, isOnboardingClient, isRequestStats,
  providerKeyState, providerKeysLink,
  type OnboardingSignals,
} from './onboarding.ts'

const ok = <T,>(value: T): PromiseSettledResult<T> => ({ status: 'fulfilled', value })
const fail = (): PromiseSettledResult<never> => ({ status: 'rejected', reason: new Error('read failed') })

test('allStepsDone: unknown (null) never counts as done', () => {
  const done: OnboardingSignals = { providerKey: true, gatewayKey: true, firstRequest: true }
  assert.equal(allStepsDone(done), true)

  // Any step not confirmed true — including unknown (null) and explicit
  // false — keeps the flow open: partial data must not produce "all set".
  for (const key of ['providerKey', 'gatewayKey', 'firstRequest'] as const) {
    assert.equal(allStepsDone({ ...done, [key]: null }), false, `${key}=null`)
    assert.equal(allStepsDone({ ...done, [key]: false }), false, `${key}=false`)
  }
})

test('deep links carry the org scope and the exact W-BYOK tab', () => {
  assert.equal(providerKeysLink('org 1'), '#org-settings?tab=provider-keys&org=org%201')
  assert.equal(gatewayKeysLink('org 1'), '#keys?org=org%201')
})

test('isOnboardingClient: only the three documented clients', () => {
  for (const c of ONBOARDING_CLIENTS) assert.equal(isOnboardingClient(c), true)
  assert.equal(isOnboardingClient('cline'), false)
  assert.equal(isOnboardingClient(''), false)
})

test('clientConfigBlock: placeholder gateway + write-only key, per docs/clients', () => {
  const opencode = clientConfigBlock('opencode')
  assert.match(opencode, /baseURL: https:\/\/gateway\.example\.internal\/v1/)
  assert.match(opencode, /apiKey: yb_…/)

  const claude = clientConfigBlock('claude-code')
  assert.match(claude, /ANTHROPIC_BASE_URL='https:\/\/gateway\.example\.internal'/)
  assert.match(claude, /ANTHROPIC_AUTH_TOKEN='yb_…'/)

  const codex = clientConfigBlock('codex')
  assert.match(codex, /model_providers\.yabanin/)
  assert.match(codex, /wire_api = "responses"/)
  assert.match(codex, /YABANIN_API_KEY='yb_…'/)

  // The raw key is write-only: every block shows the yb_… placeholder only.
  for (const c of ONBOARDING_CLIENTS) {
    assert.doesNotMatch(clientConfigBlock(c), /yb_[0-9a-f]{16,}/, `${c} must never embed a real key shape`)
  }
})

test('dashboardHomeLink: root → overview, member → explorer', () => {
  assert.equal(dashboardHomeLink(true), '#overview')
  assert.equal(dashboardHomeLink(false), '#requests-explorer')
})

// ----- live step detection decisions (design/wizard §2 done-signal table,
// extracted from OnboardingPage so the state matrix is pinned by REAL
// decision-table tests, not source lint) -----

test('providerKeyState: one credential is done, an answered empty list is to-do, a failed read is unknown', () => {
  assert.equal(providerKeyState(ok([{ id: 'cred-1' }])), true, '≥1 credential = done signal')
  assert.equal(providerKeyState(ok([])), false, 'answered empty = confirmed none connected (to-do), never unknown')
  assert.equal(providerKeyState(fail()), null, 'request failed = unknown')
})

test('gatewayKeyState: an ACTIVE key is the done signal — a revoked-only registry is not a working setup', () => {
  assert.equal(gatewayKeyState(ok({ data: [{ active: true }] })), true)
  assert.equal(
    gatewayKeyState(ok({ data: [{ active: false }] })),
    false,
    'revoked-only ≠ done: the answered list proves no active key exists (confirmed to-do)',
  )
  assert.equal(
    gatewayKeyState(ok({ data: [{ active: false }, { active: false }] })),
    false,
    'every key revoked still reads to-do',
  )
  assert.equal(
    gatewayKeyState(ok({ data: [{ active: false }, { active: true }] })),
    true,
    'one active key among revoked ones is enough',
  )
  assert.equal(gatewayKeyState(ok({})), false, 'an answered list without data proves no active key')
  assert.equal(gatewayKeyState(fail()), null, 'request failed = unknown')
})

test('firstRequestState: success means total_requests > 0 AND success_rate > 0; drift and failure stay unknown', () => {
  assert.equal(firstRequestState(ok({ total_requests: 3, success_rate: 0.5 })), true)
  assert.equal(
    firstRequestState(ok({ total_requests: 5, success_rate: 0 })),
    false,
    'traffic with a 0% success rate is not a working setup (to-do, not unknown, not done)',
  )
  assert.equal(firstRequestState(ok({ total_requests: 0, success_rate: 0 })), false, 'no traffic = to-do')
  assert.equal(
    firstRequestState(ok({ total_requests: 5 })),
    null,
    'shape drift degrades to unknown, never to zero-success',
  )
  assert.equal(firstRequestState(fail()), null, 'stats failed = unknown')
})

test('isRequestStats: only objects carrying both numeric fields count', () => {
  assert.equal(isRequestStats({ total_requests: 1, success_rate: 1 }), true)
  assert.equal(isRequestStats({ total_requests: 0, success_rate: 0, extra: 'ok' }), true, 'extra fields are fine')
  assert.equal(isRequestStats({ total_requests: 1 }), false)
  assert.equal(isRequestStats({ success_rate: 1 }), false)
  assert.equal(isRequestStats({ total_requests: '1', success_rate: 1 }), false, 'string totals are drift')
  assert.equal(isRequestStats(null), false)
  assert.equal(isRequestStats('stats'), false)
})
