import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'
import {
  guardrailsCardOpenable, guardrailsLockReasonKey, guardrailsLockReasonParams,
  type GuardrailsAccess, type GuardrailsPermsView,
} from './guardrailsModel.ts'

// while /api/me loads; this pins that decision where it can actually run:
//
//   - LATENCY: while the answer is pending EVERY card is locked — including
//     when the pending answer would grant everything (root). A member never
//     sees a flash of openable links that would only produce 403s, and the
//     locked cards persist until the answer lands (no flicker-to-open).
//   - FAILURE: when the endpoint failed (identity stays null) cards open —
//     the documented fail-open (rights unknown ≠ denial; the server 403s
//     behind every link). The loading guard is checked FIRST, so a pending
//      request can never take the fail-open branch early.
//   - DEEP LINK 403: a member without analytics.read (the guardrails nav
//     gate) sees every card locked with the honest per-card reason — the
//     screen's "nothing openable" state (guardrails.noneVisible renders).
//
// Like GuardrailsPage.test.ts this is partially source-level: the SURFACES
// access shapes are re-declared here (the .tsx cannot execute); a delegation
// pin at the bottom makes sure the page did not re-derive the gate inline.

const here = dirname(fileURLToPath(import.meta.url))
const pageSource = readFileSync(join(here, 'GuardrailsPage.tsx'), 'utf8')

// are rootOnly, label-policy sits behind analytics.read. N02-P08 added the
// detector-packs card (root-only guard mount).
const SURFACES: Array<{ id: string; access: GuardrailsAccess }> = [
  { id: 'tool-policy', access: { rootOnly: true } },
  { id: 'rules', access: { rootOnly: true } },
  { id: 'label-policy', access: { anyOrg: ['analytics.read'] } },
  { id: 'guard-packs', access: { rootOnly: true } },
]

const perms = (over: Partial<GuardrailsPermsView>): GuardrailsPermsView => ({
  loading: false,
  hasIdentity: true,
  isRoot: false,
  canAnyOrg: () => false,
  ...over,
})

describe('guardrails card gate under /api/me failure and latency (R101-03)', () => {
  it('latency: every card stays locked while the answer is pending — even when it would grant everything', () => {
    const pendingRoot = perms({
      loading: true,
      hasIdentity: true,
      isRoot: true,
      canAnyOrg: () => true,
    })
    for (const s of SURFACES) {
      assert.equal(guardrailsCardOpenable(s.access, pendingRoot), false,
        `${s.id} must render locked while /api/me is in flight (no flicker-to-open)`)
    }
  })

  it('latency: the loading guard precedes the fail-open branch (pending ≠ failed)', () => {
    // The exact window the review documented: request in flight, identity
    // still null. Fail-closed must win — the cards only open once the answer
    // LANDS as null (endpoint failed), never while it is pending.
    const pendingUnknown = perms({ loading: true, hasIdentity: false })
    for (const s of SURFACES) {
      assert.equal(guardrailsCardOpenable(s.access, pendingUnknown), false)
    }
  })

  it('failure: a failed /api/me opens the cards (documented fail-open; server stays the arbiter)', () => {
    const unavailable = perms({ hasIdentity: false })
    for (const s of SURFACES) {
      assert.equal(guardrailsCardOpenable(s.access, unavailable), true,
        `${s.id} opens when the endpoint failed (me === null)`)
    }
  })

  it('root sees every card open; the gate never locks for the platform administrator', () => {
    const root = perms({ isRoot: true })
    for (const s of SURFACES) {
      assert.equal(guardrailsCardOpenable(s.access, root), true)
    }
  })

  it('member: granted permission opens the org-scoped card; root-only cards stay locked', () => {
    const member = perms({ canAnyOrg: (...p) => p.includes('analytics.read') })
    assert.equal(guardrailsCardOpenable(SURFACES[2]!.access, member), true)
    for (const s of SURFACES.slice(0, 2)) {
      assert.equal(guardrailsCardOpenable(s.access, member), false)
    }
  })

  it('deep-link 403: a member without analytics.read gets every card locked — the noneVisible state', () => {
    const outsider = perms({ canAnyOrg: () => false })
    const locked = SURFACES.filter(s => !guardrailsCardOpenable(s.access, outsider))
    assert.equal(locked.length, SURFACES.length,
      'every card locked → the page renders guardrails.noneVisible')
  })

  it('locked vocabulary: root-only names root; org-scoped names the exact permission list', () => {
    assert.equal(guardrailsLockReasonKey({ rootOnly: true }), 'guardrails.requiresRoot')
    assert.deepEqual(guardrailsLockReasonParams({ rootOnly: true }), {})
    assert.equal(guardrailsLockReasonKey({ anyOrg: ['analytics.read'] }), 'guardrails.requiresPerm')
    assert.deepEqual(guardrailsLockReasonParams({ anyOrg: ['analytics.read'] }),
      { permission: 'analytics.read' })
    assert.deepEqual(guardrailsLockReasonParams({ anyOrg: ['keys.manage', 'agent_keys.manage'] }),
      { permission: 'keys.manage, agent_keys.manage' })
  })

  it('the page delegates to the model instead of re-deriving the gate inline', () => {
    assert.ok(pageSource.includes('guardrailsCardOpenable'),
      'GuardrailsPage must call guardrailsCardOpenable')
    assert.ok(!pageSource.includes('if (perms.loading)'),
      'the loading decision lives in guardrailsModel.ts only (feeding the view object is fine)')
    assert.ok(pageSource.includes('guardrails-locked-'),
      'locked cards render with the guardrails-locked-* testids while /api/me is pending')
  })
})
