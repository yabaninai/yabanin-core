import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { resolveScopeOrg, type ScopeOrgOption } from './useGlobalScope.ts'

// hooks/useGlobalScope.ts). The store (lib/globalScope.ts) already folds the
// remembered last org into `currentOrg`, so '' here means: no explicit ?org=
// AND no memory.

const ORG_A: ScopeOrgOption = { id: 'org-a', name: 'Alpha' }
const ORG_B: ScopeOrgOption = { id: 'org-b', name: 'Beta' }
const ROOT = { identityKnown: true, isRoot: true, memberships: [] as ScopeOrgOption[] }
const IDENTITY_UNKNOWN = { identityKnown: false, isRoot: false, memberships: [] as ScopeOrgOption[] }

describe('shell scope auto-selection (IMP-31)', () => {
  it('a deep link with ?org= always wins — even against the identity', () => {
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: true, currentOrg: 'org-z', listedOrgs: [ORG_A],
    }), 'org-z')
    assert.equal(resolveScopeOrg({
      explicitInUrl: true, identityKnown: true, isRoot: false,
      currentOrg: 'not-mine', memberships: [ORG_A], listedOrgs: null,
    }), 'not-mine', 'the server arbitrates a member deep link to a foreign org')
  })

  it('while the identity is unknown nothing is rewritten (no flicker, no 403-bait)', () => {
    assert.equal(resolveScopeOrg({
      ...IDENTITY_UNKNOWN, explicitInUrl: false, currentOrg: '', listedOrgs: null,
    }), '')
    assert.equal(resolveScopeOrg({
      ...IDENTITY_UNKNOWN, explicitInUrl: false, currentOrg: 'org-a', listedOrgs: [ORG_A],
    }), 'org-a')
  })

  it('a member is pinned to their own organizations; the single org is automatic', () => {
    assert.equal(resolveScopeOrg({
      explicitInUrl: false, identityKnown: true, isRoot: false,
      currentOrg: '', memberships: [ORG_A], listedOrgs: null,
    }), 'org-a', 'the only org is selected automatically')
    assert.equal(resolveScopeOrg({
      explicitInUrl: false, identityKnown: true, isRoot: false,
      currentOrg: 'org-b', memberships: [ORG_A, ORG_B], listedOrgs: null,
    }), 'org-b', 'a remembered org the caller still owns is kept')
    assert.equal(resolveScopeOrg({
      explicitInUrl: false, identityKnown: true, isRoot: false,
      currentOrg: 'org-gone', memberships: [ORG_A, ORG_B], listedOrgs: null,
    }), 'org-a', 'an org the caller lost falls back to the first membership')
    assert.equal(resolveScopeOrg({
      explicitInUrl: false, identityKnown: true, isRoot: false,
      currentOrg: '', memberships: [], listedOrgs: null,
    }), '', 'a member without memberships keeps the scope (server arbitrates)')
  })

  it('root: the last org is kept; only a single-org directory auto-selects', () => {
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: 'org-b', listedOrgs: [ORG_A, ORG_B],
    }), 'org-b', 'the remembered org beats "All organizations"')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: '', listedOrgs: [ORG_A],
    }), 'org-a', 'the only org is selected automatically')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: '', listedOrgs: [ORG_A, ORG_B],
    }), '', 'several orgs keep the root "All organizations" default')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: '', listedOrgs: [],
    }), '', 'an empty directory keeps "All organizations"')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: '', listedOrgs: null,
    }), '', 'a not-yet-loaded directory does not guess')
  })

  it('root: a remembered org that resolves nowhere is re-anchored (stale demo DB)', () => {
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: 'org-gone', listedOrgs: [ORG_A],
    }), 'org-a', 'the single listed org is adopted')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: 'org-gone', listedOrgs: [ORG_A, ORG_B],
    }), '', 'several orgs fall back to the honest "All organizations" view')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: 'org-b', memberships: [ORG_B], listedOrgs: [ORG_A],
    }), 'org-b', 'a root membership still anchors the org')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: 'org-gone', listedOrgs: null,
    }), 'org-gone', 'an unloaded directory does not guess')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: false, currentOrg: 'org-gone', listedOrgs: [],
    }), 'org-gone', 'an empty directory does not guess either')
    assert.equal(resolveScopeOrg({
      ...ROOT, explicitInUrl: true, currentOrg: 'org-gone', listedOrgs: [ORG_A],
    }), 'org-gone', 'a deep link still wins even against a stale org')
  })
})
