// CUI-02 first-run defect fix (2026-11-20), reviewer-corrected design.
// A fresh org's first gateway request is rejected 403
// budget_not_configured; the only legitimate repair is an operator path
// to create the FIRST team budget row through the EXISTING
// PUT /api/teams/{id}/budget. These node --test pins (no DOM) cover:
//
//  - identity binding: the write target is the VERIFIED setup-key team
//    (a key row's server-set team_id — explicit or fallback, the client
//    cannot and must not distinguish). List order is NEVER default-team
//    evidence (blocking review): with two candidate keys, BOTH orders
//    leave the choice to the operator; a single explicitly-non-default
//    key binds to ITS team and is never labeled "default";
//  - explicit confirmation: high-risk action with entity=team id, so the
//    dialog requires typing the exact team id; the limit is validated
//    positive and finite, always a HARD cap (bounded spending);
//  - no bypass: the root-only team enumeration must never appear; the
//    write is the existing endpoint, no auto-provision/preseed/enforcement
//    change;
//  - honest states: keys.manage missing is SAID (identity unresolvable),
//    load failures are error notices with retry, no-key and
//    already-budgeted states are explicit, the wizard mounts the section.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import {
  autoSelectedSetupKey, firstBudgetPhase, setupKeyTeamCandidates,
} from './firstTeamBudget.ts'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'FirstTeamBudget.tsx'), 'utf8')
const steps = readFileSync(join(here, '..', 'onboarding', 'OnboardingSteps.tsx'), 'utf8')
const en = JSON.parse(readFileSync(join(here, '..', '..', 'i18n', 'en.json'), 'utf8')) as {
  budgets: Record<string, string>; welcome: Record<string, string>
}

const key = (over: Record<string, unknown>) => ({ id: 'k', name: 'k', ...over })
const base = {
  permsLoading: false, canBudgets: true, canKeys: true,
  keysError: '', budgetsError: '', keys: [], budgetedIds: [], selected: null,
}

test('setupKeyTeamCandidates: only key rows with a server-set team_id are candidates', () => {
  assert.deepEqual(
    setupKeyTeamCandidates([key({ id: 'k1' }), key({ id: 'k2', name: 'k2', team_id: 'team-2' })]),
    [{ keyId: 'k2', keyName: 'k2', teamId: 'team-2' }],
  )
  assert.deepEqual(setupKeyTeamCandidates([]), [])
})

test('REVIEW CONTROL (two teams, reordered): no automatic pick in EITHER order — the operator must choose', () => {
  const a = key({ id: 'ka', name: 'alpha', team_id: 'team-a' })
  const b = key({ id: 'kb', name: 'beta', team_id: 'team-b' })
  // An ordered list is not default-team evidence: reversing it must not
  // change that nothing is auto-selected (nothing is silently written).
  assert.equal(autoSelectedSetupKey(setupKeyTeamCandidates([a, b])), null)
  assert.equal(autoSelectedSetupKey(setupKeyTeamCandidates([b, a])), null)
  // The section stays ready for an explicit choice in both orders.
  assert.equal(firstBudgetPhase({ ...base, keys: [a, b] }).kind, 'ready')
  assert.equal(firstBudgetPhase({ ...base, keys: [b, a] }).kind, 'ready')
})

test('REVIEW CONTROL (single explicitly non-default key): binds to THAT key\'s team, never a guessed default', () => {
  // Key creation permits an explicit non-default team (crud.go:529);
  // server-side evidence is identical, so the identity is the key row\'s
  // team_id — asserted here, and the UI never labels it "default".
  const nonDefault = key({ id: 'k1', name: 'prod', team_id: 'team-explicit' })
  const cands = setupKeyTeamCandidates([nonDefault])
  assert.equal(cands.length, 1)
  assert.equal(cands[0].teamId, 'team-explicit')
  const auto = autoSelectedSetupKey(cands)
  assert.ok(auto && auto.teamId === 'team-explicit')
  const phase = firstBudgetPhase({ ...base, keys: [nonDefault] })
  assert.equal(phase.kind, 'ready')
})

test('autoSelectedSetupKey: exactly one candidate auto-selects; zero never does', () => {
  assert.equal(autoSelectedSetupKey([]), null)
  const solo = setupKeyTeamCandidates([key({ team_id: 'team-x' })])
  assert.equal(autoSelectedSetupKey(solo)?.teamId, 'team-x')
})

test('firstBudgetPhase: every render state is decided honestly', () => {
  assert.equal(firstBudgetPhase({ ...base, permsLoading: true }).kind, 'hidden')
  assert.equal(firstBudgetPhase({ ...base, canBudgets: false }).kind, 'hidden')
  assert.equal(firstBudgetPhase({ ...base, canKeys: false }).kind, 'no-keys-perm')
  const withKey = { ...base, keys: [key({ team_id: 'team-x' })] }
  assert.equal(firstBudgetPhase({ ...withKey, keysError: 'keys read failed' }).kind, 'error')
  assert.equal(firstBudgetPhase({ ...withKey, budgetsError: 'budgets read failed' }).kind, 'error')
  assert.equal(firstBudgetPhase({ ...withKey, keys: null }).kind, 'waiting')
  assert.equal(firstBudgetPhase({ ...withKey, budgetedIds: null }).kind, 'waiting')
  assert.equal(firstBudgetPhase({ ...base }).kind, 'no-keys')
  const selected = { keyId: 'k1', keyName: 'k1', teamId: 'team-x' }
  assert.equal(firstBudgetPhase({ ...withKey, budgetedIds: ['team-x'], selected }).kind, 'done')
  assert.equal(firstBudgetPhase({ ...withKey, selected }).kind, 'ready')
})

test('the write binds to the selected key row\'s team via the EXISTING endpoint, always a hard cap', () => {
  assert.ok(src.includes('upsertTeamBudget(selected.teamId, v, true)'), 'must write selected.teamId through the existing PUT wrapper with hard_limit=true')
  assert.ok(src.includes("!Number.isFinite(v) || v <= 0"), 'must reject non-finite and non-positive limits')
})

test('explicit identity confirmation: high risk + entity=team id forces typing the exact team', () => {
  assert.ok(src.includes("risk: 'high'"), 'the first budget is a high-risk action')
  assert.ok(src.includes('entity: selected.teamId'), 'confirmation requires typing the team id')
})

test('no bypass: root-only team enumeration never appears; no auto-provision or preseed', () => {
  assert.ok(!src.includes('listTeamsByOrg(') && !src.includes('listTeams('), 'must not use the root-only team enumeration')
  assert.ok(!src.includes("'/api/teams'"), 'must not call the root-only /api/teams')
  assert.ok(!src.includes('createTeam') && !src.includes('provisionTeam'), 'must not provision teams')
  assert.ok(!src.includes('seedBudget') && !src.includes('bootstrapBudget'), 'must not preseed budgets')
})

test('no default-team labeling: identity copy says server-set, in code and in English strings', () => {
  // Comments may explain why "default" is never used; code and copy may not label it.
  const code = src.split('\n').filter(l => !l.trim().startsWith('//')).join('\n')
  assert.ok(!code.includes('default team'), 'component code must not label the identity as the default team')
  const firstKeys = Object.entries(en.budgets).filter(([k]) => k.startsWith('first'))
  assert.ok(firstKeys.length >= 10, 'first-budget copy keys present')
  for (const [k, v] of firstKeys) {
    assert.ok(!v.toLowerCase().includes('default team'), `en.budgets.${k} must not say "default team"`)
  }
  assert.equal(en.budgets.firstTeamLabel, 'Team this key bills to (server-set)')
})

test('honest states and guards in the component source', () => {
  assert.ok(src.includes("perms.can('budgets.manage')") && src.includes("perms.can('keys.manage')"), 'permission gates')
  assert.ok(src.includes("state=\"partial\"") && src.includes('firstNoKeysPerm'), 'keys.manage missing is said, not hidden')
  assert.ok(src.includes('StateNotice') && src.includes("state=\"error\"") && src.includes("t('common.retry')"), 'load failures are retryable error notices')
  assert.ok(src.includes('firstNoKeys') && src.includes('gatewayKeysLink(org)'), 'no-key state deep-links key creation')
  assert.ok(src.includes('AbortController') && src.includes('cancelled = true'), 'org-scope abort guard')
  assert.ok(src.includes('listOrgTeamBudgets') && src.includes('listAPIKeys'), 'self-contained reads (no parent-fed budget ids)')
  assert.ok(src.includes('setReload'), 'refetch after the write (budgeted state takes over)')
})

test('the wizard step mounts the section next to the budget note', () => {
  assert.ok(steps.includes('<FirstTeamBudget org={org} />'), 'ClientSetupStep renders the section')
  assert.ok(steps.includes('welcome-step-budget-note') && steps.includes('welcome-open-budgets'), 'the 403 is explained before the first request')
  assert.ok(en.welcome.budgetNote.includes('budget_not_configured'), 'note names the exact rejection')
})

test('locale parity: all 8 locales carry the full first-budget key set', () => {
  const locales = ['ar', 'en', 'es', 'hi', 'id', 'ja', 'ko', 'pt-BR']
  const wanted = ['firstTitle', 'firstNote', 'firstNone', 'firstSubmit', 'firstImpactHard', 'firstNoKeysPerm', 'firstNoKeys', 'firstKeyLabel', 'firstTeamLabel', 'firstSelectKey', 'firstSelectPlaceholder']
  for (const loc of locales) {
    const data = JSON.parse(readFileSync(join(here, '..', '..', 'i18n', `${loc}.json`), 'utf8'))
    for (const k of wanted) assert.ok(typeof data.budgets?.[k] === 'string' && data.budgets[k].length > 0, `${loc}.budgets.${k}`)
    assert.ok(data.welcome?.budgetNote && data.welcome?.openBudgets, `${loc}.welcome keys`)
  }
})
