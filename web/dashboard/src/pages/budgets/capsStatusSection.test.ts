// CapsStatusSection source pins (node --test, no DOM). The behaviors that
// must not regress: read-only, unknown-as-unknown, null limit as "not
// configured", credits_scale verbatim, distinct failure states, org-scope
// guard on switch.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'CapsStatusSection.tsx'), 'utf8')
const budgetsPage = readFileSync(join(here, '..', 'BudgetsPage.tsx'), 'utf8')

test('loads through the typed client, org-scoped, no mutation surface', () => {
  assert.ok(src.includes('getBudgetCaps(org'), 'must call the typed client with the applied org')
  for (const banned of ['postJSON', 'updateOrgCaps', 'sendMutation', 'putJSON']) {
    assert.ok(!src.includes(banned), `read-only status section must not reference ${banned}`)
  }
})

test('a delayed org-A answer can never land in org B (abort on scope change)', () => {
  assert.ok(src.includes('ctrl.abort()'), 'cleanup must abort the in-flight request')
  assert.ok(src.includes("if (signal?.aborted || (e as { name?: string })?.name === 'AbortError') return"), 'aborted loads must not set state')
})

test('unknown is a state: null used renders unknown, never a zero', () => {
  assert.ok(src.includes('cap.used.amount === null'))
  assert.ok(src.includes('budgets.capsStatus.unknownUsed'))
})

test('null limit renders "not configured" — an unconfigured cap is not unlimited', () => {
  assert.ok(src.includes('cap.limit === null'))
  assert.ok(src.includes('budgets.capsStatus.notConfigured'))
})

test('credits_scale renders verbatim as a caption, never re-derived', () => {
  assert.ok(src.includes('{status.credits_scale}'), 'the server string must render as-is')
  assert.ok(!/credits_scale\s*=[^=]/.test(src), 'the page must not compute a scale')
})

test('distinct failure states: 501 not-deployed vs 403 forbidden vs 404 invisible', () => {
  assert.ok(src.includes('error?.status === 501'))
  assert.ok(src.includes('budgets.capsStatus.notDeployed'))
  assert.ok(src.includes('error.status === 403'))
  assert.ok(src.includes('error.status === 404'))
  assert.ok(src.includes('budgets.capsStatus.forbidden'))
  assert.ok(src.includes('budgets.capsStatus.orgInvisible'))
})

test('the server cap vocabulary renders with friendly labels, unknown ids verbatim', () => {
  for (const id of ['usd_monthly_budget', 'carbon_monthly_grams', 'credits_floor']) {
    assert.ok(src.includes(id), `cap id ${id} must map to a label`)
  }
  assert.ok(src.includes(': cap.id'), 'an unmapped cap id falls back to the verbatim id')
})

test('BudgetsPage mounts the section under the same gate as the server (root or budgets.manage)', () => {
  assert.ok(budgetsPage.includes('<CapsStatusSection org={org} />'))
  assert.ok(/isRoot \|\| canBudgets\) && \(\s*\n\s*<CapsStatusSection/.test(budgetsPage), 'the mount must be gated root || canBudgets')
})
