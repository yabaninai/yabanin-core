// UnitsSpendSection source pins (node --test, no DOM — same convention as
// capsStatusSection.test.ts). The behaviors that must not regress:
// read-only rollup, unknown amount as unknown, the SERVED window (never the
// draft), coverage gaps surfaced only when reported, credits_scale verbatim,
// distinct failure states, org-scope guard, and the BudgetsPage gate
// mirroring the server's analytics.read gate.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { formatUnitAmount, labelSpendLines } from '../../lib/unitSpend.ts'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, 'UnitsSpendSection.tsx'), 'utf8')
const budgetsPage = readFileSync(join(here, '..', 'BudgetsPage.tsx'), 'utf8')

test('loads through the typed client, org-scoped, no mutation surface', () => {
  assert.ok(src.includes('getUnitSpendRollup(org'), 'must call the typed client with the applied org')
  for (const banned of ['postJSON', 'updateOrgCaps', 'sendMutation', 'putJSON', 'promoteRatesPack', 'diffRatesPack']) {
    assert.ok(!src.includes(banned), `read-only rollup must not reference ${banned}`)
  }
})

test('a delayed org-A answer can never land in org B (abort on scope change)', () => {
  assert.ok(src.includes('ctrl.abort()'), 'cleanup must abort the in-flight request')
  assert.ok(src.includes("if (signal?.aborted || (e as { name?: string })?.name === 'AbortError') return"), 'aborted loads must not set state')
})

test('the window is a DRAFT: inputs never fire, Apply commits, the response wins', () => {
  assert.ok(src.includes('onClick={applyWindow}'), 'only Apply may start a scoped request')
  assert.ok(!/onChange=\{[^}]*load/.test(src), 'no keystroke may trigger a load')
  assert.ok(src.includes('rollup.window.from'), 'the served window is rendered, not the draft bounds')
})

test('unknown is a state: null amount renders unknown, never a zero', () => {
  assert.ok(src.includes('line.amount === null'))
  assert.ok(src.includes('budgets.unitsSpend.unknownAmount'))
})

test('coverage gaps surface as partial data, and only when the server reports them', () => {
  for (const row of ['unknown_usage_rows', 'unmodeled_carbon_rows', 'legacy_cost_rows']) {
    assert.ok(src.includes(row), `rollup field ${row} must be read`)
  }
  assert.ok(src.includes('[, n]) => n > 0'), 'a zero gap renders nothing')
  assert.ok(src.includes('state="partial"'))
})

test('credits_scale renders verbatim as a caption, never re-derived', () => {
  assert.ok(src.includes('{rollup.credits_scale}'), 'the server string must render as-is')
  assert.ok(!/credits_scale\s*=[^=]/.test(src), 'the page must not compute a scale')
})

test('the pricing citation is copyable when a catalog is cited', () => {
  assert.ok(src.includes('pricing_catalog'), 'catalog citation must depend on the server field')
  assert.ok(src.includes('IdChip value={rollup.pricing.pricing_catalog.digest}'), 'the digest must be copyable in full')
})

test('distinct failure states: 501 not-deployed vs 403 forbidden vs 404 invisible vs 400 window', () => {
  assert.ok(src.includes('error?.status === 501'))
  assert.ok(src.includes('budgets.unitsSpend.notDeployed'))
  assert.ok(src.includes('error.status === 403'))
  assert.ok(src.includes('error.status === 404'))
  assert.ok(src.includes('error.status === 400'))
  assert.ok(src.includes('budgets.unitsSpend.forbidden'))
  assert.ok(src.includes('budgets.unitsSpend.orgInvisible'))
  assert.ok(src.includes('budgets.unitsSpend.invalidWindow'))
})

test('the server family/fidelity vocabularies render localized, unknown ids verbatim', () => {
  // The vocabulary map must point at REAL i18n keys: the browser proof
  // (ui01-units-spend) caught a dot-form vs flat-key drift rendering
  // "[missing:…]" — so this pin resolves every mapped key against en.json.
  const en = JSON.parse(readFileSync(new URL('../../i18n/en.json', import.meta.url), 'utf8')) as Record<string, unknown>
  const nested = (key: string): unknown =>
    key.split('.').reduce<unknown>((acc, part) =>
      acc != null && typeof acc === 'object' ? (acc as Record<string, unknown>)[part] : undefined, en)
  for (const fam of ['money', 'resource', 'impact']) {
    const key = `budgets.unitsSpend.family_${fam}`
    assert.ok(src.includes(`'${key}'`), `family ${fam} must map to the flat i18n key`)
    assert.ok(typeof nested(key) === 'string', `i18n key ${key} must exist in en.json`)
  }
  for (const fid of ['exact', 'estimated', 'simulated', 'unknown']) {
    const key = `budgets.unitsSpend.fidelity_${fid}`
    assert.ok(src.includes(`'${key}'`), `fidelity ${fid} must map to the flat i18n key`)
    assert.ok(typeof nested(key) === 'string', `i18n key ${key} must exist in en.json`)
  }
  assert.ok(src.includes(': line.family'), 'an unmapped family falls back to the verbatim id')
  assert.ok(src.includes(': line.fidelity'), 'an unmapped fidelity falls back to the verbatim id')
})

test('BudgetsPage mounts the section under the same gate as the server (root or analytics.read)', () => {
  assert.ok(budgetsPage.includes('<UnitsSpendSection org={org} />'))
  assert.ok(/isRoot \|\| canAnalytics\) && \(\s*\n\s*<UnitsSpendSection/.test(budgetsPage), 'the mount must be gated root || canAnalytics')
})

test('recorded and what-if USD stay distinct when both are zero or unknown', () => {
  for (const amount of [0, null]) {
    const rows = labelSpendLines([
      { unit: 'USD', family: 'money', fidelity: amount === null ? 'unknown' : 'exact', amount },
      { unit: 'USD', family: 'money', fidelity: amount === null ? 'unknown' : 'exact', amount },
      { unit: 'credits', family: 'money', fidelity: 'exact', amount: 42 },
      { unit: 'tokens', family: 'resource', fidelity: 'exact', amount: 1234 },
      { unit: 'gCO2e', family: 'impact', fidelity: 'estimated', amount: null },
    ])
    assert.deepEqual(rows.map(row => row.labelKey), [
      'budgets.unitsSpend.actualCost', 'budgets.unitsSpend.counterfactualCost',
      'budgets.unitsSpend.creditsSpent', 'budgets.unitsSpend.tokensUsed',
      'budgets.unitsSpend.carbonEstimate',
    ])
    assert.equal(rows[0].line.amount, amount)
    assert.equal(rows[1].line.amount, amount)
    assert.equal(rows[4].line.amount, null)
  }
})

test('tiny costs and carbon values remain nonzero, while missing values stay unknown', () => {
  assert.equal(formatUnitAmount(0.00000048, 'en'), '0.00000048')
  assert.equal(formatUnitAmount(0.00048, 'de'), '0,00048')
  assert.equal(formatUnitAmount(0, 'en'), '0')
  assert.equal(formatUnitAmount(null, 'en'), null)
  assert.equal(formatUnitAmount(Number.NaN, 'en'), null)
  assert.equal(formatUnitAmount(Number.POSITIVE_INFINITY, 'en'), null)
})

test('additional units retain their own values without being folded into USD', () => {
  const row = { unit: 'future-unit', family: 'resource', fidelity: 'unknown', amount: null }
  const result = labelSpendLines([row])
  assert.equal(result[0].labelKey, undefined)
  assert.deepEqual(result[0].line, row)
})
