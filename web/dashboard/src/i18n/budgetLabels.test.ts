// explicitly-unlimited mode — «без скрытого unlimited». The UI label that
// makes the unlimited nature explicit is the budgets.impactSoft copy (and
// the budgets.soft badge) rendered from the API's hard_limit:false field.
// This gate pins that every shipped locale carries the label and that the
// canonical en copy states the advisory semantics, the uncapped team spend
// and the wallet backstop. A regression that waters the copy back down to
// a bare "soft limit" (hiding the unlimited) fails here.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const DIR = fileURLToPath(new URL('./', import.meta.url)).replace(/\/$/, '')

// Locale files are the shipped set (en canonical + machine-translated;
// keep in sync with LOCALES in ./index.ts).
const locales = readdirSync(DIR)
  .filter(f => f.endsWith('.json'))
  .map(f => f.slice(0, -'.json'.length))
  .sort()

for (const loc of locales) {
  test(`budgets soft-limit advisory copy is present in ${loc}`, () => {
    const dict = JSON.parse(readFileSync(new URL(`./${loc}.json`, import.meta.url), 'utf8')) as {
      budgets?: Record<string, unknown>
    }
    assert.ok(dict.budgets, `${loc}: budgets namespace missing`)
    for (const key of ['soft', 'hard', 'impactSoft', 'impactHard']) {
      const v = dict.budgets[key]
      assert.ok(typeof v === 'string' && v.length > 0, `${loc}: budgets.${key} must be a non-empty string`)
    }
  })
}

test('en budgets.impactSoft keeps the unlimited explicit (D3)', () => {
  const dict = JSON.parse(readFileSync(new URL('./en.json', import.meta.url), 'utf8')) as {
    budgets: Record<string, string>
  }
  const impact = dict.budgets.impactSoft
  assert.match(impact, /advisory/i, 'the advisory nature must be named')
  assert.match(impact, /requests continue/i, 'crossing the limit must not block')
  assert.match(impact, /not capped/i, 'the unlimited team spend must be explicit')
  assert.match(impact, /wallet/i, 'the wallet backstop must be named')
})
