// TP-05 unit tests: USD money formatting keeps the honest unit.
//
// A non-USD org presentation must never relabel USD amounts with a foreign
// symbol (that would imply an FX conversion that does not exist). These cases
// failed before the fix: formatMoney(12.34, 'EUR') rendered "€12.34".

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { formatUsdMoney, MONEY_UNIT } from './money.ts'

test('USD presentation keeps the currency form', () => {
  assert.equal(formatUsdMoney(12.34, 'USD', 'en'), '$12.34')
  assert.equal(formatUsdMoney(12.34, undefined, 'en'), '$12.34')
  assert.equal(formatUsdMoney(12.34, 'usd', 'en'), '$12.34')
})

test('non-USD presentation keeps the honest USD unit, never the foreign symbol', () => {
  const eur = formatUsdMoney(12.34, 'EUR', 'en')
  assert.equal(eur, '12.34 USD')
  assert.ok(!eur.includes('€'), 'must not relabel USD as euro')
  assert.ok(!eur.includes('$'), 'USD symbol belongs to USD presentation only')

  const rub = formatUsdMoney(12.34, 'RUB', 'en')
  assert.equal(rub, '12.34 USD')
  assert.ok(!rub.includes('₽'))
})

test('locale separators apply to the number while the unit stays USD', () => {
  // ru uses a comma decimal separator; the unit must remain the USD code.
  assert.equal(formatUsdMoney(12.34, 'EUR', 'ru'), '12,34 USD')
  // ru puts an NBSP between the number and the currency symbol.
  assert.equal(formatUsdMoney(12.34, 'USD', 'ru'), '12,34\u00A0$')
  // Grouping follows the locale, not the presentation currency.
  assert.equal(formatUsdMoney(12345.67, 'EUR', 'de'), '12.345,67 USD')
})

test('sub-cent amounts keep their magnitude instead of collapsing to zero', () => {
  assert.equal(formatUsdMoney(0.000009, 'USD', 'en'), '$0.000009')
  assert.equal(formatUsdMoney(0.000009, 'EUR', 'en'), '0.000009 USD')
  // Zero itself stays the plain two-digit form (and unknown is a caller
  // concern — it must never be formatted as a zero amount).
  assert.equal(formatUsdMoney(0, 'USD', 'en'), '$0.00')
  assert.equal(formatUsdMoney(0, 'EUR', 'en'), '0.00 USD')
})

test('negative savings format with the same honest unit', () => {
  assert.equal(formatUsdMoney(-1.26, 'EUR', 'en'), '-1.26 USD')
  assert.equal(formatUsdMoney(-1.26, 'USD', 'en'), '-$1.26')
})

test('invalid presentation codes degrade to the USD default', () => {
  // Wrong-length codes fall back to USD presentation.
  assert.equal(formatUsdMoney(12.34, 'EU', 'en'), '$12.34')
  assert.equal(formatUsdMoney(12.34, '', 'en'), '$12.34')
})

test('unknown locale tag degrades to a plain number with the USD unit', () => {
  const out = formatUsdMoney(12.34, 'EUR', 'not-a-locale-tag!')
  assert.equal(out, '12.34 USD')
  assert.equal(MONEY_UNIT, 'USD')
})
