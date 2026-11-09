// Pure node:test (no DOM, no i18n runtime), in the money.ts/tableSort.ts
// test style: pin the visible text, the missing-value honesty and the
// sub-cent hint, since these render operator-facing money/usage figures.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  MISSING_VALUE,
  formatCellByFormat,
  formatCodeCell,
  formatDateCell,
  formatDurationCell,
  formatMoneyCell,
  formatNumberCell,
  formatPercentCell,
  formatTokensCell,
} from './columnFormat.ts'

// ---------------------------------------------------------------------------
// money
// ---------------------------------------------------------------------------

test('money renders 2 decimals with grouping', () => {
  assert.equal(formatMoneyCell(1234.5, { locale: 'en' }).text, '$1,234.50')
  assert.equal(formatMoneyCell(0, { locale: 'en' }).text, '$0.00')
  assert.equal(formatMoneyCell('42', { locale: 'en' }).text, '$42.00')
})

test('money sub-cent shows <$0.01 with the exact value in the hint', () => {
  const cell = formatMoneyCell(0.000009, { locale: 'en' })
  assert.equal(cell.text, '<$0.01')
  assert.ok(cell.title, 'sub-cent cell carries an exact-value hint')
  assert.equal(cell.title, '$0.000009')
  assert.notEqual(cell.title, '<$0.01')
})

test('money exactly one cent keeps 2 decimals (no < hint)', () => {
  const cell = formatMoneyCell(0.01, { locale: 'en' })
  assert.equal(cell.text, '$0.01')
  assert.equal(cell.title, undefined)
})

test('money negative sub-cent keeps the sign in the bounded view', () => {
  const cell = formatMoneyCell(-0.002, { locale: 'en' })
  assert.equal(cell.text, '-<$0.01')
  assert.equal(cell.title, '-$0.002000')
})

test('money missing/unknown is an em dash, never zero', () => {
  assert.equal(formatMoneyCell(null).text, MISSING_VALUE)
  assert.equal(formatMoneyCell(undefined).text, MISSING_VALUE)
  assert.equal(formatMoneyCell('').text, MISSING_VALUE)
  assert.equal(formatMoneyCell('soon').text, MISSING_VALUE)
})

test('money non-USD presentation keeps the honest USD unit', () => {
  assert.equal(formatMoneyCell(12.34, { locale: 'en', currency: 'EUR' }).text, '12.34 EUR')
})

test('money dispatches through formatCellByFormat', () => {
  assert.equal(formatCellByFormat('money', 1234.5, { locale: 'en' }).text, '$1,234.50')
})

// ---------------------------------------------------------------------------
// number
// ---------------------------------------------------------------------------

test('number groups digits and caps fraction digits', () => {
  assert.equal(formatNumberCell(1234567, { locale: 'en' }).text, '1,234,567')
  assert.equal(formatNumberCell(12.3456, { locale: 'en' }).text, '12.35')
  assert.equal(formatNumberCell(12.3456, { locale: 'en', maximumFractionDigits: 1 }).text, '12.3')
})

test('number missing is an em dash', () => {
  assert.equal(formatNumberCell(null).text, MISSING_VALUE)
  assert.equal(formatNumberCell('n/a').text, MISSING_VALUE)
})

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------

test('tokens render as "input / output" with grouping', () => {
  assert.equal(formatTokensCell({ input: 1234, output: 56789 }, { locale: 'en' }).text, '1,234 / 56,789')
  assert.equal(formatTokensCell([0, 42], { locale: 'en' }).text, '0 / 42')
})

test('tokens keep a missing side visible as em dash (never 0)', () => {
  assert.equal(formatTokensCell({ input: 1234 }, { locale: 'en' }).text, `1,234 / ${MISSING_VALUE}`)
  assert.equal(formatTokensCell({ output: 7 }, { locale: 'en' }).text, `${MISSING_VALUE} / 7`)
  assert.equal(formatTokensCell({ input: null, output: null }).text, MISSING_VALUE)
})

test('tokens accept a bare total', () => {
  assert.equal(formatTokensCell(1234, { locale: 'en' }).text, '1,234')
  assert.equal(formatTokensCell(null).text, MISSING_VALUE)
})

// ---------------------------------------------------------------------------
// date
// ---------------------------------------------------------------------------

test('date renders a localized date+time and stays parseable text', () => {
  const cell = formatDateCell('2026-10-03T14:05:00Z', { locale: 'en', timezone: 'UTC' })
  assert.ok(cell.text.includes('2026'), cell.text)
  assert.ok(cell.text.includes('2:05'), cell.text)
})

test('date zero/placeholder and unparsable values are em dashes', () => {
  assert.equal(formatDateCell('0001-01-01T00:00:00Z', { locale: 'en' }).text, MISSING_VALUE)
  assert.equal(formatDateCell('not-a-date', { locale: 'en' }).text, MISSING_VALUE)
  assert.equal(formatDateCell('', { locale: 'en' }).text, MISSING_VALUE)
  assert.equal(formatDateCell(null).text, MISSING_VALUE)
})

test('date accepts epoch milliseconds', () => {
  const cell = formatDateCell(Date.UTC(2026, 0, 2, 3, 4, 0), { locale: 'en', timezone: 'UTC' })
  assert.ok(cell.text.includes('2026'), cell.text)
})

// ---------------------------------------------------------------------------
// code
// ---------------------------------------------------------------------------

test('code passes values through verbatim and blanks stay missing', () => {
  assert.equal(formatCodeCell('gpt-4o-mini').text, 'gpt-4o-mini')
  assert.equal(formatCodeCell('us-east-1').text, 'us-east-1')
  assert.equal(formatCodeCell('').text, MISSING_VALUE)
  assert.equal(formatCodeCell(null).text, MISSING_VALUE)
})

// ---------------------------------------------------------------------------
// duration
// ---------------------------------------------------------------------------

test('duration tiers: ms, s, m s, h m', () => {
  assert.equal(formatDurationCell(850, { locale: 'en' }).text, '850 ms')
  assert.equal(formatDurationCell(1400, { locale: 'en' }).text, '1.4 s')
  assert.equal(formatDurationCell(125000, { locale: 'en' }).text, '2 m 05 s')
  assert.equal(formatDurationCell(3840000, { locale: 'en' }).text, '1 h 04 m')
})

test('duration carries at most one fraction digit and carries rounding', () => {
  assert.equal(formatDurationCell(59999, { locale: 'en' }).text, '60 s')
  assert.equal(formatDurationCell(3599999, { locale: 'en' }).text, '60 m')
  assert.equal(formatDurationCell(1200, { locale: 'en' }).text, '1.2 s')
})

test('duration missing/negative-safe', () => {
  assert.equal(formatDurationCell(null).text, MISSING_VALUE)
  assert.equal(formatDurationCell(-2000, { locale: 'en' }).text, '-2 s')
})

// ---------------------------------------------------------------------------
// percent
// ---------------------------------------------------------------------------

test('percent default scale is ratio (API rates are fractions)', () => {
  assert.equal(formatPercentCell(0.7, { locale: 'en' }).text, '70%')
  assert.equal(formatPercentCell(0.125, { locale: 'en' }).text, '12.5%')
  assert.equal(formatPercentCell(1, { locale: 'en' }).text, '100%')
})

test('percent percent-scale divides by 100 first', () => {
  assert.equal(formatPercentCell(70, { locale: 'en', scale: 'percent' }).text, '70%')
})

test('percent missing is an em dash', () => {
  assert.equal(formatPercentCell(null).text, MISSING_VALUE)
})

// ---------------------------------------------------------------------------
// dispatch table
// ---------------------------------------------------------------------------

test('formatCellByFormat dispatches every declared kind', () => {
  assert.equal(formatCellByFormat('number', 1234, { locale: 'en' }).text, '1,234')
  assert.equal(formatCellByFormat('tokens', { input: 1, output: 2 }, { locale: 'en' }).text, '1 / 2')
  assert.equal(formatCellByFormat('code', 'm1').text, 'm1')
  assert.equal(formatCellByFormat('duration', 850).text, '850 ms')
  assert.equal(formatCellByFormat('percent', 0.5, { locale: 'en' }).text, '50%')
  assert.equal(formatCellByFormat('date', null).text, MISSING_VALUE)
})
