import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compareSortState, nextSortState } from './tableSort.ts'

// AUX-01 acceptance: typed comparator over numbers, money, dates, numeric
// strings; missing values last in BOTH directions; locale-aware text
// (including ar); header-click cycle asc → desc → default.

const asc = (a: Parameters<typeof compareSortState>[0], b: Parameters<typeof compareSortState>[0], type: 'text' | 'number' | 'money' | 'date', locale?: string) =>
  compareSortState(a, b, type, 'asc', locale)
const desc = (a: Parameters<typeof compareSortState>[0], b: Parameters<typeof compareSortState>[0], type: 'text' | 'number' | 'money' | 'date', locale?: string) =>
  compareSortState(a, b, type, 'desc', locale)

test('numbers compare numerically, including numeric strings', () => {
  assert.ok(asc(2, 10, 'number') < 0)
  assert.ok(asc('9', '10', 'number') < 0) // string compare would put "10" first
  assert.ok(asc('0.5', 0.4, 'number') > 0)
  assert.ok(desc(2, 10, 'number') > 0)
})

test('text order is locale-aware and numeric ("9" < "10")', () => {
  assert.ok(asc('9', '10', 'text', 'en') < 0)
  assert.ok(asc('a9', 'a10', 'text', 'en') < 0)
  assert.ok(asc('apple', 'Banana', 'text', 'en') < 0) // base sensitivity: case-insensitive
})

test('ar locale collates Arabic script order', () => {
  // ا (alef) precedes ب (ba) in the Arabic alphabet.
  assert.ok(asc('ب', 'ا', 'text', 'ar') > 0)
  assert.ok(desc('ب', 'ا', 'text', 'ar') < 0)
})

test('money strings sort by amount: USD, euro-comma, NBSP grouping', () => {
  assert.ok(asc('$999.00', '$1,234.00', 'money') < 0)
  assert.ok(asc('12.33 USD', '12.34 USD', 'money') < 0)
  assert.ok(asc('999,00 €', '1 234,00 €', 'money') < 0) // comma decimal + NBSP grouping
  assert.ok(asc('-$5.00', '$3.00', 'money') < 0)
  assert.ok(asc('1,234', '1,235', 'money') < 0) // lone comma with 3-digit group = thousands
  assert.ok(desc('$999.00', '$1,234.00', 'money') > 0)
})

test('dates sort chronologically (ISO strings and epoch numbers)', () => {
  assert.ok(asc('2026-09-30T10:00:00Z', '2026-09-30T12:00:00Z', 'date') < 0)
  assert.ok(asc('2026-09-30', '2026-10-01', 'date') < 0)
  assert.ok(asc(1_000, 2_000, 'date') < 0)
  assert.ok(desc('2026-09-30T10:00:00Z', '2026-09-30T12:00:00Z', 'date') > 0)
})

test('missing values sort last in BOTH directions, never as 0', () => {
  for (const dir of ['asc', 'desc'] as const) {
    assert.ok(compareSortState(null, 5, 'number', dir) > 0)
    assert.ok(compareSortState(5, null, 'number', dir) < 0)
    assert.ok(compareSortState(undefined, 'x', 'text', dir) > 0)
    assert.ok(compareSortState('not-a-date', '2026-01-01', 'date', dir) > 0) // unparsable = missing
    assert.ok(compareSortState('(untagged)', '$3.00', 'money', dir) > 0)
    assert.equal(compareSortState(null, undefined, 'number', dir), 0)
  }
})

test('two present values keep their order only within one direction', () => {
  const a = asc('$1.00', '$2.00', 'money')
  const b = desc('$1.00', '$2.00', 'money')
  assert.ok(a < 0)
  assert.ok(b > 0)
  assert.equal(a, -b)
})

test('header-click cycle: unsorted → asc → desc → default', () => {
  assert.deepEqual(nextSortState(null, 'cost'), { key: 'cost', dir: 'asc' })
  assert.deepEqual(nextSortState({ key: 'cost', dir: 'asc' }, 'cost'), { key: 'cost', dir: 'desc' })
  assert.equal(nextSortState({ key: 'cost', dir: 'desc' }, 'cost'), null)
  // A different column always starts at asc.
  assert.deepEqual(nextSortState({ key: 'cost', dir: 'desc' }, 'model'), { key: 'model', dir: 'asc' })
})

test('header-click cycle returns a declared defaultSort as the third state', () => {
  const def = { key: 'created', dir: 'desc' as const }
  assert.deepEqual(nextSortState({ key: 'created', dir: 'asc' }, 'created'), { key: 'created', dir: 'desc' })
  assert.deepEqual(nextSortState({ key: 'created', dir: 'desc' }, 'created', def), def)
  assert.deepEqual(nextSortState(null, 'created', def), { key: 'created', dir: 'asc' })
})
