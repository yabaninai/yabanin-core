// real date — "0001-01-01T00:00:00Z" and unparseable input render as "—",
// valid dates render locale-correct as before.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { INVALID_DATE, formatDateIn, formatDateTimeIn, renderableDate } from './date.ts'

test('zero and pre-2000 instants render as the em dash', () => {
  assert.equal(formatDateIn('en', '0001-01-01T00:00:00Z'), INVALID_DATE)
  assert.equal(formatDateTimeIn('en', '0001-01-01T00:00:00Z'), INVALID_DATE)
  assert.equal(formatDateIn('en', new Date(Date.UTC(1, 0, 1))), INVALID_DATE)
  assert.equal(formatDateIn('en', '1970-01-01T00:00:00Z'), INVALID_DATE)
})

test('unparseable input renders as the em dash', () => {
  assert.equal(formatDateIn('en', ''), INVALID_DATE)
  assert.equal(formatDateIn('en', 'not-a-date'), INVALID_DATE)
  assert.equal(formatDateIn('en', new Date('nope')), INVALID_DATE)
  assert.equal(formatDateTimeIn('en', ''), INVALID_DATE)
})

test('valid dates render locale-correct, unchanged by the guard', () => {
  const out = formatDateIn('en', '2026-10-02T12:34:56Z', 'UTC')
  assert.match(out, /Oct/)
  assert.match(out, /2026/)

  const withTime = formatDateTimeIn('en', '2026-10-02T12:34:56Z', 'UTC')
  assert.match(withTime, /2026/)
  assert.match(withTime, /12:34/)
})

test('org timezone is honored for valid dates', () => {
  // 2026-10-02T00:30:00Z is still Oct 1 in Los Angeles (UTC-7).
  assert.match(formatDateIn('en', '2026-10-02T00:30:00Z', 'America/Los_Angeles'), /Oct 1/)
  assert.match(formatDateIn('en', '2026-10-02T00:30:00Z', 'UTC'), /Oct 2/)
  // Missing timezone falls back to UTC.
  assert.match(formatDateIn('en', '2026-10-02T00:30:00Z'), /Oct 2/)
})

test('invalid timezone falls back instead of throwing', () => {
  assert.equal(formatDateIn('en', '2026-10-02T12:34:56Z', 'Mars/Olympus'), '2026-10-02')
  const dt = formatDateTimeIn('en', '2026-10-02T12:34:56Z', 'Mars/Olympus')
  assert.equal(dt, '2026-10-02T12:34:56.000Z')
})

test('renderableDate passes real dates through and rejects placeholders', () => {
  const d = new Date('2026-10-02T12:34:56Z')
  assert.equal(renderableDate(d), d)
  assert.equal(renderableDate('2026-10-02T12:34:56Z')?.getTime(), d.getTime())
  assert.equal(renderableDate('0001-01-01T00:00:00Z'), null)
  assert.equal(renderableDate('garbage'), null)
})
