import { test } from 'node:test'
import assert from 'node:assert/strict'
import { formatAsOfTime, parseAutoRefreshInterval } from './freshness.ts'

// AUX-23: the stored auto-refresh choice must be honest — anything that is
// not one of the offered presets (off / 30 s / 1 min / 5 min) reads as off.
test('parseAutoRefreshInterval accepts the preset whitelist', () => {
  assert.equal(parseAutoRefreshInterval('0'), 0)
  assert.equal(parseAutoRefreshInterval('30000'), 30_000)
  assert.equal(parseAutoRefreshInterval('60000'), 60_000)
  assert.equal(parseAutoRefreshInterval('300000'), 300_000)
})

test('parseAutoRefreshInterval reads garbage as off', () => {
  assert.equal(parseAutoRefreshInterval(null), 0)
  assert.equal(parseAutoRefreshInterval(undefined), 0)
  assert.equal(parseAutoRefreshInterval(''), 0)
  assert.equal(parseAutoRefreshInterval('banana'), 0)
  assert.equal(parseAutoRefreshInterval('999'), 0) // not an offered preset
  assert.equal(parseAutoRefreshInterval('-30000'), 0)
  assert.equal(parseAutoRefreshInterval('1e9'), 0)
})

// AUX-23: the «данные на ЧЧ:ММ» label is a real clock readout in the
// operator's local wall clock (the moment the data landed), locale-aware.
test('formatAsOfTime renders the local hour:minute', () => {
  const epoch = Date.UTC(2026, 9, 1, 14, 32)
  const d = new Date(epoch)
  const expected = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  assert.equal(formatAsOfTime(epoch, 'en-GB'), expected)
})

test('formatAsOfTime zero-pads and survives an unknown locale', () => {
  const epoch = Date.UTC(2026, 9, 1, 5, 7)
  const d = new Date(epoch)
  const expected = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  assert.equal(formatAsOfTime(epoch, 'en-GB'), expected)
  // An unknown locale tag falls back to default-locale formatting; either
  // way the label stays a readable hour:minute value.
  assert.match(formatAsOfTime(epoch, 'zz-ZZ-INVALID'), /^\d{1,2}:\d{2}( ?[AP]M)?$/)
})
