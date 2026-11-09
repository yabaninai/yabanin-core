import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  analyticsDailyByDim,
  dayKey,
  forecastAlert,
  forecastDaily,
  forecastMonthly,
  utcDayStart,
} from './budgetForecast.ts'

const NOON = new Date('2026-10-07T12:00:00Z')

test('dayKey and utcDayStart are UTC-based', () => {
  assert.equal(dayKey(NOON), '2026-10-07')
  assert.equal(utcDayStart(NOON).toISOString(), '2026-10-07T00:00:00.000Z')
})

test('forecastMonthly: limit already spent is exceeded', () => {
  assert.deepEqual(forecastMonthly(100, 100, [40, 60], NOON), { kind: 'exceeded' })
  assert.deepEqual(forecastMonthly(100, 120, [40, 60], NOON), { kind: 'exceeded' })
})

test('forecastMonthly: date from the pace of the last three full days', () => {
  // pace = mean(80, 90, 100) = 90/day; remaining 200 → ~2.22 days from noon.
  const at = new Date(NOON.getTime() + ((1000 - 800) / 90) * 86_400_000)
  assert.deepEqual(forecastMonthly(1000, 800, [80, 90, 100], NOON), { kind: 'date', at })
})

test('forecastMonthly: pace beyond the month end is period_ok', () => {
  // pace 5/day, remaining 950 → 190 days — far past October.
  assert.deepEqual(forecastMonthly(1000, 50, [5, 5, 5], NOON), { kind: 'period_ok' })
})

test('forecastMonthly: zero pace and empty series are honest', () => {
  assert.deepEqual(forecastMonthly(1000, 50, [0, 0, 0], NOON), { kind: 'period_ok' })
  assert.deepEqual(forecastMonthly(1000, 50, [], NOON), { kind: 'unknown' })
  assert.deepEqual(forecastMonthly(0, 50, [10], NOON), { kind: 'unknown' })
})

test('forecastDaily: today spend over the limit is exceeded', () => {
  assert.deepEqual(forecastDaily(100, 100.5, NOON, null), { kind: 'exceeded' })
})

test('forecastDaily: date from today\u2019s own pace once the day is underway', () => {
  // elapsed 12h = 43_200_000 ms; pace 60/12h; limit 100 → 20h into the day.
  const at = utcDayStart(NOON).getTime() + 100 / (60 / 43_200_000)
  assert.deepEqual(forecastDaily(100, 60, NOON, null), { kind: 'date', at: new Date(at) })
})

test('forecastDaily: today\u2019s pace hitting the day end exactly is period_ok', () => {
  // pace 50/12h projects the limit exactly at the day boundary — capped.
  assert.deepEqual(forecastDaily(100, 50, NOON, null), { kind: 'period_ok' })
})

test('forecastDaily: falls back to the previous-days average when today is quiet', () => {
  const early = new Date('2026-10-07T00:30:00Z')
  const at = utcDayStart(early).getTime() + (100 / 200) * 86_400_000
  assert.deepEqual(forecastDaily(100, 0, early, 200), { kind: 'date', at: new Date(at) })
})

test('forecastDaily: today\u2019s own pace wins over the average once usable', () => {
  const early = new Date('2026-10-07T00:30:00Z')
  // Today: $2 in 30 min projects $96 < limit → period_ok, even though the
  // previous-days average (200) would cross at noon. Current pace wins.
  assert.deepEqual(forecastDaily(100, 2, early, 200), { kind: 'period_ok' })
})

test('forecastDaily: average pace that cannot reach the limit is period_ok', () => {
  const early = new Date('2026-10-07T00:30:00Z')
  assert.deepEqual(forecastDaily(100, 2, early, 50), { kind: 'period_ok' })
})

test('forecastDaily: no usable pace anywhere is unknown', () => {
  const early = new Date('2026-10-07T00:05:00Z')
  assert.deepEqual(forecastDaily(100, 0, early, null), { kind: 'unknown' })
  assert.deepEqual(forecastDaily(100, 0, early, 0), { kind: 'unknown' })
  assert.deepEqual(forecastDaily(0, 5, NOON, 10), { kind: 'unknown' })
})

test('forecastAlert: projected threshold time within the running day', () => {
  // elapsed 12h; pace 12.5/12h; threshold 20 → 19.2h into the day.
  const at = utcDayStart(NOON).getTime() + 20 / (12.5 / 43_200_000)
  assert.deepEqual(forecastAlert(20, 12.5, NOON), { kind: 'date', at: new Date(at) })
})

test('forecastAlert: a pace that misses the threshold today is period_ok', () => {
  assert.deepEqual(forecastAlert(50, 12.5, NOON), { kind: 'period_ok' })
})

test('forecastAlert: exceeded, quiet day and fresh day stay honest', () => {
  assert.deepEqual(forecastAlert(50, 60, NOON), { kind: 'exceeded' })
  assert.deepEqual(forecastAlert(50, 0, NOON), { kind: 'unknown' })
  const fresh = new Date('2026-10-07T00:05:00Z')
  assert.deepEqual(forecastAlert(50, 1, fresh), { kind: 'unknown' })
  assert.deepEqual(forecastAlert(0, 10, NOON), { kind: 'unknown' })
})

const RESULT = {
  columns: [
    { name: 'time', type: 'time' },
    { name: 'agent', type: 'string' },
    { name: 'cost_usd', type: 'number' },
  ],
  rows: [
    ['2026-10-05T00:00:00Z', 'agent-1', 10],
    ['2026-10-06T00:00:00Z', 'agent-1', 20],
    ['2026-10-07T00:00:00Z', 'agent-1', 5],
    ['2026-10-06T00:00:00Z', 'agent-2', 7],
  ],
}

test('analyticsDailyByDim: per-day series with a partial today', () => {
  const series = analyticsDailyByDim(RESULT, 'agent', '2026-10-07')
  assert.equal(series.size, 2)
  const a1 = series.get('agent-1')!
  assert.equal(a1.perDay.get('2026-10-05'), 10)
  assert.equal(a1.today, 5)
  assert.equal(a1.total, 35)
  assert.equal(series.get('agent-2')!.today, 0)
})

test('analyticsDailyByDim: unknown dimension or metric yields an empty map', () => {
  assert.equal(analyticsDailyByDim(RESULT, 'team', '2026-10-07').size, 0)
  assert.equal(
    analyticsDailyByDim({ columns: [{ name: 'time', type: 'time' }], rows: [] }, 'agent', '2026-10-07').size,
    0,
  )
})

test('analyticsDailyByDim: skips placeholder and malformed rows', () => {
  const r = {
    columns: RESULT.columns,
    rows: [
      ['2026-10-06T00:00:00Z', '(other)', 99],
      ['2026-10-06T00:00:00Z', null, 99],
      ['garbage', 'agent-1', 5],
      ['2026-10-06T00:00:00Z', 'agent-1', 'not-a-number'],
    ],
  }
  const series = analyticsDailyByDim(r, 'agent', '2026-10-07')
  assert.equal(series.size, 0)
})
