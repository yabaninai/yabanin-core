import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  LINE_MIN_POINTS,
  chartDataState,
  chartLineType,
  chooseChartKind,
  compactMoneyLabel,
  compactNumberLabel,
  detectGranularity,
  sortByTime,
  timeTickLabel,
  timeTooltipLabel,
  valueDomain,
} from './chartData.ts'

describe('chartData (IMP-06)', () => {
  // D-08: the cost/savings endpoints return daily buckets newest-first.
  it('sorts the X axis ascending by time without mutating the input', () => {
    const input = [
      { date: '2026-09-29', cost: 3 },
      { date: '2026-09-27', cost: 1 },
      { date: '2026-09-28', cost: 2 },
    ]
    const sorted = sortByTime(input, r => r.date)
    assert.deepEqual(sorted.map(r => r.date), ['2026-09-27', '2026-09-28', '2026-09-29'])
    // the input array and its order stay untouched (page reuses raw rows)
    assert.deepEqual(input.map(r => r.date), ['2026-09-29', '2026-09-27', '2026-09-28'])
  })

  it('sorts hourly ISO buckets and keeps unparseable labels last, stable', () => {
    const rows = [
      { x: '2026-09-29T14:00:00Z', v: 'b' },
      { x: 'garbage', v: 'x1' },
      { x: '2026-09-29T08:00:00Z', v: 'a' },
      { x: 'garbage', v: 'x2' },
    ]
    const sorted = sortByTime(rows, r => r.x)
    assert.deepEqual(sorted.map(r => r.v), ['a', 'b', 'x1', 'x2'])
  })

  it('detects day vs hour buckets and rejects non-time categories', () => {
    assert.equal(detectGranularity(['2026-09-27', '2026-09-28', '2026-09-29']), 'day')
    // the analytics day bucket is an all-midnight ISO stamp (date_trunc day)
    assert.equal(detectGranularity(['2026-09-01T00:00:00Z', '2026-09-02T00:00:00Z']), 'day')
    assert.equal(detectGranularity(['2026-09-29T08:00:00Z', '2026-09-29T09:00:00Z']), 'hour')
    assert.equal(detectGranularity(['2026-09-29T00:00:00Z', '2026-09-29T01:00:00Z']), 'hour')
    assert.equal(detectGranularity(['gpt-4o', 'claude']), null)
    assert.equal(detectGranularity([]), null)
  })

  // UX-06: axes showed raw ISO "2026-09-29T00:00:00Z".
  it('formats day ticks as a short localized date, never ISO', () => {
    const en = timeTickLabel('2026-09-29', 'day', 'en', 'UTC')
    assert.match(en, /^Sep \d/)
    assert.ok(!en.includes('2026-09-29'))
    const ru = timeTickLabel('2026-09-29', 'day', 'ru', 'UTC')
    assert.match(ru, /29/)
    assert.match(ru, /[а-яё]/i)
    assert.ok(!ru.includes('-') && !ru.includes('T'))
  })

  it('formats hour ticks as wall-clock time in the org timezone', () => {
    assert.equal(timeTickLabel('2026-09-29T14:00:00Z', 'hour', 'en', 'UTC'), '14:00')
    assert.equal(timeTickLabel('2026-09-29T14:00:00Z', 'hour', 'en', 'Europe/Berlin'), '16:00')
    assert.ok(!timeTickLabel('2026-09-29T14:00:00Z', 'hour', 'en', 'UTC').includes('2026'))
  })

  it('formats tooltip labels with the full date and the timezone', () => {
    const day = timeTooltipLabel('2026-09-29', 'day', 'en', 'UTC')
    assert.ok(day.includes('2026') && day.includes('UTC'))
    const hour = timeTooltipLabel('2026-09-29T14:00:00Z', 'hour', 'en', 'Europe/Berlin')
    assert.ok(hour.includes('2026') && hour.includes('Europe/Berlin'))
    assert.match(hour, /4:00/) // 14:00Z = 16:00 Berlin = "4:00 PM" (en medium)
    // unparseable label passes through (presentation must not break)
    assert.equal(timeTooltipLabel('n/a', 'day', 'en', 'UTC'), 'n/a')
  })

  // UX-06: daily buckets rendered as a smoothed line.
  it('renders buckets below the threshold as columns and a line from 8 points', () => {
    assert.equal(chooseChartKind(1), 'bar')
    assert.equal(chooseChartKind(4), 'bar')
    assert.equal(chooseChartKind(LINE_MIN_POINTS - 1), 'bar')
    assert.equal(chooseChartKind(8), 'line')
    assert.equal(chooseChartKind(30), 'line')
    // single point is an explicit state and renders as a column, not a dot
    assert.equal(chartDataState(1), 'single')
    assert.equal(chartDataState(0), 'empty')
    assert.equal(chartDataState(2), 'many')
  })

  // UX-06: monotone splines over few daily points invented peaks.
  it('interpolates lines linearly (monotone → linear)', () => {
    assert.equal(chartLineType(), 'linear')
    assert.notEqual(chartLineType(), 'monotone')
  })

  // acceptance: a line never goes below zero for non-negative data.
  it('pins the Y lower bound at 0 for non-negative data, auto for negatives', () => {
    assert.deepEqual(valueDomain([12.5, 0, 3]), [0, 'auto'])
    assert.deepEqual(valueDomain([0, 0]), [0, 'auto'])
    assert.deepEqual(valueDomain([5, -1]), ['auto', 'auto'])
    assert.deepEqual(valueDomain([]), ['auto', 'auto'])
    assert.deepEqual(valueDomain([Number.NaN, 4]), [0, 'auto'])
  })

  it('formats compact Y ticks for numbers and money', () => {
    assert.equal(compactNumberLabel(12_000, 'en'), '12K')
    assert.equal(compactMoneyLabel(1_200, 'en', 'USD'), '$1.2K')
    // TP-05 honesty: a non-USD presentation never relabels USD as foreign money
    const eur = compactMoneyLabel(1_200, 'en', 'EUR')
    assert.ok(eur.includes('USD') && !eur.includes('€'))
    assert.equal(compactMoneyLabel(Number.NaN, 'en', 'USD'), 'NaN')
  })
})
