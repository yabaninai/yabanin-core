import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  ALL_METRICS, GAP_NULL, METRICS, METRIC_GROUPS,
  formatMetricValue, formatPercentRatio, metricDisplayUnit, metricMeta,
} from './analyticsQuery.ts'

// AUX-10 acceptance: the metric glossary is complete — every registry metric
// has a label AND a "what this means" description in EVERY locale file, and
// the registry never hands out a raw id (or a raw String(number)) as UI text.
// The test scans src/i18n/*.json directly (the same files i18next loads), so
// adding a locale file without the glossary fails here, before any screen
// renders a missing key.

const here = dirname(fileURLToPath(import.meta.url))
const i18nDir = join(here, '..', 'i18n')
const localeFiles = readdirSync(i18nDir).filter(f => f.endsWith('.json')).map(f => f.replace(/\.json$/, '')).sort()

// The dashboard ships exactly these locales (src/i18n/index.ts LOCALES).
// A ninth locale must land together with its glossary or this test fails.
const EXPECTED_LOCALES = ['ar', 'en', 'es', 'hi', 'id', 'ja', 'ko', 'pt-BR']

test('the i18n directory holds exactly the shipped locale files', () => {
  assert.deepEqual(localeFiles, EXPECTED_LOCALES)
})

function loadSection(locale: string, section: string): Record<string, unknown> {
  const data = JSON.parse(readFileSync(join(i18nDir, `${locale}.json`), 'utf-8')) as Record<string, Record<string, unknown>>
  const out = data[section]
  assert.ok(out && typeof out === 'object', `${locale}: missing section ${section}`)
  return out
}

test('every metric has a real label and description in every locale', () => {
  for (const locale of localeFiles) {
    const metric = loadSection(locale, 'analytics').metric as Record<string, unknown>
    const metricDesc = loadSection(locale, 'analytics').metricDesc as Record<string, unknown>
    for (const m of METRICS) {
      const label = metric[m.id]
      assert.ok(typeof label === 'string' && label.trim().length > 0, `${locale}: analytics.metric.${m.id} missing`)
      // The label is never the raw id and never a missing-key placeholder.
      assert.notEqual(label, m.id, `${locale}: metric ${m.id} renders its raw id as the label`)
      assert.ok(!label.includes('missing:'), `${locale}: metric ${m.id} label is a missing-key placeholder`)
      const desc = metricDesc[m.id]
      assert.ok(typeof desc === 'string' && desc.trim().length > 0, `${locale}: analytics.metricDesc.${m.id} missing`)
      assert.notEqual(desc, m.descKey, `${locale}: metric ${m.id} description is the raw key`)
      assert.ok(!desc.includes('missing:'), `${locale}: metric ${m.id} description is a missing-key placeholder`)
      assert.notEqual(desc, label, `${locale}: metric ${m.id} description repeats the label`)
    }
  }
})

test('the tooltip affordance strings exist in every locale', () => {
  for (const locale of localeFiles) {
    const common = loadSection(locale, 'common')
    assert.ok(typeof common.metricHintAria === 'string' && common.metricHintAria.length > 0, `${locale}: common.metricHintAria missing`)
    assert.ok(typeof common.metricHint === 'string' && common.metricHint.length > 0, `${locale}: common.metricHint missing`)
  }
})

test('the registry never exposes the raw id as a label', () => {
  for (const m of METRICS) {
    // Names resolve through i18n keys only; an unknown id has NO entry at all
    // (no fallback object that could leak the id to the UI).
    assert.equal(m.labelKey, `analytics.metric.${m.id}`)
    assert.equal(m.descKey, `analytics.metricDesc.${m.id}`)
    assert.equal(metricMeta('no_such_metric'), undefined)
    // Every registry id is covered by the flat list the screens iterate.
    assert.ok(ALL_METRICS.includes(m.id))
  }
  // Groups and ALL_METRICS stay derived from the single registry.
  assert.deepEqual(Object.values(METRIC_GROUPS).flat(), ALL_METRICS)
})

test('units and formats mirror the server contract', () => {
  const byFormat: Record<string, string[]> = {}
  for (const m of METRICS) {
    const expected = m.unit === 'usd' ? 'money'
      : m.unit === 'ratio' ? 'percent'
      : m.unit === 'ms' ? 'ms'
      : 'number'
    assert.equal(m.format, expected, `${m.id}: format must follow the server unit ${m.unit}`)
    ;(byFormat[m.format] ??= []).push(m.id)
  }
  assert.ok(byFormat.money!.includes('cost_usd'))
  assert.ok(byFormat.percent!.includes('error_rate'))
  assert.ok(byFormat.ms!.length >= 4)
  // Gap semantics (line breaks instead of fake zeros) only apply to rates and
  // percentiles — all of them must be registry metrics.
  for (const id of GAP_NULL) assert.ok(metricMeta(id), `GAP_NULL id ${id} is not in the registry`)
})

test('values render per the numbers contract (localized, never raw)', () => {
  // Money goes through the USD money core: grouped, currency-honest.
  const cost = formatMetricValue('cost_usd', 1234.5, { locale: 'en' })
  assert.equal(cost, '$1,234.50')
  // A tiny real cost must not collapse to $0.00 (money.ts contract).
  assert.equal(formatMetricValue('cost_usd', 0.000004, { locale: 'en' }), '$0.000004')
  // Ratios render as percents, not 0..1 fractions.
  assert.equal(formatMetricValue('error_rate', 0.123, { locale: 'en' }), '12.3%')
  // Counts and tokens group digits; ms keeps display precision (≥100ms →
  // whole ms, below that one decimal).
  assert.equal(formatMetricValue('requests', 12345, { locale: 'en' }), '12,345')
  assert.equal(formatMetricValue('latency_p95', 1234.56, { locale: 'en' }), '1,235')
  assert.equal(formatMetricValue('ttft_p50', 12.34, { locale: 'en' }), '12.3')
  // Locale-aware: ar uses Arabic-Indic digits, ja groups with narrow spaces… —
  // both must differ from the raw String(number).
  for (const locale of ['ar', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es']) {
    assert.notEqual(formatMetricValue('requests', 12345, { locale }), '12345')
  }
  // Unknown is never formatted as 0.
  assert.equal(formatMetricValue('cost_usd', null), null)
  assert.equal(formatMetricValue('cost_usd', Number.NaN), null)
  // An unknown (future server) metric still renders a localized number.
  assert.equal(formatMetricValue('future_metric', 12345, { locale: 'en' }), '12,345')
  // Delta/share helper is a percent, not a fraction.
  assert.equal(formatPercentRatio(0.123, 'en'), '12.3%')
})

test('display units match the plan contract', () => {
  assert.equal(metricDisplayUnit('cost_usd'), 'USD')
  assert.equal(metricDisplayUnit('cost_per_request'), 'USD')
  assert.equal(metricDisplayUnit('error_rate'), '%')
  assert.equal(metricDisplayUnit('latency_p95'), 'ms')
  assert.equal(metricDisplayUnit('tokens_in'), 'tokens')
  assert.equal(metricDisplayUnit('requests'), undefined)
  assert.equal(metricDisplayUnit('no_such_metric'), undefined)
})
