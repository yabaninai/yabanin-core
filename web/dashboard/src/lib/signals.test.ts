import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  BUDGET_NEAR_RATIO, CACHE_BASE_FLOOR, CACHE_DROP, CREDITS_CRITICAL_CENTS,
  CREDITS_LOW_CENTS, ERROR_RATE_JUMP, ERROR_RATE_JUMP_CRITICAL,
  P95_GROWTH_RATIO, P95_NOISE_FLOOR_MS, computeSignals, registryFormatters,
  type SignalCompare, type SignalInputs,
} from './signals.ts'

// AUX-18 acceptance: every detector is pinned at its boundary values, and an
// unknown input never produces a signal (unknown ≠ 0 — a missing measurement
// must not read as calm-or-breached either way).

const fmt = registryFormatters({ locale: 'en' })

const WINDOW = { org: 'org-1', from: '2026-09-01T00:00:00Z', to: '2026-09-08T00:00:00Z' }

function signalsFor(patch: Partial<SignalInputs>): ReturnType<typeof computeSignals> {
  return computeSignals({ ...WINDOW, ...patch }, fmt)
}

const cmp = (totals: Record<string, number | null>, previous: Record<string, number | null>, coverage?: SignalCompare['coverage']): SignalCompare =>
  ({ totals, previous, coverage })

test('team budget: boundaries at 80% / 100%, unknown inputs stay silent', () => {
  const budget = (spend: number, limit: number) => [{ team_id: 't1', spend_usd: spend, monthly_limit_usd: limit }]

  // Below the near threshold — no signal.
  assert.deepEqual(signalsFor({ teamBudgets: budget(799, 1000) }), [])
  // Exactly at the near threshold — warning.
  let out = signalsFor({ teamBudgets: budget(800, 1000) })
  assert.equal(out.length, 1)
  assert.equal(out[0].type, 'team-budget-near')
  assert.equal(out[0].severity, 'warning')
  // Just under the limit — still near, never exceeded.
  out = signalsFor({ teamBudgets: budget(999.9, 1000) })
  assert.equal(out[0].type, 'team-budget-near')
  // Exactly at the limit — exceeded.
  out = signalsFor({ teamBudgets: budget(1000, 1000) })
  assert.equal(out[0].type, 'team-budget-exceeded')
  assert.equal(out[0].severity, 'critical')
  // Over the limit stays exceeded (and the pct is honest, not clamped).
  out = signalsFor({ teamBudgets: budget(1200, 1000) })
  assert.equal(out[0].type, 'team-budget-exceeded')
  assert.equal(out[0].params.pct, fmt.pct(1.2))

  // Unknown ≠ 0: a zero/absent limit and unknown spend never signal…
  assert.deepEqual(signalsFor({ teamBudgets: budget(50, 0) }), [])
  assert.deepEqual(signalsFor({ teamBudgets: [{ team_id: 't1', spend_usd: null as unknown as number, monthly_limit_usd: 100 }] }), [])
  assert.deepEqual(signalsFor({ teamBudgets: [{ team_id: 't1', spend_usd: Number.NaN, monthly_limit_usd: 100 }] }), [])
  // …and a team without an id is skipped, not reported as "team (empty)".
  assert.deepEqual(signalsFor({ teamBudgets: [{ team_id: '', spend_usd: 5000, monthly_limit_usd: 100 }] }), [])
  // One breached team out of many yields exactly one signal for that team.
  out = signalsFor({ teamBudgets: [budget(50, 1000)[0], { team_id: 't2', spend_usd: 5000, monthly_limit_usd: 1000 }] })
  assert.equal(out.length, 1)
  assert.equal(out[0].id, 'team-budget:t2')
})

test('team budget: the message params are registry-formatted, never raw', () => {
  const out = signalsFor({ teamBudgets: [{ team_id: 't1', spend_usd: 1200, monthly_limit_usd: 1000 }] })
  assert.equal(out[0].params.spent, '$1,200.00')
  assert.equal(out[0].params.limit, '$1,000.00')
  assert.equal(out[0].params.pct, '120%')
  assert.equal(out[0].href, '#budgets')
  assert.equal(out[0].metricId, 'cost_usd')
  assert.equal(out[0].metricValue, 1200)
})

test('error rate: jump thresholds at +5pp / +15pp, unknown previous is not a zero baseline', () => {
  const rate = (cur: number | null, prev: number | null) =>
    signalsFor({ compare: cmp({ error_rate: cur }, { error_rate: prev }) })

  // Unknown on either side — no signal (never read as 0).
  assert.deepEqual(rate(null, 0.1), [])
  assert.deepEqual(rate(0.2, null), [])
  assert.deepEqual(rate(undefined as unknown as number, 0.1), [])

  // Small growth and a decrease — no signal.
  assert.deepEqual(rate(0.03, 0.02), [])
  assert.deepEqual(rate(0.01, 0.05), [])
  // Zero current errors — nothing to attend to.
  assert.deepEqual(rate(0, 0.05), [])

  // Exactly +5pp — warning boundary.
  let out = rate(0.10, 0.05)
  assert.equal(out.length, 1)
  assert.equal(out[0].type, 'error-rate-jump')
  assert.equal(out[0].severity, 'warning')
  // Just under critical stays warning.
  out = rate(0.19999, 0.05)
  assert.equal(out[0].severity, 'warning')
  // Exactly +15pp — critical.
  out = rate(0.20, 0.05)
  assert.equal(out[0].severity, 'critical')

  // The params carry registry-formatted percents for both periods.
  out = rate(0.20, 0.05)
  assert.equal(out[0].params.current, '20%')
  assert.equal(out[0].params.previous, '5%')
  assert.equal(out[0].metricPrevious, 0.05)
  // The evidence link is the analytics explorer with the same compare query.
  assert.ok(out[0].href.startsWith('#analytics?'))
  assert.ok(out[0].href.includes('m=error_rate'))
  assert.ok(out[0].href.includes('cmp=1'))
  assert.ok(out[0].href.includes('org=org-1'))
})

test('latency p95: 1.5× growth over a real baseline only', () => {
  const p95 = (cur: number | null, prev: number | null) =>
    signalsFor({ compare: cmp({ latency_p95: cur }, { latency_p95: prev }) })

  assert.deepEqual(p95(null, 800), [])
  assert.deepEqual(p95(2000, null), [])
  // Below the noise floor the baseline proves nothing.
  assert.deepEqual(p95(500, P95_NOISE_FLOOR_MS - 1), [])
  // Growth under the ratio — no signal.
  assert.deepEqual(p95(Math.floor(800 * (P95_GROWTH_RATIO - 0.01)), 800), [])
  // Exactly 1.5× — warning.
  const out = p95(800 * P95_GROWTH_RATIO, 800)
  assert.equal(out.length, 1)
  assert.equal(out[0].type, 'latency-p95-jump')
  assert.equal(out[0].severity, 'warning')
  assert.equal(out[0].params.current, fmt.ms(1200))
  assert.equal(out[0].params.previous, fmt.ms(800))
})

test('cache hit rate: drop of 10pp over a non-negligible base', () => {
  const hit = (cur: number | null, prev: number | null) =>
    signalsFor({ compare: cmp({ cache_hit_rate: cur }, { cache_hit_rate: prev }) })

  assert.deepEqual(hit(null, 0.5), [])
  assert.deepEqual(hit(0.4, null), [])
  // A negligible base cannot "drop".
  assert.deepEqual(hit(0, CACHE_BASE_FLOOR - 0.01), [])
  // Drop smaller than the threshold — no signal (FP-close values included).
  assert.deepEqual(hit(0.5 - CACHE_DROP + 0.001, 0.5), [])
  assert.deepEqual(hit(0.4, 0.5), [])
  // A clear drop warns; a drop to a measured zero is still a signal.
  let out = hit(0.25, 0.5)
  assert.equal(out.length, 1)
  assert.equal(out[0].type, 'cache-hit-dropped')
  out = hit(0, 0.5)
  assert.equal(out.length, 1)
  assert.equal(out[0].params.current, '0%')
})

test('unpriced coverage: share boundaries — unknown/0 silent, partial warning, all critical', () => {
  const unpriced = (share: number | null, requests: number | null = 30) =>
    signalsFor({ compare: cmp({ requests: 100 }, {}, { unpriced_requests: requests, unpriced_share: share }) })

  assert.deepEqual(unpriced(null), [])
  assert.deepEqual(unpriced(undefined as unknown as number), [])
  assert.deepEqual(unpriced(0), [])

  let out = unpriced(0.35)
  assert.equal(out.length, 1)
  assert.equal(out[0].type, 'unpriced-requests')
  assert.equal(out[0].severity, 'warning')
  assert.equal(out[0].params.pct, '35%')
  assert.equal(out[0].metricValue, 30)

  // Exactly 1 — nothing is priced; cost is unknown, not $0.
  out = unpriced(1, 100)
  assert.equal(out[0].severity, 'critical')
  assert.ok(out[0].messageKey.includes('unpricedAll'))
  // Unknown request COUNT keeps the signal (share is measured) with value null.
  out = unpriced(0.35, null)
  assert.equal(out.length, 1)
  assert.equal(out[0].metricValue, null)
})

test('credits: <$5 low, ≤ −$1 critical, unknown silent (CreditsPage thresholds)', () => {
  const credits = (cents: number | null) => signalsFor({ creditBalanceCents: cents })

  assert.deepEqual(credits(null), [])
  assert.deepEqual(credits(undefined as unknown as number), [])
  assert.deepEqual(credits(Number.NaN), [])
  // Boundary: at $5 there is no signal; $4.99 warns.
  assert.deepEqual(credits(CREDITS_LOW_CENTS), [])
  let out = credits(CREDITS_LOW_CENTS - 1)
  assert.equal(out[0].type, 'credits-low')
  assert.equal(out[0].severity, 'warning')
  assert.equal(out[0].params.balance, '$4.99')
  // Zero balance is measured and low — never silently calm.
  out = credits(0)
  assert.equal(out[0].type, 'credits-low')
  // Boundary: exactly −$1 — critical; just above — low.
  out = credits(CREDITS_CRITICAL_CENTS)
  assert.equal(out[0].type, 'credits-negative')
  assert.equal(out[0].severity, 'critical')
  out = credits(CREDITS_CRITICAL_CENTS + 1)
  assert.equal(out[0].type, 'credits-low')
  assert.equal(out[0].params.balance, '-$0.99')
})

test('spend alert: breached only when today\'s spend reaches an active threshold', () => {
  const alert = (threshold: number | null, spend: number | null) =>
    signalsFor({ spendAlert: { threshold_usd: threshold, spend_today: spend } })

  // Disabled alert or unknown spend — silent.
  assert.deepEqual(alert(null, 60), [])
  assert.deepEqual(alert(0, 60), [])
  assert.deepEqual(alert(50, null), [])
  // Below the threshold — silent.
  assert.deepEqual(alert(50, 49.99), [])
  // Exactly at the threshold — critical (the checker fires at >=).
  const out = alert(50, 50)
  assert.equal(out.length, 1)
  assert.equal(out[0].type, 'spend-alert-breached')
  assert.equal(out[0].severity, 'critical')
  assert.equal(out[0].params.spend, '$50.00')
  assert.equal(out[0].href, '#budgets')
})

test('signals sort critical before warning with a stable type order', () => {
  const out = signalsFor({
    teamBudgets: [{ team_id: 't1', spend_usd: 1200, monthly_limit_usd: 1000 }, { team_id: 't2', spend_usd: 900, monthly_limit_usd: 1000 }],
    compare: cmp(
      // +5pp exactly (FP: 0.1 − 0.05 lands just above the boundary) — warning.
      { error_rate: 0.1, latency_p95: 3000, cache_hit_rate: 0.1 },
      { error_rate: 0.05, latency_p95: 800, cache_hit_rate: 0.5 },
      { unpriced_requests: 10, unpriced_share: 0.4 },
    ),
    spendAlert: { threshold_usd: 50, spend_today: 60 },
    creditBalanceCents: -500,
  })
  assert.deepEqual(out.map(s => [s.type, s.severity]), [
    ['team-budget-exceeded', 'critical'],
    ['spend-alert-breached', 'critical'],
    ['credits-negative', 'critical'],
    ['team-budget-near', 'warning'],
    ['error-rate-jump', 'warning'],
    ['unpriced-requests', 'warning'],
    ['latency-p95-jump', 'warning'],
    ['cache-hit-dropped', 'warning'],
  ])
})

test('absent inputs produce no signals — the lib never invents calm from missing data', () => {
  assert.deepEqual(computeSignals({ ...WINDOW }, fmt), [])
  assert.deepEqual(signalsFor({ compare: cmp({}, {}) }), [])
  assert.deepEqual(signalsFor({ teamBudgets: [] }), [])
  // A signal with no unknown-blown params: every param is a formatted string.
  const out = signalsFor({
    teamBudgets: [{ team_id: 't1', spend_usd: 1200, monthly_limit_usd: 1000 }],
  })
  for (const s of out) {
    for (const v of Object.values(s.params)) {
      assert.equal(typeof v, 'string')
      assert.ok(!(v as string).includes('NaN'))
      assert.ok(!(v as string).includes('null'))
    }
  }
})

test('threshold constants stay pinned to the documented values', () => {
  assert.equal(BUDGET_NEAR_RATIO, 0.8)
  assert.equal(ERROR_RATE_JUMP, 0.05)
  assert.equal(ERROR_RATE_JUMP_CRITICAL, 0.15)
  assert.equal(P95_GROWTH_RATIO, 1.5)
  assert.equal(P95_NOISE_FLOOR_MS, 200)
  assert.equal(CACHE_DROP, 0.1)
  assert.equal(CACHE_BASE_FLOOR, 0.2)
  assert.equal(CREDITS_LOW_CENTS, 500)
  assert.equal(CREDITS_CRITICAL_CENTS, -100)
})

test('registry formatters route through the AUX-10 registry (locale-aware, en contract)', () => {
  assert.equal(fmt.money(1200), '$1,200.00')
  assert.equal(fmt.pct(0.123), '12.3%')
  assert.equal(fmt.ms(1875.4), '1,875')
  assert.equal(fmt.count(12345), '12,345')
  // Non-default locale formatting flows through the registry too (de groups
  // decimals with a comma and a locale-specific narrow space before %).
  const de = registryFormatters({ locale: 'de' })
  assert.match(de.pct(0.123), /^12,3\s*%$/)
  // Money keeps the honest USD unit (no FX) in a non-USD presentation.
  const eur = registryFormatters({ locale: 'en', currency: 'EUR' })
  assert.equal(eur.money(1200), '1,200.00 USD')
})
