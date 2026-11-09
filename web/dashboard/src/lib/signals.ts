// AUX-18 — the "requires attention" signal detectors (Overview inbox).
//
// Pure client-side rules over data that already exists behind existing client
// methods (no new endpoints): the analytics compare query (error rate, p95,
// cache hit rate, pricing coverage), team budgets (budgets.manage), the org
// spend alert and the credit balance (both root-only server-side). The lib is
// node-testable: no react/i18next imports — the display vocabulary comes from
// the AUX-10 metric registry (analyticsQuery.ts) through the formatter port,
// and the messages are i18n KEYS + preformatted params, never raw numbers.
//
// Honesty rules (plan "Числа", card acceptance "unknown ≠ 0"):
//   - an unknown input produces no signal — an unmeasured error rate or a
//     missing budget limit is never folded into 0 and never reported as calm;
//   - every signal carries a severity, a human "why" with the number, and a
//     link to the existing page that shows the evidence.

import {
  formatMetricValue, formatPercentRatio, serializeAnalyticsHash,
  type MetricFormatOptions,
} from './analyticsQuery.ts'

export type SignalType =
  | 'team-budget-exceeded'
  | 'team-budget-near'
  | 'spend-alert-breached'
  | 'error-rate-jump'
  | 'latency-p95-jump'
  | 'cache-hit-dropped'
  | 'unpriced-requests'
  | 'credits-negative'
  | 'credits-low'

export type SignalSeverity = 'critical' | 'warning'

export interface Signal {
  /** Stable id ("team-budget:team-1") — dedupe/keys in the inbox UI. */
  id: string
  type: SignalType
  severity: SignalSeverity
  /** i18n key under signals.* — rendered with `params` by the caller. */
  messageKey: string
  /** Preformatted interpolation params (registry-formatted, never raw). */
  params: Record<string, string | number>
  /** Registry metric behind the headline number, when one exists (AUX-10). */
  metricId?: string
  /** Raw measured value (registry formatting happens at render; null = unknown). */
  metricValue?: number | null
  /** Raw value of the compared previous period, when the signal is a delta. */
  metricPrevious?: number | null
  /** Existing route that shows the evidence (no new pages/endpoints). */
  href: string
  /** i18n key of the action-link label. */
  linkKey: string
}

/** The compare slice of an /api/analytics/query result (client.ts). */
export interface SignalCompare {
  totals: Record<string, number | null>
  previous: Record<string, number | null>
  coverage?: { unpriced_requests?: number | null; unpriced_share?: number | null } | null
}

/** Structural slice of TeamSpendSummary (api/client.ts) — keeps the lib decoupled. */
export interface TeamBudgetLike {
  team_id: string
  spend_usd: number
  monthly_limit_usd: number
}

/** Structural slice of OrgSpendAlertSettings (spend_today is server-computed). */
export interface SpendAlertLike {
  threshold_usd: number | null
  spend_today: number | null
}

export interface SignalInputs {
  /** Applied org scope; '' = global — budget/alert/credits sources need one. */
  org: string
  /** Applied analytics window (ISO) the compare query ran with. */
  from: string
  to: string
  compare?: SignalCompare | null
  teamBudgets?: TeamBudgetLike[] | null
  spendAlert?: SpendAlertLike | null
  /** CreditBalance.balance_cents (root); null = not measured. */
  creditBalanceCents?: number | null
}

/**
 * Formatter port so the lib never formats raw numbers itself: every value
 * that reaches a message param goes through the AUX-10 registry formatters
 * (locale/currency-aware). `registryFormatters` is the canonical instance.
 */
export interface SignalFormatters {
  money: (usd: number) => string
  pct: (ratio: number) => string
  ms: (value: number) => string
  count: (value: number) => string
}

/** Registry-backed formatters (AUX-10): money/percent/ms/count, locale-aware. */
export function registryFormatters(opts: MetricFormatOptions = {}): SignalFormatters {
  const orRaw = (id: string, v: number): string => formatMetricValue(id, v, opts) ?? String(v)
  return {
    money: v => orRaw('cost_usd', v),
    pct: v => formatPercentRatio(v, opts.locale || 'en'),
    ms: v => orRaw('latency_p95', v),
    count: v => orRaw('requests', v),
  }
}

// Thresholds — named so the unit tests pin the exact boundaries.
/** Team budget usage that starts to warn ("близок к лимиту"). */
export const BUDGET_NEAR_RATIO = 0.8
/** Error-rate jump over the previous period (percentage points as a ratio). */
export const ERROR_RATE_JUMP = 0.05
/** Error-rate jump that is critical rather than a warning. */
export const ERROR_RATE_JUMP_CRITICAL = 0.15
/** p95 growth multiple over the previous period that warns. */
export const P95_GROWTH_RATIO = 1.5
/** Previous p95 below this is noise, not a baseline (ms). */
export const P95_NOISE_FLOOR_MS = 200
/** Cache-hit-rate drop over the previous period (percentage points as a ratio). */
export const CACHE_DROP = 0.1
/** A previous hit rate below this is negligible cache usage — no signal. */
export const CACHE_BASE_FLOOR = 0.2
/** Credit balance under $5 warns (CreditsPage thresholds, AUX-00). */
export const CREDITS_LOW_CENTS = 500
/** Credit balance at or below −$1 is critical (insufficient-credits grace). */
export const CREDITS_CRITICAL_CENTS = -100

function finite(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

function analyticsHref(
  org: string, from: string, to: string,
  metrics: string[], granularity: 'day' | 'none', compare: boolean,
  groupBy: string[] = [],
): string {
  return `#analytics?${serializeAnalyticsHash({
    org, from, to, metrics, groupBy, granularity, filter: '', top: 20, compare,
    chart: granularity === 'none' ? 'bar' : 'line', tz: '', period: 'custom',
  })}`
}

function budgetSignals(budgets: TeamBudgetLike[] | null | undefined, fmt: SignalFormatters): Signal[] {
  const out: Signal[] = []
  for (const b of budgets ?? []) {
    if (!b || typeof b.team_id !== 'string' || b.team_id === '') continue
    // Unknown limit or unknown spend is not a breach — never folded to 0.
    if (!finite(b.monthly_limit_usd) || b.monthly_limit_usd <= 0) continue
    if (!finite(b.spend_usd) || b.spend_usd < 0) continue
    const ratio = b.spend_usd / b.monthly_limit_usd
    if (ratio >= 1) {
      out.push({
        id: `team-budget:${b.team_id}`,
        type: 'team-budget-exceeded',
        severity: 'critical',
        messageKey: 'signals.teamBudgetExceeded',
        params: { team: b.team_id, spent: fmt.money(b.spend_usd), limit: fmt.money(b.monthly_limit_usd), pct: fmt.pct(ratio) },
        metricId: 'cost_usd',
        metricValue: b.spend_usd,
        href: '#budgets',
        linkKey: 'signals.linkBudgets',
      })
    } else if (ratio >= BUDGET_NEAR_RATIO) {
      out.push({
        id: `team-budget:${b.team_id}`,
        type: 'team-budget-near',
        severity: 'warning',
        messageKey: 'signals.teamBudgetNear',
        params: { team: b.team_id, spent: fmt.money(b.spend_usd), limit: fmt.money(b.monthly_limit_usd), pct: fmt.pct(ratio) },
        metricId: 'cost_usd',
        metricValue: b.spend_usd,
        href: '#budgets',
        linkKey: 'signals.linkBudgets',
      })
    }
  }
  return out
}

function spendAlertSignal(alert: SpendAlertLike | null | undefined, fmt: SignalFormatters): Signal | null {
  if (!alert) return null
  // A disabled alert (null threshold) or unknown spend never signals.
  if (!finite(alert.threshold_usd) || alert.threshold_usd <= 0) return null
  if (!finite(alert.spend_today) || alert.spend_today < 0) return null
  if (alert.spend_today < alert.threshold_usd) return null
  return {
    id: 'spend-alert',
    type: 'spend-alert-breached',
    severity: 'critical',
    messageKey: 'signals.spendAlertBreached',
    params: { spend: fmt.money(alert.spend_today), threshold: fmt.money(alert.threshold_usd) },
    metricId: 'cost_usd',
    metricValue: alert.spend_today,
    href: '#budgets',
    linkKey: 'signals.linkBudgets',
  }
}

function creditsSignal(cents: number | null | undefined, fmt: SignalFormatters): Signal | null {
  if (!finite(cents)) return null
  if (cents <= CREDITS_CRITICAL_CENTS) {
    return {
      id: 'credits',
      type: 'credits-negative',
      severity: 'critical',
      messageKey: 'signals.creditsNegative',
      params: { balance: fmt.money(cents / 100) },
      href: '#credits',
      linkKey: 'signals.linkCredits',
    }
  }
  if (cents < CREDITS_LOW_CENTS) {
    return {
      id: 'credits',
      type: 'credits-low',
      severity: 'warning',
      messageKey: 'signals.creditsLow',
      params: { balance: fmt.money(cents / 100) },
      href: '#credits',
      linkKey: 'signals.linkCredits',
    }
  }
  return null
}

function compareSignals(
  inputs: SignalInputs, compare: SignalCompare, fmt: SignalFormatters,
): Signal[] {
  const out: Signal[] = []
  const { org, from, to } = inputs
  const cur = (id: string): number | null => (finite(compare.totals?.[id]) ? compare.totals[id] as number : null)
  const prev = (id: string): number | null => (finite(compare.previous?.[id]) ? compare.previous[id] as number : null)

  // Error share grew versus the previous period. Both periods must be
  // measured: an unknown previous is not a zero baseline.
  const rate = cur('error_rate')
  const ratePrev = prev('error_rate')
  if (rate != null && ratePrev != null && rate > 0) {
    const delta = rate - ratePrev
    if (delta >= ERROR_RATE_JUMP) {
      const critical = delta >= ERROR_RATE_JUMP_CRITICAL
      out.push({
        id: 'error-rate',
        type: 'error-rate-jump',
        severity: critical ? 'critical' : 'warning',
        messageKey: 'signals.errorRateJump',
        params: { current: fmt.pct(rate), previous: fmt.pct(ratePrev) },
        metricId: 'error_rate',
        metricValue: rate,
        metricPrevious: ratePrev,
        href: analyticsHref(org, from, to, ['error_rate'], 'day', true, ['model']),
        linkKey: 'signals.linkAnalytics',
      })
    }
  }

  // p95 latency grew versus the previous period (noise floor on the baseline).
  const p95 = cur('latency_p95')
  const p95Prev = prev('latency_p95')
  if (p95 != null && p95Prev != null && p95Prev >= P95_NOISE_FLOOR_MS && p95 >= p95Prev * P95_GROWTH_RATIO) {
    out.push({
      id: 'latency-p95',
      type: 'latency-p95-jump',
      severity: 'warning',
      messageKey: 'signals.latencyP95Jump',
      params: { current: fmt.ms(p95), previous: fmt.ms(p95Prev) },
      metricId: 'latency_p95',
      metricValue: p95,
      metricPrevious: p95Prev,
      href: analyticsHref(org, from, to, ['latency_p95'], 'day', true),
      linkKey: 'signals.linkAnalytics',
    })
  }

  // Cache hit rate fell versus the previous period (only above a negligible base).
  const hit = cur('cache_hit_rate')
  const hitPrev = prev('cache_hit_rate')
  if (hit != null && hitPrev != null && hitPrev >= CACHE_BASE_FLOOR && hitPrev - hit >= CACHE_DROP) {
    out.push({
      id: 'cache-hit-rate',
      type: 'cache-hit-dropped',
      severity: 'warning',
      messageKey: 'signals.cacheHitDropped',
      params: { current: fmt.pct(hit), previous: fmt.pct(hitPrev) },
      metricId: 'cache_hit_rate',
      metricValue: hit,
      metricPrevious: hitPrev,
      href: analyticsHref(org, from, to, ['cache_hit_rate'], 'day', true),
      linkKey: 'signals.linkAnalytics',
    })
  }

  // Unpriced requests: a share of traffic whose cost is not measured
  // (coverage of the same query). unknown share → no signal, 0 → no signal.
  const share = compare.coverage?.unpriced_share
  if (finite(share) && share > 0) {
    const all = share >= 1
    out.push({
      id: 'unpriced',
      type: 'unpriced-requests',
      severity: all ? 'critical' : 'warning',
      messageKey: all ? 'signals.unpricedAll' : 'signals.unpricedPartial',
      params: { pct: fmt.pct(share) },
      metricId: 'unpriced_requests',
      metricValue: finite(compare.coverage?.unpriced_requests) ? compare.coverage.unpriced_requests as number : null,
      href: analyticsHref(org, from, to, ['unpriced_requests', 'requests'], 'none', false),
      linkKey: 'signals.linkAnalytics',
    })
  }

  return out
}

// Display order: severity first, then a fixed per-type rank, then id — a
// deterministic list where the burning issues read first.
const SEVERITY_RANK: Record<SignalSeverity, number> = { critical: 0, warning: 1 }
const TYPE_RANK: Record<SignalType, number> = {
  'team-budget-exceeded': 0,
  'spend-alert-breached': 1,
  'credits-negative': 2,
  'team-budget-near': 3,
  'error-rate-jump': 4,
  'unpriced-requests': 5,
  'latency-p95-jump': 6,
  'cache-hit-dropped': 7,
  'credits-low': 8,
}

/**
 * All signals for the applied scope, sorted for display. Every detector is
 * independent: a missing input (source not loaded / not permitted) yields no
 * signal from that source — the inbox UI owns the honest "sources failed"
 * state, the lib never fabricates calm from absent data.
 */
export function computeSignals(inputs: SignalInputs, fmt: SignalFormatters): Signal[] {
  const alert = spendAlertSignal(inputs.spendAlert, fmt)
  const credits = creditsSignal(inputs.creditBalanceCents, fmt)
  const signals: Signal[] = [
    ...budgetSignals(inputs.teamBudgets, fmt),
    ...(alert ? [alert] : []),
    ...(credits ? [credits] : []),
    ...(inputs.compare ? compareSignals(inputs, inputs.compare, fmt) : []),
  ]
  return signals.sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    || TYPE_RANK[a.type] - TYPE_RANK[b.type]
    || a.id.localeCompare(b.id))
}
