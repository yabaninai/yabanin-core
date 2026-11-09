import { useEffect, useId, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  fetchAnalyticsQuery, fetchCreditBalance, getOrgSpendAlert, listOrgTeamBudgets,
  type CreditBalance, type OrgSpendAlertSettings, type TeamSpendSummary,
} from '../../api/client'
import { StateNotice } from './StateNotice'
import { MetricHint } from './MetricHint'
import { usePermissions } from '../../hooks/usePermissions'
import { useOrgPresentation } from '../../i18n/useOrgPresentation'
import { uiLocale } from '../../i18n/format'
import {
  formatMetricValue, metricDisplayUnit, metricMeta, type AnalyticsResult,
} from '../../lib/analyticsQuery'
import {
  computeSignals, registryFormatters, type Signal, type SignalCompare,
} from '../../lib/signals'

// AUX-18 — the "requires attention" inbox block on Overview.
//
// Signals are computed client-side by lib/signals.ts over data that already
// exists (no new endpoints): the org analytics compare query (analytics.read),
// team budgets (budgets.manage), the org spend alert and the credit balance
// (both MustBeRoot server-side — the same gates BudgetsPage lives behind).
// Sources the caller has no right to read are not requested at all, so the
// inbox never manufactures 403s.
//
// Honest states (design standard "states"):
//   - no applied organization → "select an organization", never "all clear";
//   - rights cover no source → said plainly, never "all clear";
//   - every attempted source failed → an error notice with Retry — a failed
//     check can never claim the coast is clear;
//   - some sources failed → the list renders with a partial-data warning;
//   - everything loaded and nothing fired → one calm "all clear" line;
//   - otherwise the signal list: severity, the "why" with registry-formatted
//     numbers, and a link to the existing page carrying the evidence.

/** One compare query backs every analytics-based detector (AUX-18). */
const SIGNAL_METRICS = ['error_rate', 'latency_p95', 'cache_hit_rate']

function severityGlyph(severity: Signal['severity']): string {
  // Same shapes as StateNotice: ✕ error/critical, ▲ warning — color is
  // never the only carrier (the sr-only severity word repeats it).
  return severity === 'critical' ? '✕' : '▲'
}

export function SignalInbox({ orgId, from, to }: { orgId: string; from: string; to: string }) {
  const { t } = useTranslation()
  const headingId = useId()
  const org = orgId.trim()
  const perms = usePermissions(org || undefined)
  const { currency } = useOrgPresentation(org || undefined)
  // Registry formatting locale (same contract as uiLocale()); a locale switch
  // re-renders through i18next and reformats the signal params.
  const locale = uiLocale()

  const [loading, setLoading] = useState(Boolean(org))
  const [attempts, setAttempts] = useState(0)
  const [failures, setFailures] = useState(0)
  const [compare, setCompare] = useState<SignalCompare | null>(null)
  const [budgets, setBudgets] = useState<TeamSpendSummary[] | null>(null)
  const [alert, setAlert] = useState<OrgSpendAlertSettings | null>(null)
  const [balanceCents, setBalanceCents] = useState<number | null>(null)
  const [nonce, setNonce] = useState(0)

  const canBudgets = perms.can('budgets.manage')
  const canAnalytics = perms.can('analytics.read')
  const isRoot = perms.isRoot

  useEffect(() => {
    if (!org || perms.loading) return
    const ctrl = new AbortController()
    let alive = true
    setLoading(true)
    // Fresh scope — the previous scope's signals never leak into the new one.
    setCompare(null)
    setBudgets(null)
    setAlert(null)
    setBalanceCents(null)

    let runAttempts = 0
    let runFailures = 0
    const tracked: Array<Promise<void>> = []
    const track = (p: Promise<unknown>) => {
      runAttempts++
      tracked.push(p.then(() => {}, () => { runFailures++ }))
    }
    const opts = { signal: ctrl.signal }

    if (canAnalytics) {
      track(
        fetchAnalyticsQuery({
          org, from, to, metrics: SIGNAL_METRICS,
          groupBy: [], granularity: 'day', filter: '', top: 20,
          compare: true, chart: 'line', tz: 'UTC', period: 'custom',
        }, opts).then((res: AnalyticsResult) => {
          if (!alive) return
          setCompare({
            totals: res.totals ?? {},
            previous: res.compare?.totals ?? {},
            coverage: res.coverage ?? null,
          })
        }),
      )
    }
    if (canBudgets) {
      track(listOrgTeamBudgets(org, opts).then(rows => { if (alive) setBudgets(rows) }))
    }
    if (isRoot) {
      track(getOrgSpendAlert(org, opts).then(a => { if (alive) setAlert(a) }))
      track(fetchCreditBalance(org, opts).then((b: CreditBalance) => {
        if (!alive) return
        setBalanceCents(typeof b?.balance_cents === 'number' ? b.balance_cents : null)
      }))
    }

    void Promise.all(tracked).then(() => {
      if (!alive) return
      setAttempts(runAttempts)
      setFailures(runFailures)
      setLoading(false)
    })
    return () => {
      alive = false
      ctrl.abort()
    }
  }, [org, from, to, perms.loading, canBudgets, canAnalytics, isRoot, nonce])

  const signals = useMemo(() => {
    return computeSignals({
      org, from, to,
      compare, teamBudgets: budgets, spendAlert: alert, creditBalanceCents: balanceCents,
    }, registryFormatters({ locale, currency }))
  }, [org, from, to, compare, budgets, alert, balanceCents, currency, locale])

  const attemptedNothing = !loading && attempts === 0
  const allFailed = !loading && attempts > 0 && failures >= attempts
  const someFailed = !loading && failures > 0 && failures < attempts

  return (
    <section aria-labelledby={headingId} className="astra-panel min-w-0 px-4 py-4">
      <h2 id={headingId} className="text-base font-semibold text-[color:var(--astra-ink)]">
        {t('signals.title')}
      </h2>
      <p className="mt-1 mb-3 text-xs text-[color:var(--astra-text-muted)]">{t('signals.scopeNote')}</p>

      {org === '' ? (
        <StateNotice state="empty" message={t('signals.needOrg')} />
      ) : (loading || perms.loading) && signals.length === 0 ? (
        <StateNotice state="loading" message={t('signals.checking')} />
      ) : attemptedNothing ? (
        <StateNotice state="empty" message={t('signals.noSources')} />
      ) : allFailed ? (
        <StateNotice
          state="error"
          message={t('signals.loadFailed')}
          action={{ label: t('common.retry'), onClick: () => setNonce(n => n + 1) }}
        />
      ) : signals.length === 0 ? (
        someFailed ? (
          <StateNotice state="warning" message={t('signals.partialLoad')} action={{ label: t('common.retry'), onClick: () => setNonce(n => n + 1) }} />
        ) : (
          <p role="status" className="flex items-center gap-2 py-1 text-sm text-[color:var(--astra-ink)]">
            <span aria-hidden="true" style={{ color: 'var(--astra-success)' }}>✓</span>
            {t('signals.allClear')}
          </p>
        )
      ) : (
        <>
          {loading && <StateNotice state="loading" message={t('signals.checking')} />}
          {someFailed && (
            <StateNotice state="warning" message={t('signals.partialLoad')} action={{ label: t('common.retry'), onClick: () => setNonce(n => n + 1) }} />
          )}
          <ul className="mt-1 flex flex-col">
            {signals.map(s => {
              const meta = s.metricId ? metricMeta(s.metricId) : undefined
              const value = s.metricId
                ? formatMetricValue(s.metricId, s.metricValue, { locale, currency })
                : null
              const previous = s.metricId && s.metricPrevious != null
                ? formatMetricValue(s.metricId, s.metricPrevious, { locale, currency })
                : null
              const unit = s.metricId ? metricDisplayUnit(s.metricId) : undefined
              return (
                <li
                  key={s.id}
                  className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-[color:var(--astra-rule)] py-2 last:border-b-0"
                >
                  <span
                    aria-hidden="true"
                    className="shrink-0"
                    style={{ color: s.severity === 'critical' ? 'var(--astra-danger)' : 'var(--astra-warning)' }}
                  >
                    {severityGlyph(s.severity)}
                  </span>
                  <span className="sr-only">
                    {t(s.severity === 'critical' ? 'signals.severityCritical' : 'signals.severityWarning')}
                  </span>
                  <span className="min-w-0 flex-1 text-sm text-[color:var(--astra-ink)]">
                    {t(s.messageKey, s.params)}
                    {meta && (
                      <span className="ms-2 inline-flex flex-wrap items-center gap-x-1 text-xs text-[color:var(--astra-text-muted)]">
                        <span>
                          {t(meta.labelKey)}
                          {unit ? ` · ${unit}` : ''}
                        </span>
                        <span className="font-medium" style={{ fontFamily: 'var(--astra-font-code)', fontVariantNumeric: 'tabular-nums' }}>
                          {value ?? t('common.unknown')}
                        </span>
                        {previous != null && (
                          <span>({t('signals.was', { value: previous })})</span>
                        )}
                        <MetricHint label={t(meta.labelKey)} description={t(meta.descKey)} />
                      </span>
                    )}
                  </span>
                  <a href={s.href} className="btn-secondary shrink-0">
                    {t(s.linkKey)}
                  </a>
                </li>
              )
            })}
          </ul>
        </>
      )}
    </section>
  )
}
