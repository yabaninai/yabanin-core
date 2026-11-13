import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/transport'
import { getBudgetCaps, type BudgetCapLine, type BudgetCapsStatus } from '../../api/currencies'
import { StateNotice } from '../../components/astra/StateNotice'
import { formatDateTime, formatNumber } from '../../i18n/format'

// Currencies UI slice 3 (brief 2026-11-02 §6.2): the Policies-workspace caps
// status — GET /api/budgets, three caps in the server's fixed order. This is
// a READ-ONLY status surface: the settings that produce these numbers live
// in the sections above (team budgets, org caps, budget settings); nothing
// here mutates anything.
//
// Honesty rules (brief §2):
//  - used.amount null renders "unknown" with the fidelity — never 0;
//  - limit null renders "not configured" — an unconfigured carbon cap is
//    NOT an unlimited one;
//  - status unknown is a state, not an error: the cap cannot be compared;
//  - credits_scale renders verbatim under the caps, never re-derived;
//  - 403 = lacks budgets.manage; 404 = org invisible; 501 = deployment
//    predates the currencies program (distinct notice, not "broken").

const CAP_LABELS: Record<string, string> = {
  usd_monthly_budget: 'budgets.capsStatus.usdMonthlyBudget',
  carbon_monthly_grams: 'budgets.capsStatus.carbonMonthlyGrams',
  credits_floor: 'budgets.capsStatus.creditsFloor',
}

function statusTone(status: string): string {
  if (status === 'over') return 'var(--astra-danger)'
  if (status === 'near') return 'var(--astra-warning)'
  if (status === 'ok') return 'var(--astra-success)'
  return 'var(--astra-text-muted)' // unknown — muted, not alarming
}

function CapsStatusSection({ org }: { org: string }) {
  const { t } = useTranslation()
  const [status, setStatus] = useState<BudgetCapsStatus | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)

  // Scope guard: on org change the previous effect's AbortController fires,
  // so a delayed org-A response can never land in org B.
  const abortRef = useRef<AbortController | null>(null)

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    try {
      const s = await getBudgetCaps(org, { signal })
      if (signal?.aborted) return
      setStatus(s)
      setError(null)
    } catch (e) {
      if (signal?.aborted || (e as { name?: string })?.name === 'AbortError') return
      setStatus(null)
      setError(e instanceof ApiError ? e : null)
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }, [org])

  useEffect(() => {
    const ctrl = new AbortController()
    abortRef.current = ctrl
    void load(ctrl.signal)
    return () => { ctrl.abort() }
  }, [load])

  const retry = () => {
    const ctrl = new AbortController()
    abortRef.current?.abort()
    abortRef.current = ctrl
    void load(ctrl.signal)
  }

  const renderCap = (cap: BudgetCapLine) => {
    const labelKey = CAP_LABELS[cap.id]
    return (
      <tr key={cap.id} data-testid={`cap-${cap.id}`}>
        <th scope="row" className="py-2 pe-4 text-start align-top font-medium text-[color:var(--astra-ink)]">
          {labelKey ? t(labelKey) : cap.id}
          {cap.note && (
            <span className="block max-w-[34ch] text-xs font-normal text-[color:var(--astra-text-muted)]">{cap.note}</span>
          )}
        </th>
        <td className="py-2 pe-4 align-top" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {cap.used.amount === null ? (
            <span className="text-[color:var(--astra-text-muted)]">
              {t('budgets.capsStatus.unknownUsed', { fidelity: cap.used.fidelity })}
            </span>
          ) : (
            <>
              <span className="font-medium">{formatNumber(cap.used.amount)}</span>{' '}
              <span className="text-[color:var(--astra-text-muted)]">{cap.used.unit}</span>
              {cap.used.fidelity !== 'metered' && (
                <span className="ms-1 text-xs text-[color:var(--astra-text-muted)]">({cap.used.fidelity})</span>
              )}
            </>
          )}
        </td>
        <td className="py-2 pe-4 align-top" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {cap.limit === null ? (
            <span className="text-[color:var(--astra-text-muted)]">{t('budgets.capsStatus.notConfigured')}</span>
          ) : (
            <>
              {formatNumber(cap.limit)} <span className="text-[color:var(--astra-text-muted)]">{cap.used.unit}</span>
            </>
          )}
        </td>
        <td className="py-2 align-top">
          <span
            className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm font-medium"
            style={{ color: statusTone(cap.status) }}
          >
            <span aria-hidden="true" className="inline-block h-2 w-2 rounded-full" style={{ background: statusTone(cap.status) }} />
            {t(`budgets.capsStatus.status.${cap.status}`, cap.status)}
          </span>
        </td>
      </tr>
    )
  }

  return (
    <section aria-labelledby="caps-status-title" className="astra-panel flex flex-col gap-3 p-4">
      <h2 id="caps-status-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">
        {t('budgets.capsStatus.title')}
      </h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.capsStatus.purpose')}</p>

      {loading && !status && !error && <StateNotice state="loading" />}

      {error?.status === 501 && (
        <StateNotice state="empty" message={t('budgets.capsStatus.notDeployed')} />
      )}

      {error && error.status !== 501 && (
        <StateNotice
          state="error"
          title={t('states.failedToLoad')}
          message={error.status === 403
            ? t('budgets.capsStatus.forbidden')
            : error.status === 404
              ? t('budgets.capsStatus.orgInvisible')
              : error.message || t('budgets.capsStatus.loadFailed')}
          action={{ label: t('common.retry'), onClick: retry }}
        />
      )}

      {status && (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <caption className="sr-only">{t('budgets.capsStatus.caption')}</caption>
              <thead>
                <tr className="border-b border-[color:var(--astra-rule)] text-start text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">
                  <th scope="col" className="py-2 pe-4 text-start">{t('budgets.capsStatus.colCap')}</th>
                  <th scope="col" className="py-2 pe-4 text-start">{t('budgets.capsStatus.colUsed')}</th>
                  <th scope="col" className="py-2 pe-4 text-start">{t('budgets.capsStatus.colLimit')}</th>
                  <th scope="col" className="py-2 text-start">{t('budgets.capsStatus.colStatus')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[color:var(--astra-rule)]">
                {status.caps.map(renderCap)}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-[color:var(--astra-text-muted)]">
            {t('budgets.capsStatus.window', {
              from: formatDateTime(status.window.from, undefined),
              to: formatDateTime(status.window.to, undefined),
            })}
          </p>
          {/* credits_scale: verbatim server caption — the unit story for every
              money number on this page. Never re-derived client-side. */}
          <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="caps-credits-scale">
            {status.credits_scale}
          </p>
        </>
      )}
    </section>
  )
}

export { CapsStatusSection }
