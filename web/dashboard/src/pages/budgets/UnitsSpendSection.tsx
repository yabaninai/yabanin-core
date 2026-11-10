import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/transport'
import { getUnitSpendRollup, type UnitSpendLine, type UnitSpendRollup } from '../../api/currencies'
import { IdChip } from '../../components/astra/IdChip'
import { MetricStrip, type Metric } from '../../components/astra/MetricStrip'
import { StateNotice } from '../../components/astra/StateNotice'
import { formatDateTime, formatNumber, uiLocale } from '../../i18n/format'
import { formatUnitAmount, labelSpendLines } from '../../lib/unitSpend'

// Currencies UI slice 5 (brief 2026-11-02 §6.1): the units & spend rollup —
// GET /api/units/spend, one line per measured unit (USD, credits, tokens,
// gCO2e). READ-ONLY: nothing here mutates anything.
//
// Honesty rules (brief §2, same family as CapsStatusSection):
//  - amount null renders "unknown" — never a fabricated 0;
//  - the SERVED window is displayed (response source of truth), never the
//    requested draft bounds;
//  - coverage gaps (unknown_usage_rows / unmodeled_carbon_rows /
//    legacy_cost_rows) are surfaced as partial-data notices, never silently
//    dropped, and only when the server actually reports them;
//  - credits_scale renders verbatim near the money lines, never re-derived;
//  - 403 = lacks analytics.read; 404 = org invisible (never "no access to
//    org X"); 501 = deployment predates the currencies program; 400 = the
//    requested window was rejected.
//
// The window picker keeps a DRAFT (from/to inputs) separate from the APPLIED
// window — inputs never fire requests on keystroke; Apply commits them.

/** Closed server vocabulary (adminstore UnitFamily*): localized with verbatim fallback. */
const FAMILY_KEYS: Record<string, string> = {
  money: 'budgets.unitsSpend.family_money',
  resource: 'budgets.unitsSpend.family_resource',
  impact: 'budgets.unitsSpend.family_impact',
}

/** Closed server vocabulary (adminstore Fidelity*). */
const FIDELITY_KEYS: Record<string, string> = {
  exact: 'budgets.unitsSpend.fidelity_exact',
  estimated: 'budgets.unitsSpend.fidelity_estimated',
  simulated: 'budgets.unitsSpend.fidelity_simulated',
  unknown: 'budgets.unitsSpend.fidelity_unknown',
}

/** datetime-local input value ("2026-10-01T00:00") → RFC3339, or undefined when blank. */
function draftToRFC3339(value: string): string | undefined {
  if (!value) return undefined
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

function UnitsSpendSection({ org }: { org: string }) {
  const { t } = useTranslation()
  const [response, setResponse] = useState<{ scope: string; data: UnitSpendRollup } | null>(null)
  const [failure, setFailure] = useState<{ scope: string; error: ApiError } | null>(null)
  const [loading, setLoading] = useState(true)

  // Draft window bounds (datetime-local strings); applied drives the request.
  const [draftFrom, setDraftFrom] = useState('')
  const [draftTo, setDraftTo] = useState('')
  const [applied, setApplied] = useState<{ from?: string; to?: string }>({})
  const scope = JSON.stringify([org, applied.from, applied.to])
  const rollup = response?.scope === scope ? response.data : null
  const error = failure?.scope === scope ? failure.error : null

  // Scope guard: on org change the previous effect's AbortController fires,
  // so a delayed org-A response can never land in org B (TP-06 pattern).
  const abortRef = useRef<AbortController | null>(null)

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setResponse(null)
    setFailure(null)
    try {
      const r = await getUnitSpendRollup(org, applied.from || applied.to ? applied : undefined, { signal })
      if (signal?.aborted) return
      if (r.org_id !== org) throw new ApiError(502, t('budgets.unitsSpend.scopeMismatch'))
      setResponse({ scope, data: r })
    } catch (e) {
      if (signal?.aborted || (e as { name?: string })?.name === 'AbortError') return
      setFailure({ scope, error: e instanceof ApiError ? e : new ApiError(0, t('budgets.unitsSpend.loadFailed')) })
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }, [org, applied, scope, t])

  useEffect(() => {
    const ctrl = new AbortController()
    abortRef.current = ctrl
    void load(ctrl.signal)
    return () => { ctrl.abort(); abortRef.current?.abort() }
  }, [load])

  const retry = () => {
    const ctrl = new AbortController()
    abortRef.current?.abort()
    abortRef.current = ctrl
    void load(ctrl.signal)
  }

  const applyWindow = () => setApplied({
    from: draftToRFC3339(draftFrom),
    to: draftToRFC3339(draftTo),
  })

  const describedLines = labelSpendLines(rollup?.lines ?? [])
  const amountText = (line: UnitSpendLine) => formatUnitAmount(line.amount, uiLocale()) ?? t('budgets.unitsSpend.unknownAmount')
  const metrics: Metric[] = describedLines.map(({ line, labelKey }) => ({
    label: labelKey ? t(labelKey) : line.unit,
    value: amountText(line),
    unit: line.unit === 'gCO2e' ? 'gCO₂e' : line.unit,
    source: line.unit === 'gCO2e'
      ? t('budgets.unitsSpend.carbonSource')
      : FIDELITY_KEYS[line.fidelity] ? t(FIDELITY_KEYS[line.fidelity]) : line.fidelity,
    coverage: line.note,
    state: line.amount === null || !Number.isFinite(line.amount) || line.fidelity === 'unknown'
      ? 'unknown'
      : line.fidelity !== 'exact' || line.unit === 'gCO2e' ? 'warning' : 'ok',
  }))

  const renderLine = ({ line, labelKey, id }: ReturnType<typeof labelSpendLines>[number]) => {
    const familyKey = FAMILY_KEYS[line.family]
    const fidelityKey = FIDELITY_KEYS[line.fidelity]
    return (
      <tr key={id} data-testid={`spend-line-${line.unit}`}>
        <th scope="row" className="py-2 pe-4 text-start align-top font-medium text-[color:var(--astra-ink)]">
          {labelKey ? t(labelKey) : line.unit}
          {line.note && (
            <span className="block max-w-[34ch] text-xs font-normal text-[color:var(--astra-text-muted)]">{line.note}</span>
          )}
        </th>
        <td className="py-2 pe-4 align-top" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {line.amount === null ? (
            <span className="text-[color:var(--astra-text-muted)]">{t('budgets.unitsSpend.unknownAmount')}</span>
          ) : (
            <>
              <span className="font-medium">{amountText(line)}</span>{' '}
              <span className="text-[color:var(--astra-text-muted)]">{line.unit}</span>
            </>
          )}
        </td>
        <td className="py-2 pe-4 align-top text-[color:var(--astra-text-muted)]">
          {familyKey ? t(familyKey) : line.family}
        </td>
        <td className="py-2 pe-4 align-top text-[color:var(--astra-text-muted)]">
          {fidelityKey ? t(fidelityKey) : line.fidelity}
        </td>
        <td className="py-2 align-top text-xs text-[color:var(--astra-text-muted)]">
          {line.provenance ?? '—'}
        </td>
      </tr>
    )
  }

  const coverage: Array<[string, number]> = rollup ? ([
    ['budgets.unitsSpend.unknownUsageRows', rollup.unknown_usage_rows],
    ['budgets.unitsSpend.unmodeledCarbonRows', rollup.unmodeled_carbon_rows],
    ['budgets.unitsSpend.legacyCostRows', rollup.legacy_cost_rows],
  ] as Array<[string, number]>).filter(([, n]) => n > 0) : []

  return (
    <section aria-labelledby="units-spend-title" className="astra-panel flex flex-col gap-3 p-4" data-testid="units-spend-section">
      <h2 id="units-spend-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">
        {t('budgets.unitsSpend.title')}
      </h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.unitsSpend.purpose')}</p>

      {/* Window picker: draft inputs + explicit Apply — no request on keystroke. */}
      <div className="flex flex-wrap items-end gap-2 text-sm" data-testid="units-spend-window">
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('budgets.unitsSpend.from')}</span>
          <input
            type="datetime-local"
            className="input min-w-0"
            value={draftFrom}
            onChange={(e) => setDraftFrom(e.target.value)}
            aria-label={t('budgets.unitsSpend.from')}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('budgets.unitsSpend.to')}</span>
          <input
            type="datetime-local"
            className="input min-w-0"
            value={draftTo}
            onChange={(e) => setDraftTo(e.target.value)}
            aria-label={t('budgets.unitsSpend.to')}
          />
        </label>
        <button type="button" className="btn-secondary" onClick={applyWindow}>
          {t('budgets.unitsSpend.applyWindow')}
        </button>
      </div>

      {loading && !rollup && !error && <StateNotice state="loading" />}

      {error?.status === 501 && (
        <StateNotice state="empty" message={t('budgets.unitsSpend.notDeployed')} />
      )}

      {error && error.status !== 501 && (
        <StateNotice
          state="error"
          title={t('states.failedToLoad')}
          message={error.status === 403
            ? t('budgets.unitsSpend.forbidden')
            : error.status === 404
              ? t('budgets.unitsSpend.orgInvisible')
              : error.status === 400
                ? t('budgets.unitsSpend.invalidWindow', { detail: error.message })
                : error.message || t('budgets.unitsSpend.loadFailed')}
          action={{ label: t('common.retry'), onClick: retry }}
        />
      )}

      {rollup && (
        <>
          {rollup.lines.length === 0 && (
            <StateNotice state="empty" message={t('budgets.unitsSpend.empty')} />
          )}
          {rollup.lines.length > 0 && <MetricStrip metrics={metrics} aria-label={t('budgets.unitsSpend.summary')} />}
          {rollup.lines.some(line => line.unit === 'gCO2e') && (
            <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="units-spend-carbon-method">
              {t('budgets.unitsSpend.carbonMethod')}
            </p>
          )}
          {rollup.lines.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">{t('budgets.unitsSpend.caption')}</caption>
                <thead>
                  <tr className="border-b border-[color:var(--astra-rule)] text-start text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">
                    <th scope="col" className="py-2 pe-4 text-start">{t('budgets.unitsSpend.colUnit')}</th>
                    <th scope="col" className="py-2 pe-4 text-start">{t('budgets.unitsSpend.colAmount')}</th>
                    <th scope="col" className="py-2 pe-4 text-start">{t('budgets.unitsSpend.colFamily')}</th>
                    <th scope="col" className="py-2 pe-4 text-start">{t('budgets.unitsSpend.colFidelity')}</th>
                    <th scope="col" className="py-2 text-start">{t('budgets.unitsSpend.colProvenance')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[color:var(--astra-rule)]">
                  {describedLines.map(renderLine)}
                </tbody>
              </table>
            </div>
          )}

          {/* The SERVED window and request count — response truth, not the draft. */}
          <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="units-spend-window-served">
            {t('budgets.unitsSpend.window', {
              from: formatDateTime(rollup.window.from, undefined),
              to: formatDateTime(rollup.window.to, undefined),
              requests: formatNumber(rollup.requests),
            })}
          </p>

          {/* Partial data: coverage gaps only when the server reports them. */}
          {coverage.length > 0 && (
            <StateNotice
              state="partial"
              details={
                <ul className="list-disc ps-4">
                  {coverage.map(([key, count]) => (
                    <li key={key}>{t(key, { count })}</li>
                  ))}
                </ul>
              }
            />
          )}

          {/* Pricing citation: the audit anchor for every priced line. */}
          <p className="overflow-wrap-anywhere text-xs text-[color:var(--astra-text-muted)]" data-testid="units-spend-pricing">
            {rollup.pricing.pricing_catalog
              ? t('budgets.unitsSpend.pricingCatalog', {
                asOf: rollup.pricing.pricing_as_of,
                version: rollup.pricing.pricing_catalog.version,
              })
              : t('budgets.unitsSpend.pricingAsOf', { asOf: rollup.pricing.pricing_as_of })}
            {rollup.pricing.pricing_catalog && (
              <span className="ms-2 whitespace-nowrap">
                <IdChip value={rollup.pricing.pricing_catalog.digest} />
              </span>
            )}
          </p>

          {/* credits_scale: verbatim server caption — the unit story for every
              money number on this page. Never re-derived client-side. */}
          <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="units-spend-credits-scale">
            {rollup.credits_scale}
          </p>
        </>
      )}
    </section>
  )
}

export { UnitsSpendSection }
