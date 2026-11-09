import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  getOrgCaps, updateOrgCaps, isValidOrgCapsValue, isValidOrgCapsBudgetCents,
  ORG_CAPS_MAX_VALUE, ORG_CAPS_MAX_BUDGET_CENTS,
  type OrgCaps, type OrgCapsPatch,
} from '../../api/orgCaps'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import { MetricStrip } from '../../components/astra/MetricStrip'
import { StateNotice } from '../../components/astra/StateNotice'
import { formatMoney, formatNumber } from '../../i18n/format'

// W-CAPS: the org caps section (beta limits: RPM / TPM / hard monthly
// by the Budgets & alerts screen for callers the server will accept: root
// or the org's budgets.manage admins.
//
// Honesty rules this section lives by:
//  - null means "beta default" (60 RPM / 200k TPM / $50 month) — never
//    have no beta default; the aggregate TPM default keeps applying);
//  - every edit sends the full sextuple so a partial save can never
//    silently reset another dimension;
//  - month_spend_cents is server-measured; budget_exceeded is the server's
//    verdict (the gateway answers 402 budget_exceeded in enforce mode) and
//    renders as an error notice, never a silent state;
//  - every mutation is high risk with a MANDATORY reason (the server 400s
//    an empty one), sent as X-Audit-Reason and in the body.

function errorOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Coordinates of one settable integer token cap inside the caps block. */
interface TokenCapSlot {
  field: 'rpm' | 'tpm' | 'input_tokens_per_min' | 'output_tokens_per_min' | 'key_tokens_per_min'
  effective: number
  overrideValue: number | null
  /** false: empty input clears to OFF; true: empty input clears to the beta default. */
  hasBetaDefault: boolean
}

export function OrgCapsSection({ org, canBudgets, isRoot, currency }: {
  org: string
  canBudgets: boolean
  isRoot: boolean
  currency: string | undefined
}) {
  const { t } = useTranslation()
  const [caps, setCaps] = useState<OrgCaps | null>(null)
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(false)

  // Scope epoch: a delayed org-A response can never land in org B (TP-06).
  const epoch = useRef(0)
  const orgRef = useRef(org)
  useEffect(() => {
    epoch.current++
    orgRef.current = org
  }, [org])
  const abortRef = useRef<AbortController | null>(null)

  const load = useCallback(async () => {
    if (!org) return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    const seen = { org, epoch: epoch.current }
    const live = () => orgRef.current === seen.org && epoch.current === seen.epoch
    setLoading(true)
    try {
      const next = await getOrgCaps(org, { signal: ctrl.signal })
      if (live()) {
        setCaps(next)
        setLoadError('')
      }
    } catch (e: unknown) {
      if (live() && !(e instanceof DOMException && e.name === 'AbortError')) {
        setCaps(null)
        setLoadError(errorOf(e))
      }
    } finally {
      if (live()) setLoading(false)
    }
  }, [org])

  useEffect(() => {
    if (!org || (!isRoot && !canBudgets)) return
    void load()
    return () => { abortRef.current?.abort() }
  }, [org, isRoot, canBudgets, load])

  // ----- actions (AUX-12 contract; reasons ride X-Audit-Reason, AUX-14b) -----
  const rpmAction = useAction({ id: 'budgets.caps.rpm', risk: 'high', permission: 'budgets.manage', reversible: true })
  const tpmAction = useAction({ id: 'budgets.caps.tpm', risk: 'high', permission: 'budgets.manage', reversible: true })
  const budgetAction = useAction({ id: 'budgets.caps.budget', risk: 'high', permission: 'budgets.manage', reversible: true })
  const itpmAction = useAction({ id: 'budgets.caps.itpm', risk: 'high', permission: 'budgets.manage', reversible: true })
  const otpmAction = useAction({ id: 'budgets.caps.otpm', risk: 'high', permission: 'budgets.manage', reversible: true })
  const keyTpmAction = useAction({ id: 'budgets.caps.keyTpm', risk: 'high', permission: 'budgets.manage', reversible: true })

  // Every edit sends the full sextuple from the loaded snapshot: absent
  // fields would decode to null server-side and silently reset to the beta
  const saveCaps = useCallback(async (next: Omit<OrgCapsPatch, 'reason'>, reason: string) => {
    const updated = await updateOrgCaps(org, { ...next, reason }, auditReasonOpts(reason))
    setCaps(updated)
  }, [org])

  // Shared runner for the five integer token caps. The i18n keys stay at the
  // literal call sites (the keys gate forbids dynamic t() arguments); only
  // the slot coordinates are parameterized.
  const openTokenCap = useCallback((action: ReturnType<typeof useAction>, slot: TokenCapSlot, copy: {
    save: string; input: string; edit: string
  }) => {
    if (!caps) return
    action.run({
      confirmLabel: copy.save,
      was: slot.overrideValue == null
        ? (slot.hasBetaDefault
          ? t('budgets.caps.defaultValue', { value: formatNumber(slot.effective) })
          : t('budgets.caps.offValue'))
        : formatNumber(slot.overrideValue),
      input: {
        label: copy.input,
        initial: slot.overrideValue == null ? '' : String(slot.overrideValue),
      },
      reason: { required: true },
      execute: async ({ value, reason }) => {
        const trimmed = value.trim()
        let parsed: number | null = null
        if (trimmed !== '') {
          const n = Number(trimmed)
          if (!Number.isInteger(n) || !isValidOrgCapsValue(n)) {
            throw new Error(t('budgets.caps.valueInvalid', { min: formatNumber(1), max: formatNumber(ORG_CAPS_MAX_VALUE) }))
          }
          parsed = n
        }
        await saveCaps({
          rpm: slot.field === 'rpm' ? parsed : (caps.rpm_override ?? null),
          tpm: slot.field === 'tpm' ? parsed : (caps.tpm_override ?? null),
          monthly_budget_cents: caps.monthly_budget_override_cents ?? null,
          input_tokens_per_min: slot.field === 'input_tokens_per_min' ? parsed : (caps.input_tokens_per_min_override ?? null),
          output_tokens_per_min: slot.field === 'output_tokens_per_min' ? parsed : (caps.output_tokens_per_min_override ?? null),
          key_tokens_per_min: slot.field === 'key_tokens_per_min' ? parsed : (caps.key_tokens_per_min_override ?? null),
        }, reason)
      },
      onDone: load,
    })
  }, [caps, load, saveCaps, t])

  const openRpm = useCallback(() => {
    if (!caps) return
    openTokenCap(rpmAction, { field: 'rpm', effective: caps.rpm, overrideValue: caps.rpm_override, hasBetaDefault: true }, {
      save: t('budgets.caps.rpmSave'),
      input: t('budgets.caps.rpmInput', { min: formatNumber(1), max: formatNumber(ORG_CAPS_MAX_VALUE) }),
      edit: t('budgets.caps.rpmEdit'),
    })
  }, [caps, openTokenCap, rpmAction, t])

  const openTpm = useCallback(() => {
    if (!caps) return
    openTokenCap(tpmAction, { field: 'tpm', effective: caps.tpm, overrideValue: caps.tpm_override, hasBetaDefault: true }, {
      save: t('budgets.caps.tpmSave'),
      input: t('budgets.caps.tpmInput', { min: formatNumber(1), max: formatNumber(ORG_CAPS_MAX_VALUE) }),
      edit: t('budgets.caps.tpmEdit'),
    })
  }, [caps, openTokenCap, t, tpmAction])

  const openItpm = useCallback(() => {
    if (!caps) return
    openTokenCap(itpmAction, { field: 'input_tokens_per_min', effective: caps.input_tokens_per_min, overrideValue: caps.input_tokens_per_min_override, hasBetaDefault: false }, {
      save: t('budgets.caps.itpmSave'),
      input: t('budgets.caps.itpmInput', { min: formatNumber(1), max: formatNumber(ORG_CAPS_MAX_VALUE) }),
      edit: t('budgets.caps.itpmEdit'),
    })
  }, [caps, itpmAction, openTokenCap, t])

  const openOtpm = useCallback(() => {
    if (!caps) return
    openTokenCap(otpmAction, { field: 'output_tokens_per_min', effective: caps.output_tokens_per_min, overrideValue: caps.output_tokens_per_min_override, hasBetaDefault: false }, {
      save: t('budgets.caps.otpmSave'),
      input: t('budgets.caps.otpmInput', { min: formatNumber(1), max: formatNumber(ORG_CAPS_MAX_VALUE) }),
      edit: t('budgets.caps.otpmEdit'),
    })
  }, [caps, openTokenCap, otpmAction, t])

  const openKeyTpm = useCallback(() => {
    if (!caps) return
    openTokenCap(keyTpmAction, { field: 'key_tokens_per_min', effective: caps.key_tokens_per_min, overrideValue: caps.key_tokens_per_min_override, hasBetaDefault: false }, {
      save: t('budgets.caps.keyTpmSave'),
      input: t('budgets.caps.keyTpmInput', { min: formatNumber(1), max: formatNumber(ORG_CAPS_MAX_VALUE) }),
      edit: t('budgets.caps.keyTpmEdit'),
    })
  }, [caps, keyTpmAction, openTokenCap, t])

  const openBudget = useCallback(() => {
    if (!caps) return
    budgetAction.run({
      confirmLabel: t('budgets.caps.budgetSave'),
      was: caps.monthly_budget_override_cents == null
        ? t('budgets.caps.defaultValue', { value: formatMoney(caps.monthly_budget_cents / 100, currency) })
        : formatMoney(caps.monthly_budget_override_cents / 100, currency),
      input: {
        label: t('budgets.caps.budgetInput', { max: formatMoney(ORG_CAPS_MAX_BUDGET_CENTS / 100, currency) }),
        initial: caps.monthly_budget_override_cents == null ? '' : String(caps.monthly_budget_override_cents / 100),
      },
      reason: { required: true },
      execute: async ({ value, reason }) => {
        const trimmed = value.trim()
        let cents: number | null = null
        if (trimmed !== '') {
          const dollars = Number(trimmed)
          if (!Number.isFinite(dollars) || dollars <= 0) {
            throw new Error(t('budgets.caps.budgetInvalid', { max: formatMoney(ORG_CAPS_MAX_BUDGET_CENTS / 100, currency) }))
          }
          cents = Math.round(dollars * 100)
          if (!isValidOrgCapsBudgetCents(cents)) {
            throw new Error(t('budgets.caps.budgetInvalid', { max: formatMoney(ORG_CAPS_MAX_BUDGET_CENTS / 100, currency) }))
          }
        }
        await saveCaps({
          rpm: caps.rpm_override ?? null,
          tpm: caps.tpm_override ?? null,
          monthly_budget_cents: cents,
          input_tokens_per_min: caps.input_tokens_per_min_override ?? null,
          output_tokens_per_min: caps.output_tokens_per_min_override ?? null,
          key_tokens_per_min: caps.key_tokens_per_min_override ?? null,
        }, reason)
      },
      onDone: load,
    })
  }, [budgetAction, caps, currency, load, saveCaps, t])

  // Token-cap strip entries with their literal copy (the keys gate requires
  // static t() arguments, so the five entries are spelled out).
  const tokenCapMetrics = caps ? [
    {
      label: t('budgets.caps.rpmLabel'),
      value: formatNumber(caps.rpm),
      source: caps.rpm_override != null ? t('budgets.caps.overrideSource') : t('budgets.caps.defaultSource'),
    },
    {
      label: t('budgets.caps.tpmLabel'),
      value: formatNumber(caps.tpm),
      source: caps.tpm_override != null ? t('budgets.caps.overrideSource') : t('budgets.caps.defaultSource'),
    },
    {
      label: t('budgets.caps.itpmLabel'),
      value: caps.input_tokens_per_min > 0 ? formatNumber(caps.input_tokens_per_min) : t('budgets.caps.offValue'),
      source: caps.input_tokens_per_min_override != null ? t('budgets.caps.overrideSource') : t('budgets.caps.offSource'),
    },
    {
      label: t('budgets.caps.otpmLabel'),
      value: caps.output_tokens_per_min > 0 ? formatNumber(caps.output_tokens_per_min) : t('budgets.caps.offValue'),
      source: caps.output_tokens_per_min_override != null ? t('budgets.caps.overrideSource') : t('budgets.caps.offSource'),
    },
    {
      label: t('budgets.caps.keyTpmLabel'),
      value: caps.key_tokens_per_min > 0 ? formatNumber(caps.key_tokens_per_min) : t('budgets.caps.offValue'),
      source: caps.key_tokens_per_min_override != null ? t('budgets.caps.overrideSource') : t('budgets.caps.offSource'),
    },
  ] : []

  return (
    <section aria-labelledby="budgets-caps-title" className="flex flex-col gap-3">
      <h2 id="budgets-caps-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('budgets.caps.title')}</h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.caps.note')}</p>

      {loadError ? (
        <StateNotice state="error" message={loadError} action={{ label: t('common.retry'), onClick: () => void load() }} />
      ) : caps ? (
        <div className="flex flex-col gap-3">
          {caps.budget_exceeded && (
            <StateNotice
              state="error"
              title={t('budgets.caps.budgetExceededTitle')}
              message={t('budgets.caps.budgetExceededMessage', {
                spend: formatMoney(caps.month_spend_cents / 100, currency),
                budget: formatMoney(caps.monthly_budget_cents / 100, currency),
              })}
            />
          )}
          <MetricStrip
            aria-label={t('budgets.caps.title')}
            metrics={[
              ...tokenCapMetrics,
              {
                label: t('budgets.caps.budgetLabel'),
                value: formatMoney(caps.monthly_budget_cents / 100, currency),
                unit: 'USD',
                source: caps.monthly_budget_override_cents != null ? t('budgets.caps.overrideSource') : t('budgets.caps.defaultSource'),
              },
              {
                label: t('budgets.caps.spendLabel'),
                value: formatMoney(caps.month_spend_cents / 100, currency),
                unit: 'USD',
                state: caps.budget_exceeded ? 'error' : caps.monthly_budget_cents > 0 && caps.month_spend_cents * 100 / caps.monthly_budget_cents >= 80 ? 'warning' : 'ok',
              },
            ]}
          />

          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn-secondary" onClick={openRpm}>{t('budgets.caps.rpmEdit')}</button>
            <button type="button" className="btn-secondary" onClick={openTpm}>{t('budgets.caps.tpmEdit')}</button>
            <button type="button" className="btn-secondary" onClick={openItpm}>{t('budgets.caps.itpmEdit')}</button>
            <button type="button" className="btn-secondary" onClick={openOtpm}>{t('budgets.caps.otpmEdit')}</button>
            <button type="button" className="btn-secondary" onClick={openKeyTpm}>{t('budgets.caps.keyTpmEdit')}</button>
            <button type="button" className="btn-secondary" onClick={openBudget}>{t('budgets.caps.budgetEdit')}</button>
          </div>
        </div>
      ) : (
        <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('budgets.caps.loading')} />
      )}

      {rpmAction.ui}
      {tpmAction.ui}
      {itpmAction.ui}
      {otpmAction.ui}
      {keyTpmAction.ui}
      {budgetAction.ui}
    </section>
  )
}
