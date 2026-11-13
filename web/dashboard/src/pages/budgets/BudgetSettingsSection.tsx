import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  getOrgBudgetSettings, updateOrgDefaultOutputCap, updateOrgGraceFloor,
  updateOrgReservationsMode, isReservationsMode, isValidGraceFloorCents,
  RESERVATIONS_MODES,
  type OrgBudgetSettings, type ReservationsMode,
} from '../../api/orgSettings'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import { MetricStrip } from '../../components/astra/MetricStrip'
import { StateNotice } from '../../components/astra/StateNotice'
import { formatMoney, formatNumber } from '../../i18n/format'

// NEXT-18f: the Credits/Budgets org settings section (ADR-0001 rev. 3 §8/§9).
// Mounted by the Budgets & alerts screen for callers the server will accept:
// root (everything) or the org's budgets.manage admins (grace floor and
// output cap; the reservations-mode switch is root-only and hidden here).
//
// Honesty rules this section lives by:
//  - reserved (SUM of active reservations) is NOT exposed by the org credits
//    API yet (NEXT-18a not merged) — it renders "—" with a note instead of 0;
//  - balance_cents null (credits store not wired) renders "—", never 0;
//  - deep_overdraft (wallet below -$100, §8 root signal) is an error notice
//    for root, never a silent state;
//  - every mutation is high/medium risk with a MANDATORY reason (server 400s
//    an empty one), sent as X-Audit-Reason and in the body;
//  - grace_floor_cents: null (platform default) and explicit 0 (no
//    overdraft) are distinct states the form never conflates.

const GRACE_FLOOR_MIN = -100_000
const GRACE_FLOOR_MAX = 0

function errorOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

export function BudgetSettingsSection({ org, isRoot, canBudgets, currency }: {
  org: string
  isRoot: boolean
  canBudgets: boolean
  currency: string | undefined
}) {
  const { t } = useTranslation()
  const [settings, setSettings] = useState<OrgBudgetSettings | null>(null)
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(false)

  // Scope epoch: a delayed org-A response can never land in org B.
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
      const s = await getOrgBudgetSettings(org, { signal: ctrl.signal })
      if (live()) {
        setSettings(s)
        setLoadError('')
      }
    } catch (e: unknown) {
      if (live() && !(e instanceof DOMException && e.name === 'AbortError')) {
        setSettings(null)
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

  // ----- actions (ActionDialog contract; reasons ride X-Audit-Reason) -----
  const graceAction = useAction({ id: 'budgets.settings.grace', risk: 'high', permission: 'budgets.manage', reversible: true })
  const modeAction = useAction({ id: 'budgets.settings.reservations', risk: 'high', permission: 'budgets.manage', reversible: true })
  const capAction = useAction({ id: 'budgets.settings.outputCap', risk: 'medium', permission: 'budgets.manage', reversible: true })

  const openGrace = useCallback(() => {
    if (!settings) return
    graceAction.run({
      confirmLabel: t('budgets.settings.graceSave'),
      was: settings.grace_floor_cents == null
        ? t('budgets.settings.floorDefault', { value: formatMoney(settings.effective_grace_floor_cents / 100, currency) })
        : formatMoney(settings.grace_floor_cents / 100, currency),
      input: {
        label: t('budgets.settings.graceInput', { min: formatNumber(GRACE_FLOOR_MIN), max: formatNumber(GRACE_FLOOR_MAX) }),
        initial: settings.grace_floor_cents == null ? '' : String(settings.grace_floor_cents),
      },
      reason: { required: true },
      execute: async ({ value, reason }) => {
        const trimmed = value.trim()
        let next: number | null = null
        if (trimmed !== '') {
          const parsed = Number(trimmed)
          if (!Number.isInteger(parsed) || !isValidGraceFloorCents(parsed)) {
            throw new Error(t('budgets.settings.graceInvalid', { min: formatNumber(GRACE_FLOOR_MIN), max: formatNumber(GRACE_FLOOR_MAX) }))
          }
          next = parsed
        }
        const updated = await updateOrgGraceFloor(org, next, reason, auditReasonOpts(reason))
        setSettings(updated)
      },
      onDone: load,
    })
  }, [graceAction, load, org, settings, t, currency])

  const openMode = useCallback(() => {
    if (!settings) return
    modeAction.run({
      confirmLabel: t('budgets.settings.modeSave'),
      was: settings.saved_reservations_mode,
      input: { label: t('budgets.settings.modeInput', { modes: RESERVATIONS_MODES.join(' / ') }), initial: settings.saved_reservations_mode },
      reason: { required: true },
      execute: async ({ value, reason }) => {
        const mode = value.trim().toLowerCase()
        if (!isReservationsMode(mode)) {
          throw new Error(t('budgets.settings.modeInvalid', { modes: RESERVATIONS_MODES.join(' / ') }))
        }
        const updated = await updateOrgReservationsMode(org, mode as ReservationsMode, reason, auditReasonOpts(reason))
        setSettings(updated)
      },
      onDone: load,
    })
  }, [load, modeAction, org, settings, t])

  const openCap = useCallback(() => {
    if (!settings) return
    capAction.run({
      confirmLabel: t('budgets.settings.capSave'),
      was: settings.default_output_cap_tokens == null
        ? t('budgets.settings.capNone')
        : formatNumber(settings.default_output_cap_tokens),
      input: { label: t('budgets.settings.capInput'), initial: settings.default_output_cap_tokens == null ? '' : String(settings.default_output_cap_tokens) },
      reason: { required: true },
      execute: async ({ value, reason }) => {
        const trimmed = value.trim()
        let next: number | null = null
        if (trimmed !== '') {
          const parsed = Number(trimmed)
          if (!Number.isInteger(parsed) || parsed <= 0) {
            throw new Error(t('budgets.settings.capInvalid'))
          }
          next = parsed
        }
        const updated = await updateOrgDefaultOutputCap(org, next, reason, auditReasonOpts(reason))
        setSettings(updated)
      },
      onDone: load,
    })
  }, [capAction, load, org, settings, t])

  const floorKnown = settings != null && settings.grace_floor_cents != null
  const effectiveFloor = settings?.effective_grace_floor_cents
  const balanceKnown = settings != null && settings.balance_cents != null
  const available = balanceKnown ? (settings!.balance_cents! - (effectiveFloor ?? 0)) : null

  return (
    <section aria-labelledby="budgets-settings-title" className="flex flex-col gap-3">
      <h2 id="budgets-settings-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('budgets.settings.title')}</h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.settings.note')}</p>

      {loadError ? (
        <StateNotice state="error" message={loadError} action={{ label: t('common.retry'), onClick: () => void load() }} />
      ) : settings ? (
        <div className="flex flex-col gap-3">
          <MetricStrip
            aria-label={t('budgets.settings.title')}
            metrics={[
              {
                label: t('budgets.settings.availableLabel'),
                value: available == null ? '—' : formatMoney(available / 100, currency),
                unit: available == null ? undefined : 'USD',
                source: balanceKnown
                  ? t('budgets.settings.availableSource', { balance: formatMoney(settings.balance_cents! / 100, currency), floor: formatMoney((effectiveFloor ?? 0) / 100, currency) })
                  : t('budgets.settings.balanceUnknown'),
                state: balanceKnown && available != null && available <= 0 ? 'error' : 'ok',
              },
              {
                label: t('budgets.settings.floorLabel'),
                value: settings.grace_floor_cents == null
                  ? t('budgets.settings.floorDefault', { value: formatMoney((effectiveFloor ?? 0) / 100, currency) })
                  : formatMoney(settings.grace_floor_cents / 100, currency),
                unit: floorKnown ? 'USD' : undefined,
                source: floorKnown ? t('budgets.settings.floorOverride') : t('budgets.settings.floorPlatform'),
              },
              {
                label: t('budgets.settings.reservedLabel'),
                value: '—',
                source: t('budgets.settings.reservedUnknown'),
              },
              {
                label: t('budgets.settings.modeLabel'),
                value: settings.effective_reservations_mode,
                state: settings.effective_reservations_mode === 'enforce' ? 'ok' : settings.effective_reservations_mode === 'shadow' ? 'warning' : 'ok',
                source: settings.effective_reservations_mode !== settings.saved_reservations_mode
                  ? t('budgets.settings.modeClamped', { saved: settings.saved_reservations_mode })
                  : `${t('budgets.settings.modeSource')} ${t('budgets.settings.modeEffectiveNote')}`,
              },
            ]}
          />

          {settings.effective_reservations_mode !== settings.saved_reservations_mode && (
            <p className="inline-flex w-fit items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-warning)] bg-[color:var(--astra-warning-surface)] px-2 py-1 text-xs text-[color:var(--astra-ink)]">
              {t('budgets.settings.modeClamped', { saved: settings.saved_reservations_mode })}
            </p>
          )}

          {settings.deep_overdraft && isRoot && (
            <StateNotice
              state="error"
              title={t('budgets.settings.deepOverdraftTitle')}
              message={t('budgets.settings.deepOverdraftMessage', { balance: formatMoney((settings.balance_cents ?? 0) / 100, currency) })}
            />
          )}

          {settings.default_output_cap_tokens != null && (
            <p className="text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{t('budgets.settings.capLabel')}: </span>
              <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatNumber(settings.default_output_cap_tokens)}</span>
            </p>
          )}

          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn-secondary" onClick={openGrace}>{t('budgets.settings.graceEdit')}</button>
            {isRoot && (
              <button type="button" className="btn-secondary" onClick={openMode}>{t('budgets.settings.modeEdit')}</button>
            )}
            <button type="button" className="btn-secondary" onClick={openCap}>{t('budgets.settings.capEdit')}</button>
          </div>
          {!isRoot && (
            <p className="text-xs text-[color:var(--astra-text-muted)]">{t('budgets.settings.modeRootOnly')}</p>
          )}
        </div>
      ) : (
        <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('budgets.settings.loading')} />
      )}

      {graceAction.ui}
      {modeAction.ui}
      {capAction.ui}
    </section>
  )
}
