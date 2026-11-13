import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  getOrgSpendAlert, isValidWebhookUrl, updateOrgSpendAlert,
  type OrgSpendAlertSettings,
} from '../api/exports.ts'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { useAction, auditReasonOpts } from '../components/astra/ActionDialog'
import { usePermissions } from '../hooks/usePermissions'
import { useHashParam } from '../hooks/useHashParam'
import { formatDateTime, formatMoney } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { isCurrentScope, type AsyncScope } from '../lib/asyncScope'

// The receivers list is READ-ONLY over the receivers that actually exist:
//   - Spend-alert webhook — GET/PATCH /api/organizations/{id}/spend-alert,
//     MustBeRoot server-side (router_billing.go). last_alert_at is the only
//     delivery signal; the API has no connection-test endpoint, no privacy
//     mode and no sampling, so those three render as explicit
//     "not supported by this API" rows — never as fake controls.
//   - WORM lineage export — CLI-only today (pkg/trcli/lineage_export.go),
//     no admin API: the card says so instead of inventing a status.
//   - OTLP spans / SIEM: planned rows without data.
// Honest-data rules: no delivery success/failure is claimed (the API does
// not track it); a failed save keeps the previous receiver state visible;
// edits go through the ActionDialog (reason rides X-Audit-Reason and
// the server writes the audit journal).

function errorOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

export function ExportsPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useHashParam('org')
  const { currency, timezone } = useOrgPresentation(orgId.trim() || undefined)
  const perms = usePermissions(orgId.trim() || undefined)
  const isRoot = perms.isRoot

  const [alert, setAlert] = useState<OrgSpendAlertSettings | null>(null)
  const [alertError, setAlertError] = useState('')
  const [loading, setLoading] = useState(false)

  // Org-scope epoch: a delayed response can never land in another org.
  const orgEpoch = useRef(0)
  const orgRef = useRef('')
  useEffect(() => {
    orgEpoch.current++
    orgRef.current = orgId
  }, [orgId])
  const abortRef = useRef<AbortController | null>(null)

  const org = orgId.trim()

  const load = useCallback(async () => {
    const seenOrg = orgRef.current
    if (!seenOrg) return
    // Fail-closed: the only data endpoint here is MustBeRoot, so while the
    // rights are unknown (or the caller is not root) nothing is requested.
    if (perms.loading || !perms.isRoot) return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    const opts = { signal: ctrl.signal }
    const seen: AsyncScope = { org: seenOrg, epoch: orgEpoch.current }
    const live = () => isCurrentScope(seen, { org: orgRef.current, epoch: orgEpoch.current })
    setLoading(true)
    await getOrgSpendAlert(seenOrg, opts)
      .then(a => { if (live()) { setAlert(a); setAlertError('') } })
      .catch((e: unknown) => { if (live()) { setAlert(null); setAlertError(errorOf(e)) } })
    if (live()) setLoading(false)
  }, [perms.loading, perms.isRoot])

  useEffect(() => {
    if (!org) return
    const timer = setTimeout(() => { void load() }, 300)
    return () => { clearTimeout(timer); abortRef.current?.abort() }
  }, [load, org])

  // ----- actions (ActionDialog contract; reasons ride X-Audit-Reason) -----

  const thresholdAction = useAction({ id: 'exports.alert.threshold', risk: 'medium', reversible: true })
  const webhookAction = useAction({ id: 'exports.alert.webhook', risk: 'medium', reversible: true })
  const disableAlertAction = useAction({ id: 'exports.alert.disable', risk: 'low', reversible: true })

  const openThreshold = useCallback(() => {
    if (!alert) return
    thresholdAction.run({
      confirmLabel: t('exports.saveThreshold'),
      was: alert.threshold_usd != null ? formatMoney(alert.threshold_usd, currency) : t('exports.alertsOff'),
      input: { label: t('exports.thresholdInput'), initial: alert.threshold_usd != null ? String(alert.threshold_usd) : '' },
      impact: <span>{t('exports.impactThreshold')}</span>,
      reason: {},
      execute: async ({ value, reason }) => {
        const v = Number(value)
        if (!Number.isFinite(v) || v <= 0) throw new Error(t('exports.invalidThreshold'))
        // The PATCH overwrites BOTH fields server-side — always send the pair.
        await updateOrgSpendAlert(org, { threshold_usd: v, webhook_url: alert.webhook_url }, auditReasonOpts(reason))
      },
      onDone: () => void load(),
    })
  }, [alert, currency, load, org, t, thresholdAction])

  const openWebhook = useCallback(() => {
    if (!alert) return
    webhookAction.run({
      confirmLabel: t('exports.saveWebhook'),
      was: alert.webhook_url ?? t('exports.webhookNone'),
      input: { label: t('exports.webhookInput'), initial: alert.webhook_url ?? '' },
      impact: <span>{t('exports.impactWebhook')}</span>,
      reason: {},
      execute: async ({ value, reason }) => {
        const v = value.trim()
        // Client gate BEFORE any request: an invalid URL is never saved.
        if (v !== '' && !isValidWebhookUrl(v)) throw new Error(t('exports.invalidWebhook'))
        await updateOrgSpendAlert(org, { threshold_usd: alert.threshold_usd, webhook_url: v === '' ? null : v }, auditReasonOpts(reason))
      },
      onDone: () => void load(),
    })
  }, [alert, load, org, t, webhookAction])

  const disableAlerts = useCallback(() => {
    if (!alert || alert.threshold_usd == null) return
    const prevThreshold = alert.threshold_usd
    const prevWebhook = alert.webhook_url
    disableAlertAction.run({
      confirmLabel: t('exports.disableAlerts'),
      execute: async () => {
        await updateOrgSpendAlert(org, { threshold_usd: null, webhook_url: null })
      },
      undo: async () => {
        await updateOrgSpendAlert(org, { threshold_usd: prevThreshold, webhook_url: prevWebhook })
      },
      onDone: () => void load(),
    })
  }, [alert, disableAlertAction, load, org, t])

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('exports.title')}
        purpose={t('exports.purpose')}
        appliedScope={org || undefined}
      />

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('exports.orgId')}</span>
          <OrgSelect
            value={orgId}
            onChange={setOrgId}
            autoSelect
            className="sm:w-72"
            manualAriaLabel={t('exports.orgUuid')}
          />
        </label>
      </div>

      {!org && <StateNotice state="not-loaded" message={t('exports.notLoaded')} />}

      {org && perms.loading && <StateNotice state="loading" message={t('exports.checkingRights')} />}

      {/* Rights resolved: every receiver endpoint on this screen is a root
          surface today (spend-alert PATCH is MustBeRoot; the others have no
          API at all), so a non-root visitor gets the honest no-access state
          and the page fires no requests the server would only 403. */}
      {org && !perms.loading && !isRoot && (
        <StateNotice state="empty" message={t('exports.noAccess')} />
      )}

      {org && !perms.loading && isRoot && (
        <section aria-labelledby="exports-receivers-title" className="flex flex-col gap-3">
          <h2 id="exports-receivers-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('exports.receiversTitle')}</h2>

          {/* ===== Receiver 1: spend-alert webhook (root-only server-side) ===== */}
          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('exports.webhookTitle')}</h3>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('exports.webhookAbout')}</p>
          {alertError ? (
            <StateNotice state="error" message={alertError} action={{ label: t('common.retry'), onClick: () => void load() }} />
          ) : alert ? (
            <div className="astra-panel flex flex-col gap-3 p-4" data-testid="exports-webhook-card">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                <span className="min-w-0">
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.webhookLabel')}: </span>
                  <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{alert.webhook_url ?? t('exports.webhookNone')}</span>
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.thresholdLabel')}: </span>
                  {alert.threshold_usd != null
                    ? <span className="font-medium" style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(alert.threshold_usd, currency)}</span>
                    : <span className="text-[color:var(--astra-text-muted)]">{t('exports.alertsOff')}</span>}
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.lastDeliveryLabel')}: </span>
                  {alert.last_alert_at
                    ? <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(alert.last_alert_at, timezone)}</span>
                    : <span className="text-[color:var(--astra-text-muted)]">{t('exports.lastDeliveryNone')}</span>}
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.spentTodayLabel')}: </span>
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(alert.spend_today, currency)}</span>
                </span>
              </div>
              <p className="text-sm text-[color:var(--astra-text-muted)]">{t('exports.deliveryProvenance')}</p>
              <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.privacyLabel')}: </span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.privacyUnsupported')}</span>
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.samplingLabel')}: </span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.samplingUnsupported')}</span>
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.connectionLabel')}: </span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('exports.connectionUnavailable')}</span>
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn-secondary" onClick={openWebhook}>{t('exports.setWebhook')}</button>
                <button type="button" className="btn-secondary" onClick={openThreshold}>{t('exports.editThreshold')}</button>
                {alert.threshold_usd != null && (
                  <button type="button" className="btn-secondary" onClick={disableAlerts}>{t('exports.disableAlerts')}</button>
                )}
              </div>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('exports.webhookLoading')} />
          )}

          {/* ===== Receiver 2: WORM lineage export — no admin API yet ===== */}
          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('exports.wormTitle')}</h3>
          <StateNotice
            state="not-loaded"
            message={t('exports.wormNotConfigured')}
            details={t('exports.wormCliNote')}
          />

          {/* ===== Planned receivers: honest placeholders, no data ===== */}
          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('exports.plannedTitle')}</h3>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('exports.plannedNote')}</p>
        </section>
      )}

      {thresholdAction.ui}
      {webhookAction.ui}
      {disableAlertAction.ui}
    </div>
  )
}
