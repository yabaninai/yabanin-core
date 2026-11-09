import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { EntityDrawer } from '../../components/astra/EntityDrawer'
import { useAction } from '../../components/astra/ActionDialog'
import { usePermissions } from '../../hooks/usePermissions'
import { ApiError } from '../../api/transport'
import { updateAPIKeyLabels, type APIKey } from '../../api/keys'
import { getOrgBudgetSettings } from '../../api/orgSettings'
import { listKeyWhitelist, listTeamWhitelist } from '../../api/members'
import { listOrgTeamBudgets, type TeamSpendSummary } from '../../api/budgets'
import { validateKeyLabels, type LabelProblem } from '../../lib/labels'
import { relatedListHref, currentHashQuery } from '../../lib/inspectUrl'
import { formatMoneyCell } from '../../lib/columnFormat'

// inspector fields, the "Effective policy" panel (layered org → team → key →
// renders only when the API provides the fields. The labels editor (AT-13)
// rides along as drawer content; the raw secret is never shown.

export function KeyDrawer({
  org, apiKey, inspectId, canManage, hint, onClose, onSaved,
}: {
  org: string
  /** The row from the loaded page; null renders the honest not-found state. */
  apiKey: APIKey | null
  inspectId: string
  canManage: boolean
  hint?: string
  onClose: () => void
  onSaved: (next: APIKey) => void
}) {
  const { t } = useTranslation()
  return (
    <EntityDrawer
      kind={t('keys.title')}
      title={apiKey ? apiKey.name : inspectId}
      onClose={onClose}
      missing={!apiKey}
      ids={apiKey ? [{ label: t('keys.id'), value: apiKey.id }] : []}
      fields={apiKey ? [
        { label: t('keys.name'), value: apiKey.name },
        { label: t('keys.active'), value: apiKey.active ? t('keys.activeStatus') : t('keys.disabledStatus') },
        { label: t('keys.organization'), value: apiKey.org_id ?? t('common.notRecorded'), mono: true },
        ...(apiKey.team_id ? [{ label: t('drawer.team'), value: apiKey.team_id, mono: true }] : []),
        { label: t('drawer.created'), value: apiKey.created_at ?? t('common.notRecorded'), mono: true },
        ...(apiKey.last_used_at !== undefined
          ? [{ label: t('keys.lastUsed'), value: apiKey.last_used_at ?? t('common.unknown'), mono: true }]
          : []),
        ...(apiKey.expires_at !== undefined
          ? [{ label: t('keys.expiresAt'), value: apiKey.expires_at ?? t('common.unknown'), mono: true }]
          : []),
      ] : []}
      links={apiKey ? [
        { label: t('app.navRequestsExplorer'), href: relatedListHref('requests-explorer', currentHashQuery(), { org: apiKey.org_id ?? '' }) },
        { label: t('app.navOrganizations'), href: relatedListHref('orgs', currentHashQuery()) },
      ] : []}
    >
      {apiKey && <EffectivePolicyPanel org={org} apiKey={apiKey} />}
      {apiKey && <LimitsSection apiKey={apiKey} />}
      {apiKey && (
        <KeyLabelsBlock
          apiKey={apiKey}
          canManage={canManage}
          hint={hint}
          onSaved={onSaved}
        />
      )}
    </EntityDrawer>
  )
}

function formatLabels(labels: Record<string, string> | undefined): string {
  return Object.entries(labels ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
}

// value comes from (org → team → key → session). Read-only over EXISTING
// endpoints; a fetch the caller has no right for (whitelists are root-only)
// or a missing value renders as "—" — never invented, never an error banner.
function EffectivePolicyPanel({ org, apiKey }: { org: string; apiKey: APIKey }) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  // Stable effect inputs: usePermissions returns a fresh object per render.
  const isRoot = perms.isRoot
  const canBudgets = perms.can('budgets.manage')
  const [state, setState] = useState<{
    graceCents: number | null
    teamBudget: TeamSpendSummary | null
    keyModels: string[]
    teamModels: string[]
  }>({ graceCents: null, teamBudget: null, keyModels: [], teamModels: [] })
  const orgRef = useRef(org)
  orgRef.current = org

  useEffect(() => {
    let alive = true
    const keep = <T,>(run: () => Promise<T>, apply: (v: T) => void) => {
      // No right / endpoint absent: the layer stays "—" (never an error banner).
      void run().then(v => { if (alive && orgRef.current === org) apply(v) }).catch(() => {})
    }
    if (isRoot) {
      keep(
        () => listKeyWhitelist(apiKey.id),
        v => setState(s => ({ ...s, keyModels: (v.data ?? []).filter(e => e.allowed).map(e => e.model_name) })),
      )
      if (apiKey.team_id) {
        keep(
          () => listTeamWhitelist(apiKey.team_id!),
          v => setState(s => ({ ...s, teamModels: (v.data ?? []).filter(e => e.allowed).map(e => e.model_name) })),
        )
      }
      keep(
        () => getOrgBudgetSettings(org),
        v => setState(s => ({ ...s, graceCents: v.effective_grace_floor_cents ?? null })),
      )
    }
    if (canBudgets && apiKey.team_id) {
      keep(
        () => listOrgTeamBudgets(org),
        rows => setState(s => ({ ...s, teamBudget: rows.find(b => b.team_id === apiKey.team_id) ?? null })),
      )
    }
    return () => { alive = false }
  }, [org, apiKey.id, apiKey.team_id, isRoot, canBudgets])

  const money = (cents: number | null) =>
    cents == null ? '—' : formatMoneyCell(cents / 100).text

  const rows: Array<{ source: string; label: string; value: string }> = [
    { source: t('keys.organization'), label: t('keys.policyGrace'), value: money(state.graceCents) },
    ...(apiKey.team_id
      ? [{
          source: t('drawer.team'),
          label: t('budgets.colLimit'),
          value: state.teamBudget ? formatMoneyCell(state.teamBudget.monthly_limit_usd).text : '—',
        }]
      : []),
    { source: t('keys.sourceKey'), label: t('keys.allowedModels'), value: state.keyModels.length ? state.keyModels.join(', ') : '—' },
    ...(apiKey.team_id && state.teamModels.length
      ? [{ source: t('drawer.team'), label: t('keys.allowedModels'), value: state.teamModels.join(', ') }]
      : []),
    { source: t('keys.sourceKey'), label: t('keys.labelsTitle'), value: formatLabels(apiKey.labels) || t('keys.policyNone') },
    ...(apiKey.rate_limit_rpm != null || apiKey.rate_limit_tpm != null
      ? [{
          source: t('keys.sourceKey'),
          label: t('keys.limits'),
          value: [
            apiKey.rate_limit_rpm != null ? `${t('keys.rateLimitRpm')}: ${apiKey.rate_limit_rpm}` : '',
            apiKey.rate_limit_tpm != null ? `${t('keys.rateLimitTpm')}: ${apiKey.rate_limit_tpm}` : '',
          ].filter(Boolean).join(' · '),
        }]
      : []),
    ...(apiKey.can_mint_sessions
      ? [{ source: t('keys.sourceSession'), label: t('keys.canMintSessions'), value: t('keys.canMintSessionsHint') }]
      : []),
  ]

  return (
    <section aria-label={t('keys.policyTitle')} className="flex flex-col gap-2 border-t border-[color:var(--astra-rule)] pt-3">
      <h3 className="text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('keys.policyTitle')}</h3>
      <p className="text-xs text-[color:var(--astra-text-muted)]">
        {t('keys.organization')} → {t('drawer.team')} → {t('keys.sourceKey')} → {t('keys.sourceSession')}
      </p>
      <dl className="flex flex-col gap-2">
        {rows.map(r => (
          <div key={`${r.source}:${r.label}`} className="min-w-0">
            <dt className="flex flex-wrap items-baseline gap-2 text-[color:var(--astra-text-muted)]" style={{ font: 'var(--astra-font-label)/1.4 var(--astra-font-ui)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              <span>{r.label}</span>
              <span className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-1.5 py-0.5 text-[10px] normal-case">{r.source}</span>
            </dt>
            <dd className="mt-0.5 break-all text-sm text-[color:var(--astra-ink)]">{r.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

// provides the fields (conditional render per the card).
function LimitsSection({ apiKey }: { apiKey: APIKey }) {
  const { t } = useTranslation()
  if (apiKey.rate_limit_rpm == null && apiKey.rate_limit_tpm == null && apiKey.budget_id == null) return null
  return (
    <section aria-label={t('keys.limits')} className="flex flex-col gap-2 border-t border-[color:var(--astra-rule)] pt-3">
      <h3 className="text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('keys.limits')}</h3>
      <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {apiKey.rate_limit_rpm != null && (
          <div className="min-w-0">
            <dt className="text-[color:var(--astra-text-muted)]">{t('keys.rateLimitRpm')}</dt>
            <dd className="mt-0.5 text-sm text-[color:var(--astra-ink)]">{apiKey.rate_limit_rpm}</dd>
          </div>
        )}
        {apiKey.rate_limit_tpm != null && (
          <div className="min-w-0">
            <dt className="text-[color:var(--astra-text-muted)]">{t('keys.rateLimitTpm')}</dt>
            <dd className="mt-0.5 text-sm text-[color:var(--astra-ink)]">{apiKey.rate_limit_tpm}</dd>
          </div>
        )}
        {apiKey.budget_id != null && (
          <div className="min-w-0">
            <dt className="text-[color:var(--astra-text-muted)]">{t('budgets.colLimit')}</dt>
            <dd className="mt-0.5 text-sm">
              <a href={relatedListHref('budgets', currentHashQuery())} className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4">{t('app.navBudgets')}</a>
              <span className="ms-2 break-all text-xs text-[color:var(--astra-text-muted)]" style={{ fontFamily: 'var(--astra-font-code)' }}>{apiKey.budget_id}</span>
            </dd>
          </div>
        )}
      </dl>
    </section>
  )
}

// AT-13 labels editor (moved from the inline expanded row into the key card;
// same DOM contract: chips, Key/Value inputs, Add, validation alert, save).
export function KeyLabelsBlock({ apiKey, canManage, hint, onSaved }: { apiKey: APIKey; canManage: boolean; hint?: string; onSaved: (next: APIKey) => void }) {
  const { t } = useTranslation()
  const [labels, setLabels] = useState<Record<string, string>>({ ...(apiKey.labels ?? {}) })
  const [locked, setLocked] = useState(Boolean(apiKey.labels_locked))
  const [mint, setMint] = useState(Boolean(apiKey.can_mint_sessions))
  const [usage, setUsage] = useState(Boolean(apiKey.can_read_usage))
  const [keyName, setKeyName] = useState('')
  const [keyValue, setKeyValue] = useState('')
  const [problems, setProblems] = useState<LabelProblem[]>([])
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState('')

  useEffect(() => {
    setLabels({ ...(apiKey.labels ?? {}) })
    setLocked(Boolean(apiKey.labels_locked))
    setMint(Boolean(apiKey.can_mint_sessions))
    setUsage(Boolean(apiKey.can_read_usage))
  }, [apiKey])

  const reasonText = (reason: string) => {
    switch (reason) {
      case 'invalid_key': return t('keys.dropInvalidKey')
      case 'invalid_value': return t('keys.dropInvalidValue')
      case 'value_too_long': return t('keys.dropValueTooLong')
      case 'reserved': return t('keys.dropReserved')
      case 'too_many': return t('keys.dropTooMany')
      case 'secret_like': return t('keys.dropSecretLike')
      default: return t('keys.dropInvalidValue')
    }
  }

  const addLabel = (e: React.FormEvent) => {
    e.preventDefault()
    const checked = validateKeyLabels({ ...labels, [keyName]: keyValue })
    const fresh = checked.problems.filter(p => p.key === keyName.trim().toLowerCase() || p.key === keyName)
    if (fresh.length > 0 || checked.problems.some(p => p.reason === 'too_many' || p.reason === 'reserved' || p.reason === 'invalid_key')) {
      const mine = checked.problems.filter(p => !Object.prototype.hasOwnProperty.call(labels, p.key))
      setProblems(mine.length > 0 ? mine : checked.problems)
      return
    }
    setLabels(checked.labels)
    setProblems([])
    setKeyName('')
    setKeyValue('')
  }

  // AUX-12: label/mode save is low risk and reversible — no dialog; the
  // toast's Undo restores the pre-save label set and mode switches.
  const labelSaveAction = useAction({ id: 'keys.labels', risk: 'low', permission: 'keys.manage', reversible: true })

  const save = () => {
    const checked = validateKeyLabels(labels)
    if (checked.problems.length > 0) {
      setProblems(checked.problems)
      return
    }
    setProblems([])
    setNote('')
    const body = {
      labels: checked.labels,
      labels_locked: locked,
      can_mint_sessions: mint,
      can_read_usage: usage,
    }
    // Undo restores what the server had before the save, not the draft.
    const previous = {
      labels: { ...(apiKey.labels ?? {}) },
      labels_locked: Boolean(apiKey.labels_locked),
      can_mint_sessions: Boolean(apiKey.can_mint_sessions),
      can_read_usage: Boolean(apiKey.can_read_usage),
    }
    setBusy(true)
    labelSaveAction.run({
      confirmLabel: t('keys.saveLabels'),
      execute: async () => {
        try {
          await updateAPIKeyLabels(apiKey.id, body)
        } catch (err: unknown) {
          if (err instanceof ApiError && err.body) {
            try {
              const parsed = JSON.parse(err.body) as LabelProblem[]
              if (Array.isArray(parsed) && parsed.length > 0 && typeof parsed[0]?.key === 'string') {
                setProblems(parsed)
              }
            } catch {
              // not a problem list
            }
          }
          throw err
        }
        onSaved({ ...apiKey, ...body })
      },
      undo: async () => {
        await updateAPIKeyLabels(apiKey.id, previous)
        onSaved({ ...apiKey, ...previous })
      },
      onDone: () => setBusy(false),
      onError: (message) => { setBusy(false); setNote(message) },
    })
  }

  const entries = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b))

  return (
    <div className="flex flex-col gap-2 border-t border-[color:var(--astra-rule)] pt-3">
      <div>
        <h3 className="text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('keys.labelsTitle')}</h3>
        <p className="text-xs text-[color:var(--astra-text-muted)]">{t('keys.labelsHint')}</p>
      </div>
      {entries.length === 0 ? (
        <p className="text-xs text-[color:var(--astra-text-muted)]">{t('keys.noLabels')}</p>
      ) : (
        <ul className="flex flex-wrap gap-2">
          {entries.map(([name, value]) => (
            <li key={name}>
              <button
                type="button"
                onClick={() => setLabels(prev => {
                  const next = { ...prev }
                  delete next[name]
                  return next
                })}
                className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-2 py-1 text-xs text-[color:var(--astra-ink)]"
              >
                <span style={{ fontFamily: 'var(--astra-font-code)' }}>{name}={value}</span>
                {' '}
                {t('keys.removeLabel', { label: name })}
              </button>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={addLabel} className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.labelKey')}</span>
          <input value={keyName} onChange={e => setKeyName(e.target.value)} className="control sm:w-40" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.labelValue')}</span>
          <input value={keyValue} onChange={e => setKeyValue(e.target.value)} className="control sm:w-40" />
        </label>
        <button type="submit" disabled={!canManage} title={hint} className="btn-secondary">{t('keys.addLabel')}</button>
      </form>
      {([
        { label: t('keys.lockLabels'), hint: t('keys.lockLabelsHint'), checked: locked, set: setLocked },
        { label: t('keys.canMintSessions'), hint: t('keys.canMintSessionsHint'), checked: mint, set: setMint },
        { label: t('keys.canReadUsage'), hint: t('keys.canReadUsageHint'), checked: usage, set: setUsage },
      ] as const).map(item => (
        <label key={item.label} className="flex items-start gap-2 text-sm">
          <input type="checkbox" checked={item.checked} onChange={e => item.set(e.target.checked)} />
          <span>
            <span className="font-medium">{item.label}</span>
            <span className="block text-xs text-[color:var(--astra-text-muted)]">{item.hint}</span>
          </span>
        </label>
      ))}
      {problems.length > 0 && (
        <ul role="alert">
          {problems.map(p => (
            <li key={`${p.key}:${p.reason}`} className="text-xs text-[color:var(--astra-danger)]">
              {p.key} {reasonText(p.reason)}
            </li>
          ))}
        </ul>
      )}
      {note !== '' && <p className="text-xs text-[color:var(--astra-danger)]">{note}</p>}
      {labelSaveAction.ui}
      <button type="button" onClick={save} disabled={busy || !canManage} title={hint} className="btn-secondary w-fit">
        {busy ? t('keys.savingLabels') : t('keys.saveLabels')}
      </button>
    </div>
  )
}
