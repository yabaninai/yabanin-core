import type { ReactNode } from 'react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { listOrgTeamBudgets, upsertTeamBudget } from '../../api/budgets'
import { listAPIKeys, type APIKey } from '../../api/keys'
import { ApiError } from '../../api/transport'
import { useAction } from '../../components/astra/ActionDialog'
import { StateNotice } from '../../components/astra/StateNotice'
import { usePermissions } from '../../hooks/usePermissions'
import { gatewayKeysLink } from '../../lib/onboarding'
import {
  autoSelectedSetupKey, firstBudgetPhase, setupKeyTeamCandidates,
  type SetupKeyTeamCandidate,
} from './firstTeamBudget'

// CUI-02 first-run defect (2026-11-20): a fresh org's first gateway request
// is rejected 403 budget_not_configured — spending fails closed until the
// KEY'S TEAM has a budget row. No existing control could create the first
// row (the budgets page lists rows only; its org query starts FROM
// team_budgets, so an unbudgeted team is invisible). This section is that
// missing path, through the EXISTING write endpoint (PUT
// /api/teams/{id}/budget, budgets.manage + org scope, server-validated).
//
// Identity binding (reviewer correction): the write target is the VERIFIED
// setup-key team — the server-set team_id on a key row the operator can
// see — never a team inferred from list order or labeled "default" (key
// creation permits an explicit non-default team; only omission falls back
// server-side). With more than one key the operator selects explicitly;
// confirmation requires typing the team id. No auto-provisioning, no
// enforcement bypass, no preseed, no new global policy.
//
// Honesty rules (no hidden unknown/error states):
//  - keys.manage missing: the identity cannot be resolved — say so, and
//    never guess a team id;
//  - a read failure is an error notice with retry, never a silent blank;
//  - the selected team already budgeted: render nothing (the budgets
//    screen rows carry the truth).
export function FirstTeamBudget({ org }: { org: string }): ReactNode {
  const { t } = useTranslation()
  const perms = usePermissions(org)
  const canBudgets = perms.can('budgets.manage')
  const canKeys = perms.can('keys.manage')
  const [keys, setKeys] = useState<APIKey[] | null>(null)
  const [budgetedIds, setBudgetedIds] = useState<string[] | null>(null)
  const [keysError, setKeysError] = useState('')
  const [budgetsError, setBudgetsError] = useState('')
  const [selectedKeyId, setSelectedKeyId] = useState('')
  const [reload, setReload] = useState(0)

  // Org-scope guard: on org/reload change the previous AbortController
  // fires, so a delayed org-A answer can never land in org B.
  const abortRef = useRef<AbortController | null>(null)
  useEffect(() => {
    abortRef.current?.abort()
    setKeys(null); setBudgetedIds(null); setKeysError(''); setBudgetsError(''); setSelectedKeyId('')
    if (perms.loading || !canBudgets || !canKeys) return
    const ctrl = new AbortController()
    abortRef.current = ctrl
    let cancelled = false
    const live = (e: unknown): boolean => !cancelled && (e as { name?: string })?.name !== 'AbortError'
    void listAPIKeys(org, 1, { signal: ctrl.signal })
      .then(page => { if (live(undefined)) { setKeys(page.data ?? []); setKeysError('') } })
      .catch((e: unknown) => { if (live(e)) setKeysError(errorText(e)) })
    void listOrgTeamBudgets(org, { signal: ctrl.signal })
      .then(rows => { if (live(undefined)) { setBudgetedIds(rows.map(row => row.team_id)); setBudgetsError('') } })
      .catch((e: unknown) => { if (live(e)) setBudgetsError(errorText(e)) })
    return () => { cancelled = true; ctrl.abort() }
  }, [org, canBudgets, canKeys, perms.loading, reload])

  const candidates = useMemo(() => setupKeyTeamCandidates(keys ?? []), [keys])
  const selected = useMemo<SetupKeyTeamCandidate | null>(() => {
    if (selectedKeyId) return candidates.find(c => c.keyId === selectedKeyId) ?? null
    return autoSelectedSetupKey(candidates)
  }, [candidates, selectedKeyId])

  const phase = firstBudgetPhase({
    permsLoading: perms.loading, canBudgets, canKeys, keysError, budgetsError,
    keys, budgetedIds, selected,
  })

  // Explicit identity confirmation: the dialog requires typing the exact
  // team id (high risk + entity) before the write; the first budget is
  // always a positive finite HARD cap (spending stays bounded — the rows
  // on the budgets screen can soften it later).
  const firstBudgetAction = useAction({ id: 'budgets.team.limit', risk: 'high', permission: 'budgets.manage', reversible: true })
  const openFirstBudget = useCallback(() => {
    if (!selected) return
    firstBudgetAction.run({
      entity: selected.teamId,
      confirmLabel: t('budgets.firstSubmit'),
      was: t('budgets.firstNone'),
      input: { label: t('budgets.monthlyLimitInput'), initial: '50' },
      impact: <span>{t('budgets.firstImpactHard')}</span>,
      execute: async ({ value }) => {
        const v = Number(value)
        if (!Number.isFinite(v) || v <= 0) throw new Error(t('budgets.invalidLimit'))
        await upsertTeamBudget(selected.teamId, v, true)
      },
      onDone: () => setReload(n => n + 1),
    })
  }, [firstBudgetAction, selected, t])

  if (phase.kind === 'hidden' || phase.kind === 'waiting' || phase.kind === 'done') return null
  const title = <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('budgets.firstTitle')}</h3>
  if (phase.kind === 'no-keys-perm') {
    return (
      <div className="card space-y-2 p-4" data-testid="first-team-budget">
        {title}
        <StateNotice state="partial" message={t('budgets.firstNoKeysPerm')} />
      </div>
    )
  }
  if (phase.kind === 'error') {
    return (
      <div className="card space-y-2 p-4" data-testid="first-team-budget">
        {title}
        <StateNotice state="error" message={phase.message} action={{ label: t('common.retry'), onClick: () => setReload(n => n + 1) }} />
      </div>
    )
  }
  if (phase.kind === 'no-keys') {
    return (
      <div className="card space-y-2 p-4" data-testid="first-team-budget">
        {title}
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.firstNoKeys')}</p>
        <a href={gatewayKeysLink(org)} className="btn-secondary min-h-[44px] w-fit" data-testid="first-team-budget-open-keys">{t('welcome.stepGatewayOpen')}</a>
      </div>
    )
  }
  return (
    <div className="card space-y-2 p-4" data-testid="first-team-budget">
      {title}
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.firstNote')}</p>
      {candidates.length > 1 ? (
        <label className="block text-sm text-[color:var(--astra-text-muted)]">
          {t('budgets.firstSelectKey')}
          <select
            className="mt-1 w-full rounded border px-2 py-1"
            value={selectedKeyId}
            onChange={e => setSelectedKeyId(e.target.value)}
            data-testid="first-team-budget-key"
          >
            <option value="">{t('budgets.firstSelectPlaceholder')}</option>
            {candidates.map(c => (
              <option key={c.keyId} value={c.keyId}>{c.keyName} — {c.teamId}</option>
            ))}
          </select>
        </label>
      ) : null}
      {selected ? (
        <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="first-team-budget-identity">
          {t('budgets.firstKeyLabel')}: <span className="font-medium">{selected.keyName}</span>
          {' · '}
          {t('budgets.firstTeamLabel')}: <span className="font-mono break-all">{selected.teamId}</span>
        </p>
      ) : null}
      <button
        type="button"
        className="btn-primary min-h-[44px] w-fit"
        disabled={!selected}
        onClick={openFirstBudget}
      >{t('budgets.firstSubmit')}</button>
    </div>
  )
}

function errorText(e: unknown): string {
  return e instanceof ApiError ? e.message : String(e)
}
