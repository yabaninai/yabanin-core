import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listAgentKeys, listAgentProfiles, createAgentKey, revokeAgentKey,
  getAgentBudget, upsertAgentBudget,
  type AgentKey,
} from '../../api/agentKeys'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { RowActions } from '../../components/astra/RowActions'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { usePermissions } from '../../hooks/usePermissions'
import { formatMoneyCell } from '../../lib/columnFormat'
import { OneTimeSecretBanner } from './OneTimeSecretBanner'

// in the FormDrawer (name + optional profile), the daily budget is edited
// through the row's ⋯ menu with the amount entered in CURRENCY and stored
// as cents. Budgets are fetched per agent only when the caller holds
// agent_keys.manage (a reader never fires the budget requests, AUX-13).

export function AgentKeysPanel({ org, createOpen, onCreateClosed }: {
  org: string
  createOpen: boolean
  onCreateClosed: () => void
}) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  const canManage = perms.can('agent_keys.manage')

  const fetchAgentKeys = useCallback(
    (signal: AbortSignal) => listAgentKeys(org, { signal }),
    [org],
  )
  const keysQuery = useScopedQuery({
    key: `agent-keys|${org}`,
    org,
    fetcher: fetchAgentKeys,
  })
  const fetchProfiles = useCallback(
    (signal: AbortSignal) => listAgentProfiles(org, { signal }),
    [org],
  )
  const profilesQuery = useScopedQuery({
    key: `agent-profiles|${org}`,
    org,
    fetcher: fetchProfiles,
  })
  const agentKeys = keysQuery.data ?? []
  const profiles = profilesQuery.data ?? []

  // Daily budgets: one GET per listed agent (small sets). Unknown stays
  // unknown — a missing budget row means DENIED, never 0.
  const [budgets, setBudgets] = useState<Record<string, number | null>>({})
  const orgRef = useRef(org)
  orgRef.current = org
  const agentIds = agentKeys.map(k => k.id).join('\n')
  useEffect(() => {
    if (!canManage || agentIds === '') { setBudgets({}); return }
    let alive = true
    const ids = agentIds.split('\n')
    void Promise.all(ids.map(async id => [id, await getAgentBudget(id).then(b => b.daily_limit_cents).catch(() => null) as number | null] as const))
      .then(pairs => {
        if (!alive || orgRef.current !== org) return
        setBudgets(Object.fromEntries(pairs))
      })
    return () => { alive = false }
  }, [agentIds, canManage, org])

  const [agentName, setAgentName] = useState('')
  const [issueProfileId, setIssueProfileId] = useState('')
  const [oneTimeKey, setOneTimeKey] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    setOneTimeKey(''); setError(''); setIssueProfileId('')
  }, [org])

  // The drawer closes at once; the create keeps running under its org scope
  // (a delayed completion can never surface its secret under another org).
  const submitCreate = async () => {
    const seenOrg = org
    void (async () => {
      try {
        const resp = await createAgentKey(agentName.trim(), org, issueProfileId || undefined)
        if (orgRef.current !== seenOrg) return
        setOneTimeKey(resp.key)
        setAgentName('')
        setIssueProfileId('')
        keysQuery.load()
      } catch (err: unknown) {
        if (orgRef.current !== seenOrg) return
        setError(err instanceof Error ? err.message : String(err))
      }
    })()
  }

  const revokeAction = useAction({
    id: 'keys.agent.revoke', risk: 'high', permission: 'agent_keys.manage', reversible: false,
    impact: t('keys.revokeConfirm'),
  })
  const handleRevoke = (k: AgentKey) => {
    setError('')
    revokeAction.run({
      entity: k.name,
      confirmLabel: t('keys.revoke'),
      reason: {},
      execute: async ({ reason }) => {
        await revokeAgentKey(k.id, auditReasonOpts(reason))
      },
      onDone: () => keysQuery.load(),
    })
  }

  // The daily limit is entered in currency (e.g. 25.50) and stored in cents.
  const budgetAction = useAction({
    id: 'keys.agent.budget', risk: 'medium', permission: 'agent_keys.manage', reversible: false,
  })
  const handleSetBudget = (k: AgentKey) => {
    setError('')
    const current = budgets[k.id]
    budgetAction.run({
      entity: k.name,
      input: { label: t('keys.dailyLimitMoney'), initial: current != null ? String(current / 100) : '' },
      was: current != null ? formatMoneyCell(current / 100).text : t('keys.budgetNotSet'),
      confirmLabel: t('budgets.editLimit'),
      reason: {},
      execute: async ({ value }) => {
        const amount = Number(value.replace(',', '.'))
        if (!Number.isFinite(amount) || amount <= 0) throw new Error(t('keys.dailyLimitMoney'))
        await upsertAgentBudget(k.id, Math.round(amount * 100))
      },
      onDone: () => keysQuery.load(),
      onError: (message) => setError(message),
    })
  }

  const removeBudgetAction = useAction({
    id: 'keys.agent.budget.delete', risk: 'high', permission: 'agent_keys.manage', reversible: false,
    impact: t('keys.removeBudgetConfirm'),
  })
  const handleRemoveBudget = (k: AgentKey) => {
    setError('')
    removeBudgetAction.run({
      entity: k.name,
      confirmLabel: t('keys.remove'),
      reason: {},
      execute: async ({ reason }) => {
        const { deleteAgentBudget } = await import('../../api/agentKeys')
        await deleteAgentBudget(k.id, auditReasonOpts(reason))
      },
      onDone: () => keysQuery.load(),
    })
  }

  const columns: DataTableColumn<AgentKey>[] = useMemo(() => [
    {
      key: 'name',
      header: t('keys.name'),
      type: 'text',
      render: k => <span className="font-medium">{k.name}</span>,
    },
    {
      key: 'created_at',
      header: t('drawer.created'),
      format: 'date',
    },
    {
      key: 'active',
      header: t('keys.status'),
      type: 'number',
      getSortValue: k => (k.active ? 1 : 0),
      render: k => (
        <span className="whitespace-nowrap text-xs">
          <span aria-hidden="true" style={{ color: k.active ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
            {k.active ? '●' : '○'}
          </span>{' '}
          {k.active ? t('keys.activeStatus') : t('keys.revokedStatus')}
        </span>
      ),
    },
    {
      key: 'daily_budget_cents',
      header: t('budgets.colDailyLimit'),
      format: 'money',
      sortable: false,
      render: k => {
        const cents = budgets[k.id]
        if (cents == null) {
          // Unknown (not fetched / no row) — never folded into a zero amount.
          return <span className="text-xs text-[color:var(--astra-text-muted)]">—</span>
        }
        return <span className="whitespace-nowrap">{formatMoneyCell(cents / 100).text}</span>
      },
    },
  ], [t, budgets])

  const [agentPage, setAgentPage] = useState(1)

  return (
    <div className="flex flex-col gap-4">
      {revokeAction.ui}
      {budgetAction.ui}
      {removeBudgetAction.ui}

      {(error !== '' || keysQuery.error !== '') && (
        <StateNotice state="error" message={error !== '' ? error : keysQuery.error} />
      )}

      {oneTimeKey && (
        <OneTimeSecretBanner
          title={t('keys.newAgentKeyTitle')}
          message={t('keys.newKeyMessageAgent')}
          secret={oneTimeKey}
          onDismiss={() => setOneTimeKey('')}
        />
      )}

      <FormDrawer
        open={createOpen}
        kind={t('keys.agentKeys')}
        title={t('keys.createAgentKey')}
        submitLabel={t('common.save')}
        onClose={onCreateClosed}
        onSubmit={submitCreate}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.agentName')}</span>
          <input
            value={agentName}
            onChange={e => setAgentName(e.target.value)}
            placeholder={t('keys.agentNamePlaceholder')}
            className="control"
            required
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.issueOnProfile')}</span>
          <select
            value={issueProfileId}
            onChange={e => setIssueProfileId(e.target.value)}
            className="control"
          >
            <option value="">{t('keys.noProfile')}</option>
            {profiles.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          {profiles.length > 0 && (
            <span className="text-xs text-[color:var(--astra-text-muted)]">{t('keys.issueOnProfileNote')}</span>
          )}
        </label>
      </FormDrawer>

      <DataTable
        columns={columns}
        rows={agentKeys}
        getRowId={k => k.id}
        loading={keysQuery.loading && agentKeys.length === 0}
        empty={t('keys.agentKeysEmpty')}
        page={agentPage}
        pageSize={50}
        onPageChange={setAgentPage}
        caption={t('keys.agentKeys')}
        renderActions={k => (
          <RowActions
            label={t('common.actions')}
            items={[
              {
                id: 'budget',
                label: t('budgets.editLimit'),
                disabled: !canManage,
                onSelect: () => handleSetBudget(k),
              },
              ...(budgets[k.id] != null
                ? [{
                    id: 'budget-remove',
                    label: t('keys.remove'),
                    risk: 'high' as const,
                    disabled: !canManage,
                    onSelect: () => handleRemoveBudget(k),
                  }]
                : []),
              {
                id: 'revoke',
                label: t('keys.revoke'),
                risk: 'high',
                disabled: !canManage || !k.active,
                onSelect: () => handleRevoke(k),
              },
            ]}
          />
        )}
      />
      <p className="text-xs text-[color:var(--astra-text-muted)]">
        {t('budgets.agentsNote')}
      </p>
    </div>
  )
}
