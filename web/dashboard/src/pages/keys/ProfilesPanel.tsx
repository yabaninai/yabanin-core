import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listAgentProfiles, createAgentProfile, deleteAgentProfile,
  type AgentProfile,
} from '../../api/agentKeys'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { RowActions } from '../../components/astra/RowActions'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { usePermissions } from '../../hooks/usePermissions'
import { formatMoneyCell } from '../../lib/columnFormat'

// for yag_ keys. Creation moved into the FormDrawer; the daily cap is entered
// in CURRENCY and stored as cents. Profile CRUD stays root-only server-side —
// the controls disable with the root hint (AUX-13).

export function ProfilesPanel({ org, createOpen, onCreateClosed }: {
  org: string
  createOpen: boolean
  onCreateClosed: () => void
}) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  const canManage = perms.isRoot
  const manageHint = canManage ? undefined : t('perms.requiredRoot')

  const fetchProfiles = useCallback(
    (signal: AbortSignal) => listAgentProfiles(org, { signal }),
    [org],
  )
  const profilesQuery = useScopedQuery({
    key: `agent-profiles|${org}`,
    org,
    fetcher: fetchProfiles,
  })
  const profiles = profilesQuery.data ?? []
  const [profilePage, setProfilePage] = useState(1)
  const [error, setError] = useState('')

  const [name, setName] = useState('')
  const [tier, setTier] = useState('')
  const [grants, setGrants] = useState('')
  const [cap, setCap] = useState('')

  const refresh = () => profilesQuery.load()

  // The drawer closes at once; the create keeps running under its org scope.
  const submitCreate = async () => {
    const capCents = cap.trim() === '' ? null : Math.round(Number(cap.replace(',', '.')) * 100)
    void (async () => {
      try {
        await createAgentProfile(org, {
          name: name.trim(),
          tier_hint: tier.trim(),
          mcp_grants: grants.split(',').map(s => s.trim()).filter(Boolean),
          budget_cap_cents: capCents != null && Number.isFinite(capCents) && capCents > 0 ? capCents : null,
        })
        setName(''); setTier(''); setGrants(''); setCap('')
        refresh()
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err))
      }
    })()
  }

  const deleteAction = useAction({
    id: 'keys.profile.delete', risk: 'high', permission: 'agent_keys.manage', reversible: false,
    impact: t('keys.profileDeleteConfirm'),
  })
  const handleDelete = (p: AgentProfile) => {
    setError('')
    deleteAction.run({
      entity: p.name,
      confirmLabel: t('keys.delete'),
      reason: {},
      execute: async ({ reason }) => {
        await deleteAgentProfile(p.id, auditReasonOpts(reason))
      },
      onDone: () => refresh(),
    })
  }

  const columns: DataTableColumn<AgentProfile>[] = [
    {
      key: 'name',
      header: t('keys.name'),
      type: 'text',
      render: p => <span className="font-medium">{p.name}</span>,
    },
    {
      key: 'tier_hint',
      header: t('keys.profileTier'),
      render: p => <span className="text-xs text-[color:var(--astra-text-muted)]">{p.tier_hint || '—'}</span>,
    },
    {
      key: 'mcp_grants',
      header: t('keys.profileGrants'),
      sortable: false,
      render: p => <span className="text-xs text-[color:var(--astra-text-muted)]">{p.mcp_grants.length ? p.mcp_grants.join(', ') : '—'}</span>,
    },
    {
      key: 'budget_cap_cents',
      header: t('budgets.colDailyLimit'),
      sortable: false,
      render: p => (
        <span className="whitespace-nowrap">
          {p.budget_cap_cents != null ? formatMoneyCell(p.budget_cap_cents / 100).text : '—'}
        </span>
      ),
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      {deleteAction.ui}

      {(error !== '' || profilesQuery.error !== '') && (
        <StateNotice state="error" message={error !== '' ? error : profilesQuery.error} />
      )}

      <FormDrawer
        open={createOpen}
        kind={t('keys.agentProfiles')}
        title={t('keys.createProfile')}
        submitLabel={t('common.save')}
        onClose={onCreateClosed}
        onSubmit={submitCreate}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.profileName')}</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder={t('keys.profileNamePlaceholder')}
            className="control"
            required
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.profileTier')}</span>
          <input
            value={tier}
            onChange={e => setTier(e.target.value)}
            placeholder="premium"
            className="control"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.profileGrants')}</span>
          <input
            value={grants}
            onChange={e => setGrants(e.target.value)}
            placeholder={t('keys.profileGrantsPlaceholder')}
            className="control"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.dailyLimitMoney')}</span>
          <input
            type="number"
            min="0"
            step="0.01"
            value={cap}
            onChange={e => setCap(e.target.value)}
            placeholder="50.00"
            className="control"
          />
          <span className="text-xs text-[color:var(--astra-text-muted)]">{t('keys.dailyLimitMoneyHint')}</span>
        </label>
      </FormDrawer>

      <DataTable
        columns={columns}
        rows={profiles}
        getRowId={p => p.id}
        loading={profilesQuery.loading && profiles.length === 0}
        empty={t('keys.profilesEmpty')}
        page={profilePage}
        pageSize={50}
        onPageChange={setProfilePage}
        caption={t('keys.agentProfiles')}
        renderActions={p => (
          <RowActions
            label={t('common.actions')}
            items={[
              {
                id: 'delete',
                label: t('keys.delete'),
                risk: 'high',
                disabled: !canManage,
                onSelect: () => handleDelete(p),
              },
            ]}
          />
        )}
      />
      <p className="text-xs text-[color:var(--astra-text-muted)]" title={manageHint}>
        {t('keys.agentProfilesNote')}
      </p>
    </div>
  )
}
