import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { OrgName } from '../components/astra/OrgName'
import { useGlobalScope } from '../hooks/useGlobalScope'
import { usePermissions } from '../hooks/usePermissions'
import { ApiKeysPanel } from './keys/ApiKeysPanel'
import { AgentKeysPanel } from './keys/AgentKeysPanel'
import { ProfilesPanel } from './keys/ProfilesPanel'

// picker — the shell's OrgSwitcher owns the scope, and every read runs
// through the panels' useScopedQuery (a scope change aborts the in-flight
// load). List-first (checklist «страница v2»): the header's primary action
// opens the active tab's FormDrawer; rows keep one ⋯ action menu and open
// the key card on a name click.

type KeysTab = 'api' | 'agent' | 'profiles'

export function KeysPage() {
  const { t } = useTranslation()
  const scope = useGlobalScope()
  const org = scope.org
  const perms = usePermissions(org || undefined)
  const [tab, setTab] = useState<KeysTab>('api')
  // One "create" intent shared by the header and the active tab's FormDrawer.
  const [createOpen, setCreateOpen] = useState(false)
  const closeCreate = () => setCreateOpen(false)

  const canManageKeys = perms.can('keys.manage')
  const canManageAgentKeys = perms.can('agent_keys.manage')
  const primaryByTab: Record<KeysTab, { label: string; disabled: boolean }> = {
    api: { label: t('keys.createKey'), disabled: !canManageKeys },
    agent: { label: t('keys.createAgentKey'), disabled: !canManageAgentKeys },
    profiles: { label: t('keys.createProfile'), disabled: !perms.isRoot },
  }
  const primary = primaryByTab[tab]

  const tabs: Array<{ id: KeysTab; label: string }> = [
    { id: 'api', label: t('keys.title') },
    { id: 'agent', label: t('keys.agentKeys') },
    { id: 'profiles', label: t('keys.agentProfiles') },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('keys.title')}
        purpose={t('keys.purpose')}
        appliedScope={org ? <OrgName orgId={org} /> : undefined}
        primaryAction={{
          label: primary.label,
          disabled: primary.disabled,
          onClick: () => setCreateOpen(true),
        }}
      />

      {/* FE-01: the three key families as tabs. Only the active panel mounts,
          so switching tabs never keeps a hidden screen's requests alive. */}
      <div role="tablist" aria-label={t('keys.title')} className="flex flex-wrap gap-2">
        {tabs.map(item => {
          const selected = tab === item.id
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              id={`keys-tab-${item.id}`}
              aria-selected={selected}
              aria-controls={`keys-panel-${item.id}`}
              onClick={() => {
                setCreateOpen(false)
                setTab(item.id)
              }}
              className={`inline-flex min-h-[40px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm font-medium ${
                selected
                  ? 'border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-accent-surface)] text-[color:var(--astra-ink)]'
                  : 'border-transparent text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]'
              }`}
            >
              {item.label}
            </button>
          )
        })}
      </div>

      {org === '' ? (
        <StateNotice state="not-loaded" message={t('keys.createOrgFirst')} />
      ) : (
        <div role="tabpanel" id={`keys-panel-${tab}`} aria-labelledby={`keys-tab-${tab}`} tabIndex={-1}>
          {tab === 'api' && (
            <ApiKeysPanel org={org} createOpen={createOpen} onCreateClosed={closeCreate} />
          )}
          {tab === 'agent' && (
            <AgentKeysPanel org={org} createOpen={createOpen} onCreateClosed={closeCreate} />
          )}
          {tab === 'profiles' && (
            <ProfilesPanel org={org} createOpen={createOpen} onCreateClosed={closeCreate} />
          )}
        </div>
      )}
    </div>
  )
}
