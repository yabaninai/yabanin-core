import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listOrgMembers, createOrgMember, updateOrgMember, deleteOrgMember,
  listDevelopers, createDeveloper, setDeveloperActive, deleteDeveloper,
  listMemberInvites, inviteMember, resendMemberInvite, revokeMemberInvite,
  ORG_ROLES,
  type OrgMembership, type OrgRole, type DeveloperUser, type MemberInvite,
} from '../api/client'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useAction } from '../components/astra/ActionDialog'
import { usePermissions } from '../hooks/usePermissions'

// AUX-16: teams & members console over the EXISTING org-scoped endpoints —
// members (GET/POST/PUT/DELETE /api/organizations/{id}/members) and developer
// principals (…/developers; only mounted on portal-enabled deployments, so
// the section shows an honest error when the routes answer 404). Every route
// sits under members.manage (RequireOrgPermission): mutating controls are
// disabled with that hint while the right is unknown/absent (AUX-13) and the
// server keeps arbitrating.
//
// Create flows use small forms (the pattern of Keys/Orgs create); role
// changes go through a medium ActionDialog (was → becomes) and removals
// through high dialogs with the typed-entity confirmation (AUX-12). The
// server rejects self-role changes and above-rank grants for non-root
// callers — that error surfaces in the dialog, never pre-empted here.

export function MembersPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useState('')
  const perms = usePermissions(orgId || undefined)
  const canManage = perms.can('members.manage')
  const manageHint = t('perms.required', { permission: 'members.manage' })

  const [members, setMembers] = useState<OrgMembership[]>([])
  const [membersLoaded, setMembersLoaded] = useState(false)
  const [developers, setDevelopers] = useState<DeveloperUser[]>([])
  const [developersLoaded, setDevelopersLoaded] = useState(false)
  const [invites, setInvites] = useState<MemberInvite[]>([])
  const [invitesLoaded, setInvitesLoaded] = useState(false)
  const [membersError, setMembersError] = useState('')
  const [developersError, setDevelopersError] = useState('')
  const [invitesError, setInvitesError] = useState('')
  const [loading, setLoading] = useState(false)
  const [notice, setNotice] = useState('')

  // Add-member form.
  const [newUserId, setNewUserId] = useState('')
  const [newRole, setNewRole] = useState<OrgRole>('reader')
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState('')

  // W-INV: invite form + the one-time link of the last create/resend (shown
  // once — the raw token is never retrievable again).
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<OrgRole>('reader')
  const [inviting, setInviting] = useState(false)
  const [inviteError, setInviteError] = useState('')
  const [inviteLink, setInviteLink] = useState('')
  const [linkCopied, setLinkCopied] = useState(false)

  // Add-developer form.
  const [newEmail, setNewEmail] = useState('')
  const [newDevName, setNewDevName] = useState('')
  const [newTeamId, setNewTeamId] = useState('')
  const [addingDev, setAddingDev] = useState(false)
  const [addDevError, setAddDevError] = useState('')

  // U07/TP-06: the fetch epoch discards stale responses after an org switch —
  // a delayed org-A member list can never render under org B.
  const epoch = useRef(0)

  const load = useCallback(async (org: string) => {
    if (!org) {
      setMembers([]); setDevelopers([]); setInvites([])
      setMembersLoaded(false); setDevelopersLoaded(false); setInvitesLoaded(false)
      return
    }
    const run = ++epoch.current
    setLoading(true)
    setMembersError(''); setDevelopersError(''); setInvitesError('')
    // Independent sections: a members failure must not blank developers and
    // vice versa (the developers routes answer 404 on deployments without
    // the portal — that stays an honest per-section error).
    const [m, d, i] = await Promise.allSettled([listOrgMembers(org), listDevelopers(org), listMemberInvites(org)])
    if (epoch.current !== run) return
    if (m.status === 'fulfilled') {
      setMembers(m.value)
    } else {
      setMembersError(m.reason instanceof Error ? m.reason.message : String(m.reason))
    }
    setMembersLoaded(true)
    if (d.status === 'fulfilled') {
      setDevelopers(d.value)
    } else {
      setDevelopersError(d.reason instanceof Error ? d.reason.message : String(d.reason))
    }
    setDevelopersLoaded(true)
    if (i.status === 'fulfilled') {
      setInvites(i.value)
    } else {
      setInvitesError(i.reason instanceof Error ? i.reason.message : String(i.reason))
    }
    setInvitesLoaded(true)
    setLoading(false)
  }, [])

  useEffect(() => {
    setNotice('')
    setAddError(''); setAddDevError('')
    setInviteError(''); setInviteLink('')
    void load(orgId)
  }, [load, orgId])

  // Medium dialog: change a member's role (was → becomes, no free input).
  const roleAction = useAction({
    id: 'members.role', risk: 'medium', reversible: false,
    permission: 'members.manage',
  })
  const handleRoleChange = (m: OrgMembership, role: OrgRole) => {
    if (role === m.role) return
    setNotice('')
    roleAction.run({
      confirmLabel: t('members.changeRole'),
      was: m.role,
      becomes: role,
      execute: async () => {
        await updateOrgMember(orgId, m.user_id, role)
      },
      onDone: () => {
        setNotice(t('members.roleChanged', { user: m.user_id }))
        void load(orgId)
      },
    })
  }

  // High dialog: remove a member (typed user id confirmation).
  const removeAction = useAction({
    id: 'members.remove', risk: 'high', reversible: false,
    permission: 'members.manage',
    impact: t('members.removeImpact'),
  })
  const handleRemoveMember = (m: OrgMembership) => {
    setNotice('')
    removeAction.run({
      entity: m.user_id,
      confirmLabel: t('common.delete'),
      execute: async () => {
        await deleteOrgMember(orgId, m.user_id)
      },
      onDone: () => {
        setNotice(t('members.removed', { user: m.user_id }))
        void load(orgId)
      },
    })
  }

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!orgId || !newUserId.trim() || adding) return
    setAdding(true)
    setAddError(''); setNotice('')
    try {
      await createOrgMember(orgId, newUserId.trim(), newRole)
      setNewUserId('')
      setNotice(t('members.added', { user: newUserId.trim() }))
      await load(orgId)
    } catch (err: unknown) {
      setAddError(err instanceof Error ? err.message : String(err))
    } finally {
      setAdding(false)
    }
  }

  // Medium dialog: activate/deactivate a developer (deactivation revokes the
  // developer's keys server-side — hence a dialog, not a silent toggle).
  const devActiveAction = useAction({
    id: 'developers.active', risk: 'medium', reversible: true,
    permission: 'members.manage',
  })
  const handleDevActive = (d: DeveloperUser, active: boolean) => {
    setNotice('')
    devActiveAction.run({
      confirmLabel: active ? t('developers.activate') : t('developers.deactivate'),
      was: d.active ? t('developers.active') : t('developers.inactive'),
      becomes: active ? t('developers.active') : t('developers.inactive'),
      execute: async () => {
        await setDeveloperActive(orgId, d.id, active)
      },
      onDone: () => {
        setNotice(t('developers.statusChanged', { email: d.email }))
        void load(orgId)
      },
    })
  }

  // High dialog: delete a developer (deactivates the account and its keys).
  const devRemoveAction = useAction({
    id: 'developers.remove', risk: 'high', reversible: false,
    permission: 'members.manage',
    impact: t('developers.removeImpact'),
  })
  const handleRemoveDeveloper = (d: DeveloperUser) => {
    setNotice('')
    devRemoveAction.run({
      entity: d.email,
      confirmLabel: t('common.delete'),
      execute: async () => {
        await deleteDeveloper(orgId, d.id)
      },
      onDone: () => {
        setNotice(t('developers.removed', { email: d.email }))
        void load(orgId)
      },
    })
  }

  const handleAddDeveloper = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!orgId || !newEmail.trim() || addingDev) return
    setAddingDev(true)
    setAddDevError(''); setNotice('')
    try {
      await createDeveloper(orgId, {
        email: newEmail.trim().toLowerCase(),
        display_name: newDevName.trim() || undefined,
        team_id: newTeamId.trim() || undefined,
      })
      setNewEmail(''); setNewDevName(''); setNewTeamId('')
      setNotice(t('developers.added', { email: newEmail.trim().toLowerCase() }))
      await load(orgId)
    } catch (err: unknown) {
      setAddDevError(err instanceof Error ? err.message : String(err))
    } finally {
      setAddingDev(false)
    }
  }

  // Medium dialog: revoke a pending invitation (the one-time link dies with
  // the row; an accepted invitation cannot be revoked — the server 410s).
  const revokeInviteAction = useAction({
    id: 'invites.revoke', risk: 'medium', reversible: false,
    permission: 'members.manage',
    impact: t('members.invites.revokeImpact'),
  })
  const handleRevokeInvite = (inv: MemberInvite) => {
    setNotice(''); setInviteLink('')
    revokeInviteAction.run({
      entity: inv.email,
      confirmLabel: t('members.invites.revoke'),
      execute: async () => {
        await revokeMemberInvite(orgId, inv.id)
      },
      onDone: () => {
        setNotice(t('members.invites.revoked', { email: inv.email }))
        void load(orgId)
      },
    })
  }

  const handleResendInvite = async (inv: MemberInvite) => {
    setNotice(''); setInviteError(''); setInviteLink('')
    try {
      const link = await resendMemberInvite(orgId, inv.id)
      setInviteLink(link.invite_path)
      setLinkCopied(false)
      await load(orgId)
    } catch (err: unknown) {
      setInviteError(err instanceof Error ? err.message : String(err))
    }
  }

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!orgId || !inviteEmail.trim() || inviting) return
    setInviting(true)
    setInviteError(''); setNotice(''); setInviteLink('')
    try {
      const link = await inviteMember(orgId, inviteEmail.trim().toLowerCase(), inviteRole)
      setInviteLink(link.invite_path)
      setLinkCopied(false)
      setInviteEmail('')
      setNotice(t('members.invites.invited', { email: link.invite.email }))
      await load(orgId)
    } catch (err: unknown) {
      setInviteError(err instanceof Error ? err.message : String(err))
    } finally {
      setInviting(false)
    }
  }

  // The one-time acceptance link is absolutized against this console origin;
  // the token itself never comes back from the server again.
  const copyInviteLink = async () => {
    if (!inviteLink) return
    const absolute = `${window.location.origin}${inviteLink}`
    try {
      await navigator.clipboard.writeText(absolute)
    } catch {
      // Clipboard unavailable (permissions/http): fall back to a prompt.
      window.prompt(t('members.invites.copyFallback'), absolute)
      return
    }
    setLinkCopied(true)
  }

  const disabled = !canManage
  const disabledHint = canManage ? undefined : manageHint
  const controlCls = 'btn-secondary px-3 py-1 text-xs font-medium'

  const memberColumns: DataTableColumn<OrgMembership>[] = [
    { key: 'user_id', header: t('members.colUser'), type: 'text', mono: true, render: m => m.user_id },
    {
      key: 'role', header: t('members.colRole'), type: 'text',
      render: m => (
        <select
          value={m.role}
          disabled={disabled}
          title={disabledHint}
          onChange={e => handleRoleChange(m, e.target.value as OrgRole)}
          aria-label={t('members.roleSelectAria', { user: m.user_id })}
          className="control max-w-full px-2 py-1 text-xs"
        >
          {ORG_ROLES.map(role => <option key={role} value={role}>{role}</option>)}
        </select>
      ),
    },
    { key: 'created_at', header: t('members.colSince'), type: 'date', mono: true, render: m => m.created_at ?? '—' },
  ]

  const devColumns: DataTableColumn<DeveloperUser>[] = [
    { key: 'email', header: t('developers.colEmail'), type: 'text', render: d => d.email },
    { key: 'display_name', header: t('developers.colName'), type: 'text', render: d => d.display_name || '—' },
    { key: 'team_id', header: t('developers.colTeam'), type: 'text', mono: true, render: d => d.team_id || '—' },
    {
      key: 'active', header: t('developers.colStatus'), type: 'text',
      getSortValue: d => (d.active ? 1 : 0),
      render: d => (d.active
        ? <span className="whitespace-nowrap text-xs" style={{ color: 'var(--astra-success)' }}>● {t('developers.active')}</span>
        : <span className="whitespace-nowrap text-xs text-[color:var(--astra-text-muted)]">○ {t('developers.inactive')}</span>),
    },
  ]

  const inviteColumns: DataTableColumn<MemberInvite>[] = [
    { key: 'email', header: t('developers.colEmail'), type: 'text', render: i => i.email },
    { key: 'role', header: t('members.colRole'), type: 'text', render: i => i.role },
    { key: 'expires_at', header: t('members.invites.colExpires'), type: 'date', mono: true, render: i => i.expires_at },
    {
      key: 'expired', header: t('members.invites.colState'), type: 'text',
      getSortValue: i => (new Date(i.expires_at).getTime() > Date.now() ? 1 : 0),
      render: i => (new Date(i.expires_at).getTime() > Date.now()
        ? <span className="whitespace-nowrap text-xs" style={{ color: 'var(--astra-success)' }}>● {t('members.invites.pending')}</span>
        : <span className="whitespace-nowrap text-xs text-[color:var(--astra-text-muted)]">○ {t('members.invites.expired')}</span>),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader title={t('members.title')} purpose={t('members.purpose')} />

      <div className="card flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('scope.organization')}</span>
          <OrgSelect value={orgId} onChange={setOrgId} autoSelect allowAll={false} />
        </label>
      </div>

      {roleAction.ui}
      {removeAction.ui}
      {devActiveAction.ui}
      {devRemoveAction.ui}
      {revokeInviteAction.ui}

      {notice && <p className="text-xs text-[color:var(--astra-success)]">{notice}</p>}

      <section className="space-y-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--astra-text-muted)]">
          {t('members.invites.section')}
        </h2>

        <form onSubmit={handleInvite} className="card flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('developers.colEmail')}</span>
            <input
              type="email"
              value={inviteEmail}
              onChange={e => setInviteEmail(e.target.value)}
              disabled={disabled || inviting}
              title={disabledHint}
              className="control w-56"
              placeholder={t('developers.phEmail')}
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('members.colRole')}</span>
            <select
              value={inviteRole}
              onChange={e => setInviteRole(e.target.value as OrgRole)}
              disabled={disabled || inviting}
              title={disabledHint}
              className="control w-44"
            >
              {ORG_ROLES.map(role => <option key={role} value={role}>{role}</option>)}
            </select>
          </label>
          <button
            type="submit"
            disabled={disabled || inviting || !inviteEmail.trim()}
            title={disabledHint}
            className="btn-primary"
          >
            {t('members.invites.invite')}
          </button>
        </form>
        {inviteError && <StateNotice state="error" message={inviteError} />}

        {inviteLink && (
          <div className="card flex flex-wrap items-center gap-2" data-testid="invite-link-box">
            <p className="min-w-0 flex-1 break-all font-[family-name:var(--astra-font-code)] text-xs">
              {window.location.origin}{inviteLink}
            </p>
            <button type="button" onClick={copyInviteLink} className={controlCls} data-testid="invite-link-copy">
              {linkCopied ? t('members.invites.copied') : t('members.invites.copy')}
            </button>
          </div>
        )}

        <div className="card overflow-x-auto">
          {!orgId ? (
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('members.pickOrg')}</p>
          ) : loading && !invitesLoaded ? (
            <StateNotice state="loading" message={t('members.invites.fetching')} />
          ) : invitesError ? (
            <StateNotice state="error" message={t('members.invites.loadFailed', { message: invitesError })} />
          ) : invites.length === 0 ? (
            <StateNotice state="empty" message={t('members.invites.empty')} />
          ) : (
            <DataTable
              columns={inviteColumns}
              rows={invites}
              getRowId={i => i.id}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              sortMode="client"
              caption={t('members.invites.section')}
              renderActions={i => (
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => handleResendInvite(i)}
                    disabled={disabled}
                    title={disabledHint}
                    className={controlCls}
                  >
                    {t('members.invites.resend')}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRevokeInvite(i)}
                    disabled={disabled}
                    title={disabledHint}
                    className={`${controlCls} !text-[color:var(--astra-danger)]`}
                  >
                    {t('members.invites.revoke')}
                  </button>
                </div>
              )}
            />
          )}
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--astra-text-muted)]">
          {t('members.membersSection')}
        </h2>

        <form onSubmit={handleAddMember} className="card flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('members.userId')}</span>
            <input
              value={newUserId}
              onChange={e => setNewUserId(e.target.value)}
              disabled={disabled || adding}
              title={disabledHint}
              className="control w-64 font-[family-name:var(--astra-font-code)]"
              placeholder="admin-…"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('members.colRole')}</span>
            <select
              value={newRole}
              onChange={e => setNewRole(e.target.value as OrgRole)}
              disabled={disabled || adding}
              title={disabledHint}
              className="control w-44"
            >
              {ORG_ROLES.map(role => <option key={role} value={role}>{role}</option>)}
            </select>
          </label>
          <button
            type="submit"
            disabled={disabled || adding || !newUserId.trim()}
            title={disabledHint}
            className="btn-primary"
          >
            {t('members.add')}
          </button>
        </form>
        {addError && <StateNotice state="error" message={addError} />}

        <div className="card overflow-x-auto">
          {!orgId ? (
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('members.pickOrg')}</p>
          ) : loading && !membersLoaded ? (
            <StateNotice state="loading" message={t('members.fetching')} />
          ) : membersError ? (
            <StateNotice state="error" message={membersError} />
          ) : members.length === 0 ? (
            <StateNotice state="empty" message={t('members.empty')} />
          ) : (
            <DataTable
              columns={memberColumns}
              rows={members}
              getRowId={m => m.id}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              sortMode="client"
              caption={t('members.membersSection')}
              renderActions={m => (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => handleRemoveMember(m)}
                    disabled={disabled}
                    title={disabledHint}
                    className={`${controlCls} !text-[color:var(--astra-danger)]`}
                  >
                    {t('common.delete')}
                  </button>
                </div>
              )}
            />
          )}
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--astra-text-muted)]">
          {t('developers.section')}
        </h2>

        <form onSubmit={handleAddDeveloper} className="card flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('developers.colEmail')}</span>
            <input
              type="email"
              value={newEmail}
              onChange={e => setNewEmail(e.target.value)}
              disabled={disabled || addingDev}
              title={disabledHint}
              className="control w-56"
              placeholder={t('developers.phEmail')}
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('developers.colName')}</span>
            <input
              value={newDevName}
              onChange={e => setNewDevName(e.target.value)}
              disabled={disabled || addingDev}
              title={disabledHint}
              className="control w-44"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('developers.teamOptional')}</span>
            <input
              value={newTeamId}
              onChange={e => setNewTeamId(e.target.value)}
              disabled={disabled || addingDev}
              title={disabledHint}
              className="control w-48 font-[family-name:var(--astra-font-code)]"
            />
          </label>
          <button
            type="submit"
            disabled={disabled || addingDev || !newEmail.trim()}
            title={disabledHint}
            className="btn-primary"
          >
            {t('developers.add')}
          </button>
        </form>
        {addDevError && <StateNotice state="error" message={addDevError} />}

        <div className="card overflow-x-auto">
          {!orgId ? (
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('members.pickOrg')}</p>
          ) : loading && !developersLoaded ? (
            <StateNotice state="loading" message={t('developers.fetching')} />
          ) : developersError ? (
            <StateNotice state="error" message={t('developers.loadFailed', { message: developersError })} />
          ) : developers.length === 0 ? (
            <StateNotice state="empty" message={t('developers.empty')} />
          ) : (
            <DataTable
              columns={devColumns}
              rows={developers}
              getRowId={d => d.id}
              page={1}
              pageSize={50}
              onPageChange={() => {}}
              sortMode="client"
              caption={t('developers.section')}
              renderActions={d => (
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => handleDevActive(d, !d.active)}
                    disabled={disabled}
                    title={disabledHint}
                    className={controlCls}
                  >
                    {d.active ? t('developers.deactivate') : t('developers.activate')}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRemoveDeveloper(d)}
                    disabled={disabled}
                    title={disabledHint}
                    className={`${controlCls} !text-[color:var(--astra-danger)]`}
                  >
                    {t('common.delete')}
                  </button>
                </div>
              )}
            />
          )}
        </div>
      </section>

      <p className="text-xs text-[color:var(--astra-text-muted)]">
        {t('members.impact')}
      </p>
    </div>
  )
}
