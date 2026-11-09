import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listAPIKeys, listTeams,
  listKeyWhitelist, addKeyWhitelist, removeKeyWhitelist,
  listTeamWhitelist, addTeamWhitelist, removeTeamWhitelist,
  type APIKey, type Team, type WhitelistEntry,
} from '../api/client'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useAction } from '../components/astra/ActionDialog'
import { usePermissions } from '../hooks/usePermissions'

// AUX-16: the Model access summary (plan card "who can use which models").
// One page over EXISTING root-only endpoints: the per-key and per-team model
// allowlists (GET/POST/DELETE /api/whitelist/…), plus the key and team lists
// that name the targets. The whitelist routes sit under MustBeRoot today, so
// mutation controls carry the root hint for a non-root operator (AUX-13) and
// the server stays the arbiter on every request.
//
// Lists request one large page (server cap 100) and sort client-side — the
// count line reports fetched vs total when an org has more rows. The UI only
// creates allowed=true grants: the server contract carries an `allowed` flag,
// but no operator flow for explicit denies exists yet (recorded as remaining
// work); entries loaded with allowed=false still render with their honest
// "denied" state and can be removed.

const LIST_PAGE_SIZE = 100

type TargetKind = 'key' | 'team'

interface ExpandedTarget {
  kind: TargetKind
  id: string
  name: string
}

const entryKey = (kind: TargetKind, id: string) => `${kind}:${id}`

export function ModelAccessPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useState('')
  const perms = usePermissions()
  // The whitelist endpoints are root-only: while rights are unknown the
  // controls stay disabled (fail-closed, AUX-13); an unavailable /api/me
  // fails open and the server keeps arbitrating.
  const canManage = perms.isRoot

  const [keys, setKeys] = useState<APIKey[]>([])
  const [keysTotal, setKeysTotal] = useState(0)
  const [teams, setTeams] = useState<Team[]>([])
  const [teamsTotal, setTeamsTotal] = useState(0)
  const [listsLoaded, setListsLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Expanded allowlist panel (one at a time) + its lazily loaded entries.
  const [expanded, setExpanded] = useState<ExpandedTarget | null>(null)
  const [entries, setEntries] = useState<Record<string, WhitelistEntry[]>>({})
  const [entriesLoading, setEntriesLoading] = useState<Record<string, boolean>>({})
  const [entryErrors, setEntryErrors] = useState<Record<string, string>>({})
  const [notice, setNotice] = useState('')

  // U07: a newer scope load aborts the previous one; the epoch also drops
  // stale entry fetches after an org switch.
  const loadAbort = useRef<AbortController | null>(null)
  const epoch = useRef(0)

  const load = useCallback(async (org: string) => {
    if (!org) {
      setKeys([]); setTeams([]); setListsLoaded(false)
      return
    }
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    const run = ++epoch.current
    setLoading(true)
    setError('')
    try {
      const [keysResp, teamsResp] = await Promise.all([
        listAPIKeys(org, 1, { signal: ctrl.signal, pageSize: LIST_PAGE_SIZE }),
        listTeams(org, 1, LIST_PAGE_SIZE, { signal: ctrl.signal }),
      ])
      if (epoch.current !== run) return
      setKeys(keysResp.data ?? [])
      setKeysTotal(keysResp.pagination?.total ?? keysResp.data?.length ?? 0)
      setTeams(teamsResp.data ?? [])
      setTeamsTotal(teamsResp.pagination?.total ?? teamsResp.data?.length ?? 0)
      setListsLoaded(true)
    } catch (e: unknown) {
      if (epoch.current !== run) return
      if (e instanceof DOMException && e.name === 'AbortError') return
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      if (epoch.current === run) setLoading(false)
    }
  }, [])

  useEffect(() => {
    setExpanded(null)
    setEntries({})
    setEntryErrors({})
    void load(orgId)
    return () => loadAbort.current?.abort()
  }, [load, orgId])

  const loadEntries = useCallback(async (target: ExpandedTarget) => {
    const k = entryKey(target.kind, target.id)
    const run = epoch.current
    setEntriesLoading(prev => ({ ...prev, [k]: true }))
    setEntryErrors(prev => ({ ...prev, [k]: '' }))
    try {
      const resp = target.kind === 'key'
        ? await listKeyWhitelist(target.id)
        : await listTeamWhitelist(target.id)
      if (epoch.current !== run) return
      setEntries(prev => ({ ...prev, [k]: resp.data ?? [] }))
    } catch (e: unknown) {
      if (epoch.current !== run) return
      setEntryErrors(prev => ({
        ...prev,
        [k]: e instanceof Error ? e.message : String(e),
      }))
    } finally {
      if (epoch.current === run) {
        setEntriesLoading(prev => ({ ...prev, [k]: false }))
      }
    }
  }, [])

  const openExpanded = (target: ExpandedTarget) => {
    setNotice('')
    if (expanded?.kind === target.kind && expanded.id === target.id) {
      setExpanded(null)
      return
    }
    setExpanded(target)
    void loadEntries(target)
  }

  const refreshExpanded = (target: ExpandedTarget) => void loadEntries(target)

  // Medium dialog: add an allowed=true model grant (typed model name).
  const addAction = useAction({
    id: 'modelAccess.add', risk: 'medium', reversible: false,
    impact: t('modelAccess.addImpact'),
  })
  const handleAdd = (target: ExpandedTarget) => {
    setNotice('')
    addAction.run({
      input: { label: t('modelAccess.modelName'), initial: '' },
      confirmLabel: t('modelAccess.add'),
      execute: async ({ value }) => {
        const model = value.trim()
        if (target.kind === 'key') await addKeyWhitelist(target.id, model, true)
        else await addTeamWhitelist(target.id, model, true)
        setNotice(t('modelAccess.added', { name: target.name, model }))
      },
      onDone: () => refreshExpanded(target),
    })
  }

  // High dialog: removing a grant changes what the key/team may call.
  const removeAction = useAction({
    id: 'modelAccess.remove', risk: 'high', reversible: false,
    impact: t('modelAccess.removeImpact'),
  })
  const handleRemove = (target: ExpandedTarget, entry: WhitelistEntry) => {
    setNotice('')
    removeAction.run({
      entity: entry.model_name,
      confirmLabel: t('modelAccess.remove'),
      execute: async () => {
        if (target.kind === 'key') await removeKeyWhitelist(target.id, entry.model_name)
        else await removeTeamWhitelist(target.id, entry.model_name)
      },
      onDone: () => refreshExpanded(target),
    })
  }

  const disabledHint = canManage ? undefined : t('perms.requiredRoot')

  const keyColumns: DataTableColumn<APIKey>[] = [
    { key: 'name', header: t('modelAccess.colKey'), type: 'text', render: k => k.name },
    { key: 'id', header: t('modelAccess.colId'), type: 'text', mono: true, render: k => k.id },
    { key: 'team_id', header: t('modelAccess.colTeam'), type: 'text', sortable: false, render: k => k.team_id || '—' },
    {
      key: 'active', header: t('modelAccess.colActive'), type: 'text',
      getSortValue: k => (k.active ? 1 : 0),
      render: k => (k.active ? t('models.enabled') : t('models.disabled')),
    },
  ]
  const teamColumns: DataTableColumn<Team>[] = [
    { key: 'name', header: t('modelAccess.colTeamName'), type: 'text', render: m => m.name },
    { key: 'slug', header: t('modelAccess.colSlug'), type: 'text', mono: true, render: m => m.slug },
    { key: 'id', header: t('modelAccess.colId'), type: 'text', mono: true, render: m => m.id },
  ]

  const renderAllowlistPanel = (target: ExpandedTarget) => {
    const k = entryKey(target.kind, target.id)
    const list = entries[k] ?? []
    const busy = entriesLoading[k] ?? false
    const loadError = entryErrors[k] ?? ''
    return (
      <div className="space-y-3 py-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-medium text-[color:var(--astra-text-muted)]">
            {t('modelAccess.allowlistFor', { name: target.name })}
          </p>
          <button
            type="button"
            onClick={() => handleAdd(target)}
            disabled={!canManage}
            title={disabledHint}
            className="btn-secondary px-3 py-1 text-xs font-medium"
          >
            {t('modelAccess.add')}
          </button>
        </div>
        {loadError && <StateNotice state="error" message={loadError} />}
        {busy ? (
          <StateNotice state="loading" message={t('modelAccess.fetchingEntries')} />
        ) : !loadError && list.length === 0 ? (
          <StateNotice state="empty" message={t('modelAccess.emptyEntries')} />
        ) : (
          <ul className="divide-y divide-[color:var(--astra-rule)] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)]">
            {list.map(entry => (
              <li key={entry.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                <span className="min-w-0 break-all text-sm text-[color:var(--astra-ink)]" style={{ fontFamily: 'var(--astra-font-code)' }}>
                  {entry.model_name}
                  {!entry.allowed && (
                    <span className="ms-2 text-xs font-medium text-[color:var(--astra-warning)]">
                      {t('modelAccess.denied')}
                    </span>
                  )}
                </span>
                <button
                  type="button"
                  onClick={() => handleRemove(target, entry)}
                  disabled={!canManage}
                  title={disabledHint}
                  className="btn-secondary px-3 py-1 text-xs font-medium !text-[color:var(--astra-danger)]"
                >
                  {t('modelAccess.remove')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    )
  }

  const listState = (rows: number, emptyText: string) => {
    if (!orgId) {
      return <p className="text-sm text-[color:var(--astra-text-muted)]">{t('modelAccess.pickOrg')}</p>
    }
    if (loading && !listsLoaded) {
      return <StateNotice state="loading" message={t('modelAccess.fetching')} />
    }
    if (error) return <StateNotice state="error" message={error} />
    if (rows === 0) return <StateNotice state="empty" message={emptyText} />
    return null
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t('modelAccess.title')} purpose={t('modelAccess.purpose')} />

      <div className="card flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('scope.organization')}</span>
          <OrgSelect value={orgId} onChange={setOrgId} autoSelect allowAll={false} />
        </label>
      </div>

      {addAction.ui}
      {removeAction.ui}

      {notice && <p className="text-xs text-[color:var(--astra-success)]">{notice}</p>}

      <section className="space-y-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--astra-text-muted)]">
          {t('modelAccess.keysSection')}
        </h2>
        <div className="card overflow-x-auto">
          {listState(keys.length, t('modelAccess.emptyKeys')) ?? (
            <DataTable
              columns={keyColumns}
              rows={keys}
              getRowId={k => k.id}
              page={1}
              pageSize={LIST_PAGE_SIZE}
              onPageChange={() => {}}
              serverTotal={keysTotal}
              scopeNote={t('modelAccess.scopeNote')}
              sortMode="client"
              caption={t('modelAccess.keysSection')}
              renderExpanded={expanded?.kind === 'key'
                ? (k => (expanded.id === k.id ? renderAllowlistPanel(expanded) : null))
                : undefined}
              renderActions={k => (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => openExpanded({ kind: 'key', id: k.id, name: k.name })}
                    aria-expanded={expanded?.kind === 'key' && expanded.id === k.id}
                    className="btn-secondary px-3 py-1 text-xs font-medium"
                  >
                    {expanded?.kind === 'key' && expanded.id === k.id
                      ? t('modelAccess.closeAllowlist')
                      : t('modelAccess.allowlist')}
                  </button>
                </div>
              )}
            />
          )}
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--astra-text-muted)]">
          {t('modelAccess.teamsSection')}
        </h2>
        <div className="card overflow-x-auto">
          {listState(teams.length, t('modelAccess.emptyTeams')) ?? (
            <DataTable
              columns={teamColumns}
              rows={teams}
              getRowId={m => m.id}
              page={1}
              pageSize={LIST_PAGE_SIZE}
              onPageChange={() => {}}
              serverTotal={teamsTotal}
              scopeNote={t('modelAccess.scopeNote')}
              sortMode="client"
              caption={t('modelAccess.teamsSection')}
              renderExpanded={expanded?.kind === 'team'
                ? (m => (expanded.id === m.id ? renderAllowlistPanel(expanded) : null))
                : undefined}
              renderActions={m => (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => openExpanded({ kind: 'team', id: m.id, name: m.name })}
                    aria-expanded={expanded?.kind === 'team' && expanded.id === m.id}
                    className="btn-secondary px-3 py-1 text-xs font-medium"
                  >
                    {expanded?.kind === 'team' && expanded.id === m.id
                      ? t('modelAccess.closeAllowlist')
                      : t('modelAccess.allowlist')}
                  </button>
                </div>
              )}
            />
          )}
        </div>
      </section>

      <p className="text-xs text-[color:var(--astra-text-muted)]">
        {t('modelAccess.impact')}
      </p>
    </div>
  )
}
