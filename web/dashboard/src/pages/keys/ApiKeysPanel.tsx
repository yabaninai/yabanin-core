import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { listAPIKeys, createAPIKey, rotateAPIKey, setAPIKeyActive, deleteAPIKey, type APIKey } from '../../api/keys'
import { addKeyWhitelist, listTeams, type Team } from '../../api/members'
import { Pagination } from '../../components/Pagination'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { BulkActions, BULK_SELECTION_LIMIT } from '../../components/astra/BulkActions'
import { RowActions } from '../../components/astra/RowActions'
import { FormDrawer } from '../../components/astra/FormDrawer'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import { downloadCSV, toCSV } from '../../components/astra/csv'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { useTableUrlState } from '../../hooks/useTableUrlState'
import { useInspectParam } from '../../hooks/useInspectParam'
import { usePermissions } from '../../hooks/usePermissions'
import type { SortState } from '../../lib/tableSort'
import { formatNumberCell, formatMoneyCell } from '../../lib/columnFormat'
import { relatedListHref, currentHashQuery } from '../../lib/inspectUrl'
import { KeyDrawer } from './KeyDrawer'
import { OneTimeSecretBanner } from './OneTimeSecretBanner'

// FormDrawer opened from the page header; the row keeps one ⋯ action menu
// and a name click opens the key card. The org comes from the global scope
// render ONLY when the API provides the fields.

export function ApiKeysPanel({ org, createOpen, onCreateClosed }: {
  org: string
  createOpen: boolean
  onCreateClosed: () => void
}) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  const canManageKeys = perms.can('keys.manage')
  const keysHint = canManageKeys ? undefined : t('perms.required', { permission: 'keys.manage' })

  // AUX-03 (server sort): page + sort live in the URL and the server owns
  // the row order (allowlist: id, name, active — a foreign column answers
  // 400 invalid_sort and surfaces as an error notice).
  const { page, setPage, sort, setSort } = useTableUrlState('keys')
  const sortKey = sort?.key ?? ''
  const sortDir = sort?.dir ?? ''
  // Stable fetcher identity: useScopedQuery reloads whenever it changes.
  const fetchKeys = useCallback(
    (signal: AbortSignal) => listAPIKeys(org, page, { signal, sort: sortKey || undefined, dir: sortDir || undefined }),
    [org, page, sortKey, sortDir],
  )
  const keysQuery = useScopedQuery({
    key: `api-keys|${org}|${page}|${sortKey}|${sortDir}`,
    org,
    fetcher: fetchKeys,
  })

  // AT-13: a saved label set patches the loaded row until the next refetch.
  const [overrides, setOverrides] = useState<Record<string, APIKey>>({})
  const fetchedRows = useMemo(() => keysQuery.data?.data ?? [], [keysQuery.data])
  const pagedRows = useMemo(() => fetchedRows.map(r => overrides[r.id] ?? r), [fetchedRows, overrides])
  const total = keysQuery.data?.pagination?.total ?? pagedRows.length
  const totalPages = keysQuery.data?.pagination?.total_pages ?? 1

  // AUX-20: bulk selection (panel-owned state; the bar renders the
  // permission-gated actions + the per-row report).
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  // AUX-17: the key card — from a name click and the ?inspect= deep link.
  const [inspectId, setInspectId] = useInspectParam()
  const inspectedKey = pagedRows.find(k => k.id === inspectId) ?? null
  // TP-06: a one-time secret belongs to exactly one org — any org switch
  // clears it; in-flight mutations are dropped when their org is gone.
  const [oneTimeKey, setOneTimeKey] = useState('')
  const [error, setError] = useState('')
  const [busyRowId, setBusyRowId] = useState('')
  const orgRef = useRef(org)
  orgRef.current = org
  useEffect(() => {
    setOneTimeKey(''); setError(''); setSelectedIds([]); setOverrides({}); setTeamId('')
  }, [org])
  const refresh = useCallback(() => { keysQuery.load() }, [keysQuery])

  // Team picker for the create form: the org's teams load only while the
  // drawer is open, and the list endpoint is root-only. `teams === null`
  // (non-root, failed load, drawer closed) falls back to the raw-ID input —
  // the fallback keeps the old capability instead of a dead select.
  const [teams, setTeams] = useState<Team[] | null>(null)
  useEffect(() => {
    if (!createOpen || !perms.isRoot || !org) { setTeams(null); return }
    const ctrl = new AbortController()
    setTeams(null)
    listTeams(org, 1, 100, { signal: ctrl.signal }) // server caps page_size at 100
      .then(r => { if (!ctrl.signal.aborted) setTeams(r.data ?? []) })
      .catch(() => { if (!ctrl.signal.aborted) setTeams(null) })
    return () => ctrl.abort()
  }, [createOpen, org, perms.isRoot])

  // --- create: the drawer closes at once; the create keeps running under
  // its org scope (a switch never surfaces a stale one-time secret) ---
  const [name, setName] = useState('')
  const [teamId, setTeamId] = useState('')
  const [modelsText, setModelsText] = useState('')
  const [labelsText, setLabelsText] = useState('')
  const submitCreate = async () => {
    const seenOrg = org
    const labelPairs = parsePairs(labelsText)
    const models = modelsText.split(',').map(s => s.trim()).filter(Boolean)
    void (async () => {
      try {
        const { key, rawKey } = await createAPIKey(name.trim(), org, teamId.trim() || undefined)
        if (orgRef.current !== seenOrg) return
        setOneTimeKey(rawKey)
        setName(''); setTeamId(''); setModelsText(''); setLabelsText('')
        setPage(1)
        keysQuery.load()
        // Best-effort post-steps over existing APIs: model whitelist
        // (root-only routes — a denial is surfaced, the key stays created).
        const failedModels: string[] = []
        for (const model of models) {
          try { await addKeyWhitelist(key.id, model, true) } catch { failedModels.push(model) }
        }
        if (Object.keys(labelPairs).length > 0) {
          const { updateAPIKeyLabels } = await import('../../api/keys')
          await updateAPIKeyLabels(key.id, {
            labels: labelPairs, labels_locked: false, can_mint_sessions: false, can_read_usage: false,
          })
        }        if (orgRef.current !== seenOrg) return
        if (failedModels.length > 0) setError(`${t('keys.allowedModels')}: ${failedModels.join(', ')}`)
        keysQuery.load()
      } catch (err: unknown) {
        if (orgRef.current !== seenOrg) return
        setError(err instanceof Error ? err.message : String(err))
      }
    })()
  }

  // --- row mutations (AUX-12 contracts unchanged) ---
  const rotateAction = useAction({
    id: 'keys.rotate', risk: 'high', permission: 'keys.manage', reversible: false,
    impact: t('keys.rotateConfirm'),
  })
  const handleRotate = (k: APIKey) => {
    setError('')
    const seenOrg = org
    rotateAction.run({
      entity: k.name,
      confirmLabel: t('keys.rotate'),
      reason: {},
      execute: async ({ reason }) => {
        const rawKey = await rotateAPIKey(k.id, auditReasonOpts(reason))
        if (orgRef.current !== seenOrg) return
        setOneTimeKey(rawKey)
      },
    })
  }

  // Activation/deactivation is low risk and reversible — no dialog; the
  // toast's 10s Undo affordance covers the inverse call.
  const setActiveAction = useAction({ id: 'keys.set-active', risk: 'low', permission: 'keys.manage', reversible: true })
  const handleSetActive = (k: APIKey, active: boolean) => {
    setError('')
    setBusyRowId(k.id)
    setActiveAction.run({
      confirmLabel: active ? t('keys.activate') : t('keys.deactivate'),
      execute: async () => { await setAPIKeyActive(k.id, active) },
      undo: async () => { await setAPIKeyActive(k.id, !active) },
      onDone: () => { setBusyRowId(''); refresh() },
      onError: (message) => { setBusyRowId(''); setError(message) },
    })
  }

  const deleteKeyAction = useAction({
    id: 'keys.delete', risk: 'high', permission: 'keys.manage', reversible: false,
    impact: t('keys.deleteConfirm'),
  })
  const handleDeleteKey = (k: APIKey) => {
    setError('')
    deleteKeyAction.run({
      entity: k.name,
      confirmLabel: t('keys.delete'),
      reason: {},
      execute: async ({ reason }) => { await deleteAPIKey(k.id, auditReasonOpts(reason)) },
      onDone: () => refresh(),
    })
  }

  // AUX-20: bulk enable/disable (delete never batches — see BulkActions).
  const bulkKeysAction = useAction({ id: 'keys.bulk', risk: 'medium', permission: 'keys.manage', reversible: true })
  const exportSelectedKeysCsv = (selected: APIKey[]) => {
    downloadCSV('api-keys.csv', toCSV(
      [t('keys.name'), t('keys.id'), t('keys.active'), t('drawer.created'), t('keys.labelsTitle')],
      selected.map(k => [
        k.name, k.id,
        k.active ? t('keys.activeStatus') : t('keys.disabledStatus'),
        k.created_at ?? '',
        Object.entries(k.labels ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([key, v]) => `${key}=${v}`).join(' '),
      ]),
    ))
  }

  const showLastUsed = fetchedRows.some(k => k.last_used_at != null)
  const showUsage7d = fetchedRows.some(k => k.requests_7d != null || k.spend_usd_7d != null)
  const showExpires = fetchedRows.some(k => k.expires_at != null)
  const showLimits = fetchedRows.some(k => k.rate_limit_rpm != null || k.rate_limit_tpm != null || k.budget_id != null)

  const columns: DataTableColumn<APIKey>[] = [
    {
      key: 'name',
      header: t('keys.name'),
      type: 'text',
      render: k => (
        // AUX-17: the key name opens the key card (read-only).
        <button
          type="button"
          onClick={() => setInspectId(k.id)}
          title={t('drawer.inspectHint')}
          className="inline-flex min-h-[36px] items-center text-start font-medium text-[color:var(--astra-ink)] hover:underline"
        >
          {k.name}
        </button>
      ),
    },
    { key: 'team_id', header: t('drawer.team'), sortable: false, render: k => <span className="text-xs text-[color:var(--astra-text-muted)]">{k.team_id ?? '—'}</span> },
    { key: 'created_at', header: t('drawer.created'), format: 'date', sortable: false },
    ...(showLastUsed ? [{ key: 'last_used_at', header: t('keys.lastUsed'), format: 'date', sortable: false } satisfies DataTableColumn<APIKey>] : []),
    ...(showUsage7d ? [{
      key: 'requests_7d',
      header: t('keys.usage7d'),
      sortable: false,
      render: (k: APIKey) => (
        <span className="whitespace-nowrap">
          {formatNumberCell(k.requests_7d).text} / {formatMoneyCell(k.spend_usd_7d).text}
        </span>
      ),
    } satisfies DataTableColumn<APIKey>] : []),
    {
      key: 'active',
      header: t('keys.active'),
      type: 'number',
      getSortValue: k => (k.active ? 1 : 0),
      render: k => (
        <span className="whitespace-nowrap text-xs">
          <span aria-hidden="true" style={{ color: k.active ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
            {k.active ? '●' : '○'}
          </span>{' '}
          {k.active ? t('keys.activeStatus') : t('keys.disabledStatus')}
        </span>
      ),
    },
    ...(showExpires ? [{ key: 'expires_at', header: t('keys.expiresAt'), format: 'date', sortable: false } satisfies DataTableColumn<APIKey>] : []),
    ...(showLimits ? [{
      key: 'limits',
      header: t('keys.limits'),
      sortable: false,
      render: (k: APIKey) => (
        <span className="whitespace-nowrap text-xs text-[color:var(--astra-text-muted)]">
          {[
            k.rate_limit_rpm != null ? `${t('keys.rateLimitRpm')} ${k.rate_limit_rpm}` : '',
            k.rate_limit_tpm != null ? `${t('keys.rateLimitTpm')} ${k.rate_limit_tpm}` : '',
          ].filter(Boolean).join(' · ') || '—'}
        </span>
      ),
    } satisfies DataTableColumn<APIKey>] : []),
  ]

  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  const errorNode: ReactNode = error !== ''
    ? <StateNotice state="error" message={error} />
    : keysQuery.error !== ''
      ? <StateNotice state="error" message={keysQuery.error} />
      : null

  return (
    <div className="flex flex-col gap-4">
      {/* AUX-12 surfaces (dialogs + undo toast). The bulk dialog renders
          inside <BulkActions> — do not duplicate it here. */}
      {rotateAction.ui}
      {setActiveAction.ui}
      {deleteKeyAction.ui}

      {errorNode}

      {oneTimeKey && (
        <OneTimeSecretBanner
          title={t('keys.newKeyTitle')}
          message={t('keys.newKeyMessage')}
          secret={oneTimeKey}
          onDismiss={() => setOneTimeKey('')}
        />
      )}

      <FormDrawer
        open={createOpen}
        kind={t('keys.title')}
        title={t('keys.createKey')}
        submitLabel={t('common.save')}
        onClose={onCreateClosed}
        onSubmit={submitCreate}
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.keyName')}</span>
          <input value={name} onChange={e => setName(e.target.value)} placeholder={t('keys.keyNamePlaceholder')} className="control" required />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('drawer.team')}</span>
          {teams !== null ? (
            <select value={teamId} onChange={e => setTeamId(e.target.value)} className="control">
              <option value="">{t('keys.teamDefaultOption')}</option>
              {teams.map(team => (
                <option key={team.id} value={team.id}>{teamLabel(team)}</option>
              ))}
            </select>
          ) : (
            <input value={teamId} onChange={e => setTeamId(e.target.value)} className="control" style={{ fontFamily: 'var(--astra-font-code)' }} />
          )}
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.labelsTitle')}</span>
          <input value={labelsText} onChange={e => setLabelsText(e.target.value)} placeholder={t('keys.labelsPlaceholder')} className="control" />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('keys.allowedModels')}</span>
          <input value={modelsText} onChange={e => setModelsText(e.target.value)} placeholder={t('keys.modelsPlaceholder')} className="control" />
          <span className="text-xs text-[color:var(--astra-text-muted)]">{t('keys.allowedModelsHint')}</span>
        </label>
        <p className="text-xs text-[color:var(--astra-text-muted)]">
          {t('keys.newKeyMessage')}{' '}
          <a href={relatedListHref('budgets', currentHashQuery())} className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4">{t('app.navBudgets')}</a>
        </p>
      </FormDrawer>

      <BulkActions
        rows={pagedRows}
        getRowId={k => k.id}
        getRowLabel={k => k.name}
        selectedIds={selectedIds}
        onSelectionChange={setSelectedIds}
        limit={BULK_SELECTION_LIMIT}
        dialog={bulkKeysAction}
        onChanged={() => refresh()}
        actions={[
          {
            id: 'keys.bulk.enable',
            label: t('keys.activate'),
            disabled: !canManageKeys || busyRowId !== '',
            applyRow: (k, reason) => setAPIKeyActive(k.id, true, auditReasonOpts(reason)),
            revertRow: (k, reason) => setAPIKeyActive(k.id, false, auditReasonOpts(reason)),
          },
          {
            id: 'keys.bulk.disable',
            label: t('keys.deactivate'),
            disabled: !canManageKeys || busyRowId !== '',
            applyRow: (k, reason) => setAPIKeyActive(k.id, false, auditReasonOpts(reason)),
            revertRow: (k, reason) => setAPIKeyActive(k.id, true, auditReasonOpts(reason)),
          },
          { id: 'keys.bulk.export', label: t('common.exportCsv'), instant: exportSelectedKeysCsv },
        ]}
      />

      <DataTable
        columns={columns}
        rows={pagedRows}
        getRowId={k => k.id}
        loading={keysQuery.loading && pagedRows.length === 0}
        empty={t('keys.empty')}
        page={page}
        pageSize={50}
        onPageChange={setPage}
        pagination="external"
        serverTotal={total}
        sortMode="server"
        sort={sort}
        onSortChange={handleSortChange}
        caption={t('keys.title')}
        selection={{
          selectedRowIds: selectedIds,
          onSelectionChange: setSelectedIds,
          limit: BULK_SELECTION_LIMIT,
          rowLabel: k => k.name,
        }}
        renderActions={k => (
          <RowActions
            label={t('common.actions')}
            items={[
              { id: 'rotate', label: t('keys.rotate'), risk: 'high', disabled: !canManageKeys || busyRowId !== '', onSelect: () => handleRotate(k) },
              { id: 'set-active', label: k.active ? t('keys.deactivate') : t('keys.activate'), disabled: !canManageKeys || busyRowId !== '', onSelect: () => handleSetActive(k, !k.active) },
              { id: 'delete', label: t('keys.delete'), risk: 'high', disabled: !canManageKeys || busyRowId !== '', onSelect: () => handleDeleteKey(k) },
            ]}
          />
        )}
      />

      <Pagination page={page} pageSize={50} total={total} totalPages={totalPages} loading={keysQuery.loading} onChange={setPage} />

      {(inspectId && (inspectedKey || keysQuery.data != null)) && (
        <KeyDrawer
          org={org}
          apiKey={inspectedKey}
          inspectId={inspectId}
          canManage={canManageKeys}
          hint={keysHint}
          onClose={() => setInspectId(null)}
          onSaved={next => setOverrides(prev => ({ ...prev, [next.id]: next }))}
        />
      )}
    </div>
  )
}

// Option label: readable slug/name first, short id for disambiguation.
function teamLabel(team: Team): string {
  return `${team.slug || team.name} · ${team.id.slice(0, 8)}`
}

function parsePairs(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const pair of text.split(',')) {
    const idx = pair.indexOf('=')
    if (idx <= 0) continue
    const k = pair.slice(0, idx).trim()
    const v = pair.slice(idx + 1).trim()
    if (k && v) out[k] = v
  }
  return out
}
