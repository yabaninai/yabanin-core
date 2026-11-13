import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listRoutingRules, setRoutingRuleEnabled, deleteRoutingRule, type RoutingRule } from '../../api/rules'
import { listModels } from '../../api/models'
import { useGlobalScope } from '../../hooks/useGlobalScope'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { usePermissions } from '../../hooks/usePermissions'
import { useTableUrlState } from '../../hooks/useTableUrlState'
import { useInspectParam } from '../../hooks/useInspectParam'
import { currentHashQuery, relatedListHref } from '../../lib/inspectUrl'
import { Pagination } from '../../components/Pagination'
import { OrgName } from '../../components/astra/OrgName'
import { PageHeader } from '../../components/astra/PageHeader'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { BulkActions, BULK_SELECTION_LIMIT } from '../../components/astra/BulkActions'
import { EntityDrawer } from '../../components/astra/EntityDrawer'
import { RowActions } from '../../components/astra/RowActions'
import { useAction, auditReasonOpts } from '../../components/astra/ActionDialog'
import type { SortState } from '../../lib/tableSort'
import { RuleFormDrawer, type RuleDraftPrefill } from './RuleFormDrawer'

// The rules center: global scope (the shell's OrgSwitcher owns the
// organization; the page has no org select of its own), all reads through
// useScopedQuery, create/edit in one FormDrawer (constructor + expression
// text + the server preview expanded by default), at most one primary
// action per row with Edit/Delete in the «⋯» menu, and a visible one-line
// explanation of the evaluation order. Empty-field behavior lives in
// RuleFormDrawer: an empty field is never red.
//
// The rule CRUD remains root-only server-side: the mutating
// surface is disabled from /api/me, never clicked into a 403.
// A quality-screen draft (?draft_expr=…) pre-fills the create form
// and shows a provenance banner — nothing is saved automatically.

export function RulesPage() {
  const { t } = useTranslation()
  const scope = useGlobalScope()
  const org = scope.org
  const perms = usePermissions(org || undefined)
  const canManageRules = perms.isRoot
  const rulesHint = canManageRules ? undefined : t('perms.requiredRoot')

  // Server sort: page + sort live in the URL; the server owns the
  // row order (server-side rules allowlist) and 400 invalid_sort surfaces as an
  // error notice — never a silent unsorted view.
  const { page, setPage, sort, setSort } = useTableUrlState('rules')
  const [inspectId, setInspectId] = useInspectParam()
  const [models, setModels] = useState<string[]>([])
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([])
  const [actionError, setActionError] = useState('')
  const [notice, setNotice] = useState('')
  // The rule inspector — opened from a match-expression click and
  // from the ?inspect=<rule_id> deep link. The row carries the full record
  // (no per-rule detail endpoint exists).
  // The routing draft from the quality screen pre-fills the create
  // form but is NEVER saved — applying is human-only; the banner explains
  // the provenance until the user edits a field or dismisses it.
  const [draft, setDraft] = useState<RuleDraftPrefill | null>(null)

  // Scoped read: org/page/sort form the applied-scope
  // identity; a change aborts the in-flight load and starts a new one.
  const listFetcher = useCallback(async (signal: AbortSignal) => {
    const resp = await listRoutingRules(org, page, { signal, sort: sort?.key, dir: sort?.dir })
    return {
      rows: resp.data ?? [],
      total: resp.pagination?.total ?? resp.data?.length ?? 0,
      totalPages: Math.max(1, resp.pagination?.total_pages ?? 1),
    }
  }, [org, page, sort])
  const list = useScopedQuery<{ rows: RoutingRule[]; total: number; totalPages: number }>({
    key: `rules|${org}|${page}|${sort?.key ?? ''}|${sort?.dir ?? ''}`,
    enabled: org !== '',
    fetcher: listFetcher,
  })
  const rows = useMemo(() => list.data?.rows ?? [], [list.data])
  const inspectedRule = useMemo(
    () => rows.find(r => r.id === inspectId) ?? null,
    [rows, inspectId],
  )

  // An org switch resets pagination to page 1 (the row set is
  // org-scoped); the scoped key change reloads under the new scope.
  const prevOrgRef = useRef(org)
  useEffect(() => {
    if (prevOrgRef.current === org) return
    prevOrgRef.current = org
    setSelectedRuleIds([])
    if (page !== 1) setPage(1)
  }, [org, page, setPage])

  // Best-effort model registry slice (page 1) for the target autocomplete —
  // never a validator.
  useEffect(() => {
    listModels(1)
      .then(resp => setModels((resp.data ?? []).map(m => m.model_name)))
      .catch(() => setModels([]))
  }, [])

  // On first load, a hash carrying ?draft_expr=…&draft_model=…&
  // draft_from=quality pre-fills the form (via the drawer's prefill) and
  // surfaces the provenance banner. The params are stripped so a reload
  // does not re-apply the draft; nothing is saved.
  useEffect(() => {
    try {
      const hash = window.location.hash
      const q = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '')
      const expr = q.get('draft_expr')
      const model = q.get('draft_model')
      const from = q.get('draft_from')
      const priorityRaw = q.get('draft_priority')
      if (!expr || !model || from !== 'quality') return
      const priority = priorityRaw ? Number(priorityRaw) : NaN
      setDraft({
        match_expr: expr,
        target_model: model,
        priority: Number.isFinite(priority) ? priority : undefined,
      })
      const base = hash.split('?')[0]
      const rest = new URLSearchParams(hash.slice(hash.indexOf('?') + 1))
      for (const k of ['draft_expr', 'draft_model', 'draft_priority', 'draft_from']) rest.delete(k)
      const qs = rest.toString()
      window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${qs ? `${base}?${qs}` : base}`)
    } catch {
      // Non-browser environment (tests) — draft pre-fill is best-effort.
    }
  }, [])

  // Enable/disable is low risk and reversible — no dialog; a toast
  // with a 10s Undo affordance covers the inverse call. Delete stays high
  // risk (dialog with name confirmation + required reason).
  const toggleRuleAction = useAction({ id: 'rules.toggle', risk: 'low', reversible: true })
  const deleteRuleAction = useAction({
    id: 'rules.delete', risk: 'high', reversible: false, impact: t('rules.deleteConfirm'),
  })
  const [busyRuleId, setBusyRuleId] = useState('')

  const refresh = useCallback(() => list.load({ refresh: true }), [list])

  const handleToggleRule = (rule: RoutingRule) => {
    setBusyRuleId(rule.id)
    setActionError('')
    setNotice('')
    toggleRuleAction.run({
      confirmLabel: rule.enabled ? t('rules.disable') : t('rules.enable'),
      execute: async () => {
        await setRoutingRuleEnabled(rule.id, !rule.enabled)
      },
      undo: async () => {
        await setRoutingRuleEnabled(rule.id, rule.enabled)
      },
      onDone: () => { setBusyRuleId(''); refresh() },
      onError: (message) => { setBusyRuleId(''); setActionError(message) },
    })
  }

  const handleDeleteRule = (rule: RoutingRule) => {
    setActionError('')
    setNotice('')
    deleteRuleAction.run({
      entity: rule.match_expr,
      confirmLabel: t('common.delete'),
      reason: {},
      execute: async ({ reason }) => {
        await deleteRoutingRule(rule.id, auditReasonOpts(reason))
      },
      onDone: () => refresh(),
      onError: (message) => setActionError(message),
    })
  }

  // Bulk enable/disable through the existing single-rule endpoint
  // (no batch API). Rule CRUD is root-only server-side, so the bar buttons
  // carry the root gate.
  const bulkRulesAction = useAction({ id: 'rules.bulk', risk: 'medium', reversible: true })

  // ===== form drawer =====
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<RoutingRule | null>(null)
  const openCreate = () => { setEditing(null); setDrawerOpen(true) }
  const openEdit = (rule: RoutingRule) => { setEditing(rule); setDrawerOpen(true) }
  const onSaved = useCallback((created: boolean) => {
    setNotice(t(created ? 'rules.created' : 'rules.saved'))
    if (created && page !== 1) setPage(1)
    else refresh()
  }, [page, setPage, refresh, t])

  // Sort contract: a header click in server mode re-asks the backend; the
  // sort change resets the page to 1 (the view is a new ordering).
  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  const columns: DataTableColumn<RoutingRule>[] = [
    {
      key: 'priority',
      header: t('rules.priorityHeader'),
      type: 'number',
      unit: 'count',
      align: 'right',
      render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.priority}</span>,
    },
    {
      key: 'match_expr',
      header: t('rules.match'),
      type: 'text',
      render: r => (
        // The match expression opens the entity inspector (read-only).
        <button
          type="button"
          onClick={() => setInspectId(r.id)}
          title={t('drawer.inspectHint')}
          className="inline-flex min-h-[36px] items-center text-start break-all font-mono text-xs text-[color:var(--astra-ink)] hover:underline"
        >
          {r.match_expr}
        </button>
      ),
    },
    {
      key: 'target_model',
      header: t('rules.target'),
      type: 'text',
      render: r => <span className="whitespace-nowrap font-mono text-xs text-[color:var(--astra-text-muted)]">{r.target_model}</span>,
    },
    {
      key: 'enabled',
      header: t('rules.enabled'),
      type: 'text',
      getSortValue: r => (r.enabled ? 1 : 0),
      render: r => (
        <span className="whitespace-nowrap text-xs">
          <span aria-hidden="true" style={{ color: r.enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
            {r.enabled ? '●' : '○'}
          </span>{' '}
          {r.enabled ? t('rules.enabled') : t('rules.disabled')}
        </span>
      ),
    },
  ]

  const listLoading = list.loading && !list.data
  const empty = !listLoading && !list.error && list.data != null && rows.length === 0

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('rules.title')}
        purpose={t('rules.purpose')}
        appliedScope={org ? <OrgName orgId={org} /> : undefined}
        primaryAction={{
          label: t('rules.newRule'),
          disabled: !canManageRules,
          onClick: openCreate,
        }}
      />

      {notice && <p className="text-xs" style={{ color: 'var(--astra-success)' }}>{notice}</p>}
      {actionError && <StateNotice state="error" message={actionError} />}
      {/* A failed load (e.g. 400 invalid_sort) is an honest error —
          shown even when stale rows from the previous scope are still on
          screen (the failed load never replaces the last good data). */}
      {list.error && (
        <StateNotice
          state="error"
          message={list.error}
          action={list.data ? undefined : { label: t('common.retry'), onClick: () => list.load() }}
        />
      )}

      {/* ActionDialog surfaces (dialog + undo toast), fixed-position. */}
      {toggleRuleAction.ui}
      {deleteRuleAction.ui}

      {/* A draft pre-filled from the quality screen. It is NOT saved
          — review and adjust in the drawer, then create the rule yourself. */}
      {draft && (
        <StateNotice
          state="stale"
          message={t('rules.draftBanner', { from: draft.match_expr, to: draft.target_model })}
        />
      )}

      {/* Sticky bulk bar + per-row report for the rules table. */}
      <BulkActions
        rows={rows}
        getRowId={r => r.id}
        getRowLabel={r => r.match_expr}
        selectedIds={selectedRuleIds}
        onSelectionChange={setSelectedRuleIds}
        limit={BULK_SELECTION_LIMIT}
        dialog={bulkRulesAction}
        onChanged={() => refresh()}
        actions={[
          {
            id: 'rules.bulk.enable',
            label: t('rules.enable'),
            disabled: !canManageRules || busyRuleId !== '',
            title: rulesHint,
            applyRow: (r, reason) => setRoutingRuleEnabled(r.id, true, auditReasonOpts(reason)),
            revertRow: (r, reason) => setRoutingRuleEnabled(r.id, false, auditReasonOpts(reason)),
          },
          {
            id: 'rules.bulk.disable',
            label: t('rules.disable'),
            disabled: !canManageRules || busyRuleId !== '',
            title: rulesHint,
            applyRow: (r, reason) => setRoutingRuleEnabled(r.id, false, auditReasonOpts(reason)),
            revertRow: (r, reason) => setRoutingRuleEnabled(r.id, true, auditReasonOpts(reason)),
          },
        ]}
      />

      <div className="card overflow-x-auto">
        {!org ? (
          <StateNotice
            state="not-loaded"
            message={perms.isRoot ? t('rules.orgRequired') : t('rules.createOrgFirst')}
          />
        ) : listLoading ? (
          <StateNotice state="loading" message={t('rules.fetching')} />
        ) : list.error && !list.data ? (
          <StateNotice state="error" message={list.error} />
        ) : empty ? (
          <StateNotice state="empty" message={t('rules.empty')} />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            getRowId={r => r.id}
            selection={{
              selectedRowIds: selectedRuleIds,
              onSelectionChange: setSelectedRuleIds,
              limit: BULK_SELECTION_LIMIT,
              rowLabel: r => r.match_expr,
            }}
            page={page}
            pageSize={50}
            onPageChange={setPage}
            pagination="external"
            serverTotal={list.data?.total}
            sortMode="server"
            sort={sort}
            onSortChange={handleSortChange}
            caption={t('rules.title')}
            renderActions={r => (
              // One primary row action (the reversible
              // enable/disable); Edit/Delete live in the «⋯» menu.
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => handleToggleRule(r)}
                  disabled={!canManageRules || busyRuleId !== ''}
                  title={rulesHint}
                  className="btn-secondary !px-3 !py-1 !text-xs"
                >
                  {busyRuleId === r.id ? '…' : r.enabled ? t('rules.disable') : t('rules.enable')}
                </button>
                <RowActions
                  label={t('common.actions')}
                  items={[
                    {
                      id: 'edit',
                      label: t('common.edit'),
                      disabled: !canManageRules || busyRuleId !== '',
                      onSelect: () => openEdit(r),
                    },
                    {
                      id: 'delete',
                      label: t('common.delete'),
                      risk: 'high' as const,
                      disabled: !canManageRules || busyRuleId !== '',
                      onSelect: () => handleDeleteRule(r),
                    },
                  ]}
                />
              </div>
            )}
          />
        )}
        {org && (
          <Pagination
            page={page}
            pageSize={50}
            total={list.data?.total ?? 0}
            totalPages={list.data?.totalPages ?? 1}
            loading={list.loading}
            onChange={p => setPage(p)}
          />
        )}
      </div>

      <RuleFormDrawer
        open={drawerOpen}
        editing={editing}
        prefill={editing ? null : draft}
        orgId={org}
        models={models}
        onClose={() => setDrawerOpen(false)}
        onSaved={onSaved}
        onFieldEdit={() => setDraft(null)}
      />

      {/* The rule inspector card. Fields come from the loaded row
          (the list response carries the full record). */}
      {(inspectedRule || (inspectId && list.data && !list.loading)) && (
        <EntityDrawer
          kind={t('rules.title')}
          title={inspectedRule ? inspectedRule.match_expr : inspectId}
          onClose={() => setInspectId(null)}
          missing={!inspectedRule}
          ids={inspectedRule ? [{ label: t('drawer.id'), value: inspectedRule.id }] : []}
          fields={inspectedRule ? [
            { label: t('rules.matchExpression'), value: inspectedRule.match_expr, mono: true },
            { label: t('rules.targetModel'), value: inspectedRule.target_model, mono: true },
            { label: t('rules.priorityHeader'), value: inspectedRule.priority },
            { label: t('rules.enabled'), value: inspectedRule.enabled ? t('drawer.yes') : t('drawer.no') },
            { label: t('rules.organization'), value: inspectedRule.org_id, mono: true },
          ] : []}
          links={inspectedRule ? [
            { label: t('app.navRequestsExplorer'), href: relatedListHref('requests-explorer', currentHashQuery(), { org: inspectedRule.org_id }) },
            { label: t('app.navModels'), href: relatedListHref('models', currentHashQuery()) },
          ] : []}
        />
      )}
    </div>
  )
}
