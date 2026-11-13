import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  listModels, listAllModels, setModelEnabled, deleteModel, getModel,
  MODEL_TIERS, type ModelEntry,
} from '../../api/models'
import { listPricing, type PricingEntry } from '../../api/pricing'
import { fetchAnalyticsQuery } from '../../api/analytics'
import { presetRange, type AnalyticsResult } from '../../lib/analyticsQuery'
import { useShellScope } from '../../hooks/useGlobalScope'
import { useScopedQuery } from '../../hooks/useScopedQuery'
import { useTableUrlState } from '../../hooks/useTableUrlState'
import { useInspectParam } from '../../hooks/useInspectParam'
import { currentHashQuery, relatedListHref } from '../../lib/inspectUrl'
import { Pagination } from '../../components/Pagination'
import { PageHeader } from '../../components/astra/PageHeader'
import { StateNotice } from '../../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../../components/astra/DataTable'
import { EntityDrawer, type EntityDrawerField } from '../../components/astra/EntityDrawer'
import { RowActions } from '../../components/astra/RowActions'
import { useAction } from '../../components/astra/ActionDialog'
import { formatMoneyCell } from '../../lib/columnFormat'
import type { SortState } from '../../lib/tableSort'
import { ModelFormDrawer } from './ModelFormDrawer'
import { AliasesTab } from './AliasesTab'
import { ChainChips } from './ChainChips'
import { chainTargetsOf, parseModelStats, pickPricing, type ModelUsageStats } from './helpers'

const PAGE_SIZE = 25

// for create/edit (the three self-written dialogs are gone), ≤1 row action +
// the «⋯» menu, typed columns (price in/out per 1M from the pricing API,
// 7-day requests/errors/p95 from the analytics query engine — hidden honestly
// when unavailable), fallback-chain chips, provider/tier/status filters and
// the aliases tab. Routing chains validate against the loaded registry slice
// in the drawer; the server re-checks on save and stays the source of truth.

type StatusFilter = 'all' | 'enabled' | 'disabled'

export function ModelsPage() {
  const { t, i18n } = useTranslation()
  // Shell scope controller: the registry itself is global (no org param on
  // /api/models) — the scope line and the 7-day per-model stats are what the
  // selected organization scopes (and orgName shows a name, not a UUID).
  const gs = useShellScope()

  const { page, setPage, sort, setSort } = useTableUrlState('models')
  const [inspectId, setInspectId] = useInspectParam()
  const [tab, setTab] = useState<'models' | 'aliases'>('models')
  const [notice, setNotice] = useState('')
  const [actionError, setActionError] = useState('')

  // ===== scoped reads =====
  const [filterProvider, setFilterProvider] = useState('')
  const [filterTier, setFilterTier] = useState('')
  const [filterStatus, setFilterStatus] = useState<StatusFilter>('all')

  // Fetchers are memoized — useScopedQuery re-arms its auto-load effect on a
  // fetcher identity change, so an inline closure would loop fetches forever.
  const listFetcher = useCallback(async (signal: AbortSignal) => {
    const resp = await listModels(page, { signal, sort: sort?.key, dir: sort?.dir, pageSize: PAGE_SIZE })
    return {
      data: resp.data ?? [],
      total: resp.pagination?.total ?? resp.data?.length ?? 0,
      totalPages: Math.max(1, resp.pagination?.total_pages ?? 1),
      pageSize: resp.pagination?.page_size ?? PAGE_SIZE,
    }
  }, [page, sort])
  const list = useScopedQuery<{ data: ModelEntry[]; total: number; totalPages: number; pageSize: number }>({
    key: `models|${page}|${sort?.key ?? ''}|${sort?.dir ?? ''}`,
    fetcher: listFetcher,
  })

  // or URL-restored page beyond it steps back to the served last page.
  useEffect(() => {
    if (list.data && page > list.data.totalPages) setPage(list.data.totalPages)
  }, [list.data, page, setPage])

  // Registry index: chain-target validation/autocomplete and chain-chip truth.
  const indexFetcher = useCallback((signal: AbortSignal) => listAllModels({ signal }), [])
  const index = useScopedQuery<ModelEntry[]>({
    key: 'registry-index',
    fetcher: indexFetcher,
  })
  const knownModels = useMemo(() => {
    const map = new Map<string, boolean>()
    for (const m of index.data ?? []) map.set(m.model_name, m.enabled)
    return map
  }, [index.data])

  // Pricing registry (read-only here): price in/out per 1M per provider+model.
  const pricingFetcher = useCallback((signal: AbortSignal) => listPricing({ signal }), [])
  const pricing = useScopedQuery<PricingEntry[]>({
    key: 'pricing',
    fetcher: pricingFetcher,
  })

  // 7-day per-model usage from the analytics query engine. The engine
  // requires an org (org_id is required server-side) — with no org selected
  // the columns stay hidden with a one-line reason instead of zeros.
  const statsFetcher = useCallback((signal: AbortSignal) => {
    const range = presetRange('7d', new Date())
    return fetchAnalyticsQuery({
      org: gs.org,
      from: range.from,
      to: range.to,
      period: '7d',
      metrics: ['requests', 'errors', 'latency_p95'],
      groupBy: ['model'],
      granularity: 'none',
      filter: '',
      top: 100,
      compare: false,
      chart: 'table',
      tz: '',
    }, { signal })
  }, [gs.org])
  const stats = useScopedQuery<AnalyticsResult>({
    key: `stats|${gs.org}`,
    enabled: gs.org !== '',
    fetcher: statsFetcher,
  })
  const statsByModel = useMemo(() => parseModelStats(stats.data), [stats.data])
  const statsUsable = gs.org !== '' && !stats.error && statsByModel !== null

  const rows = useMemo(() => list.data?.data ?? [], [list.data])
  const filtered = useMemo(() => rows.filter(m => {
    if (filterProvider && (m.provider ?? '') !== filterProvider) return false
    if (filterTier && m.tier !== filterTier) return false
    if (filterStatus === 'enabled' && !m.enabled) return false
    if (filterStatus === 'disabled' && m.enabled) return false
    return true
  }), [rows, filterProvider, filterTier, filterStatus])
  const filtersActive = filterProvider !== '' || filterTier !== '' || filterStatus !== 'all'

  const providers = useMemo(
    () => [...new Set(rows.map(m => m.provider).filter((p): p is string => !!p))].sort(),
    [rows],
  )

  // ===== inspector =====
  const inspected = useMemo(
    () => rows.find(m => m.model_name === inspectId) ?? null,
    [rows, inspectId],
  )
  const [inspectedDetail, setInspectedDetail] = useState<ModelEntry | null>(null)
  const [detailError, setDetailError] = useState('')
  const inspectedFull = inspected ? inspectedDetail ?? inspected : null

  useEffect(() => {
    if (!inspected) { setInspectedDetail(null); setDetailError(''); return }
    let alive = true
    setInspectedDetail(null)
    setDetailError('')
    getModel(inspected.model_name)
      .then(full => { if (alive) setInspectedDetail(full) })
      .catch((e: unknown) => {
        if (alive) setDetailError(e instanceof Error ? e.message : String(e))
      })
    return () => { alive = false }
  }, [inspected])

  // ===== mutations =====
  const enableInFlight = useRef<Set<string>>(new Set())
  const [enabling, setEnabling] = useState<Record<string, boolean>>({})

  const enable = async (m: ModelEntry) => {
    if (enableInFlight.current.has(m.model_name)) return
    enableInFlight.current.add(m.model_name)
    setEnabling(prev => ({ ...prev, [m.model_name]: true }))
    setActionError(''); setNotice('')
    try {
      await setModelEnabled(m.model_name, true)
      setNotice(t('models.updated', { name: m.model_name }))
      list.load({ refresh: true })
    } catch (e: unknown) {
      setActionError(t('models.toggleFailed', { action: 'enable', name: m.model_name, message: e instanceof Error ? e.message : String(e) }))
    } finally {
      enableInFlight.current.delete(m.model_name)
      setEnabling(prev => {
        if (!prev[m.model_name]) return prev
        const { [m.model_name]: _drop, ...rest } = prev
        return rest
      })
    }
  }

  const disableAction = useAction({
    id: 'models.disable', risk: 'medium', reversible: true,
    impact: t('models.disableConfirm'),
  })
  const deleteAction = useAction({
    id: 'models.delete', risk: 'high', reversible: false,
    impact: t('models.deleteConfirm'),
  })

  const disable = (m: ModelEntry) => {
    const name = m.model_name
    const fallbackCount = (index.data ?? []).filter(x => x.fallback_model === name).length
    const failoverCount = (index.data ?? []).filter(x => (x.failover_models ?? []).includes(name)).length
    disableAction.run({
      entity: name,
      confirmLabel: t('models.disableAction'),
      impact: (
        <>
          <p>{t('models.disableConfirm')}</p>
          <p className="mt-1 text-xs">{t('models.disableDependsOnIt')}</p>
          <ul className="mt-1 list-disc ps-5 text-xs">
            {fallbackCount > 0 && <li>{t('models.disableDependentsFallback', { count: fallbackCount, name })}</li>}
            {failoverCount > 0 && <li>{t('models.disableDependentsFailover', { count: failoverCount, name })}</li>}
            {fallbackCount === 0 && failoverCount === 0 && <li>{t('models.disableDependentsNone', { name })}</li>}
          </ul>
        </>
      ),
      execute: async () => {
        await setModelEnabled(name, false)
      },
      onDone: () => {
        setNotice(t('models.updated', { name }))
        list.load({ refresh: true })
      },
      onError: msg => setActionError(t('models.toggleFailed', { action: 'disable', name, message: msg })),
    })
  }

  const remove = (m: ModelEntry) => {
    deleteAction.run({
      entity: m.model_name,
      confirmLabel: t('models.delete'),
      execute: async () => {
        await deleteModel(m.model_name)
      },
      onDone: () => {
        setNotice(t('models.deleted', { name: m.model_name }))
        list.load({ refresh: true })
      },
      onError: msg => setActionError(t('models.deleteFailed', { name: m.model_name, message: msg })),
    })
  }

  // ===== form drawer =====
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<ModelEntry | null>(null)

  const openCreate = () => { setEditing(null); setDrawerOpen(true) }
  const openEdit = (m: ModelEntry) => { setEditing(m); setDrawerOpen(true) }
  const onSaved = useCallback((name: string, created: boolean) => {
    setNotice(t(created ? 'models.created' : 'models.updated', { name }))
    if (created && page !== 1) setPage(1)
    else list.load({ refresh: true })
    // list.load re-arms on page changes; a create from a non-first page just
    // jumps to page 1 (the auto-load follows the key change).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, setPage, t])

  // A header click in server mode re-asks the backend; the
  // sort change resets the page to 1 (the view is a new ordering).
  const handleSortChange = (next: SortState | null) => {
    setSort(next)
    setPage(1)
  }

  // ===== columns =====
  const locale = i18n.language
  const statsCols = (): DataTableColumn<ModelEntry>[] => {
    if (!statsUsable) return []
    const value = (m: ModelEntry, pick: (s: ModelUsageStats) => number | null): number | null =>
      statsByModel ? pick(statsByModel.get(m.model_name) ?? { requests: 0, errors: 0, p95_ms: null }) : null
    const fmtNumber = (n: number | null) =>
      n == null ? '—' : new Intl.NumberFormat(locale || 'en').format(n)
    return [
      {
        key: 'stats_requests', header: t('models.statsRequests'),
        sortable: false, align: 'right', mono: true,
        render: m => fmtNumber(value(m, s => s.requests)),
      },
      {
        key: 'stats_errors', header: t('models.statsErrors'),
        sortable: false, align: 'right', mono: true,
        render: m => fmtNumber(value(m, s => s.errors)),
      },
      {
        key: 'stats_p95', header: t('models.statsP95'),
        sortable: false, align: 'right', mono: true,
        render: m => fmtNumber(value(m, s => s.p95_ms)),
      },
    ]
  }

  const columns: DataTableColumn<ModelEntry>[] = [
    {
      key: 'model_name',
      header: t('models.model'),
      type: 'text',
      mono: true,
      render: m => (
        <button
          type="button"
          onClick={e => { e.stopPropagation(); setInspectId(m.model_name) }}
          title={t('drawer.inspectHint')}
          className="inline-flex min-h-[36px] items-center text-start hover:underline"
          style={{ fontFamily: 'var(--astra-font-code)' }}
        >
          {m.model_name}
        </button>
      ),
    },
    { key: 'display_name', header: t('models.displayName'), type: 'text', render: m => m.display_name || '—' },
    { key: 'provider', header: t('models.provider'), type: 'text', mono: true, sortable: false, render: m => m.provider || '—' },
    { key: 'tier', header: t('models.tier'), type: 'text', render: m => m.tier || '—' },
    {
      key: 'price',
      header: t('models.priceInOut'),
      headerHint: t('models.priceHint'),
      sortable: false,
      align: 'right',
      mono: true,
      render: (m) => {
        const p = pickPricing(pricing.data, m.provider, m.model_name)
        if (!p) return <span title={t('models.priceUnmatched')}>—</span>
        const inCell = formatMoneyCell(p.input_per_m, { locale })
        const outCell = formatMoneyCell(p.output_per_m, { locale })
        return (
          <span className="whitespace-nowrap" title={`${p.input_per_m} / ${p.output_per_m} USD / 1M`}>
            {inCell.text} / {outCell.text}
          </span>
        )
      },
    },
    {
      key: 'enabled',
      header: t('models.status'),
      type: 'text',
      getSortValue: m => (m.enabled ? 1 : 0),
      render: m => (m.enabled ? (
        <span className="whitespace-nowrap text-xs" style={{ color: 'var(--astra-success)' }}>
          <span aria-hidden="true">● </span>{t('models.enabled')}
        </span>
      ) : (
        <span className="whitespace-nowrap text-xs text-[color:var(--astra-text-muted)]">
          <span aria-hidden="true">○ </span>{t('models.disabled')}
        </span>
      )),
    },
    ...statsCols(),
    {
      key: 'chain',
      header: t('models.chain'),
      headerHint: t('models.chainHint'),
      sortable: false,
      render: m => {
        const targets = chainTargetsOf(m)
        if (targets.length === 0) return '—'
        return (
          // The chips open the TARGET's inspector — keep the row-click
          // handler from overriding inspectId with this row's model.
          <span onClick={e => e.stopPropagation()}>
            <ChainChips targets={targets} known={knownModels} onInspect={setInspectId} inspectTitle={() => t('drawer.inspectHint')} />
          </span>
        )
      },
    },
  ]

  const listLoading = list.loading && !list.data
  const empty = !listLoading && !list.error && list.data != null && rows.length === 0

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('models.title')}
        purpose={t('models.purpose')}
        appliedScope={gs.org ? (gs.orgName || gs.org) : t('orgSwitcher.allOrgs')}
        primaryAction={{ label: t('models.create'), onClick: openCreate }}
      />

      {/* StateNotice has no success state (honest visual vocabulary): the
          confirmation line is a plain muted note, not a status banner. */}
      {notice && <p className="text-xs text-[color:var(--astra-success)]">{notice}</p>}
      {actionError && <StateNotice state="error" message={actionError} />}

      <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('models.title')}>
        {(['models', 'aliases'] as const).map(id => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm ${
              tab === id
                ? 'border-[color:var(--astra-accent)] bg-[color:var(--astra-selection)] font-semibold text-[color:var(--astra-on-selection)]'
                : 'border-[color:var(--astra-rule-strong)] hover:bg-[color:var(--astra-surface-muted)]'
            }`}
          >
            {id === 'models' ? t('models.tabModels') : t('models.tabAliases')}
          </button>
        ))}
      </div>

      {tab === 'aliases' ? (
        <AliasesTab knownModels={knownModels} />
      ) : (
        <>
          {/* Client filters — the server list endpoint has no provider/tier/
              status params, so filtering is scoped to the loaded page and
              labeled as such (honesty). */}
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1 text-sm">
              <label className="text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="models-filter-provider">
                {t('models.provider')}
              </label>
              <select
                id="models-filter-provider"
                className="control w-44"
                value={filterProvider}
                onChange={e => setFilterProvider(e.target.value)}
              >
                <option value="">{t('models.filterAll')}</option>
                {providers.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1 text-sm">
              <label className="text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="models-filter-tier">
                {t('models.tier')}
              </label>
              <select id="models-filter-tier" className="control w-36" value={filterTier} onChange={e => setFilterTier(e.target.value)}>
                <option value="">{t('models.filterAll')}</option>
                {MODEL_TIERS.map(tier => <option key={tier} value={tier}>{tier}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1 text-sm">
              <label className="text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor="models-filter-status">
                {t('models.status')}
              </label>
              <select
                id="models-filter-status"
                className="control w-36"
                value={filterStatus}
                onChange={e => setFilterStatus(e.target.value as StatusFilter)}
              >
                <option value="all">{t('models.filterAll')}</option>
                <option value="enabled">{t('models.enabled')}</option>
                <option value="disabled">{t('models.disabled')}</option>
              </select>
            </div>
            {filtersActive && (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => { setFilterProvider(''); setFilterTier(''); setFilterStatus('all') }}
              >
                {t('models.filtersReset')}
              </button>
            )}
          </div>
          {filtersActive && (
            <p className="text-xs text-[color:var(--astra-text-muted)]">
              {t('models.filtersActive', { shown: filtered.length, total: rows.length })}
            </p>
          )}

          {!statsUsable && (
            <p className="text-xs text-[color:var(--astra-text-muted)]">
              {gs.org === ''
                ? t('models.statsNoOrg')
                : stats.error
                  ? t('models.statsFailed', { message: stats.error })
                  : stats.loading ? '' : t('models.statsFailed', { message: t('common.unavailable') })}
            </p>
          )}
          {statsUsable && gs.org && (
            <p className="text-xs text-[color:var(--astra-text-muted)]">
              {t('models.statsScope', { org: gs.orgName || gs.org })}
            </p>
          )}

          {/* a failed reload — a rejected server sort
              (400 invalid_sort) among them — keeps the last good rows on
              screen, so the in-card error branch, gated on
              !list.data, would never fire after a first successful load. The
              notice goes above the kept data, like OrgsPage/RulesPage. */}
          {list.error && list.data && <StateNotice state="error" message={list.error} />}

          <div className="card overflow-x-auto">
            {listLoading ? (
              <StateNotice state="loading" message={t('models.fetching')} />
            ) : list.error && !list.data ? (
              <StateNotice
                state="error"
                message={list.error}
                action={{ label: t('common.retry'), onClick: () => list.load() }}
              />
            ) : empty ? (
              <StateNotice state="empty" message={t('models.empty')} />
            ) : (
              <DataTable
                columns={columns}
                rows={filtered}
                getRowId={m => m.model_name}
                page={page}
                pageSize={list.data?.pageSize ?? PAGE_SIZE}
                onPageChange={setPage}
                pagination="external"
                serverTotal={list.data?.total}
                sortMode="server"
                sort={sort}
                onSortChange={handleSortChange}
                caption={t('models.title')}
                onRowClick={m => setInspectId(m.model_name)}
                renderActions={m => (
                  // Row actions must not trigger the row-click inspector.
                  <div className="flex justify-end gap-2" onClick={e => e.stopPropagation()}>
                    <button type="button" onClick={() => openEdit(m)} className="btn-secondary !px-3 !py-1 !text-xs">
                      {t('models.edit')}
                    </button>
                    <RowActions
                      label={t('common.actions')}
                      items={[
                        m.enabled
                          ? { id: 'disable', label: t('models.disable'), risk: 'medium' as const, onSelect: () => disable(m) }
                          : { id: 'enable', label: t('models.enable'), risk: 'low' as const, disabled: enabling[m.model_name] === true, onSelect: () => void enable(m) },
                        { id: 'delete', label: t('models.delete'), risk: 'high' as const, onSelect: () => remove(m) },
                      ]}
                    />
                  </div>
                )}
              />
            )}
            <Pagination
              page={page}
              pageSize={list.data?.pageSize ?? PAGE_SIZE}
              total={list.data?.total ?? 0}
              totalPages={list.data?.totalPages ?? 1}
              loading={list.loading}
              onChange={p => setPage(p)}
            />
          </div>

          <p className="text-xs text-[color:var(--astra-text-muted)]">
            {t('models.impact')}
          </p>
        </>
      )}

      <ModelFormDrawer
        open={drawerOpen}
        editing={editing}
        knownModels={knownModels}
        onClose={() => setDrawerOpen(false)}
        onSaved={onSaved}
      />

      {disableAction.ui}
      {deleteAction.ui}

      {/* the model inspector card. Detail GET first, row as the
          fallback; the key is only ever its status. */}
      {(inspected || (inspectId && list.data && !list.loading)) && (
        <EntityDrawer
          kind={t('models.title')}
          title={inspectedFull ? inspectedFull.model_name : inspectId}
          onClose={() => setInspectId(null)}
          missing={!inspectedFull}
          ids={inspectedFull ? [{ label: t('models.model'), value: inspectedFull.model_name }] : []}
          fields={inspectedFull ? [
            { label: t('models.displayName'), value: inspectedFull.display_name || '—' },
            { label: t('models.tier'), value: inspectedFull.tier || '—' },
            { label: t('models.status'), value: inspectedFull.enabled ? t('models.enabled') : t('models.disabled') },
            { label: t('models.provider'), value: inspectedFull.provider || '—', mono: true },
            { label: t('models.upstreamUrl'), value: inspectedFull.upstream_url || '—', mono: true },
            {
              label: t('models.keyStatus'),
              value: inspectedFull.has_key ? t('models.keySet') : t('models.keyMissing'),
            },
            (() => {
              const p = pickPricing(pricing.data, inspectedFull.provider, inspectedFull.model_name)
              return p ? {
                label: t('models.priceInOut'),
                value: `${formatMoneyCell(p.input_per_m, { locale }).text} / ${formatMoneyCell(p.output_per_m, { locale }).text}`,
                mono: true,
              } : null
            })(),
            { label: t('models.timeout'), value: inspectedFull.upstream_timeout_ms != null ? `${inspectedFull.upstream_timeout_ms} ms` : '—' },
            { label: t('models.fallbackModel'), value: inspectedFull.fallback_model || '—', mono: true },
            {
              label: t('models.chain'),
              value: (() => {
                const targets = chainTargetsOf(inspectedFull)
                if (targets.length === 0) return '—'
                return <ChainChips targets={targets} known={knownModels} />
              })(),
            },
            {
              label: t('models.tierPool'),
              value: (inspectedFull.tier_pool ?? []).length > 0 ? inspectedFull.tier_pool!.join(', ') : '—',
              mono: true,
            },
          ].filter(Boolean) as EntityDrawerField[] : []}
          links={inspectedFull ? [
            { label: t('app.navRequestsExplorer'), href: relatedListHref('requests-explorer', currentHashQuery(), { model: inspectedFull.model_name }) },
            { label: t('app.navRoutingRules'), href: relatedListHref('rules', currentHashQuery()) },
          ] : []}
        >
          {detailError && <StateNotice state="error" message={t('drawer.detailFailed', { message: detailError })} />}
        </EntityDrawer>
      )}
    </div>
  )
}
