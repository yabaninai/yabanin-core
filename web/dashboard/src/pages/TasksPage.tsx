import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  type TaskAnalyticsReport,
  type TaskGroupBy,
} from '../api/client'
import { ScopeBar } from '../components/ScopeBar'
import { PageHeader } from '../components/astra/PageHeader'
import { MetricStrip } from '../components/astra/MetricStrip'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { useTablePrefs } from '../hooks/useTablePrefs'
import { TableSettingsMenu } from '../components/astra/TableSettingsMenu'
import { SavedViewsMenu } from '../components/astra/SavedViewsMenu'
import {
  currentHashQuery, deleteSavedView, listSavedViews, parseViewQuery,
  renameSavedView, saveSavedView, type SavedViewRecord,
} from '../lib/savedViews'
import { readTableUrlState } from '../lib/tableUrl'
import { downloadCSV, toCSV } from '../components/astra/csv'
import { drillClause, explorerLink } from '../lib/explorerLink'
import { formatMoney } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { useTaskReport } from './hooks/useTaskReport'

// Tasks screen — CTOR cost per task / session / agent.
//
// The backend (GET /api/analytics/tasks) already groups request_logs by
// task_id / session_id / agent_id into cost / counterfactual / savings /
// cache-hits. This screen renders that report and exports it as CSV — the
// chargeback-ready artifact for "what did this task/PR cost". The pairing that
// makes a PR auditable is documented in docs/agent-governance.md: a
// `Yabanin-Task:` commit trailer (what shipped under the tag) + the `YABANIN_TASK`
// CI env (what the tag spent).
//
// States are derived (empty ≠ not-loaded ≠ stale ≠ error) in the domain
// hook. Auto-load: the scope commits via the ScopeBar debounce and the
// window/group selects refetch immediately (no Load button); the read
// lifecycle itself lives in useScopedQuery.

const PAGE_SIZE = 20

export function TasksPage() {
  const { t } = useTranslation()
  const [scope, setScope] = useState<{ orgId: string; provider: string }>({ orgId: '', provider: '' })
  const [days, setDays] = useState(30)
  const [groupBy, setGroupBy] = useState<TaskGroupBy>('task')
  // The scoped read lifecycle (generation/abort/applied guards, screen
  // states) lives in useScopedQuery via the domain hook; `applied` is frozen
  // at load time, never the live draft.
  const { report, applied, loading, error, state, load } = useTaskReport(scope.orgId, days, groupBy)
  // Sort + page live in the URL (#tasks?tasks__sort=…:…) — a sorted
  // view is a shareable link and survives reload.
  const { page, setPage, sort, setSort } = useTableUrlState('tasks')
  // Per-table personalization (hidden columns + density) and the
  // local saved-views registry, both keyed by the table id in localStorage.
  const prefs = useTablePrefs('tasks')
  const [views, setViews] = useState<SavedViewRecord[]>(() => listSavedViews('tasks'))
  const orgId = scope.orgId
  const { currency } = useOrgPresentation(orgId || undefined)

  // Reset to page 1 whenever the applied group/window changes (a different
  // report has a different row set; the old page may no longer exist). The
  // mount run is a no-op so a URL-restored page survives the initial load.
  const prevScopeKey = useRef(`${orgId}|${days}|${groupBy}`)
  useEffect(() => {
    const key = `${orgId}|${days}|${groupBy}`
    if (prevScopeKey.current === key) return
    prevScopeKey.current = key
    setPage(1)
  }, [orgId, days, groupBy, setPage])

  const groups = report?.groups ?? []

  const appliedSummary = applied
    ? t('tasks.appliedSummary', { org: applied.orgId, days: applied.days, group: t(`tasks.group_${applied.groupBy}`) })
    : ''

  const totalSavings = report
    ? report.groups.reduce((sum, g) => sum + g.savings_usd, 0)
    : 0

  // CSV export: one row per group, chargeback-ready (cost / counterfactual /
  // savings / cache hits / request count) for the applied window + group.
  // Hidden columns stay out of the export — the CSV mirrors exactly
  // what the table renders.
  const exportCsv = () => {
    if (!report || groups.length === 0) return
    const csvColumns: Array<{ key: string; header: string; value: (g: TaskAnalyticsReport['groups'][number]) => string | number }> = [
      { key: 'group', header: t('tasks.colGroup'), value: g => g.group },
      { key: 'request_count', header: t('tasks.colRequests'), value: g => g.request_count },
      { key: 'cost_usd', header: t('tasks.colCost'), value: g => g.cost_usd },
      { key: 'counterfactual_usd', header: t('tasks.colCounterfactual'), value: g => g.counterfactual_usd },
      { key: 'savings_usd', header: t('tasks.colSavings'), value: g => g.savings_usd },
      { key: 'cache_hits', header: t('tasks.colCacheHits'), value: g => g.cache_hits },
    ]
    const hidden = new Set(prefs.hiddenColumnIds)
    const visible = csvColumns.filter(c => !hidden.has(c.key))
    const rows = groups.map(g => visible.map(c => c.value(g)))
    const stamp = applied ? `_${applied.orgId.slice(0, 8)}` : ''
    downloadCSV(`yabanin-tasks-${groupBy}${stamp}.csv`, toCSV(visible.map(c => c.header), rows))
  }

  // Drill-down — the group value opens its requests in the explorer.
  // task/agent map 1:1 onto request-side YQL fields; sessions have no
  // request-side field, so that drill narrows by the applied window alone
  // (honest fallback — a filter is never invented). Muted buckets ("(untagged)")
  // never become clauses (lib/explorerLink.ts). The field follows the APPLIED
  // grouping (the grouping the shown rows were fetched with), not the live
  // selector mid-refetch.
  const drillGroupBy = applied?.groupBy ?? groupBy
  const groupDrillField = drillGroupBy === 'agent' ? 'agent' : drillGroupBy === 'task' ? 'task' : null

  const columns: DataTableColumn<TaskAnalyticsReport['groups'][number]>[] = [
    {
      key: 'group',
      header: t('tasks.colGroup'),
      mono: true,
      render: g => (
        <a
          href={explorerLink({
            org: applied?.orgId || orgId,
            from: applied?.from,
            to: applied?.to,
            yql: groupDrillField ? drillClause(groupDrillField, g.group) ?? undefined : undefined,
          })}
          title={t('analytics.drillHint')}
          className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]"
        >
          {g.group}
        </a>
      ),
    },
    { key: 'request_count', header: t('tasks.colRequests'), align: 'right', type: 'number' },
    { key: 'cost_usd', header: t('tasks.colCost'), align: 'right', type: 'money', unit: currency, render: g => formatMoney(g.cost_usd, currency) },
    { key: 'counterfactual_usd', header: t('tasks.colCounterfactual'), align: 'right', type: 'money', unit: currency, render: g => formatMoney(g.counterfactual_usd, currency) },
    { key: 'savings_usd', header: t('tasks.colSavings'), align: 'right', type: 'money', unit: currency, render: g => formatMoney(g.savings_usd, currency) },
    { key: 'cache_hits', header: t('tasks.colCacheHits'), align: 'right', type: 'number' },
  ]

  // Saved views over the page's URL state. A view snapshot is the
  // hash query at save time; applying restores the table sort/page through
  // the same hook setters (the Tasks scope itself is component state, so it
  // is honestly not part of the snapshot — only what the URL carries).
  const refreshViews = () => setViews(listSavedViews('tasks'))
  const saveView = (name: string) => {
    saveSavedView('tasks', name, currentHashQuery())
    refreshViews()
  }
  const renameView = (id: string, name: string) => {
    renameSavedView('tasks', id, name)
    refreshViews()
  }
  const deleteView = (id: string) => {
    deleteSavedView('tasks', id)
    refreshViews()
  }
  const applyView = (item: { id: string }) => {
    const view = views.find(v => v.id === item.id)
    if (!view) return
    const table = readTableUrlState(parseViewQuery(view.query), 'tasks')
    setPage(table.page)
    setSort(table.sort)
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t('tasks.title')} purpose={t('tasks.purpose')} />

      {/* Org scope only — GET /api/analytics/tasks accepts org_id,
          from/to, group_by and limit (services/admin/handlers/analytics.go);
          there is no provider param, so the provider field is hidden rather
          than rendered as a filter that changes nothing. */}
      <ScopeBar orgId={scope.orgId} provider={scope.provider} loading={loading} onChange={setScope}
        fields={['org']}
        appliedSummary={appliedSummary || undefined} />

      {/* Window + group selector — a change refetches automatically (UX-03). */}
      <div className="card flex flex-wrap gap-4 items-end">
        <div>
          <label className="mb-1 block text-sm font-medium text-[color:var(--astra-ink)]">{t('compare.days')}</label>
          <select value={days} onChange={e => setDays(Number(e.target.value))} className="control sm:w-44">
            {[7, 14, 30, 60, 90].map(d => (
              <option key={d} value={d}>{t('cost.daysOption', { days: d })}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-sm font-medium text-[color:var(--astra-ink)]">{t('tasks.groupBy')}</label>
          <select value={groupBy} onChange={e => setGroupBy(e.target.value as TaskGroupBy)} className="control sm:w-44">
            <option value="task">{t('tasks.group_task')}</option>
            <option value="session">{t('tasks.group_session')}</option>
            <option value="agent">{t('tasks.group_agent')}</option>
          </select>
        </div>
      </div>

      {state === 'error' && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void load() }} />}
      {state === 'not-loaded' && !orgId && <StateNotice state="not-loaded" message={t('tasks.notLoaded')} />}
      {state === 'stale' && <StateNotice state="stale" message={t('tasks.refreshingPrevious')} />}
      {state === 'empty' && <StateNotice state="empty" message={t('tasks.noData')} />}

      {report && (state === 'ready' || state === 'stale') && (
        <>
          {/* KPI strip: total cost + total CTOR savings over the applied scope. */}
          <MetricStrip
            aria-label={t('tasks.title')}
            metrics={[
              {
                label: t('tasks.totalCost'),
                value: formatMoney(report.total_cost_usd, currency),
                unit: currency,
                state: 'ok',
                source: appliedSummary,
              },
              {
                label: t('tasks.totalSavings'),
                value: formatMoney(totalSavings, currency),
                unit: currency,
                state: totalSavings >= 0 ? 'ok' : 'warning',
                source: t('tasks.sourceSavings'),
              },
              {
                label: t('tasks.groupsCount'),
                value: String(groups.length),
                state: 'ok',
                source: t('tasks.sourceGroups', { group: t(`tasks.group_${groupBy}`) }),
              },
            ]}
          />

          {/* Group table + CSV export (chargeback artifact) + table
              personalization (views, columns, density). */}
          <div className="card">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-lg font-semibold">{t('tasks.tableTitle', { group: t(`tasks.group_${groupBy}`) })}</h3>
              <div className="flex flex-wrap items-center gap-2">
                <SavedViewsMenu
                  menuId="tasks-views-menu"
                  views={views.map(v => ({ id: v.id, name: v.name }))}
                  onApply={applyView}
                  onSave={saveView}
                  onRename={renameView}
                  onDelete={deleteView}
                />
                <TableSettingsMenu
                  columns={columns.map(c => ({ key: c.key, header: c.header }))}
                  hiddenColumnIds={prefs.hiddenColumnIds}
                  onHiddenChange={prefs.setHiddenColumnIds}
                  density={prefs.density}
                  onDensityChange={prefs.setDensity}
                  onReset={prefs.reset}
                />
                <button
                  type="button"
                  onClick={exportCsv}
                  className="btn-secondary"
                >
                  {t('common.exportCsv')}
                </button>
              </div>
            </div>
            <DataTable
              columns={columns}
              rows={groups}
              getRowId={g => g.group}
              page={page}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
              sort={sort}
              onSortChange={setSort}
              hiddenColumnIds={prefs.hiddenColumnIds}
              density={prefs.density}
              caption={t('tasks.tableCaption', { group: t(`tasks.group_${groupBy}`) })}
              scopeNote={t('tasks.scopeNote', { group: t(`tasks.group_${groupBy}`), days: applied?.days ?? days })}
            />
          </div>
        </>
      )}
    </div>
  )
}

export default TasksPage
