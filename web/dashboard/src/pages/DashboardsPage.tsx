import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchLabelKeys, getOrganization } from '../api/client'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { EvidenceLabel } from '../components/astra/EvidenceLabel'
import { FreshnessControl } from '../components/astra/FreshnessControl'
import { BoardPanelCard } from '../components/astra/BoardPanelCard'
import { FilterBar, simpleValues } from '../components/astra/FilterBar'
import { GlobalScopeBar } from '../components/GlobalScopeBar'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { uiLocale } from '../i18n/format'
import { quoteYqlValue, type YqlFieldMeta } from '../lib/queryLang'
import {
  BOARDS, explorerHash, resolveBoard,
} from '../lib/boards'
import type { AnalyticsResult } from '../lib/analyticsQuery'
import { ApiError } from '../api/transport'
import { drillPanelPoint, loadPanels, type PanelPayload } from '../lib/boardPanels'
import { useGlobalScope } from '../lib/globalScope'
import { useAutoRefresh, useAutoRefreshInterval, useDocumentHidden } from '../lib/freshness'
import { listPinnedPanels, pinPanel, unpinPanel } from '../lib/pinnedPanels'

const BOARD_IDS = ['agents', 'ci', 'issues', 'reliability', 'budgets'] as const

// AUX-05: the global board filter is a simple-mode FilterBar over the board
// fields the analytics query endpoint actually accepts. Both are YQL
// label.<key> clauses (the shared server-side ParseYQL whitelist has no bare
// `team` field — the previous `team = …` quick filter was rejected with
// invalid_filter and failed every panel; the team cut is still visible via
// the group-by on the budgets board).
const BOARD_FIELDS: YqlFieldMeta[] = [
  { name: 'label.git.repo', kind: 'text', nullable: true, orderable: false, aliases: [] },
  { name: 'label.issue', kind: 'text', nullable: true, orderable: false, aliases: [] },
]

function readHash(): URLSearchParams {
  return new URLSearchParams(window.location.hash.split('?')[1] ?? '')
}

// Legacy hash params (repo=/issue=) migrate into the global filter so old
// shareable links keep working.
function initialFilter(q: URLSearchParams): string {
  const f = q.get('f')
  if (f !== null) return f
  const clauses: string[] = []
  if (q.get('repo')) clauses.push(`label.git.repo = ${quoteYqlValue(q.get('repo') as string)}`)
  if (q.get('issue')) clauses.push(`label.issue = ${quoteYqlValue(q.get('issue') as string)}`)
  return clauses.join(' and ')
}

export function DashboardsPage() {
  const { t } = useTranslation()
  const initial = readHash()
  const [board, setBoard] = useState(BOARDS[initial.get('board') ?? ''] ? (initial.get('board') as string) : 'agents')
  // AUX-08: org/period/tz come from the GlobalScope store (hash first, then
  // the remembered scope) — the same scope Overview/Requests/Analytics use,
  // so a board reproduces the operator's current cut without re-selection.
  const gs = useGlobalScope()
  const org = gs.org
  // AUX-10: panel totals render through the metric registry — locale-aware
  // values, display units and the per-metric glossary tooltip.
  const { currency } = useOrgPresentation(org || undefined)
  const metricFmt = useMemo(() => ({ locale: uiLocale(), currency }), [currency])
  // AUX-05: the global filter is one YQL string (removable chips in the
  // FilterBar). It ANDs into every panel through resolveBoard: repo → every
  // panel, issue → the issue-scoped panels (pre-existing distribution).
  const [globalFilter, setGlobalFilter] = useState(() => initialFilter(initial))
  const [keys, setKeys] = useState<string[]>([])
  const [template, setTemplate] = useState('')
  const [data, setData] = useState<Map<string, PanelPayload>>(new Map())
  const [loading, setLoading] = useState(false)
  // AUX-07: pins — any visible panel can be pinned to Overview. The list is
  // per-browser localStorage (lib/pinnedPanels); toggling re-reads it so the
  // buttons stay honest after cap/dedup decisions in the lib.
  const [pins, setPins] = useState<string[]>(() => listPinnedPanels())
  const togglePin = (pin: string) => {
    if (pins.includes(pin)) unpinPanel(pin)
    else pinPanel(pin)
    setPins(listPinnedPanels())
  }
  // AUX-23: freshness — clock label of the last successful board load, the
  // honest stale marker when a REFRESH failed entirely, and the operator's
  // auto-refresh interval (localStorage). Dashboards has no modal, so the
  // only pause is the hidden tab.
  const [asOf, setAsOf] = useState<number | null>(null)
  const [refreshStale, setRefreshStale] = useState(false)
  const [autoRefreshMs, setAutoRefreshMs] = useAutoRefreshInterval()
  const tabHidden = useDocumentHidden()
  // The store always carries a concrete window (a preset resolves at
  // write/read time; a custom range is pinned), so panels fetch exactly it.
  const range = useMemo(() => ({ from: gs.from, to: gs.to }), [gs.from, gs.to])
  // AUX-07: the applied scope the SHOWN numbers were fetched with — the
  // per-panel captions describe this, never the live draft (AVR-01).
  const [applied, setApplied] = useState<{ org: string; from: string; to: string; tz: string; filters: Map<string, string> } | null>(null)

  // The simple-mode chips are canonical `label.<key> = value` clauses; read
  // them back so resolveBoard keeps its per-panel distribution rules (the
  // issue-trend panel stays hidden until an issue is selected).
  const boardScope = useMemo(
    () => simpleValues(globalFilter, BOARD_FIELDS.map(f => f.name)),
    [globalFilter],
  )

  const panels = useMemo(
    () => resolveBoard(board, keys, { team: '', repo: boardScope['label.git.repo'] ?? '', issue: boardScope['label.issue'] ?? '' }),
    [board, keys, boardScope],
  )

  useEffect(() => {
    const q = new URLSearchParams()
    q.set('board', board)
    if (org) q.set('org', org)
    if (globalFilter) q.set('f', globalFilter)
    const next = `#dashboards?${q.toString()}`
    if (window.location.hash !== next) history.replaceState(null, '', next)
  }, [board, org, globalFilter])

  useEffect(() => {
    if (!org) return
    const ctrl = new AbortController()
    fetchLabelKeys(org, range.from, range.to, { signal: ctrl.signal }).then(rows => setKeys(rows.map(r => r.key))).catch(() => setKeys([]))
    getOrganization(org, { signal: ctrl.signal }).then(o => setTemplate(o.issue_url_template ?? '')).catch(() => setTemplate(''))
    return () => ctrl.abort()
  }, [org, range.from, range.to])

  // AUX-23: the board loader, shared by the scope effect (replace) and the
  // manual/auto refresh (merge). One generation guard + one AbortController:
  // a newer run aborts and supersedes the older one (asyncScope — no stale
  // completion ever lands, no parallel board loads pile up).
  const dataRef = useRef(data)
  useEffect(() => { dataRef.current = data })
  const boardGen = useRef(0)
  const boardCtrl = useRef<AbortController | null>(null)
  // AUX-23: an in-flight REFRESH must not flash the loading notice over the
  // still-shown panels; a scope change is a real load and may.
  const refreshingRun = useRef(false)

  const runBoard = useCallback(async (mode: 'replace' | 'merge') => {
    if (!org) return
    const g = ++boardGen.current
    boardCtrl.current?.abort()
    const ctrl = new AbortController()
    boardCtrl.current = ctrl
    refreshingRun.current = mode === 'merge'
    // Snapshot for the applied-scope captions: the filters this run fetches.
    const runPanels = panels
    setLoading(true)
    const result = await loadPanels(org, range.from, range.to, gs.tz, runPanels, ctrl.signal)
    if (boardGen.current !== g || ctrl.signal.aborted) return
    // AUX-07: captions follow the window/filter the data was fetched with.
    setApplied({
      org,
      from: range.from,
      to: range.to,
      tz: gs.tz,
      filters: new Map(runPanels.map(p => [p.id, p.query.filter])),
    })
    if (mode === 'replace') {
      // Scope/window/board change: the fresh result replaces the old one as
      // a whole — per-panel errors render their own honest panel states.
      setData(result)
      setAsOf(Date.now())
      setRefreshStale(false)
    } else {
      // AUX-23 refresh: successful panels replace their entries; a failed
      // panel keeps its previous result. Only when EVERY visible panel
      // failed does the refresh admit failure — the last good board stays
      // on screen with the honest stale marker instead of being wiped.
      const merged = new Map(dataRef.current)
      let success = false
      for (const [id, entry] of result) {
        if (!(entry instanceof ApiError)) { merged.set(id, entry); success = true }
      }
      if (success) {
        setData(merged)
        setAsOf(Date.now())
        setRefreshStale(false)
      } else {
        setRefreshStale(true)
      }
    }
    if (boardGen.current === g) setLoading(false)
  }, [org, range.from, range.to, gs.tz, panels])

  useEffect(() => {
    void runBoard('replace')
    return () => boardCtrl.current?.abort()
  }, [runBoard])

  // AUX-23: auto-refresh — the operator's interval (localStorage); paused
  // while the tab is hidden; ticks landing on an in-flight load are skipped
  // inside the hook (no parallel requests).
  useAutoRefresh({
    intervalMs: autoRefreshMs,
    paused: tabHidden,
    active: data.size > 0,
    loading,
    onRefresh: () => { void runBoard('merge') },
  })

  // AUX-23: uniform data-source evidence (raw / rollup / sample) for the
  // shown panels, via the shared EvidenceLabel primitive. The strictest
  // source present wins: any truncated result reads as a sample, any
  // pre-aggregated result as a rollup.
  const visibleResults = panels
    .filter(p => !p.hidden)
    .map(p => data.get(p.id))
    .filter((r): r is AnalyticsResult => r != null && !(r instanceof ApiError))
  const evidenceTier: 'raw' | 'rollup' | 'sample' | null = visibleResults.length === 0
    ? null
    : visibleResults.some(r => r.truncated)
      ? 'sample'
      : visibleResults.some(r => r.source === 'rollup')
        ? 'rollup'
        : 'raw'

  // AUX-07: "Open in Analytics" reproduces the board's cut — the applied
  // window (never the live draft) and the global filter ride along
  // (clause-level merge, no duplicates), the applied tz with them.
  const panelExplorerHref = (panelId: string) => {
    const win = applied ?? { from: range.from, to: range.to, tz: gs.tz }
    return explorerHash(org, win.from, win.to, panels.find(p => p.id === panelId)!, {
      extraFilter: globalFilter,
      tz: win.tz,
    })
  }
  const panelWin = applied ?? { from: range.from, to: range.to, tz: gs.tz }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t('dashboards.title')}
        purpose={t('dashboards.purpose')}
        freshness={
          <FreshnessControl
            asOf={asOf}
            stale={refreshStale}
            loading={loading}
            disabled={!org}
            onRefresh={() => { void runBoard('merge') }}
            intervalMs={autoRefreshMs}
            onIntervalChange={setAutoRefreshMs}
          />
        }
      />
      {/* AUX-07: the active board tab is visibly highlighted (accent surface
          + ink border), not only aria-selected. */}
      <div className="flex flex-wrap gap-2" role="tablist" aria-label={t('dashboards.title')}>
        {BOARD_IDS.map(id => {
          const active = board === id
          return (
            <button key={id} type="button" role="tab" aria-selected={active} onClick={() => setBoard(id)}
              className={`inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border px-3 text-sm ${active
                ? 'border-[color:var(--astra-ink)] bg-[color:var(--astra-accent-surface)] font-medium text-[color:var(--astra-ink)]'
                : 'border-[color:var(--astra-rule-strong)] text-[color:var(--astra-ink)]'}`}>
              {t(BOARDS[id].titleKey)}
            </button>
          )
        })}
      </div>
      {/* AUX-08: the shared GlobalScope controls (org · period · tz) replace
          this page's own org picker and period select. */}
      <div className="card flex flex-wrap items-end gap-3">
        <GlobalScopeBar fields={['org', 'period', 'tz']} />
      </div>
      {/* AUX-05: the global board filter — repo/issue chips (simple mode over
          the server-valid label fields). The bar commits once 400ms after the
          last keystroke, so the panels below refetch exactly once per edit. */}
      <FilterBar
        id="dashboards-filter"
        label={t('analytics.filter')}
        fields={BOARD_FIELDS}
        applied={globalFilter}
        onApply={setGlobalFilter}
        mode="simple"
        debounceMs={400}
        fieldLabels={{ 'label.git.repo': t('dashboards.repo'), 'label.issue': t('dashboards.issue') }}
      />
      {panels.some(p => p.slower && !p.hidden) && <StateNotice state="partial" title={t('dashboards.slower')} />}
      {loading && !refreshingRun.current && <StateNotice state="loading" title={t('dashboards.loading')} />}
      {evidenceTier && (
        <EvidenceLabel
          tier={evidenceTier}
          explanation={t(
            evidenceTier === 'sample'
              ? 'evidence.sourceSample'
              : evidenceTier === 'rollup'
                ? 'evidence.sourceRollup'
                : 'evidence.sourceRaw',
          )}
        />
      )}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {panels.map(panel => {
          const payload = data.get(panel.id)
          if (panel.hidden) {
            return <StateNotice key={panel.id} state="partial" title={t(panel.titleKey)} message={t('dashboards.unavailable', { dim: panel.missing ?? 'invalid_dimension' })} />
          }
          return (
            <BoardPanelCard
              key={panel.id}
              panel={panel}
              result={payload}
              applied={applied ? { from: applied.from, to: applied.to, tz: applied.tz, filter: applied.filters.get(panel.id) ?? '' } : undefined}
              explorerHref={panelExplorerHref(panel.id)}
              metricFmt={metricFmt}
              issueTemplate={template}
              pinned={pins.includes(`${board}/${panel.id}`)}
              onTogglePin={() => togglePin(`${board}/${panel.id}`)}
              onPointClick={drillPanelPoint(panel, payload, org, panelWin)}
            />
          )
        })}
      </div>
    </div>
  )
}
