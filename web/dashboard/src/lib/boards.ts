import {
  serializeAnalyticsHash,
  type AnalyticsParams,
  type ChartKind,
  type Granularity,
} from './analyticsQuery.ts'

export const BUILTIN_DIMS = new Set([
  'model', 'model_requested', 'endpoint', 'team', 'agent', 'task', 'status_class', 'cache',
])

export interface BoardPanelDef {
  id: string
  titleKey: string
  metrics: string[]
  groupBy: string[]
  granularity: Granularity
  filter: string
  top: number
  chart: ChartKind
  requires?: string[]
  note?: 'forecast' | 'pipeline' | 'hygiene'
}

export interface ResolvedPanel {
  id: string
  titleKey: string
  hidden: boolean
  missing?: string
  query: Pick<AnalyticsParams, 'metrics' | 'groupBy' | 'granularity' | 'filter' | 'top' | 'chart'>
  note?: BoardPanelDef['note']
  slower: boolean
}

const AGENTS: BoardPanelDef[] = [
  { id: 'cost-client', titleKey: 'dashboards.panel.costByClient', metrics: ['cost_usd'], groupBy: ['client'], granularity: 'day', filter: '', top: 20, chart: 'line', requires: ['client'] },
  { id: 'tokens-model', titleKey: 'dashboards.panel.tokensByModel', metrics: ['tokens_in', 'tokens_out'], groupBy: ['model'], granularity: 'day', filter: '', top: 20, chart: 'line' },
  { id: 'cache-rates', titleKey: 'dashboards.panel.cacheRates', metrics: ['prompt_cache_ratio', 'cache_hit_rate'], groupBy: [], granularity: 'day', filter: '', top: 20, chart: 'line' },
  { id: 'repos', titleKey: 'dashboards.panel.topRepos', metrics: ['cost_usd'], groupBy: ['repo'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['repo'] },
  { id: 'cost-session', titleKey: 'dashboards.panel.costPerSession', metrics: ['cost_usd', 'sessions'], groupBy: [], granularity: 'day', filter: '', top: 20, chart: 'line' },
  { id: 'request-class', titleKey: 'dashboards.panel.requestClass', metrics: ['requests'], groupBy: ['request_class'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['request_class'] },
]

const CI: BoardPanelDef[] = [
  { id: 'ci-cost', titleKey: 'dashboards.panel.ciCost', metrics: ['cost_usd'], groupBy: [], granularity: 'day', filter: 'label.ci.system is not empty', top: 20, chart: 'line', requires: ['label:ci.system'] },
  { id: 'ci-pipeline', titleKey: 'dashboards.panel.ciPipeline', metrics: ['cost_usd'], groupBy: ['label:ci.pipeline'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['label:ci.pipeline'], note: 'pipeline' },
  { id: 'ci-job', titleKey: 'dashboards.panel.ciJob', metrics: ['cost_usd'], groupBy: ['label:ci.job_name'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['label:ci.job_name'] },
  { id: 'ci-trigger', titleKey: 'dashboards.panel.ciTrigger', metrics: ['cost_usd'], groupBy: ['label:ci.trigger'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['label:ci.trigger'] },
  { id: 'session-outcome', titleKey: 'dashboards.panel.sessionOutcome', metrics: ['requests'], groupBy: ['session_outcome'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['session_outcome'] },
]

const ISSUES: BoardPanelDef[] = [
  { id: 'top-issues', titleKey: 'dashboards.panel.topIssues', metrics: ['cost_usd'], groupBy: ['label:issue'], granularity: 'none', filter: '', top: 50, chart: 'bar', requires: ['label:issue'] },
  { id: 'issue-project', titleKey: 'dashboards.panel.issueProject', metrics: ['cost_usd'], groupBy: ['label:issue.project'], granularity: 'none', filter: '', top: 20, chart: 'bar', requires: ['label:issue.project'] },
  { id: 'hygiene', titleKey: 'dashboards.panel.hygiene', metrics: ['requests'], groupBy: ['label:issue'], granularity: 'none', filter: '', top: 50, chart: 'table', requires: ['label:issue'], note: 'hygiene' },
  { id: 'issue-trend', titleKey: 'dashboards.panel.issueTrend', metrics: ['cost_usd'], groupBy: [], granularity: 'day', filter: '', top: 20, chart: 'line', requires: ['label:issue'] },
]

const RELIABILITY: BoardPanelDef[] = [
  { id: 'error-rate', titleKey: 'dashboards.panel.errorRate', metrics: ['error_rate'], groupBy: ['model', 'endpoint'], granularity: 'none', filter: '', top: 20, chart: 'bar' },
  { id: 'latency', titleKey: 'dashboards.panel.latency', metrics: ['latency_p95', 'ttft_p95'], groupBy: [], granularity: 'day', filter: '', top: 20, chart: 'line' },
  { id: 'retries', titleKey: 'dashboards.panel.retries', metrics: ['retried_requests', 'fallback_requests'], groupBy: [], granularity: 'day', filter: '', top: 20, chart: 'line' },
  { id: 'status', titleKey: 'dashboards.panel.status', metrics: ['requests'], groupBy: ['status_class'], granularity: 'day', filter: '', top: 20, chart: 'stacked_bar' },
]

const BUDGETS: BoardPanelDef[] = [
  { id: 'team-month', titleKey: 'dashboards.panel.teamMonth', metrics: ['cost_usd'], groupBy: ['team'], granularity: 'day', filter: '', top: 20, chart: 'line', note: 'forecast' },
  { id: 'top-agents', titleKey: 'dashboards.panel.topAgents', metrics: ['cost_usd'], groupBy: ['agent'], granularity: 'none', filter: '', top: 20, chart: 'bar' },
]

export const BOARDS: Record<string, { titleKey: string; panels: BoardPanelDef[] }> = {
  agents: { titleKey: 'dashboards.board.agents', panels: AGENTS },
  ci: { titleKey: 'dashboards.board.ci', panels: CI },
  issues: { titleKey: 'dashboards.board.issues', panels: ISSUES },
  reliability: { titleKey: 'dashboards.board.reliability', panels: RELIABILITY },
  budgets: { titleKey: 'dashboards.board.budgets', panels: BUDGETS },
}

function available(dim: string, labelKeys: Set<string>): boolean {
  if (dim.startsWith('label:')) return labelKeys.has(dim.slice('label:'.length))
  return BUILTIN_DIMS.has(dim)
}

function quote(value: string): string {
  if (/^[A-Za-z0-9_.:+/@-]+$/.test(value)) return value
  return `"${value.replace(/"/g, "'")}"`
}

export function resolveBoard(boardId: string, labelKeys: string[], boardFilter: { team: string; repo: string; issue: string }): ResolvedPanel[] {
  const board = BOARDS[boardId]
  if (!board) return []
  const keys = new Set(labelKeys)
  const extra: string[] = []
  if (boardFilter.team) extra.push(`team = ${quote(boardFilter.team)}`)
  if (boardFilter.repo) extra.push(`label.git.repo = ${quote(boardFilter.repo)}`)
  return board.panels.map(panel => {
    let groupBy = [...panel.groupBy]
    if (groupBy[0] === 'client' && !available('client', keys)) groupBy = ['agent']
    if (groupBy.includes('repo') && !available('repo', keys)) {
      groupBy = keys.has('git.repo') ? groupBy.map(g => g === 'repo' ? 'label:git.repo' : g) : groupBy
    }
    const missing = (panel.requires ?? []).find(dim => {
      if (dim === 'client' && groupBy[0] === 'agent') return false
      if (dim === 'repo' && groupBy.includes('label:git.repo')) return false
      return !available(dim, keys)
    })
    let filter = panel.filter
    if (panel.id === 'issue-trend' && boardFilter.issue) {
      filter = `label.issue = ${quote(boardFilter.issue)}`
    }
    if (panel.id === 'issue-trend' && !boardFilter.issue) {
      return { id: panel.id, titleKey: panel.titleKey, hidden: true, missing: 'label:issue', query: { metrics: panel.metrics, groupBy, granularity: panel.granularity, filter, top: panel.top, chart: panel.chart }, note: panel.note, slower: false }
    }
    const parts = [filter, ...extra].filter(Boolean)
    const merged = parts.join(' and ')
    return {
      id: panel.id,
      titleKey: panel.titleKey,
      hidden: Boolean(missing),
      missing,
      query: { metrics: panel.metrics, groupBy, granularity: panel.granularity, filter: merged, top: panel.top, chart: panel.chart },
      note: panel.note,
      slower: merged !== '',
    }
  })
}

// AUX-07: the board's global filter (the simple-mode FilterBar on
// Dashboards) must survive the jump to Analytics — a transition has to
// reproduce the result. Panel filters and the global filter are both flat
// top-level AND lists (canonical `field = value` chips / board clauses), so
// merging is clause-level: trim, drop empties, dedupe exact duplicates (a
// repo chip is already ANDed into every panel by resolveBoard — merging
// must not double it).
export function mergeYqlClauses(...parts: Array<string | undefined>): string {
  const out: string[] = []
  const seen = new Set<string>()
  for (const part of parts) {
    for (const clause of (part ?? '').split(/\s+and\s+/)) {
      const c = clause.trim()
      if (!c || seen.has(c)) continue
      seen.add(c)
      out.push(c)
    }
  }
  return out.join(' and ')
}

export interface ExplorerHashOptions {
  /** The board's global filter — carried so Analytics reproduces the cut. */
  extraFilter?: string
  /** The applied query timezone (a real analytics param on boards). */
  tz?: string
}

export function explorerHash(org: string, from: string, to: string, panel: ResolvedPanel, opts: ExplorerHashOptions = {}): string {
  const params: AnalyticsParams = {
    org, from, to,
    // The explorer link pins the board's exact window (AUX-07 "переход в
    // Analytics воспроизводит результат") — custom, never a drifting preset.
    period: 'custom',
    metrics: panel.query.metrics,
    groupBy: panel.query.groupBy,
    granularity: panel.query.granularity,
    filter: mergeYqlClauses(panel.query.filter, opts.extraFilter),
    top: panel.query.top,
    compare: false,
    chart: panel.query.chart,
    tz: opts.tz ?? '',
  }
  return `#analytics?${serializeAnalyticsHash(params)}`
}

// AUX-06: ready questions on the Analytics explorer. Every question reuses
// the query shape of an existing board panel (or composes the same
// primitives), so the explorer and the dashboards answer with the same
// queries. A question is about WHAT to look at — the explorer owns the
// period, org and filter, so a template never touches them.
export interface AnalyticsQuestion {
  id: string
  titleKey: string
  query: Pick<BoardPanelDef, 'metrics' | 'groupBy' | 'granularity' | 'filter' | 'top' | 'chart'>
}

function panelById(boardId: string, panelId: string): BoardPanelDef {
  const panel = BOARDS[boardId]?.panels.find(p => p.id === panelId)
  if (!panel) throw new Error(`unknown board panel ${boardId}/${panelId}`)
  return panel
}

function question(
  id: string,
  titleKey: string,
  src: BoardPanelDef,
  patch: Partial<Pick<BoardPanelDef, 'metrics' | 'groupBy' | 'granularity' | 'filter' | 'top' | 'chart'>> = {},
): AnalyticsQuestion {
  return {
    id,
    titleKey,
    query: {
      metrics: [...(patch.metrics ?? src.metrics)],
      groupBy: [...(patch.groupBy ?? src.groupBy)],
      granularity: patch.granularity ?? src.granularity,
      filter: patch.filter ?? src.filter,
      top: patch.top ?? src.top,
      chart: patch.chart ?? src.chart,
    },
  }
}

export const ANALYTICS_QUESTIONS: readonly AnalyticsQuestion[] = [
  // "Cost by model, by day" — the tokens-by-model panel shape with the spend
  // metric (cost, not raw tokens).
  question('cost-by-model', 'analytics.question.costByModel',
    panelById('agents', 'tokens-model'), { metrics: ['cost_usd'] }),
  question('error-growth', 'analytics.question.errorGrowth',
    panelById('reliability', 'error-rate')),
  question('cache-efficiency', 'analytics.question.cacheEfficiency',
    panelById('agents', 'cache-rates')),
  // The reliability latency panel is org-wide; the question asks "by model".
  question('latency-p95', 'analytics.question.latencyP95',
    panelById('reliability', 'latency'), { groupBy: ['model'] }),
  // "Priciest keys and agents": a key belongs to a team, an agent is its own
  // dimension — the split shows both.
  question('priciest-keys-agents', 'analytics.question.priciestKeysAgents',
    panelById('budgets', 'top-agents'), { groupBy: ['team', 'agent'] }),
]

export function issueURL(template: string, issue: string): string | null {
  if (!template.includes('{issue}') || !template.startsWith('https://')) return null
  return template.split('{issue}').join(encodeURIComponent(issue))
}

export function monthForecast(spent: number, now: Date): number {
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)
  const end = Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)
  const elapsed = now.getTime() - start
  const span = end - start
  if (elapsed <= 0 || span <= 0) return spent
  return spent * (span / elapsed)
}

export function hygieneShare(rows: Array<Array<string | number | null>>): number | null {
  let none = 0
  let total = 0
  for (const row of rows) {
    const label = String(row[0] ?? '')
    const count = typeof row[1] === 'number' ? row[1] : 0
    total += count
    if (label === '(none)') none += count
  }
  if (total === 0) return null
  return none / total
}

export function pipelineAverage(rows: Array<Array<string | number | null>>): number | null {
  let cost = 0
  let n = 0
  for (const row of rows) {
    if (row[0] === '(other)') continue
    const value = typeof row[1] === 'number' ? row[1] : 0
    cost += value
    n += 1
  }
  if (n === 0) return null
  return cost / n
}
