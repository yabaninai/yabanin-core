import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  deleteAgentBudget, deleteTeamBudget, fetchAnalyticsQuery, fetchCreditBalance,
  fetchLowBalanceOrgs, getAgentBudget, getOrgSpendAlert, listAgentKeys,
  listOrgTeamBudgets, listTeamsByOrg, updateOrgSpendAlert, upsertAgentBudget,
  upsertTeamBudget,
  type AgentBudget, type AgentKey, type CreditBalance, type LowBalanceOrgsResponse,
  type OrgSpendAlertSettings, type TeamSpendSummary,
} from '../api/client'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { BulkActions, BULK_SELECTION_LIMIT } from '../components/astra/BulkActions'
import { downloadCSV, toCSV } from '../components/astra/csv'
import { EvidenceLabel } from '../components/astra/EvidenceLabel'
import { MetricStrip } from '../components/astra/MetricStrip'
import { useAction } from '../components/astra/ActionDialog'
import { usePermissions } from '../hooks/usePermissions'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { formatDateTime, formatMoney, formatNumber } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { isCurrentScope, type AsyncScope } from '../lib/asyncScope'
import { BudgetSettingsSection } from './budgets/BudgetSettingsSection'
import { OrgCapsSection } from './budgets/OrgCapsSection'
import { CapsStatusSection } from './budgets/CapsStatusSection'
import { UnitsSpendSection } from './budgets/UnitsSpendSection'
import {
  analyticsDailyByDim, analyticsDisplayNames, dayKey, forecastAlert, forecastDaily,
  forecastMonthly, type BudgetForecast, type DimDailySeries,
} from '../lib/budgetForecast'
import type { AnalyticsResult } from '../lib/analyticsQuery'

// AUX-15: one control surface over the EXISTING budget and alert APIs.
//
// Honest-data rules this page lives by:
//  - a bar exists only where both spent and limit are measured (team budgets
//    report both; agent keys report only the limit, so the spend side comes
//    from the org analytics time series — without analytics.read it stays "—",
//    never 0);
//  - forecasts are client-side linear-pace estimates over that series and are
//    marked as such (EvidenceLabel "estimate"); any gap renders "—";
//  - sections are gated by the same rights the server enforces (budgets.manage
//    for team budgets, agent_keys.manage for agent budgets; the spend alert
//    and the credits low-balance report are MustBeRoot server-side, so they
//    render for root only);
//  - the spend-alert PATCH overwrites BOTH fields server-side, so every edit
//    sends the full {threshold_usd, webhook_url} pair.

interface TeamRow {
  summary: TeamSpendSummary
  name?: string
  usagePct: number | null
  forecast: BudgetForecast
}

interface AgentRow {
  key: AgentKey
  budgetState: AgentBudget | 'none' | 'error'
  limitUsd: number | null
  spendToday: number | null
  usagePct: number | null
  forecast: BudgetForecast
}

const DAY_MS = 86_400_000

function toIso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function errorOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

function ForecastCell({ forecast, timezone }: { forecast: BudgetForecast; timezone: string | undefined }) {
  const { t } = useTranslation()
  if (forecast.kind === 'unknown') {
    return <span className="text-[color:var(--astra-text-muted)]">—</span>
  }
  if (forecast.kind === 'exceeded') {
    return <span className="font-medium" style={{ color: 'var(--astra-danger)' }}>{t('budgets.forecastExceeded')}</span>
  }
  if (forecast.kind === 'period_ok') {
    return <span className="text-[color:var(--astra-text-muted)]">{t('budgets.forecastNone')}</span>
  }
  return (
    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
      {t('budgets.forecastDate', { date: formatDateTime(forecast.at, timezone) })}
    </span>
  )
}

/** Spent/limit bar; pct === null means not measured — rendered as "—". */
function UsageBar({ pct, ariaLabel }: { pct: number | null; ariaLabel: string }) {
  const { t } = useTranslation()
  if (pct == null || !Number.isFinite(pct)) {
    return (
      <span className="text-[color:var(--astra-text-muted)]" aria-label={ariaLabel}>—</span>
    )
  }
  const clamped = Math.min(100, Math.max(0, pct))
  const color = pct >= 100
    ? 'var(--astra-danger)'
    : pct >= 80
      ? 'var(--astra-warning)'
      : 'var(--astra-info)'
  return (
    <div className="flex min-w-[140px] max-w-[260px] items-center gap-2">
      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        // In-range value; the raw percentage (may exceed 100) stays in the
        // aria-valuetext/visible text — never faked to a capped number.
        aria-valuenow={Math.round(clamped)}
        aria-valuetext={t('budgets.usagePct', { pct: formatNumber(Math.round(pct * 10) / 10) })}
        aria-label={ariaLabel}
        className="h-2 min-w-[72px] flex-1 overflow-hidden rounded-[length:var(--astra-radius-control)]"
        style={{ background: 'var(--astra-surface-muted)' }}
      >
        <div className="h-full" style={{ width: `${clamped}%`, background: color }} />
      </div>
      <span className="whitespace-nowrap text-sm" style={{ fontVariantNumeric: 'tabular-nums' }}>
        {t('budgets.usagePct', { pct: formatNumber(Math.round(pct * 10) / 10) })}
      </span>
    </div>
  )
}

export function BudgetsPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useState('')
  const { currency, timezone } = useOrgPresentation(orgId.trim() || undefined)
  const perms = usePermissions(orgId.trim() || undefined)
  const canBudgets = perms.can('budgets.manage')
  const canAgentKeys = perms.can('agent_keys.manage')
  const canAnalytics = perms.can('analytics.read')
  const isRoot = perms.isRoot

  const [teams, setTeams] = useState<TeamSpendSummary[] | null>(null)
  // AUX-20: per-table bulk selection. The budgets API is write-only for this
  // page's mutations (upsert/delete with per-row dialogs already), and a
  // bulk upsert without per-row values is meaningless — so the honest bulk
  // action here is the CSV export of the selected rows.
  const [selectedTeamIds, setSelectedTeamIds] = useState<string[]>([])
  const [selectedAgentIds, setSelectedAgentIds] = useState<string[]>([])
  const [teamError, setTeamError] = useState('')
  const [teamNames, setTeamNames] = useState<Record<string, string>>({})
  const [teamPace, setTeamPace] = useState<Map<string, DimDailySeries> | null>(null)
  const [agentKeys, setAgentKeys] = useState<AgentKey[] | null>(null)
  const [agentError, setAgentError] = useState('')
  const [agentBudgets, setAgentBudgets] = useState<Record<string, AgentBudget | 'none' | 'error'>>({})
  const [agentNames, setAgentNames] = useState<Record<string, string>>({})
  const [agentSpend, setAgentSpend] = useState<Map<string, DimDailySeries> | null>(null)
  const [paceError, setPaceError] = useState(false)
  const [alert, setAlert] = useState<OrgSpendAlertSettings | null>(null)
  const [alertError, setAlertError] = useState('')
  const [balance, setBalance] = useState<CreditBalance | null>(null)
  const [lowBalance, setLowBalance] = useState<LowBalanceOrgsResponse | null>(null)
  const [creditsError, setCreditsError] = useState('')
  const [lowBalanceError, setLowBalanceError] = useState('')
  const [loading, setLoading] = useState(false)
  // "Now" is pinned per load so bars/forecasts and their labels stay one
  // consistent snapshot (a render-time Date() would drift mid-view).
  const [forecastNow, setForecastNow] = useState(() => new Date())

  // AUX-01: sort + page in the URL, default order = usage percentage desc
  // (the whole point of the center: what burns first sorts first).
  const { page: teamsPage, setPage: setTeamsPage, sort: teamsSort, setSort: setTeamsSort } =
    useTableUrlState('budgets-teams', { defaultSort: { key: 'usage', dir: 'desc' } })
  const { page: agentsPage, setPage: setAgentsPage, sort: agentsSort, setSort: setAgentsSort } =
    useTableUrlState('budgets-agents', { defaultSort: { key: 'usage', dir: 'desc' } })

  // Org-scope epoch (TP-06): a delayed org-A response can never land in org B.
  const orgEpoch = useRef(0)
  const orgRef = useRef('')
  useEffect(() => {
    orgEpoch.current++
    orgRef.current = orgId
  }, [orgId])
  const abortRef = useRef<AbortController | null>(null)

  const load = useCallback(async () => {
    const org = orgId.trim()
    if (!org) return
    // Rights unknown yet (fail-closed): the sections are hidden, so do not
    // fire requests that could only 403. The loader re-runs once /api/me
    // lands (the callback identity changes with the rights snapshot).
    if (perms.loading) return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    const opts = { signal: ctrl.signal }
    const seen: AsyncScope = { org, epoch: orgEpoch.current }
    const live = () => isCurrentScope(seen, { org: orgRef.current, epoch: orgEpoch.current })
    setLoading(true)

    const runs: Array<Promise<void>> = []

    if (canBudgets) {
      runs.push(
        listOrgTeamBudgets(org, opts)
          .then(rows => { if (live()) { setTeams(rows); setTeamError('') } })
          .catch((e: unknown) => { if (live()) { setTeams(null); setTeamError(errorOf(e)) } }),
      )
    } else if (live()) {
      setTeams(null)
      setTeamError('')
    }

    if (canAgentKeys) {
      runs.push(
        listAgentKeys(org, opts)
          .then(async keys => {
            if (!live()) return
            setAgentKeys(keys)
            setAgentError('')
            const budgets = await Promise.all(keys.map(async k => {
              try {
                return [k.id, await getAgentBudget(k.id, opts)] as const
              } catch (e) {
                const status = (e as { status?: number }).status
                return [k.id, status === 404 ? 'none' as const : 'error' as const] as const
              }
            }))
            if (!live()) return
            setAgentBudgets(Object.fromEntries(budgets))
          })
          .catch((e: unknown) => {
            if (!live()) return
            setAgentKeys(null)
            setAgentBudgets({})
            setAgentError(errorOf(e))
          }),
      )
    } else if (live()) {
      setAgentKeys(null)
      setAgentBudgets({})
      setAgentError('')
    }

    // Pace series (analytics.read): team month-to-date, agent last 7 days.
    // Without the analytics right the requests are not even attempted — the
    // forecasts collapse to "—" without a misleading error.
    if ((canBudgets || canAgentKeys) && canAnalytics) {
      const now = new Date()
      const monthStart = toIso(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)))
      const weekAgo = toIso(new Date(now.getTime() - 7 * DAY_MS))
      const nowIso = toIso(now)
      const today = dayKey(now)
      const paceRuns: Array<Promise<void>> = []
      if (canBudgets) {
        paceRuns.push(
          fetchAnalyticsQuery({
            org, from: monthStart, to: nowIso, metrics: ['cost_usd'], groupBy: ['team'],
            granularity: 'day', filter: '', top: 100, compare: false, chart: 'table', tz: 'UTC', period: 'custom',
          }, opts).then((res: AnalyticsResult) => {
            if (!live()) return
            setTeamPace(analyticsDailyByDim(res, 'team', today))
            setTeamNames(prev => ({ ...prev, ...analyticsDisplayNames(res, 'team') }))
          }),
        )
      }
      if (canAgentKeys) {
        paceRuns.push(
          fetchAnalyticsQuery({
            org, from: weekAgo, to: nowIso, metrics: ['cost_usd'], groupBy: ['agent'],
            granularity: 'day', filter: '', top: 100, compare: false, chart: 'table', tz: 'UTC', period: 'custom',
          }, opts).then((res: AnalyticsResult) => {
            if (!live()) return
            setAgentSpend(analyticsDailyByDim(res, 'agent', today))
            setAgentNames(analyticsDisplayNames(res, 'agent'))
          }),
        )
      }
      runs.push(
        Promise.allSettled(paceRuns).then(results => {
          if (!live()) return
          const ok = results.every(r => r.status === 'fulfilled')
          setPaceError(!ok)
          setForecastNow(now)
        }),
      )
    }

    if (isRoot) {
      runs.push(
        getOrgSpendAlert(org, opts)
          .then(a => { if (live()) { setAlert(a); setAlertError('') } })
          .catch((e: unknown) => { if (live()) { setAlert(null); setAlertError(errorOf(e)) } }),
      )
      runs.push(
        fetchCreditBalance(org, opts)
          .then(b => { if (live()) { setBalance(b); setCreditsError('') } })
          .catch((e: unknown) => { if (live()) { setBalance(null); setCreditsError(errorOf(e)) } }),
      )
      runs.push(
        fetchLowBalanceOrgs(-500, 100, opts)
          .then(lb => { if (live()) { setLowBalance(lb); setLowBalanceError('') } })
          .catch((e: unknown) => { if (live()) { setLowBalance(null); setLowBalanceError(errorOf(e)) } }),
      )
      // Root nicety: resolve budgeted teams' display names (root-only list).
      runs.push(
        listTeamsByOrg(org, opts)
          .then(page => {
            if (!live()) return
            const names: Record<string, string> = {}
            for (const team of page) names[team.id] = team.name
            setTeamNames(prev => ({ ...prev, ...names }))
          })
          .catch(() => { /* absence renders the raw team id — still honest */ }),
      )
    } else if (live()) {
      setAlert(null)
      setAlertError('')
      setBalance(null)
      setLowBalance(null)
      setCreditsError('')
      setLowBalanceError('')
    }

    await Promise.allSettled(runs)
    if (live()) setLoading(false)
  }, [orgId, perms.loading, canBudgets, canAgentKeys, canAnalytics, isRoot])

  // UX-03 pattern: debounced auto-load on org change (Enter commits at once).
  useEffect(() => {
    if (!orgId.trim()) return
    const timer = setTimeout(() => { void load() }, 300)
    return () => { clearTimeout(timer); abortRef.current?.abort() }
  }, [load, orgId])

  const todayKey = dayKey(forecastNow)

  const teamRows: TeamRow[] = useMemo(() => {
    if (!teams) return []
    return teams.map(summary => {
      const series = teamPace?.get(summary.team_id) ?? null
      const fullDays = series
        ? [...series.perDay.entries()]
          .filter(([d]) => d !== todayKey)
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(([, v]) => v)
        : []
      return {
        summary,
        name: teamNames[summary.team_id],
        usagePct: summary.monthly_limit_usd > 0
          ? (summary.spend_usd / summary.monthly_limit_usd) * 100
          : null,
        forecast: forecastMonthly(summary.monthly_limit_usd, summary.spend_usd, fullDays, forecastNow),
      }
    })
  }, [teams, teamPace, teamNames, todayKey, forecastNow])

  const agentRows: AgentRow[] = useMemo(() => {
    if (!agentKeys) return []
    return agentKeys.map(k => {
      const state = agentBudgets[k.id] ?? 'none'
      const budget = state === 'none' || state === 'error' ? null : state
      const limitUsd = budget ? budget.daily_limit_cents / 100 : null
      const series = agentSpend?.get(k.id) ?? null
      const spendToday = series ? series.today : null
      const prev = series
        ? [...series.perDay.entries()].filter(([d]) => d !== todayKey).map(([, v]) => v)
        : []
      const prevAvg = prev.length > 0 ? prev.reduce((a, b) => a + b, 0) / prev.length : null
      return {
        key: k,
        budgetState: state,
        limitUsd,
        spendToday,
        usagePct: limitUsd != null && spendToday != null ? (spendToday / limitUsd) * 100 : null,
        forecast: limitUsd != null
          ? forecastDaily(limitUsd, spendToday ?? 0, forecastNow, series ? prevAvg : null)
          : { kind: 'unknown' },
      }
    })
  }, [agentKeys, agentBudgets, agentSpend, todayKey, forecastNow])

  // ----- actions (AUX-12 contract) -----

  const editTeamAction = useAction({ id: 'budgets.team.limit', risk: 'medium', permission: 'budgets.manage', reversible: true })
  const hardToggleAction = useAction({ id: 'budgets.team.hard', risk: 'low', permission: 'budgets.manage', reversible: true })
  const removeTeamAction = useAction({ id: 'budgets.team.remove', risk: 'high', permission: 'budgets.manage', reversible: false })
  const editAgentAction = useAction({ id: 'budgets.agent.limit', risk: 'medium', permission: 'agent_keys.manage', reversible: true })
  const removeAgentAction = useAction({ id: 'budgets.agent.remove', risk: 'high', permission: 'agent_keys.manage', reversible: false })
  const thresholdAction = useAction({ id: 'budgets.alert.threshold', risk: 'medium', permission: 'budgets.manage', reversible: true })
  const webhookAction = useAction({ id: 'budgets.alert.webhook', risk: 'medium', permission: 'budgets.manage', reversible: true })
  const disableAlertAction = useAction({ id: 'budgets.alert.disable', risk: 'low', permission: 'budgets.manage', reversible: true })

  const openEditTeam = useCallback((row: TeamRow) => {
    editTeamAction.run({
      entity: row.name ?? row.summary.team_id,
      confirmLabel: t('budgets.saveLimit'),
      was: `${formatMoney(row.summary.monthly_limit_usd, currency)} · ${row.summary.hard_limit ? t('budgets.hard') : t('budgets.soft')}`,
      input: { label: t('budgets.monthlyLimitInput'), initial: String(row.summary.monthly_limit_usd) },
      impact: <span>{t(row.summary.hard_limit ? 'budgets.impactHard' : 'budgets.impactSoft')}</span>,
      execute: async ({ value }) => {
        const v = Number(value)
        if (!Number.isFinite(v) || v <= 0) throw new Error(t('budgets.invalidLimit'))
        await upsertTeamBudget(row.summary.team_id, v, row.summary.hard_limit)
      },
      onDone: () => void load(),
    })
  }, [currency, editTeamAction, load, t])

  const toggleTeamHard = useCallback((row: TeamRow) => {
    const next = !row.summary.hard_limit
    hardToggleAction.run({
      confirmLabel: t(next ? 'budgets.makeHard' : 'budgets.makeSoft'),
      execute: async () => {
        await upsertTeamBudget(row.summary.team_id, row.summary.monthly_limit_usd, next)
      },
      undo: async () => {
        await upsertTeamBudget(row.summary.team_id, row.summary.monthly_limit_usd, row.summary.hard_limit)
      },
      onDone: () => void load(),
    })
  }, [hardToggleAction, load, t])

  const openRemoveTeam = useCallback((row: TeamRow) => {
    removeTeamAction.run({
      entity: row.name ?? row.summary.team_id,
      confirmLabel: t('budgets.removeBudget'),
      impact: <span>{t('budgets.removeTeamImpact')}</span>,
      execute: async () => { await deleteTeamBudget(row.summary.team_id) },
      onDone: () => void load(),
    })
  }, [removeTeamAction, load, t])

  const openEditAgent = useCallback((row: AgentRow) => {
    const budget = row.budgetState === 'none' || row.budgetState === 'error' ? null : row.budgetState
    editAgentAction.run({
      entity: row.key.name,
      confirmLabel: t('budgets.saveLimit'),
      was: budget
        ? t('budgets.centsPerDay', { cents: formatNumber(budget.daily_limit_cents) })
        : t('budgets.noBudget'),
      input: { label: t('budgets.dailyLimitInput'), initial: budget ? String(budget.daily_limit_cents) : '' },
      impact: <span>{t('budgets.impactAgent')}</span>,
      execute: async ({ value }) => {
        const cents = Number(value)
        if (!Number.isFinite(cents) || cents <= 0 || !Number.isInteger(cents)) {
          throw new Error(t('budgets.invalidCents'))
        }
        await upsertAgentBudget(row.key.id, cents)
      },
      onDone: () => void load(),
    })
  }, [editAgentAction, load, t])

  const openRemoveAgent = useCallback((row: AgentRow) => {
    removeAgentAction.run({
      entity: row.key.name,
      confirmLabel: t('budgets.removeBudget'),
      impact: <span>{t('budgets.removeAgentImpact')}</span>,
      execute: async () => { await deleteAgentBudget(row.key.id) },
      onDone: () => void load(),
    })
  }, [removeAgentAction, load, t])

  const openThreshold = useCallback(() => {
    if (!alert) return
    thresholdAction.run({
      confirmLabel: t('budgets.saveThreshold'),
      was: alert.threshold_usd != null ? formatMoney(alert.threshold_usd, currency) : t('budgets.alertsOff'),
      input: { label: t('budgets.thresholdInput'), initial: alert.threshold_usd != null ? String(alert.threshold_usd) : '' },
      impact: <span>{t('budgets.impactAlert')}</span>,
      execute: async ({ value }) => {
        const v = Number(value)
        if (!Number.isFinite(v) || v <= 0) throw new Error(t('budgets.invalidLimit'))
        await updateOrgSpendAlert(orgId.trim(), { threshold_usd: v, webhook_url: alert.webhook_url })
      },
      onDone: () => void load(),
    })
  }, [alert, currency, orgId, thresholdAction, load, t])

  const openWebhook = useCallback(() => {
    if (!alert) return
    webhookAction.run({
      confirmLabel: t('budgets.saveWebhook'),
      was: alert.webhook_url ?? t('budgets.webhookNone'),
      input: { label: t('budgets.webhookInput'), initial: alert.webhook_url ?? '' },
      impact: <span>{t('budgets.impactWebhook')}</span>,
      execute: async ({ value }) => {
        const v = value.trim()
        if (v !== '' && !/^https?:\/\//.test(v)) throw new Error(t('budgets.invalidWebhook'))
        await updateOrgSpendAlert(orgId.trim(), { threshold_usd: alert.threshold_usd, webhook_url: v === '' ? null : v })
      },
      onDone: () => void load(),
    })
  }, [alert, orgId, webhookAction, load, t])

  const disableAlerts = useCallback(() => {
    if (!alert || alert.threshold_usd == null) return
    const prevThreshold = alert.threshold_usd
    const prevWebhook = alert.webhook_url
    disableAlertAction.run({
      confirmLabel: t('budgets.disableAlerts'),
      execute: async () => {
        await updateOrgSpendAlert(orgId.trim(), { threshold_usd: null, webhook_url: null })
      },
      undo: async () => {
        await updateOrgSpendAlert(orgId.trim(), { threshold_usd: prevThreshold, webhook_url: prevWebhook })
      },
      onDone: () => void load(),
    })
  }, [alert, orgId, disableAlertAction, load, t])

  // ----- columns -----

  const teamColumns: DataTableColumn<TeamRow>[] = [
    {
      key: 'team',
      header: t('budgets.colTeam'),
      type: 'text',
      getSortValue: r => r.name ?? r.summary.team_id,
      render: r => (
        <span className="flex flex-col">
          <span className="font-medium">{r.name ?? r.summary.team_id}</span>
          {r.name && <span className="text-xs text-[color:var(--astra-text-muted)]" style={{ fontFamily: 'var(--astra-font-code)' }}>{r.summary.team_id}</span>}
        </span>
      ),
    },
    {
      key: 'spend',
      header: t('budgets.colSpend'),
      type: 'money',
      unit: 'USD',
      align: 'right',
      render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(r.summary.spend_usd, currency)}</span>,
    },
    {
      key: 'limit',
      header: t('budgets.colLimit'),
      type: 'money',
      unit: 'USD',
      align: 'right',
      render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(r.summary.monthly_limit_usd, currency)}</span>,
    },
    {
      key: 'usage',
      header: t('budgets.colUsage'),
      type: 'number',
      getSortValue: r => r.usagePct,
      render: r => (
        <UsageBar
          pct={r.usagePct}
          ariaLabel={t('budgets.usageAria', {
            pct: r.usagePct == null ? '—' : formatNumber(Math.round(r.usagePct)),
            spent: formatMoney(r.summary.spend_usd, currency),
            limit: formatMoney(r.summary.monthly_limit_usd, currency),
          })}
        />
      ),
    },
    {
      key: 'forecast',
      header: t('budgets.colForecast'),
      type: 'number',
      getSortValue: r => r.forecast.kind === 'date'
        ? r.forecast.at.getTime()
        : r.forecast.kind === 'exceeded' ? Number.MAX_SAFE_INTEGER : null,
      render: r => <ForecastCell forecast={r.forecast} timezone={timezone} />,
    },
    {
      key: 'breach',
      header: t('budgets.colBreach'),
      type: 'text',
      getSortValue: r => (r.summary.hard_limit ? 'hard' : 'soft'),
      render: r => (
        <span
          className="inline-flex items-center whitespace-nowrap rounded-[length:var(--astra-radius-control)] border px-2 py-0.5 text-xs font-medium"
          style={r.summary.hard_limit
            ? { borderColor: 'var(--astra-danger)', color: 'var(--astra-danger)', background: 'var(--astra-danger-surface)' }
            : { borderColor: 'var(--astra-warning)', color: 'var(--astra-warning)', background: 'var(--astra-warning-surface)' }}
        >
          <span className="flex flex-col">
            <span>{r.summary.hard_limit ? t('budgets.hard') : t('budgets.soft')}</span>
            <span className="text-[10px] font-normal">{t(r.summary.hard_limit ? 'budgets.hardBreach' : 'budgets.softBreach')}</span>
          </span>
        </span>
      ),
    },
  ]

  const agentColumns: DataTableColumn<AgentRow>[] = [
    {
      key: 'agent',
      header: t('budgets.colAgent'),
      type: 'text',
      getSortValue: r => agentNames[r.key.id] ?? r.key.name,
      render: r => (
        <span className="flex flex-col">
          <span className="font-medium">{agentNames[r.key.id] ?? r.key.name}</span>
          <span className="text-xs text-[color:var(--astra-text-muted)]" style={{ fontFamily: 'var(--astra-font-code)' }}>{r.key.id}</span>
        </span>
      ),
    },
    {
      key: 'status',
      header: t('budgets.colStatus'),
      type: 'text',
      getSortValue: r => (r.key.active ? 'active' : 'revoked'),
      render: r => (
        <span className="whitespace-nowrap">
          <span aria-hidden="true" style={{ color: r.key.active ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
            {r.key.active ? '●' : '○'}
          </span>{' '}
          {r.key.active ? t('budgets.statusActive') : t('budgets.statusRevoked')}
        </span>
      ),
    },
    {
      key: 'spent_today',
      header: t('budgets.colSpentToday'),
      type: 'money',
      unit: 'USD',
      align: 'right',
      getSortValue: r => r.spendToday,
      render: r => r.spendToday != null
        ? <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(r.spendToday, currency)}</span>
        : <span className="text-[color:var(--astra-text-muted)]" title={t('budgets.spendUnknown')}>—</span>,
    },
    {
      key: 'daily_limit',
      header: t('budgets.colDailyLimit'),
      type: 'money',
      unit: 'USD',
      align: 'right',
      getSortValue: r => r.limitUsd,
      render: r => r.limitUsd != null
        ? <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(r.limitUsd, currency)}</span>
        : <span className="text-[color:var(--astra-text-muted)]" title={t('budgets.limitNotSet')}>—</span>,
    },
    {
      key: 'usage',
      header: t('budgets.colUsage'),
      type: 'number',
      getSortValue: r => r.usagePct,
      render: r => (
        <UsageBar
          pct={r.usagePct}
          ariaLabel={t('budgets.usageAria', {
            pct: r.usagePct == null ? '—' : formatNumber(Math.round(r.usagePct)),
            spent: r.spendToday != null ? formatMoney(r.spendToday, currency) : t('budgets.spendUnknown'),
            limit: r.limitUsd != null ? formatMoney(r.limitUsd, currency) : t('budgets.limitNotSet'),
          })}
        />
      ),
    },
    {
      key: 'forecast',
      header: t('budgets.colForecast'),
      type: 'number',
      getSortValue: r => r.forecast.kind === 'date'
        ? r.forecast.at.getTime()
        : r.forecast.kind === 'exceeded' ? Number.MAX_SAFE_INTEGER : null,
      render: r => <ForecastCell forecast={r.forecast} timezone={timezone} />,
    },
  ]

  const rowBtnCls =
    'rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-1 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50'
  const rowBtnQuietCls =
    'rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-1 text-xs text-[color:var(--astra-text-muted)] hover:text-[color:var(--astra-ink)] disabled:opacity-50'

  // AUX-20: CSV export of the selected rows — client-side over data already
  // on the page (the budgets API has no batch endpoint, and a bulk upsert
  // without per-row values is meaningless). Missing numbers export as empty
  // cells, never as faked zeros.
  const exportSelectedTeamsCsv = (selected: TeamRow[]) => {
    downloadCSV(
      'team-budgets.csv',
      toCSV(
        [t('budgets.colTeam'), 'team_id', t('budgets.colSpend'), t('budgets.colLimit'), t('budgets.colBreach'), t('budgets.colUsage')],
        selected.map(r => [
          r.name ?? r.summary.team_id,
          r.summary.team_id,
          r.summary.spend_usd,
          r.summary.monthly_limit_usd,
          r.summary.hard_limit ? t('budgets.hard') : t('budgets.soft'),
          r.usagePct == null ? '' : Math.round(r.usagePct * 10) / 10,
        ]),
      ),
    )
  }
  const exportSelectedAgentsCsv = (selected: AgentRow[]) => {
    downloadCSV(
      'agent-budgets.csv',
      toCSV(
        [t('budgets.colAgent'), 'agent_id', t('budgets.colStatus'), t('budgets.colSpentToday'), t('budgets.colDailyLimit')],
        selected.map(r => [
          agentNames[r.key.id] ?? r.key.name,
          r.key.id,
          r.key.active ? t('budgets.statusActive') : t('budgets.statusRevoked'),
          r.spendToday ?? '',
          r.limitUsd ?? '',
        ]),
      ),
    )
  }

  const alertPct = alert && alert.threshold_usd != null && alert.threshold_usd > 0
    ? (alert.spend_today / alert.threshold_usd) * 100
    : null
  const alertForecast = useMemo(
    () => (alert ? forecastAlert(alert.threshold_usd ?? 0, alert.spend_today, forecastNow) : null),
    [alert, forecastNow],
  )

  const balanceLow = balance != null && balance.balance_cents < 500
  const balanceCritical = balance != null && balance.balance_cents <= -100
  const orgOnLowList = lowBalance != null && lowBalance.org_ids.includes(orgId.trim())
  const org = orgId.trim()

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('budgets.title')}
        purpose={t('budgets.purpose')}
        appliedScope={org || undefined}
      />

      {/* Every forecast column on this page is a client-side pace estimate. */}
      {(canBudgets || canAgentKeys || isRoot) && (
        <EvidenceLabel tier="estimate" explanation={t('budgets.estimateNote')} />
      )}

      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('budgets.orgId')}</span>
          <OrgSelect
            value={orgId}
            onChange={v => { setOrgId(v); setSelectedTeamIds([]); setSelectedAgentIds([]) }}
            autoSelect
            className="sm:w-72"
            manualAriaLabel={t('budgets.orgUuid')}
          />
        </label>
      </div>

      {!org && <StateNotice state="not-loaded" message={t('budgets.notLoaded')} />}

      {org && perms.loading && <StateNotice state="loading" message={t('budgets.checkingRights')} />}

      {/* Rights resolved, but no section has a usable server-side path. */}
      {org && !perms.loading && !canBudgets && !canAgentKeys && !isRoot && (
        <StateNotice state="empty" message={t('budgets.noAccess')} />
      )}

      {/* Pace series unavailable: forecasts collapse to "—" everywhere, honestly. */}
      {org && !perms.loading && paceError && (canBudgets || canAgentKeys) && (
        <StateNotice state="partial" message={t('budgets.paceUnavailable')} details={t('budgets.spendUnknown')} />
      )}

      {/* ===== Team budgets (budgets.manage) ===== */}
      {org && !perms.loading && canBudgets && (
        <section aria-labelledby="budgets-teams-title" className="flex flex-col gap-3">
          <h2 id="budgets-teams-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('budgets.teamsTitle')}</h2>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.teamsNote')}</p>
          {teamError ? (
            <StateNotice state="error" message={teamError} action={{ label: t('common.retry'), onClick: () => void load() }} />
          ) : (
            <>
            <BulkActions
              rows={teamRows}
              getRowId={r => r.summary.team_id}
              getRowLabel={r => r.name ?? r.summary.team_id}
              selectedIds={selectedTeamIds}
              onSelectionChange={setSelectedTeamIds}
              limit={BULK_SELECTION_LIMIT}
              actions={[{ id: 'budgets.teams.export', label: t('common.exportCsv'), instant: exportSelectedTeamsCsv }]}
            />
            <DataTable
              columns={teamColumns}
              rows={teamRows}
              getRowId={r => r.summary.team_id}
              selection={{
                selectedRowIds: selectedTeamIds,
                onSelectionChange: setSelectedTeamIds,
                limit: BULK_SELECTION_LIMIT,
                rowLabel: r => r.name ?? r.summary.team_id,
              }}
              loading={teams === null && loading}
              empty={t('budgets.teamsEmpty')}
              page={teamsPage}
              pageSize={25}
              onPageChange={setTeamsPage}
              sort={teamsSort}
              onSortChange={setTeamsSort}
              defaultSort={{ key: 'usage', dir: 'desc' }}
              sortMode="client"
              caption={t('budgets.teamsCaption')}
              renderActions={r => (
                <span className="flex flex-wrap gap-1.5">
                  <button type="button" className={rowBtnCls} onClick={() => openEditTeam(r)}>{t('budgets.editLimit')}</button>
                  <button type="button" className={rowBtnCls} onClick={() => toggleTeamHard(r)}>
                    {r.summary.hard_limit ? t('budgets.makeSoft') : t('budgets.makeHard')}
                  </button>
                  <button type="button" className={rowBtnQuietCls} onClick={() => openRemoveTeam(r)}>{t('budgets.removeBudget')}</button>
                </span>
              )}
            />
            </>
          )}
        </section>
      )}

      {/* ===== Agent-key budgets (agent_keys.manage) ===== */}
      {org && !perms.loading && canAgentKeys && (
        <section aria-labelledby="budgets-agents-title" className="flex flex-col gap-3">
          <h2 id="budgets-agents-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('budgets.agentsTitle')}</h2>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.agentsNote')}</p>
          {agentError ? (
            <StateNotice state="error" message={agentError} action={{ label: t('common.retry'), onClick: () => void load() }} />
          ) : (
            <>
            <BulkActions
              rows={agentRows}
              getRowId={r => r.key.id}
              getRowLabel={r => agentNames[r.key.id] ?? r.key.name}
              selectedIds={selectedAgentIds}
              onSelectionChange={setSelectedAgentIds}
              limit={BULK_SELECTION_LIMIT}
              actions={[{ id: 'budgets.agents.export', label: t('common.exportCsv'), instant: exportSelectedAgentsCsv }]}
            />
            <DataTable
              columns={agentColumns}
              rows={agentRows}
              getRowId={r => r.key.id}
              selection={{
                selectedRowIds: selectedAgentIds,
                onSelectionChange: setSelectedAgentIds,
                limit: BULK_SELECTION_LIMIT,
                rowLabel: r => agentNames[r.key.id] ?? r.key.name,
              }}
              loading={agentKeys === null && loading}
              empty={t('budgets.agentsEmpty')}
              page={agentsPage}
              pageSize={25}
              onPageChange={setAgentsPage}
              sort={agentsSort}
              onSortChange={setAgentsSort}
              defaultSort={{ key: 'usage', dir: 'desc' }}
              sortMode="client"
              caption={t('budgets.agentsCaption')}
              renderActions={r => (
                <span className="flex flex-wrap gap-1.5">
                  <button type="button" className={rowBtnCls} onClick={() => openEditAgent(r)}>{t('budgets.editLimit')}</button>
                  {(r.budgetState !== 'none' && r.budgetState !== 'error') && (
                    <button type="button" className={rowBtnQuietCls} onClick={() => openRemoveAgent(r)}>{t('budgets.removeBudget')}</button>
                  )}
                </span>
              )}
            />
            </>
          )}
        </section>
      )}

      {/* ===== Org spend alert + credits low balance (root-only server-side) ===== */}
      {org && !perms.loading && isRoot && (
        <section aria-labelledby="budgets-alerts-title" className="flex flex-col gap-3">
          <h2 id="budgets-alerts-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('budgets.alertsTitle')}</h2>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.alertsNote')}</p>
          {alertError ? (
            <StateNotice state="error" message={alertError} action={{ label: t('common.retry'), onClick: () => void load() }} />
          ) : alert ? (
            <div className="astra-panel flex flex-col gap-3 p-4">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('budgets.thresholdLabel')}: </span>
                  {alert.threshold_usd != null
                    ? <span className="font-medium" style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(alert.threshold_usd, currency)}</span>
                    : <span className="text-[color:var(--astra-text-muted)]">{t('budgets.alertsOff')}</span>}
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('budgets.spentTodayLabel')}: </span>
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(alert.spend_today, currency)}</span>
                </span>
                <span className="min-w-0">
                  <span className="text-[color:var(--astra-text-muted)]">{t('budgets.webhookLabel')}: </span>
                  <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{alert.webhook_url ?? t('budgets.webhookNone')}</span>
                </span>
                <span>
                  <span className="text-[color:var(--astra-text-muted)]">{t('budgets.lastAlertLabel')}: </span>
                  {alert.last_alert_at
                    ? <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(alert.last_alert_at, timezone)}</span>
                    : <span className="text-[color:var(--astra-text-muted)]">—</span>}
                </span>
              </div>
              {alert.threshold_usd != null && (
                <UsageBar
                  pct={alertPct}
                  ariaLabel={t('budgets.usageAria', {
                    pct: alertPct == null ? '—' : formatNumber(Math.round(alertPct)),
                    spent: formatMoney(alert.spend_today, currency),
                    limit: formatMoney(alert.threshold_usd, currency),
                  })}
                />
              )}
              {alertForecast && alert.threshold_usd != null && (
                <p className="text-sm">
                  <span className="text-[color:var(--astra-text-muted)]">{t('budgets.colForecast')}: </span>
                  <ForecastCell forecast={alertForecast} timezone={timezone} />
                </p>
              )}
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn-secondary" onClick={openThreshold}>{t('budgets.editThreshold')}</button>
                <button type="button" className="btn-secondary" onClick={openWebhook}>{t('budgets.setWebhook')}</button>
                {alert.threshold_usd != null && (
                  <button type="button" className="btn-secondary" onClick={disableAlerts}>{t('budgets.disableAlerts')}</button>
                )}
              </div>
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('budgets.alertsLoading')} />
          )}

          <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('budgets.creditsTitle')}</h3>
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.creditsNote')}</p>
          {creditsError ? (
            <StateNotice state="error" message={creditsError} action={{ label: t('common.retry'), onClick: () => void load() }} />
          ) : balance ? (
            <div className="flex flex-col gap-3">
              <MetricStrip
                aria-label={t('budgets.creditsTitle')}
                metrics={[{
                  label: t('budgets.balanceLabel'),
                  value: formatMoney(balance.balance_cents / 100, currency),
                  unit: 'USD',
                  source: t('budgets.balanceSource', { updated: formatDateTime(balance.updated_at, timezone) }),
                  state: balanceCritical ? 'error' : balanceLow ? 'warning' : 'ok',
                }]}
              />
              {balanceCritical && <StateNotice state="error" title={t('budgets.overdraftTitle')} message={t('budgets.overdraftMessage')} />}
              {orgOnLowList
                ? <StateNotice state="warning" title={t('budgets.lowBalanceTitle')} message={t('budgets.lowBalanceMessage')} />
                : !lowBalanceError && <p className="text-sm text-[color:var(--astra-text-muted)]">{t('budgets.lowBalanceOk')}</p>}
              {lowBalanceError && <StateNotice state="partial" message={t('budgets.lowBalanceUnavailable')} details={lowBalanceError} />}
            </div>
          ) : (
            <StateNotice state={loading ? 'loading' : 'not-loaded'} message={t('budgets.balanceLoading')} />
          )}
        </section>
      )}

      {/* ===== Org budget settings: grace floor / reservations mode / output
              cap (NEXT-18f). Root sees everything; a budgets.manage admin
              manages their own org's floor and cap. The reservations-mode
              switch is root-only and stays hidden for org admins. ===== */}
      {org && !perms.loading && (isRoot || canBudgets) && (
        <BudgetSettingsSection org={org} isRoot={isRoot} canBudgets={canBudgets} currency={currency} />
      )}

      {/* ===== Org caps: beta rate limits + hard monthly budget (W-CAPS).
              Root sees everything; a budgets.manage admin manages their own
              org's caps. The gateway enforces them (YABANIN_ORG_CAPS). ===== */}
      {org && !perms.loading && (isRoot || canBudgets) && (
        <OrgCapsSection org={org} isRoot={isRoot} canBudgets={canBudgets} currency={currency} />
      )}

      {/* ===== Caps status: the Policies-workspace verdict (currencies
              slice 3, GET /api/budgets). Read-only status of the caps the
              sections above configure — usd monthly budget, carbon cap,
              credits floor — with unknown rendered as unknown. Root or the
              org's budgets.manage admins (server gate). ===== */}
      {org && !perms.loading && (isRoot || canBudgets) && (
        <CapsStatusSection org={org} />
      )}

      {/* ===== Units & spend rollup (currencies slice 5, GET
              /api/units/spend): one measured line per unit — USD,
              credits, tokens, gCO2e — for the picked window, with coverage
              gaps surfaced as partial data. Root or the org's
              analytics.read members (server gate differs from caps above
              on purpose: spend is an analytics view, not a budget
              verdict). ===== */}
      {org && !perms.loading && (isRoot || canAnalytics) && (
        <UnitsSpendSection org={org} />
      )}

      {editTeamAction.ui}
      {hardToggleAction.ui}
      {removeTeamAction.ui}
      {editAgentAction.ui}
      {removeAgentAction.ui}
      {thresholdAction.ui}
      {webhookAction.ui}
      {disableAlertAction.ui}
    </div>
  )
}
