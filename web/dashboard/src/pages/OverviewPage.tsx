import { useTranslation } from 'react-i18next'
import { AnalyticsSeriesChart } from '../components/LazyCharts'
import { ChartCard } from '../components/astra/ChartCard'
import { OnboardingCard } from '../components/OnboardingCard'
import { PageHeader } from '../components/astra/PageHeader'
import { SignalInbox } from '../components/astra/SignalInbox'
import { OverviewActions } from '../components/astra/OverviewActions'
import { PinnedPanels } from '../components/astra/PinnedPanels'
import { MetricStrip } from '../components/astra/MetricStrip'
import { ProvenanceNote } from '../components/astra/ProvenanceNote'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import type { PricingMetadata } from '../api/client'
import type { MetricState } from '../components/astra/MetricStrip'
import { catalogNodeRef, collapsedProvenanceRef, parsePricingProvenance } from '../lib/pricingProvenance'
import { parsePricingMetadata, pricingCoverageCopy, resolvePricingCoverage } from '../lib/pricingCoverage'
import { formatMoney, formatNumber, uiLocale } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { useGlobalScope, useShellScope } from '../hooks/useGlobalScope'
import { windowDays } from '../lib/globalScope'
import { drillClause, explorerLink } from '../lib/explorerLink'
import { formatMoneyCell } from '../lib/columnFormat'
import { sortByTime } from '../lib/chartData'
import { useAutoRefresh, useAutoRefreshInterval, useDocumentHidden } from '../lib/freshness'
import { FreshnessControl } from '../components/astra/FreshnessControl'
import { usePermissions } from '../hooks/usePermissions'
import { useOverviewReport } from './hooks/useOverviewReport'
import { useOverviewConsumers } from './hooks/useOverviewConsumers'
import {
  toolBucketRows, type ConsumerRow, type ToolBucketRow,
} from './hooks/overviewConsumers'

// page keeps no local ScopeBar/OrgSelect and no page-local draft. The v2
// checklist (plan §5.4) applied: reads through useScopedQuery, states per
// block, typed table columns, no jargon in the visible copy, permissions by
// /api/me, no horizontal overflow at 1440/1024/390.
//
// Summary first; attention and investigation next; spend and consumers
// share a row on wide screens. Personal panels and setup follow the overview.

// AVR-02 (F02): pricing coverage semantics (savings.go documents that
// decision lives in lib/pricingCoverage —
//  - all-unpriced (share = 1) and UNMEASURED (share = null/absent, or a
//    missing coverage_status) resolve to unknown — a $0 must never be shown
//    as a measured value;
//  - partial (0 < share < 1): numbers stay, but they are labeled as a
//    known-subtotal with the coverage, and the state is warning (not ok);
//  - complete (share = 0, status present) / empty window: normal ok (a real
//    $0.0000 on priced models is valid and shown as such).
interface PricingCoverage {
  state: MetricState
  /** Suffix for the source line, e.g. " · 30% of requests unpriced". */
  note: string
  /** The model names in the unpriced set (may be empty). */
  unpricedModels: string[]
}

function pricingCoverage(pricing: PricingMetadata | undefined, t: (k: string, o?: Record<string, unknown>) => string): PricingCoverage {
  const d = resolvePricingCoverage(pricing)
  const models = parsePricingMetadata(pricing).models
  // provenance label (pinned git URL + date + sha256, ~170 chars of
  // unbreakable tokens) and the unpriced-models list move into the
  // collapsed ProvenanceNote below the strip — they used to ride along here
  // and widened the document to 1517px.
  if (d.state === 'ok') return { state: 'ok', note: '', unpricedModels: models }
  // warning / unknown: the honest coverage wording (pricingExcludes /
  // pricingNoModels / pricingCoverageUnknown) via the shared copy helper.
  return { state: d.state, note: pricingCoverageCopy(d, t, 'overview'), unpricedModels: models }
}

// AUX-08: the applied-scope captions fold the 24h preset (a 1-day window) to
// its preset label — "last 1 days" would be broken copy. Scope lines name the
// ORGANIZATION (v2 checklist #1), never a raw UUID; the provider dimension
// was dropped with the page-local ScopeBar (the shell carries org · period).
function appliedScopeText(
  t: (k: string, o?: Record<string, unknown>) => string,
  orgName: string, days: number,
): string {
  const o = orgName || t('overview.allOrgs')
  return days === 1
    ? t('overview.appliedPreset', { org: o, period: t('analytics.preset.24h') })
    : t('overview.appliedDays', { org: o, days })
}

function sourceScopeText(
  t: (k: string, o?: Record<string, unknown>) => string,
  orgName: string, days: number,
): string {
  const o = orgName || t('overview.allOrgs')
  return days === 1
    ? t('overview.sourcePreset', { org: o, period: t('analytics.preset.24h') })
    : t('overview.sourceDays', { org: o, days })
}

// Top consumers — who spends the applied budget: teams (the group that owns
// API keys) and agent keys, one merged spend-descended table. Independent
// read: own states, own permissions (analytics.read to load, requests.read
// for the row drill). No right → the block stays hidden (no 403 noise).
function ConsumersPanel({ org, from, to, currency }: { org: string; from: string; to: string; currency: string }) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  const canAnalytics = perms.can('analytics.read')
  const canRequests = perms.can('requests.read')
  const { board, loading, refreshStale, error, load } = useOverviewConsumers(org, from, to, org !== '' && canAnalytics)

  if (!perms.loading && !canAnalytics) return null

  const columns: DataTableColumn<ConsumerRow>[] = [
    {
      key: 'name',
      header: t('overview.consumer'),
      // ≤1 primary action per row (v2 #4): the drill link on the consumer
      // name. Only agent rows drill — the explorer's YQL has an `agent`
      // field, no `team` field; muted buckets never invent a filter.
      render: r => {
        const label = r.name || t('overview.unattributed')
        if (!r.drillable || !canRequests) return label
        return (
          <a
            href={explorerLink({ org, from, to, yql: drillClause('agent', r.id) ?? undefined })}
            title={t('analytics.drillHint')}
            className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]"
          >
            {label}
          </a>
        )
      },
      getSortValue: r => r.name || r.id,
    },
    {
      key: 'kind',
      header: t('overview.consumerType'),
      sortable: false,
      render: r => (r.kind === 'team' ? t('analytics.dim.team') : t('analytics.dim.agent')),
    },
    {
      key: 'costUsd',
      header: t('analytics.metric.cost_usd'),
      format: 'money',
      formatOptions: { currency },
      getSortValue: r => r.costUsd,
    },
    {
      key: 'requests',
      header: t('analytics.metric.requests'),
      format: 'number',
      getSortValue: r => r.requests,
    },
  ]

  return (
    <section className="card" data-testid="overview-consumers" aria-label={t('overview.consumersTitle')}>
      <div className="mb-2 flex min-w-0 flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('overview.consumersTitle')}</h2>
      </div>
      <p className="mb-3 text-xs text-[color:var(--astra-text-muted)]">{t('overview.consumersAbout')}</p>

      {perms.loading ? (
        <StateNotice state="loading" />
      ) : org === '' ? (
        <StateNotice state="empty" message={t('overview.consumersNeedOrg')} />
      ) : error ? (
        <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void load() }} />
      ) : loading ? (
        <StateNotice state="loading" />
      ) : !board || board.rows.length === 0 ? (
        <StateNotice state="empty" message={t('overview.consumersEmpty')} />
      ) : (
        <>
          {(refreshStale || board.failures > 0) && (
            <StateNotice
              state={refreshStale ? 'stale' : 'partial'}
              message={refreshStale ? undefined : t('overview.consumersPartial')}
            />
          )}
          <DataTable
            columns={columns}
            rows={board.rows}
            getRowId={r => `${r.kind}:${r.id}`}
            caption={t('overview.consumersTitle')}
            page={1}
            pageSize={board.rows.length}
            onPageChange={() => {}}
            pagination="external"
            defaultSort={{ key: 'costUsd', dir: 'desc' }}
          />
        </>
      )}
    </section>
  )
}

// Tool buckets (a2a / mcp) — gateway tool calls logged as model_used
// «a2a:<target>» / «mcp:<server>:<tool>» (D-19: they are neither models nor
// consumers). Rendered only when such traffic exists in the applied window.
function ToolBucketsPanel({ rows, org, from, to, currency }: {
  rows: ToolBucketRow[]; org: string; from: string; to: string; currency: string
}) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  const canRequests = perms.can('requests.read')
  if (rows.length === 0) return null
  const columns: DataTableColumn<ToolBucketRow>[] = [
    {
      key: 'tool',
      header: t('overview.tool'),
      format: 'code',
      render: r => {
        if (!canRequests) return r.tool
        return (
          <a
            href={explorerLink({ org, from, to, yql: drillClause('model', r.tool) ?? undefined })}
            title={t('analytics.drillHint')}
            className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]"
          >
            {r.tool}
          </a>
        )
      },
    },
    {
      key: 'requests',
      header: t('analytics.metric.requests'),
      format: 'number',
      getSortValue: r => r.requests,
    },
    {
      key: 'costUsd',
      header: t('analytics.metric.cost_usd'),
      format: 'money',
      formatOptions: { currency },
      getSortValue: r => r.costUsd,
    },
  ]
  return (
    <section className="card" data-testid="overview-tools" aria-label={t('overview.toolsTitle')}>
      <h2 className="mb-1 text-base font-semibold text-[color:var(--astra-ink)]">{t('overview.toolsTitle')}</h2>
      <p className="mb-3 text-xs text-[color:var(--astra-text-muted)]">{t('overview.toolsAbout')}</p>
      <DataTable
        columns={columns}
        rows={rows}
        getRowId={r => r.tool}
        caption={t('overview.toolsTitle')}
        page={1}
        pageSize={rows.length}
        onPageChange={() => {}}
        pagination="external"
        defaultSort={{ key: 'costUsd', dir: 'desc' }}
      />
    </section>
  )
}

export function OverviewPage() {
  const { t } = useTranslation()
  // same vocabulary and store Requests, Analytics and Dashboards read, so
  // "30 days here" is "30 days everywhere" and a topbar pick re-scopes this
  // page live (no page-local draft any more).
  const gs = useGlobalScope()
  const shell = useShellScope()
  const days = windowDays(gs.period, gs.from, gs.to)
  // AF-17: the scoped read lifecycle (generation/abort/applied guards) plus
  // the AUX-23 freshness semantics (asOf clock, honest refresh-stale marker,
  // keep-data refreshes) live in useScopedQuery via the domain hook.
  // AVR-01 (F01): appliedOrg/loadedDays are frozen at load time — captions
  // must describe the applied scope, not the live topbar value.
  const {
    data, appliedOrg, loadedDays, loading, refreshStale,
    error, asOf, state, load: handleLoad, refresh,
  } = useOverviewReport(gs.org, days)
  const { currency, timezone } = useOrgPresentation(appliedOrg || undefined)
  const [autoRefreshMs, setAutoRefreshMs] = useAutoRefreshInterval()
  const tabHidden = useDocumentHidden()

  // AUX-23: auto-refresh — the operator's interval (localStorage); paused
  // while the tab is hidden; ticks landing on an in-flight load are skipped
  // inside the hook (no parallel requests).
  useAutoRefresh({
    intervalMs: autoRefreshMs,
    paused: tabHidden,
    active: data != null,
    loading,
    onRefresh: refresh,
  })

  // v2 checklist #1: the captions show the organization NAME, not a UUID.
  // Resolved against the shell's option pool (root: the directory; member:
  // /api/me memberships) — no extra request, the lists are session-cached.
  const orgDisplayName = (id: string): string =>
    id === '' ? '' : (shell.options.find(o => o.id === id)?.name ?? id)
  const appliedOrgName = orgDisplayName(appliedOrg)

  // AUX-09: the drill links carry the APPLIED scope (the org + window the
  // shown numbers were computed over), never the live topbar value.
  const drillOrg = appliedOrg
  const drillWindow = { from: gs.from, to: gs.to }

  // daily buckets newest-first — the chart (and its data table) feed through
  // the chartData helper so the timeline always runs forward.
  const dailyCostData = sortByTime(
    data?.daily_breakdown?.map(d => ({
      date: d.date,
      cost_usd: d.actual_cost_usd,
    })) ?? [],
    d => d.date,
  )

  // D-19: tool calls (a2a / mcp) split out of the model board — the savings
  // payload is the source, no extra request.
  const toolRows = toolBucketRows(data?.top_models_by_cost)

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('overview.title')}
        purpose={t('overview.purpose')}
        appliedScope={
          data && (state === 'ready' || state === 'stale')
            ? appliedScopeText(t, appliedOrgName, loadedDays)
            : t('overview.appliedScopeEmpty')
        }
        freshness={
          <FreshnessControl
            asOf={asOf}
            stale={refreshStale}
            loading={loading}
            onRefresh={refresh}
            intervalMs={autoRefreshMs}
            onIntervalChange={setAutoRefreshMs}
          />
        }
      />

      {gs.period === 'custom' && (
        <StateNotice state="warning" message={t('overview.rollingWindowNote', { days: loadedDays })} />
      )}

      {/* U04: states — exact notice per state, no blurred fallbacks. */}
      {state === 'error' && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void handleLoad() }} />}
      {state === 'not-loaded' && <StateNotice state="not-loaded" message={t('overview.pressLoad')} />}
      {state === 'loading' && <StateNotice state="loading" message={t('overview.fetchingAnalytics')} />}
      {state === 'stale' && <StateNotice state="stale" message={t('overview.refreshingPrevious')} />}
      {state === 'empty' && <StateNotice state="empty" message={t('overview.noTraffic')} />}

      {data && (state === 'ready' || state === 'stale') && (
        <>
          {/* KPI strip. AVR-02 (F02): cost/savings respect pricing coverage —
              unknown is never rendered as $0.0000 (see pricingCoverage). */}
          {(() => {
            const pc = pricingCoverage(data.pricing, t)
            const allUnpriced = pc.state === 'unknown'
            // label inside the disclosure. Absent metadata renders nothing.
            // CORE-REF-04: the collapsed node prefers the structured catalog
            // citation when the payload carries it, rendering
            // `catalog:<version> digest:<prefix>`; legacy labels collapse to
            // their 7-char ref via the parser.
            const prov = data.pricing?.pricing_as_of
              ? parsePricingProvenance(data.pricing.pricing_as_of)
              : null
            const shortRef = data.pricing?.pricing_catalog
              ? catalogNodeRef(data.pricing.pricing_catalog)
              : prov
                ? collapsedProvenanceRef(prov)
                : undefined
            const fmtUsd = (v: number | null | undefined) =>
              v != null ? formatMoney(v, currency) : t('common.unknown')
            const costState: MetricState = allUnpriced
              ? 'unknown'
              : pc.state === 'warning'
                ? 'warning'
                : 'ok'
            return (
              <>
                <MetricStrip
                aria-label={t('overview.title')}
                metrics={[
                  {
                    label: t('overview.totalRequests'),
                    value: data.total_requests != null ? formatNumber(data.total_requests) : '—',
                    unit: 'count',
                    source: sourceScopeText(t, appliedOrgName, loadedDays),
                  },
                  {
                    label: t('overview.estimatedUsageCost'),
                    value: allUnpriced ? t('common.unknown') : fmtUsd(data.actual_cost_usd),
                    unit: allUnpriced ? undefined : 'USD',
                    state: costState,
                    source: allUnpriced
                      ? t('overview.sourceUnpriced')
                      : t('overview.sourceNoSavings', { cost: fmtUsd(data.counterfactual_cost_usd) }),
                    coverage: pc.note || undefined,
                  },
                  {
                    label: t('overview.estimatedSavings'),
                    value: allUnpriced
                      ? t('common.unknown')
                      : data.combined_savings_pct != null
                        ? `${data.combined_savings_pct.toFixed(1)}%`
                        : t('common.unknown'),
                    state: allUnpriced
                      ? 'unknown'
                      : data.combined_savings_pct != null && data.combined_savings_pct < 0
                        ? 'warning' // negative savings = optimizations cost money — never green
                        : pc.state === 'warning' && data.combined_savings_pct != null
                          ? 'warning'
                          : pc.state,
                    source: allUnpriced
                      ? t('overview.sourceSavingsUnpriced')
                      : t('overview.sourceSavingsBreakdown', {
                          cache: data.cache_savings_pct?.toFixed(1) ?? '—',
                          routing: data.routing_savings_pct?.toFixed(1) ?? '—',
                        }),
                    coverage: pc.note || undefined,
                  },
                  {
                    label: t('overview.cacheHits'),
                    value: data.cache_hits != null ? formatNumber(data.cache_hits) : t('common.unknown'),
                    source: t('overview.sourceCacheQuality'),
                  },
                ]}
                />
                {prov && (
                  // collapsed provenance node + date, the full label and the
                  // unpriced-models list inside the disclosure.
                  <ProvenanceNote shortRef={shortRef} date={prov.date} raw={prov.raw}>
                    {pc.unpricedModels.length > 0 && (
                      <p className="mt-1">{t('provenance.unpricedModels', { models: pc.unpricedModels.join(', ') })}</p>
                    )}
                  </ProvenanceNote>
                )}
              </>
            )
          })()}

        </>
      )}

      <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <SignalInbox key={`${gs.org}:${gs.from}:${gs.to}`} orgId={gs.org} from={gs.from} to={gs.to} />
        <OverviewActions org={gs.org} from={gs.from} to={gs.to} />
      </div>

      <div className="grid min-w-0 items-start gap-4 xl:grid-cols-2">
        {data && (state === 'ready' || state === 'stale') && (
          <div className="min-w-0">
          {dailyCostData.length > 0 ? (
            <div className="card">
              <ChartCard title={t('overview.dailyCostTrendTitle')} unit="USD" timezone={timezone} filename="overview-daily-cost"
                data={dailyCostData}
                columns={[
                  { key: 'date', label: t('overview.dateUtc'), format: r => r.date },
                  {
                    key: 'cost_usd',
                    label: t('overview.costUsd'),
                    align: 'right',
                    format: r => formatMoneyCell(r.cost_usd, { locale: uiLocale(), currency }).text,
                  },
                ]}>
                <AnalyticsSeriesChart
                  data={dailyCostData}
                  xKey="date"
                  series={[{ key: 'cost_usd', name: t('analytics.metric.cost_usd') }]}
                  kind="bar"
                  legend={false}
                  timezone={timezone}
                  valueFormatter={(_key, v) => formatMoney(v, currency)}
                />
              </ChartCard>
            </div>
          ) : (
            <StateNotice state="empty" title={t('overview.dailyCostTrendTitle')} message={t('overview.noDailyData')} />
          )}
          </div>
        )}
        <ConsumersPanel org={gs.org} from={gs.from} to={gs.to} currency={currency} />
      </div>

      {data && (state === 'ready' || state === 'stale') && (
        <ToolBucketsPanel rows={toolRows} org={drillOrg} from={drillWindow.from} to={drillWindow.to} currency={currency} />
      )}

      <PinnedPanels org={gs.org} from={gs.from} to={gs.to} tz={gs.tz} />
      <OnboardingCard orgId={appliedOrg} requestCount={data?.total_requests ?? null} />
    </div>
  )
}
