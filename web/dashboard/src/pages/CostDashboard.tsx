import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BarChart, LineChart } from '../components/LazyCharts'
import { ScopeBar } from '../components/ScopeBar'
import { ChartCard } from '../components/astra/ChartCard'
import { PageHeader } from '../components/astra/PageHeader'
import { MetricStrip } from '../components/astra/MetricStrip'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { drillClause, explorerLink } from '../lib/explorerLink'
import { pricingCoverageCopy, resolvePricingCoverage } from '../lib/pricingCoverage'
import { sortByTime } from '../lib/chartData'
import { formatMoney } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import type { MetricState } from '../components/astra/MetricStrip'
import { useCostReport, type CostReport } from './hooks/useCostReport'

// PO-05c / AVR-02 (F02) on the Cost screen: incomplete pricing coverage must
// share ≠ 0 semantics) lives in lib/pricingCoverage — an unmeasured share
// (JSON null) or a missing coverage_status resolves to 'unknown' too, not to
// the ok branch. Mirrors OverviewPage.pricingCoverage — the cost endpoint
// (GetCostAnalytics) returns the same pricing metadata.
type CostPricingCoverage =
  | { state: 'ok'; note?: string }
  | { state: 'warning'; note: string }
  | { state: 'unknown'; note: string }

function costPricingCoverage(
  pricing: CostReport['pricing'],
  t: (k: string, o?: Record<string, unknown>) => string,
): CostPricingCoverage {
  const d = resolvePricingCoverage(pricing)
  if (d.state === 'ok') return { state: 'ok', note: '' }
  const models = pricing?.unpriced_models ?? []
  const modelsSuffix = models.length ? ` (${models.join(', ')})` : ''
  const asOf = pricing?.pricing_as_of ? ` · ${t('cost.pricesAsOf', { date: pricing.pricing_as_of })}` : ''
  if (d.state === 'warning') {
    return { state: 'warning', note: `${t('cost.pricingExcludes', { pct: d.pct })}${asOf}${modelsSuffix}` }
  }
  return { state: 'unknown', note: `${pricingCoverageCopy(d, t, 'cost')}${asOf}${modelsSuffix}` }
}

export default function CostDashboard() {
  const { t } = useTranslation()
  // U03: scope (org + provider) from the shared ScopeBar; URL-synced.
  const [scope, setScope] = useState<{ orgId: string; provider: string }>({ orgId: '', provider: '' })
  const [days, setDays] = useState(30)
  const orgId = scope.orgId
  const { currency, timezone } = useOrgPresentation(orgId || undefined)
  // AF-17: the scoped read lifecycle (generation/abort/applied guards,
  // U04 screen states) lives in useScopedQuery via the domain hook.
  const { report, loading, error, state, load } = useCostReport(orgId, scope.provider, days)


  return (
    <div className="space-y-6">
      <PageHeader
        title={t('cost.title')}
        purpose={t('cost.purpose')}
      />

      {/* U03: org + provider scope (URL-synced). The per-org cost endpoint
          requires an org; provider is recorded/deep-linked for the scope.
          AUX-04: both fields are real — GET /api/analytics/{org}/cost accepts
          org_id + provider (+ days from the window select below;
          cost_handlers.go CostAnalyticsHandler). */}
      <ScopeBar
        orgId={scope.orgId}
        provider={scope.provider}
        loading={loading}
        onChange={setScope}
        fields={['org', 'provider']}
      />

      {/* UX-03: days filter — a change refetches automatically (the load
          callback identity depends on the window; no Load button). The scope
          (ScopeBar) commits after its own debounce. */}
      <div className="card flex flex-wrap gap-4 items-end">
        <div>
          <label className="mb-1 block text-sm font-medium text-[color:var(--astra-ink)]">{t('cost.days')}</label>
          <select
            value={days}
            onChange={e => setDays(Number(e.target.value))}
            className="control sm:w-44"
          >
            {[7, 14, 30, 60, 90].map(d => (
              <option key={d} value={d}>{t('cost.daysOption', { days: d })}</option>
            ))}
          </select>
        </div>
      </div>

      {/* U04: states */}
      {state === 'error' && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void load() }} />}
      {state === 'not-loaded' && !orgId && (
        <StateNotice state="not-loaded" message={t('cost.notLoaded')} />
      )}
      {state === 'stale' && <StateNotice state="stale" message={t('cost.refreshingPrevious')} />}
      {state === 'empty' && (
        <StateNotice state="empty" message={t('cost.noCostData')} />
      )}

      {report && (state === 'ready' || state === 'stale') && (() => {
          // PO-05c / AVR-02: resolve pricing coverage once for the KPI strip.
          // Unknown (all unpriced) cost is never shown as $0.0000.
          const pc = costPricingCoverage(report.pricing, t)
          const allUnpriced = pc.state === 'unknown'
          const costState: MetricState = allUnpriced
            ? 'unknown'
            : pc.state === 'warning'
              ? 'warning'
              : 'ok'
          const usd = (v: number) => (allUnpriced ? t('common.unknown') : formatMoney(v, currency))
          // time for both the chart and its accessible data table.
          const dailyTrend = sortByTime(
            report.by_day.map(d => ({ date: d.date, cost: d.total_cost })),
            d => d.date,
          )
          return (
        <>
          {/* KPI strip */}
          <MetricStrip
            aria-label={t('cost.title')}
            metrics={[
              {
                 label: t('cost.totalCost'),
                 value: usd(report.total_cost_usd),
                 unit: allUnpriced ? undefined : 'USD',
                 state: costState,
                 coverage: pc.note || undefined,
                // AVR-01 (F01): the endpoint is per-org, so the caption names
                // the applied org explicitly (not just the provider).
                source: allUnpriced
                  ? t('cost.sourceUnpriced')
                  : t('cost.sourceRequestsScope', {
                    requests: report.request_count,
                    org: orgId,
                    provider: scope.provider || t('overview.allProviders'),
                  }),
              },
              {
                 label: t('cost.counterfactual'),
                 value: usd(report.counterfactual_cost),
                 unit: allUnpriced ? undefined : 'USD',
                 state: costState,
                source: allUnpriced
                  ? t('cost.sourceUnpriced')
                  : t('cost.sourceCounterfactual'),
              },
               {
                  label: t('cost.savings'),
                  value: usd(report.savings_usd),
                 // TP-05: values are USD by origin (no FX) — label the
                 // honest unit, never the org's presentation code.
                 unit: allUnpriced ? undefined : 'USD',
                // Honest states: positive savings are good, zero is neutral
                // (no optimization fired), negative means the optimizations
                // COST money (e.g. routing upgraded to a pricier model) —
                // that is a warning, not "no data".
                source: allUnpriced
                  ? t('cost.sourceUnpriced')
                  : t('cost.sourceSavedPct', { pct: report.savings_percent.toFixed(1) }),
                state: allUnpriced
                  ? 'unknown'
                  : report.savings_usd > 0
                    ? 'ok'
                    : report.savings_usd < 0
                      ? 'warning'
                      : 'unknown',
              },
              {
                 label: t('cost.avgPerRequest'),
                 value: usd(report.avg_cost_per_request),
                 unit: allUnpriced ? undefined : 'USD',
                 state: costState,
                source: allUnpriced
                  ? t('cost.sourceUnpriced')
                  : t('cost.sourceAllModels'),
              },
            ]}
          />

          {/* By-model cost bar chart (heading lives in ChartCard) */}
          {report.by_model.length > 0 && (
            <div className="card">
              <ChartCard title={t('cost.costByModelChart')} unit="USD" filename="cost-by-model"
                data={report.by_model.map(m => ({ name: m.model_name, cost: m.total_cost }))}
                columns={[{ key: 'name', label: t('cost.model') }, { key: 'cost', label: t('cost.costUsd'), align: 'right', format: r => formatMoney(r.cost, currency) }]}>
                 <BarChart data={report.by_model.map(m => ({ name: m.model_name, cost: m.total_cost }))} currency={currency} />
              </ChartCard>
            </div>
          )}

          {/* By-day trend line chart (heading lives in ChartCard) */}
          {report.by_day.length > 0 && (
            <div className="card">
              <ChartCard title={t('cost.dailyCostTrendChart')} unit="USD" timezone={timezone} filename="daily-cost-trend"
                data={dailyTrend}
                columns={[{ key: 'date', label: t('cost.dateUtc') }, { key: 'cost', label: t('cost.costUsd'), align: 'right', format: r => formatMoney(r.cost, currency) }]}>
                 <LineChart data={dailyTrend} currency={currency} timezone={timezone} />
              </ChartCard>
            </div>
          )}

          {/* Model breakdown table */}
          {report.by_model.length > 0 && (
            <div className="card overflow-x-auto">
              <h3 className="text-lg font-semibold mb-4">{t('cost.modelBreakdown')}</h3>
              <CostModelTable
                rows={report.by_model}
                totalCostUsd={report.total_cost_usd}
                currency={currency}
                // AUX-09: the drill carries the exact applied window (the
                // report is always fetched for the current `days` — a change
                // refetches immediately) and the scoped org.
                org={orgId}
                from={new Date(Date.now() - days * 86_400_000).toISOString()}
                to={new Date().toISOString()}
              />
            </div>
          )}
        </>
          )
        })()}
    </div>
  )
}

// AUX-03: the model breakdown runs on DataTable v2 (client mode) — money by
// cent value, requests numerically, share of total as a derived sort value;
// the default sort is the most expensive model first.
// AUX-09: the model name drills into its requests — org + applied window ride
// along, the model id becomes the applied YQL chip in the explorer.
function CostModelTable({ rows, totalCostUsd, currency, org, from, to }: {
  rows: CostReport['by_model']
  totalCostUsd: number
  currency: string
  org: string
  from: string
  to: string
}) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns: DataTableColumn<CostReport['by_model'][number]>[] = [
    {
      key: 'model_name',
      header: t('cost.model'),
      type: 'text',
      mono: true,
      render: m => (
        <a
          href={explorerLink({ org, from, to, yql: drillClause('model', m.model_name) ?? undefined })}
          title={t('analytics.drillHint')}
          className="font-medium underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]"
        >
          {m.model_name}
        </a>
      ),
    },
    { key: 'total_cost', header: t('cost.cost'), type: 'money', unit: 'USD', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(m.total_cost, currency)}</span> },
    { key: 'request_count', header: t('cost.requests'), type: 'number', unit: 'count', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{m.request_count}</span> },
    {
      key: 'share_pct',
      header: t('cost.pctOfTotal'),
      type: 'number',
      unit: '%',
      align: 'right',
      getSortValue: m => (totalCostUsd > 0 ? (m.total_cost / totalCostUsd) * 100 : null),
      render: m => (
        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
          {totalCostUsd > 0
            ? `${((m.total_cost / totalCostUsd) * 100).toFixed(1)}%`
            : '—'}
        </span>
      ),
    },
  ]
  return (
    <DataTable
      columns={columns}
      rows={rows}
      getRowId={m => m.model_name}
      page={page}
      pageSize={50}
      onPageChange={setPage}
      defaultSort={{ key: 'total_cost', dir: 'desc' }}
      caption={t('cost.modelBreakdown')}
    />
  )
}


