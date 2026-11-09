import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { LineChart } from '../components/LazyCharts'
import { ChartCard } from '../components/astra/ChartCard'
import { PageHeader } from '../components/astra/PageHeader'
import { MetricStrip } from '../components/astra/MetricStrip'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { fetchSavingsReport, type CostAnalyticsData } from '../api/client'
import { sortByTime } from '../lib/chartData'
import { formatMoney, formatNumber } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'

type SavingsModelRow = NonNullable<CostAnalyticsData['top_models_by_cost']>[number]

export function CachePage() {
  const { t } = useTranslation()
  const [days, setDays] = useState(7)
  const [data, setData] = useState<CostAnalyticsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const { currency, timezone } = useOrgPresentation(undefined)

  // UX-03: auto-load on mount and window change; no Load button.
  // Stale-fetch safety (U07): a newer load aborts the previous in-flight
  // one, so a slow response cannot clobber a newer window's data.
  const loadAbort = useRef<AbortController | null>(null)
  const handleLoad = useCallback(async () => {
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    setLoading(true)
    setError('')
    try {
      const d = await fetchSavingsReport({ days }, { signal: ctrl.signal })
      setData(d)
    } catch (e: unknown) {
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      setLoading(false)
    }
  }, [days])
  useEffect(() => {
    void handleLoad()
    return () => loadAbort.current?.abort()
  }, [handleLoad])

  const dailySavingsData = sortByTime(
    data?.daily_breakdown?.map(d => ({
      date: d.date,
      cost: d.counterfactual_cost_usd - d.actual_cost_usd,
    })) ?? [],
    d => d.date,
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('cache.title')}
        purpose={t('cache.purpose')}
      />

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('cache.reportingPeriod')}</span>
          <select
            value={days}
            onChange={e => setDays(Number(e.target.value))}
            className="control sm:w-44"
          >
            <option value={7}>{t('cache.last7')}</option>
            <option value={14}>{t('cache.last14')}</option>
            <option value={30}>{t('cache.last30')}</option>
          </select>
        </label>
      </div>

      {loading && <StateNotice state="loading" message={t('states.loading')} />}

      {error && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void handleLoad() }} />}

      {data && data.total_requests === 0 && (
        <StateNotice state="empty" message={t('cache.emptyWindow')} />
      )}

      {data && data.total_requests > 0 && (
        <>
          {/* KPI strip */}
          <MetricStrip
            aria-label={t('cache.title')}
            metrics={[
              {
                label: t('cache.cacheHits'),
                value: data.cache_hits != null ? formatNumber(data.cache_hits) : t('common.unknown'),
                unit: 'count',
                source: t('cache.sourceLastDays', { days }),
              },
              {
                label: t('cache.cacheSavings'),
                value: data.cache_savings_pct != null ? `${data.cache_savings_pct.toFixed(1)}%` : t('common.unknown'),
                source: t('cache.sourceCacheDiscount'),
              },
              {
                label: t('cache.totalRequests'),
                value: data.total_requests != null ? formatNumber(data.total_requests) : t('common.unknown'),
                unit: 'count',
                source: t('cache.sourceAllTraffic'),
              },
              {
                label: t('cache.hitRate'),
                value: data.total_requests > 0 ? `${((data.cache_hits / data.total_requests) * 100).toFixed(1)}%` : t('common.unknown'),
                source: t('cache.sourceExactSemantic'),
              },
            ]}
          />

          {/* Daily savings trend (heading lives in ChartCard) */}
          {dailySavingsData.length > 0 && (
            <div className="card">
              <ChartCard title={t('cache.dailySavingsChart')} unit="USD" timezone={timezone} filename="daily-savings"
                data={dailySavingsData}
                columns={[{ key: 'date', label: t('cache.dateUtc') }, { key: 'cost', label: t('cache.savingsUsd'), align: 'right', format: r => formatMoney(r.cost, currency) }]}>
                 <LineChart data={dailySavingsData} currency={currency} timezone={timezone} />
              </ChartCard>
            </div>
          )}

          {/* Top models with savings */}
          {data.top_models_by_cost && data.top_models_by_cost.length > 0 && (
            <div className="card overflow-x-auto">
              <h3 className="text-lg font-semibold mb-4">{t('cache.modelSavingsBreakdown')}</h3>
              <CacheModelTable rows={data.top_models_by_cost} currency={currency} />
            </div>
          )}
        </>
      )}
    </div>
  )
}

// AUX-03: the per-model savings breakdown runs on DataTable v2 (client mode);
// the default sort is the biggest saver first.
function CacheModelTable({ rows, currency }: { rows: SavingsModelRow[]; currency: string }) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns: DataTableColumn<SavingsModelRow>[] = [
    {
      key: 'model',
      header: t('cache.model'),
      type: 'text',
      mono: true,
      render: m => (
        <a
          href={`#explorer?model=${encodeURIComponent(m.model)}`}
          className="font-medium underline decoration-dotted underline-offset-4 hover:text-[color:var(--astra-action)]"
          title={t('cache.showRequests')}
        >
          {m.model}
        </a>
      ),
    },
    { key: 'requests', header: t('cache.requests'), type: 'number', unit: 'count', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{m.requests}</span> },
    { key: 'actual_cost_usd', header: t('cache.actual'), type: 'money', unit: 'USD', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(m.actual_cost_usd, currency)}</span> },
    { key: 'counterfactual_cost_usd', header: t('cache.counterfactual'), type: 'money', unit: 'USD', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(m.counterfactual_cost_usd, currency)}</span> },
    {
      key: 'savings_pct',
      header: t('cache.savingsPctHeader'),
      type: 'number',
      unit: '%',
      align: 'right',
      render: m => (
        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
          {m.savings_pct.toFixed(1)}%
          <span className="ms-1 text-xs" style={{ color: m.savings_pct > 0 ? 'var(--astra-success)' : 'var(--astra-text-muted)' }}>
            {m.savings_pct > 0 ? '▲' : '○'}
          </span>
        </span>
      ),
    },
  ]
  return (
    <DataTable
      columns={columns}
      rows={rows}
      getRowId={m => m.model}
      page={page}
      pageSize={50}
      onPageChange={setPage}
      defaultSort={{ key: 'savings_pct', dir: 'desc' }}
      caption={t('cache.modelSavingsBreakdown')}
    />
  )
}
