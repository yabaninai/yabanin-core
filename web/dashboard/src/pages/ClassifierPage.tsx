import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PieChartSmall, BarChart } from '../components/LazyCharts'
import { ChartCard } from '../components/astra/ChartCard'
import { PageHeader } from '../components/astra/PageHeader'
import { MetricStrip } from '../components/astra/MetricStrip'
import { StateNotice } from '../components/astra/StateNotice'
import { fetchSavingsReport, type CostAnalyticsData } from '../api/client'

export function ClassifierPage() {
  const { t } = useTranslation()
  const [days, setDays] = useState(7)
  const [data, setData] = useState<CostAnalyticsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // UX-03: auto-load — on mount and whenever the window changes; no Load
  // button (the error notice keeps an explicit Retry).
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

  const classDist = data?.classifier_distribution?.map(c => ({
    name: c.class,
    value: c.count,
  })) ?? []

  const confidenceData = data?.classifier_distribution?.map(c => ({
    name: c.class,
    cost: c.avg_confidence * 100,
  })) ?? []

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('classifier.title')}
        purpose={t('classifier.purpose')}
      />
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('classifier.reportingPeriod')}</span>
          <select
            value={days}
            onChange={e => setDays(Number(e.target.value))}
            className="control sm:w-44"
          >
            <option value={7}>{t('classifier.last7')}</option>
            <option value={14}>{t('classifier.last14')}</option>
            <option value={30}>{t('classifier.last30')}</option>
          </select>
        </label>
      </div>

      {loading && <StateNotice state="loading" message={t('states.loading')} />}

      {error && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void handleLoad() }} />}

      {data && data.total_requests === 0 && (
        <StateNotice state="empty" message={t('classifier.emptyWindow')} />
      )}

      {data && data.total_requests > 0 && (
        <>
          {/* KPI cards */}
          <MetricStrip
            aria-label={t('classifier.title')}
            metrics={[
              {
                label: t('classifier.routedRequests'),
                value: data.routed_requests?.toLocaleString() ?? t('common.unknown'),
                unit: 'count',
                source: t('classifier.sourceThroughClassifier'),
              },
              {
                label: t('classifier.routingSavings'),
                value: data.routing_savings_pct != null ? `${data.routing_savings_pct.toFixed(1)}%` : t('common.unknown'),
                source: t('classifier.sourceTierDiscount'),
              },
              {
                label: t('classifier.cacheSavings'),
                value: data.cache_savings_pct != null ? `${data.cache_savings_pct.toFixed(1)}%` : t('common.unknown'),
                source: t('classifier.sourceCacheHits', { hits: data.cache_hits?.toLocaleString() ?? 0 }),
              },
              {
                label: t('classifier.combinedSavings'),
                value: data.combined_savings_pct != null ? `${data.combined_savings_pct.toFixed(1)}%` : t('common.unknown'),
                source: data.kill_criterion_met ? t('classifier.killMet') : t('classifier.killNotMet'),
                state: data.kill_criterion_met ? 'ok' : 'warning',
              },
            ]}
          />

          {/* Class distribution pie (heading lives in ChartCard) */}
          {classDist.length > 0 && (
            <div className="card">
              <ChartCard title={t('classifier.classDistributionChart')} unit={t('classifier.unitShare')} filename="class-distribution"
                data={classDist}
                columns={[{ key: 'name', label: t('classifier.class') }, { key: 'value', label: t('classifier.requests'), align: 'right' }]}>
                <PieChartSmall data={classDist} />
              </ChartCard>
            </div>
          )}

          {/* Avg confidence by class (heading lives in ChartCard) */}
          {confidenceData.length > 0 && (
            <div className="card">
              <ChartCard title={t('classifier.avgConfidenceChart')} unit={t('classifier.unitPercent')} filename="avg-confidence"
                data={confidenceData}
                columns={[{ key: 'name', label: t('classifier.class') }, { key: 'cost', label: t('classifier.confidencePct'), align: 'right' }]}>
                <BarChart data={confidenceData} />
              </ChartCard>
            </div>
          )}
        </>
      )}
    </div>
  )
}
