import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { DataTable, type DataTableColumn } from './DataTable'
import { MetricStrip, type Metric } from './MetricStrip'
import { StateNotice } from './StateNotice'
import { AnalyticsSeriesChart } from '../LazyCharts'
import { ApiError } from '../../api/transport'
import { formatDate } from '../../i18n/format'
import {
  chartRows, formatMetricValue, metricDisplayUnit, metricMeta, seriesDisplayName,
  type AnalyticsResult, type Translate,
} from '../../lib/analyticsQuery'
import { hygieneShare, issueURL, monthForecast, pipelineAverage, type ResolvedPanel } from '../../lib/boards'

// The shared board-panel card. One rendering for the Dashboards
// boards and the Overview pinned-panels section (a pin re-renders the SAME
// panel, not a snapshot of numbers). The card owns the per-panel honesty
// contract:
//   * the applied-scope caption names the window and filter the shown data
//     was actually fetched with (captions describe applied scope);
//   * numbers go through the metric registry — locale-aware values,
//     display units, glossary hints, never a raw id or String(number);
//   * table panels render a real DataTable (client-mode: the analytics
//     endpoint owns neither paging nor ordering), chart panels the series
//     chart; a failed panel says so instead of rendering an empty card.

export interface PanelAppliedScope {
  from: string
  to: string
  tz: string
  /** The YQL the panel was fetched with ('' → no filter). */
  filter: string
}

export interface BoardPanelCardProps {
  panel: ResolvedPanel
  result?: AnalyticsResult | ApiError
  applied?: PanelAppliedScope
  explorerHref: string
  metricFmt: { locale: string; currency: string }
  /** Organization issue_url_template (the top-issues panel links out). */
  issueTemplate?: string
  pinned?: boolean
  onTogglePin?: () => void
  onPointClick?: (click: { seriesKey: string; x: string }) => void
}

interface PanelRow { id: string; cells: Array<string | number | null> }

export function BoardPanelCard({ panel, result, applied, explorerHref, metricFmt, issueTemplate, pinned, onTogglePin, onPointClick }: BoardPanelCardProps) {
  const { t } = useTranslation()
  // The table panel's local pager lives here so a panel keeps its page while
  // the board around it re-renders.
  const [tablePage, setTablePage] = useState(1)

  const failed = result instanceof ApiError
  const data = failed ? undefined : result
  const hiddenByError = failed && (result.code ?? '').includes('invalid_dimension')

  const caption = applied
    ? t('dashboards.appliedScope', {
        window: `${formatDate(applied.from, applied.tz || undefined)} – ${formatDate(applied.to, applied.tz || undefined)}`,
        filter: applied.filter || t('dashboards.noFilter'),
      })
    : undefined

  // Table columns through the metric registry — glossary headers,
  // formatted numbers, typed sorting.
  const table = useMemo(() => {
    if (!data || panel.query.chart !== 'table') return null
    const columns: DataTableColumn<PanelRow>[] = data.columns.map((col, i) => {
      const meta = col.type === 'number' ? metricMeta(col.name) : undefined
      return {
        key: col.name,
        header: col.type === 'time'
          ? t('analytics.time')
          : col.type === 'number'
            ? (meta ? t(meta.labelKey) : t(`analytics.metric.${col.name}`))
            : (col.name.startsWith('label:') ? t('analytics.labelDim', { key: col.name.slice(6) }) : t(`analytics.dim.${col.name}`)),
        headerHint: meta ? t(meta.descKey) : undefined,
        align: col.type === 'number' ? 'right' as const : 'left' as const,
        mono: true,
        type: col.type === 'time' ? 'date' as const : col.type === 'number' ? 'number' as const : 'text' as const,
        unit: col.unit,
        getSortValue: (row: PanelRow) => row.cells[i],
        render: (row: PanelRow) => {
          const v = row.cells[i]
          if (v == null) return <span className="text-[color:var(--astra-text-muted)]">—</span>
          const text = meta
            ? (formatMetricValue(col.name, typeof v === 'number' ? v : Number(v), metricFmt) ?? String(v))
            : String(v)
          return <span>{text}</span>
        },
      }
    })
    const rows: PanelRow[] = data.rows.map((cells, i) => ({ id: String(i), cells }))
    return { columns, rows }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- metricFmt carries locale/currency
  }, [data, panel.query.chart, t, metricFmt.locale, metricFmt.currency])

  const chart = data && panel.query.chart !== 'table' ? chartRows(data, panel.query.chart) : null

  return (
    <section className="card flex flex-col gap-3" aria-label={t(panel.titleKey)}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t(panel.titleKey)}</h2>
        <div className="flex flex-wrap items-center gap-3">
          {onTogglePin && (
            <button
              type="button"
              className="btn-secondary"
              aria-pressed={pinned === true}
              onClick={onTogglePin}
            >
              {pinned ? t('dashboards.unpin') : t('dashboards.pin')}
            </button>
          )}
          <a className="text-sm underline" href={explorerHref}>{t('dashboards.openExplorer')}</a>
        </div>
      </div>
      {caption && (
        // An applied filter clause can be long — it wraps, never
        // widens the document.
        <p className="overflow-wrap-anywhere text-xs text-[color:var(--astra-text-muted)]"
          style={{ font: '11px/1.4 var(--astra-font-code)' }}>
          {caption}
        </p>
      )}
      {hiddenByError ? (
        <StateNotice state="partial" title={t(panel.titleKey)} message={t('dashboards.unavailable', { dim: panel.missing ?? 'invalid_dimension' })} />
      ) : failed ? (
        <StateNotice state="error" title={t(panel.titleKey)} message={t('dashboards.panelFailed', { code: result.code ?? String(result.status) })} />
      ) : null}
      {data && <MetricStrip aria-label={t(panel.titleKey)} metrics={panel.query.metrics.map((id): Metric => {
        const meta = metricMeta(id)
        const v = data.totals[id]
        return {
          label: meta ? t(meta.labelKey) : t(`analytics.metric.${id}`),
          value: v == null ? '—' : formatMetricValue(id, typeof v === 'number' ? v : Number(v), metricFmt) ?? '—',
          unit: meta ? metricDisplayUnit(id) : undefined,
          description: meta ? t(meta.descKey) : undefined,
        }
      })} />}
      {panel.note === 'forecast' && data && (
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('dashboards.forecast', { value: monthForecast(typeof data.totals.cost_usd === 'number' ? data.totals.cost_usd : 0, new Date()).toFixed(2) })}</p>
      )}
      {panel.note === 'hygiene' && data && (
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('dashboards.hygiene', { share: String(hygieneShare(data.rows) ?? 0) })}</p>
      )}
      {panel.note === 'pipeline' && data && (
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('dashboards.pipelineAvg', { value: String(pipelineAverage(data.rows) ?? 0) })}</p>
      )}
      {panel.id === 'top-issues' && data && data.rows.map(row => {
        const name = String(row[0] ?? '')
        const href = issueURL(issueTemplate ?? '', name)
        return href
          ? <a key={name} href={href}>{name}</a>
          : <span key={name} title={issueTemplate ? undefined : t('dashboards.noTemplate')}>{name}</span>
      })}
      {table && table.rows.length > 0 && (
        <DataTable<PanelRow>
          columns={table.columns}
          rows={table.rows}
          getRowId={r => r.id}
          page={tablePage}
          pageSize={10}
          onPageChange={setTablePage}
          caption={t(panel.titleKey)}
        />
      )}
      {chart && chart.points.length > 0 && panel.query.chart !== 'table' && data && onPointClick && (
        // seriesDisplayName mapping as the explorer — the raw chartRows key
        // stays the onPointClick drill-down contract, never visible text.
        <AnalyticsSeriesChart data={chart.points} xKey="x"
          series={chart.series.map(s => ({ key: s.key, name: seriesDisplayName(s.key, data, t as Translate) }))}
          kind={panel.query.chart}
          onPointClick={onPointClick} />
      )}
    </section>
  )
}
