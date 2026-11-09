// AUX-06 — the human summary of the applied analytics query. The same string
// heads the result block, titles the chart and names the exported CSV, so
// what you read, what you plot and what you download are always one query.
//
// This module stays pure (no i18next import): `t` and the date formatter are
// injected, so node tests can drive it without a DOM.

import { metricMeta, type AnalyticsParams } from './analyticsQuery.ts'

export interface SummaryOptions {
  t: (key: string, opts?: Record<string, unknown>) => string
  /** Localized medium date for the range borders (i18n/format.formatDate). */
  formatDate: (iso: string) => string
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}

export function summarizeQuery(params: AnalyticsParams, opts: SummaryOptions): string {
  const { t, formatDate } = opts
  const metricNames = params.metrics.map(id => {
    const meta = metricMeta(id)
    return meta ? t(meta.labelKey) : t(`analytics.metric.${id}`)
  })
  const parts: string[] = [metricNames.join(' + ')]
  if (params.groupBy.length) {
    const dims = params.groupBy.map(d =>
      d.startsWith('label:') ? t('analytics.labelDim', { key: d.slice(6) }) : t(`analytics.dim.${d}`),
    ).join(' × ')
    parts.push(t('analytics.summaryBy', { dims }))
  }
  if (params.granularity !== 'none') parts.push(t(`analytics.gran.${params.granularity}`))
  parts.push(`${formatDate(params.from)} – ${formatDate(params.to)}`)
  parts.push(t('analytics.summaryTop', { count: params.top }))
  const filter = params.filter.trim()
  if (filter) parts.push(t('analytics.summaryFilter', { filter: truncate(filter, 60) }))
  if (params.compare) parts.push(t('analytics.summaryVsPrev'))
  return parts.join(' · ')
}

/** File-system-safe name for the CSV export derived from the summary. */
export function summarySlug(summary: string): string {
  const slug = summary
    .toLowerCase()
    .replace(/[\s]+/g, '-')
    .replace(/[^\p{Letter}\p{Number}-]+/gu, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80)
    .replace(/-$/, '')
  return slug || 'analytics'
}
