import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getToolCallsReport, type ToolCallsReport } from '../api/client'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { MetricStrip, type Metric, type MetricState } from '../components/astra/MetricStrip'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { drillClause, explorerLink } from '../lib/explorerLink'

// AV-13 card: the cross-request tool-call aggregate. The explorer inspector
// shows the calls one request made; this screen answers "which tools do the
// models actually use, how often, on which models". Rows exist only for
// parsed calls — a tool that never appears is absent, not zero.

type TopTool = NonNullable<ToolCallsReport['top_tools']>[number]
type ModelUsage = NonNullable<ToolCallsReport['by_model']>[number]
export function ToolCallsPage() {
  const { t } = useTranslation()
  const [org, setOrg] = useState('')
  const [report, setReport] = useState<ToolCallsReport | null>(null)
  const [failed, setFailed] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const gen = useRef(0)

  useEffect(() => {
    if (!org.trim()) return
    const g = ++gen.current
    const timer = setTimeout(() => {
      getToolCallsReport(org.trim(), 30)
        .then(rep => { if (gen.current === g) { setReport(rep); setFailed(false) } })
        .catch(() => { if (gen.current === g) { setFailed(true); setReport(null) } })
        .finally(() => { if (gen.current === g) setLoaded(true) })
    }, 400)
    return () => clearTimeout(timer)
  }, [org])

  const metrics: Metric[] = (() => {
    const labels = ['statCalls', 'statTools', 'statRequestsUsing']
    if (failed) return labels.map(l => ({ label: t(`toolCalls.${l}`), value: t('states.failedToLoad'), state: 'unknown' as MetricState }))
    if (!report) return labels.map(l => ({ label: t(`toolCalls.${l}`), value: '', state: 'loading' as MetricState }))
    return [
      { label: t('toolCalls.statCalls'), value: report.total_calls.toLocaleString(), state: 'ok' as MetricState },
      { label: t('toolCalls.statTools'), value: report.distinct_tools.toLocaleString(), state: 'ok' as MetricState },
      { label: t('toolCalls.statRequestsUsing'), value: report.requests_using_tools.toLocaleString(), source: t('toolCalls.statRequestsUsingSource'), state: 'ok' as MetricState },
    ]
  })()

  // AUX-03: both aggregates run on DataTable v2 in client mode — every header
  // sorts via the typed comparator, defaulting to the busiest rows first.
  const [topPage, setTopPage] = useState(1)
  const [modelPage, setModelPage] = useState(1)

  // AUX-09: the drill window is the report's own window (the aggregate is
  // always fetched for the last 30 days, ending at load time).
  const drillOrg = org.trim()
  const drillWindow = {
    from: new Date(Date.now() - 30 * 86_400_000).toISOString(),
    to: new Date().toISOString(),
  }
  const drillLink = (field: 'tool' | 'model', value: string): string =>
    explorerLink({ org: drillOrg, ...drillWindow, yql: drillClause(field, value) ?? undefined })

  const topColumns: DataTableColumn<TopTool>[] = [
    {
      key: 'tool_name',
      header: t('toolCalls.colTool'),
      type: 'text',
      mono: true,
      render: r => (
        <a
          href={drillLink('tool', r.tool_name)}
          title={t('analytics.drillHint')}
          className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]"
        >
          {r.tool_name}
        </a>
      ),
    },
    { key: 'calls', header: t('toolCalls.colCalls'), type: 'number', unit: 'count', align: 'right', render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.calls.toLocaleString()}</span> },
    { key: 'share', header: t('toolCalls.colShare'), type: 'number', unit: '%', align: 'right', render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.share.toFixed(1)}%</span> },
    { key: 'last_used_at', header: t('toolCalls.colLastUsed'), type: 'date', align: 'right', render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.last_used_at.slice(0, 19).replace('T', ' ')}</span> },
  ]

  const modelColumns: DataTableColumn<ModelUsage>[] = [
    {
      key: 'model',
      header: t('toolCalls.colModel'),
      type: 'text',
      mono: true,
      render: r => r.model
        ? (
          <a
            href={drillLink('model', r.model)}
            title={t('analytics.drillHint')}
            className="underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]"
          >
            {r.model}
          </a>
        )
        : '—',
    },
    { key: 'calls', header: t('toolCalls.colCalls'), type: 'number', unit: 'count', align: 'right', render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.calls.toLocaleString()}</span> },
  ]

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t('toolCalls.title')} purpose={t('toolCalls.purpose')} />
      <form className="card flex flex-wrap items-end gap-3" onSubmit={e => { e.preventDefault() }}>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('explorer.organizationId')}</span>
          {/* UI-VF-1: OrgSelect picker instead of a hand-copied UUID;
              autoSelect pre-commits the last-used or first org. */}
          <OrgSelect
            value={org}
            onChange={v => { setOrg(v); setLoaded(false) }}
            autoSelect
            className="w-64"
            manualAriaLabel={t('explorer.orgUuid')}
          />
        </label>
      </form>

      {!org.trim() && !loaded && <StateNotice state="not-loaded" message={t('toolCalls.notLoaded')} />}
      {loaded && failed && <StateNotice state="error" message={t('toolCalls.loadFailed')} />}
      {loaded && !failed && report && (
        <>
          <MetricStrip aria-label={t('toolCalls.title')} metrics={metrics} />

          <section aria-labelledby="toolcalls-top-title" className="card flex flex-col gap-3">
            <h2 id="toolcalls-top-title" className="text-base font-semibold text-[color:var(--astra-ink)]">{t('toolCalls.topTitle')}</h2>
            {(report.top_tools ?? []).length === 0 ? (
              <StateNotice state="empty" message={t('toolCalls.empty')} />
            ) : (
              <DataTable
                columns={topColumns}
                rows={report.top_tools ?? []}
                getRowId={r => r.tool_name}
                page={topPage}
                pageSize={50}
                onPageChange={setTopPage}
                defaultSort={{ key: 'calls', dir: 'desc' }}
                caption={t('toolCalls.topTitle')}
              />
            )}
          </section>

          {(report.by_model ?? []).length > 0 && (
            <section aria-labelledby="toolcalls-model-title" className="card flex flex-col gap-3">
              <h2 id="toolcalls-model-title" className="text-base font-semibold text-[color:var(--astra-ink)]">{t('toolCalls.byModelTitle')}</h2>
              <DataTable
                columns={modelColumns}
                rows={report.by_model ?? []}
                getRowId={r => r.model || '—'}
                page={modelPage}
                pageSize={50}
                onPageChange={setModelPage}
                defaultSort={{ key: 'calls', dir: 'desc' }}
                caption={t('toolCalls.byModelTitle')}
              />
            </section>
          )}
        </>
      )}
    </div>
  )
}
