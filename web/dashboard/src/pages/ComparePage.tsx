import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type {
  QualityReport,
  ShadowComparison,
} from '../api/client'
import { ScopeBar } from '../components/ScopeBar'
import { ChartCard } from '../components/astra/ChartCard'
import { BarChart } from '../components/LazyCharts'
import { PageHeader } from '../components/astra/PageHeader'
import { MetricStrip, type MetricState } from '../components/astra/MetricStrip'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { formatMoney } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'
import { useCompareReports } from './hooks/useCompareReports'

// CMP-01: model comparison screen.
//
// Data sources (G4, Phase 1):
//   - cost/latency comparison comes from the SHADOW eval: the backend mirrors
//     primary traffic to a shadow model and compares per-request cost on the
//     overlap (request_ids present on both sides). /api/analytics/shadow.
//   - latency is ORG-WIDE percentiles (the backend has no per-model latency
//     endpoint), so it is shown and captioned as org-wide, not per-model.
//   - quality (LLM-as-judge / qualityeval) has NO admin API yet, so the screen
//     shows an honest "not available" state rather than fabricating a number —
//     the same availability-honesty posture as the Cost screen's unknown pricing.
//
// Every figure carries an applied-scope caption: the scope and
// window the number was computed over, frozen at load time. The read
// lifecycle (generation/abort/applied guards, screen states) lives in
// useScopedQuery via the domain hook.

const VERDICT_STATE: Record<ShadowComparison['verdict'], MetricState> = {
  cheaper: 'ok',
  pricier: 'warning',
  insufficient_data: 'unknown',
}

export function ComparePage() {
  const { t } = useTranslation()
  const [scope, setScope] = useState<{ orgId: string; provider: string }>({ orgId: '', provider: '' })
  const [days, setDays] = useState(30)
  // The scoped read lifecycle lives in the domain hook; latency and
  // quality stay supplementary (a failure there never blanks the shadow
  // comparison), and `applied` is frozen at load time.
  const { shadow, latency, quality, applied, loading, error, state, load } = useCompareReports(scope.orgId, days)
  const orgId = scope.orgId
  const { currency } = useOrgPresentation(orgId || undefined)

  const appliedSummary = applied
    ? t('compare.appliedScopeSummary', {
        org: applied.orgId,
        days: applied.days,
      })
    : ''

  // The headline verdict for the KPI strip (from the shadow comparison).
  const headlineState: MetricState = shadow ? VERDICT_STATE[shadow.verdict] : 'loading'
  const headlineLabel = shadow
    ? t(`compare.verdict_${shadow.verdict}`)
    : t('common.unknown')

  // Per-primary-model quality (the cheap side = the primary model). A
  // row with no judged sample in the window shows "—", not a fabricated number.
  const qualityByPrimary = new Map<string, QualityReport['by_model'][number]>()
  if (quality) for (const m of quality.by_model) qualityByPrimary.set(m.primary_model, m)
  const qualityCol = (primary: string) => {
    const m = qualityByPrimary.get(primary)
    return m && m.verdicts > 0 ? m : null
  }

  // The four tables run on DataTable v2 in client mode — every header
  // sorts via the typed comparator (money/mumber/date semantics), the default
  // sort is the analytically useful one, and the third click returns to it.
  const [costPage, setCostPage] = useState(1)
  const [taskPage, setTaskPage] = useState(1)
  const [qualityModelPage, setQualityModelPage] = useState(1)
  const [qualityTaskPage, setQualityTaskPage] = useState(1)

  const costColumns: DataTableColumn<ShadowComparison['by_model'][number]>[] = [
    { key: 'primary_model', header: t('compare.primaryModel'), type: 'text', mono: true, render: m => <span className="font-medium">{m.primary_model}</span> },
    { key: 'shadow_model', header: t('compare.shadowModel'), type: 'text', mono: true, render: m => m.shadow_model },
    { key: 'overlap', header: t('compare.overlap'), type: 'number', unit: 'count', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{m.overlap}</span> },
    { key: 'primary_avg_usd', header: t('compare.primaryAvgCost'), type: 'money', unit: 'USD', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(m.primary_avg_usd, currency)}</span> },
    { key: 'shadow_avg_usd', header: t('compare.shadowAvgCost'), type: 'money', unit: 'USD', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(m.shadow_avg_usd, currency)}</span> },
    {
      key: 'delta_pct',
      header: t('compare.delta'),
      type: 'number',
      unit: '%',
      align: 'right',
      getSortValue: m => m.delta_pct,
      render: m => (
        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
          {m.verdict === 'insufficient_data' && Math.abs(m.delta_pct) < 0.0001 && m.primary_avg_usd === 0
            ? '—'
            : `${m.delta_pct >= 0 ? '+' : ''}${m.delta_pct.toFixed(1)}%`}
        </span>
      ),
    },
    {
      key: 'verdict',
      header: t('compare.verdict'),
      type: 'text',
      getSortValue: m => m.verdict,
      render: m => (
        <span
          className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium"
          style={{
            color: m.verdict === 'cheaper' ? 'var(--astra-success)' : m.verdict === 'pricier' ? 'var(--astra-warning)' : 'var(--astra-text-muted)',
            backgroundColor: m.verdict === 'cheaper' ? 'color-mix(in srgb, var(--astra-success) 12%, transparent)' : m.verdict === 'pricier' ? 'color-mix(in srgb, var(--astra-warning) 12%, transparent)' : 'color-mix(in srgb, var(--astra-text-muted) 12%, transparent)',
          }}
        >
          {t(`compare.verdict_${m.verdict}`)}
        </span>
      ),
    },
    {
      key: 'cheap_quality',
      header: t('compare.qualityCol'),
      type: 'number',
      unit: '%',
      align: 'right',
      getSortValue: m => qualityCol(m.primary_model)?.cheap_quality ?? null,
      render: m => {
        const q = qualityCol(m.primary_model)
        if (!q) return <span style={{ fontVariantNumeric: 'tabular-nums' }}>—</span>
        return (
          <span style={{ fontVariantNumeric: 'tabular-nums' }} title={t('compare.qualityColTitle', { cheap: q.cheap_quality.toFixed(2), premium: q.premium_quality.toFixed(2), upgrade: Math.round(q.upgrade_rate * 100), verdicts: q.verdicts })}>
            {Math.round(q.cheap_quality * 100)}%
          </span>
        )
      },
    },
  ]

  const taskColumns: DataTableColumn<ShadowComparison['by_task_class'][number]>[] = [
    { key: 'task_class', header: t('compare.taskClass'), type: 'text', render: g => <span className="font-medium">{g.task_class}</span> },
    { key: 'primary_model', header: t('compare.primaryModel'), type: 'text', mono: true, render: g => g.primary_model },
    { key: 'shadow_model', header: t('compare.shadowModel'), type: 'text', mono: true, render: g => g.shadow_model },
    { key: 'overlap', header: t('compare.overlap'), type: 'number', unit: 'count', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{g.overlap}</span> },
    { key: 'primary_avg_usd', header: t('compare.primaryAvgCost'), type: 'money', unit: 'USD', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(g.primary_avg_usd, currency)}</span> },
    { key: 'shadow_avg_usd', header: t('compare.shadowAvgCost'), type: 'money', unit: 'USD', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatMoney(g.shadow_avg_usd, currency)}</span> },
    {
      key: 'delta_pct',
      header: t('compare.delta'),
      type: 'number',
      unit: '%',
      align: 'right',
      getSortValue: g => g.delta_pct,
      render: g => (
        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
          {g.verdict === 'insufficient_data' && Math.abs(g.delta_pct) < 0.0001 && g.primary_avg_usd === 0
            ? '—'
            : `${g.delta_pct >= 0 ? '+' : ''}${g.delta_pct.toFixed(1)}%`}
        </span>
      ),
    },
    { key: 'primary_avg_ms', header: t('compare.primaryLatency'), type: 'number', unit: 'ms', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{g.primary_avg_ms} ms</span> },
    { key: 'shadow_avg_ms', header: t('compare.shadowLatency'), type: 'number', unit: 'ms', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{g.shadow_avg_ms} ms</span> },
    {
      key: 'verdict',
      header: t('compare.verdict'),
      type: 'text',
      getSortValue: g => g.verdict,
      render: g => (
        <span
          className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium"
          style={{
            color: g.verdict === 'cheaper' ? 'var(--astra-success)' : g.verdict === 'pricier' ? 'var(--astra-warning)' : 'var(--astra-text-muted)',
            backgroundColor: g.verdict === 'cheaper' ? 'color-mix(in srgb, var(--astra-success) 12%, transparent)' : g.verdict === 'pricier' ? 'color-mix(in srgb, var(--astra-warning) 12%, transparent)' : 'color-mix(in srgb, var(--astra-text-muted) 12%, transparent)',
          }}
        >
          {t(`compare.verdict_${g.verdict}`)}
        </span>
      ),
    },
  ]

  const qualityModelColumns: DataTableColumn<QualityReport['by_model'][number]>[] = [
    { key: 'primary_model', header: t('compare.primaryModel'), type: 'text', mono: true, render: m => <span className="font-medium">{m.primary_model}</span> },
    { key: 'shadow_model', header: t('compare.shadowModel'), type: 'text', mono: true, render: m => m.shadow_model },
    { key: 'verdicts', header: t('compare.qualityVerdicts'), type: 'number', unit: 'count', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{m.verdicts}</span> },
    { key: 'cheap_quality', header: t('compare.qualityCheap'), type: 'number', unit: '%', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(m.cheap_quality * 100)}%</span> },
    { key: 'premium_quality', header: t('compare.qualityPremium'), type: 'number', unit: '%', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(m.premium_quality * 100)}%</span> },
    { key: 'upgrade_rate', header: t('compare.qualityUpgradeRate'), type: 'number', unit: '%', align: 'right', render: m => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(m.upgrade_rate * 100)}%</span> },
  ]

  const qualityTaskColumns: DataTableColumn<QualityReport['by_task_class'][number]>[] = [
    { key: 'task_class', header: t('compare.qualityTaskClass'), type: 'text', mono: true, render: g => <span className="font-medium">{g.task_class}</span> },
    { key: 'primary_model', header: t('compare.primaryModel'), type: 'text', mono: true, render: g => g.primary_model },
    { key: 'verdicts', header: t('compare.qualityVerdicts'), type: 'number', unit: 'count', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{g.verdicts}</span> },
    { key: 'cheap_quality', header: t('compare.qualityCheap'), type: 'number', unit: '%', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(g.cheap_quality * 100)}%</span> },
    { key: 'upgrade_rate', header: t('compare.qualityUpgradeRate'), type: 'number', unit: '%', align: 'right', render: g => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(g.upgrade_rate * 100)}%</span> },
  ]

  // Apply → DRAFT. Pre-fills the Rules form via query params and does
  // NOT save (human-only). task_id is not a rule field, so the draft is a
  // model-swap (model_requested == <primary>).
  const applyRecommendation = () => {
    const rec = quality?.recommendation
    if (!rec) return
    const p = new URLSearchParams(window.location.hash.split('?')[1] ?? '')
    p.set('org', orgId)
    p.set('draft_expr', rec.match_expr)
    p.set('draft_model', rec.target_model)
    p.set('draft_priority', String(rec.priority))
    p.set('draft_from', 'quality')
    window.location.hash = `rules?${p.toString()}`
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t('compare.title')} purpose={t('compare.purpose')} />

      {/* Org scope (URL-synced). The provider field is HIDDEN
          here, not decorative — GET /api/analytics/shadow, /latency and
          /quality accept org_id + window only (services/admin/handlers/
          cost_handlers.go, analytics.go); they have no provider param, so
          showing one would be a filter that changes nothing. */}
      <ScopeBar orgId={scope.orgId} provider={scope.provider} loading={loading} onChange={setScope}
        fields={['org']}
        appliedSummary={appliedSummary || undefined} />

      {/* UX-03: days filter — a change refetches automatically (no Load
          button; the scope commits via the ScopeBar debounce). */}
      <div className="card flex flex-wrap gap-4 items-end">
        <div>
          <label className="mb-1 block text-sm font-medium text-[color:var(--astra-ink)]">{t('compare.days')}</label>
          <select value={days} onChange={e => setDays(Number(e.target.value))} className="control sm:w-44">
            {[7, 14, 30, 60, 90].map(d => (
              <option key={d} value={d}>{t('cost.daysOption', { days: d })}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Derived screen states. */}
      {state === 'error' && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void load() }} />}
      {state === 'not-loaded' && !orgId && <StateNotice state="not-loaded" message={t('compare.notLoaded')} />}
      {state === 'stale' && <StateNotice state="stale" message={t('compare.refreshingPrevious')} />}
      {state === 'empty' && <StateNotice state="empty" message={t('compare.noShadowData')} />}

      {shadow && (state === 'ready' || state === 'stale') && (
        <>
          {/* KPI strip: headline verdict + per-side avg cost + overlap. Each is
              captioned with the applied scope. */}
          <MetricStrip
            aria-label={t('compare.title')}
            metrics={[
              {
                label: t('compare.headlineVerdict'),
                value: headlineLabel,
                state: headlineState,
                source: appliedSummary,
              },
              {
                label: t('compare.primaryAvgCost'),
                value: formatMoney(shadow.primary_avg_usd, currency),
                unit: 'USD',
                state: 'ok',
                source: t('compare.sourcePrimaryAvg', { model: shadow.primary_model }),
              },
              {
                label: t('compare.shadowAvgCost'),
                value: formatMoney(shadow.shadow_avg_usd, currency),
                unit: 'USD',
                state: 'ok',
                source: t('compare.sourceShadowAvg', { model: shadow.shadow_model }),
              },
              {
                label: t('compare.overlap'),
                value: String(shadow.overlap),
                unit: t('compare.overlapUnit'),
                state: 'ok',
                source: t('compare.sourceOverlap', { days: applied?.days ?? days, org: applied?.orgId ?? orgId }),
              },
            ]}
          />

          {/* Per-(primary, shadow) model cost comparison bar chart. */}
          {shadow.by_model.length > 0 && (
            <div className="card">
              <ChartCard
                title={t('compare.costByModelChart')}
                unit="USD"
                filename="model-compare-cost"
                data={shadow.by_model.map(m => ({ name: m.primary_model, cost: m.primary_avg_usd, shadow: m.shadow_avg_usd }))}
                columns={[
                  { key: 'name', label: t('compare.primaryModel') },
                  { key: 'cost', label: t('compare.primaryAvgCost'), align: 'right', format: r => formatMoney(r.cost, currency) },
                  { key: 'shadow', label: t('compare.shadowAvgCost'), align: 'right', format: r => formatMoney(r.shadow, currency) },
                ]}>
                <BarChart
                  data={shadow.by_model.map(m => ({ name: m.primary_model, cost: m.primary_avg_usd }))}
                  currency={currency}
                />
              </ChartCard>
            </div>
          )}

          {/* Per-model cost comparison table with verdicts. */}
          {shadow.by_model.length > 0 && (
            <div className="card overflow-x-auto">
              <h3 className="text-lg font-semibold mb-4">{t('compare.modelComparison')}</h3>
              <DataTable
                columns={costColumns}
                rows={shadow.by_model}
                getRowId={m => `${m.primary_model}->${m.shadow_model}`}
                page={costPage}
                pageSize={50}
                onPageChange={setCostPage}
                defaultSort={{ key: 'primary_avg_usd', dir: 'desc' }}
                caption={t('compare.modelComparison')}
              />
            </div>
          )}

          {/* The task-tag dimension — cost + latency per model × task
              class (request_logs.task_id; NULL → "(untagged)"). */}
          {shadow.by_task_class.length > 0 && (
            <div className="card overflow-x-auto">
              <h3 className="text-lg font-semibold mb-4">{t('compare.taskClassInsights')}</h3>
              <p className="text-sm mb-4 text-[color:var(--astra-text-muted)]">{t('compare.taskClassInsightsNote')}</p>
              <DataTable
                columns={taskColumns}
                rows={shadow.by_task_class}
                getRowId={g => `${g.task_class}|${g.primary_model}->${g.shadow_model}`}
                page={taskPage}
                pageSize={50}
                onPageChange={setTaskPage}
                defaultSort={{ key: 'primary_avg_usd', dir: 'desc' }}
                caption={t('compare.taskClassInsights')}
              />
            </div>
          )}

          {/* Org-wide latency percentiles — honestly captioned as NOT per-model
              (the backend has no per-model latency). */}
          <div className="card">
            <h3 className="text-lg font-semibold mb-1">{t('compare.latencyTitle')}</h3>
            <p className="mb-4 text-sm text-[color:var(--astra-text-muted)]">{t('compare.latencyNote')}</p>
            {latency ? (
              <MetricStrip
                aria-label={t('compare.latencyTitle')}
                metrics={[
                  { label: 'p50', value: `${Math.round(latency.p50)} ms`, state: 'ok', source: appliedSummary },
                  { label: 'p90', value: `${Math.round(latency.p90)} ms`, state: 'ok', source: appliedSummary },
                  { label: 'p95', value: `${Math.round(latency.p95)} ms`, state: 'ok', source: appliedSummary },
                  { label: 'p99', value: `${Math.round(latency.p99)} ms`, state: 'ok', source: appliedSummary },
                ]}
              />
            ) : (
              <StateNotice state="empty" message={t('compare.latencyUnavailable')} />
            )}
          </div>

          {/* Quality closed-loop. evalgate (LLM-as-judge) verdicts are
              aggregated into per-model + per-task-class quality scores. The
              sample scope + window are stated honestly (the judge samples a
              subset of low-confidence medium-class requests — not the whole
              org), so a low count is never presented as a whole-org truth. A
              window with no judged traffic keeps the honest "not available"
              state (availability-honesty, same posture as PO-05c). */}
          <div className="card">
            <h3 className="text-lg font-semibold mb-1">{t('compare.qualityTitle')}</h3>
            <p className="mb-4 text-sm text-[color:var(--astra-text-muted)]">
              {quality ? t('compare.qualityScopeNote', { sample: quality.sample_scope_note, days }) : t('compare.qualityNote')}
            </p>
            {quality && quality.verdict === 'has_data' ? (
              <div className="space-y-6">
                {/* Per-model quality (the same primary/shadow pairs as the cost
                    table, so a model's cost + quality read on one row). */}
                {quality.by_model.length > 0 && (
                  <div className="overflow-x-auto">
                    <h4 className="text-sm font-medium mb-2 text-[color:var(--astra-ink)]">{t('compare.qualityByModel')}</h4>
                    <DataTable
                      columns={qualityModelColumns}
                      rows={quality.by_model}
                      getRowId={m => `q-${m.primary_model}->${m.shadow_model}`}
                      page={qualityModelPage}
                      pageSize={50}
                      onPageChange={setQualityModelPage}
                      defaultSort={{ key: 'verdicts', dir: 'desc' }}
                      caption={t('compare.qualityByModel')}
                    />
                  </div>
                )}

                {/* Per-task-class quality: which model serves which class of
                    agentic task well (task_id; NULL → "(untagged)"). */}
                {quality.by_task_class.length > 0 && (
                  <div className="overflow-x-auto">
                    <h4 className="text-sm font-medium mb-2 text-[color:var(--astra-ink)]">{t('compare.qualityByTask')}</h4>
                    <DataTable
                      columns={qualityTaskColumns}
                      rows={quality.by_task_class}
                      getRowId={g => `qt-${g.task_class}-${g.primary_model}`}
                      page={qualityTaskPage}
                      pageSize={50}
                      onPageChange={setQualityTaskPage}
                      defaultSort={{ key: 'verdicts', dir: 'desc' }}
                      caption={t('compare.qualityByTask')}
                    />
                  </div>
                )}

                {/* Recommendation row: a suggested routing change with its
                    justification (data + window). Applying is HUMAN-ONLY — the
                    button pre-fills the Rules form with a draft; it never
                    saves. */}
                {quality.recommendation && quality.recommendation.has_recommendation ? (
                  <div
                    className="rounded-lg border p-4"
                    style={{ borderColor: 'var(--astra-warning)', backgroundColor: 'color-mix(in srgb, var(--astra-warning) 8%, transparent)' }}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h4 className="text-sm font-semibold" style={{ color: 'var(--astra-warning)' }}>{t('compare.recommendationTitle')}</h4>
                        <p className="mt-1 text-sm text-[color:var(--astra-ink)]">
                          {t('compare.recommendationBody', { from: quality.recommendation.primary_model, to: quality.recommendation.shadow_model })}
                        </p>
                        <p className="mt-2 text-xs text-[color:var(--astra-text-muted)]">{quality.recommendation.justification}</p>
                        <p className="mt-1 text-xs text-[color:var(--astra-text-muted)]">{t('compare.recommendationHumanOnly')}</p>
                      </div>
                      <button
                        type="button"
                        onClick={applyRecommendation}
                        className="shrink-0 rounded-md border px-3 py-1.5 text-sm font-medium"
                        style={{ borderColor: 'var(--astra-warning)', color: 'var(--astra-ink)' }}
                      >
                        {t('compare.recommendationApply')}
                      </button>
                    </div>
                  </div>
                ) : (
                  <StateNotice state="empty" message={t('compare.recommendationNone')} />
                )}
              </div>
            ) : (
              <StateNotice state="empty" message={t('compare.qualityUnavailable')} />
            )}
          </div>
        </>
      )}
    </div>
  )
}

export default ComparePage
