//   - failover chains as a table (model → fallback → failovers, the order
//     the gateway assembles attempts), with the computed configuration
//     warnings (cycle / missing / disabled target) both as a dedicated
//     panel and as per-row chips — the API's warnings are the single
//     source, the UI never re-derives them;
//   - aliases and routing rules with their target warnings;
//   - provider health over the shared period: per-provider aggregates with
//     a plain-SVG traffic sparkline (requests by model — no chart library)
//     and the per-provider×model rows with p50/p95 and the last error.
// Every model row and health-model row drills into the request explorer
// with the model filter prefilled (#requests-explorer?…&model=…, UI-contract
// #9) — the same drill-down the request explorer itself accepts.

import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  getRoutingMap, getProviderHealth, healthPeriodParam, chainSteps,
  type RoutingMap, type RoutingMapModel, type RoutingMapRule, type RoutingMapWarning,
  type ProviderHealth, type ProviderHealthModel, type ProviderHealthReport,
} from '../api/routing'
import { ApiError } from '../api/transport'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { RoutingGraphSection } from '../components/astra/RoutingGraph'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { GlobalScopeBar } from '../components/GlobalScopeBar'
import { useGlobalScope } from '../hooks/useGlobalScope'
import { currentHashQuery, relatedListHref } from '../lib/inspectUrl'
import { missingTargetNames } from '../lib/routingTopology'
import { formatDateTime } from '../i18n/format'

type LoadState = 'idle' | 'loading' | 'ready' | 'failed'
type T = ReturnType<typeof useTranslation>['t']

/** Localized category for a stable warning code; unknown codes stay data. */
function warnLabel(code: string, t: T): string {
  switch (code) {
    case 'chain_cycle':
      return t('routingMap.warnCycle')
    case 'chain_target_missing':
    case 'alias_target_missing':
    case 'rule_target_missing':
      return t('routingMap.warnTargetMissing')
    case 'chain_target_disabled':
    case 'alias_target_disabled':
    case 'rule_target_disabled':
      return t('routingMap.warnTargetDisabled')
    default:
      return code
  }
}

function scopeLabel(scope: string, t: T): string {
  switch (scope) {
    case 'model':
      return t('routingMap.scopeModel')
    case 'alias':
      return t('routingMap.scopeAlias')
    case 'rule':
      return t('routingMap.scopeRule')
    default:
      return scope
  }
}

export function RoutingMapPage() {
  const { t } = useTranslation()
  const gs = useGlobalScope()
  const org = gs.org.trim()
  // The health window is the shared GlobalScope period, expressed in the
  // health API's `period` vocabulary — no second period control here.
  const healthPeriod = healthPeriodParam(gs.period, gs.from, gs.to)

  const [map, setMap] = useState<RoutingMap | null>(null)
  const [mapState, setMapState] = useState<LoadState>('idle')
  // Why the last map load failed (undefined status = network/unknown). The
  // notice copy branches on it: session/permission, membership-vs-foreign-org
  // (the API answers 404 for both), or a plain failure.
  const [mapError, setMapError] = useState<{ status?: number; message: string } | null>(null)
  // Bumping this re-runs the map effect (the notices' retry action).
  const [mapTick, setMapTick] = useState(0)
  const [health, setHealth] = useState<ProviderHealthReport | null>(null)
  const [healthState, setHealthState] = useState<LoadState>('idle')
  const mapGen = useRef(0)
  const healthGen = useRef(0)

  useEffect(() => {
    if (!org) {
      setMap(null)
      setMapState('idle')
      setMapError(null)
      return
    }
    const g = ++mapGen.current
    let live = true
    setMapState('loading')
    getRoutingMap(org)
      .then(res => {
        if (!live || mapGen.current !== g) return
        setMap(res)
        setMapState('ready')
        setMapError(null)
      })
      .catch((err: unknown) => {
        if (!live || mapGen.current !== g) return
        // Honest failure: drop the stale map instead of painting old data
        // as if it were current — the notice says what happened.
        setMap(null)
        setMapState('failed')
        setMapError(err instanceof ApiError ? { status: err.status, message: err.message } : { message: String(err) })
      })
    return () => { live = false }
  }, [org, mapTick])

  useEffect(() => {
    if (!org) {
      setHealth(null)
      setHealthState('idle')
      return
    }
    const g = ++healthGen.current
    let live = true
    setHealthState('loading')
    getProviderHealth(org, healthPeriod)
      .then(res => {
        if (!live || healthGen.current !== g) return
        setHealth(res)
        setHealthState('ready')
      })
      .catch(() => {
        if (!live || healthGen.current !== g) return
        setHealth(null)
        setHealthState('failed')
      })
    return () => { live = false }
  }, [org, healthPeriod])

  // Warnings grouped by `${scope}:${source}` — the row-level chip lookup.
  const warningsBySource = useMemo(() => {
    const idx = new Map<string, RoutingMapWarning[]>()
    for (const w of map?.warnings ?? []) {
      const key = `${w.scope}:${w.source}`
      const list = idx.get(key)
      if (list) list.push(w)
      else idx.set(key, [w])
    }
    return idx
  }, [map])
  const warningsFor = (scope: string, source: string): RoutingMapWarning[] =>
    warningsBySource.get(`${scope}:${source}`) ?? []

  const modelRows = useMemo(
    () => (health?.providers ?? []).flatMap(p => p.models.map(m => ({ ...m, provider: p.provider }))),
    [health],
  )

  // Configured-but-unregistered targets: the honest input behind the partial
  // notice (phantoms in the graph, missing rows in the tables).
  const missingTargets = useMemo(() => (map === null ? [] : missingTargetNames(map)), [map])

  return (
    <div className="space-y-6">
      <PageHeader title={t('routingMap.title')} purpose={t('routingMap.purpose')} />
      <GlobalScopeBar fields={['org', 'period']} />
      {!org && <StateNotice state="not-loaded" message={t('routingMap.notLoaded')} />}
      {org && (
        <div className="space-y-6">
          <MapStatusBlock mapState={mapState} map={map} mapError={mapError} onRetry={() => setMapTick(n => n + 1)} />
          {map !== null && (mapState === 'ready' || mapState === 'loading') && (
            <>
              <MissingTargetsNotice names={missingTargets} />
              <WarningsPanel warnings={map.warnings} />
              {/* CV-01 (V01 rendering child): the configuration-topology
                  visualizer (alias → rule → model → provider lanes, olive
                  selected path). The tables below carry the same payload —
                  the graph is the visual alternative, not a second data
                  source. */}
              <RoutingGraphSection map={map} />
              <ChainsSection map={map} warningsFor={warningsFor} />
              <AliasesSection map={map} warningsFor={warningsFor} />
              <RulesSection map={map} warningsFor={warningsFor} />
            </>
          )}

          {healthState === 'failed' && <StateNotice state="error" message={t('routingMap.healthFailed')} />}
          {healthState === 'loading' && <StateNotice state="loading" />}
          {healthState === 'ready' && health && (
            <HealthSection health={health} modelRows={modelRows} />
          )}
        </div>
      )}
    </div>
  )
}

// ===== Configuration warnings =====

function WarningsPanel({ warnings }: { warnings: RoutingMapWarning[] }) {
  const { t } = useTranslation()
  if (warnings.length === 0) {
    return <StateNotice state="empty" title={t('routingMap.warningsTitle')} message={t('routingMap.noWarnings')} />
  }
  return (
    <section className="astra-panel flex flex-col gap-2 px-4 py-4" data-testid="routing-warnings" aria-label={t('routingMap.warningsTitle')}>
      <h2 className="flex items-center gap-2 text-base font-semibold" style={{ color: 'var(--astra-warning)' }}>
        <span aria-hidden="true">△</span>
        {t('routingMap.warningsTitle')}
      </h2>
      <ul className="space-y-1">
        {warnings.map((w, i) => (
          <li
            key={`${w.scope}:${w.source}:${w.code}:${w.target ?? ''}:${i}`}
            data-testid="routing-warning"
            className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm"
          >
            <span className="font-medium" style={{ color: 'var(--astra-warning)' }}>{warnLabel(w.code, t)}</span>
            <span className="text-[color:var(--astra-text-muted)]">{scopeLabel(w.scope, t)}</span>
            <span className="overflow-wrap-anywhere min-w-0" style={{ font: '13px/1.5 var(--astra-font-code)' }}>
              {w.source}{w.target ? ` → ${w.target}` : ''}
            </span>
            <span className="overflow-wrap-anywhere min-w-0 text-[color:var(--astra-text-muted)]">{w.message}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function WarnChips({ warnings }: { warnings: RoutingMapWarning[] }) {
  const { t } = useTranslation()
  if (warnings.length === 0) return <span className="text-[color:var(--astra-text-muted)]" aria-label={t('routingMap.noWarnings')}>—</span>
  return (
    <span className="flex flex-wrap gap-1">
      {warnings.map((w, i) => (
        <span
          key={`${w.code}:${w.target ?? ''}:${i}`}
          title={w.message}
          data-testid={`routing-warning-chip-${w.code}`}
          className="rounded border px-1.5 py-0.5 text-xs"
          style={{ color: 'var(--astra-warning)', borderColor: 'var(--astra-warning)' }}
        >
          ▲ {warnLabel(w.code, t)}{w.target ? `: ${w.target}` : ''}
        </span>
      ))}
    </span>
  )
}

// ===== Failover chains =====

function ChainView({ steps }: { steps: string[] }) {
  return (
    <span className="overflow-wrap-anywhere" style={{ font: '13px/1.6 var(--astra-font-code)' }}>
      {steps.map((s, i) => (
        <span key={`${s}:${i}`}>
          {i > 0 && <span aria-hidden="true" className="mx-1 text-[color:var(--astra-text-muted)]">→</span>}
          {s}
        </span>
      ))}
    </span>
  )
}

function StatusChip({ enabled, t }: { enabled: boolean; t: T }) {
  const color = enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)'
  return (
    <span className="inline-flex items-center gap-1 text-sm" style={{ color }}>
      <span aria-hidden="true">{enabled ? '●' : '○'}</span>
      {enabled ? t('routingMap.statusEnabled') : t('routingMap.statusDisabled')}
    </span>
  )
}

function requestsHref(model: string): string {
  // UI-contract #9: the current hash query (org, period, locale) is carried;
  // the model filter is prefilled on the explorer.
  return relatedListHref('requests-explorer', currentHashQuery(), { model })
}

function RequestsLink({ model }: { model: string }) {
  const { t } = useTranslation()
  return (
    <a
      href={requestsHref(model)}
      className="underline decoration-dotted underline-offset-2"
      data-testid={`routing-requests-${model}`}
    >
      {t('routingMap.openRequests')}
    </a>
  )
}

function ChainsSection({ map, warningsFor }: {
  map: RoutingMap
  warningsFor: (scope: string, source: string) => RoutingMapWarning[]
}) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns: DataTableColumn<RoutingMapModel>[] = [
    {
      key: 'model_name', header: t('routingMap.colModel'), type: 'text', mono: true,
      render: m => <span title={m.display_name}>{m.model_name}</span>,
    },
    { key: 'provider', header: t('routingMap.colProvider'), type: 'text', mono: true },
    {
      key: 'enabled', header: t('routingMap.colStatus'), type: 'number',
      getSortValue: m => (m.enabled ? 1 : 0),
      render: m => <StatusChip enabled={m.enabled} t={t} />,
    },
    {
      key: 'chain', header: t('routingMap.colChain'), type: 'text',
      headerHint: t('routingMap.chainsHint'),
      getSortValue: m => chainSteps(m).join(' → '),
      render: m => <ChainView steps={chainSteps(m)} />,
    },
    {
      key: 'warnings', header: t('routingMap.colWarnings'), sortable: false,
      render: m => <WarnChips warnings={warningsFor('model', m.model_name)} />,
    },
  ]
  return (
    <section className="space-y-2">
      <h2 className="text-base font-semibold">{t('routingMap.chainsTitle')}</h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('routingMap.chainsHint')}</p>
      <DataTable
        columns={columns}
        rows={map.models}
        getRowId={m => m.model_name}
        page={page}
        pageSize={50}
        onPageChange={setPage}
        caption={t('routingMap.chainsTitle')}
        empty={t('routingMap.emptyChains')}
        renderActions={m => <RequestsLink model={m.model_name} />}
      />
    </section>
  )
}

// ===== Aliases and routing rules =====

function AliasesSection({ map, warningsFor }: {
  map: RoutingMap
  warningsFor: (scope: string, source: string) => RoutingMapWarning[]
}) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns: DataTableColumn<{ alias: string; target_model: string }>[] = [
    { key: 'alias', header: t('routingMap.colAlias'), type: 'text', mono: true },
    { key: 'target_model', header: t('routingMap.colTarget'), type: 'text', mono: true },
    {
      key: 'warnings', header: t('routingMap.colWarnings'), sortable: false,
      render: r => <WarnChips warnings={warningsFor('alias', r.alias)} />,
    },
  ]
  return (
    <section className="space-y-2">
      <h2 className="text-base font-semibold">{t('routingMap.aliasesTitle')}</h2>
      <DataTable
        columns={columns}
        rows={map.aliases}
        getRowId={a => a.alias}
        page={page}
        pageSize={50}
        onPageChange={setPage}
        caption={t('routingMap.aliasesTitle')}
        empty={t('routingMap.emptyAliases')}
        renderActions={a => <RequestsLink model={a.target_model} />}
      />
    </section>
  )
}

function RulesSection({ map, warningsFor }: {
  map: RoutingMap
  warningsFor: (scope: string, source: string) => RoutingMapWarning[]
}) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns: DataTableColumn<RoutingMapRule>[] = [
    { key: 'match_expr', header: t('routingMap.colRule'), type: 'text', mono: true },
    { key: 'priority', header: t('routingMap.colPriority'), type: 'number', align: 'right' },
    {
      key: 'enabled', header: t('routingMap.colEnabled'), type: 'number',
      getSortValue: r => (r.enabled ? 1 : 0),
      render: r => <StatusChip enabled={r.enabled} t={t} />,
    },
    { key: 'target_model', header: t('routingMap.colTarget'), type: 'text', mono: true },
    {
      key: 'warnings', header: t('routingMap.colWarnings'), sortable: false,
      render: r => <WarnChips warnings={warningsFor('rule', r.id)} />,
    },
  ]
  return (
    <section className="space-y-2">
      <h2 className="text-base font-semibold">{t('routingMap.rulesTitle')}</h2>
      <DataTable
        columns={columns}
        rows={map.rules}
        getRowId={r => r.id}
        page={page}
        pageSize={50}
        onPageChange={setPage}
        caption={t('routingMap.rulesTitle')}
        empty={t('routingMap.emptyRules')}
        renderActions={r => <RequestsLink model={r.target_model} />}
      />
    </section>
  )
}

// ===== Provider health =====

// Plain-SVG traffic sparkline: one bar per model (∝ requests), warning-tinted
// when the model served errors. No chart library — the numbers stay in the
// neighboring columns; the bars only shape the mix.
function TrafficSpark({ models }: { models: ProviderHealthModel[] }) {
  const { t } = useTranslation()
  const shown = models.slice(0, 12)
  if (shown.length === 0) return <span className="text-[color:var(--astra-text-muted)]">—</span>
  const max = Math.max(1, ...shown.map(m => m.requests))
  const bw = 8
  const gap = 2
  const h = 24
  return (
    <svg
      role="img"
      aria-label={t('routingMap.sparkAria', {
        breakdown: models.map(m => `${m.model} ${m.requests}`).join(', '),
      })}
      width={shown.length * (bw + gap)}
      height={h}
      className="align-middle"
    >
      {shown.map((m, i) => {
        const bh = Math.max(2, Math.round((m.requests / max) * (h - 2)))
        return (
          <rect
            key={m.model}
            x={i * (bw + gap)}
            y={h - bh}
            width={bw}
            height={bh}
            rx="1"
            fill={m.errors > 0 ? 'var(--astra-warning)' : 'var(--astra-accent)'}
          >
            <title>{`${m.model}: ${m.requests}`}</title>
          </rect>
        )
      })}
    </svg>
  )
}

type HealthModelRow = ProviderHealthModel & { provider: string }

function LastErrorCell({ row }: { row: HealthModelRow }) {
  const { t } = useTranslation()
  if (!row.last_error) {
    return <span className="text-[color:var(--astra-text-muted)]" aria-label={t('common.notRecorded')}>—</span>
  }
  return (
    <span className="flex min-w-0 flex-col">
      <span className="overflow-wrap-anywhere min-w-0" title={row.last_error}>{row.last_error}</span>
      {row.last_error_at && (
        <span className="text-xs text-[color:var(--astra-text-muted)]">{formatDateTime(row.last_error_at)}</span>
      )}
    </span>
  )
}

function HealthSection({ health, modelRows }: {
  health: ProviderHealthReport
  modelRows: HealthModelRow[]
}) {
  const { t } = useTranslation()
  const [providerPage, setProviderPage] = useState(1)
  const [modelPage, setModelPage] = useState(1)
  if (health.providers.length === 0) {
    return (
      <section className="space-y-2">
        <h2 className="text-base font-semibold">{t('routingMap.healthTitle')}</h2>
        <StateNotice state="empty" message={t('routingMap.emptyHealth')} />
      </section>
    )
  }
  const providerColumns: DataTableColumn<ProviderHealth>[] = [
    { key: 'provider', header: t('routingMap.colProvider'), type: 'text', mono: true },
    { key: 'requests', header: t('routingMap.colRequests'), format: 'number', align: 'right' },
    { key: 'errors', header: t('routingMap.colErrors'), format: 'number', align: 'right' },
    { key: 'error_rate', header: t('routingMap.colErrorRate'), format: 'percent', align: 'right' },
    {
      key: 'models', header: t('routingMap.colTraffic'), sortable: false,
      render: p => <TrafficSpark models={p.models} />,
    },
  ]
  const modelColumns: DataTableColumn<HealthModelRow>[] = [
    { key: 'provider', header: t('routingMap.colProvider'), type: 'text', mono: true },
    { key: 'model', header: t('routingMap.colModel'), type: 'text', mono: true },
    { key: 'requests', header: t('routingMap.colRequests'), format: 'number', align: 'right' },
    { key: 'errors', header: t('routingMap.colErrors'), format: 'number', align: 'right' },
    { key: 'error_rate', header: t('routingMap.colErrorRate'), format: 'percent', align: 'right' },
    { key: 'p50_ms', header: t('routingMap.colP50'), format: 'duration', unit: 'ms', align: 'right' },
    { key: 'p95_ms', header: t('routingMap.colP95'), format: 'duration', unit: 'ms', align: 'right' },
    { key: 'last_error', header: t('routingMap.colLastError'), sortable: false, render: r => <LastErrorCell row={r} /> },
  ]
  return (
    <section className="space-y-4">
      <h2 className="text-base font-semibold">{t('routingMap.healthTitle')}</h2>
      <DataTable
        columns={providerColumns}
        rows={health.providers}
        getRowId={p => p.provider}
        page={providerPage}
        pageSize={50}
        onPageChange={setProviderPage}
        caption={t('routingMap.healthTitle')}
      />
      <DataTable
        columns={modelColumns}
        rows={modelRows}
        getRowId={r => `${r.provider}:${r.model}`}
        page={modelPage}
        pageSize={50}
        onPageChange={setModelPage}
        caption={`${t('routingMap.healthTitle')} · ${t('routingMap.colModel')}`}
        renderActions={r => <RequestsLink model={r.model} />}
      />
    </section>
  )
}

/** Copy for a failed map load, branched on the HTTP status the API contract defines. */
function mapFailCopy(status: number | undefined, t: T): string {
  if (status === 401 || status === 403) return t('routingMap.mapSessionRequired')
  if (status === 404) return t('routingMap.mapNoAccess')
  return t('routingMap.mapFailed')
}

/**
 * The failed-map notice: what the API contract actually means by the status
 * (session/permission; the API answers 404 for a foreign org AND for a
 * member without routing permission — indistinguishable by design, so the
 * copy says both), plus the one useful next action: retry.
 */
function MapStateNotices({ error, onRetry }: { error: { status?: number; message: string } | null; onRetry: () => void }) {
  const { t } = useTranslation()
  return (
    <StateNotice
      state="error"
      message={mapFailCopy(error?.status, t)}
      action={{ label: t('common.retry'), onClick: onRetry }}
    />
  )
}

/**
 * The partial input, named: targets that chains/aliases/rules point at but
 * that have no registry row. The graph shows them as dashed phantoms; this
 * notice says the same fact in words (code font, not a fake table).
 */
function MissingTargetsNotice({ names }: { names: string[] }) {
  const { t } = useTranslation()
  if (names.length === 0) return null
  return (
    <StateNotice
      state="partial"
      message={t('routingMap.mapPartial')}
      details={
        <span style={{ fontFamily: 'var(--astra-font-code)' }}>
          {names.join(' · ')}
        </span>
      }
    />
  )
}

/**
 * Map-scope status notices, extracted so the page body stays flat: failed
 * copy (status-branched) or the loading/stale distinction — a refresh with
 * no data yet is "loading", a refresh over still-renderable data is
 * "stale" and keeps the graph visible below.
 */
function MapStatusBlock({ mapState, map, mapError, onRetry }: {
  mapState: LoadState
  map: RoutingMap | null
  mapError: { status?: number; message: string } | null
  onRetry: () => void
}) {
  const { t } = useTranslation()
  if (mapState === 'failed') {
    return <MapStateNotices error={mapError} onRetry={onRetry} />
  }
  if (mapState === 'loading') {
    return map === null
      ? <StateNotice state="loading" />
      : <StateNotice state="stale" message={t('routingMap.mapStale')} />
  }
  return null
}
