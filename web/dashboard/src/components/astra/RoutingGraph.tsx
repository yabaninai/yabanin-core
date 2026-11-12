// CV-01 (V01 rendering child): the configuration-topology visualizer.
//
// Honesty contract (yabanin-contracts, engineering.md "no fake success"):
//  * ONE input: the /api/routing/map payload, through the pure models in
//    lib/routingGraph.ts (phantoms, warning attachment, chain ownership) and
//    lib/routingTopology.ts (provider lane, selected path, band layout).
//    Chains render in the gateway's own attempt order; missing targets render
//    as dashed phantoms; warnings are the server's codes — this view never
//    re-derives a verdict.
//  * Provider nodes are the only structural addition: one node per distinct
//    models[].provider, one uniform config edge per registry model. A missing
//    phantom has no registry row, so it never gets a provider edge — no
//    invented provider.
//  * Edges are configuration facts: one uniform width for every edge; the
//    kind is encoded by dash pattern and color, never by traffic-like
//    emphasis. Selecting a node highlights the configuration path through it
//    in the olive selection color and dims everything off that path; it does
//    not widen anything (width would read as volume, and this view has none).
//  * The mode selector keeps the three routing-viz modes unmixed: only
//    "possible routes" exists today; "recorded paths" and "simulation" are
//    disabled WITH a visible reason — never silently merged into the
//    configuration view, and the map never pretends to be recorded traffic.
//  * The tables in RoutingMapPage stay the table alternative carrying the
//    same payload; the graph is additive, not a replacement.
//  * Plain SVG, astra tokens only, no chart library, no animation beyond the
//    140ms opacity/stroke transition on selection (none under
//    prefers-reduced-motion).
import { useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { RoutingMap } from '../../api/routing'
import { currentHashQuery, relatedListHref } from '../../lib/inspectUrl'
import { edgeEndpoints, isBackEdge, nearestNode, type NavDir, type NodeBox } from '../../lib/routingGraph'
import {
  buildTopology, focusTopology, layoutTopology, selectionPath,
  type TopoEdge, type TopoNode, type TopoNodeKind, type TopoBand, type TopologyView, type SelectionPath,
} from '../../lib/routingTopology'
import { StateNotice } from './StateNotice'

type T = ReturnType<typeof useTranslation>['t']

/** One uniform width: edges are config facts, not traffic volumes. */
const EDGE_W = 1.5
const EDGE_STROKE: Record<TopoEdge['kind'], string> = {
  chain: 'var(--astra-accent)',
  alias: 'var(--astra-info)',
  rule: 'var(--astra-ink)',
  provider: 'var(--astra-rule-strong)',
}
const EDGE_DASH: Record<TopoEdge['kind'], string> = {
  chain: '',
  alias: '7 4',
  rule: '2 3',
  provider: '1 4',
}
const EDGE_KIND_KEY: Record<TopoEdge['kind'], string> = {
  chain: 'routingMap.graphLegendChain',
  alias: 'routingMap.graphLegendAlias',
  rule: 'routingMap.graphLegendRule',
  provider: 'routingMap.graphLegendProvider',
}
const NODE_KIND_KEY: Record<TopoNodeKind, string> = {
  model: 'routingMap.scopeModel',
  alias: 'routingMap.scopeAlias',
  rule: 'routingMap.scopeRule',
  missing: 'routingMap.graphMissing',
  provider: 'routingMap.colProvider',
}
/** Stable warning code → localized label; unknown codes stay raw. */
const WARN_KEY: Record<string, string> = {
  chain_cycle: 'routingMap.warnCycle',
  chain_target_missing: 'routingMap.warnTargetMissing',
  alias_target_missing: 'routingMap.warnTargetMissing',
  rule_target_missing: 'routingMap.warnTargetMissing',
  chain_target_disabled: 'routingMap.warnTargetDisabled',
  alias_target_disabled: 'routingMap.warnTargetDisabled',
  rule_target_disabled: 'routingMap.warnTargetDisabled',
}
const NODE_GLYPH: Record<TopoNodeKind, string> = { model: 'M', alias: 'A', rule: 'R', missing: '?', provider: 'P' }
const BAND_KEY: Record<TopoBand, string> = {
  alias: 'routingMap.laneAliases',
  rule: 'routingMap.laneRules',
  model: 'routingMap.laneModels',
  provider: 'routingMap.laneProviders',
}
const NAV: Record<string, NavDir> = { ArrowLeft: 'left', ArrowRight: 'right', ArrowUp: 'up', ArrowDown: 'down' }
/** Kinds that carry an enabled/disabled registry status line. */
const STATUS_KINDS = new Set<TopoNodeKind>(['model', 'rule'])

const safeId = (id: string) => id.replace(/[^A-Za-z0-9._-]+/g, '-')
const warnLabel = (code: string, t: T) => (WARN_KEY[code] !== undefined ? t(WARN_KEY[code]) : code)
const kindLabel = (kind: TopoNodeKind, t: T) => t(NODE_KIND_KEY[kind])
const fitLabel = (label: string) => (label.length > 24 ? `${label.slice(0, 23)}…` : label)

/** SVG path for one edge: straight, a sagging back-edge curve, or a loop. */
function edgeD(a: { x: number; y: number }, b: { x: number; y: number }, self: boolean, back: boolean): string {
  if (self) {
    return `M ${a.x} ${a.y} C ${a.x - 36} ${a.y - 58}, ${b.x + 36} ${b.y - 58}, ${b.x} ${b.y}`
  }
  if (back) {
    const sag = Math.max(70, Math.abs(b.x - a.x) * 0.4)
    return `M ${a.x} ${a.y} C ${a.x} ${a.y + sag}, ${b.x} ${b.y + sag}, ${b.x} ${b.y}`
  }
  return `M ${a.x} ${a.y} L ${b.x} ${b.y}`
}

/** Stroke and arrowhead for one edge: the olive path wins, then a warning. */
function edgePaint(edge: TopoEdge, onPath: boolean): { stroke: string; markerId: string } {
  if (onPath) return { stroke: 'var(--astra-selection)', markerId: 'rg-arrow-selected' }
  if (edge.warningCodes.length > 0) return { stroke: 'var(--astra-danger)', markerId: 'rg-arrow-warn' }
  return { stroke: EDGE_STROKE[edge.kind], markerId: `rg-arrow-${edge.kind}` }
}

/** Uniform opacity ladder: search-dim < off-path-dim < full. */
function edgeOpacity(focusDim: boolean, onPath: boolean, hasSelection: boolean): number {
  if (focusDim) return 0.15
  return hasSelection && !onPath ? 0.35 : 1
}

/** Same ladder for nodes, with the stronger search-dim floor. */
function nodeOpacity(dim: boolean, onPath: boolean, hasSelection: boolean): number {
  if (dim) return 0.18
  return hasSelection && !onPath ? 0.35 : 1
}

function edgeTitle(edge: TopoEdge, labelOf: (id: string) => string, t: T): string {
  const kind = t(EDGE_KIND_KEY[edge.kind])
  const hop = edge.kind === 'chain' ? ` (${t('routingMap.graphHop', { n: edge.label })})` : ''
  return `${kind}: ${labelOf(edge.from)} → ${labelOf(edge.to)}${hop}`
}

/** Second line under the label: status, alias target, or the phantom mark. */
function nodeStatus(node: TopoNode, t: T): string {
  if (node.kind === 'missing') return t('routingMap.graphMissing')
  if (node.kind === 'alias') return node.sublabel
  if (node.kind === 'provider') return ''
  return node.enabled ? t('routingMap.statusEnabled') : t('routingMap.statusDisabled')
}

function nodeStroke(node: TopoNode, isSelected: boolean, isMatch: boolean): string {
  if (isSelected) return 'var(--astra-selection)'
  if (isMatch) return 'var(--astra-focus)'
  if (node.kind === 'missing') return 'var(--astra-danger)'
  return 'var(--astra-rule-strong)'
}

/** Full accessible name: kind, label, provider, status, warning codes. */
function nodeAria(node: TopoNode, t: T): string {
  return [
    `${kindLabel(node.kind, t)}, ${node.label}`,
    node.provider ?? '',
    nodeStatus(node, t),
    node.warningCodes.length > 0
      ? `${t('routingMap.colWarnings')}: ${node.warningCodes.map(c => warnLabel(c, t)).join(', ')}`
      : '',
  ]
    .filter(part => part !== '')
    .join(', ')
}

/** Does this edge flow out of the node (owner ⇒ outgoing, even mid-chain)? */
function flowOut(edge: TopoEdge, nodeId: string): boolean {
  return edge.from === nodeId || (edge.owner === nodeId && edge.to !== nodeId)
}

/** Inspector flow detail: hop number for chains, kind (· tag) otherwise. */
function flowDetail(edge: TopoEdge, t: T): string {
  const kind = t(EDGE_KIND_KEY[edge.kind])
  if (edge.kind === 'chain') return t('routingMap.graphHop', { n: edge.label })
  return edge.label !== '' ? `${kind} · ${edge.label}` : kind
}

export function RoutingGraphSection({ map }: { map: RoutingMap }) {
  const { t } = useTranslation()
  const view = useMemo(() => buildTopology(map), [map])
  const layout = useMemo(() => layoutTopology(view), [view])
  const byId = useMemo(() => new Map(view.nodes.map(n => [n.id, n])), [view])
  // Deterministic DOM ids for roving focus (index-based: unique by construction).
  const domId = useMemo(() => {
    const idx = new Map<string, string>()
    view.nodes.forEach((n, i) => idx.set(n.id, `rg-node-${i}`))
    return idx
  }, [view])

  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const focus = useMemo(() => focusTopology(view, query), [view, query])
  const path = useMemo(() => selectionPath(view, selectedId), [view, selectedId])
  const searchRef = useRef<HTMLInputElement>(null)

  if (view.nodes.length === 0) {
    return (
      <section className="astra-panel space-y-2 px-4 py-4">
        <h2 className="text-base font-semibold">{t('routingMap.graphTitle')}</h2>
        <StateNotice state="empty" message={t('routingMap.graphEmpty')} />
      </section>
    )
  }

  const selected = selectedId !== null ? byId.get(selectedId) ?? null : null
  // Selected stays fully visible even when dimmed by the search focus.
  const visible = (id: string) => focus.focusIds.has(id) || id === selectedId
  const labelOf = (id: string) => byId.get(id)?.label ?? id

  const moveFocus = (from: string, dir: NavDir) => {
    // Arrow keys walk the VISIBLE subgraph only — navigating into a dimmed
    // node would silently drop the user's search focus.
    const boxes = new Map([...layout.boxes].filter(([id]) => visible(id)))
    const next = nearestNode(boxes, from, dir)
    if (next === null) return
    const el = document.getElementById(domId.get(next) ?? '')
    el?.focus()
  }

  const onNodeKeyDown = (event: KeyboardEvent, id: string) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      setSelectedId(prev => (prev === id ? null : id))
      return
    }
    const dir = NAV[event.key]
    if (dir !== undefined) {
      event.preventDefault()
      moveFocus(id, dir)
    }
  }

  return (
    <section className="astra-panel space-y-3 px-4 py-4" data-testid="routing-graph" aria-label={t('routingMap.graphTitle')}>
      <div>
        <h2 className="text-base font-semibold">{t('routingMap.graphTitle')}</h2>
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('routingMap.graphHint')}</p>
      </div>

      <GraphModes />

      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-2 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('routingMap.graphSearchLabel')}</span>
          <input
            ref={searchRef}
            type="search"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={t('routingMap.graphSearchPlaceholder')}
            data-testid="routing-graph-search"
            className="min-h-[36px] w-64 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-paper)] px-2 text-sm"
          />
        </label>
        <button
          type="button"
          onClick={() => { setQuery(''); setSelectedId(null); searchRef.current?.focus() }}
          data-testid="routing-graph-reset"
          className="min-h-[36px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-3 text-sm hover:bg-[color:var(--astra-surface-muted)]"
        >
          {t('routingMap.graphReset')}
        </button>
        <MatchCount view={view} query={query} matched={focus.matchedIds.size} noMatches={focus.noMatches} />
      </div>

      <div className="flex flex-wrap items-start gap-4">
        <div className="max-w-full min-w-0 flex-1 overflow-auto rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] p-1">
          <TopologyCanvas
            view={view}
            layout={layout}
            visible={visible}
            path={path}
            hasSelection={selectedId !== null}
            selectedId={selectedId}
            matchedIds={focus.matchedIds}
            domId={domId}
            labelOf={labelOf}
            onSelect={id => setSelectedId(prev => (prev === id ? null : id))}
            onNodeKeyDown={onNodeKeyDown}
          />
        </div>

        {selected && (
          <NodeInspector
            map={map}
            view={view}
            node={selected}
            labelOf={labelOf}
            onClear={() => {
              setSelectedId(null)
              const el = document.getElementById(domId.get(selected.id) ?? '')
              el?.focus()
            }}
          />
        )}
      </div>

      <GraphLegend />
    </section>
  )
}

/** The three routing-viz modes, never mixed: one real, two disabled with a visible reason. */
function GraphModes() {
  const { t } = useTranslation()
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">
        {t('routingMap.graphModes')}
      </legend>
      <div className="flex flex-wrap items-center gap-2">
        <label className="inline-flex min-h-[36px] cursor-default items-center gap-2 rounded-[length:var(--astra-radius-control)] border px-3 text-sm"
          style={{ borderColor: 'var(--astra-accent)', background: 'var(--astra-accent-surface)' }}>
          <input type="radio" name="routing-map-mode" defaultChecked data-testid="routing-graph-mode-config"
            className="accent-[color:var(--astra-accent)]" />
          {t('routingMap.graphModeConfig')}
        </label>
        <label className="inline-flex min-h-[36px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-3 text-sm opacity-60">
          <input type="radio" name="routing-map-mode" disabled aria-describedby="routing-graph-mode-recorded-reason"
            data-testid="routing-graph-mode-recorded" className="accent-[color:var(--astra-accent)]" />
          {t('routingMap.graphModeRecorded')}
        </label>
        <label className="inline-flex min-h-[36px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-3 text-sm opacity-60">
          <input type="radio" name="routing-map-mode" disabled aria-describedby="routing-graph-mode-simulation-reason"
            data-testid="routing-graph-mode-simulation" className="accent-[color:var(--astra-accent)]" />
          {t('routingMap.graphModeSimulation')}
        </label>
      </div>
      <p id="routing-graph-mode-recorded-reason" className="text-xs text-[color:var(--astra-text-muted)]">
        {t('routingMap.graphModeRecordedReason')}
      </p>
      <p id="routing-graph-mode-simulation-reason" className="text-xs text-[color:var(--astra-text-muted)]">
        {t('routingMap.graphModeSimulationReason')}
      </p>
    </fieldset>
  )
}

/** "N nodes · M edges — matched x of y / no match" beside the search box. */
function MatchCount({ view, query, matched, noMatches }: {
  view: TopologyView
  query: string
  matched: number
  noMatches: boolean
}) {
  const { t } = useTranslation()
  const suffix = query.trim() === ''
    ? ''
    : noMatches
      ? ` — ${t('routingMap.graphNoMatch')}`
      : ` — ${t('routingMap.graphMatches', { matched, total: view.nodes.length })}`
  return (
    <span className="text-sm text-[color:var(--astra-text-muted)]" data-testid="routing-graph-count">
      {t('routingMap.graphCount', { nodes: view.nodes.length, edges: view.edges.length })}{suffix}
    </span>
  )
}

/** The SVG canvas: band headers, then edges, then nodes (nodes paint last). */
function TopologyCanvas({ view, layout, visible, path, hasSelection, selectedId, matchedIds, domId, labelOf, onSelect, onNodeKeyDown }: {
  view: TopologyView
  layout: ReturnType<typeof layoutTopology>
  visible: (id: string) => boolean
  path: SelectionPath
  hasSelection: boolean
  selectedId: string | null
  matchedIds: Set<string>
  domId: Map<string, string>
  labelOf: (id: string) => string
  onSelect: (id: string) => void
  onNodeKeyDown: (event: KeyboardEvent, id: string) => void
}) {
  const { t } = useTranslation()
  return (
    <svg
      role="group"
      className="routing-topo"
      aria-label={t('routingMap.graphAria', { nodes: view.nodes.length, edges: view.edges.length })}
      width={layout.width}
      height={layout.height}
      data-testid="routing-graph-canvas"
    >
      <defs>
        {(['chain', 'alias', 'rule', 'provider'] as const).map(kind => (
          <marker key={kind} id={`rg-arrow-${kind}`} viewBox="0 0 10 10" refX={8.5} refY={5}
            markerWidth={6.5} markerHeight={6.5} orient="auto-start-reverse">
            <polygon points="0,0 10,5 0,10" fill={EDGE_STROKE[kind]} />
          </marker>
        ))}
        <marker id="rg-arrow-warn" viewBox="0 0 10 10" refX={8.5} refY={5}
          markerWidth={6.5} markerHeight={6.5} orient="auto-start-reverse">
          <polygon points="0,0 10,5 0,10" fill="var(--astra-danger)" />
        </marker>
        <marker id="rg-arrow-selected" viewBox="0 0 10 10" refX={8.5} refY={5}
          markerWidth={6.5} markerHeight={6.5} orient="auto-start-reverse">
          <polygon points="0,0 10,5 0,10" fill="var(--astra-selection)" />
        </marker>
      </defs>

      {layout.headers.map(h => (
        <text key={h.band} x={h.x + 2} y={12} fontSize={10} fill="var(--astra-text-muted)"
          fontFamily="var(--astra-font-ui)" letterSpacing={0.4}>
          {t(BAND_KEY[h.band]).toUpperCase()}
        </text>
      ))}

      {view.edges.map(edge => {
        const from = layout.boxes.get(edge.from)
        const to = layout.boxes.get(edge.to)
        if (from === undefined || to === undefined) return null
        return (
          <TopoEdgeView
            key={edge.id}
            edge={edge}
            from={from}
            to={to}
            focusDim={!(visible(edge.from) && visible(edge.to))}
            onPath={path.edgeIds.has(edge.id)}
            hasSelection={hasSelection}
            labelOf={labelOf}
          />
        )
      })}

      {view.nodes.map(node => {
        const box = layout.boxes.get(node.id)
        if (box === undefined) return null
        return (
          <TopoNodeView
            key={node.id}
            node={node}
            box={box}
            dim={!visible(node.id)}
            onPath={path.nodeIds.has(node.id)}
            hasSelection={hasSelection}
            isMatch={matchedIds.has(node.id)}
            isSelected={node.id === selectedId}
            domId={domId.get(node.id) ?? node.id}
            onSelect={onSelect}
            onNodeKeyDown={onNodeKeyDown}
          />
        )
      })}
    </svg>
  )
}

/** One directed config edge: uniform width, dash by kind, olive on the path. */
function TopoEdgeView({ edge, from, to, focusDim, onPath, hasSelection, labelOf }: {
  edge: TopoEdge
  from: NodeBox
  to: NodeBox
  focusDim: boolean
  onPath: boolean
  hasSelection: boolean
  labelOf: (id: string) => string
}) {
  const { t } = useTranslation()
  const { a, b } = edgeEndpoints(from, to)
  const self = edge.from === edge.to
  const back = !self && isBackEdge(from, to)
  const { stroke, markerId } = edgePaint(edge, onPath)
  const opacity = edgeOpacity(focusDim, onPath, hasSelection)
  const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - (self ? 30 : 0) }
  return (
    <g className="topo-edge" data-testid="routing-graph-edge" opacity={opacity}>
      <path
        d={edgeD(a, b, self, back)}
        fill="none"
        stroke={stroke}
        strokeWidth={EDGE_W}
        strokeDasharray={EDGE_DASH[edge.kind] || undefined}
        markerEnd={`url(#${markerId})`}
      >
        <title>{edgeTitle(edge, labelOf, t)}</title>
      </path>
      {edge.label !== '' && !focusDim && (
        <text x={mid.x} y={mid.y} textAnchor="middle" dominantBaseline="middle"
          fontSize={10} fontFamily="var(--astra-font-code)" fill="var(--astra-text-muted)"
          paintOrder="stroke" stroke="var(--astra-paper)" strokeWidth={3}>
          {edge.label}
        </text>
      )}
    </g>
  )
}

/** Second status line text: ✕ for phantoms, ●/○ + text for registry rows. */
function nodeStatusLine(node: TopoNode, status: string): string {
  const prefix = node.kind === 'missing' ? '✕ ' : STATUS_KINDS.has(node.kind) ? `${node.enabled ? '●' : '○'} ` : ''
  return `${prefix}${status}`
}

/** One node box: kind glyph, label, status line (●/○ for model/rule), △ warnings. */
function TopoNodeView({ node, box, dim, onPath, hasSelection, isMatch, isSelected, domId, onSelect, onNodeKeyDown }: {
  node: TopoNode
  box: NodeBox
  dim: boolean
  onPath: boolean
  hasSelection: boolean
  isMatch: boolean
  isSelected: boolean
  domId: string
  onSelect: (id: string) => void
  onNodeKeyDown: (event: KeyboardEvent, id: string) => void
}) {
  const { t } = useTranslation()
  const aria = nodeAria(node, t)
  const status = nodeStatus(node, t)
  const opacity = nodeOpacity(dim, onPath, hasSelection)
  return (
    <g
      id={domId}
      className="topo-node"
      role="button"
      tabIndex={dim ? -1 : 0}
      aria-label={aria}
      aria-pressed={isSelected}
      data-testid={`routing-graph-node-${safeId(node.id)}`}
      opacity={opacity}
      cursor="pointer"
      onClick={() => onSelect(node.id)}
      onKeyDown={e => onNodeKeyDown(e, node.id)}
    >
      <title>{aria}</title>
      <rect
        x={box.x} y={box.y} width={box.w} height={box.h} rx={8}
        fill="var(--astra-paper)"
        stroke={nodeStroke(node, isSelected, isMatch)}
        strokeWidth={isMatch || isSelected ? 2.5 : 1.25}
        strokeDasharray={node.kind === 'missing' ? '6 4' : undefined}
      />
      <text x={box.x + 10} y={box.y + 15} fontSize={9} fill="var(--astra-text-muted)" fontFamily="var(--astra-font-code)">
        <tspan aria-hidden="true">{NODE_GLYPH[node.kind]}</tspan>
      </text>
      <text x={box.x + 24} y={box.y + 17} fontSize={12} fontFamily="var(--astra-font-code)" fill="var(--astra-ink)">
        {fitLabel(node.label)}
      </text>
      {status !== '' && (
        <text x={box.x + 10} y={box.y + 34} fontSize={10} fill="var(--astra-text-muted)">
          {nodeStatusLine(node, status)}
        </text>
      )}
      {STATUS_KINDS.has(node.kind) && (
        <text x={box.x + box.w - 12} y={box.y + 34} fontSize={9} textAnchor="end"
          fill={node.enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)'}>
          {node.enabled ? '●' : '○'}
        </text>
      )}
      {node.warningCodes.length > 0 && (
        <text x={box.x + box.w - 10} y={box.y + 16} fontSize={11} textAnchor="end" fill="var(--astra-warning)" aria-hidden="true">△</text>
      )}
    </g>
  )
}

/** Server warnings that address this node (scope+source), with their messages. */
function NodeWarnings({ map, node }: { map: RoutingMap; node: TopoNode }) {
  const { t } = useTranslation()
  const scope = node.kind
  const source = node.kind === 'model' || node.kind === 'alias' ? node.label : node.rule?.id ?? ''
  const rows = map.warnings.filter(w => w.scope === scope && w.source === source)
  if (rows.length === 0) return null
  return (
    <div className="mt-2 flex flex-col gap-1">
      <p className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('routingMap.colWarnings')}</p>
      <ul className="flex flex-col gap-1">
        {rows.map((w, i) => (
          <li key={`${w.code}:${i}`} className="text-sm">
            <span style={{ color: 'var(--astra-warning)' }}>▲ {warnLabel(w.code, t)}{w.target ? `: ${w.target}` : ''}</span>
            <span className="block text-xs text-[color:var(--astra-text-muted)]">{w.message}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** One flow row in the inspector: direction, other end, kind, warnings. */
function FlowRow({ edge, node, byId, labelOf }: {
  edge: TopoEdge
  node: TopoNode
  byId: Map<string, TopoNode>
  labelOf: (id: string) => string
}) {
  const { t } = useTranslation()
  // Outgoing unless this node is purely the edge's destination. A chain's
  // hop 2+ starts at the previous hop's node, but it still flows out of the
  // owning model's config — so owner ⇒ outgoing.
  const out = flowOut(edge, node.id)
  const other = byId.get(out ? edge.to : edge.from)
  const warns = edge.warningCodes.length > 0
    ? ` — ▲ ${edge.warningCodes.map(c => warnLabel(c, t)).join(', ')}`
    : ''
  return (
    <li className="text-sm">
      <span aria-hidden="true">{out ? '→ ' : '← '}</span>
      <span style={{ fontFamily: 'var(--astra-font-code)' }}>{other?.label ?? labelOf(out ? edge.to : edge.from)}</span>
      <span className="text-[color:var(--astra-text-muted)]">
        {' '}({flowDetail(edge, t)}){warns}
      </span>
    </li>
  )
}

/** Every edge this node participates in — the node's routing reality. */
function Flows({ node, view, labelOf }: {
  node: TopoNode
  view: TopologyView
  labelOf: (id: string) => string
}) {
  const { t } = useTranslation()
  const edges = view.adjacency.get(node.id) ?? []
  const byId = new Map(view.nodes.map(n => [n.id, n]))
  if (edges.length === 0) return null
  return (
    <div className="mt-2 flex flex-col gap-1">
      <p className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('routingMap.graphFlows')}</p>
      <ul className="flex flex-col gap-1">
        {edges.map(e => (
          <FlowRow key={e.id} edge={e} node={node} byId={byId} labelOf={labelOf} />
        ))}
      </ul>
    </div>
  )
}

/** The selected node's facts: kind, identity, target, warnings, flows, drill-down. */
function NodeInspector({ map, view, node, labelOf, onClear }: {
  map: RoutingMap
  view: TopologyView
  node: TopoNode
  labelOf: (id: string) => string
  onClear: () => void
}) {
  const { t } = useTranslation()
  return (
    <aside data-testid="routing-graph-inspector"
      className="w-72 shrink-0 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] p-3"
      aria-label={t('routingMap.graphInspect')}>
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{kindLabel(node.kind, t)}</p>
        <button type="button" onClick={onClear}
          className="min-h-[28px] min-w-[28px] rounded border border-[color:var(--astra-rule-strong)] text-sm leading-none hover:bg-[color:var(--astra-surface-muted)]"
          aria-label={t('common.close')} data-testid="routing-graph-inspector-close">×</button>
      </div>
      <p className="overflow-wrap-anywhere mt-1 text-sm" style={{ font: '13px/1.5 var(--astra-font-code)' }}>{node.label}</p>

      {node.provider && (
        <p className="mt-2 text-sm"><span className="text-[color:var(--astra-text-muted)]">{t('routingMap.colProvider')}: </span>
          <span style={{ fontFamily: 'var(--astra-font-code)' }}>{node.provider}</span></p>
      )}
      {(node.alias ?? node.rule) && (
        <p className="mt-1 text-sm"><span className="text-[color:var(--astra-text-muted)]">{t('routingMap.colTarget')}: </span>
          <span style={{ fontFamily: 'var(--astra-font-code)' }}>{(node.alias ?? node.rule)!.target_model}</span></p>
      )}
      {node.rule && (
        <p className="mt-1 text-sm"><span className="text-[color:var(--astra-text-muted)]">{t('routingMap.colPriority')}: </span>{node.rule.priority}</p>
      )}

      <NodeWarnings map={map} node={node} />

      <Flows node={node} view={view} labelOf={labelOf} />

      <p className="mt-3">
        <a className="underline decoration-dotted underline-offset-2" data-testid={`routing-graph-requests-${safeId(node.id)}`}
          href={relatedListHref('requests-explorer', currentHashQuery(), {
            model: node.model?.model_name ?? node.alias?.target_model ?? node.rule?.target_model ?? node.label,
          })}>
          {t('routingMap.openRequests')}
        </a>
      </p>
    </aside>
  )
}

/** Legend: every visual code the canvas uses, color plus pattern plus words. */
function GraphLegend() {
  const { t } = useTranslation()
  const line = (stroke: string, dash?: string) => (
    <svg width="22" height="6" aria-hidden="true">
      <line x1={0} y1={3} x2={22} y2={3} stroke={stroke} strokeWidth={EDGE_W} strokeDasharray={dash} />
    </svg>
  )
  return (
    <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[color:var(--astra-text-muted)]">
      <span className="inline-flex items-center gap-1.5">{line('var(--astra-accent)')}{t('routingMap.graphLegendChain')}</span>
      <span className="inline-flex items-center gap-1.5">{line('var(--astra-info)', '7 4')}{t('routingMap.graphLegendAlias')}</span>
      <span className="inline-flex items-center gap-1.5">{line('var(--astra-ink)', '2 3')}{t('routingMap.graphLegendRule')}</span>
      <span className="inline-flex items-center gap-1.5">{line('var(--astra-rule-strong)', '1 4')}{t('routingMap.graphLegendProvider')}</span>
      <span className="inline-flex items-center gap-1.5">{line('var(--astra-selection)')}{t('routingMap.graphLegendSelected')}</span>
      <span className="inline-flex items-center gap-1.5">
        <svg width="22" height="10" aria-hidden="true"><rect x={1} y={1} width={20} height={8} fill="none" stroke="var(--astra-danger)" strokeDasharray="6 4" /></svg>
        {t('routingMap.graphLegendMissing')}
      </span>
    </p>
  )
}
