// UI-DEV slice 1 (brief §(e) routing viz): the read-only route map.
//
// Honesty contract (yabanin-contracts, engineering.md "no fake success"):
//  * ONE input: the /api/routing/map payload, through the pure model in
//    lib/routingGraph.ts. Chains render in the gateway's own attempt order;
//    missing targets render as dashed phantoms; warnings are the server's
//    codes — this view never re-derives a verdict.
//  * The mode selector keeps the three routing-viz modes unmixed: only
//    "possible routes" exists today; "recorded paths" and "simulation" are
//    disabled WITH a visible reason (the backend gaps recorded in
//    artifacts/internal-delivery-program/UI-DEV/PROGRESS.md) — they are never silently
//    merged into the configuration view, and the map never pretends to be
//    recorded traffic.
//  * The tables in RoutingMapPage stay the table alternative carrying the
//    same payload; the graph is additive, not a replacement.
//  * Plain SVG, astra tokens only, no chart library, no animation.
import { useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { RoutingMap } from '../../api/routing'
import { currentHashQuery, relatedListHref } from '../../lib/inspectUrl'
import {
  buildRoutingGraph, edgeEndpoints, focusSubgraph, isBackEdge, layoutRoutingGraph, nearestNode,
  type GraphEdge, type GraphNode, type NavDir,
} from '../../lib/routingGraph'
import { StateNotice } from './StateNotice'

const EDGE_STROKE: Record<GraphEdge['kind'], string> = {
  chain: 'var(--astra-accent)',
  alias: 'var(--astra-info)',
  rule: 'var(--astra-ink)',
}
const EDGE_DASH: Record<GraphEdge['kind'], string> = {
  chain: '',
  alias: '7 4',
  rule: '2 3',
}

/** Localized label for a stable warning code; unknown codes stay raw. */
function warnLabel(code: string, t: ReturnType<typeof useTranslation>['t']): string {
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

function kindLabel(kind: GraphNode['kind'], t: ReturnType<typeof useTranslation>['t']): string {
  switch (kind) {
    case 'model': return t('routingMap.scopeModel')
    case 'alias': return t('routingMap.scopeAlias')
    case 'rule': return t('routingMap.scopeRule')
    case 'missing': return t('routingMap.graphMissing')
  }
}

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

export function RoutingGraphSection({ map }: { map: RoutingMap }) {
  const { t } = useTranslation()
  const graph = useMemo(() => buildRoutingGraph(map), [map])
  const layout = useMemo(() => layoutRoutingGraph(graph), [graph])
  const byId = useMemo(() => new Map(graph.nodes.map(n => [n.id, n])), [graph])
  // Deterministic DOM ids for roving focus (index-based: unique by construction).
  const domId = useMemo(() => {
    const idx = new Map<string, string>()
    graph.nodes.forEach((n, i) => idx.set(n.id, `rg-node-${i}`))
    return idx
  }, [graph])

  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const focus = useMemo(() => focusSubgraph(graph, query), [graph, query])
  const searchRef = useRef<HTMLInputElement>(null)

  if (graph.nodes.length === 0) {
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
    switch (event.key) {
      case 'Enter':
      case ' ':
        event.preventDefault()
        setSelectedId(prev => (prev === id ? null : id))
        break
      case 'ArrowLeft': event.preventDefault(); moveFocus(id, 'left'); break
      case 'ArrowRight': event.preventDefault(); moveFocus(id, 'right'); break
      case 'ArrowUp': event.preventDefault(); moveFocus(id, 'up'); break
      case 'ArrowDown': event.preventDefault(); moveFocus(id, 'down'); break
      default: break
    }
  }

  const labelOf = (id: string) => byId.get(id)?.label ?? id

  return (
    <section className="astra-panel space-y-3 px-4 py-4" data-testid="routing-graph" aria-label={t('routingMap.graphTitle')}>
      <div>
        <h2 className="text-base font-semibold">{t('routingMap.graphTitle')}</h2>
        <p className="text-sm text-[color:var(--astra-text-muted)]">{t('routingMap.graphHint')}</p>
      </div>

      {/* The three routing-viz modes, never mixed: one real, two disabled
          with a visible reason instead of silently merged or hidden. */}
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
        <span className="text-sm text-[color:var(--astra-text-muted)]" data-testid="routing-graph-count">
          {t('routingMap.graphCount', { nodes: graph.nodes.length, edges: graph.edges.length })}
          {query.trim() !== '' && (
            focus.noMatches
              ? ` — ${t('routingMap.graphNoMatch')}`
              : ` — ${t('routingMap.graphMatches', { matched: focus.matchedIds.size, total: graph.nodes.length })}`
          )}
        </span>
      </div>

      <div className="flex flex-wrap items-start gap-4">
        <div className="max-w-full min-w-0 flex-1 overflow-auto rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] p-1">
          <svg
            role="group"
            aria-label={t('routingMap.graphAria', { nodes: graph.nodes.length, edges: graph.edges.length })}
            width={layout.width}
            height={layout.height}
            data-testid="routing-graph-canvas"
          >
            <defs>
              {(['chain', 'alias', 'rule'] as const).map(kind => (
                <marker key={kind} id={`rg-arrow-${kind}`} viewBox="0 0 10 10" refX={8.5} refY={5}
                  markerWidth={6.5} markerHeight={6.5} orient="auto-start-reverse">
                  <polygon points="0,0 10,5 0,10" fill={EDGE_STROKE[kind]} />
                </marker>
              ))}
              <marker id="rg-arrow-warn" viewBox="0 0 10 10" refX={8.5} refY={5}
                markerWidth={6.5} markerHeight={6.5} orient="auto-start-reverse">
                <polygon points="0,0 10,5 0,10" fill="var(--astra-danger)" />
              </marker>
            </defs>

            {graph.edges.map(edge => {
              const from = layout.boxes.get(edge.from)
              const to = layout.boxes.get(edge.to)
              if (!from || !to) return null
              const { a, b } = edgeEndpoints(from, to)
              const self = edge.from === edge.to
              const back = !self && isBackEdge(from, to)
              const warned = edge.warningCodes.length > 0
              const stroke = warned ? 'var(--astra-danger)' : EDGE_STROKE[edge.kind]
              // url(#id) references the <marker> defs above; built from the
              // kind so the arrowhead inherits the edge style.
              const markerId = warned ? 'rg-arrow-warn' : `rg-arrow-${edge.kind}`
              const arrow = `url(#${markerId})`
              const dim = !(visible(edge.from) && visible(edge.to))
              const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - (self ? 30 : 0) }
              const kindText = edge.kind === 'chain'
                ? t('routingMap.graphLegendChain')
                : edge.kind === 'alias' ? t('routingMap.graphLegendAlias') : t('routingMap.graphLegendRule')
              const title = `${kindText}: ${labelOf(edge.from)} → ${labelOf(edge.to)}${edge.kind === 'chain' ? ` (${t('routingMap.graphHop', { n: edge.label })})` : ''}`
              return (
                <g key={edge.id} opacity={dim ? 0.15 : 1} data-testid="routing-graph-edge">
                  <path
                    d={edgeD(a, b, self, back)}
                    fill="none"
                    stroke={stroke}
                    strokeWidth={warned ? 2 : 1.5}
                    strokeDasharray={EDGE_DASH[edge.kind] || undefined}
                    markerEnd={arrow}
                  >
                    <title>{title}</title>
                  </path>
                  {edge.label !== '' && !dim && (
                    <text x={mid.x} y={mid.y} textAnchor="middle" dominantBaseline="middle"
                      fontSize={10} fontFamily="var(--astra-font-code)" fill="var(--astra-text-muted)"
                      paintOrder="stroke" stroke="var(--astra-paper)" strokeWidth={3}>
                      {edge.label}
                    </text>
                  )}
                </g>
              )
            })}

            {graph.nodes.map(node => {
              const box = layout.boxes.get(node.id)
              if (!box) return null
              const isMatch = focus.matchedIds.has(node.id)
              const isSelected = node.id === selectedId
              const dim = !visible(node.id)
              const stroke = isSelected
                ? 'var(--astra-selection)'
                : isMatch
                  ? 'var(--astra-focus)'
                  : node.kind === 'missing'
                    ? 'var(--astra-danger)'
                    : 'var(--astra-rule-strong)'
              const glyph = node.kind === 'model' ? 'M' : node.kind === 'alias' ? 'A' : node.kind === 'rule' ? 'R' : '?'
              const statusText = node.kind === 'missing'
                ? t('routingMap.graphMissing')
                : node.kind === 'alias'
                  ? node.sublabel
                  : node.enabled ? t('routingMap.statusEnabled') : t('routingMap.statusDisabled')
              const aria = [
                `${kindLabel(node.kind, t)}, ${node.label}`,
                node.provider ? node.provider : '',
                statusText,
                node.warningCodes.length > 0 ? `${t('routingMap.colWarnings')}: ${node.warningCodes.map(c => warnLabel(c, t)).join(', ')}` : '',
              ].filter(part => part !== '').join(', ')
              const shown = node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label
              return (
                <g
                  key={node.id}
                  id={domId.get(node.id)}
                  role="button"
                  tabIndex={dim ? -1 : 0}
                  aria-label={aria}
                  aria-pressed={isSelected}
                  data-testid={`routing-graph-node-${node.id.replace(/[^A-Za-z0-9._-]+/g, '-')}`}
                  opacity={dim ? 0.18 : 1}
                  cursor="pointer"
                  onClick={() => setSelectedId(prev => (prev === node.id ? null : node.id))}
                  onKeyDown={e => onNodeKeyDown(e, node.id)}
                >
                  <title>{aria}</title>
                  <rect
                    x={box.x} y={box.y} width={box.w} height={box.h} rx={8}
                    fill="var(--astra-paper)"
                    stroke={stroke}
                    strokeWidth={isMatch || isSelected ? 2.5 : 1.25}
                    strokeDasharray={node.kind === 'missing' ? '6 4' : undefined}
                  />
                  <text x={box.x + 10} y={box.y + 15} fontSize={9} fill="var(--astra-text-muted)" fontFamily="var(--astra-font-code)">
                    <tspan aria-hidden="true">{glyph}</tspan>
                  </text>
                  <text x={box.x + 24} y={box.y + 17} fontSize={12} fontFamily="var(--astra-font-code)" fill="var(--astra-ink)">
                    {shown}
                  </text>
                  <text x={box.x + 10} y={box.y + 34} fontSize={10} fill="var(--astra-text-muted)">
                    {node.kind === 'missing' ? t('routingMap.graphMissing') : node.sublabel}
                  </text>
                  {node.kind !== 'missing' && node.kind !== 'alias' && (
                    <text x={box.x + box.w - 12} y={box.y + 34} fontSize={9} textAnchor="end" fill={node.enabled ? 'var(--astra-success)' : 'var(--astra-text-muted)'}>
                      {statusText}
                    </text>
                  )}
                  {node.warningCodes.length > 0 && (
                    <text x={box.x + box.w - 10} y={box.y + 16} fontSize={11} textAnchor="end" fill="var(--astra-warning)" aria-hidden="true">△</text>
                  )}
                </g>
              )
            })}
          </svg>
        </div>

        {selected && (
          <aside data-testid="routing-graph-inspector"
            className="w-72 shrink-0 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] p-3"
            aria-label={t('routingMap.graphInspect')}>
            <div className="flex items-start justify-between gap-2">
              <p className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{kindLabel(selected.kind, t)}</p>
              <button type="button" onClick={() => {
                setSelectedId(null)
                const el = document.getElementById(domId.get(selected.id) ?? '')
                el?.focus()
              }} className="min-h-[28px] min-w-[28px] rounded border border-[color:var(--astra-rule-strong)] text-sm leading-none hover:bg-[color:var(--astra-surface-muted)]"
                aria-label={t('common.close')} data-testid="routing-graph-inspector-close">×</button>
            </div>
            <p className="overflow-wrap-anywhere mt-1 text-sm" style={{ font: '13px/1.5 var(--astra-font-code)' }}>{selected.label}</p>

            {selected.provider && (
              <p className="mt-2 text-sm"><span className="text-[color:var(--astra-text-muted)]">{t('routingMap.colProvider')}: </span>
                <span style={{ fontFamily: 'var(--astra-font-code)' }}>{selected.provider}</span></p>
            )}
            {(selected.alias ?? selected.rule) && (
              <p className="mt-1 text-sm"><span className="text-[color:var(--astra-text-muted)]">{t('routingMap.colTarget')}: </span>
                <span style={{ fontFamily: 'var(--astra-font-code)' }}>{(selected.alias ?? selected.rule)!.target_model}</span></p>
            )}
            {selected.rule && (
              <p className="mt-1 text-sm"><span className="text-[color:var(--astra-text-muted)]">{t('routingMap.colPriority')}: </span>{selected.rule.priority}</p>
            )}

            <NodeWarnings map={map} node={selected} />

            <Flows node={selected} graph={graph} byId={byId} labelOf={labelOf} />

            <p className="mt-3">
              <a className="underline decoration-dotted underline-offset-2" data-testid={`routing-graph-requests-${selected.id.replace(/[^A-Za-z0-9._-]+/g, '-')}`}
                href={relatedListHref('requests-explorer', currentHashQuery(), {
                  model: selected.model?.model_name ?? selected.alias?.target_model ?? selected.rule?.target_model ?? selected.label,
                })}>
                {t('routingMap.openRequests')}
              </a>
            </p>
          </aside>
        )}
      </div>

      <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[color:var(--astra-text-muted)]">
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="6" aria-hidden="true"><line x1={0} y1={3} x2={22} y2={3} stroke="var(--astra-accent)" strokeWidth={1.5} /></svg>
          {t('routingMap.graphLegendChain')}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="6" aria-hidden="true"><line x1={0} y1={3} x2={22} y2={3} stroke="var(--astra-info)" strokeWidth={1.5} strokeDasharray="7 4" /></svg>
          {t('routingMap.graphLegendAlias')}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="6" aria-hidden="true"><line x1={0} y1={3} x2={22} y2={3} stroke="var(--astra-ink)" strokeWidth={1.5} strokeDasharray="2 3" /></svg>
          {t('routingMap.graphLegendRule')}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="22" height="10" aria-hidden="true"><rect x={1} y={1} width={20} height={8} fill="none" stroke="var(--astra-danger)" strokeDasharray="6 4" /></svg>
          {t('routingMap.graphLegendMissing')}
        </span>
      </p>
    </section>
  )
}

/** Server warnings that address this node (scope+source), with their messages. */
function NodeWarnings({ map, node }: { map: RoutingMap; node: GraphNode }) {
  const { t } = useTranslation()
  const scope = node.kind
  const source = node.kind === 'model' ? node.label : node.kind === 'alias' ? node.label : node.rule?.id ?? ''
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

/** Every edge this node participates in — the node's routing reality. */
function Flows({ node, graph, byId, labelOf }: {
  node: GraphNode
  graph: ReturnType<typeof buildRoutingGraph>
  byId: Map<string, GraphNode>
  labelOf: (id: string) => string
}) {
  const { t } = useTranslation()
  const edges = graph.adjacency.get(node.id) ?? []
  if (edges.length === 0) return null
  return (
    <div className="mt-2 flex flex-col gap-1">
      <p className="text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('routingMap.graphFlows')}</p>
      <ul className="flex flex-col gap-1">
        {edges.map(e => {
          // Outgoing unless this node is purely the edge's destination. A
          // chain's hop 2+ starts at the previous hop's node, but it still
          // flows out of the owning model's config — so owner ⇒ outgoing.
          const out = e.from === node.id || (e.owner === node.id && e.to !== node.id)
          const other = byId.get(out ? e.to : e.from)
          const kind = e.kind === 'chain' ? t('routingMap.graphLegendChain') : e.kind === 'alias' ? t('routingMap.graphLegendAlias') : t('routingMap.graphLegendRule')
          // Chain: just the hop number (the kind is the section's premise);
          // alias/rule: the kind, rules also carry their `p<priority>` tag.
          const detail = e.kind === 'chain' ? t('routingMap.graphHop', { n: e.label }) : `${kind}${e.label ? ` · ${e.label}` : ''}`
          return (
            <li key={e.id} className="text-sm">
              <span aria-hidden="true">{out ? '→ ' : '← '}</span>
              <span style={{ fontFamily: 'var(--astra-font-code)' }}>{other?.label ?? labelOf(out ? e.to : e.from)}</span>
              <span className="text-[color:var(--astra-text-muted)]">
                {' '}({detail}){e.warningCodes.length > 0 ? ` — ▲ ${e.warningCodes.map(c => warnLabel(c, t)).join(', ')}` : ''}
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
