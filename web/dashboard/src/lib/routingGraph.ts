// UI-DEV slice 1 (brief §(e) "routing viz"): the pure model behind the
// read-only routing graph on the Routing map screen.
//
// Honest-data contract (yabanin-contracts / engineering.md):
//  * The ONLY input is the real `/api/routing/map` payload (models, aliases,
//    rules, warnings). The graph renders what the CURRENT CONFIGURATION makes
//    possible — it is explicitly NOT a record of actual traffic. Recorded
//    aggregates live in the Provider health tables on the same screen, and
//    the two are never mixed (brief: "3 unmixed modes").
//  * Warnings are the server's computed codes (routing_map.go); this module
//    indexes and attaches them, it never re-derives a verdict.
//  * Chain hops reuse `chainSteps` from api/routing.ts (the gateway's own
//    buildChain order: model, fallback, failovers).
//  * A chain/alias/rule target that is NOT in the model registry becomes a
//    dashed "missing" phantom node — a gap is drawn as a gap, never silently
//    dropped and never redrawn from some other source.

import { chainSteps, type RoutingMap, type RoutingMapAlias, type RoutingMapModel, type RoutingMapRule, type RoutingMapWarning } from '../api/routing.ts'

export type GraphNodeKind = 'model' | 'alias' | 'rule' | 'missing'

export interface GraphNode {
  /** Stable unique id: `model:<name>` / `alias:<name>` / `rule:<id>` / `missing:<name>`. */
  id: string
  kind: GraphNodeKind
  /** Primary label: model name, alias, rule match expression. */
  label: string
  /** Secondary line: provider (model) / target (alias, rule) / — (missing). */
  sublabel: string
  /** Models and rules carry an enabled flag; aliases are always usable. */
  enabled: boolean
  provider?: string
  /** Server warning codes attached to this node, in payload order. */
  warningCodes: string[]
  /** Original payload rows (for the inspector); only the own kind is set. */
  model?: RoutingMapModel
  alias?: RoutingMapAlias
  rule?: RoutingMapRule
}

export type GraphEdgeKind = 'alias' | 'rule' | 'chain'

export interface GraphEdge {
  id: string
  kind: GraphEdgeKind
  from: string
  to: string
  /** Edge label: failover hop number (chain) or `p<priority>` (rule). */
  label: string
  warningCodes: string[]
  /**
   * The config entry that owns this edge (`model:` for a chain hop, the
   * alias/rule node for entries). Server warnings address the OWNER by
   * source, and a failover hop beyond the first starts at a different node —
   * so attachment must match owner+target, not from+target.
   */
  owner: string
}

export interface RoutingGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  /** node id → edges the node participates in OR OWNS: chain hops 2+ start
   *  at a different node, but the owner's config draws them — the owner's
   *  flow list (inspector) must include every hop of its chain. */
  adjacency: Map<string, GraphEdge[]>
}

const MODEL = (name: string) => `model:${name}`
const MISSING = (name: string) => `missing:${name}`
const ALIAS = (name: string) => `alias:${name}`
const RULE = (id: string) => `rule:${id}`

/** Node id a target name resolves to: a registry model, else a phantom. */
function targetNodeId(name: string, knownModels: Set<string>): string {
  return knownModels.has(name) ? MODEL(name) : MISSING(name)
}

/**
 * Build the graph from the server payload. Deterministic: node order is
 * models (payload order), then aliases, then rules; missing phantoms are
 * appended in first-mention order. Edge ids are stable (`kind:from:to:n`).
 */
export function buildRoutingGraph(map: RoutingMap): RoutingGraph {
  const knownModels = new Set(map.models.map(m => m.model_name))
  const nodes = new Map<string, GraphNode>()
  const edges: GraphEdge[] = []
  const adjacency = new Map<string, GraphEdge[]>()

  const addNode = (node: Omit<GraphNode, 'warningCodes'>) => {
    if (!nodes.has(node.id)) nodes.set(node.id, { ...node, warningCodes: [] })
  }
  const addEdge = (edge: GraphEdge) => {
    edges.push(edge)
    // Index by both endpoints AND the owner: a chain's hops 2+ start at the
    // previous hop's node, so the chain's model is not an endpoint of those
    // edges — yet its config (and its inspector flow list) includes them.
    for (const end of edge.owner ? [edge.from, edge.to, edge.owner] : [edge.from, edge.to]) {
      const list = adjacency.get(end)
      if (!list?.includes(edge)) {
        if (list) list.push(edge)
        else adjacency.set(end, [edge])
      }
    }
  }

  for (const m of map.models) {
    addNode({
      id: MODEL(m.model_name),
      kind: 'model',
      label: m.model_name,
      sublabel: m.provider,
      enabled: m.enabled,
      provider: m.provider,
      model: m,
    })
  }

  const edgeSeq = new Map<string, number>()
  const pushEdge = (kind: GraphEdgeKind, owner: string, from: string, to: string, label: string) => {
    const seq = (edgeSeq.get(`${kind}:${from}:${to}`) ?? 0) + 1
    edgeSeq.set(`${kind}:${from}:${to}`, seq)
    addEdge({ id: `${kind}:${from}:${to}:${seq}`, kind, owner, from, to, label, warningCodes: [] })
  }

  // Chain hops in the gateway's own attempt order. Each model's chain is
  // drawn from the model node itself; a hop onto an unknown name creates the
  // phantom. A self-loop (server flags chain_cycle) stays a real edge — the
  // gap is drawn, not hidden. The edge's owner is the chain's model: hop 2+
  // starts at the previous hop's node, but the config that created it (and
  // that server warnings name as source) is the chain owner.
  for (const m of map.models) {
    const steps = chainSteps(m)
    for (let i = 1; i < steps.length; i++) {
      const from = targetNodeId(steps[i - 1]!, knownModels)
      const to = targetNodeId(steps[i]!, knownModels)
      if (from === to && i > 1) continue // duplicate consecutive hop of the same chain
      pushEdge('chain', MODEL(m.model_name), from, to, String(i))
      if (!nodes.has(to)) {
        addNode({
          id: to,
          kind: 'missing',
          label: steps[i]!,
          sublabel: '',
          enabled: false,
        })
      }
    }
  }

  for (const a of map.aliases) {
    addNode({
      id: ALIAS(a.alias),
      kind: 'alias',
      label: a.alias,
      sublabel: a.target_model,
      enabled: true,
      alias: a,
    })
    pushEdge('alias', ALIAS(a.alias), ALIAS(a.alias), targetNodeId(a.target_model, knownModels), '')
    if (!nodes.has(targetNodeId(a.target_model, knownModels))) {
      addNode({
        id: targetNodeId(a.target_model, knownModels),
        kind: 'missing',
        label: a.target_model,
        sublabel: '',
        enabled: false,
      })
    }
  }

  for (const r of map.rules) {
    addNode({
      id: RULE(r.id),
      kind: 'rule',
      label: r.match_expr,
      sublabel: r.target_model,
      enabled: r.enabled,
      rule: r,
    })
    pushEdge('rule', RULE(r.id), RULE(r.id), targetNodeId(r.target_model, knownModels), `p${r.priority}`)
    if (!nodes.has(targetNodeId(r.target_model, knownModels))) {
      addNode({
        id: targetNodeId(r.target_model, knownModels),
        kind: 'missing',
        label: r.target_model,
        sublabel: '',
        enabled: false,
      })
    }
  }

  // Attach the server warnings. Scope+source address the OWN node; a warning
  // with a target also rides the edge the OWNER's config draws into that
  // target (owner+target match: hop 2+ of a chain starts at a different node
  // than the source the warning names) — so the gap is visible exactly where
  // the configuration points it.
  const sourceNodeId = (w: RoutingMapWarning): string | null => {
    if (w.scope === 'model') return nodes.has(MODEL(w.source)) ? MODEL(w.source) : null
    if (w.scope === 'alias') return nodes.has(ALIAS(w.source)) ? ALIAS(w.source) : null
    if (w.scope === 'rule') return nodes.has(RULE(w.source)) ? RULE(w.source) : null
    return null
  }
  for (const w of map.warnings) {
    const src = sourceNodeId(w)
    if (src) nodes.get(src)!.warningCodes.push(w.code)
    if (!w.target) continue
    const dst = targetNodeId(w.target, knownModels)
    const onEdge = edges.find(e => e.owner === src && e.to === dst)
    if (onEdge) onEdge.warningCodes.push(w.code)
  }

  return { nodes: [...nodes.values()], edges, adjacency }
}

// ===== Search / focus =====

export interface GraphFocus {
  /** Node ids that keep full emphasis (matches + their 1-hop context). */
  focusIds: Set<string>
  /** Node ids the query itself matched (stronger emphasis). */
  matchedIds: Set<string>
  /** True when a non-empty query matched nothing — the honest empty result. */
  noMatches: boolean
}

/**
 * Case-insensitive substring search over node label + sublabel + provider.
 * A match keeps its direct neighbours as context (a routing gap is only
 * readable with both ends visible); everything else is dimmed by the view.
 * The empty query focuses everything (no hidden nodes).
 */
export function focusSubgraph(graph: RoutingGraph, rawQuery: string): GraphFocus {
  const query = rawQuery.trim().toLowerCase()
  if (query === '') {
    const all = new Set(graph.nodes.map(n => n.id))
    return { focusIds: all, matchedIds: new Set(), noMatches: false }
  }
  const matched = new Set<string>()
  for (const n of graph.nodes) {
    const hay = `${n.label} ${n.sublabel} ${n.provider ?? ''}`.toLowerCase()
    if (hay.includes(query)) matched.add(n.id)
  }
  const focus = new Set(matched)
  for (const id of matched) {
    for (const e of graph.adjacency.get(id) ?? []) {
      focus.add(e.from)
      focus.add(e.to)
    }
  }
  return { focusIds: focus, matchedIds: matched, noMatches: matched.size === 0 }
}

// ===== Deterministic layered layout =====

export interface Point { x: number; y: number }
export interface NodeBox extends Point { w: number; h: number }
export interface GraphLayout {
  boxes: Map<string, NodeBox>
  /** Column index per node id (entries 0, models by depth, phantoms last). */
  columns: Map<string, number>
  width: number
  height: number
}

export const NODE_W = 200
export const NODE_H = 46
export const COL_GAP = 90
export const ROW_GAP = 18
export const PAD = 12
/** Rows per lane; longer columns wrap into another lane (new x offset). */
export const LANE_ROWS = 10

/**
 * Layered left-to-right layout:
 *  - column 0 = entry points (aliases and rules — what a request can name);
 *  - models are placed by their longest chain distance from any entry point
 *    (or from being a requestable model with no incoming chain hop);
 *  - missing phantoms sit one column past their deepest predecessor.
 * Deterministic: within a lane, nodes sort by (kind rank, provider, label).
 * The longest-path loop iterates at most edges+1 rounds; a cycle (already
 * flagged by the server) can never make it spin forever — depths freeze.
 */
export function layoutRoutingGraph(graph: RoutingGraph): GraphLayout {
  const depth = new Map<string, number>()
  const byId = new Map(graph.nodes.map(n => [n.id, n]))

  // Seed: entries at 0; requestable models with no incoming chain hop at 1.
  const incomingChain = new Set(graph.edges.filter(e => e.kind === 'chain').map(e => e.to))
  for (const n of graph.nodes) {
    if (n.kind === 'alias' || n.kind === 'rule') depth.set(n.id, 0)
    else if (n.kind === 'model' && !incomingChain.has(n.id)) depth.set(n.id, 1)
  }

  // Relaxation: longest path over ALL edges (aliases/rules pull their target
  // right of the entry; chains push each hop one column further). A self-loop
  // (the server-flagged chain_cycle) must not push its own node right every
  // round — self-edges are drawn as loops but do not advance depth, so the
  // loop is bounded and the node stays with its peers. One extra node with no
  // seed at all (e.g. every model is chained) still lands: the unseeded pass
  // below gives it depth 1.
  for (let round = 0; round <= graph.edges.length + 1; round++) {
    let changed = false
    for (const e of graph.edges) {
      if (e.from === e.to) continue
      const base = depth.get(e.from)
      if (base === undefined) continue
      const want = e.kind === 'chain' ? base + 1 : Math.max(base + 1, 1)
      if (want > (depth.get(e.to) ?? -1)) {
        depth.set(e.to, want)
        changed = true
      }
    }
    if (!changed) break
  }
  for (const n of graph.nodes) if (!depth.has(n.id)) depth.set(n.id, 1)

  // Column buckets → lanes (LANE_ROWS per lane) → deterministic order.
  const KIND_RANK: Record<GraphNodeKind, number> = { alias: 0, rule: 1, model: 2, missing: 3 }
  const columns = new Map<number, string[]>()
  for (const n of graph.nodes) {
    const col = depth.get(n.id) ?? 1
    const list = columns.get(col)
    if (list) list.push(n.id)
    else columns.set(col, [n.id])
  }
  const sortLane = (ids: string[]) => ids.sort((a, b) => {
    const na = byId.get(a)!
    const nb = byId.get(b)!
    return (
      KIND_RANK[na.kind] - KIND_RANK[nb.kind] ||
      (na.provider ?? '').localeCompare(nb.provider ?? '') ||
      na.label.localeCompare(nb.label)
    )
  })

  const boxes = new Map<string, NodeBox>()
  const colNumbers = new Map<string, number>()
  const colList = [...columns.keys()].sort((a, b) => a - b)
  let x = PAD
  let height = 0
  for (const col of colList) {
    const ids = sortLane(columns.get(col) ?? [])
    const lanes: string[][] = []
    for (let i = 0; i < ids.length; i += LANE_ROWS) lanes.push(ids.slice(i, i + LANE_ROWS))
    lanes.forEach((lane, li) => {
      const laneX = x + li * (NODE_W + COL_GAP)
      lane.forEach((id, row) => {
        boxes.set(id, { x: laneX, y: PAD + row * (NODE_H + ROW_GAP), w: NODE_W, h: NODE_H })
      })
      height = Math.max(height, PAD + lane.length * (NODE_H + ROW_GAP))
    })
    for (const id of ids) colNumbers.set(id, col)
    const laneCount = Math.max(1, Math.ceil(ids.length / LANE_ROWS))
    x += laneCount * (NODE_W + COL_GAP)
  }
  return {
    boxes,
    columns: colNumbers,
    width: Math.max(x - COL_GAP + PAD, NODE_W + 2 * PAD),
    height: Math.max(height, NODE_H + 2 * PAD),
  }
}

/** Straight connector from the source's right edge to the target's left edge. */
export function edgeEndpoints(from: NodeBox, to: NodeBox): { a: Point; b: Point } {
  const sameSpot = from.x === to.x && from.y === to.y
  if (sameSpot) {
    // Self-loop (chain_cycle): leave at the top edge, re-enter on the right.
    return { a: { x: from.x + from.w / 2, y: from.y }, b: { x: from.x + from.w, y: from.y + from.h / 2 } }
  }
  return { a: { x: from.x + from.w, y: from.y + from.h / 2 }, b: { x: to.x, y: to.y + to.h / 2 } }
}

/** True when the edge is drawn right-to-left (back edge) and needs a curve. */
export function isBackEdge(from: NodeBox, to: NodeBox): boolean {
  return to.x < from.x
}

// ===== Keyboard navigation =====

export type NavDir = 'left' | 'right' | 'up' | 'down'

/**
 * Nearest node for arrow-key navigation from `from` in `dir`: candidates must
 * actually advance on the primary axis; distance is the primary-axis gap plus
 * a 3× penalty on the drift across the orthogonal axis, so "right" prefers
 * the horizontally-next node over a far one that merely starts further right.
 * Deterministic tie-break by node id. Null when nothing lies that way.
 */
export function nearestNode(boxes: Map<string, NodeBox>, from: string, dir: NavDir): string | null {
  const a = boxes.get(from)
  if (!a) return null
  let best: string | null = null
  let bestScore = Infinity
  for (const [id, b] of boxes) {
    if (id === from) continue
    const dx = b.x - a.x
    const dy = b.y - a.y
    let primary: number
    let drift: number
    if (dir === 'right' || dir === 'left') {
      primary = dir === 'right' ? dx : -dx
      drift = Math.abs(dy)
    } else {
      primary = dir === 'down' ? dy : -dy
      drift = Math.abs(dx)
    }
    if (primary <= 1) continue
    const score = primary + 3 * drift
    if (score < bestScore || (score === bestScore && best !== null && id < best)) {
      bestScore = score
      best = id
    }
  }
  return best
}
