// CV-01 (V01 rendering child): the configuration-topology view model over
// the routing map — layered alias → rule → model → provider lanes.
//
// Contract (V01 spec + docs/visualizers/field-matrix.md):
//  * The provider lane is the ONLY structural addition to lib/routingGraph's
//    model: one provider node per distinct models[].provider, one config
//    edge per registry model (model → its provider). A missing phantom has
//    no registry row, so it never gets a provider edge — no invented
//    provider. An empty provider string (impossible per schema) draws
//    nothing rather than an empty node.
//  * Edges are configuration facts: uniform visual weight is the view's job;
//    this module only keeps kind (chain/alias/rule/provider) so the view can
//    encode it by dash pattern, never by traffic-like emphasis.
//  * Everything derives from the /api/routing/map payload through
//    buildRoutingGraph (phantoms, warning attachment, chain ownership);
//    this module never re-derives a server verdict.
//  * Deterministic: node order and layout positions sort by content
//    (kind, provider, label, id), so reordering the API arrays moves nothing.

import { chainSteps, type RoutingMap } from '../api/routing.ts'
import {
  buildRoutingGraph, COL_GAP, LANE_ROWS, NODE_H, NODE_W, PAD, ROW_GAP,
  type GraphFocus, type GraphNode, type NodeBox, type RoutingGraph,
} from './routingGraph.ts'

export type TopoNodeKind = GraphNode['kind'] | 'provider'
export type TopoEdgeKind = 'alias' | 'rule' | 'chain' | 'provider'
export type TopoBand = 'alias' | 'rule' | 'model' | 'provider'

export type TopoNode = Omit<GraphNode, 'kind'> & { kind: TopoNodeKind }

export interface TopoEdge {
  id: string
  kind: TopoEdgeKind
  from: string
  to: string
  /** Edge label: failover hop number (chain) or `p<priority>` (rule). */
  label: string
  warningCodes: string[]
  /** The config entry that owns this edge (chain owner / entry / model). */
  owner: string
}

export interface TopologyView {
  /** The untouched base graph (phantoms, warnings, chain ownership). */
  graph: RoutingGraph
  nodes: TopoNode[]
  edges: TopoEdge[]
  /** node id → incident (or owned) edges, including provider edges. */
  adjacency: Map<string, TopoEdge[]>
  /** node id → its lane band (missing targets belong to the model band). */
  bandOf: Map<string, TopoBand>
}

const PROVIDER = (name: string) => `provider:${name}`
const MODEL = (name: string) => `model:${name}`

const KIND_RANK: Record<TopoNodeKind, number> = { alias: 0, rule: 1, model: 2, missing: 3, provider: 4 }

/** Content-based node order — stable when the API arrays are reordered. */
function compareNodes(a: TopoNode, b: TopoNode): number {
  return (
    KIND_RANK[a.kind] - KIND_RANK[b.kind] ||
    (a.provider ?? '').localeCompare(b.provider ?? '') ||
    a.label.localeCompare(b.label) ||
    a.id.localeCompare(b.id)
  )
}

/** One provider node per distinct registry provider, in name order. */
function providerNodes(map: RoutingMap): TopoNode[] {
  const names = [...new Set(map.models.map(m => m.provider).filter(p => p !== ''))]
  return names.sort((a, b) => a.localeCompare(b)).map(p => ({
    id: PROVIDER(p), kind: 'provider', label: p, sublabel: '', enabled: true, warningCodes: [],
  }))
}

function indexAdjacency(edges: TopoEdge[]): Map<string, TopoEdge[]> {
  const adjacency = new Map<string, TopoEdge[]>()
  for (const e of edges) {
    // Index by both endpoints AND the owner (a chain's hop 2+ starts at the
    // previous hop's node; the owner's inspector flow list needs every hop).
    for (const end of [e.from, e.to, e.owner]) pushEdge(adjacency, end, e)
  }
  return adjacency
}

function pushEdge(adjacency: Map<string, TopoEdge[]>, key: string, edge: TopoEdge): void {
  const list = adjacency.get(key)
  if (list === undefined) {
    adjacency.set(key, [edge])
    return
  }
  if (!list.includes(edge)) list.push(edge)
}

export function buildTopology(map: RoutingMap): TopologyView {
  const graph = buildRoutingGraph(map)
  // Content-sorted so node order (paint order, DOM ids) is reorder-stable.
  const nodes: TopoNode[] = graph.nodes.map(n => ({ ...n })).sort(compareNodes)
  const providers = providerNodes(map)
  nodes.push(...providers)
  const bandOf = new Map<string, TopoBand>()
  for (const n of nodes) bandOf.set(n.id, n.kind === 'missing' ? 'model' : n.kind)

  const edges: TopoEdge[] = graph.edges.map(e => ({ ...e }))
  for (const p of providers) {
    for (const m of map.models) {
      if (m.provider !== p.label) continue
      edges.push({
        id: `provider:${p.label}:${m.model_name}`, kind: 'provider',
        from: MODEL(m.model_name), to: p.id, label: '', warningCodes: [], owner: MODEL(m.model_name),
      })
    }
  }
  return { graph, nodes, edges, adjacency: indexAdjacency(edges), bandOf }
}

// ===== Search / focus (over the topology, so provider nodes match too) =====

export function focusTopology(view: TopologyView, rawQuery: string): GraphFocus {
  const query = rawQuery.trim().toLowerCase()
  if (query === '') {
    return { focusIds: new Set(view.nodes.map(n => n.id)), matchedIds: new Set(), noMatches: false }
  }
  const matched = new Set<string>()
  for (const n of view.nodes) {
    const hay = `${n.label} ${n.sublabel} ${n.provider ?? ''}`.toLowerCase()
    if (hay.includes(query)) matched.add(n.id)
  }
  // A match keeps its 1-hop context (a routing gap is only readable with
  // both ends visible); provider edges pull a matched model's provider in.
  const focus = new Set(matched)
  for (const id of matched) {
    for (const e of view.adjacency.get(id) ?? []) {
      focus.add(e.from)
      focus.add(e.to)
    }
  }
  return { focusIds: focus, matchedIds: matched, noMatches: matched.size === 0 }
}

// ===== Selected path =====

export interface SelectionPath {
  edgeIds: Set<string>
  nodeIds: Set<string>
}

const EMPTY_PATH: SelectionPath = { edgeIds: new Set(), nodeIds: new Set() }

/** Forward/backward from→to adjacency (self-loops add no reachability). */
function flowIndex(edges: TopoEdge[]): { fwd: Map<string, string[]>; rev: Map<string, string[]> } {
  const put = (m: Map<string, string[]>, k: string, v: string) => {
    const list = m.get(k)
    if (list) list.push(v)
    else m.set(k, [v])
  }
  const fwd = new Map<string, string[]>()
  const rev = new Map<string, string[]>()
  for (const e of edges) {
    if (e.from === e.to) continue
    put(fwd, e.from, e.to)
    put(rev, e.to, e.from)
  }
  return { fwd, rev }
}

/** Everything reachable from `start` through `next` (start included). */
function reachable(start: string, next: Map<string, string[]>): Set<string> {
  const seen = new Set<string>([start])
  const queue = [start]
  while (queue.length > 0) {
    for (const id of next.get(queue.shift()!) ?? []) {
      if (!seen.has(id)) {
        seen.add(id)
        queue.push(id)
      }
    }
  }
  return seen
}

/**
 * The directed configuration path(s) through the selected node: every edge
 * that lies on a path from any entry through the selection to a provider
 * (ancestors ∩ descendants). Null selection highlights nothing.
 */
export function selectionPath(view: TopologyView, selectedId: string | null): SelectionPath {
  if (selectedId === null) return EMPTY_PATH
  const { fwd, rev } = flowIndex(view.edges)
  const down = reachable(selectedId, fwd)
  const up = reachable(selectedId, rev)
  const nodeIds = new Set<string>([...up, ...down])
  const edgeIds = new Set<string>()
  for (const e of view.edges) {
    // On a path through the selection: both endpoints on the path AND the
    // edge either heads downstream of (or into) the selection, or leaves
    // from upstream of it.
    const flowsIntoPath = down.has(e.to) || up.has(e.from)
    if (flowsIntoPath && nodeIds.has(e.from) && nodeIds.has(e.to)) edgeIds.add(e.id)
  }
  return { edgeIds, nodeIds }
}

// ===== Deterministic lane layout =====

export interface BandHeader { band: TopoBand; x: number; width: number }

export interface TopoLayout {
  boxes: Map<string, NodeBox>
  headers: BandHeader[]
  width: number
  height: number
}

/** Vertical space reserved for the lane title row. */
export const HEADER_H = 18
/** Lane seed per band: aliases 0, rules 1, models (and phantoms) ≥ 2. */
const BAND_SEED: Record<'alias' | 'rule' | 'model', number> = { alias: 0, rule: 1, model: 2 }

function seedDepths(view: TopologyView): Map<string, number> {
  const depth = new Map<string, number>()
  for (const n of view.nodes) {
    depth.set(n.id, n.kind === 'provider' ? -1 : BAND_SEED[n.kind === 'missing' ? 'model' : n.kind])
  }
  return depth
}

/** The depth an edge wants for its target, or -1 when it carries none. */
function wantedDepth(edge: TopoEdge, depth: Map<string, number>): number {
  const base = depth.get(edge.from)
  if (base === undefined || base < 0) return -1
  if (edge.kind === 'alias' || edge.kind === 'rule') return Math.max(base + 1, 2)
  return base + 1
}

/** One relaxation round; true when any depth moved (another round is due). */
function relaxOnce(view: TopologyView, depth: Map<string, number>): boolean {
  let changed = false
  for (const e of view.edges) {
    if (e.from === e.to) continue
    const want = wantedDepth(e, depth)
    if (want < 0 || want <= (depth.get(e.to) ?? -1)) continue
    depth.set(e.to, want)
    changed = true
  }
  return changed
}

/**
 * Longest-path relaxation over config edges: chain and provider hops advance
 * one column; entry edges land their target in the model band (max(from+1,
 * 2)). Self-edges never advance depth (the cycle guard — a server-flagged
 * chain_cycle must not push its node right every round); rounds are bounded
 * by edges+2, so a cycle can never spin forever. Providers sit one column
 * past the deepest model that feeds them.
 */
function relaxDepths(view: TopologyView, depth: Map<string, number>): void {
  for (let round = 0; round <= view.edges.length + 2; round++) {
    if (!relaxOnce(view, depth)) break
  }
}

/** Content-based lane order — stable when the API arrays are reordered. */
function sortLane(ids: string[], byId: Map<string, TopoNode>): string[] {
  return [...ids].sort((a, b) => compareNodes(byId.get(a)!, byId.get(b)!))
}

/** Place one column's nodes into wrapped lanes of ≤LANE_ROWS rows. */
function placeLanes(ids: string[], x: number, boxes: Map<string, NodeBox>): [number, number] {
  const lanes: string[][] = []
  for (let i = 0; i < ids.length; i += LANE_ROWS) lanes.push(ids.slice(i, i + LANE_ROWS))
  let height = 0
  lanes.forEach((lane, li) => {
    const laneX = x + li * (NODE_W + COL_GAP)
    lane.forEach((id, row) => {
      boxes.set(id, { x: laneX, y: HEADER_H + PAD + row * (NODE_H + ROW_GAP), w: NODE_W, h: NODE_H })
    })
    height = Math.max(height, lane.length * (NODE_H + ROW_GAP))
  })
  return [height, Math.max(1, lanes.length)]
}

/**
 * The provider lane starts one column past the deepest model/phantom, so
 * every provider shares ONE rightmost lane however deep individual chains
 * reach (per-model relaxation could otherwise land a shallow-fed provider
 * in the same column as a deep model).
 */
function seatProviders(view: TopologyView, depth: Map<string, number>): void {
  let deepest = 1
  for (const n of view.nodes) {
    if (n.kind === 'provider') continue
    deepest = Math.max(deepest, depth.get(n.id) ?? 2)
  }
  for (const n of view.nodes) {
    if (n.kind === 'provider') depth.set(n.id, deepest + 1)
  }
}

/** Grow `bandRange` to cover the column [x, end] of `band`. */
function spanBand(bandRange: Map<TopoBand, { min: number; max: number }>, band: TopoBand, x: number, end: number): void {
  const span = bandRange.get(band)
  if (span === undefined) {
    bandRange.set(band, { min: x, max: end })
    return
  }
  span.min = Math.min(span.min, x)
  span.max = Math.max(span.max, end)
}

/**
 * Left-to-right lane layout: alias column, rule column, model columns by
 * chain depth (missing phantoms past their deepest predecessor), provider
 * column last. Deterministic: lane order is content-based; two runs produce
 * identical boxes.
 */
export function layoutTopology(view: TopologyView): TopoLayout {
  const depth = seedDepths(view)
  relaxDepths(view, depth)
  seatProviders(view, depth)
  const byId = new Map(view.nodes.map(n => [n.id, n]))

  const columns = new Map<number, string[]>()
  for (const n of view.nodes) {
    const col = depth.get(n.id) ?? 2
    const list = columns.get(col)
    if (list) list.push(n.id)
    else columns.set(col, [n.id])
  }

  const boxes = new Map<string, NodeBox>()
  const bandRange = new Map<TopoBand, { min: number; max: number }>()
  let x = PAD
  let height = 0
  for (const col of [...columns.keys()].sort((a, b) => a - b)) {
    const ids = sortLane(columns.get(col) ?? [], byId)
    const [colHeight, laneCount] = placeLanes(ids, x, boxes)
    height = Math.max(height, colHeight)
    const band = view.bandOf.get(ids[0] ?? '') ?? 'model'
    spanBand(bandRange, band, x, x + laneCount * (NODE_W + COL_GAP) - COL_GAP)
    x += laneCount * (NODE_W + COL_GAP)
  }

  const headers: BandHeader[] = (['alias', 'rule', 'model', 'provider'] as const)
    .filter(band => bandRange.has(band))
    .map(band => {
      const r = bandRange.get(band)!
      return { band, x: r.min, width: r.max - r.min }
    })
  return {
    boxes,
    headers,
    width: Math.max(x - COL_GAP + PAD, NODE_W + 2 * PAD),
    height: Math.max(HEADER_H + PAD + height, HEADER_H + NODE_H + 2 * PAD),
  }
}

// ===== Partial-state input: configured targets missing from the registry =====

/** Remember `name` when nothing in the registry can answer it. */
function noteMissing(missing: Set<string>, known: Set<string>, name: string): void {
  if (!known.has(name)) missing.add(name)
}

/**
 * Every model name that some configuration points at (chain hop, alias or
 * rule target) but that has no registry row — the honest input for the
 * partial notice. Sorted, deduplicated.
 */
export function missingTargetNames(map: RoutingMap): string[] {
  const known = new Set(map.models.map(m => m.model_name))
  const missing = new Set<string>()
  for (const m of map.models) {
    for (const step of chainSteps(m).slice(1)) noteMissing(missing, known, step)
  }
  for (const a of map.aliases) noteMissing(missing, known, a.target_model)
  for (const r of map.rules) noteMissing(missing, known, r.target_model)
  return [...missing].sort((a, b) => a.localeCompare(b))
}
