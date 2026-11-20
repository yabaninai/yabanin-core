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

export type TopoNodeKind = GraphNode['kind'] | 'provider' | 'group'
export type TopoEdgeKind = 'alias' | 'rule' | 'chain' | 'provider'
export type TopoBand = 'alias' | 'rule' | 'model' | 'provider'

/**
 * A bounded mount's stand-in for one lane band's unmounted entries: the
 * named, deterministic member list (content order) plus the exact count of
 * edges hidden with them — nothing about the hidden entries is estimated.
 */
export interface GroupSummary {
  band: TopoBand
  /** Hidden member ids, content order — named, never anonymous. */
  memberIds: string[]
  /** Hidden edges attributed to this band (every hidden edge counts once). */
  hiddenEdgeCount: number
}

export type TopoNode = Omit<GraphNode, 'kind'> & { kind: TopoNodeKind; group?: GroupSummary }

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

const KIND_RANK: Record<TopoNodeKind, number> = { alias: 0, rule: 1, model: 2, missing: 3, provider: 4, group: 5 }

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

// TopoNodeKind widens at the mount boundary (group summaries); this index
// is pre-mount and never sees a group node, so narrow the kind to TopoBand.
function bandIndex(nodes: TopoNode[]): Map<string, TopoBand> {
  const bandOf = new Map<string, TopoBand>()
  for (const n of nodes) {
    if (n.kind === 'group') continue
    bandOf.set(n.id, n.kind === 'missing' ? 'model' : n.kind)
  }
  return bandOf
}

export function buildTopology(map: RoutingMap): TopologyView {
  const graph = buildRoutingGraph(map)
  // Content-sorted so node order (paint order, DOM ids) is reorder-stable.
  const nodes: TopoNode[] = graph.nodes.map(n => ({ ...n })).sort(compareNodes)
  const providers = providerNodes(map)
  nodes.push(...providers)
  const bandOf = bandIndex(nodes)

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
    // Seed by lane band, not kind: mounted views (mountTopology) add group
    // summaries that must seat inside their members' band, and the band map
    // already folds missing phantoms into the model band.
    const band = view.bandOf.get(n.id) ?? 'model'
    depth.set(n.id, band === 'provider' ? -1 : BAND_SEED[band])
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
function relaxOnce(edges: readonly TopoEdge[], depth: Map<string, number>): boolean {
  let changed = false
  for (const e of edges) {
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
  // A cyclic chain can keep accumulating depth until the round limit.
  // Choose a stable traversal order without changing configured hop order.
  const edges = [...view.edges].sort((a, b) => a.id.localeCompare(b.id))
  for (let round = 0; round <= edges.length + 2; round++) {
    if (!relaxOnce(edges, depth)) break
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
  // Band-based (kind-based in spirit): group summaries belong to a lane and
  // must not be mistaken for rightmost-lane providers.
  let deepest = 1
  for (const n of view.nodes) {
    if ((view.bandOf.get(n.id) ?? 'model') === 'provider') continue
    deepest = Math.max(deepest, depth.get(n.id) ?? 2)
  }
  for (const n of view.nodes) {
    if ((view.bandOf.get(n.id) ?? 'model') === 'provider') depth.set(n.id, deepest + 1)
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

// ===== Bounded mount: everything exists, only the canvas is bounded =====
//
// The honest-scale contract for the visualizer: every configured entry
// exists in the view model (exact totals), while the RENDERED canvas stays
// bounded. mountTopology derives — BEFORE any render — which entries may
// mount:
//
//  * ≤ limits.maxNodes node boxes (group summaries included) and
//    ≤ limits.maxEdges edge paths;
//  * every unmounted entry survives verbatim as a deterministic, NAMED
//    group summary per lane band (member list in content order plus the
//    exact hidden member and edge counts — nothing estimated, nothing
//    anonymous);
//  * selection is content-based, so reordering the API arrays moves
//    nothing: each band contributes members in content order, bands
//    interleave round-robin (alias, rule, model, provider) so no lane is
//    decapitated, and the last-added entry retires first when a budget is
//    exceeded. Expanding a band group (`group:<band>`) reprioritizes that
//    band's hidden members under the SAME budgets — the named expansion.
//    The operator's selection is PINNED ahead of its band: an entry found
//    via search stays mounted as the query clears or broadens — a bounded
//    mount never evicts the inspected entry. An active search shrinks the
//    candidate pool to the focus (matches + 1-hop context) BEFORE
//    bounding, so a query reduces what mounts instead of merely dimming
//    it.

export interface MountLimits { maxNodes: number; maxEdges: number }

/** Bounded-mount budgets for the rendered canvas: ≤200 nodes / ≤400 edges. */
export const MOUNT_LIMITS: MountLimits = { maxNodes: 200, maxEdges: 400 }

export interface MountSelection {
  /** Active-search focus (matches + 1-hop context) over the FULL view. */
  focusIds: Set<string>
  /** True while a search query is active — the pool shrinks to the focus. */
  queryActive: boolean
  /** The selected node stays mounted (a selection must stay inspectable). */
  selectedId: string | null
  /** `group:<band>` whose hidden members this mount reprioritizes. */
  expandedGroupId: string | null
}

export interface MountedTopology {
  /** What renders: kept nodes + group summaries, and kept edges. */
  view: TopologyView
  /** Group node id → its named members and hidden-edge count. */
  groups: Map<string, GroupSummary>
  /** Exact FULL totals — the count chip and the canvas aria carry these. */
  totals: { nodes: number; edges: number }
  /** True when any grouping happened (false = the untouched base view). */
  grouped: boolean
}

const BAND_ORDER: TopoBand[] = ['alias', 'rule', 'model', 'provider']

/** The candidate pool: under an active query only the focus (plus the
 * current selection) may mount — a search reduces the mount, it never
 * merely dims it. */
function mountPool(view: TopologyView, sel: MountSelection): TopoNode[] {
  if (!sel.queryActive) return view.nodes
  return view.nodes.filter(n => sel.focusIds.has(n.id) || n.id === sel.selectedId)
}

/** Per-band candidate lists in content order (missing phantoms fold into the model band). */
function bandListsFor(pool: TopoNode[], bandOf: Map<string, TopoBand>): Map<TopoBand, string[]> {
  const lists = new Map<TopoBand, string[]>(BAND_ORDER.map(band => [band, [] as string[]]))
  for (const n of pool) {
    lists.get(bandOf.get(n.id) ?? 'model')!.push(n.id)
  }
  return lists
}

/** Round-robin seats across the bands (alias, rule, model, provider),
 * content order inside each band, capped at the node budget — bands
 * interleave so no lane is decapitated. */
function allocateRounds(lists: Map<TopoBand, string[]>, maxNodes: number): string[] {
  const seq: string[] = []
  const widest = Math.max(0, ...BAND_ORDER.map(band => lists.get(band)!.length))
  for (let round = 0; round < widest; round++) {
    for (const band of BAND_ORDER) {
      const row = lists.get(band)!
      if (round < row.length && seq.length < maxNodes) seq.push(row[round]!)
    }
  }
  return seq
}

/** How many edges have BOTH endpoints kept — what still renders. */
function edgesWithin(view: TopologyView, kept: Set<string>): number {
  let count = 0
  for (const e of view.edges) {
    if (kept.has(e.from) && kept.has(e.to)) count++
  }
  return count
}

/** Bands that still hide members under `kept` — each needs a group
 * summary, and group summaries count toward the node budget. */
function hiddenBandCount(lists: Map<TopoBand, string[]>, kept: Set<string>): number {
  let count = 0
  for (const band of BAND_ORDER) {
    if (lists.get(band)!.some(id => !kept.has(id))) count++
  }
  return count
}

/** Tail-retirement: the LAST-ADDED seats retire first until BOTH budgets
 * fit. A pinned or expanded priority sits at the head, never at the tail,
 * so it never retires. */
function retireToFit(seq: string[], kept: Set<string>, lists: Map<TopoBand, string[]>, view: TopologyView, limits: MountLimits): void {
  while (seq.length > 0
    && (seq.length + hiddenBandCount(lists, kept) > limits.maxNodes || edgesWithin(view, kept) > limits.maxEdges)) {
    kept.delete(seq.pop()!)
  }
}

/** Round-robin allocation under both budgets: seats first, tail-retirement
 * second. Deterministic in the list orders and the budgets alone. */
function allocateBounded(lists: Map<TopoBand, string[]>, view: TopologyView, limits: MountLimits): Set<string> {
  const seq = allocateRounds(lists, limits.maxNodes)
  const kept = new Set(seq)
  retireToFit(seq, kept, lists, view, limits)
  return kept
}

/** The band whose group the operator expanded (never under an active
 * query — the query already shrinks the pool). */
function expandedBandOf(sel: MountSelection): TopoBand | null {
  const id = sel.expandedGroupId
  if (sel.queryActive || id === null) return null
  const band = id.slice('group:'.length) as TopoBand
  return BAND_ORDER.includes(band) ? band : null
}

/** The operator's selection, pinned: a selected real entry (never a group
 * stand-in) is seated first in its band — no bounded mount may evict it,
 * so clearing or broadening a search never loses the inspected entry. */
function pinnedId(view: TopologyView, sel: MountSelection): string | null {
  const id = sel.selectedId
  if (id === null || id.startsWith('group:')) return null
  return view.bandOf.has(id) ? id : null
}

/** The band's priority order: the pinned selection first, then the
 * expanded band's hidden members (relative to the DEFAULT mount's post-fit
 * kept set), then the rest — content order preserved inside each tier.
 * Rotation changes WHO mounts, never the naming order. */
function priorityOrder(list: string[], pinned: string | null, expanded: boolean, defaultKept: Set<string>): string[] {
  const head = pinned === null ? [] : [pinned]
  if (expanded) head.push(...list.filter(id => id !== pinned && !defaultKept.has(id)))
  const prioritized = (id: string): boolean => id === pinned || (expanded && !defaultKept.has(id))
  return [...head, ...list.filter(id => !prioritized(id))]
}

/** Re-allocate under the SAME budgets with the mount's priorities
 * applied: the pinned selection, then the named expansion. */
function boundedWithPriority(lists: Map<TopoBand, string[]>, view: TopologyView, limits: MountLimits, sel: MountSelection, defaultKept: Set<string>): Set<string> {
  const expanded = expandedBandOf(sel)
  const pinned = pinnedId(view, sel)
  if (expanded === null && pinned === null) return defaultKept
  // The pin belongs to exactly ONE band — the band lists partition the
  // pool, so seating the selection anywhere else would double-book the
  // node budget and evict real entries. (Regression: the pin used to be
  // prepended to every band list, seating one id four times.)
  const pinnedBand = pinned === null ? null : view.bandOf.get(pinned) ?? 'model'
  const prioritized = new Map(lists)
  for (const band of BAND_ORDER) {
    prioritized.set(band, priorityOrder(lists.get(band)!, band === pinnedBand ? pinned : null, band === expanded, defaultKept))
  }
  return allocateBounded(prioritized, view, limits)
}

/** Group summaries: hidden members NAMED in content order, one per band
 * that keeps members hidden. */
function collectGroups(lists: Map<TopoBand, string[]>, kept: Set<string>): Map<string, GroupSummary> {
  const groups = new Map<string, GroupSummary>()
  for (const band of BAND_ORDER) {
    const hidden = lists.get(band)!.filter(id => !kept.has(id))
    if (hidden.length > 0) groups.set(`group:${band}`, { band, memberIds: hidden, hiddenEdgeCount: 0 })
  }
  return groups
}

/** The hidden endpoint's band: the target if hidden, else the source
 * (missing phantoms fold into the model band). */
function hiddenEndpointBand(e: TopoEdge, kept: Set<string>, bandOf: Map<string, TopoBand>): TopoBand {
  const hidden = kept.has(e.to) ? e.from : e.to
  return bandOf.get(hidden) ?? 'model'
}

/** A pool-internal edge: BOTH endpoints are mount candidates. An edge an
 * ACTIVE QUERY filtered out (an endpoint outside the pool) is hidden by
 * SEARCH, not by grouping — it is never a candidate for attribution. */
function poolInternal(e: TopoEdge, poolIds: Set<string>): boolean {
  return poolIds.has(e.from) && poolIds.has(e.to)
}

/** Attribute every pool-internal hidden edge exactly once — to the band of
 * the hidden `to` if any, else the band of the hidden `from`. That band
 * always has a group when the edge is hidden by the budget (query-only
 * hiding is not grouping and stays uncounted). */
function attributeHiddenEdges(view: TopologyView, kept: Set<string>, groups: Map<string, GroupSummary>, poolIds: Set<string>): void {
  for (const e of view.edges) {
    if (!poolInternal(e, poolIds)) continue
    if (kept.has(e.from) && kept.has(e.to)) continue
    const group = groups.get(`group:${hiddenEndpointBand(e, kept, view.bandOf)}`)
    if (group !== undefined) group.hiddenEdgeCount++
  }
}

/** Group stand-in nodes: labeled first…last in content order, carrying the named summary. */
function groupNodes(groups: Map<string, GroupSummary>, byId: Map<string, TopoNode>): TopoNode[] {
  return [...groups.entries()].map(([gid, group]) => {
    const first = byId.get(group.memberIds[0]!)!
    const last = byId.get(group.memberIds[group.memberIds.length - 1]!)!
    return {
      id: gid,
      kind: 'group' as const,
      label: group.memberIds.length === 1 ? first.label : `${first.label}…${last.label}`,
      sublabel: '',
      enabled: true,
      warningCodes: [],
      group,
    }
  })
}

export function mountTopology(view: TopologyView, sel: MountSelection, limits: MountLimits = MOUNT_LIMITS): MountedTopology {
  const totals = { nodes: view.nodes.length, edges: view.edges.length }
  const byId = new Map(view.nodes.map(n => [n.id, n]))

  // The candidate pool, then the budgets. A pool inside both budgets
  // renders verbatim — the baseline small graph and every focused search
  // result mount untouched, with no grouping at all.
  const pool = mountPool(view, sel)
  const lists = bandListsFor(pool, view.bandOf)
  const poolIds = new Set(pool.map(n => n.id))
  let kept = new Set(poolIds)
  if (pool.length > limits.maxNodes || edgesWithin(view, kept) > limits.maxEdges) {
    const defaultKept = allocateBounded(lists, view, limits)
    kept = boundedWithPriority(lists, view, limits, sel, defaultKept)
  }
  const groups = collectGroups(lists, kept)
  attributeHiddenEdges(view, kept, groups, poolIds)

  // The mounted view: kept nodes in content order, then the group
  // summaries — layout, DOM ids and keyboard focus see ONLY this view, so
  // the canvas can never mount more than the budgets allow.
  const bandOf = new Map(view.bandOf)
  for (const [gid, group] of groups) bandOf.set(gid, group.band)
  const nodes: TopoNode[] = view.nodes.filter(n => kept.has(n.id))
  nodes.push(...groupNodes(groups, byId))
  const edges = view.edges.filter(e => kept.has(e.from) && kept.has(e.to))
  return {
    view: { graph: view.graph, nodes, edges, adjacency: indexAdjacency(edges), bandOf },
    groups,
    totals,
    grouped: groups.size > 0,
  }
}
