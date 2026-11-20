// CV-01 (V01 rendering child): node:test coverage for the topology view
// model — provider lane derivation, lane layout (determinism + the reorder
// oracle), the olive selection path, focus over provider nodes, and the
// missing-target input for the partial state. The pure model keeps the SVG
// composition testable without a browser.
// The bounded-mount section covers the scale contract: oracle-counted final
// fixtures (200/400 and 1000/5000), budget bounds with exact-total
// conservation, named group expansion, search reducing the MOUNT, isolated
// limit controls, and source pins that the component renders the bounded
// mount (never the unbounded view).
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  buildTopology, focusTopology, layoutTopology, missingTargetNames, selectionPath,
  mountTopology, MOUNT_LIMITS, type MountSelection,
  HEADER_H,
} from './routingTopology.ts'
import { NODE_H, PAD, LANE_ROWS, ROW_GAP } from './routingGraph.ts'
import type { RoutingMap } from '../api/routing.ts'

// Mirrors the imp47b fixture shape: a chain into a disabled model, a chain
// into a nonexistent model, a self-loop, plus alias/rule entries.
const MAP: RoutingMap = {
  org_id: 'org-1',
  models: [
    { model_name: 'm-primary', display_name: 'Primary', tier: 'medium', provider: 'zai', enabled: true, fallback_model: 'm-second', failover_models: [], tier_pool: [] },
    { model_name: 'm-second', display_name: 'Second', tier: 'easy', provider: 'local', enabled: true, fallback_model: null, failover_models: ['m-off', 'm-ghost'], tier_pool: [] },
    { model_name: 'm-cyc', display_name: 'Cycle', tier: 'easy', provider: 'local', enabled: true, fallback_model: null, failover_models: ['m-cyc'], tier_pool: [] },
    { model_name: 'm-off', display_name: 'Off', tier: 'easy', provider: 'local', enabled: false, fallback_model: null, failover_models: [], tier_pool: [] },
  ],
  aliases: [{ alias: 'smart', target_model: 'm-off' }],
  rules: [{ id: 'rule-9', match_expr: 'label.tier == "free"', target_model: 'm-off', priority: 10, enabled: true }],
  warnings: [
    { code: 'chain_cycle', scope: 'model', source: 'm-cyc', target: 'm-cyc', message: 'loops' },
    { code: 'chain_target_disabled', scope: 'model', source: 'm-second', target: 'm-off', message: 'disabled hop' },
    { code: 'chain_target_missing', scope: 'model', source: 'm-second', target: 'm-ghost', message: 'no such model' },
    { code: 'alias_target_disabled', scope: 'alias', source: 'smart', target: 'm-off', message: 'disabled target' },
    { code: 'rule_target_disabled', scope: 'rule', source: 'rule-9', target: 'm-off', message: 'disabled target' },
  ],
}

// The same payload with every array reordered — identical nodes must render
// at identical positions (V01 non-negotiable: reordering identical API
// nodes never moves anything).
const SHUFFLED: RoutingMap = {
  ...MAP,
  models: [...MAP.models].reverse(),
  aliases: [...MAP.aliases].reverse(),
  rules: [...MAP.rules].reverse(),
  warnings: [...MAP.warnings].reverse(),
}

test('buildTopology: one provider node per distinct provider, one uniform config edge per model', () => {
  const view = buildTopology(MAP)
  const providers = view.nodes.filter(n => n.kind === 'provider')
  assert.deepEqual(providers.map(p => p.label), ['local', 'zai']) // sorted by name
  const providerEdges = view.edges.filter(e => e.kind === 'provider')
  assert.equal(providerEdges.length, 4) // one per registry model
  assert.ok(providerEdges.some(e => e.from === 'model:m-primary' && e.to === 'provider:zai'))
  assert.ok(providerEdges.some(e => e.from === 'model:m-off' && e.to === 'provider:local'))
  // Edges carry no warnings of their own (server warnings target config
  // edges; provider grouping is a derivation, never a verdict).
  for (const e of providerEdges) assert.deepEqual(e.warningCodes, [])
})

test('buildTopology: a missing phantom never gets a provider edge', () => {
  const view = buildTopology(MAP)
  assert.ok(view.nodes.some(n => n.id === 'missing:m-ghost'))
  assert.ok(!view.edges.some(e => e.from === 'missing:m-ghost'))
  assert.ok(!view.edges.some(e => e.to.startsWith('provider:') && e.from.startsWith('missing:')))
  // Phantoms belong to the model band (a would-be model), not a lane of
  // their own.
  assert.equal(view.bandOf.get('missing:m-ghost'), 'model')
})

test('buildTopology: base graph edges and warning attachment pass through untouched', () => {
  const view = buildTopology(MAP)
  const base = view.edges.filter(e => e.kind !== 'provider')
  assert.equal(base.length, view.graph.edges.length)
  const aliasEdge = base.find(e => e.kind === 'alias')
  assert.deepEqual(aliasEdge?.warningCodes, ['alias_target_disabled'])
})

test('layoutTopology: lanes ordered alias → rule → model → provider, chains strictly right', () => {
  const view = buildTopology(MAP)
  const l = layoutTopology(view)
  const x = (id: string) => l.boxes.get(id)?.x ?? -1
  assert.ok(x('alias:smart') < x('rule:rule-9'), 'alias lane left of rule lane')
  assert.ok(x('rule:rule-9') < x('model:m-primary'), 'rule lane left of models')
  assert.ok(x('model:m-primary') < x('model:m-second'), 'failover hop lands further right')
  assert.ok(x('model:m-second') < x('missing:m-ghost'), 'phantom sits past its predecessor')
  // Providers are the rightmost lane; every model is left of its provider.
  assert.ok(x('model:m-primary') < x('provider:zai'))
  assert.ok(x('model:m-off') < x('provider:local'))
  const providerX = Math.min(x('provider:zai'), x('provider:local'))
  for (const n of view.nodes.filter(n => n.kind !== 'provider')) {
    assert.ok(x(n.id) < providerX, `${n.id} must sit left of the provider lane`)
  }
  // Band headers cover exactly the bands that exist, in lane order.
  assert.deepEqual(l.headers.map(h => h.band), ['alias', 'rule', 'model', 'provider'])
})

test('layoutTopology: deterministic, non-overlapping, and reorder-stable (the oracle)', () => {
  const a = layoutTopology(buildTopology(MAP))
  const b = layoutTopology(buildTopology(MAP))
  assert.deepEqual([...a.boxes.entries()], [...b.boxes.entries()])
  const shuffled = layoutTopology(buildTopology(SHUFFLED))
  assert.deepEqual([...shuffled.boxes.entries()], [...a.boxes.entries()],
    'reordering the API arrays must not move any node')
  assert.deepEqual(
    buildTopology(SHUFFLED).nodes.map(n => n.id),
    buildTopology(MAP).nodes.map(n => n.id),
    'node order (paint order, DOM ids) is content-sorted, not payload-sorted',
  )
  const boxes = [...a.boxes.values()]
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const p = boxes[i]!, q = boxes[j]!
      const overlap = p.x < q.x + q.w && q.x < p.x + p.w && p.y < q.y + q.h && q.y < p.y + p.h
      assert.equal(overlap, false, `boxes ${i} and ${j} overlap`)
    }
  }
})

test('layoutTopology: long model lanes wrap instead of growing unbounded', () => {
  const many = Array.from({ length: 30 }, (_, i) => ({
    model_name: `m-${String(i).padStart(2, '0')}`,
    display_name: `M${i}`, tier: 'easy', provider: 'local', enabled: true,
    fallback_model: null, failover_models: [], tier_pool: [],
  }))
  const view = buildTopology({ org_id: 'o', models: many, aliases: [], rules: [], warnings: [] })
  const l = layoutTopology(view)
  const maxY = Math.max(...[...l.boxes.values()].map(b => b.y + b.h))
  assert.ok(maxY <= HEADER_H + PAD + LANE_ROWS * (NODE_H + ROW_GAP), `height ${maxY} stays within one lane`)
  const modelXs = new Set([...l.boxes.entries()]
    .filter(([id, b]) => view.bandOf.get(id) === 'model' && b.y === HEADER_H + PAD)
    .map(([, b]) => b.x))
  assert.equal(modelXs.size, 3, '30 models wrap into 3 lanes')
})

test('selectionPath: an alias selection highlights its full path to the provider', () => {
  const view = buildTopology(MAP)
  const path = selectionPath(view, 'alias:smart')
  // Downstream of the alias: its target, that target's own outgoing hop
  // (m-second's hop 2 starts at m-off) and the provider. rule-9 also enters
  // m-off but is not ON a path through the selection — it stays off.
  assert.deepEqual([...path.nodeIds].sort(),
    ['alias:smart', 'missing:m-ghost', 'model:m-off', 'provider:local'])
  const aliasEdge = view.edges.find(e => e.kind === 'alias')!
  const providerEdge = view.edges.find(e => e.kind === 'provider' && e.from === 'model:m-off')!
  const ghostHop = view.edges.find(e => e.to === 'missing:m-ghost')!
  const ruleEdge = view.edges.find(e => e.kind === 'rule')!
  assert.ok(path.edgeIds.has(aliasEdge.id), 'the alias edge is on the path')
  assert.ok(path.edgeIds.has(providerEdge.id), 'the model→provider edge is on the path')
  assert.ok(path.edgeIds.has(ghostHop.id), 'the outgoing hop from the selected path is on the path')
  assert.ok(!path.edgeIds.has(ruleEdge.id), 'an alternative entry into the path is not on it')
  assert.equal(path.edgeIds.size, 3)
})

test('selectionPath: a chain-owner selection follows every hop it configured', () => {
  const view = buildTopology(MAP)
  const path = selectionPath(view, 'model:m-second')
  assert.ok(path.nodeIds.has('missing:m-ghost'), 'the missing hop-2 target is on the path')
  const ghostHop = view.edges.find(e => e.to === 'missing:m-ghost')!
  assert.ok(path.edgeIds.has(ghostHop.id))
  // Upstream: m-primary's chain reaches m-second, so its hop is on the path.
  const upstream = view.edges.find(e => e.kind === 'chain' && e.from === 'model:m-primary')!
  assert.ok(path.edgeIds.has(upstream.id))
})

test('selectionPath: a self-loop stays on its own path; null selects nothing', () => {
  const view = buildTopology(MAP)
  const loop = view.edges.find(e => e.from === e.to)!
  const path = selectionPath(view, loop.from)
  assert.ok(path.edgeIds.has(loop.id), 'the server-flagged cycle edge is drawn on its path')
  const none = selectionPath(view, null)
  assert.equal(none.edgeIds.size, 0)
  assert.equal(none.nodeIds.size, 0)
})

test('focusTopology: provider names match, with 1-hop context', () => {
  const view = buildTopology(MAP)
  const f = focusTopology(view, 'ZAI')
  assert.ok(f.matchedIds.has('provider:zai'), 'the provider node matches')
  assert.ok(f.matchedIds.has('model:m-primary'), 'its models match via provider field')
  assert.ok(f.focusIds.has('provider:zai'))
  const empty = focusTopology(view, '   ')
  assert.equal(empty.focusIds.size, view.nodes.length, 'empty query focuses everything, providers included')
  const miss = focusTopology(view, 'does-not-exist')
  assert.equal(miss.noMatches, true)
})

test('missingTargetNames: the honest partial input, deduplicated and sorted', () => {
  assert.deepEqual(missingTargetNames(MAP), ['m-ghost'])
  const empty = { org_id: 'o', models: [], aliases: [{ alias: 'a', target_model: 'ghost' }], rules: [], warnings: [] }
  assert.deepEqual(missingTargetNames(empty), ['ghost'])
})

test('buildTopology: an empty payload is an honest empty topology', () => {
  const view = buildTopology({ org_id: 'o', models: [], aliases: [], rules: [], warnings: [] })
  assert.equal(view.nodes.length, 0)
  assert.equal(view.edges.length, 0)
  const l = layoutTopology(view)
  assert.equal(l.headers.length, 0)
  assert.equal(l.boxes.size, 0)
})

// ===== Bounded mount (the scale contract) =====
//
// The final acceptance-class tenants, generated with exact arithmetic and
// verified FIRST against an oracle that counts nodes/edges straight from
// the payload rows (registry models + aliases + rules + referenced-but-
// absent names + distinct providers; chain hops + entry rows + provider
// rows). The expected data is never self-computed from the code under test:
// the literals (200/400, 1000/5000) are the acceptance numbers.
//
//  * org-standard: 156 models · 24 aliases · 8 rules · 4 missing · 8
//    providers = 200 nodes; 212 chain hops + 24 + 8 + 156 = 400 edges.
//  * org-stress: 804 models · 100 aliases · 60 rules · 16 missing · 20
//    providers = 1000 nodes; 4036 chain hops + 100 + 60 + 804 = 5000 edges.

/** A chain/alias/rule reference to an absent model — named, never guessed. */
const noteMissing = (known: Set<string>, missing: Set<string>, name: string): void => {
  if (!known.has(name)) missing.add(name)
}

const hasFallback = (m: RoutingMap['models'][number]): boolean => (m.fallback_model ?? '').trim() !== ''

/** Chain edges straight from the payload rows: every failover hop of every model, plus the fallback when set. */
function chainHopCount(map: RoutingMap, known: Set<string>, missing: Set<string>): number {
  let hops = 0
  for (const m of map.models) {
    for (const step of m.failover_models) {
      hops++
      noteMissing(known, missing, step)
    }
    if (hasFallback(m)) {
      hops++
      noteMissing(known, missing, m.fallback_model!)
    }
  }
  return hops
}

/** Counts nodes/edges straight from the payload rows: registry models +
 * aliases + rules + referenced-but-absent names + distinct providers;
 * chain hops + entry rows + provider rows. The literals (200/400,
 * 1000/5000) are the acceptance numbers. */
function payloadOracle(map: RoutingMap): { nodes: number; edges: number } {
  const known = new Set(map.models.map(m => m.model_name))
  const missing = new Set<string>()
  const hops = chainHopCount(map, known, missing)
  for (const a of map.aliases) noteMissing(known, missing, a.target_model)
  for (const r of map.rules) noteMissing(known, missing, r.target_model)
  const providers = new Set(map.models.map(m => m.provider).filter(p => p !== ''))
  return {
    nodes: map.models.length + map.aliases.length + map.rules.length + missing.size + providers.size,
    edges: hops + map.aliases.length + map.rules.length + map.models.length,
  }
}

const pad3 = (i: number) => String(i).padStart(3, '0')
const pad2 = (i: number) => String(i).padStart(2, '0')

function standardFinalMap(): RoutingMap {
  const models = Array.from({ length: 156 }, (_, i) => ({
    model_name: `nm-${pad3(i)}`,
    display_name: `Model ${i}`,
    tier: 'easy', provider: `np-${i % 8}`, enabled: i % 9 !== 4,
    fallback_model: null,
    failover_models: [
      // 4 chains point at a missing target (named, counted by the oracle):
      i % 40 === 10 ? `sx-${pad2((i - 10) / 40)}` : `nm-${pad3((i + 3) % 156)}`,
      ...(i < 56 ? [`nm-${pad3((i + 7) % 156)}`] : []),
    ],
    tier_pool: [],
  }))
  return {
    org_id: 'org-standard',
    models,
    aliases: Array.from({ length: 24 }, (_, i) => ({ alias: `na-${pad2(i)}`, target_model: `nm-${pad3((i * 5) % 156)}` })),
    rules: Array.from({ length: 8 }, (_, i) => ({
      id: `nr-${i}`, match_expr: `label.tier == "t${i}"`, target_model: `nm-${pad3((i * 11) % 156)}`, priority: i + 1, enabled: true,
    })),
    warnings: [10, 50, 90, 130].map(i => ({
      code: 'chain_target_missing', scope: 'model', source: `nm-${pad3(i)}`, target: `sx-${pad2((i - 10) / 40)}`, message: 'no such model',
    })),
  }
}

function stressMap(): RoutingMap {
  const models = Array.from({ length: 804 }, (_, i) => ({
    model_name: `sn-${pad3(i)}`,
    display_name: `Model ${i}`,
    tier: 'easy', provider: `sp-${i % 20}`, enabled: i % 9 !== 4,
    fallback_model: null,
    failover_models: [
      // 5 real in-band hops for every model, plus a 6th missing hop for the
      // 16 models at i % 50 === 2 below 800 (16 distinct phantom names).
      ...Array.from({ length: 5 }, (_, k) => `sn-${pad3((i + 1 + k) % 804)}`),
      ...(i % 50 === 2 && i < 800 ? [`sx-${pad2(Math.floor(i / 50))}`] : []),
    ],
    tier_pool: [],
  }))
  const missing = Array.from({ length: 16 }, (_, k) => k)
  return {
    org_id: 'org-stress',
    models,
    aliases: Array.from({ length: 100 }, (_, i) => ({ alias: `sa-${pad3(i)}`, target_model: `sn-${pad3((i * 3) % 804)}` })),
    rules: Array.from({ length: 60 }, (_, i) => ({
      id: `sr-${pad2(i)}`, match_expr: `label.tier == "s${i}"`, target_model: `sn-${pad3((i * 7) % 804)}`, priority: i + 1, enabled: true,
    })),
    warnings: missing.map(k => ({
      code: 'chain_target_missing', scope: 'model', source: `sn-${pad3(2 + k * 50)}`, target: `sx-${pad2(k)}`, message: 'no such model',
    })),
  }
}

/**
 * The pinning/attribution fixture: 80 models, 80 aliases and 80 rules each
 * targeting their same-index model, one provider — 241 nodes, 240 edges,
 * no phantoms, no failover hops. With maxNodes 20 every seat is visible:
 * the round-robin takes 6 alias + 6 rule + 6 model + 1 provider = 19
 * seats, the 20th takes one more alias, and tail-retirement gives it back
 * — 17 real nodes + 3 band groups = exactly 20.
 */
function pinFixture(): RoutingMap {
  const models = Array.from({ length: 80 }, (_, i) => ({
    model_name: `m${pad3(i)}`,
    display_name: `Model ${i}`,
    tier: 'easy', provider: 'prov', enabled: true,
    fallback_model: null,
    failover_models: [],
    tier_pool: [],
  }))
  return {
    org_id: 'org-pin',
    models,
    aliases: Array.from({ length: 80 }, (_, i) => ({ alias: `a${pad3(i)}`, target_model: `m${pad3(i)}` })),
    rules: Array.from({ length: 80 }, (_, i) => ({
      id: `r${pad3(i)}`, match_expr: `label.tier == "t${i}"`, target_model: `m${pad3(i)}`, priority: i + 1, enabled: true,
    })),
    warnings: [],
  }
}

const IDLE: MountSelection = { focusIds: new Set(), queryActive: false, selectedId: null, expandedGroupId: null }

test('fixtures meet the final acceptance class exactly (oracle over payload rows)', () => {
  assert.deepEqual(payloadOracle(standardFinalMap()), { nodes: 200, edges: 400 })
  assert.deepEqual(payloadOracle(stressMap()), { nodes: 1000, edges: 5000 })
  // The view model agrees with the payload oracle on both tenants:
  const a = buildTopology(standardFinalMap())
  const b = buildTopology(stressMap())
  assert.equal(a.nodes.length, 200)
  assert.equal(a.edges.length, 400)
  assert.equal(b.nodes.length, 1000)
  assert.equal(b.edges.length, 5000)
})

test('mountTopology: a view inside the budgets mounts verbatim — no groups, no reordering', () => {
  const view = buildTopology(standardFinalMap())
  const mount = mountTopology(view, IDLE)
  assert.equal(mount.grouped, false)
  assert.deepEqual(mount.view.nodes.map(n => n.id), view.nodes.map(n => n.id))
  assert.deepEqual(mount.view.edges.map(e => e.id), view.edges.map(e => e.id))
  assert.deepEqual(mount.totals, { nodes: 200, edges: 400 })
  assert.deepEqual([...mount.groups.entries()], [])
})

test('mountTopology: the stress tenant groups down to the budgets with exact totals (conservation)', () => {
  const map = stressMap()
  const oracle = payloadOracle(map)
  const mount = mountTopology(buildTopology(map), IDLE)
  assert.deepEqual(mount.totals, { nodes: oracle.nodes, edges: oracle.edges })
  assert.ok(mount.view.nodes.length <= MOUNT_LIMITS.maxNodes, `mounted nodes ${mount.view.nodes.length} must be ≤ ${MOUNT_LIMITS.maxNodes}`)
  assert.ok(mount.view.edges.length <= MOUNT_LIMITS.maxEdges, `mounted edges ${mount.view.edges.length} must be ≤ ${MOUNT_LIMITS.maxEdges}`)
  assert.equal(mount.grouped, true)
  assert.ok(mount.groups.size >= 1, 'at least one named band group')
  // Conservation — nothing invented, nothing lost:
  const groupedMembers = [...mount.groups.values()].reduce((n, g) => n + g.memberIds.length, 0)
  assert.equal(mount.view.nodes.filter(n => n.kind !== 'group').length + groupedMembers, oracle.nodes)
  const hiddenEdges = [...mount.groups.values()].reduce((n, g) => n + g.hiddenEdgeCount, 0)
  assert.equal(mount.view.edges.length + hiddenEdges, oracle.edges)
  // Groups are named per band, deterministic, and count toward the budget:
  for (const [gid, g] of mount.groups) {
    assert.match(gid, /^group:(alias|rule|model|provider)$/)
    assert.ok(g.memberIds.length >= 1, 'a group always names real members')
    assert.equal(mount.view.nodes.find(n => n.id === gid)?.kind, 'group')
    for (const id of g.memberIds) assert.ok(!mount.view.nodes.some(n => n.id === id), 'a member is never double-mounted')
  }
})

test('mountTopology: deterministic and reorder-stable under bounding', () => {
  const map = stressMap()
  const a = mountTopology(buildTopology(map), IDLE)
  const b = mountTopology(buildTopology(map), IDLE)
  assert.deepEqual(a.view.nodes.map(n => n.id), b.view.nodes.map(n => n.id))
  assert.deepEqual([...a.groups.entries()].map(([k, g]) => [k, g.memberIds]), [...b.groups.entries()].map(([k, g]) => [k, g.memberIds]))
  assert.deepEqual([...a.groups.entries()].map(([, g]) => g.hiddenEdgeCount), [...b.groups.entries()].map(([, g]) => g.hiddenEdgeCount))
  // Reordering the API arrays must not move the mounted set, the groups or
  // the rendered layout (the scale contract keeps the reorder oracle).
  const shuffled: RoutingMap = {
    ...map,
    models: [...map.models].reverse(),
    aliases: [...map.aliases].reverse(),
    rules: [...map.rules].reverse(),
    warnings: [...map.warnings].reverse(),
  }
  const c = mountTopology(buildTopology(shuffled), IDLE)
  assert.deepEqual(c.view.nodes.map(n => n.id), a.view.nodes.map(n => n.id))
  assert.deepEqual([...c.groups.entries()].map(([k, g]) => [k, g.memberIds]), [...a.groups.entries()].map(([k, g]) => [k, g.memberIds]))
  assert.deepEqual([...layoutTopology(c.view).boxes.entries()], [...layoutTopology(a.view).boxes.entries()])
})

test('mountTopology: named expansion mounts hidden members under the SAME budgets', () => {
  const view = buildTopology(stressMap())
  const base = mountTopology(view, IDLE)
  const group = base.groups.get('group:model')
  assert.ok(group, 'the model band groups')
  const named = group.memberIds[0]!
  // The member is named INDEPENDENTLY (content-order arithmetic: the model
  // band's first hidden entry in the default mount is sn-361):
  assert.equal(named, 'model:sn-361', 'the independently named first hidden member')
  assert.ok(!base.view.nodes.some(n => n.id === named), 'the named member starts hidden')
  // …and so is one specific incident edge — the member's own provider edge
  // (its provider mounts in every bounded mount, so the edge appears
  // exactly when the member does):
  const incident = view.edges.find(e => e.from === named && e.kind === 'provider')
  assert.ok(incident, 'the named member has an incident provider edge')
  assert.ok(!base.view.edges.some(b => b.id === incident!.id), 'that incident edge starts hidden in the base mount')
  const expanded = mountTopology(view, { ...IDLE, expandedGroupId: 'group:model' })
  assert.ok(expanded.view.nodes.some(n => n.id === named), 'expansion mounts the first hidden member')
  assert.ok(expanded.view.edges.some(e => e.id === incident!.id), 'expansion mounts the named member AND its incident edge')
  assert.ok(expanded.view.nodes.length <= MOUNT_LIMITS.maxNodes, 'expansion still respects the node budget')
  assert.ok(expanded.view.edges.length <= MOUNT_LIMITS.maxEdges, 'expansion still respects the edge budget')
  assert.deepEqual(expanded.totals, { nodes: 1000, edges: 5000 }, 'the labeled totals stay exact after expansion')
  // Exact totals and conservation are unchanged by expansion:
  assert.deepEqual(expanded.totals, base.totals)
  const groupedMembers = [...expanded.groups.values()].reduce((n, g) => n + g.memberIds.length, 0)
  assert.equal(expanded.view.nodes.filter(n => n.kind !== 'group').length + groupedMembers, 1000)
  const hiddenEdges = [...expanded.groups.values()].reduce((n, g) => n + g.hiddenEdgeCount, 0)
  assert.equal(expanded.view.edges.length + hiddenEdges, 5000)
  // Expanding a band that has nothing hidden is a no-op (accordion):
  if (!base.groups.has('group:provider')) {
    const noop = mountTopology(view, { ...IDLE, expandedGroupId: 'group:provider' })
    assert.deepEqual(noop.view.nodes.map(n => n.id), base.view.nodes.map(n => n.id))
  }
})

test('mountTopology: an active query reduces the MOUNT (not the dimming)', () => {
  const view = buildTopology(stressMap())
  const focus = focusTopology(view, 'sx-')
  assert.equal(focus.matchedIds.size, 16, 'the 16 missing phantoms match by name')
  const mount = mountTopology(view, { ...IDLE, queryActive: true, focusIds: focus.focusIds })
  assert.ok(mount.view.nodes.length > 0)
  assert.ok(mount.view.nodes.length <= MOUNT_LIMITS.maxNodes)
  // Everything mounted is focus; every match is mounted — hidden members
  // become reachable through search instead of staying grouped:
  for (const n of mount.view.nodes) assert.ok(focus.focusIds.has(n.id), `${n.id} mounted outside the focus`)
  for (const id of focus.matchedIds) assert.ok(mount.view.nodes.some(n => n.id === id), `${id} must be mounted`)
  assert.equal(mount.grouped, false, 'a focused result inside the budgets renders verbatim')
  assert.deepEqual(mount.totals, { nodes: 1000, edges: 5000 }, 'totals stay exact under search')
})

test('mountTopology: a broad query still bounds, with groups and exact totals', () => {
  const view = buildTopology(stressMap())
  const focus = focusTopology(view, 'sn-0')
  const mount = mountTopology(view, { ...IDLE, queryActive: true, focusIds: focus.focusIds })
  assert.ok(mount.view.nodes.length <= MOUNT_LIMITS.maxNodes)
  assert.ok(mount.view.edges.length <= MOUNT_LIMITS.maxEdges)
  // FULL totals stay exact (the count chip reports the whole map)…
  assert.deepEqual(mount.totals, { nodes: 1000, edges: 5000 })
  // …while conservation holds relative to the query's candidate POOL (the
  // non-focus entries are search-filtered, not grouped away).
  const pool = focus.focusIds.size
  const groupedMembers = [...mount.groups.values()].reduce((n, g) => n + g.memberIds.length, 0)
  assert.equal(mount.view.nodes.filter(n => n.kind !== 'group').length + groupedMembers, pool)
  const hiddenEdges = [...mount.groups.values()].reduce((n, g) => n + g.hiddenEdgeCount, 0)
  assert.equal(mount.view.edges.length + hiddenEdges <= 5000, true)
  for (const n of mount.view.nodes) {
    if (n.kind === 'group') continue // group summaries stand for focus entries
    assert.ok(focus.focusIds.has(n.id), `${n.id} mounted outside the focus`)
  }
})

test('mountTopology: a no-match query mounts nothing, totals stay exact', () => {
  const view = buildTopology(stressMap())
  const mount = mountTopology(view, { ...IDLE, queryActive: true, focusIds: new Set() })
  assert.equal(mount.view.nodes.length, 0)
  assert.equal(mount.view.edges.length, 0)
  assert.deepEqual(mount.totals, { nodes: 1000, edges: 5000 })
})

test('mountTopology: the selection always stays mounted', () => {
  const view = buildTopology(stressMap())
  const selectedId = view.nodes.find(n => n.kind === 'model')!.id
  const mount = mountTopology(view, { ...IDLE, queryActive: true, focusIds: new Set(), selectedId })
  assert.ok(mount.view.nodes.some(n => n.id === selectedId), 'the selected node survives even a no-match query')
})

test('mountTopology: a model selected through a search survives clearing or broadening the query (pinned selection)', () => {
  const view = buildTopology(stressMap())
  const base = mountTopology(view, IDLE)
  const hiddenId = base.groups.get('group:model')!.memberIds[0]!
  assert.ok(!base.view.nodes.some(n => n.id === hiddenId), 'the pinned model starts hidden in the default mount')
  // Via search the hidden model mounts (the pool is focus + selection)…
  const focus = focusTopology(view, hiddenId.slice('model:'.length))
  const viaSearch = mountTopology(view, { ...IDLE, queryActive: true, focusIds: focus.focusIds, selectedId: hiddenId })
  assert.ok(viaSearch.view.nodes.some(n => n.id === hiddenId))
  // …and clearing the query restores the FULL pool under the SAME budgets
  // without evicting the operator's selection into the group:
  const cleared = mountTopology(view, { ...IDLE, selectedId: hiddenId })
  assert.ok(cleared.view.nodes.some(n => n.id === hiddenId), 'the selection was evicted on query clear')
  assert.ok(!cleared.groups.get('group:model')!.memberIds.includes(hiddenId), 'the selection was grouped away on query clear')
  assert.ok(cleared.view.nodes.length <= MOUNT_LIMITS.maxNodes)
  assert.ok(cleared.view.edges.length <= MOUNT_LIMITS.maxEdges)
  assert.deepEqual(cleared.totals, { nodes: 1000, edges: 5000 })
  let conserved = cleared.view.nodes.filter(n => n.kind !== 'group').length
  for (const g of cleared.groups.values()) conserved += g.memberIds.length
  assert.equal(conserved, 1000, 'conservation with the selection pinned')
  // Broadening the query instead of clearing keeps the same guarantees —
  // the budgets still bind on the broad pool:
  const broad = focusTopology(view, 'sn')
  assert.ok(broad.focusIds.size > MOUNT_LIMITS.maxNodes, 'a genuinely broad pool — the budgets bind')
  const broadened = mountTopology(view, { ...IDLE, queryActive: true, focusIds: broad.focusIds, selectedId: hiddenId })
  assert.ok(broadened.view.nodes.some(n => n.id === hiddenId), 'the selection was evicted on query broaden')
  assert.ok(broadened.view.nodes.length <= MOUNT_LIMITS.maxNodes)
  assert.ok(broadened.view.edges.length <= MOUNT_LIMITS.maxEdges)
  assert.deepEqual(broadened.totals, { nodes: 1000, edges: 5000 })
  let conserved2 = broadened.view.nodes.filter(n => n.kind !== 'group').length
  for (const g of broadened.groups.values()) conserved2 += g.memberIds.length
  assert.equal(conserved2, broad.focusIds.size, 'pool-relative conservation with the selection pinned')
})

test('mountTopology: pinning the selection never double-books a seat (exactly one occurrence per real node)', () => {
  const limits = { maxNodes: 20, maxEdges: Infinity }
  const view = buildTopology(pinFixture())
  assert.deepEqual(payloadOracle(pinFixture()), { nodes: 241, edges: 240 }, 'independent fixture oracle: 80+80+80+1 nodes, 80+80+80 edges')
  const base = mountTopology(view, IDLE, limits)
  // Independent literal: 17 real nodes + 3 band groups = exactly the 20 seats.
  assert.equal(base.view.nodes.filter(n => n.kind !== 'group').length, 17, 'the default mount seats 17 real nodes')
  assert.equal(base.view.nodes.length, 20, '17 real nodes + 3 groups = exactly the node budget')
  const hiddenId = base.groups.get('group:model')!.memberIds[0]!
  assert.equal(hiddenId, 'model:m005', 'the first hidden model, named independently')
  // Pinning that model must keep ALL 17 real seats (regression: the pin
  // used to be seated once per band, 4 duplicate seats, evicting 3 real
  // nodes down to 14):
  const pinned = mountTopology(view, { ...IDLE, selectedId: hiddenId }, limits)
  assert.equal(pinned.view.nodes.filter(n => n.kind !== 'group').length, 17, 'pinning evicts no real node (regression: was 14)')
  assert.equal(pinned.view.nodes.length, 20)
  assert.ok(pinned.view.nodes.some(n => n.id === hiddenId), 'the selection stays mounted')
  assert.ok(!pinned.groups.get('group:model')!.memberIds.includes(hiddenId), 'the selection is not grouped away')
  let conserved = pinned.view.nodes.filter(n => n.kind !== 'group').length
  for (const g of pinned.groups.values()) conserved += g.memberIds.length
  assert.equal(conserved, 241, 'conservation with the selection pinned')
  const expanded = mountTopology(view, { ...IDLE, selectedId: hiddenId, expandedGroupId: 'group:model' }, limits)
  assert.equal(expanded.view.nodes.filter(n => n.kind !== 'group').length, 17, 'pin plus expansion must not consume a second seat')
  assert.equal(expanded.groups.size, 3)
  assert.equal(expanded.view.nodes.length, 20)
  assert.ok(expanded.view.nodes.some(n => n.id === 'model:m009'), 'the selected hidden member must not displace m009')
})

test('mountTopology: a query hides only pool-internal edges — search filtering is not grouping', () => {
  const limits = { maxNodes: 20, maxEdges: Infinity }
  const view = buildTopology(pinFixture())
  const focus = focusTopology(view, 'm00')
  assert.equal(focus.focusIds.size, 31, '10 models + their 10 aliases + 10 rules + the provider')
  // Independent candidate-edge oracle: BOTH endpoints in the pool —
  // 10 alias + 10 rule + 10 provider edges = 30.
  let candidates = 0
  for (const e of view.edges) {
    if (focus.focusIds.has(e.from) && focus.focusIds.has(e.to)) candidates++
  }
  assert.equal(candidates, 30)
  const mount = mountTopology(view, { ...IDLE, queryActive: true, focusIds: focus.focusIds }, limits)
  assert.ok(mount.view.nodes.length <= limits.maxNodes)
  assert.deepEqual(mount.totals, { nodes: 241, edges: 240 }, 'the labeled totals stay exact under search')
  // The displayed hidden total counts ONLY pool-internal hidden edges
  // (regression: edges the query filtered out were attributed too,
  // displaying 225 hidden of a 30-edge candidate pool):
  const hidden = [...mount.groups.values()].reduce((n, g) => n + g.hiddenEdgeCount, 0)
  assert.equal(hidden, 15, 'hidden = the pool-internal hidden edges only (regression: was 225)')
  assert.equal(mount.view.edges.length, 15, 'mounted edges (independent literal)')
  assert.equal(mount.view.edges.length + hidden, 30, 'pool-relative edge conservation — search filtering is not grouping')
})

// The CV-01 discriminating fixture: 240 matching models, optionally plus
// 80 completely disjoint NONMATCHING models whose only edges are to each
// other (a fallback ring). The query filters them out of the pool, so the
// two datasets must produce byte-identical mounts and identical group
// counts (regression: the disjoint ring's 80 edges used to be attributed
// to group:model, displaying 122 hidden instead of 42).
function cvFilterFixture(withUnrelated: boolean): RoutingMap {
  const models = (count: number, label: string, provider: string) => Array.from({ length: count }, (_, i) => ({
    model_name: `${label}-${pad3(i)}`,
    display_name: `${label} model ${i}`,
    provider, enabled: true, tier: 'easy', fallback_model: null,
    failover_models: [], tier_pool: [],
  }))
  const matching = models(240, 'cohort', 'a')
  const other = models(80, 'elsewhere', 'b')
  for (let i = 0; i < other.length; i++) other[i]!.fallback_model = other[(i + 1) % other.length]!.model_name
  return { org_id: 'fixture', models: withUnrelated ? [...matching, ...other] : matching, aliases: [], rules: [], warnings: [] }
}

test('mountTopology: rows the query filtered out never change the visible group count (independent CV-01 fixture)', () => {
  const report = (withUnrelated: boolean) => {
    const view = buildTopology(cvFilterFixture(withUnrelated))
    const focus = focusTopology(view, 'cohort')
    const mount = mountTopology(view, { focusIds: focus.focusIds, queryActive: true, selectedId: null, expandedGroupId: null })
    const group = mount.groups.get('group:model')!
    assert.ok(group.memberIds.length > 0, 'the model band groups')
    const members = new Set(group.memberIds)
    // Independent oracle: edges hidden from the mount whose endpoints are
    // BOTH still inside the query pool (both endpoints touch a member).
    let expected = 0
    for (const e of view.edges) {
      if ((members.has(e.from) || members.has(e.to)) && focus.focusIds.has(e.from) && focus.focusIds.has(e.to)) expected++
    }
    return {
      matched: focus.matchedIds.size,
      members: [...members].sort(),
      mounted: mount.view.nodes.map(n => n.id).sort(),
      displayed: group.hiddenEdgeCount,
      expected,
    }
  }
  const isolated = report(false)
  const unrelated = report(true)
  assert.deepEqual(isolated.members, unrelated.members, 'group membership is identical')
  assert.deepEqual(isolated.mounted, unrelated.mounted, 'the mount is identical')
  assert.equal(isolated.expected, unrelated.expected, 'the pool-internal oracle is identical')
  // Independent literals from the CV-01 record:
  assert.equal(isolated.matched, 240)
  assert.equal(isolated.members.length, 42)
  assert.equal(isolated.displayed, 42, 'the isolated dataset displays 42 hidden group edges')
  assert.equal(unrelated.displayed, 42, 'never 122: filtered-out rows must not change the visible group count')
  assert.equal(isolated.displayed, isolated.expected)
})

test('mountTopology: the pinned selection and the named expansion compose deterministically', () => {
  const view = buildTopology(stressMap())
  const base = mountTopology(view, IDLE)
  const hiddenId = base.groups.get('group:model')!.memberIds[0]!
  const sel = { ...IDLE, selectedId: hiddenId, expandedGroupId: 'group:model' }
  const a = mountTopology(view, sel)
  const b = mountTopology(view, sel)
  assert.deepEqual(a.view.nodes.map(n => n.id), b.view.nodes.map(n => n.id))
  assert.deepEqual([...a.groups.entries()].map(([k, g]) => [k, g.memberIds]), [...b.groups.entries()].map(([k, g]) => [k, g.memberIds]))
  assert.ok(a.view.nodes.some(n => n.id === hiddenId), 'the selection stays mounted while the band is expanded')
  assert.ok(a.view.nodes.length <= MOUNT_LIMITS.maxNodes)
  assert.ok(a.view.edges.length <= MOUNT_LIMITS.maxEdges)
  assert.deepEqual(a.totals, { nodes: 1000, edges: 5000 })
})

test('mountTopology: two tenants stay isolated (no cross-tenant leak)', () => {
  const a = mountTopology(buildTopology(standardFinalMap()), IDLE)
  const b = mountTopology(buildTopology(stressMap()), IDLE)
  const idsA = new Set(a.view.nodes.filter(n => n.kind !== 'group').map(n => n.id))
  const membersA = new Set([...a.groups.values()].flatMap(g => g.memberIds))
  for (const n of b.view.nodes) {
    if (n.kind === 'group') continue
    assert.ok(!idsA.has(n.id), `${n.id} leaked across tenants`)
  }
  for (const g of b.groups.values()) {
    for (const id of g.memberIds) assert.ok(!membersA.has(id), `${id} leaked across tenants`)
  }
})

// The isolated controls: each half of the bound on its own, and the
// original unbounded behavior reproduced deliberately (red, then green).
test('isolated control: with no budgets the mount is the original unbounded failure', () => {
  const view = buildTopology(stressMap())
  const unbounded = mountTopology(view, IDLE, { maxNodes: Infinity, maxEdges: Infinity })
  assert.equal(unbounded.grouped, false)
  assert.ok(unbounded.view.nodes.length > MOUNT_LIMITS.maxNodes, '1000 mounted nodes — the original failure')
  assert.ok(unbounded.view.edges.length > MOUNT_LIMITS.maxEdges, '5000 mounted edges — the original failure')
  assert.equal(unbounded.view.nodes.length, 1000)
  assert.equal(unbounded.view.edges.length, 5000)
})

test('isolated control: each budget binds on its own (node-only / edge-only)', () => {
  const view = buildTopology(stressMap())
  const nodesOnly = mountTopology(view, IDLE, { maxNodes: 60, maxEdges: Infinity })
  assert.ok(nodesOnly.view.nodes.length <= 60, 'the node budget alone still groups')
  assert.equal(nodesOnly.grouped, true)
  const edgesOnly = mountTopology(view, IDLE, { maxNodes: Infinity, maxEdges: 120 })
  assert.ok(edgesOnly.view.edges.length <= 120, 'the edge budget alone still groups')
  assert.equal(edgesOnly.grouped, true)
})

test('RoutingGraph (source pins): the canvas renders the BOUNDED mount, never the unbounded view', () => {
  const src = readFileSync(new URL('../components/astra/RoutingGraph.tsx', import.meta.url), 'utf8')
  // The mount is derived before render from the FULL view + selection state:
  assert.match(src, /const mount = useMemo\(\s*\(\) => mountTopology\(view, \{ focusIds: focus\.focusIds, queryActive, selectedId, expandedGroupId \}\),\s*\[view, focus, queryActive, selectedId, expandedGroupId\],\s*\)/)
  // Layout, lookup and DOM ids see only the bounded mounted view:
  assert.match(src, /layoutTopology\(mount\.view\)/)
  assert.match(src, /new Map\(mount\.view\.nodes\.map\(n => \[n\.id, n\]\)\)/)
  assert.match(src, /mount\.view\.nodes\.forEach\(\(n, i\) => idx\.set\(n\.id, `rg-node-\$\{i\}`\)\)/)
  // The canvas receives the mounted view plus the FULL exact totals:
  assert.match(src, /view=\{mount\.view\}/)
  assert.match(src, /totals=\{mount\.totals\}/)
  // The count chip and the selected path keep the FULL view (exact totals):
  assert.match(src, /<MatchCount view=\{view\}/)
  assert.match(src, /selectionPath\(view, selectedId\)/)
  // Group selection expands the named hidden members and reset clears it:
  assert.match(src, /setExpandedGroupId\(prev => \(prev === id \? null : id\)\)/)
  assert.match(src, /setExpandedGroupId\(null\)/)
  // Group summaries carry exact hidden member and edge counts:
  assert.match(src, /node\.group\?\.memberIds\.length \?\? 0/)
})
