// CV-01 (V01 rendering child): node:test coverage for the topology view
// model — provider lane derivation, lane layout (determinism + the reorder
// oracle), the olive selection path, focus over provider nodes, and the
// missing-target input for the partial state. The pure model keeps the SVG
// composition testable without a browser.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildTopology, focusTopology, layoutTopology, missingTargetNames, selectionPath,
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
