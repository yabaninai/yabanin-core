// UI-DEV slice 1: node:test coverage for the routing graph model —
// construction from the real /api/routing/map payload, missing-target
// phantoms, warning attachment, search focus, and the deterministic layered
// layout (including the cycle guard). These are the acceptance cases the SVG
// view renders; the pure model keeps them testable without a browser.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildRoutingGraph, focusSubgraph, layoutRoutingGraph, edgeEndpoints, isBackEdge,
  nearestNode, NODE_H, NODE_W,
} from './routingGraph.ts'
import type { NodeBox } from './routingGraph.ts'
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

test('buildRoutingGraph: nodes and edges from the payload', () => {
  const g = buildRoutingGraph(MAP)
  const ids = g.nodes.map(n => n.id)
  assert.ok(ids.includes('model:m-primary'))
  assert.ok(ids.includes('alias:smart'))
  assert.ok(ids.includes('rule:rule-9'))
  // Entries connect to the registry model.
  const aliasEdge = g.edges.find(e => e.kind === 'alias')
  assert.equal(aliasEdge?.from, 'alias:smart')
  assert.equal(aliasEdge?.to, 'model:m-off')
  // Rule edge carries the priority label.
  const ruleEdge = g.edges.find(e => e.kind === 'rule')
  assert.equal(ruleEdge?.label, 'p10')
  // Chain hops follow the gateway order with 1-based hop labels. Hop 2 of
  // m-second's chain (into the phantom) starts at the previous hop's node.
  const chain = g.edges.filter(e => e.kind === 'chain')
  assert.ok(chain.some(e => e.from === 'model:m-primary' && e.to === 'model:m-second' && e.label === '1'))
  assert.ok(chain.some(e => e.from === 'model:m-second' && e.to === 'model:m-off' && e.label === '1'))
  assert.ok(chain.some(e => e.from === 'model:m-off' && e.to === 'missing:m-ghost' && e.label === '2'))
  // Every chain edge remembers the model whose config created it.
  for (const e of chain) assert.ok(e.owner.startsWith('model:'))
})

test('buildRoutingGraph: an unknown target becomes a missing phantom, never dropped', () => {
  const g = buildRoutingGraph(MAP)
  const ghost = g.nodes.find(n => n.id === 'missing:m-ghost')
  assert.ok(ghost, 'phantom node exists')
  assert.equal(ghost.kind, 'missing')
  assert.equal(ghost.label, 'm-ghost')
  // And it is reachable by an edge (the gap is drawn where traffic hits it).
  assert.ok(g.edges.some(e => e.to === 'missing:m-ghost'))
})

test('buildRoutingGraph: server warnings attach to nodes and their edges', () => {
  const g = buildRoutingGraph(MAP)
  const byId = new Map(g.nodes.map(n => [n.id, n]))
  assert.deepEqual(byId.get('model:m-cyc')!.warningCodes, ['chain_cycle'])
  assert.deepEqual(byId.get('model:m-second')!.warningCodes, ['chain_target_disabled', 'chain_target_missing'])
  assert.deepEqual(byId.get('alias:smart')!.warningCodes, ['alias_target_disabled'])
  assert.deepEqual(byId.get('rule:rule-9')!.warningCodes, ['rule_target_disabled'])
  // Edge-level: the exact hop the OWNER's config draws into the disabled /
  // missing target is flagged (hop 2 of m-second's chain ends at the phantom).
  const intoOff = g.edges.find(e => e.owner === 'model:m-second' && e.to === 'model:m-off')
  assert.deepEqual(intoOff?.warningCodes, ['chain_target_disabled'])
  const intoGhost = g.edges.find(e => e.to === 'missing:m-ghost')
  assert.deepEqual(intoGhost?.warningCodes, ['chain_target_missing'])
  // Entries' own edges carry their warnings.
  assert.deepEqual(g.edges.find(e => e.kind === 'alias')?.warningCodes, ['alias_target_disabled'])
  assert.deepEqual(g.edges.find(e => e.kind === 'rule')?.warningCodes, ['rule_target_disabled'])
})

test('buildRoutingGraph: adjacency lists the chain owner on hop-2+ edges', () => {
  const g = buildRoutingGraph(MAP)
  const flows = g.adjacency.get('model:m-second') ?? []
  // m-second owns a 2-hop chain: → m-off (hop 1), m-off → m-ghost (hop 2).
  // Hop 2's endpoints do not include m-second, yet its config draws it — the
  // owner's flow list must contain every hop (UI-DEV e2e regression: the
  // inspector omitted the missing-target hop).
  assert.equal(flows.length, 3)
  const ghostHop = flows.find(e => e.to === 'missing:m-ghost')
  assert.ok(ghostHop, 'owner sees its hop-2 edge')
  assert.equal(ghostHop.owner, 'model:m-second')
  assert.equal(ghostHop.from, 'model:m-off')
})

test('buildRoutingGraph: empty payload is an honest empty graph', () => {
  const g = buildRoutingGraph({ org_id: 'o', models: [], aliases: [], rules: [], warnings: [] })
  assert.equal(g.nodes.length, 0)
  assert.equal(g.edges.length, 0)
})

test('focusSubgraph: empty query focuses everything, matches nothing', () => {
  const g = buildRoutingGraph(MAP)
  const f = focusSubgraph(g, '   ')
  assert.equal(f.focusIds.size, g.nodes.length)
  assert.equal(f.matchedIds.size, 0)
  assert.equal(f.noMatches, false)
})

test('focusSubgraph: a match keeps its 1-hop context for readability', () => {
  const g = buildRoutingGraph(MAP)
  // Searching the primary model keeps its failover target in view.
  const f = focusSubgraph(g, 'm-primary')
  assert.ok(f.matchedIds.has('model:m-primary'))
  assert.ok(f.focusIds.has('model:m-second'))
  assert.ok(!f.focusIds.has('alias:smart'))
  // Searching an alias keeps the alias AND its target.
  const a = focusSubgraph(g, 'smart')
  assert.ok(a.matchedIds.has('alias:smart'))
  assert.ok(a.focusIds.has('model:m-off'))
  // Provider is searchable too.
  const p = focusSubgraph(g, 'ZAI')
  assert.ok(p.matchedIds.has('model:m-primary'))
})

test('focusSubgraph: no honest match reports noMatches', () => {
  const g = buildRoutingGraph(MAP)
  const f = focusSubgraph(g, 'does-not-exist')
  assert.equal(f.noMatches, true)
  assert.equal(f.matchedIds.size, 0)
  assert.equal(f.focusIds.size, 0)
})

test('layoutRoutingGraph: entries left, chain hops strictly right, deterministic', () => {
  const g = buildRoutingGraph(MAP)
  const l1 = layoutRoutingGraph(g)
  const l2 = layoutRoutingGraph(g)
  // Deterministic across runs.
  assert.deepEqual([...l1.boxes.entries()], [...l2.boxes.entries()])

  const col = (id: string) => l1.columns.get(id) ?? -1
  assert.equal(col('alias:smart'), 0)
  assert.equal(col('rule:rule-9'), 0)
  assert.ok(col('model:m-primary') >= 1)
  assert.ok(col('model:m-second') > col('model:m-primary'), 'failover hop is a column further right')
  assert.ok(col('model:m-off') > col('model:m-second'))
  assert.ok(col('missing:m-ghost') > col('model:m-second'), 'phantom sits past its predecessor')
  // The self-looping model stays with its peers (cycle guard).
  assert.ok(col('model:m-cyc') >= 1 && col('model:m-cyc') < g.edges.length + 2)

  // Boxes do not overlap inside a lane and respect node metrics.
  const boxes = [...l1.boxes.values()]
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i]!, b = boxes[j]!
      const overlap = a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
      assert.equal(overlap, false, `boxes ${i} and ${j} overlap`)
    }
  }
  assert.equal(boxes[0]!.w, NODE_W)
  assert.equal(boxes[0]!.h, NODE_H)
  assert.ok(l1.width >= NODE_W)
  assert.ok(l1.height >= NODE_H)
})

test('layoutRoutingGraph: long columns wrap into lanes instead of growing unbounded', () => {
  const many = Array.from({ length: 30 }, (_, i) => ({
    model_name: `m-${String(i).padStart(2, '0')}`,
    display_name: `M${i}`, tier: 'easy', provider: 'local', enabled: true,
    fallback_model: null, failover_models: [], tier_pool: [],
  }))
  const g = buildRoutingGraph({ org_id: 'o', models: many, aliases: [], rules: [], warnings: [] })
  const l = layoutRoutingGraph(g)
  // 30 requestable models wrap into 3 lanes of ≤10 rows: height stays
  // bounded to one lane and three distinct x offsets exist.
  const maxY = Math.max(...[...l.boxes.values()].map(b => b.y + b.h))
  assert.ok(maxY <= 12 + 10 * (NODE_H + 18) + NODE_H, `height ${maxY} stays within one lane`)
  assert.equal(new Set([...l.boxes.values()].map(b => b.x)).size, 3, '30 nodes wrap into 3 lanes')
})

test('edgeEndpoints: straight connector leaves right and enters left', () => {
  const a = { x: 0, y: 0, w: NODE_W, h: NODE_H }
  const b = { x: 400, y: 100, w: NODE_W, h: NODE_H }
  const { a: p1, b: p2 } = edgeEndpoints(a, b)
  assert.equal(p1.x, NODE_W)
  assert.equal(p1.y, NODE_H / 2)
  assert.equal(p2.x, 400)
  assert.equal(p2.y, 100 + NODE_H / 2)
  assert.equal(isBackEdge(a, b), false)
  assert.equal(isBackEdge(b, a), true, 'a right-to-left edge is a back edge and needs a curve')
})

test('edgeEndpoints: a self-loop leaves top and re-enters right', () => {
  const box = { x: 10, y: 10, w: NODE_W, h: NODE_H }
  const { a, b } = edgeEndpoints(box, { ...box })
  assert.equal(a.y, 10, 'leaves at the top edge')
  assert.equal(b.x, 10 + NODE_W, 're-enters on the right edge')
})

test('nearestNode: arrow moves pick the nearest advancing node, never backwards', () => {
  const boxes = new Map<string, NodeBox>([
    ['a', { x: 0, y: 0, w: NODE_W, h: NODE_H }],
    ['b', { x: 0, y: NODE_H + 18, w: NODE_W, h: NODE_H }], // straight below a
    ['c', { x: NODE_W + 90, y: 20, w: NODE_W, h: NODE_H }], // right, slight drift
    ['d', { x: NODE_W + 90, y: 500, w: NODE_W, h: NODE_H }], // right, far drift
  ])
  assert.equal(nearestNode(boxes, 'a', 'down'), 'b')
  assert.equal(nearestNode(boxes, 'a', 'right'), 'c')
  assert.equal(nearestNode(boxes, 'b', 'up'), 'a')
  // Left of the leftmost column there is nothing — the key is a no-op there.
  assert.equal(nearestNode(boxes, 'a', 'left'), null)
  assert.equal(nearestNode(boxes, 'a', 'up'), null)
  assert.equal(nearestNode(boxes, 'missing', 'right'), null)
})
