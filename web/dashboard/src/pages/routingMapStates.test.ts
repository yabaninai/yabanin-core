import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

// CV-01 (V01 rendering child): the routing map's state wiring, pinned at
// source level (the JSX pages cannot execute under the node strip-types
// harness; the pure view model they render IS executed in
// src/lib/routingTopology.test.ts, and the API error branches in
// src/api/routing.test.ts):
//
//   - failure is honest: the map is cleared (no stale rows painted as
//     current), and the notice copy branches on the status the API contract
//     defines (401/403 session/permission; 404 foreign-org OR
//     member-without-permission — indistinguishable by design; anything
//     else is a plain failure) with ONE next action: retry;
//   - reloading with a previous map is stale, not loading-from-scratch:
//     the old configuration stays visible under a stale notice;
//   - partial is named, not hidden: configured-but-unregistered targets
//     (missingTargetNames) get a partial notice; the graph renders them as
//     dashed phantoms (pinned in routingGraph.test.ts);
//   - the graph is the topology visualizer: lanes alias → rule → model →
//     provider, uniform edge width (width is never traffic), the olive
//     selected path, icon+text status, motion only under
//     prefers-reduced-motion: no-preference.

const here = dirname(fileURLToPath(import.meta.url))
const src = (...parts: string[]): string => readFileSync(join(here, ...parts), 'utf8')

describe('CV-01 routing map states (V01 rendering child)', () => {
  it('RoutingMapPage: failure branches on the status contract and always offers retry', () => {
    const page = src('RoutingMapPage.tsx')
    assert.match(page, /status === 401 \|\| status === 403\) return t\('routingMap\.mapSessionRequired'\)/,
      '401/403 is a session/permission problem with its own copy')
    assert.match(page, /status === 404\) return t\('routingMap\.mapNoAccess'\)/,
      '404 says both possible causes — the API deliberately does not distinguish them')
    assert.match(page, /return t\('routingMap\.mapFailed'\)/, 'any other failure is the plain load-failure copy')
    assert.match(page, /action=\{\{ label: t\('common\.retry'\), onClick: onRetry \}\}/,
      'the one useful next action is retry')
    assert.match(page, /onRetry=\{\(\) => setMapTick\(n => n \+ 1\)\} \/>/,
      'retry bumps the tick that re-runs the map effect')
  })

  it('RoutingMapPage: a failed load drops the stale map and records why', () => {
    const page = src('RoutingMapPage.tsx')
    assert.match(page, /\.catch\(\(err: unknown\) => \{[\s\S]*?setMap\(null\)[\s\S]*?setMapState\('failed'\)/,
      'failure clears the map — old data is never painted as current')
    assert.match(page, /err instanceof ApiError \? \{ status: err\.status, message: err\.message \} : \{ message: String\(err\) \}/,
      'the HTTP status is captured for the copy branch')
    assert.match(page, /import \{ ApiError \} from '\.\.\/api\/transport'/, 'ApiError comes from the transport layer')
  })

  it('RoutingMapPage: reloading with a map is stale, not loading-from-scratch', () => {
    const page = src('RoutingMapPage.tsx')
    assert.match(page, /if \(mapState === 'loading'\) \{\s*return map === null\s*\?\s*<StateNotice state="loading" \/>\s*: <StateNotice state="stale" message=\{t\('routingMap\.mapStale'\)\} \/>\s*\}/,
      'loading-with-map is the stale notice; loading-without-map is loading')
    assert.match(page, /map !== null && \(mapState === 'ready' \|\| mapState === 'loading'\)/,
      'the previous configuration stays visible while reloading')
  })

  it('RoutingMapPage: partial input is named through missingTargetNames', () => {
    const page = src('RoutingMapPage.tsx')
    assert.match(page, /import \{ missingTargetNames \} from '\.\.\/lib\/routingTopology'/,
      'the partial input is the pure model over the payload, not a UI re-derivation')
    assert.match(page, /const missingTargets = useMemo\(\(\) => \(map === null \? \[\] : missingTargetNames\(map\)\), \[map\]\)/,
      'recomputed per map, null-safe')
    assert.match(page, /<MissingTargetsNotice names=\{missingTargets\} \/>/, 'rendered above the payload views')
    assert.match(page, /state="partial"[\s\S]*?message=\{t\('routingMap\.mapPartial'\)\}/,
      'a partial StateNotice, never a fake complete view')
    assert.match(page, /if \(names\.length === 0\) return null/, 'absent when the input is complete')
  })

  it('RoutingGraph: renders the topology model — lanes, uniform edges, olive path', () => {
    const graph = src('..', 'components', 'astra', 'RoutingGraph.tsx')
    assert.match(graph, /import \{[\s\S]*?buildTopology, focusTopology, layoutTopology, selectionPath,[\s\S]*?\} from '\.\.\/\.\.\/lib\/routingTopology'/,
      'the component consumes the pure topology view model')
    const edgeView = graph.slice(graph.indexOf('function TopoEdgeView'), graph.indexOf('function TopoNodeView'))
    assert.match(graph, /const EDGE_W = 1\.5/, 'one edge width constant')
    assert.match(edgeView, /strokeWidth=\{EDGE_W\}/, 'every edge uses it')
    assert.doesNotMatch(edgeView, /strokeWidth=\{[^}]*\?/, 'edge width never branches — width would read as traffic volume')
    assert.match(graph, /onPath\) return \{ stroke: 'var\(--astra-selection\)'/,
      'the selected path is olive, through the astra selection token')
    assert.match(graph, /hasSelection && !onPath \? 0\.35 : 1/, 'selection dims off-path content instead of widening anything')
    const bandBlock = graph.slice(graph.indexOf('const BAND_KEY'), graph.indexOf('const NAV:'))
    for (const key of ['laneAliases', 'laneRules', 'laneModels', 'laneProviders']) {
      assert.ok(bandBlock.includes(`'routingMap.${key}'`), `${key} lives in the BAND_KEY map`)
    }
    const bands = [...graph.matchAll(/'routingMap\.lane(?:Aliases|Rules|Models|Providers)'/g)]
    assert.equal(bands.length, 4, 'lane titles are not scattered — only the BAND_KEY map names them')
    assert.match(graph, /BAND_KEY: Record<TopoBand, string>/, 'all four bands titled')
    assert.match(graph, /'\u25CF' : '\u25CB'/, "registry status carries a \u25CF/\u25CB icon next to its text")
    assert.match(graph, /className="routing-topo"/, 'the svg opts into the motion rules')
  })

  it('RoutingGraph: the honest-error affordances survive the rewrite', () => {
    const graph = src('..', 'components', 'astra', 'RoutingGraph.tsx')
    for (const testid of [
      'routing-graph',
      'routing-graph-canvas',
      'routing-graph-search',
      'routing-graph-reset',
      'routing-graph-count',
      'routing-graph-edge',
      'routing-graph-node-',
      'routing-graph-inspector',
      'routing-graph-mode-config',
      'routing-graph-mode-recorded',
      'routing-graph-mode-simulation',
    ]) {
      assert.ok(graph.includes(`"${testid}`) || graph.includes(`\`${testid}`) || graph.includes(testid),
        `${testid} testid preserved`)
    }
    assert.match(graph, /<StateNotice state="empty" message=\{t\('routingMap\.graphEmpty'\)\} \/>/,
      'an empty registry is an explicit empty state, not a blank canvas')
    assert.match(graph, /flowOut[\s\S]*?edge\.owner === nodeId/, 'chain ownership still reads as outgoing flow')
  })

  it('index.css: topology transitions, none under prefers-reduced-motion', () => {
    const css = src('..', 'index.css')
    assert.match(css, /\.routing-topo \.topo-edge,\s*\.routing-topo \.topo-node \{\s*transition: opacity 140ms ease-out, stroke 140ms ease-out;\s*\}/,
      'opacity/stroke-only ease for selection')
    const reduced = css.match(/@media \(prefers-reduced-motion: reduce\) \{[\s\S]*?\n\}/)
    assert.ok(reduced !== null, 'the reduced-motion block exists')
    assert.match(reduced![0], /\.routing-topo \.topo-edge,\s*\.routing-topo \.topo-node \{ transition: none; \}/,
      'selection eases are disabled there')
  })
})
