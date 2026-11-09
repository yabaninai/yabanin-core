// the dashboard half of the contract examples — the wire response a discovery
// call returns is shaped into render state, and the manual-entry fallback
// stays available after every outcome. Scenario-level pins only: the refusal
// matrix and the reason-hint locale coverage live in
// turns the refusal pins in this file red.
//
// D-1..D-6 scenario table over the facts (matrix + panel composition +
// registry load state), plus broken-vs-fixed proofs — five planted matrix
// regressions, two planted panel regressions and the finding-2 load/outage
// conflation are each caught by the anchors, i.e. the checks distinguish
// broken behavior from fixed instead of re-stating the implementation.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildCreateInput, catalogStateFromError, catalogStateFromResult, crossCheckCatalog,
  emptyDraft, registryLoadState,
} from './providerKeysHelpers.ts'
import { modelDisplayState } from '../models/helpers.ts'
import type { ModelState, ModelStateFacts } from '../models/helpers.ts'
import type { CatalogCrossCheck } from './providerKeysHelpers.ts'
import type { ProviderModelCatalog } from '../../api/providerCredentials.ts'

// Contract Example A: the parsed snapshot (discovered=true, verified=false)
// renders the ok catalog state — the model list and count only. The render
// state carries no verified flag at all: "ok" here means "snapshot parsed",
// never "verified usability".
test('scenario A: a parsed catalog snapshot renders the ok state with the model list and no verified claim', () => {
  const wire: ProviderModelCatalog = {
    provider: 'openai-compat',
    base_url: 'https://api.example-llm.dev/v1',
    count: 2,
    data: ['example-large', 'example-mini'],
    discovered: true,
    verified: false,
  }
  assert.deepEqual(
    catalogStateFromResult(wire),
    { phase: 'ok', models: ['example-large', 'example-mini'], count: 2 },
  )
})

// The three package-criterion refusals (contract §6 B: list API absent, key
// without list permission, revoked key): each stays an honest fail with its
// machine reason and NEVER carries catalog data into the state — a refusal
// that smuggled ids in would read as a partial success.
test('scenario B: list-absent / no-list-permission / revoked-key refusals render fail states without data', () => {
  const cases: Array<{ wire: ProviderModelCatalog, want: Record<string, unknown> }> = [
    {
      wire: { provider: 'openai-compat', count: 0, reason: 'models_list_unavailable', status: 404 },
      want: { phase: 'fail', reason: 'models_list_unavailable', status: 404, error: undefined },
    },
    {
      wire: { provider: 'openai-compat', count: 0, reason: 'key_forbidden', status: 403 },
      want: { phase: 'fail', reason: 'key_forbidden', status: 403, error: undefined },
    },
    {
      wire: { provider: 'openai-compat', count: 0, reason: 'key_unauthorized', status: 401 },
      want: { phase: 'fail', reason: 'key_unauthorized', status: 401, error: undefined },
    },
  ]
  for (const { wire, want } of cases) {
    assert.deepEqual(catalogStateFromResult(wire), want, `reason ${String(wire.reason)}`)
  }
})

// Acceptance: «Fallback ручного ввода» — no discovery outcome (snapshot,
// refusal, thrown transport) blocks or reshapes the manual-entry path: the
// create helper yields the same valid contract body after every outcome.
test('scenario C: the manual-entry fallback stays available after every discovery outcome', () => {
  const outcomes: Array<{ wire: ProviderModelCatalog, kind: string }> = [
    {
      wire: { provider: 'openai-compat', count: 2, data: ['example-large'], discovered: true, verified: false },
      kind: 'snapshot',
    },
    { wire: { provider: 'openai-compat', count: 0, reason: 'key_unauthorized', status: 401 }, kind: 'refusal' },
    { wire: { provider: 'openai-compat', count: 0, reason: 'transport_error', error: 'dial refused' }, kind: 'transport' },
  ]
  for (const { wire, kind } of outcomes) {
    catalogStateFromResult(wire)
    const manual = buildCreateInput({
      ...emptyDraft(),
      name: 'example-large',
      provider: 'openai-compat',
      baseUrl: 'https://api.example-llm.dev/v1',
      key: 'sk-manual-entry-fallback-0001',
    })
    assert.ok(manual.ok, `manual entry must stay available after a ${kind}`)
    if (manual.ok) {
      assert.deepEqual(manual.input, {
        name: 'example-large',
        provider: 'openai-compat',
        base_url: 'https://api.example-llm.dev/v1',
        key: 'sk-manual-entry-fallback-0001',
      })
    }
  }
  // A thrown discovery (network layer) is a fail and still no blocker.
  assert.deepEqual(
    catalogStateFromError(new Error('upstream unreachable')),
    { phase: 'fail', error: 'upstream unreachable' },
  )
})

// ---------------------------------------------------------------------------
//
// The anchors restate the ratified D-1..D-6 examples as observable behavior
// over the facts; the mutants are deliberately broken implementations of the
// same surface. The proof the card asks for: every mutant diverges from the
// fixed behavior on at least one anchored scenario — the net catches each
// regression instead of merely echoing the code.
// ---------------------------------------------------------------------------

// Normalized form for comparisons: reason-less states must not flip on
// undefined-vs-absent bookkeeping.
function normState(s: ModelState | null): string {
  if (s === null) return 'suspended'
  return JSON.stringify([s.state, s.reason ?? null])
}

function normCheck(c: CatalogCrossCheck): string {
  return JSON.stringify({
    snapshot: c.snapshotRows.map(r => [r.model, normState(r.state)]),
    absent: c.absentRows.map(r => [r.model, normState(r.state)]),
  })
}

/** The D-1 matrix anchors: facts → display state (contract examples 1–3, D-6). */
const MATRIX_ANCHORS: Array<{ name: string, facts: ModelStateFacts, want: ModelState }> = [
  {
    name: 'example 1a: discovered-but-not-configured renders discovered (never working)',
    facts: { registered: false, enabled: false, discovered: true },
    want: { state: 'discovered' },
  },
  {
    name: 'example 1b: configured + last /test PASSED renders verified',
    facts: { registered: true, enabled: true, discovered: true, testOk: true },
    want: { state: 'verified' },
  },
  {
    name: 'example 2: the operator switch beats a PASSED check (disabled + reason)',
    facts: { registered: true, enabled: false, discovered: true, testOk: true },
    want: { state: 'unavailable', reason: 'operator_disabled' },
  },
  {
    name: 'a configured model with no test evidence stays configured, never verified',
    facts: { registered: true, enabled: true },
    want: { state: 'configured' },
  },
  {
    name: 'a failed /test renders unavailable + check_failed',
    facts: { registered: true, enabled: true, testOk: false },
    want: { state: 'unavailable', reason: 'check_failed' },
  },
  {
    name: 'absent from the provider list beats a PASSED check (D-6)',
    facts: { registered: true, enabled: true, discovered: false, testOk: true },
    want: { state: 'unavailable', reason: 'absent_from_snapshot' },
  },
  {
    name: 'an unknown model never reads working, even with test evidence',
    facts: { registered: false, enabled: false, discovered: true, testOk: true },
    want: { state: 'discovered' },
  },
  {
    name: 'unknown and absent → unavailable + not_registered (manual-register hint)',
    facts: { registered: false, enabled: false, discovered: false },
    want: { state: 'unavailable', reason: 'not_registered' },
  },
]

/** Panel-composition anchors: what ProviderKeysSection derives per snapshot. */
const PANEL_ANCHORS: Array<{ name: string, opts: Parameters<typeof crossCheckCatalog>[0], want: string }> = [
  {
    name: 'ready slice: verified / discovered / operator_disabled / absent_from_snapshot in one pass',
    opts: {
      snapshot: ['glm', 'fresh'],
      testOk: true,
      registry: new Map([['glm', true], ['qwen', false], ['gone', true]]),
    },
    want: JSON.stringify({
      snapshot: [
        ['glm', normState({ state: 'verified' })],
        ['fresh', normState({ state: 'discovered' })],
      ],
      absent: [
        ['qwen', normState({ state: 'unavailable', reason: 'operator_disabled' })],
        ['gone', normState({ state: 'unavailable', reason: 'absent_from_snapshot' })],
      ],
    }),
  },
  {
    name: 'example 3: registry outage suspends every state and makes NO absence claims (never «missing»)',
    opts: { snapshot: ['glm'], registry: null },
    want: JSON.stringify({ snapshot: [['glm', 'suspended']], absent: [] }),
  },
  {
    name: 'no parsed snapshot → no absence claims, even with the slice',
    opts: { snapshot: undefined, testOk: true, registry: new Map([['glm', true]]) },
    want: JSON.stringify({ snapshot: [], absent: [] }),
  },
  {
    name: 'an empty parsed snapshot IS a real absence claim',
    opts: { snapshot: [], testOk: true, registry: new Map([['glm', true]]) },
    want: JSON.stringify({
      snapshot: [],
      absent: [['glm', normState({ state: 'unavailable', reason: 'absent_from_snapshot' })]],
    }),
  },
]

/** Registry load-state anchors (review finding 2: loading ≠ outage). */
const LOAD_ANCHORS: Array<{ name: string, opts: Parameters<typeof registryLoadState>[0], want: string }> = [
  {
    name: 'first load in flight → transient loading (no failure copy)',
    opts: { hasData: false, loading: true, error: '' },
    want: 'loading',
  },
  {
    name: 'error without data → true outage (failure copy earned)',
    opts: { hasData: false, loading: false, error: 'API error 503' },
    want: 'outage',
  },
  {
    name: 'data on screen → ready (a refresh never blanks the slice)',
    opts: { hasData: true, loading: true, error: '' },
    want: 'ready',
  },
]

// The planted regressions. Each is a plausible bug; the proof is that the
// anchors above DETECT it (diverge on ≥1 anchored scenario).
const MATRIX_MUTANTS: Array<{ name: string, run: (f: ModelStateFacts) => ModelState }> = [
  {
    name: 'regression: absence of test evidence upgraded to verified',
    run: f => {
      const s = modelDisplayState(f)
      return s.state === 'configured' ? { state: 'verified' } : s
    },
  },
  {
    name: 'regression: disabled loses to a PASSED check',
    run: f => {
      const s = modelDisplayState(f)
      return s.reason === 'operator_disabled' && f.testOk === true ? { state: 'verified' } : s
    },
  },
  {
    name: 'regression: snapshot absence loses to a PASSED check',
    run: f => {
      const s = modelDisplayState(f)
      return s.reason === 'absent_from_snapshot' && f.testOk === true ? { state: 'verified' } : s
    },
  },
  {
    name: 'regression: unknown model rendered as (merely) working',
    run: f => (f.registered ? modelDisplayState(f) : { state: 'configured' }),
  },
  {
    name: 'regression: failed check downgraded to a mere unproven state',
    run: f => {
      const s = modelDisplayState(f)
      return s.reason === 'check_failed' ? { state: 'configured' } : s
    },
  },
]

const PANEL_MUTANTS: Array<{ name: string, run: (o: Parameters<typeof crossCheckCatalog>[0]) => CatalogCrossCheck }> = [
  {
    name: 'regression: absence claimed without the registry slice',
    run: o => {
      if (o.registry !== null) return crossCheckCatalog(o)
      return {
        snapshotRows: (o.snapshot ?? []).map(model => ({
          model, state: { state: 'unavailable', reason: 'absent_from_snapshot' },
        })),
        absentRows: [],
      }
    },
  },
  {
    name: 'regression: outage rendered as «missing» (not_registered)',
    run: o => {
      if (o.registry !== null) return crossCheckCatalog(o)
      return {
        snapshotRows: (o.snapshot ?? []).map(model => ({
          model, state: { state: 'unavailable', reason: 'not_registered' },
        })),
        absentRows: [],
      }
    },
  },
]

const LOAD_MUTANTS: Array<{ name: string, run: (o: Parameters<typeof registryLoadState>[0]) => string }> = [
  {
    name: 'regression: transient load conflated with the outage (finding 2)',
    run: o => (o.hasData ? 'ready' : 'outage'),
  },
]

test('R068 anchors: the fixed matrix matches every D-1..D-6 scenario', () => {
  for (const a of MATRIX_ANCHORS) {
    assert.deepEqual(modelDisplayState(a.facts), a.want, `fixed matrix: ${a.name}`)
  }
})

test('R068 anchors: the panel composition matches every scenario, outages included', () => {
  for (const a of PANEL_ANCHORS) {
    assert.equal(normCheck(crossCheckCatalog(a.opts)), a.want, `fixed panel: ${a.name}`)
  }
})

test('R068 anchors: the registry load state distinguishes loading, outage and ready', () => {
  for (const a of LOAD_ANCHORS) {
    assert.equal(registryLoadState(a.opts).kind, a.want, `fixed load state: ${a.name}`)
  }
})

test('broken-vs-fixed: every planted matrix regression is caught by the anchors', () => {
  for (const m of MATRIX_MUTANTS) {
    const caught = MATRIX_ANCHORS.some(a => normState(m.run(a.facts)) !== normState(a.want))
    assert.ok(caught, `anchors FAIL to catch: ${m.name}`)
  }
})

test('broken-vs-fixed: every planted panel regression is caught by the anchors', () => {
  for (const m of PANEL_MUTANTS) {
    const caught = PANEL_ANCHORS.some(a => normCheck(m.run(a.opts)) !== a.want)
    assert.ok(caught, `anchors FAIL to catch: ${m.name}`)
  }
})

test('broken-vs-fixed: the load/outage conflation is caught by the anchors', () => {
  for (const m of LOAD_MUTANTS) {
    const caught = LOAD_ANCHORS.some(a => m.run(a.opts) !== a.want)
    assert.ok(caught, `anchors FAIL to catch: ${m.name}`)
  }
})
