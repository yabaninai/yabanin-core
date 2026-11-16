// CV-02 (one recorded request journey): node:test coverage for the pure
// journey view model over RequestDetail. The model binds every displayed
// fact to a stored request_logs column — reconciliation against the stored
// row is asserted fact-by-fact, absence is modelled explicitly (null is
// "not recorded", never 0/1), and a pre-upstream termination (budget 429
// projection: model_used='', literal duration 0) is a distinct stage state
// with NO fabricated attempt facts. The six fixtures mirror producer shapes
// documented in docs/visualizers/field-matrix.md.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildRequestJourney, decisionText, parseStoredDecision } from './requestJourney.ts'
import type { RequestDetail } from '../api/requests.ts'

// Minimal RequestDetail factory: the API contract fields the journey reads;
// every fixture states its own recorded/absent columns explicitly.
function row(over: Partial<RequestDetail>): RequestDetail {
  return {
    request_id: 'req-1',
    org_id: 'org-1',
    model_requested: 'gpt-4o',
    model_used: 'gpt-4o-mini',
    method: 'POST',
    status_code: 200,
    duration_ms: 2400,
    tokens_in: 120,
    tokens_out: 480,
    created_at: '2026-11-12T10:00:00Z',
    counterfactual_cost_usd: 0,
    cost_in_usd: 0.0021,
    home_region: 'us-east',
    ...over,
  }
}

// 1 — ordinary: full modern row with a recorded tier_router reroute.
const ORDINARY = row({
  routing_decision: JSON.stringify({
    source: 'tier_router', from: 'gpt-4o', to: 'gpt-4o-mini',
    class: 'medium', confidence: 0.62, threshold: 0.6,
    reason: 'tier match', rule: { id: 'b0392f47-1c2d-4e8a-9f10-112233445566', version: '3' },
  }),
  classifier_class: 'medium', classifier_confidence: 0.62, classifier_source: 'embedding',
  attempt_count: 2, retry_count: 1, first_token_ms: 812,
  upstream_url: 'https://api.openai.com/v1/chat/completions',
  prompt_hash: 'sha:9f2c',
  response_view: { status: 'complete', content: 'ok', finish_reason: 'stop' },
})

// 2 — blocked: the budget 429 projection — model_used forced '', literal
// duration 0, error set, no attempt/counter columns written (NULL).
const BLOCKED = row({
  model_used: '',
  status_code: 429,
  duration_ms: 0,
  error: 'budget_exceeded: daily',
  tokens_in: 0,
  tokens_out: 0,
  routing_decision: JSON.stringify({ source: 'passthrough', from: 'gpt-4o', to: 'gpt-4o' }),
  attempt_count: null, retry_count: null, first_token_ms: null,
})

// 3 — cache hit: exact semantic hit, no classifier columns, passthrough.
const CACHE_HIT = row({
  cache_hit_type: 'exact',
  routing_decision: JSON.stringify({ source: 'passthrough', from: 'gpt-4o', to: 'gpt-4o' }),
  attempt_count: 1, retry_count: 0, first_token_ms: 5,
})

// 4 — failed: upstream reached, errored, no processed answer view.
const FAILED = row({
  status_code: 502,
  error: 'upstream connect timeout',
  attempt_count: 3, retry_count: 2, first_token_ms: null,
})

// 5 — redacted: served, but the viewer-visible extras are absent (privacy
// redaction / originals-gated columns simply not present).
const REDACTED = row({
  status_code: 200,
  prompt_hash: 'sha:1a2b',
  response_view: { status: 'partial', content: 'truncated…', truncated: true },
})

// 6 — legacy: row predates decision capture and observability counters.
const LEGACY = row({
  routing_decision: undefined,
  attempt_count: null, retry_count: null, first_token_ms: null,
  prompt_hash: undefined,
})

test('ordinary: every journey fact reconciles with the stored row', () => {
  const j = buildRequestJourney(ORDINARY)
  // request stage
  assert.equal(j.request.method, ORDINARY.method)
  assert.deepEqual(j.request.modelRequested, { presence: 'recorded', value: 'gpt-4o' })
  assert.deepEqual(j.request.promptHash, { presence: 'recorded', value: 'sha:9f2c' })
  assert.equal(j.request.recordedAt, ORDINARY.created_at)
  // decision stage — parsed verbatim from the stored document
  assert.equal(j.decision.presence, 'recorded')
  assert.equal(j.decision.parseFailed, false)
  assert.equal(j.decision.source, 'tier_router')
  assert.equal(j.decision.from, 'gpt-4o')
  assert.equal(j.decision.to, 'gpt-4o-mini')
  assert.equal(j.decision.rerouted, true)
  assert.equal(j.decision.cls, 'medium')
  assert.equal(j.decision.confidence, 0.62)
  assert.equal(j.decision.threshold, 0.6)
  assert.deepEqual(j.decision.rule, { id: 'b0392f47-1c2d-4e8a-9f10-112233445566', version: '3' })
  // classifier outcome columns are their own producer
  assert.deepEqual(j.decision.classifierClass, { presence: 'recorded', value: 'medium' })
  assert.equal(j.decision.classifierConfidence, 0.62)
  assert.deepEqual(j.decision.classifierSource, { presence: 'recorded', value: 'embedding' })
  // upstream stage
  assert.equal(j.upstream.reached, true)
  assert.deepEqual(j.upstream.modelUsed, { presence: 'recorded', value: 'gpt-4o-mini' })
  assert.equal(j.upstream.durationMs, 2400)
  assert.equal(j.upstream.attemptCount, 2)
  assert.equal(j.upstream.retryCount, 1)
  assert.equal(j.upstream.firstTokenMs, 812)
  assert.deepEqual(j.upstream.upstreamUrl, { presence: 'recorded', value: 'https://api.openai.com/v1/chat/completions' })
  // response stage
  assert.equal(j.response.statusCode, 200)
  assert.deepEqual(j.response.error, { presence: 'absent' })
  assert.deepEqual(j.response.cacheHit, { presence: 'absent' })
  assert.equal(j.response.tokensIn, 120)
  assert.equal(j.response.tokensOut, 480)
  assert.deepEqual(j.response.answerView, { presence: 'recorded', value: 'complete' })
  assert.deepEqual(j.response.finishReason, { presence: 'recorded', value: 'stop' })
  assert.equal(j.response.truncated, false)
})

test('blocked: terminated pre-upstream — reached=false and NO attempt facts', () => {
  const j = buildRequestJourney(BLOCKED)
  assert.equal(j.upstream.reached, false, 'model_used === "" means no upstream attempt')
  assert.deepEqual(j.upstream.modelUsed, { presence: 'absent' }, 'empty string is absence, not a served model')
  assert.equal(j.upstream.durationMs, 0, 'the recorded literal 0 passes through as the stored fact')
  // negative control: counters are unknown (NULL columns), never 0/1 —
  // missing data must not masquerade as a recorded attempt outcome.
  assert.equal(j.upstream.attemptCount, null)
  assert.equal(j.upstream.retryCount, null)
  assert.equal(j.upstream.firstTokenMs, null)
  // the blocked request still carries its recorded outcome facts
  assert.equal(j.response.statusCode, 429)
  assert.deepEqual(j.response.error, { presence: 'recorded', value: 'budget_exceeded: daily' })
  // and the decision made before the budget check stays visible
  assert.equal(j.decision.presence, 'recorded')
  assert.equal(j.decision.source, 'passthrough')
  assert.equal(j.decision.rerouted, false)
})

test('cache-hit: hit type recorded, classifier absence stays absence', () => {
  const j = buildRequestJourney(CACHE_HIT)
  assert.deepEqual(j.response.cacheHit, { presence: 'recorded', value: 'exact' })
  assert.deepEqual(j.decision.classifierClass, { presence: 'absent' })
  assert.equal(j.decision.classifierConfidence, null, 'undefined confidence is unknown, not 0')
  assert.deepEqual(j.decision.classifierSource, { presence: 'absent' })
  assert.equal(j.decision.rerouted, false)
  // retry_count 0 is a REAL recorded zero, not an unknown
  assert.equal(j.upstream.retryCount, 0)
})

test('failed: error recorded, first-token unknown stays null', () => {
  const j = buildRequestJourney(FAILED)
  assert.equal(j.upstream.reached, true)
  assert.equal(j.upstream.attemptCount, 3)
  assert.equal(j.upstream.retryCount, 2)
  assert.equal(j.upstream.firstTokenMs, null, 'failed before first token: not recorded')
  assert.deepEqual(j.response.error, { presence: 'recorded', value: 'upstream connect timeout' })
  assert.equal(j.response.statusCode, 502)
  assert.deepEqual(j.response.answerView, { presence: 'absent' }, 'no processed answer captured')
  assert.deepEqual(j.response.finishReason, { presence: 'absent' })
})

test('redacted: gated columns are absent — nothing fabricated to fill them', () => {
  const j = buildRequestJourney(REDACTED)
  assert.deepEqual(j.upstream.upstreamUrl, { presence: 'absent' }, 'originals-gated URL stays absent')
  assert.deepEqual(j.response.error, { presence: 'absent' })
  assert.deepEqual(j.response.cacheHit, { presence: 'absent' })
  assert.deepEqual(j.response.answerView, { presence: 'recorded', value: 'partial' })
  assert.equal(j.response.truncated, true)
  assert.deepEqual(j.request.promptHash, { presence: 'recorded', value: 'sha:1a2b' })
  assert.equal(j.upstream.reached, true, 'served normally despite redacted extras')
})

test('legacy: decision capture and counters predate the row — explicit absence', () => {
  const j = buildRequestJourney(LEGACY)
  assert.equal(j.decision.presence, 'absent', 'no routing_decision column content')
  assert.equal(j.decision.parseFailed, false, 'absence is not a parse failure')
  assert.equal(j.decision.source, undefined)
  assert.equal(j.upstream.attemptCount, null)
  assert.equal(j.upstream.retryCount, null)
  assert.equal(j.upstream.firstTokenMs, null)
  assert.deepEqual(j.request.promptHash, { presence: 'absent' })
  assert.deepEqual(j.response.answerView, { presence: 'absent' })
  // the row still reconciles on the columns it does carry
  assert.deepEqual(j.upstream.modelUsed, { presence: 'recorded', value: 'gpt-4o-mini' })
  assert.equal(j.response.statusCode, 200)
})

test('parseStoredDecision: rule ref (id + version) round-trips verbatim', () => {
  const d = parseStoredDecision(ORDINARY.routing_decision as string)
  assert.equal(d.ok, true)
  assert.equal(d.source, 'tier_router')
  assert.deepEqual(d.rule, { id: 'b0392f47-1c2d-4e8a-9f10-112233445566', version: '3' })
  // no id → no fabricated identity
  const bare = parseStoredDecision('{"source":"passthrough","from":"a","to":"a"}')
  assert.equal(bare.ok, true)
  assert.equal(bare.rule, undefined)
})

test('parseStoredDecision: unreadable stored value is reported, never guessed', () => {
  assert.equal(parseStoredDecision('not json').ok, false)
  // a JSON document without a source is not a decision document either
  assert.equal(parseStoredDecision('{"x":1}').ok, false)
  // page contract: ok:false keeps the raw string for verbatim display
})

test('decisionText: compact forms — reroute marker, passthrough, parse failure', () => {
  assert.equal(decisionText(parseStoredDecision(ORDINARY.routing_decision as string)),
    '⚠ tier_router: gpt-4o → gpt-4o-mini (medium @0.62/0.6 tier match)')
  assert.equal(decisionText(parseStoredDecision(CACHE_HIT.routing_decision as string)),
    'passthrough: gpt-4o')
  assert.equal(decisionText({ ok: false }), '', 'unreadable document yields no invented text')
})

test('journey stage kinds are fixed and ordered', () => {
  const j = buildRequestJourney(ORDINARY)
  assert.deepEqual(
    [j.request.stage, j.decision.stage, j.upstream.stage, j.response.stage],
    ['request', 'decision', 'upstream', 'response'],
  )
  assert.equal(j.upstream.perAttemptRecorded, false, 'G2: producers record summary counters only')
})
