// CV-02 (V-09 requests explorer): pure view model for ONE recorded
// request's journey — request → routing decision → upstream serving →
// response outcome. Every fact binds to a stored request_logs column
// (docs/visualizers/field-matrix.md); absence is modelled explicitly so the
// page can never render a fabricated intermediate state:
//   - model_used === '' is the recorded pre-upstream termination (the
//     budget 429 projection writes exactly that, with a literal duration 0
//     and no attempt columns) — "blocked", never "served with 0 attempts".
//   - attempt_count / retry_count / first_token_ms are nullable; null is
//     "not recorded" (legacy rows). A recorded 0 (e.g. retry_count 0) is a
//     real value and passes through.
//   - per-attempt records have no producer yet (field-matrix gap G2) — the
//     model states summary-counters-only instead of inventing attempts.
// The model is UI-framework-free so the node harness can test it directly.
import type { RequestDetail } from '../api/requests.ts'

// A fact that may or may not exist in the stored row. `presence` drives the
// honest rendering: recorded facts show their value; absent facts show an
// explicit not-recorded marker — never a default value.
export type JourneyPresence = 'recorded' | 'absent'

export interface JourneyFact<T> {
  presence: JourneyPresence
  value?: T
}

function strFact(v: string | null | undefined): JourneyFact<string> {
  return v == null || v === '' ? { presence: 'absent' } : { presence: 'recorded', value: v }
}

// Nullable observability counters: only a real number survives; null and
// undefined both mean "not recorded" (the API cannot distinguish them).
function optNum(v: number | null | undefined): number | null {
  return typeof v === 'number' ? v : null
}

// Meta suffix of the compact decision text: class label, confidence with
// optional threshold, and the recorded reason.
function decisionMeta(dec: StoredDecision): string {
  const meta: string[] = []
  if (dec.cls) meta.push(dec.cls)
  if (typeof dec.confidence === 'number') {
    const thr = typeof dec.threshold === 'number' ? `/${dec.threshold}` : ''
    meta.push(`@${dec.confidence.toFixed(2)}${thr}`)
  }
  if (dec.reason) meta.push(dec.reason)
  return meta.join(' ')
}

// Compact human-readable form of the parsed decision: "tier_router: a → b
// (medium @0.62/0.6)" or "passthrough: a". Language-neutral on purpose
// (technical tokens only). A cross-route move (from ≠ to) gets a ⚠ prefix
// so the cost/route implication is impossible to miss. An unreadable
// document yields '' — the page then shows the raw stored string.
export function decisionText(dec: StoredDecision): string {
  if (!dec.ok) return ''
  const from = dec.from ?? ''
  const to = dec.to ?? ''
  const parts: string[] = []
  if (dec.source === 'passthrough') parts.push(`passthrough: ${from}`)
  else if (from && to && from !== to) parts.push(`⚠ ${dec.source}: ${from} → ${to}`)
  else parts.push(`${dec.source}: ${to || from} kept`)
  const meta = decisionMeta(dec)
  if (meta) parts.push(`(${meta})`)
  return parts.join(' ')
}

export interface JourneyRequestStage {
  stage: 'request'
  method: string
  modelRequested: JourneyFact<string>
  promptHash: JourneyFact<string>
  recordedAt: string
}

// The routing_decision document as frozen into the row at match time. `ok:
// false` covers stored values that are not readable decision objects
// (legacy free-text, corrupt writes) — the page then shows the raw stored
// string verbatim instead of a guessed structure. The optional rule ref
// (namespace is the producer's business) rides inside as rule:{id,version};
// an absent ref stays absent — never a fabricated identity (CORE-TRACE-04).
// The journey decision stage re-exports these fields verbatim (plus ok), so
// renderers can consume either shape structurally.
export interface StoredDecision {
  ok: boolean
  source?: string
  from?: string
  to?: string
  cls?: string
  confidence?: number
  threshold?: number
  reason?: string
  rule?: { id?: string; version?: string }
}

// Typed readers for untrusted JSON fields: absent/wrong-typed values stay
// undefined — nothing is coerced into a plausible value.
function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v ? v : undefined
}

function asNumber(v: unknown): number | undefined {
  return typeof v === 'number' ? v : undefined
}

function parseRuleRef(v: unknown): { id?: string; version?: string } | undefined {
  if (typeof v !== 'object' || v === null) return undefined
  const r = v as Record<string, unknown>
  return { id: asString(r.id), version: asString(r.version) }
}

export function parseStoredDecision(raw: string): StoredDecision {
  let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { return { ok: false } }
  if (typeof parsed !== 'object' || parsed === null) return { ok: false }
  const d = parsed as Record<string, unknown>
  const source = asString(d.source)
  if (!source) return { ok: false }
  return {
    ok: true,
    source,
    from: asString(d.from),
    to: asString(d.to),
    cls: asString(d.class),
    confidence: asNumber(d.confidence),
    threshold: asNumber(d.threshold),
    reason: asString(d.reason),
    rule: parseRuleRef(d.rule),
  }
}

export interface JourneyDecisionStage extends StoredDecision {
  stage: 'decision'
  presence: JourneyPresence
  parseFailed: boolean
  // Recorded cross-route move (from ≠ to, both present, parse ok).
  rerouted: boolean
  // Classifier outcome columns — a distinct producer from the decision
  // document (gateway classifier result vs. the frozen decision payload);
  // kept separate so each reconciles with its own stored column.
  classifierClass: JourneyFact<string>
  classifierConfidence: number | null
  classifierSource: JourneyFact<string>
}

export interface JourneyUpstreamStage {
  stage: 'upstream'
  reached: boolean
  modelUsed: JourneyFact<string>
  durationMs: number
  attemptCount: number | null
  retryCount: number | null
  firstTokenMs: number | null
  upstreamUrl: JourneyFact<string>
  // Constant honesty note: per-attempt outcomes are not recorded by any
  // producer yet (field-matrix G2) — only per-request totals exist.
  perAttemptRecorded: false
}

export interface JourneyResponseStage {
  stage: 'response'
  statusCode: number
  error: JourneyFact<string>
  cacheHit: JourneyFact<string>
  tokensIn: number
  tokensOut: number
  answerView: JourneyFact<'complete' | 'partial'>
  finishReason: JourneyFact<string>
  truncated: boolean
}

export interface RequestJourney {
  request: JourneyRequestStage
  decision: JourneyDecisionStage
  upstream: JourneyUpstreamStage
  response: JourneyResponseStage
}

// Per-stage builders: linear column mappings with the absence rules stated
// where each fact binds. buildRequestJourney below only composes them.

const NO_DECISION: StoredDecision = { ok: false }

function buildDecisionStage(d: RequestDetail, stored: StoredDecision): JourneyDecisionStage {
  const doc = stored.ok ? stored : NO_DECISION
  return {
    stage: 'decision',
    presence: d.routing_decision ? 'recorded' : 'absent',
    parseFailed: Boolean(d.routing_decision) && !stored.ok,
    ok: doc.ok,
    source: doc.source,
    from: doc.from,
    to: doc.to,
    rerouted: Boolean(doc.from && doc.to && doc.from !== doc.to),
    cls: doc.cls,
    confidence: doc.confidence,
    threshold: doc.threshold,
    reason: doc.reason,
    rule: doc.rule,
    classifierClass: strFact(d.classifier_class),
    classifierConfidence: optNum(d.classifier_confidence),
    classifierSource: strFact(d.classifier_source),
  }
}

function buildUpstreamStage(d: RequestDetail): JourneyUpstreamStage {
  return {
    stage: 'upstream',
    reached: d.model_used !== '',
    modelUsed: strFact(d.model_used),
    durationMs: d.duration_ms,
    attemptCount: optNum(d.attempt_count),
    retryCount: optNum(d.retry_count),
    firstTokenMs: optNum(d.first_token_ms),
    upstreamUrl: strFact(d.upstream_url),
    perAttemptRecorded: false,
  }
}

function buildResponseStage(d: RequestDetail): JourneyResponseStage {
  return {
    stage: 'response',
    statusCode: d.status_code,
    error: strFact(d.error),
    cacheHit: strFact(d.cache_hit_type),
    tokensIn: d.tokens_in,
    tokensOut: d.tokens_out,
    answerView: d.response_view ? { presence: 'recorded', value: d.response_view.status } : { presence: 'absent' },
    finishReason: strFact(d.response_view?.finish_reason),
    truncated: d.response_view?.truncated === true,
  }
}

export function buildRequestJourney(d: RequestDetail): RequestJourney {
  return {
    request: {
      stage: 'request',
      method: d.method,
      modelRequested: strFact(d.model_requested),
      promptHash: strFact(d.prompt_hash),
      recordedAt: d.created_at,
    },
    decision: buildDecisionStage(d, d.routing_decision ? parseStoredDecision(d.routing_decision) : NO_DECISION),
    upstream: buildUpstreamStage(d),
    response: buildResponseStage(d),
  }
}
