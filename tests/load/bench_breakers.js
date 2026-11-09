import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// OP-23 internal benchmark — upstream circuit breakers (OP-18), per-endpoint
// scope. Two upstreams are registered:
//
//   bench-flap-model  → http://bench-mock-flap:8081  (stopped/started in a
//                      flap loop by run-bench.sh while this profile runs)
//   bench-model       → http://mock-openai:8081      (steady; the failover
//                      target of bench-flap-model)
//
// The breaker on the flapping endpoint must open after its failure threshold
// and fast-fail the primary hop; the fallback executor then serves the
// request from bench-model, whose breaker is independent. Per-endpoint
// isolation is proven exactly when http_req_failed stays < 1% and the client
// never sees a 503 while one upstream is down.
//
//   BASE_URL, API_KEY, BENCH_OUT — see bench_latency.js
//   BENCH_FLAP_MODEL  primary model whose endpoint flaps (default
//                     bench-flap-model)
//   BENCH_RPS         default 30 (failover doubles work per affected request)
//   BENCH_DUR         default 90s

const BASE_URL = __ENV.BASE_URL || 'http://gateway:8082';
const API_KEY = __ENV.API_KEY || '';
const FLAP_MODEL = __ENV.BENCH_FLAP_MODEL || 'bench-flap-model';
const RPS = parseInt(__ENV.BENCH_RPS || '30', 10);
const DURATION = __ENV.BENCH_DUR || '90s';
const OUT = __ENV.BENCH_OUT || '';

const rejected503 = new Counter('bench_breaker_503');
const errors = new Counter('bench_errors');

// Fail fast on misconfiguration before any load is generated. The check
// lives in setup() (not init scope) so `k6 inspect` — which does not
// populate __ENV — can still parse the script statically.
export function setup() {
  if (!API_KEY) {
    throw new Error('API_KEY env var is required (bench org seed key)');
  }
}

export const options = {
  discardResponseBodies: false,
  // handleSummary reads p(50)/p(99) — compute them (k6's default trend
  // stats only carry avg/min/med/max/p(90)/p(95)).
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)'],
  scenarios: {
    bench_breakers: {
      executor: 'constant-arrival-rate',
      rate: RPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 60,
      maxVUs: 300,
    },
  },
  thresholds: {
    // THE isolation assertion: with one endpoint hard-down for most of the
    // run, the client-visible failure rate must stay under 1% — failover
    // through the independent breaker keeps serving 200s.
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<2000'],
    checks: ['rate>0.99'],
    // A 503 means EVERY candidate endpoint's breaker was open (or the global
    // kill-switch fired) — per-endpoint isolation would be broken.
    bench_breaker_503: ['count == 0'],
  },
  tags: { bench: 'breakers', circuit: 'per-endpoint' },
};

const PROMPT = 'What is 2+2?';

export default function () {
  const payload = JSON.stringify({
    model: FLAP_MODEL,
    messages: [{ role: 'user', content: PROMPT }],
    max_tokens: 32,
  });

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`,
    },
    tags: { name: 'chat_completions', bench: 'breakers' },
  });

  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
    'has choices': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.choices) && body.choices.length > 0;
      } catch {
        return false;
      }
    },
  });
  if (!ok) errors.add(1);
  if (res.status === 503) rejected503.add(1);
}

export function handleSummary(data) {
  const summary = {
    bench: 'breakers',
    circuit_scope: 'per-endpoint',
    config: {
      rps: RPS,
      duration: DURATION,
      flap_model: FLAP_MODEL,
      fallback_model: __ENV.BENCH_MODEL || 'bench-model',
      base_url: BASE_URL,
    },
    metrics: {
      p50_ms: data.metrics.http_req_duration.values['p(50)'],
      p95_ms: data.metrics.http_req_duration.values['p(95)'],
      p99_ms: data.metrics.http_req_duration.values['p(99)'],
      avg_ms: data.metrics.http_req_duration.values.avg,
      max_ms: data.metrics.http_req_duration.values.max,
      http_reqs: data.metrics.http_reqs ? data.metrics.http_reqs.values.count : 0,
      rps: data.metrics.http_reqs ? data.metrics.http_reqs.values.rate : 0,
      http_req_failed_rate: data.metrics.http_req_failed.values.rate,
      checks_rate: data.metrics.checks.values.rate,
      errors: data.metrics.bench_errors ? data.metrics.bench_errors.values.count : 0,
      breaker_503: data.metrics.bench_breaker_503 ? data.metrics.bench_breaker_503.values.count : 0,
    },
    state: {
      testRunDurationMs: data.state.testRunDurationMs,
      vus_max: data.state.vus_max,
    },
  };

  const out = {};
  if (OUT) {
    out[OUT] = JSON.stringify(summary, null, 2);
  }
  out.stdout = textSummary(summary);
  return out;
}

function textSummary(s) {
  const m = s.metrics;
  return [
    '┌─ OP-23 bench: breakers (per-endpoint isolation) ─────┐',
    `│ profile        constant-arrival-rate ${s.config.rps} rps × ${s.config.duration}`,
    `│ flap model     ${s.config.flap_model} → fallback ${s.config.fallback_model}`,
    `│ requests       ${m.http_reqs} (avg ${m.rps.toFixed(1)} rps)`,
    `│ p50 / p95      ${m.p50_ms.toFixed(1)} ms / ${m.p95_ms.toFixed(1)} ms`,
    `│ p99 / max      ${m.p99_ms.toFixed(1)} ms / ${m.max_ms.toFixed(1)} ms`,
    `│ failed         ${(m.http_req_failed_rate * 100).toFixed(3)} % (< 1% proves isolation)`,
    `│ checks pass    ${(m.checks_rate * 100).toFixed(2)} %`,
    `│ 503s           ${m.breaker_503} (must be 0)`,
    '└──────────────────────────────────────────────────────┘',
  ].join('\n');
}
