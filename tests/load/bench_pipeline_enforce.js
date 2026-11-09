import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// OP-23 internal benchmark — policy pipeline in ENFORCE mode, same load shape
// as bench_latency.js. The bench policy verdict is deliberately flag-only for
// the benign bench traffic (sovereign-default denies only high-severity
// secrets), so the load keeps flowing: this profile measures enforce-mode
// overhead on allowed traffic, not denial behavior.
//
//   BASE_URL, API_KEY, BENCH_MODEL, BENCH_RPS, BENCH_DUR, BENCH_OUT — see
//   bench_latency.js. POLICY_MODE is recorded into the summary (default
//   enforce); the actual mode is enforced by run-bench.sh via gateway env.

const BASE_URL = __ENV.BASE_URL || 'http://gateway:8082';
const API_KEY = __ENV.API_KEY || '';
const MODEL = __ENV.BENCH_MODEL || 'bench-model';
const RPS = parseInt(__ENV.BENCH_RPS || '50', 10);
const DURATION = __ENV.BENCH_DUR || '120s';
const POLICY_MODE = __ENV.POLICY_MODE || 'enforce';
const OUT = __ENV.BENCH_OUT || '';

const denied = new Counter('bench_denied');
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
    bench_pipeline_enforce: {
      executor: 'constant-arrival-rate',
      rate: RPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<1000'],
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
    // The bench policy only flags benign traffic — a single deny during the
    // run means the policy or the prompts drifted from the bench contract.
    bench_denied: ['count == 0'],
  },
  tags: { bench: 'pipeline_enforce', policy_mode: POLICY_MODE },
};

// Benign prompts only: verdict = flag, request proceeds. Denials are
// exercised once by run-bench.sh's verification step (a secrets-bearing
// prompt MUST 403) and never inside the steady-state load.
const PROMPTS = [
  'What is 2+2?',
  'Summarize in one sentence: the quick brown fox jumps over the lazy dog.',
  'Name the four seasons.',
];

export default function () {
  const payload = JSON.stringify({
    model: MODEL,
    messages: [{ role: 'user', content: PROMPTS[Math.floor(Math.random() * PROMPTS.length)] }],
    max_tokens: 32,
  });

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`,
    },
    tags: { name: 'chat_completions', bench: 'pipeline_enforce' },
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
  // Policy deny is a 400 error envelope (policydecide content_policy_violation);
  // 403 is counted defensively in case the wire status moves.
  if (res.status === 400 || res.status === 403) denied.add(1);
}

export function handleSummary(data) {
  const summary = {
    bench: 'pipeline_enforce',
    policy_mode: POLICY_MODE,
    policy: 'sovereign-default (enabled, attached org-wide to the bench org)',
    config: { rps: RPS, duration: DURATION, model: MODEL, base_url: BASE_URL },
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
      denied: data.metrics.bench_denied ? data.metrics.bench_denied.values.count : 0,
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
    '┌─ OP-23 bench: pipeline enforce (flag-only policy) ───┐',
    `│ profile        constant-arrival-rate ${s.config.rps} rps × ${s.config.duration}`,
    `│ policy         sovereign-default @ ${s.policy_mode}`,
    `│ requests       ${m.http_reqs} (avg ${m.rps.toFixed(1)} rps)`,
    `│ p50 / p95      ${m.p50_ms.toFixed(1)} ms / ${m.p95_ms.toFixed(1)} ms`,
    `│ p99 / max      ${m.p99_ms.toFixed(1)} ms / ${m.max_ms.toFixed(1)} ms`,
    `│ failed         ${(m.http_req_failed_rate * 100).toFixed(3)} %`,
    `│ checks pass    ${(m.checks_rate * 100).toFixed(2)} %`,
    `│ denied         ${m.denied} (must be 0)`,
    '└──────────────────────────────────────────────────────┘',
  ].join('\n');
}
