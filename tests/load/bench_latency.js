import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// OP-23 internal benchmark — baseline latency profile (policy pipeline OFF).
// Constant-arrival-rate so the measured p95 is a property of the gateway, not
// of client pacing. Numbers are machine-dependent: compare runs, not vendors.
//
//   BASE_URL     gateway base (default http://gateway:8082 — the bench
//                compose network alias; use http://localhost:8082 for a local
//                dev gateway)
//   API_KEY      required — the key minted by `yabanin seed` for the bench org
//   BENCH_MODEL  registered model name (default bench-model)
//   BENCH_RPS    arrival rate (default 50)
//   BENCH_DUR    steady-state duration (default 120s)
//   BENCH_OUT    optional path — when set, the full end-of-test JSON summary
//                is written there (run-bench.sh collects it per run)

const BASE_URL = __ENV.BASE_URL || 'http://gateway:8082';
const API_KEY = __ENV.API_KEY || '';
const MODEL = __ENV.BENCH_MODEL || 'bench-model';
const RPS = parseInt(__ENV.BENCH_RPS || '50', 10);
const DURATION = __ENV.BENCH_DUR || '120s';
const OUT = __ENV.BENCH_OUT || '';

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
    bench_latency: {
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
  },
  tags: { bench: 'latency', policy_mode: 'off' },
};

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
    tags: { name: 'chat_completions', bench: 'latency' },
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
}

export function handleSummary(data) {
  const summary = {
    bench: 'latency',
    policy_mode: 'off',
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
    '┌─ OP-23 bench: latency (policy off) ─────────────────┐',
    `│ profile        constant-arrival-rate ${s.config.rps} rps × ${s.config.duration}`,
    `│ requests       ${m.http_reqs} (avg ${m.rps.toFixed(1)} rps)`,
    `│ p50 / p95      ${m.p50_ms.toFixed(1)} ms / ${m.p95_ms.toFixed(1)} ms`,
    `│ p99 / max      ${m.p99_ms.toFixed(1)} ms / ${m.max_ms.toFixed(1)} ms`,
    `│ failed         ${(m.http_req_failed_rate * 100).toFixed(3)} %`,
    `│ checks pass    ${(m.checks_rate * 100).toFixed(2)} %`,
    '└──────────────────────────────────────────────────────┘',
  ].join('\n');
}
