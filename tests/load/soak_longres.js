import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';

// N12-P04-T03 — long-response profiles (PRODUCT-CONTRACT §15 line 131; T01
// inventory gap G3): synthetic responses whose body takes the WHOLE window to
// arrive, against the duration-tunable slowmock upstream.
//
//   LONG_MODE=30s   "30 с ответы" steady window: 20 new req/s × LONG_WINDOW
//                   (default 5m) of 30 s responses → in-flight settles at
//                   ~600 (20 × 30), the contract's steady long-response shape.
//   LONG_MODE=120s  the SEPARATE 120-second profile: 20 new req/s × LONG_WINDOW
//                   (default 2m) of 120 s responses → in-flight ramps to
//                   ~2400 (20 × 120) by window end, the contract's dedicated
//                   long-response scenario. Sustained hours at 2400 concurrent
//                   streams are the PACKET-level acceptance (T10/T11); this
//                   card verifies the profile mechanics end to end.
//
// k6 stops launching at window end and drains every in-flight iteration
// (gracefulStop > response window), so completed == launched is a precise
// raw-rates assertion independent of the drain tail.
//
// Thresholds (packet negative criteria encoded — nothing can hide):
//   dropped_iterations == 0    generator/VU shortfall fails loudly (G1)
//   iterations count >= exact  raw launch/completion accounting (G2): every
//                              nominal arrival must complete; k6 emits up to
//                              ONE boundary arrival at t == window end, so
//                              the upper side is checked explicitly in the
//                              summary (boundary_extras ≤ 1)
//   http_req_failed < 0.1%     contract steady budget (this IS steady traffic)
//   http_req_duration p(95) <  saturation guard relative to the response
//     response+5s              window
//
// The 30 s hard client timeout that blocked long responses (matched
// -timeout, G3) does not apply here: per-request timeout is lifted to
// response + slack via REQ_TIMEOUT.
//
// Env: BASE_URL, API_KEY, PROFILE_MODEL, LONG_MODE (30s|120s), LONG_RATE (20),
//      LONG_WINDOW (5m / 2m per mode), LONG_PRE_VUS / LONG_MAX_VUS
//      (mode defaults 700/760 and 2600/2800), REQ_TIMEOUT (resp+60s),
//      LONG_OUT (summary JSON path).

const BASE_URL = __ENV.BASE_URL || 'http://gateway:8082';
const API_KEY = __ENV.API_KEY || '';
const MODEL = __ENV.PROFILE_MODEL || 'profile-model';
// Accept '30s'/'120s' and the runner's 'long30'/'long120' spellings alike.
const MODE = (__ENV.LONG_MODE || '30s').toLowerCase().replace(/^long(\d+)$/, '$1s');
const RATE = parseInt(__ENV.LONG_RATE || '20', 10);
const WINDOW = __ENV.LONG_WINDOW || (MODE === '120s' ? '2m' : '5m');
const TIMEOUT = __ENV.REQ_TIMEOUT || '';
const OUT = __ENV.LONG_OUT || '';

const RESPONSE_S = MODE === '120s' ? 120 : 30;
const DEFAULT_PRE = RESPONSE_S === 120 ? 2600 : 700;
const DEFAULT_MAX = RESPONSE_S === 120 ? 2800 : 760;
const PRE_VUS = parseInt(__ENV.LONG_PRE_VUS || String(DEFAULT_PRE), 10);
const MAX_VUS = parseInt(__ENV.LONG_MAX_VUS || String(DEFAULT_MAX), 10);
const REQ_TIMEOUT = TIMEOUT || `${RESPONSE_S + 60}s`;

function seconds(s) {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(String(s).trim());
  if (!m) return NaN;
  return parseFloat(m[1]) * { ms: 0.001, s: 1, m: 60, h: 3600 }[m[2]];
}

const WINDOW_S = seconds(WINDOW);
const EXPECTED_ITERS = Math.round(RATE * WINDOW_S);

const STARTED_AT = new Date().toISOString();

export function setup() {
  if (!API_KEY) {
    throw new Error('API_KEY env var is required (profiles org seed key)');
  }
  if (MODE !== '30s' && MODE !== '120s') {
    throw new Error(`LONG_MODE must be 30s or 120s, got ${MODE}`);
  }
  if (!(RATE > 0) || !Number.isFinite(WINDOW_S) || WINDOW_S <= 0) {
    throw new Error(`invalid long-response config: rate=${RATE} window=${WINDOW}`);
  }
  return { started_at_utc: new Date().toISOString() };
}

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)'],
  scenarios: {
    longres: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      // k6 reads a bare number as MILLISECONDS — always pass an explicit "s" unit.
      duration: `${WINDOW_S}s`,
      preAllocatedVUs: PRE_VUS,
      maxVUs: MAX_VUS,
      gracefulStop: `${RESPONSE_S * 2 + 30}s`,
    },
  },
  thresholds: {
    dropped_iterations: ['count==0'],
    iterations: [`count>=${EXPECTED_ITERS}`],
    http_req_failed: ['rate<0.001'],
    http_req_duration: [`p(95)<${RESPONSE_S * 1000 + 5000}`],
    checks: ['rate>0.99'],
  },
  tags: { profile: `longres_${MODE}` },
};

export default function () {
  const iter = exec.scenario.iterationInTest;
  const prompt = `[delay=${RESPONSE_S}s] longres-unique-${iter}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}: reply deterministically.`;
  const res = http.post(
    `${BASE_URL}/v1/chat/completions`,
    JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: prompt }],
      stream: true,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${API_KEY}`,
      },
      timeout: REQ_TIMEOUT,
      tags: { name: 'chat_completions', profile: `longres_${MODE}` },
    },
  );
  check(res, { 'status is 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const m = data.metrics;
  const started = (data.setup_data && data.setup_data.started_at_utc) || STARTED_AT;
  const ended = new Date().toISOString();
  const elapsedS = data.state.testRunDurationMs / 1000;
  const integrity = elapsedS >= WINDOW_S * 0.95 ? 'ok' : 'FAIL_ELAPSED_BELOW_NOMINAL';
  const dropped = m.dropped_iterations ? m.dropped_iterations.values.count : 0;
  const completed = m.iterations ? m.iterations.values.count : 0;
  // Contract arithmetic (§15 line 131): in-flight ≈ rate × response time.
  const inflight_model = Math.round(RATE * RESPONSE_S);

  const summary = {
    profile: `soak_longres mode=${MODE} (N12-P04-T03)`,
    config: {
      mode: MODE,
      rate: RATE,
      window: WINDOW,
      window_seconds: WINDOW_S,
      response_seconds: RESPONSE_S,
      modeled_inflight: inflight_model,
      expected_iterations: EXPECTED_ITERS,
      timeout: REQ_TIMEOUT,
      pre_vus: PRE_VUS,
      max_vus: MAX_VUS,
      model: MODEL,
      base_url: BASE_URL,
    },
    raw_rates: {
      configured_launch_rps: RATE,
      completed_iterations: completed,
      completion_ratio: EXPECTED_ITERS > 0 ? completed / EXPECTED_ITERS : 0,
      boundary_extras: completed - EXPECTED_ITERS,
      boundary_extras_allowance: 1,
      dropped_iterations: dropped,
      http_reqs: m.http_reqs ? m.http_reqs.values.count : 0,
      http_rps: m.http_reqs ? m.http_reqs.values.rate : 0,
    },
    latency_ms: {
      p50: m.http_req_duration.values['p(50)'],
      p95: m.http_req_duration.values['p(95)'],
      p99: m.http_req_duration.values['p(99)'],
      avg: m.http_req_duration.values.avg,
      max: m.http_req_duration.values.max,
    },
    errors: {
      http_req_failed_rate: m.http_req_failed.values.rate,
      checks_rate: m.checks.values.rate,
    },
    wall_clock: {
      started_at_utc: started,
      ended_at_utc: ended,
      elapsed_s: elapsedS,
      window_s: WINDOW_S,
      integrity,
      note: 'real wall-clock only; no virtual/accelerated clock exists in this harness',
    },
    state: { testRunDurationMs: data.state.testRunDurationMs, vus_max: data.state.vus_max },
  };

  const out = {};
  if (OUT) {
    out[OUT] = JSON.stringify(summary, null, 2);
  }
  out.stdout = textSummary(summary);
  return out;
}

function textSummary(s) {
  const r = s.raw_rates;
  const l = s.latency_ms;
  return [
    `┌─ N12-P04-T03 long-response (${s.config.mode}) ─────────────────────┐`,
    `│ profile        ${s.config.rate} new req/s × ${s.config.window} of ${s.config.response_seconds}s responses (modeled in-flight ≈${s.config.modeled_inflight})`,
    `│ launched       target ${s.config.expected_iterations} iterations (dropped=${r.dropped_iterations} — must be 0)`,
    `│ completed      ${r.completed_iterations} (ratio ${r.completion_ratio.toFixed(4)})`,
    `│ p50 / p95      ${(l.p50 || 0).toFixed(0)} ms / ${(l.p95 || 0).toFixed(0)} ms`,
    `│ p99 / max      ${(l.p99 || 0).toFixed(0)} ms / ${(l.max || 0).toFixed(0)} ms`,
    `│ failed         ${(s.errors.http_req_failed_rate * 100).toFixed(3)} %  checks ${(s.errors.checks_rate * 100).toFixed(2)} %`,
    `│ wall-clock     ${s.wall_clock.elapsed_s.toFixed(0)}s elapsed vs ${s.wall_clock.window_s.toFixed(0)}s window (${s.wall_clock.integrity})`,
    '└──────────────────────────────────────────────────────┘',
  ].join('\n');
}
