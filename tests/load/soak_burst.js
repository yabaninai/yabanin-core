import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';

// N12-P04-T03 — burst profile: THREE peaks of 100 new req/s × 60 s, separated
// by 5-minute idle intervals (PRODUCT-CONTRACT §15 line 129; owner decisions
// I46/I47: 100 RPS is a provisional PEAK target, not a sustained rate), each
// carrying 30 s synthetic responses (line 131 peak arithmetic: 100 RPS × 30 s
// ≈ 3000 in flight per burst) against the duration-tunable slowmock upstream.
//
// Open-arrival (constant-arrival-rate): arrivals are independent of completion
// speed, so VUs cannot "pass" a burst rate by finishing fast. The packet's
// negative criteria are encoded as thresholds:
//
//   dropped_iterations == 0        generator/VU shortfall fails loudly (G1)
//   iterations count >= exact      raw launch/completion accounting (G2):
//                                  constant-arrival with dropped==0 launches
//                                  rate × burst_len × burst_count iterations
//                                  plus up to ONE boundary arrival per burst
//                                  at t == duration (k6 emits the boundary
//                                  tick; observed 601/600 in a 30s@20rps
//                                  probe), all of which must complete
//   http_req_failed < 1%           peak error guard (recorded honestly if the
//                                  box cannot hold 3000 concurrent streams)
//   http_req_duration p(95) <      saturation guard relative to the response
//     response+5s                  window (30 s responses must not become
//                                  40 s responses under peak load)
//
// Backlog recovery (§15 line 136: return to baseline ≤5 min) is asserted by
// run-profiles.sh against a pre-load baseline; the in-run idle gaps are
// additionally visible in the captured saturation timeline.
//
// Env: BASE_URL, API_KEY, PROFILE_MODEL, BURST_RPS (100), BURST_LEN (60s),
//      BURST_GAP (300s), BURST_COUNT (3), BURST_RESP (30s marker delay),
//      BURST_PRE_VUS (3200), BURST_MAX_VUS (3600), REQ_TIMEOUT (150s),
//      BURST_OUT (summary JSON path).

const BASE_URL = __ENV.BASE_URL || 'http://gateway:8082';
const API_KEY = __ENV.API_KEY || '';
const MODEL = __ENV.PROFILE_MODEL || 'profile-model';
const RPS = parseInt(__ENV.BURST_RPS || '100', 10);
const LEN = __ENV.BURST_LEN || '60s';
const GAP = __ENV.BURST_GAP || '300s';
const COUNT = parseInt(__ENV.BURST_COUNT || '3', 10);
const RESP_S = parseInt(__ENV.BURST_RESP || '30', 10); // marker delay, seconds
const PRE_VUS = parseInt(__ENV.BURST_PRE_VUS || '3200', 10);
const MAX_VUS = parseInt(__ENV.BURST_MAX_VUS || '3600', 10);
const TIMEOUT = __ENV.REQ_TIMEOUT || '150s';
const OUT = __ENV.BURST_OUT || '';

function seconds(s) {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(String(s).trim());
  if (!m) return NaN;
  return parseFloat(m[1]) * { ms: 0.001, s: 1, m: 60, h: 3600 }[m[2]];
}

const LEN_S = seconds(LEN);
const GAP_S = seconds(GAP);
// Raw arrival span: the last burst stops launching at (COUNT-1)*(LEN+GAP)+LEN.
const ARRIVAL_SPAN_S = (COUNT - 1) * (LEN_S + GAP_S) + LEN_S;
const EXPECTED_ITERS = RPS * LEN_S * COUNT;

const STARTED_AT = new Date().toISOString();

export function setup() {
  if (!API_KEY) {
    throw new Error('API_KEY env var is required (profiles org seed key)');
  }
  if (!(RPS > 0) || !(COUNT > 0) || !Number.isFinite(LEN_S) || !Number.isFinite(GAP_S)) {
    throw new Error(`invalid burst config: rps=${RPS} count=${COUNT} len=${LEN} gap=${GAP}`);
  }
  return { started_at_utc: new Date().toISOString() };
}

// Time-disjoint burst scenarios: burst i launches during [i*(LEN+GAP), i*(LEN+GAP)+LEN].
const scenarios = {};
for (let i = 0; i < COUNT; i++) {
  scenarios[`burst${i + 1}`] = {
    executor: 'constant-arrival-rate',
    rate: RPS,
    timeUnit: '1s',
    // k6 reads a bare number as MILLISECONDS — always pass an explicit "s" unit.
    duration: `${LEN_S}s`,
    startTime: `${i * (LEN_S + GAP_S)}s`,
    preAllocatedVUs: PRE_VUS,
    maxVUs: MAX_VUS,
    gracefulStop: `${Math.ceil(RESP_S * 2 + 30)}s`,
  };
}

export const options = {
  discardResponseBodies: true, // long SSE bodies: keep the generator memory-safe at ~3000 VUs
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)'],
  scenarios,
  thresholds: {
    dropped_iterations: ['count==0'],
    // Lower bound: every nominal arrival must complete. The upper side is
    // checked explicitly as boundary_extras in the summary (k6 emits up to
    // one extra arrival per burst at t == duration).
    iterations: [`count>=${EXPECTED_ITERS}`],
    http_req_failed: ['rate<0.01'],
    http_req_duration: [`p(95)<${RESP_S * 1000 + 5000}`],
    checks: ['rate>0.99'],
  },
  tags: { profile: 'burst' },
};

export default function () {
  const iter = exec.scenario.iterationInTest;
  // Unique prompt per iteration (cache-miss primary) carrying the response
  // window marker the slowmock upstream parses.
  const prompt = `[delay=${RESP_S}s] burst-unique-${iter}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}: reply deterministically.`;
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
      timeout: TIMEOUT,
      tags: { name: 'chat_completions', profile: 'burst' },
    },
  );
  check(res, { 'status is 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const m = data.metrics;
  const started = (data.setup_data && data.setup_data.started_at_utc) || STARTED_AT;
  const ended = new Date().toISOString();
  const elapsedS = data.state.testRunDurationMs / 1000;
  const integrity = elapsedS >= ARRIVAL_SPAN_S * 0.95 ? 'ok' : 'FAIL_ELAPSED_BELOW_NOMINAL';
  const dropped = m.dropped_iterations ? m.dropped_iterations.values.count : 0;
  const completed = m.iterations ? m.iterations.values.count : 0;

  const summary = {
    profile: 'soak_burst (N12-P04-T03)',
    config: {
      rps: RPS,
      burst_len: LEN,
      burst_gap: GAP,
      burst_count: COUNT,
      response_seconds: RESP_S,
      arrival_span_seconds: ARRIVAL_SPAN_S,
      expected_iterations: EXPECTED_ITERS,
      timeout: TIMEOUT,
      max_vus: MAX_VUS,
      model: MODEL,
      base_url: BASE_URL,
    },
    raw_rates: {
      configured_launch_rps: RPS,
      launched_note: 'constant-arrival-rate with dropped_iterations==0 launches rate×len×count plus up to one boundary arrival per burst',
      completed_iterations: completed,
      completion_ratio: EXPECTED_ITERS > 0 ? completed / EXPECTED_ITERS : 0,
      boundary_extras: completed - EXPECTED_ITERS,
      boundary_extras_allowance: COUNT,
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
      arrival_span_s: ARRIVAL_SPAN_S,
      integrity,
      note: 'real wall-clock only; run-profiles.sh re-proves elapsed >= arrival span outside k6',
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
    '┌─ N12-P04-T03 burst profile ─────────────────────────┐',
    `│ profile        ${s.config.burst_count} × ${s.config.rps} new req/s × ${s.config.burst_len} (gap ${s.config.burst_gap}, resp ${s.config.response_seconds}s)`,
    `│ launched       target ${s.config.expected_iterations} iterations (dropped=${r.dropped_iterations} — must be 0)`,
    `│ completed      ${r.completed_iterations} (ratio ${r.completion_ratio.toFixed(4)})`,
    `│ p50 / p95      ${(l.p50 || 0).toFixed(0)} ms / ${(l.p95 || 0).toFixed(0)} ms`,
    `│ p99 / max      ${(l.p99 || 0).toFixed(0)} ms / ${(l.max || 0).toFixed(0)} ms`,
    `│ failed         ${(s.errors.http_req_failed_rate * 100).toFixed(3)} %  checks ${(s.errors.checks_rate * 100).toFixed(2)} %`,
    `│ wall-clock     ${s.wall_clock.elapsed_s.toFixed(0)}s elapsed vs ${s.wall_clock.arrival_span_s.toFixed(0)}s arrival span (${s.wall_clock.integrity})`,
    '└──────────────────────────────────────────────────────┘',
  ].join('\n');
}
