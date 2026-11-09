import http from 'k6/http';
import { check, sleep } from 'k6';
import exec from 'k6/execution';

// N12-P04-T02 — soak/uptime steady profile: sustained open-arrival load at a
// fixed new-request rate (I48 proposal: 20 new req/s) for a REAL wall-clock
// duration (1h acceptance / 8h soak; no time acceleration exists in k6 —
// run-soak.sh additionally proves actual elapsed >= nominal in its report).
//
// Packet-contract assertions installed in THIS profile (T01 inventory gaps
// G1+G2, owned T02 per INVENTORY.md §5 — assertions only, no product metric
// semantics touched):
//
//   G1  dropped_iterations MUST be 0 — a generator/VU shortfall (k6 cannot
//       launch the configured arrival rate) fails the run loudly and can
//       never masquerade as a sustained rate (packet negative criterion #1).
//   G2  the achieved completion rate (iterations/sec) must stay at or above
//       SOAK_COMPLETION_FLOOR of the configured arrival rate — raw launch /
//       completion rates are reported in the summary (packet acceptance:
//       "raw launch/completion rates ... доступны").
//
// Latency thresholds here are end-to-end saturation guards. The contract
// gateway-overhead budget (p95 ≤100 ms steady) is a separate RM-105
// measurement (gateway minus direct upstream); this profile does not claim it.
//
// Env:
//   BASE_URL               gateway base (default http://gateway:8082, the
//                          compose network alias; http://localhost:8082 local)
//   API_KEY                required — soak org seed key (run-soak.sh mints it)
//   SOAK_MODEL             registered model (default soak-model)
//   SOAK_RPS               arrival rate, new requests/second (default 20)
//   SOAK_DURATION          profile duration (default 1h; 8h for the soak run)
//   SOAK_COMPLETION_FLOOR  completion-rate floor as a fraction of the
//                          configured rate (default 0.98; margin only for
//                          end-of-test ramp effects, NOT for starvation —
//                          starvation shows up as dropped_iterations)
//   SOAK_PRE_VUS           pre-allocated VUs (default 100)
//   SOAK_MAX_VUS           max VUs — must cover the in-flight concurrency of
//                          the response profile (default 2000; the contract
//                          baseline 30 s-response profile needs ~600 at 20 rps)
//   SOAK_OUT               optional path — full end-of-test JSON summary
//
// Prompts are unique per iteration: the primary scenario is the cache-miss
// primary (LOAD-PROFILE.md «основной сценарий проверяет cache misses»).

const BASE_URL = __ENV.BASE_URL || 'http://gateway:8082';
const API_KEY = __ENV.API_KEY || '';
const MODEL = __ENV.SOAK_MODEL || 'soak-model';
const RPS = parseInt(__ENV.SOAK_RPS || '20', 10);
const DURATION = __ENV.SOAK_DURATION || '1h';
const FLOOR = parseFloat(__ENV.SOAK_COMPLETION_FLOOR || '0.98');
const PRE_VUS = parseInt(__ENV.SOAK_PRE_VUS || '100', 10);
const MAX_VUS = parseInt(__ENV.SOAK_MAX_VUS || '2000', 10);
const OUT = __ENV.SOAK_OUT || '';

const STARTED_AT = new Date().toISOString(); // refined in setup()

function durationSeconds(s) {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(s.trim());
  if (!m) return NaN;
  const n = parseFloat(m[1]);
  switch (m[2]) {
    case 'ms': return n / 1000;
    case 's': return n;
    case 'm': return n * 60;
    case 'h': return n * 3600;
    default: return NaN;
  }
}

export function setup() {
  if (!API_KEY) {
    throw new Error('API_KEY env var is required (soak org seed key)');
  }
  if (!(RPS > 0) || !Number.isFinite(durationSeconds(DURATION))) {
    throw new Error(`invalid SOAK_RPS/SOAK_DURATION: ${RPS}/${DURATION}`);
  }
  return { started_at_utc: new Date().toISOString() };
}

export const options = {
  discardResponseBodies: false,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)'],
  scenarios: {
    soak_steady: {
      executor: 'constant-arrival-rate',
      rate: RPS,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: PRE_VUS,
      maxVUs: MAX_VUS,
    },
  },
  thresholds: {
    // G1: generator shortfall is a loud FAIL, never a hidden rate degradation.
    dropped_iterations: ['count==0'],
    // G2: achieved completion rate must track the configured arrival rate.
    iterations: [`rate>=${(RPS * FLOOR).toFixed(2)}`],
    // Contract §15 unexpected-errors budget for the steady profile (≤0.1%).
    http_req_failed: ['rate<0.001'],
    // End-to-end saturation guard (NOT the RM-105 gateway-overhead budget).
    http_req_duration: ['p(95)<1000'],
    checks: ['rate>0.99'],
  },
  tags: { soak: 'steady' },
};

export default function () {
  // Unique prompt per iteration — cache-miss primary scenario.
  const iter = exec.scenario.iterationInTest;
  const prompt = `soak-unique-${iter}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}: reply with one short deterministic sentence.`;
  const payload = JSON.stringify({
    model: MODEL,
    messages: [{ role: 'user', content: prompt }],
    max_tokens: 32,
  });

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`,
    },
    tags: { name: 'chat_completions', soak: 'steady' },
  });

  check(res, {
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
  // Small settle pause keeps VU recycling well clear of the arrival schedule.
  sleep(0.01);
}

export function handleSummary(data) {
  const m = data.metrics;
  const started = (data.setup_data && data.setup_data.started_at_utc) || STARTED_AT;
  const ended = new Date().toISOString();
  const nominalS = durationSeconds(DURATION);
  const elapsedS = data.state.testRunDurationMs / 1000;
  const integrity = elapsedS >= nominalS * 0.95 ? 'ok' : 'FAIL_ELAPSED_BELOW_NOMINAL';
  const dropped = m.dropped_iterations ? m.dropped_iterations.values.count : 0;

  const summary = {
    profile: 'soak_steady (N12-P04-T02)',
    config: {
      rps: RPS,
      duration: DURATION,
      nominal_seconds: nominalS,
      completion_floor: FLOOR,
      max_vus: MAX_VUS,
      model: MODEL,
      base_url: BASE_URL,
    },
    raw_rates: {
      // G2: raw launch/completion accounting. With dropped_iterations==0 the
      // constant-arrival executor launched exactly `rate` per second, so the
      // configured rate is the achieved launch rate by construction.
      configured_arrival_rps: RPS,
      completed_iterations: m.iterations ? m.iterations.values.count : 0,
      completion_rps: m.iterations ? m.iterations.values.rate : 0,
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
      nominal_s: nominalS,
      integrity,
      note: 'k6 uses real wall-clock only; run-soak.sh re-proves elapsed >= nominal outside k6',
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
  const r = s.raw_rates;
  const l = s.latency_ms;
  return [
    '┌─ N12-P04-T02 soak: steady ──────────────────────────┐',
    `│ profile        constant-arrival-rate ${s.config.rps} new req/s × ${s.config.duration}`,
    `│ launched       target ${r.configured_arrival_rps}/s (dropped=${r.dropped_iterations} — must be 0)`,
    `│ completed      ${r.completed_iterations} (${r.completion_rps.toFixed(2)}/s)`,
    `│ http_reqs      ${r.http_reqs} (${r.http_rps.toFixed(2)}/s)`,
    `│ p50 / p95      ${l.p50.toFixed(1)} ms / ${l.p95.toFixed(1)} ms`,
    `│ p99 / max      ${l.p99.toFixed(1)} ms / ${l.max.toFixed(1)} ms`,
    `│ failed         ${(s.errors.http_req_failed_rate * 100).toFixed(3)} %  checks ${(s.errors.checks_rate * 100).toFixed(2)} %`,
    `│ wall-clock     ${s.wall_clock.elapsed_s.toFixed(0)}s elapsed vs ${s.wall_clock.nominal_s.toFixed(0)}s nominal (${s.wall_clock.integrity})`,
    '└──────────────────────────────────────────────────────┘',
  ].join('\n');
}
