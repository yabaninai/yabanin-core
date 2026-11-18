import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// K6 script: chat completions load test
// Usage (all load inputs are explicit; no implicit credential or host):
//   TOKENROUTER_API_KEY=<test-org key> \
//   TOKENROUTER_MODEL=<registered model id> \
//   TOKENROUTER_BASE_URL=http://127.0.0.1:8082 \
//   k6 run tests/load/k6_chat.js
// Optional bounded overrides (never labeled as the full profile):
//   TOKENROUTER_SMOKE=1                  tiny smoke profile
//   TOKENROUTER_VUS=2 TOKENROUTER_DURATION=10s   explicit custom profile

// Custom metrics for TokenRouter load testing
const requestsTotal = new Counter('requests_total');
const cacheHits = new Counter('cache_hits');
const errors = new Counter('errors');

// Cache attribution emitted by the gateway on a hit: the cache service's
// source type ("exact" | "pg_exact" | "semantic") uppercased in the X-Cache
// response header. Any other value — and in particular a missing header —
// is not a hit; absence is the normal miss case.
const CACHE_HIT_VALUES = ['EXACT', 'PG_EXACT', 'SEMANTIC'];

const FULL_STAGES = [
  { duration: '30s', target: 100 },   // ramp-up to 100 VUs
  { duration: '2m', target: 500 },     // sustain 500 VUs (≈1000 RPS with 2 req/s per VU)
  { duration: '30s', target: 1000 },   // peak at 1000 VUs
  { duration: '2m', target: 1000 },    // sustain 1000 VUs
  { duration: '30s', target: 0 },      // ramp-down
];
const FULL_THRESHOLDS = {
  http_req_duration: ['p(95)<500', 'p(99)<1000'], // p95 < 500ms, p99 < 1s
  http_req_failed: ['rate<0.01'],                   // < 1% error rate
  checks: ['rate>0.95'],                            // > 95% check pass rate
};

// Load inputs. The base URL may default to the literal loopback address of
// the local quickstart; credentials and model identity never have defaults.
// The API key must be a real key minted for the test organization. It is
// never logged and never written to disk by this script.
function requiredInput(name, value) {
  const v = (value || '').trim();
  if (!v) {
    throw new Error(
      `${name} is required and has no default; set it explicitly for the target deployment`
    );
  }
  return v;
}

const BASE_URL = (__ENV.TOKENROUTER_BASE_URL || 'http://127.0.0.1:8082').trim();
if (!/^https?:\/\//.test(BASE_URL)) {
  throw new Error(`TOKENROUTER_BASE_URL must be an http(s) URL, got: ${BASE_URL}`);
}
const API_KEY = requiredInput('TOKENROUTER_API_KEY', __ENV.TOKENROUTER_API_KEY);
const MODEL = requiredInput('TOKENROUTER_MODEL', __ENV.TOKENROUTER_MODEL);

const SMOKE = (__ENV.TOKENROUTER_SMOKE || '').trim() === '1';
const VUS = (__ENV.TOKENROUTER_VUS || '').trim();
const DURATION = (__ENV.TOKENROUTER_DURATION || '').trim();
if ((VUS ? 1 : 0) + (DURATION ? 1 : 0) === 1) {
  throw new Error('TOKENROUTER_VUS and TOKENROUTER_DURATION must be set together');
}
if (SMOKE && (VUS || DURATION)) {
  throw new Error('TOKENROUTER_SMOKE and TOKENROUTER_VUS/TOKENROUTER_DURATION are mutually exclusive');
}
let PROFILE = 'full';
let STAGES = FULL_STAGES;
if (SMOKE) {
  PROFILE = 'smoke';
  STAGES = [{ duration: '3s', target: 1 }];
} else if (VUS && DURATION) {
  const vusNum = Number(VUS);
  if (!Number.isInteger(vusNum) || vusNum < 1) {
    throw new Error(`TOKENROUTER_VUS must be a positive integer, got: ${VUS}`);
  }
  PROFILE = 'custom';
  STAGES = [{ duration: DURATION, target: vusNum }];
}

export const options = {
  stages: STAGES,
  thresholds: FULL_THRESHOLDS,
};

console.log(
  `k6_chat profile=${PROFILE} base=${BASE_URL} model=${MODEL} ` +
    `(smoke/custom profiles are NOT the full load profile)`
);

// Test prompts — mix of simple and complex queries
const PROMPTS = [
  { messages: [{ role: 'user', content: 'What is 2+2?' }] },
  { messages: [{ role: 'user', content: 'Summarize this in one sentence: The quick brown fox jumps over the lazy dog.' }] },
  { messages: [{ role: 'user', content: 'Write a Python function to calculate Fibonacci numbers recursively.' }] },
  { messages: [{ role: 'user', content: 'Explain the difference between REST and GraphQL APIs with examples.' }] },
  { messages: [{ role: 'user', content: 'Debug this code:\n```python\ndef foo(x):\n    return x[0]\nfoo(5)\n```\nExplain the bug.' }] },
];

export default function () {
  const prompt = PROMPTS[Math.floor(Math.random() * PROMPTS.length)];

  const payload = JSON.stringify({
    model: MODEL,
    messages: prompt.messages,
    max_tokens: 256,
    temperature: 0.7,
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
    },
    tags: { name: 'chat_completions' },
  };

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, params);

  requestsTotal.add(1);

  // X-Cache is only set by the gateway on cache hits, with one of the
  // explicit attribution values above; a missing header is a valid miss.
  const cacheAttribution = res.headers['X-Cache'];
  if (cacheAttribution !== undefined && CACHE_HIT_VALUES.includes(cacheAttribution)) {
    cacheHits.add(1);
  }

  const success = check(res, {
    'status is 200': (r) => r.status === 200,
    'has choices': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.choices && body.choices.length > 0;
      } catch {
        return false;
      }
    },
    // Exact identity: the response must carry the requested model, not a
    // prefix/substring match that unrelated models could satisfy.
    'model is exact': (r) => {
      try {
        return JSON.parse(r.body).model === MODEL;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    errors.add(1);
  }

  // Simulate think time between requests
  sleep(0.5 + Math.random() * 1.5);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, opts) {
  const lines = [];
  lines.push('╔══════════════════════════════════════════╗');
  lines.push('║       TokenRouter Load Test Summary      ║');
  lines.push(`║ profile:      ${PROFILE.padEnd(28)}║`);
  if (PROFILE !== 'full') {
    lines.push('║ (not the full load profile)              ║');
  }
  lines.push('╠══════════════════════════════════════════╣');

  const httpReqs = data.metrics.http_req_duration;
  if (httpReqs) {
    lines.push(`║ p50 latency:  ${(httpReqs.values['p(50)'] / 1000).toFixed(3)}s         ║`);
    lines.push(`║ p95 latency:  ${(httpReqs.values['p(95)'] / 1000).toFixed(3)}s         ║`);
    lines.push(`║ p99 latency:  ${(httpReqs.values['p(99)'] / 1000).toFixed(3)}s         ║`);
    lines.push(`║ avg rps:      ${(data.metrics.http_reqs ? data.metrics.http_reqs.values.count / data.state.duration : 0).toFixed(1)}            ║`);
  }

  const checks = data.metrics.checks;
  if (checks) {
    lines.push(`║ check pass:   ${(checks.values.rate * 100).toFixed(1)}%           ║`);
  }

  const cacheHitRate = data.metrics.cache_hits;
  if (cacheHitRate && data.metrics.requests_total) {
    const rate = (cacheHitRate.values.count / data.metrics.requests_total.values.count * 100).toFixed(1);
    lines.push(`║ cache hit:    ${rate.padEnd(5)}%          ║`);
  }

  const errorRate = data.metrics.errors;
  if (errorRate && data.metrics.requests_total) {
    const rate = (errorRate.values.count / data.metrics.requests_total.values.count * 100).toFixed(1);
    lines.push(`║ error rate:   ${rate.padEnd(5)}%          ║`);
  }

  lines.push('╚══════════════════════════════════════════╝');
  return lines.join('\n');
}
