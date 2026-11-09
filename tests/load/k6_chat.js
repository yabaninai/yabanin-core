import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics for TokenRouter load testing
const requestsTotal = new Counter('requests_total');
const cacheHits = new Counter('cache_hits');
const errors = new Counter('errors');

export const options = {
  stages: [
    { duration: '30s', target: 100 },   // ramp-up to 100 VUs
    { duration: '2m', target: 500 },     // sustain 500 VUs (≈1000 RPS with 2 req/s per VU)
    { duration: '30s', target: 1000 },   // peak at 1000 VUs
    { duration: '2m', target: 1000 },    // sustain 1000 VUs
    { duration: '30s', target: 0 },      // ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // p95 < 500ms, p99 < 1s
    http_req_failed: ['rate<0.01'],                   // < 1% error rate
    checks: ['rate>0.95'],                             // > 95% check pass rate
  },
};

const BASE_URL = __ENV.TOKENROUTER_BASE_URL || 'http://localhost:8082';
const API_KEY = __ENV.TOKENROUTER_API_KEY || 'yabanin-dev-key';

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
    model: 'gpt-4o',
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

  const isCacheHit = res.headers['X-Cache'] === 'HIT';
  if (isCacheHit) {
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
    'cache header present': (r) => r.headers['X-Cache'] !== undefined,
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
