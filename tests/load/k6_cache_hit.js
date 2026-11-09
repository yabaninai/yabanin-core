import http from 'k6/http';
import { check, sleep } from 'k6';

// K6 script: measure cache hit-rate by sending repeat prompts
// Usage: k6 run --env TOKENROUTER_BASE_URL=http://localhost:8082 \
//                  --env TOKENROUTER_API_KEY=yabanin-dev-key \
//                  tests/load/k6_cache_hit.js

export const options = {
  stages: [
    { duration: '10s', target: 50 },
    { duration: '1m', target: 200 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'], // cache hits should be very fast
    checks: ['rate>0.9'],
  },
};

const BASE_URL = __ENV.TOKENROUTER_BASE_URL || 'http://localhost:8082';
const API_KEY = __ENV.TOKENROUTER_API_KEY || 'yabanin-dev-key';

// Fixed prompts — same prompt repeated to trigger cache hits
const CACHEABLE_PROMPTS = [
  'What is the capital of France?',
  'Summarize the history of Rome in one paragraph.',
  'Write a haiku about programming.',
  'List 5 benefits of exercise.',
  'Explain quantum computing to a 10-year-old.',
];

let iteration = 0;

export default function () {
  const prompt = CACHEABLE_PROMPTS[iteration % CACHEABLE_PROMPTS.length];
  iteration++;

  const payload = JSON.stringify({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
    max_tokens: 128,
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
    },
  };

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, params);

  check(res, {
    'status is 200 or 304': (r) => r.status === 200 || r.status === 304,
    'cache header present': (r) => r.headers['X-Cache'] !== undefined,
    'response fast (< 50ms for cache hit)': (r) => r.timings.duration < 50,
  });

  sleep(0.1); // rapid fire to stress cache
}
