import http from 'k6/http';
import { check, sleep } from 'k6';

// K6 script: mixed model round-robin load test
// Tests multi-provider routing behavior under load
// Usage: k6 run --env TOKENROUTER_BASE_URL=http://localhost:8082 \
//                  --env TOKENROUTER_API_KEY=yabanin-dev-key \
//                  tests/load/k6_mixed_models.js

export const options = {
  stages: [
    { duration: '30s', target: 100 },
    { duration: '2m', target: 500 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<800', 'p(99)<1500'],
    http_req_failed: ['rate<0.05'], // more lenient for mixed models
    checks: ['rate>0.9'],
  },
};

const BASE_URL = __ENV.TOKENROUTER_BASE_URL || 'http://localhost:8082';
const API_KEY = __ENV.TOKENROUTER_API_KEY || 'yabanin-dev-key';

// Models to test — should match configured model registry
const MODELS = ['gpt-4o', 'claude-3.5-sonnet', 'gpt-4o-mini'];
const PROMPTS = [
  { messages: [{ role: 'user', content: 'Hello, world!' }] },
  { messages: [{ role: 'user', content: 'Explain the theory of relativity simply.' }] },
  { messages: [{ role: 'user', content: 'Write a REST API endpoint in Go.' }] },
];

let modelIdx = 0;
let promptIdx = 0;

export default function () {
  const model = MODELS[modelIdx % MODELS.length];
  modelIdx++;

  const prompt = PROMPTS[promptIdx % PROMPTS.length];
  promptIdx++;

  const payload = JSON.stringify({
    model: model,
    messages: prompt.messages,
    max_tokens: 256,
    temperature: 0.7,
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
    },
  };

  const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, params);

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has choices array': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.choices);
      } catch {
        return false;
      }
    },
    'model in response': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.model === model || body.model.includes(model.split('-')[0]);
      } catch {
        return false;
      }
    },
  });

  sleep(0.3 + Math.random() * 1.2);
}
