import http from 'k6/http';
import { check, sleep } from 'k6';

// K6 script: mixed model round-robin load test
// Tests multi-model routing behavior under load.
// Usage (all load inputs are explicit; no implicit credential or host):
//   TOKENROUTER_API_KEY=<test-org key> \
//   TOKENROUTER_MODELS=<model-a>,<model-b> \
//   TOKENROUTER_BASE_URL=http://127.0.0.1:8082 \
//   k6 run tests/load/k6_mixed_models.js
// The model list must contain at least two distinct models that are actually
// registered and authorized in the target deployment.
// Optional bounded overrides (never labeled as the full profile):
//   TOKENROUTER_SMOKE=1                  tiny smoke profile
//   TOKENROUTER_VUS=2 TOKENROUTER_DURATION=10s   explicit custom profile

const FULL_STAGES = [
  { duration: '30s', target: 100 },
  { duration: '2m', target: 500 },
  { duration: '30s', target: 0 },
];
const FULL_THRESHOLDS = {
  http_req_duration: ['p(95)<800', 'p(99)<1500'],
  http_req_failed: ['rate<0.05'], // more lenient for mixed models
  checks: ['rate>0.9'],
};

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

// Mixed routing needs a real choice: require an explicit list of at least
// two distinct, non-empty model IDs that exist in the target registry.
// Malformed lists (empty, empty elements, duplicates, single entry) abort
// before any request is sent.
function parseModelList(raw) {
  const entries = (raw || '')
    .split(',')
    .map((m) => m.trim());
  if (entries.every((m) => m.length === 0)) {
    throw new Error(
      'TOKENROUTER_MODELS is required and has no default; pass a comma-separated list of registered model IDs'
    );
  }
  if (entries.some((m) => m.length === 0)) {
    throw new Error(
      'TOKENROUTER_MODELS must not contain empty elements; pass comma-separated non-empty model IDs'
    );
  }
  const duplicates = entries.filter((m, i) => entries.indexOf(m) !== i);
  if (duplicates.length > 0) {
    throw new Error(`TOKENROUTER_MODELS contains duplicate entries: ${duplicates.join(', ')}`);
  }
  if (entries.length < 2) {
    throw new Error(
      `TOKENROUTER_MODELS needs at least two distinct models for mixed routing, got: ${entries.join(',')}`
    );
  }
  return entries;
}
const MODELS = parseModelList(__ENV.TOKENROUTER_MODELS);

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
  `k6_mixed_models profile=${PROFILE} base=${BASE_URL} models=${MODELS.join(',')} ` +
    `(smoke/custom profiles are NOT the full load profile)`
);

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
    // Exact identity: the response model must equal the requested model.
    // A permissive prefix match would accept unrelated models.
    'model is exact': (r) => {
      try {
        return JSON.parse(r.body).model === model;
      } catch {
        return false;
      }
    },
  });

  sleep(0.3 + Math.random() * 1.2);
}
