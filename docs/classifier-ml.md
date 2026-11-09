# External ML classifier

The public core includes an HTTP client for an optional classifier service.
It does **not** include trained classifier weights, a training corpus, or a
deployable ML server. The default configuration uses the built-in rule tier;
the [quickstart](quickstart.md) needs no ML service.

This page describes the interface an operator-supplied service must implement.
It does not promise a particular model, accuracy, throughput, or inference
latency. The classifier is separate from the response-cache embedder.

## Request and response contract

Set `YABANIN_CLASSIFIER_SERVICE_URL` on the gateway to the service's base URL,
without a trailing slash or `/v1/classify`. The client appends the endpoint.
The address must be reachable from the gateway's network namespace.

The client sends `POST /v1/classify` with `Content-Type: application/json`:

```json
{"text":"Explain how this function works","org_id":"example-organization"}
```

Return HTTP **200** and a JSON object:

```json
{"class_name":"medium","confidence":0.8}
```

Use `easy`, `medium`, or `hard` and a finite confidence between 0 and 1.
The client applies its configured confidence calibration before returning
the classification. Invalid JSON, a non-200 status, connection failure, or
timeout produces a classifier error. The current HTTP timeout is **100 ms**;
this is a client deadline, not measured service performance.

`GET /health` must return HTTP 200. The client does not require a particular
JSON health-response body. A healthy endpoint alone does not establish useful
classification quality.

## Configuration and fallback

| Gateway setting | Default | Purpose |
|---|---|---|
| `YABANIN_CLASSIFIER_SERVICE_URL` | empty | Empty leaves the external classifier disabled |
| `YABANIN_CLASSIFIER_CIRCUIT_ENABLED` | `true` | Use the configurable circuit timeout; see limitation below |
| `YABANIN_CLASSIFIER_CIRCUIT_THRESHOLD` | `3` | Consecutive failures before opening the circuit |
| `YABANIN_CLASSIFIER_CIRCUIT_TIMEOUT` | `30s` | Open interval before a recovery probe |

**Current wiring limitation:** setting `YABANIN_CLASSIFIER_CIRCUIT_ENABLED=false`
does not remove the wrapper; it constructs a breaker with a fixed 30-second
open timeout. Do not rely on that flag to disable circuit breaking.

The registry includes the rule tier as a fallback. When the circuit is open,
requests do not repeatedly call the failing ML service. Verify timeout,
non-200, malformed-response, and recovery behavior before enabling a new
service for real traffic. Source contracts are in `pkg/classifier/ml_v1.go`,
`pkg/classifier/circuit_breaker.go`, and `pkg/classifier/registry.go`.

## Data handling

The request sends prompt text and the organization identifier to the service.
The HTTP client does not add a classifier API-key header. Keep the service
behind an appropriate network boundary and configure transport protection
for your deployment. Include its logs, retention, backups, and model supply
chain in your review of prompt handling.

## Validate your classifier

1. Prepare a representative, independently labeled corpus, including
   languages, long prompts, code, and ambiguous tasks used by your clients.
2. Measure per-class errors and confidence calibration. A cheaper route
   selected incorrectly can reduce answer quality even when HTTP succeeds.
3. Measure end-to-end latency and failure rates under expected concurrency.
   Include network time within the client's 100 ms deadline.
4. Compare routed output quality and actual provider usage with a fixed-model
   baseline. Do not interpret synthetic confidence as measured savings.
5. Exercise service failure and recovery, then monitor classification and
   routing metrics described in [Task classifier](classifier.md).

Training, model licensing, deployment, and rollback of the external service
are operator responsibilities. Changing cache embedding settings does not
train or replace this classifier.
