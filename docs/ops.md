# Operations guide

Use [Quickstart](quickstart.md) for a local first request and
[Production operations](runbooks/production.md) for deployment diagnosis,
updates and recovery. This page is the runtime reference: service boundaries,
health, metrics, events and evidence interpretation.

## Processes and listeners

The unified `yabanin` executable accepts `gateway`, `admin`, `loggerd`, `migrate`
and `dev` commands. `dev` runs the application services together, as in the
quickstart. Build with the Go version required by `go.mod`; the Dockerfile pins
its build/runtime images. Do not infer current image versions from old CI examples.

| Service | Default listener | Purpose |
| --- | --- | --- |
| Gateway | 8082 | Client API, authentication, model routing and inference |
| Gateway diagnostics | 9090 | Metrics and opt-in diagnostic endpoints |
| Admin | 8086 | Admin sessions, JSON APIs and analytics |
| Loggerd | 8085 | Event persistence health and metrics |
| Dashboard | Separately served | React UI; not served by the admin port |

Deployment manifests can override ports. Gateway key authentication, admin cookie
sessions, internal-service credentials and metrics bearer keys are separate
boundaries; a key for one is not a credential for all of them. Keep diagnostics
listeners private.

## Health and readiness

| Service | Endpoint | Interpretation |
| --- | --- | --- |
| Gateway | `GET /healthz` | Inspect HTTP status and JSON `status`; a healthy probe is not an inference test |
| Admin | `GET /health` | HTTP 200 with plaintext `ok`; not a complete dependency check |
| Loggerd | `GET /healthz` | HTTP 200 while accepting work; 503 while draining |

A successful gateway response includes `status: "ok"`. The gateway source also
has build/Redis diagnostics in its health handler; clients must not depend on the
obsolete nested `redis.status` example. Read the actual response for your build.
Redis diagnosis, where present, is a top-level string, not a proof of PostgreSQL
persistence or provider readiness. During managed gateway/loggerd drain, a 503
`status: "draining"` removes the instance from readiness before listener shutdown.

For local quickstart health:

```bash
curl --fail-with-body --silent --show-error http://127.0.0.1:8082/healthz
curl --fail-with-body --silent --show-error http://127.0.0.1:8086/health
```

Loggerd and gateway diagnostics ports are not published by that Compose stack.
Use private-network access or the deployment's supported diagnostics path instead
of assuming every default container port is available on host loopback.

For acceptance, add an authenticated `/v1/models` call, a permitted chat request,
and observation of its persisted history. Exercise authorization failure and
upstream failure separately. See [Quickstart](quickstart.md) and
[history admission](runbooks/history-admission.md).

## Metrics reference

Not all metrics share the `gateway` prefix. These names match the source
declarations and shipped alert rules:

| Metric | Type | Labels / interpretation |
| --- | --- | --- |
| `gateway_http_requests_total` | Counter | `method`, `path`, `status` |
| `gateway_http_request_duration_seconds` | Histogram | `method`, `path`; seconds |
| `gateway_upstream_first_token_seconds` | Histogram | `provider`, `model`; streamed first-token delay |
| `gateway_upstream_requests_total` | Counter | `provider`, `model`, `status` |
| `gateway_retry_total` | Counter | `attempt`, `status`; intra-model retry attempts |
| `gateway_fallback_total` | Counter | `from`, `to`, `reason`; fallback completions |
| `cache_hits_total` | Counter | `type`; exact/semantic/miss lookup outcomes |
| `gateway_loggerd_events_in_flight` | Gauge | Current processing activity; not stream backlog |
| `gateway_loggerd_events_consumed_total` | Counter | `event_type`; successful consumption/persistence |
| `gateway_circuit_breaker_state` | Gauge | `upstream`; 0 closed, 1 open, 2 half-open |
| `gateway_circuit_breaker_failures_total` | Counter | `upstream`; recorded failures |
| `gateway_circuit_breaker_recoveries_total` | Counter | `upstream`; recovery transitions |

Example p95 request duration grouped by path:

```promql
histogram_quantile(0.95,
  sum by (le, path) (rate(gateway_http_request_duration_seconds_bucket[5m])))
```

Understand instrumentation and traffic mix before treating this as gateway-only
processing overhead. Streaming requests can have very different durations from
short non-streamed calls. Counters reset when processes restart; rate/increase
queries and process lifetime provide context.

Configure `YABANIN_METRICS_BEARER_KEY` and the matching scrape credential where
metrics authentication is required. Network-restrict metrics even with bearer
protection: labels can reveal organization/model activity. Use the
[alert inventory](runbooks/alerts-inventory.md), not copied historical metric names,
when adding rules. Zero consumption with zero work is ordinary idle behavior,
not evidence of a stalled consumer.

## Tracing and exported logs

Gateway, admin and loggerd startup support OTLP/HTTP tracing. An empty
`YABANIN_OTEL_ENDPOINT` disables trace export. `YABANIN_OTEL_SAMPLE_RATE` defaults
to `0.1`; inspect the version's configuration and collector setup before choosing
a rate. The shared tracing initializer uses a host/port endpoint and its exporter
transport options; do not assume an arbitrary URL or insecure transport is accepted.

Request-log export is a distinct optional loggerd path. Its configuration, payload
redaction and bounded-queue behavior are documented in
[OTel log export](observability/otel-export.md). A successfully accepted inference
request does not prove that an external collector received every record. Confirm
collector receipts, export failures and drop counters separately.

Log-level variables are `YABANIN_LOG_LEVEL` for gateway,
`YABANIN_ADMIN_LOG_LEVEL` for admin, and `YABANIN_LOGGERD_LOG_LEVEL` for loggerd.
Do not assume an unrelated `SLOG_LEVEL` variable configures these services.

## Redis events, pending work and dead letters

The default stream is `events:queue` and the consumer group is `loggerd-workers`.
Read the effective configuration when it is overridden. Pending entries are
messages delivered to a consumer but not acknowledged; stream length is not the
same as pending work or consumer lag.

Read-only checks, using a suitably authenticated private Redis connection:

```bash
redis-cli XINFO GROUPS events:queue
redis-cli XINFO CONSUMERS events:queue loggerd-workers
redis-cli XPENDING events:queue loggerd-workers
```

Do not paste raw `XRANGE` results into incident tickets: event and dead-letter
payloads can contain sensitive content. Inspect a narrowly scoped sample only
when authorized and redact it before sharing.

The consumer periodically reclaims stale pending work. Database outages pause
processing rather than treating every unavailable-database attempt as a poison
message. Other persistent handler failures can enter the `events:queue:dlq`
dead-letter stream after the retry budget. Distinguish an unavailable dependency
from malformed input when deciding recovery.

Repair the underlying error and verify both consumption and persistence. Do not
blindly republish dead letters: a previous attempt may have partially executed,
and changing stream IDs can interact with deduplication. Define and test an
idempotent replay plan for the affected event type before replaying. Do not trim
streams, delete pending entries or flush Redis to hide a backlog.

## Cache and accounting interpretation

See [Cache architecture](cache-architecture.md) for key scope, lookup layers,
privacy modes and TTLs; see [Cache precision](cache-precision.md) for the limits
of semantic matching. `Cache-Control: no-store` bypasses lookup and storage.
Exact and semantic hits are distinct outcomes. A similarity score is not proof
that a cached answer is appropriate for a different request.

The pipeline records measured usage where available and estimated/counterfactual
cost where applicable. Missing pricing or usage does not establish free inference.
Read each report's coverage and attribution basis before treating an aggregate as
savings. Counterfactual cost is a model of an alternative, not a provider invoice.
A more expensive routed model can yield negative estimated routing savings.
See [Analytics](analytics.md) for field definitions and aggregation scope.

Callers can group requests with `X-Yabanin-Task`; the gateway's `YABANIN_TASK`
environment variable is a deployment-wide default, not automatic transmission
from a remote client's shell. See [Agent governance](agent-governance.md#x-yabanin-task).

Tool-call views depend on stored, parseable samples and applicable privacy policy.
Missing or truncated samples can produce no parsed calls; absence from an aggregate
is not proof that no upstream tool call occurred. Use request IDs and sample
coverage when investigating.

## Operating procedures

- [Production operations](runbooks/production.md): diagnosis, scaling boundaries,
  updates, secrets and administrative actions.
- [Alerts](runbooks/alerts.md): current signals, notification testing and recovery.
- [Backup restore rehearsal](runbooks/backup-restore-rehearsal.md): isolated database
  restore with explicit target and evidence.
- [Disaster recovery](runbooks/dr-drill.md): full application recovery planning.
- [HA and drain](ops/runbooks/ha.md): replica readiness and bounded shutdown.
- [Multi-region boundaries](multi-region.md): implemented controls and integration
  limitations; region labels are not independent geographic proof.

CI configuration and dependency-update automation vary by repository/export.
Inspect the files shipped with your checkout rather than assuming scheduled
vulnerability checks, automatic merges or publishing are enabled.
