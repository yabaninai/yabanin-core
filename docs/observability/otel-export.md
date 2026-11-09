# OTel request-log export

loggerd can mirror content-free request-log records to an OpenTelemetry
collector over OTLP/HTTP, using the [GenAI semantic
conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) plus
`org.id`, `request.id`, `yabanin.*` attribution attributes.

**Export is disabled by default.** Without an explicit `YABANIN_OTEL_LOGS_ENDPOINT`
the process initializes nothing: no goroutine, no socket, and the consumer
path behaves bit-for-bit as if the feature did not exist. Standard
`OTEL_EXPORTER_OTLP_*` environment variables can never turn the export on —
only the explicit `YABANIN_OTEL_LOGS_*` knobs below control it.

## Environment variables

| Variable | Default | Semantics |
| --- | --- | --- |
| `YABANIN_OTEL_LOGS_ENDPOINT` | *(empty = off)* | OTLP/HTTP collector. Either `host:port` (HTTPS, like the trace exporter) or a full `http(s)://` URL for plain-HTTP collectors. Empty or absent means export off. |
| `YABANIN_OTEL_LOGS_SAMPLE` | `1.0` | Deterministic sample rate in `[0, 1]`, hashed per `request_id` (FNV-1a + splitmix64): the same request is always sampled or not, across retries, replicas and reprocessing. Invalid or out-of-range values log a warning and fall back to `1.0`. |
| `YABANIN_OTEL_LOGS_HEADERS` | *(empty)* | Extra OTLP request headers as `Key:Value,Key2:Value2` (e.g. auth for a SaaS collector). Malformed entries are skipped with a warning; a typo never disables export. |

Queue/batch tuning (`QueueSize` default 4096, batch size 512, flush interval
5s, export timeout 10s) exists in code as `tracing.LogExporterConfig` but is
deliberately not exposed via environment: the defaults are safe for every
supported deployment size.

## Content contract

Message text and provider error bodies are **never exported** unless the
operator opts in at the code level (`tracing.LogExporterConfig.IncludeContent`).
There is no environment variable that enables content export. With the default
setting the record body stays empty and only the attributes above leave the
process, which makes the exporter safe to point at a third-party collector.

## `genai.system` bucketing (cardinality bound)

The `genai.system` attribute is a bounded label, never a raw host:

- Hosts on the allowlist (`api.openai.com`, `api.anthropic.com`,
  `generativelanguage.googleapis.com`, Bedrock `*.amazonaws.com`,
  `*.openai.azure.com`, and others — see `genaiSystemByHost` in
  `pkg/tracing/export_logs.go`) map to their canonical provider name, e.g.
  `openai`, `anthropic`, `aws.bedrock`.
- Any unknown or tenant-configured upstream host collapses into the fixed
  bucket `other`.
- A record without an upstream URL carries no `genai.system` attribute at all.

The exported value set is therefore bounded by the allowlist plus one bucket,
no matter how many tenants configure their own upstream base URLs. Raw
hostnames never reach metrics or the OTel backend.

## Attribute bounds and queue memory (cardinality bound)

Attribute value LENGTH and set cardinality are bounded at the exporter's
`Enqueue` boundary, before a record enters any queue — a hostile or buggy
producer event cannot inflate per-record memory, exported attribute values,
or the backend's attribute domains:

| Field | Exported as | Bound |
| --- | --- | --- |
| `genai.system` | bounded label | Closed value set: allowlist systems + suffix rules + `other` (see above). |
| `yabanin.event_type` | bounded attribute | ≤ 64 bytes; live set has 4 members. |
| `request.id`, `org.id`, `yabanin.session_id`, `genai.request.model`, `genai.response.model`, `yabanin.policy_verdict` | bounded attributes | ≤ 256 bytes each (rune-safe truncation). |
| upstream URL | never exported | ≤ 512 bytes in the queue; only feeds `genai.system` derivation. |
| prompt sample (opt-in) | record body | ≤ 4096 characters. |

Cardinality classes, explicitly:

- **Bounded label/value sets** (`genai.system`, `yabanin.event_type`,
  `yabanin.policy_verdict`): safe for any backend, safe to aggregate by.
- **Identifiers by design** (`request.id`, `org.id`, `yabanin.session_id`):
  one distinct value per request — fine for OTel *logs* (each record is its
  own event), never safe as Prometheus label values. The bounded-length
  clamp does not make them bounded *sets*.
- **Config-bounded sets** (`genai.request.model`, `genai.response.model`):
  the value set follows the routing configuration's model names; the length
  clamp bounds the per-record cost, and the names are admin-configured, not
  request-controlled.

Truncated values are freshly materialized strings, so a clamped record never
keeps the oversized producer allocation alive in memory. Sampling is decided
on the raw `request_id` before any clamp — clamping never changes which
requests are sampled.

**Queue memory is bounded by construction, not by hope:** the pipeline has
two bounded layers — the enqueue channel and the OTel SDK batch queue — each
holding at most `QueueSize` records. `QueueSize` is clamped at construction:
a hard cap of 8192, plus a 64 MiB worst-case budget across BOTH layers
(2 × QueueSize × per-record worst case, computed from the clamps above;
content export opted in lowers the effective queue below the cap). The exact
bound for a configuration is `LogExporter.WorstCaseQueueMemoryBytes()`;
clamping the queue instead of dropping early keeps every drop observable at
the enqueue boundary. Prometheus-side label cardinality is bounded the same
way: `gateway_upstream_health_state{host}` takes only `metrics.
BoundUpstreamHostLabel` values (provider buckets + `other`/`unknown`), never
a raw URL.

## Backpressure and drops

Every record enters a bounded queue (4096 by default). `Enqueue` never blocks
the consumer loop: when the queue is full the record is dropped and counted in
the Prometheus counter `yabanin_otel_logs_dropped_total` (exported on the
loggerd `/metrics` endpoint). An unreachable or slow collector can therefore
only cost dropped records — never consumer latency or unbounded memory.
`Shutdown` drains the queue and flushes pending batches to the collector.

**Known limit (explicit limitation, not hidden):** the OTel SDK batch
processor has its own internal queue, and drops that happen inside the SDK
(between our queue and the network) are not visible to
`yabanin_otel_logs_dropped_total`. The same applies to records lost WITH a
failed export attempt: `yabanin_otel_export_errors_total` counts the failed
attempt (the outage signal, watchable on the Grafana export dashboard), not
the individual records lost with it. Additionally, length-clamped attribute
values are truncated silently — a truncated value is not counted anywhere
(it is still exported, just bounded); only full-record drops are counted.
Memory stays bounded on both layers either way, and the counters cover the
drop points the consumer actually hits (enqueue overflow / shutdown race /
failed attempts).

## OTelLogsDropped {#OTelLogsDropped}

Alert runbook (installed as `OTelLogsDropped` in
`deploy/prometheus/alert-rules.yml`:
signal `rate(yabanin_otel_logs_dropped_total[5m]) > 0`, anchored here per the
archived receipt). The counter exported on the loggerd `/metrics` endpoint
grew: request-log records were dropped at the export boundary — the bounded
queue (4096) was full or the exporter was shutting down. The consumer loop is
never blocked; drops cost log-export completeness only.

**Action:** check collector reachability from loggerd
(`YABANIN_OTEL_LOGS_ENDPOINT`): network/DNS to the sink, collector process
health, and export batch pressure at the drop window. A short drop burst
during a collector restart is the documented failure mode (bounded, memory
stays bounded); a sustained drop rate means the collector is down or
undersized for the current traffic.

**Recovery example:**

```bash
curl -fsS http://127.0.0.1:8085/metrics | grep yabanin_otel_logs_dropped_total
# -> yabanin_otel_logs_dropped_total 512
# restore the collector; the counter stalls and the queue drains:
sleep 300; curl -fsS http://127.0.0.1:8085/metrics | grep yabanin_otel_logs_dropped_total
# unchanged over 5m -> export recovered
```

Dropped records are not recoverable; the affected window is visible on the
Grafana "Yabanin — Observability Export" dashboard (§ below). Known limit:
drops inside the OTel SDK batch processor stay invisible to this counter
(§ Backpressure and drops) — a zero counter with an unreachable collector
does not prove zero loss at the SDK layer.

## Local collector quickstart

Run an OTLP/HTTP collector and inspect the records it receives:

```sh
docker run --rm -p 4318:4318 otel/opentelemetry-collector:latest
```

Point loggerd at it and restart:

```sh
export YABANIN_OTEL_LOGS_ENDPOINT=http://127.0.0.1:4318
```

Grafana dashboards ship in `deploy/grafana/dashboards/`; the provisioning
config in `deploy/grafana/provisioning/dashboards/dashboards.yml` scans that
directory, so dropping the repo on a Grafana container as
`/etc/grafana/dashboards` picks up every dashboard, including **Yabanin —
Observability Export** (`observability-export.json`), which tracks
`yabanin_otel_logs_dropped_total` (cumulative, 5m rate, per-instance and a
drops-last-hour status stat). Scraping loggerd's `/metrics` with Prometheus is
enough to feed it.

## Failure behavior summary

| Scenario | Behavior |
| --- | --- |
| Collector unreachable, queue full | Records dropped, `yabanin_otel_logs_dropped_total` grows, consumer latency unchanged, memory bounded. |
| Broken collector config (bad URL) | loggerd logs the error and continues without export. Observability never blocks the service. |
| No `YABANIN_OTEL_LOGS_ENDPOINT` | Feature fully off; no egress, no goroutines. Standard `OTEL_*` env cannot enable it. |
| Non-request event types / strict content profile | Never mirrored to the sink; content never leaves the process. |
