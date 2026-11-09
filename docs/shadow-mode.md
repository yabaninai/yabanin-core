# Yabanin — Shadow Mode (v9)

Shadow mode answers the routing question with **real production data** instead
of simulation: a sampled fraction of real, already-served requests is silently
re-sent to a candidate model/provider, and the candidate's **actual** cost and
latency are recorded next to the primary request's row. The comparison stops
being an estimate.

It is a gateway feature. It is **off by default**, it costs real money while
on, and it is built so that nothing about it can ever affect the client's
response.

## The three invariants

1. **Mandatory passthrough.** The client's response is fully written to the
   wire *before* the shadow call fires. Shadow errors, timeouts, panics and a
   completely dead shadow provider are invisible to the client,
   byte-for-byte. The test suite proves this (shadow error / timeout / panic
   cases all assert the primary response is unchanged).
 2. **Fail-safe defaults.** Off by default. Skips residency-pinned orgs, skips
    requests already going to the shadow model. Sampled, concurrency-capped,
    timeout-bounded, optionally budget-capped. Runtime kill switch. (Streaming
    primaries ARE mirrored — see [Streaming stance](#streaming-stance).)
3. **Cost accounting.** Shadow cost is real spend at the shadow provider.
   It is stored as its own `request_logs` row (`ab_group='shadow'`, same
   `request_id` as the primary), excluded from every client-visible spend
   aggregate, and **never** deducted from client credits.

## How it works

```
client ──POST /v1/chat/completions──▶ gateway
                                        │
                                        ├─ primary upstream call ──▶ response ──▶ client  (always)
                                        │
                                        └─ AFTER the response is written:
                                           eligible? (see gates) ──▶ goroutine:
                                                                  shadow upstream call
                                                                  usage → cost
                                                                  event: request.shadow_completed
                                                                          │
                                                                  loggerd ──▶ request_logs
                                                                              (ab_group='shadow',
                                                                               same request_id)
```

Per-request gates (first failure wins, each has its own skip metric):

| Gate | Skip reason | Notes |
|---|---|---|
| feature enabled (runtime state) | `disabled` | env config OR admin toggle |
| primary model ≠ shadow model | `same_model` | mirroring to itself is waste |
| sample draw < `sample_rate` | `sampling` | default 10% |
| org not residency-pinned | `residency` | pinned orgs' data may not leave the region |
| daily budget has headroom | `budget_exhausted` | in-memory, UTC-day, advisory |
| concurrency slot within grace | `semaphore` | default 4 in-flight, 250 ms grace |

There is **no streaming gate**: whether the primary request streams is not part
of the mirror decision. A shadow call is always a plain non-streaming request
to the candidate (the gateway forces `"stream": false` in the shadow body), so
a streaming primary is mirrored exactly like a non-streaming one.

## Configuration

All variables are optional; anything unset keeps the feature off or at its
safe default.

| Variable | Default | Meaning |
|---|---|---|
| `YABANIN_SHADOW_ENABLED` | `false` | master switch (env level; the runtime toggle overrides at runtime) |
| `YABANIN_SHADOW_MODEL` | — | candidate model to mirror to (**required when enabled**) |
| `YABANIN_SHADOW_UPSTREAM_URL` | primary upstream | shadow provider base URL (goes through the same pool → SSRF allowlist applies) |
| `YABANIN_SHADOW_API_KEY` | gateway key | key presented to the shadow provider |
| `YABANIN_SHADOW_SAMPLE_RATE` | `0.10` | fraction of eligible requests to mirror (0..1, clamped) |
| `YABANIN_SHADOW_TIMEOUT` | `30s` | per-shadow-call deadline |
| `YABANIN_SHADOW_MAX_CONCURRENT` | `4` | in-flight shadow calls cap |
| `YABANIN_SHADOW_DAILY_BUDGET_USD` | `0` (unlimited) | daily real-spend cap, UTC-day, advisory |

YAML equivalent under `gateway.shadow.*` in `config.yaml`.

An invalid config (e.g. enabled with no model) **degrades to disabled** with a
warning log — shadow is observability, not a request-path dependency, and a
typo must not take the gateway down.

## Runtime kill switch

On the gateway's admin listener (default `:9090`, the same one that serves
`/metrics`):

```bash
# current state (never includes the API key)
curl -H "Authorization: Bearer $YABANIN_METRICS_BEARER_KEY" \
     http://gateway:9090/admin/shadow/status

# flip at runtime (no restart)
curl -X POST -H "Authorization: Bearer $YABANIN_METRICS_BEARER_KEY" \
     -d '{"enabled": false}' http://gateway:9090/admin/shadow/toggle
```

- **Fail-closed auth.** Unlike `/metrics` (which falls back to
  network-restriction-only when no key is set), the toggle **requires**
  `YABANIN_METRICS_BEARER_KEY`: no key configured ⇒ `403`. A cost-bearing
  control must not default open. Constant-time comparison.
- Semantics: in-flight shadow calls finish; no new ones start while disabled.
- The toggle is **process-local**: a restart resets state to the env config.
  Multi-replica deployments: toggle each replica (shared state is out of v9
  scope by design — it requires schema or protocol changes).
- `409` when shadow is not configured at all.

## Cost implications (read this before enabling)

**Shadow calls are real requests at the shadow provider and cost real
money.** A 10% sample on a busy org is 10% extra spend, billed by the shadow
provider on its own clock.

- Set `YABANIN_SHADOW_DAILY_BUDGET_USD` for any org with meaningful volume.
  The ledger is in-memory per process (resets on restart, rolls at UTC
  midnight) and is advisory, not billing-grade.
- Watch `yabanin_shadow_cost_usd_total` (Prometheus) and
  `yabanin_shadow_budget_exhausted_total`.
- The comparison endpoint tells you the answer **per request**, which is what
  a routing decision needs:

  ```bash
  curl -H "Authorization: Bearer $ADMIN_TOKEN" \
       "https://admin/api/analytics/shadow?days=30"
  ```

  Response (shape):

  ```json
  {
    "period": "last_30_days",
    "primary_model": "gpt-4o-mini",
    "shadow_model": "gpt-4o",
    "overlap": 1240,
    "primary_avg_usd": 0.00042,
    "shadow_avg_usd": 0.0021,
    "delta_pct": 399.9,
    "verdict": "pricier",
    "by_model": [ ... ]
  }
  ```

  Verdicts: `cheaper` / `pricier` / `insufficient_data`. Below 20 overlapping
  requests, or a |delta| under 1%, the verdict is `insufficient_data` — the
  endpoint refuses to over-claim on noise. A window with no shadow traffic is
  a valid report (`overlap: 0`), not an error.

## Accounting semantics

- The shadow result is stored as a **separate** `request_logs` row:
  same `request_id`, `ab_group='shadow'`, `model_used` = shadow model,
  `cost_in_usd` = the shadow call's real computed cost, zero tokens/cost on
  error.
- `counterfactual_cost_usd` is **not** used for shadow: that column belongs
  to the cache-counterfactual. Routing-counterfactual and
  cache-counterfactual are different quantities and must not share a column
  without the `ab_group` discriminator.
- Every client-visible aggregate (savings report, cost analytics, cache
  analytics, spend alerts, request stats, top models/orgs, time series, error
  breakdown, latency percentiles, recent errors) explicitly excludes
  `ab_group='shadow'`.
- The credit **Deductor is never called for shadow rows.** The Deductor
  dedupes by `request_id`; a shadow row sharing the primary's id would
  double-charge the org. This is a hard invariant with a dedicated test.

## Residency stance

Orgs with a residency pin (`organizations.residency_region` set to anything
other than `global`) are **never mirrored**. Their data may not leave the
pinned region, and the shadow provider is arbitrary. The skip is counted in
`yabanin_shadow_skipped_total{reason="residency"}`. Per-org opt-in would need
a new database column would require a migration and is not included.

## Streaming stance

Streaming primaries **are** mirrored (v10). The gateway fires the shadow call
from the streaming path right after the upstream connection succeeds (before
the drain), so the candidate's latency is measured concurrently with real
load.

The shadow call itself is **always a plain non-streaming request** to the
candidate: the gateway rewrites the shadow body to force `"stream": false`.
There is no point re-emitting a shadow stream to anyone — the only things
shadow-mode needs are the candidate's real tokens, cost, and latency, which a
plain completion returns. The client's SSE bytes are never touched (the shadow
runs in its own goroutine with its own context; the SSE passthrough-invariant
tests assert the stream is byte-for-byte unchanged even when the shadow target
is dead or hangs).

**Accounting limitation:** the shadow's usage is measured on a non-streaming call
while the primary may have streamed. Token counts can differ slightly because
providers apply caching and chunking differently per transport. For a cost
comparison this is acceptable and is what "what would the candidate have
costed" means; it is not a bit-exact replay.

## Observability

Prometheus (gateway `/metrics`, registered when metrics + shadow are on):

| Metric | Meaning |
|---|---|
| `yabanin_shadow_requests_total{result}` | outcomes: `completed`/`error`/`timeout`/`panic`/`skipped` |
| `yabanin_shadow_skipped_total{reason}` | gate breakdown |
| `yabanin_shadow_latency_seconds{model}` | shadow call duration |
| `yabanin_shadow_cost_usd_total{model}` | real USD spent |
| `yabanin_shadow_budget_exhausted_total` | budget skips |
| `yabanin_shadow_enabled` | runtime state gauge (1/0) |

**Grafana dashboard.** `deploy/grafana/dashboards/shadow.json` is
auto-provisioned (like the other Yabanin dashboards): **Yabanin — Shadow
Mode** shows the enabled state, spend rate (USD/s), budget burned (24h),
budget-exhausted events (1h), requests by result, skips by reason, latency P95
by model, and spend by model. Open it at the Grafana host (demo:
http://localhost:3001, `admin` / `yabanin`).

**Alerts.** `deploy/prometheus/alert-rules.yml` (group `yabanin-shadow`):

- `ShadowHighErrorRate` (warning) — >50% of shadow calls failing over 15m
  while shadow traffic flows; sustained errors mean the target is
  misconfigured or unreachable.
- `ShadowBudgetBurn` (info) — the daily budget cap is blocking new shadow
  calls; tune `YABANIN_SHADOW_DAILY_BUDGET_USD` or lower the sample rate.

## Runbook

1. Pick the candidate: set `YABANIN_SHADOW_MODEL` (and URL/key if it's a
   different provider).
2. Start small: `YABANIN_SHADOW_SAMPLE_RATE=0.05`,
   `YABANIN_SHADOW_DAILY_BUDGET_USD` at a number you'd actually approve.
   `YABANIN_SHADOW_ENABLED=true`.
3. Let it run 24–72 h. Watch `shadow_requests_total{result="error"}` —
   sustained errors mean the target is misconfigured (or doesn't speak the
   assumed wire protocol); in that case usage/cost are zero and the rows are
   useless.
4. Read `/api/analytics/shadow?days=N`. Decide.
5. Turn it off (toggle or env) when the question is answered. Shadow traffic
   you don't read is money you don't need to spend.

## What this is not

- Not an A/B test: the client always gets the primary model's answer.
- Not a load-balancer or failover path: the shadow call is fire-and-forget
  with its own context; the request context's cancellation does not reach it,
  and it does not reach the response.
- Not billing: shadow spend is the operator's, never the client's.
