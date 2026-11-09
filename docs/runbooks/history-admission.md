# Durable Request History Admission — Operator Runbook

Configure the gateway to reject requests when durable request history cannot
accept writes, or explicitly allow requests while reporting possible history
loss. This admission check is one part of a deployment's durability design; it
does not independently guarantee recovery from every database or storage failure.

Related surfaces: the loggerd consumer's durable-buffer backpressure gate
(`services/loggerd/consumer/history_buffer.go`, armed automatically in
production) publishes the admission signal this gate reads; the HA
topology authority (`deploy/helm/yabanin/HA-TOPOLOGY.md`) owns the
RPO/RTO table this gate implements at the admission boundary.

## 1. Knobs

| Env / YAML | Default | Meaning |
| --- | --- | --- |
| `YABANIN_HISTORY_ADMISSION` / `history_admission_enabled` | `false` | Arms the gateway-side probe. **Off by default**: the request path stays bit-for-bit and no probe round-trips are paid until the deployment explicitly opts in. |
| `YABANIN_HISTORY_MODE` / `history_mode` | `""` (= `reject`) | Outage policy: `reject` refuses new requests while durable history cannot guarantee writes (fail-closed); `allow_loss` serves through the outage with the loss surfaced in logs and the admission decision (explicit opt-in). Any other value fails gateway startup — a typo must be fixed, never silently resolved to deny-everything. |
| `YABANIN_HISTORY_PROBE_MAX_ENTRIES` / `history_probe_max_entries` | `500000` | Stream-depth bound (entries) for the probe's direct `XLen` check: at or above it the stream counts as saturated even when loggerd's signal key is missing. The default matches the loggerd consumer's `DefaultHistoryBufferMaxEntries` (pinned by test). `0` = signal-only probing; negative values fail startup. |

The probe watches the gateway's own event stream
(`YABANIN_EVENT_STREAM`, default `events:queue`). That stream name must
equal loggerd's `YABANIN_LOGGERD_STREAM`: the signal key is namespaced by
the stream, and the depth check measures the stream loggerd consumes.

## 2. Arming checklist

1. Redis is configured (`redis_addr`) — the gateway refuses to start with
   the knob armed and no Redis (fail-closed: without the signal/depth
   probe the outage state is permanently unverifiable).
2. loggerd runs against the same stream (`YABANIN_LOGGERD_STREAM` ==
   `YABANIN_EVENT_STREAM`) — its signal publisher arms automatically in
   production (any Redis adapter that can `SET`).
3. Set `YABANIN_HISTORY_ADMISSION=true`, optionally the mode, restart the
   gateway.
4. Confirm the arming log line (component `gateway`):
   `history admission armed` with the resolved `mode`, `probe_stream`,
   `probe_max_entries` and the reservations gate it composes with.

The gate works with or without the reservations money leg
(`YABANIN_RESERVATIONS`): it is deployment-level, consulted in
`Admission.Plan` before the per-org §9 modes. A deployment with
reservations off gets a history-only admission controller; orgs with
reservations off still get history-gated admission.

## 3. What the gate observes

- **Signal (primary):** loggerd heartbeats a JSON payload to the Redis key
  `events:history:admission:<stream>` with a 15 s TTL, observed once per
  consumer iteration. States: `ok`, `buffer_full` (durable-buffer gate
  saturated), `write_unavailable` (durable write path down). A missing or
  stale key means "no live signal" — loggerd down or never ran — and does
  **not** by itself deny: the history store may still accept writes.
- **Depth (second line of defense):** when the signal says `ok` (or is
  absent), the gateway `XLen`s the stream directly; at or above
  `history_probe_max_entries` the stream counts as `buffer_full`. This
  catches saturation when the signal key expired mid-outage.
- **Unverifiable:** any probe error (Redis unreachable, malformed signal
  payload) fails closed — under `reject` this denies; under `allow_loss`
  this serves with the loss marker.

## 4. Observable behavior during an outage

- **API:** refused requests answer `503` with error code
  `history_unavailable` and the message "durable request history
  temporarily unavailable — new requests are refused until history writes
  are guaranteed (I40; see YABANIN_HISTORY_MODE)".
- **Metric:** `gateway_reservations_denied_total{scope_kind="history"}`
  increments once per refused admission decision (measurement window:
  per request, at the gateway pre-check before the cache lookup; the
  counter series starts when the gateway arms the gate and exports
  metrics). No `wallet`/`team_month`/... label is touched — a history
  outage is not a budget refusal.
- **Logs (component `history-admission`):** state transitions log once,
  not per request — `history outage: new requests REJECTED until durable
  history is guaranteed (default reject policy, I40)` under reject;
  `history outage: serving new requests with durable history LOSS
  permitted (explicit allow_loss opt-in); rights, spend accounting and
  mandatory audit remain fail-closed` under allow_loss; recovery logs
  `history admission recovered: durable history healthy again`.
- **Recovery:** when loggerd heartbeats `ok` again (and the depth is back
  under the bound), admission reopens without a gateway restart.

## 5. Limitations

- The gate covers the **request-admission boundary**: it cannot resurrect
  history already lost before arming, and it does not police in-flight
  requests that were admitted before the outage.
- `allow_loss` serves requests while durable history is down; it does not
  relax any other fail-closed leg (rights, spend accounting and mandatory
  audit remain denied on their own failures).
- The probe adds 1–2 Redis round-trips per admitted request while armed
  (same budget class as the §7.2 admission-overhead envelope). Un-armed
  deployments pay nothing.
- Deployment-level only: per-org §9 reservations modes are unaffected
  (the history gate composes before them); shadow-mode reservations still
  get terminal history refusals, because durable history is not a
  per-org billing choice.
