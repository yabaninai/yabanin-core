# Durable Request History Admission — Operator Runbook

The gateway has two admission checks. A paid provider dispatch requires a
confirmed start in PostgreSQL. An optional Redis probe can reject requests
earlier when loggerd reports history loss or its event stream backs up.
Sections 1–5 describe the Redis probe. Section 6 covers paid dispatch and
recovery after the provider has received a request.

Related surfaces: the loggerd consumer's durable-buffer backpressure gate
(`services/loggerd/consumer/history_buffer.go`, armed automatically in
production) publishes the admission signal this gate reads; the HA
topology authority (`deploy/helm/yabanin/HA-TOPOLOGY.md`) owns the
RPO/RTO table this gate implements at the admission boundary.

## 1. Knobs

| Env / YAML | Default | Meaning |
| --- | --- | --- |
| `YABANIN_HISTORY_ADMISSION` / `history_admission_enabled` | `false` | Arms the gateway-side probe. The Redis probe is off by default. Paid dispatch still requires a confirmed PostgreSQL write. |
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
  (same budget class as the §7.2 admission-overhead envelope). Disabling the probe removes those Redis calls.
- Deployment-level only: per-org §9 reservations modes are unaffected
  (the history gate composes before them); shadow-mode reservations still
  get terminal history refusals, because durable history is not a
  per-org billing choice.

## 6. Paid dispatch and recovery in Preview 2

The gateway creates an invocation ID for accounting. A client-supplied
`X-Request-ID` is a correlation value. A new client request can carry the
same value and incur a separate charge.

| Client observation | What happened | Client or operator action |
| --- | --- | --- |
| HTTP 503, `history_unavailable`, with a message that the paid call was not sent | The gateway could not confirm the durable start for that call. This applies even when the optional history probe is disabled or uses `allow_loss`. | Restore gateway write access to PostgreSQL. For a single refused call, retry after recovery. |
| `accounting_commit_failed` after provider dispatch | The gateway could not confirm the terminal usage record. A streaming client can receive this error after HTTP 200 and some content. The provider may already have charged for the work. | Stop automatic retries. Retain the organization ID, request ID and time of the failure. Check the invocation before issuing any new request. |
| Connection lost with no final response | The client has no reliable evidence of how far the request progressed. | Use the same lookup before deciding whether to retry. |

An operator with authorized database access can inspect the attempt with
this read-only query in `psql`. Set the `org_id` and `request_id` variables
to the affected tenant and client correlation value. Multiple rows can
represent separate attempts, including a detached shadow call.

```sql
SELECT a.invocation_id, a.kind, a.state, a.admitted_at, a.resolved_at,
       a.resolve_reason, f.committed_at AS terminal_facts_at
FROM request_admissions AS a
LEFT JOIN request_terminal_facts AS f
  ON f.invocation_id = a.invocation_id AND f.org_id = a.org_id
WHERE a.org_id = :'org_id' AND a.client_request_id = :'request_id'
ORDER BY a.admitted_at, a.invocation_id;
```

An `admitted` row records the start and can still be in flight. A
`voided` row records a proven local refusal. When terminal facts are
present, loggerd can recover the accounting from PostgreSQL under the same
invocation ID, including after a gateway restart or missed Redis delivery.
A `reconciled` admission records processed accounting. Check the
invocation's settlement job and usage transaction for the final debit.

After the 15-minute grace period, loggerd can mark an admission without
terminal facts `unresolved` with reason `grace_elapsed_no_terminal_facts`.
Keep this attempt open for investigation. Missing evidence establishes
neither zero usage nor a billable amount. Later authoritative terminal
facts can still reconcile the same invocation. Recovery does not resend
the provider request.
