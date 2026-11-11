# Visualizer field matrix

Task slice: **CV-00-01** (Core plan, `plans/CORE.md` visualizer family). Audited
at product TASK_BASE `ffc01005dfde91953161ea02b96feae8756c0e1c`, branch
`task/cv00-01`. All `file:line` citations resolve at that revision.

This slice covers the three existing producers the initial visualizer views
consume: the routing map (configuration), the org-scoped request detail
(recorded), and the provider health aggregate (recorded). Later CV-00 children
extend this matrix with attempt, tool, policy, region, price and aggregate
provenance (CV-00-02), the frozen twenty-view matrix (CV-00-03) and
producer-gap assignments (CV-00-04); nothing here pre-approves an endpoint name
that source does not already contain.

Method: the dashboard API modules (`web/dashboard/src/api/routing.ts`,
`web/dashboard/src/api/requests.ts`) were traced to their registered admin
routes, handler methods and store queries, and each recorded field was traced
onward to the gateway producer that originates it. Named symbols are real
symbols at the cited lines; absence claims cite the struct or query that was
inspected. Note: the Go package under `pkg/gateway` declares the historical
package identifier `cli` (pkg/gateway/gateway.go:1); symbols are cited by file
path regardless of package name.

## (a) Routing map fields

Chain: `getRoutingMap` (web/dashboard/src/api/routing.ts:62) calls
`GET /api/routing/map?org_id=` (registered services/admin/handlers/router_models.go:51)
and is served by `AdminHandlers.RoutingMap`
(services/admin/handlers/routing_map.go:49), which gates the call with
`AdminHandlers.requireOrgRead` against `adminstore.PermRoutingManage`
(services/admin/handlers/routing_map.go:29-45): root passes for any org; a
non-root caller needs the permission on that org; anything else — foreign org
or membership without the permission — is answered 404, indistinguishable from
a missing org. The store method is `Store.GetRoutingMap`
(pkg/adminstore/routing_map.go:79).

Everything in this response is **configuration-time** data (current tables),
not recorded traffic. Only the rules section is org-filtered; models and
aliases are platform-global (documented at pkg/adminstore/routing_map.go:75-78).

| JSON field | Kind / units | Producer (file:line) | Scoping actually applied | Data class |
| --- | --- | --- | --- | --- |
| `org_id` | string (uuid echo) | handler reads the query param (services/admin/handlers/routing_map.go:54); struct field `RoutingMap.OrgID` (pkg/adminstore/routing_map.go:57) | gated by `requireOrgRead` with `PermRoutingManage` (services/admin/handlers/routing_map.go:55) | configuration (scope echo; not a stored row) |
| `models[].model_name` | string | SQL `SELECT ... FROM models_registry` (pkg/adminstore/routing_map.go:84-88); struct `RoutingMapModel` (pkg/adminstore/routing_map.go:16-25) | none — `models_registry` is global (table: migrations/0001_init.up.sql:1089) | configuration |
| `models[].display_name` | string | same query, same scan (pkg/adminstore/routing_map.go:85-100) | global | configuration |
| `models[].tier` | string | same query | global | configuration |
| `models[].provider` | string | same query; column default `'openai-compat'` with a provider CHECK list (migrations/0001_init.up.sql:1099, :1114) | global | configuration |
| `models[].enabled` | boolean | same query | global | configuration |
| `models[].fallback_model` | nullable string (`omitempty`) | same query; column `fallback_model text` (migrations/0001_init.up.sql:1100) | global | configuration |
| `models[].failover_models` | string array | same query; column `failover_models text[]` (migrations/0001_init.up.sql:1101) | global | configuration |
| `models[].tier_pool` | string array | same query; column `tier_pool text[]` (migrations/0001_init.up.sql:1102) | global | configuration |
| `aliases[].alias` | string | `Store.ListModelAliases` (pkg/adminstore/model_aliases.go:27-33), mapped at pkg/adminstore/routing_map.go:107-114; struct `RoutingMapAlias` (pkg/adminstore/routing_map.go:28-31) | none — `model_aliases` has no org column (table: migrations/0001_init.up.sql:1036-1041) | configuration |
| `aliases[].target_model` | string | same producer | global | configuration |
| `rules[].id` | string (uuid) | SQL `SELECT id::text, ... FROM routing_rules WHERE org_id = $1 ORDER BY priority, created_at, id` (pkg/adminstore/routing_map.go:116-120); struct `RoutingMapRule` (pkg/adminstore/routing_map.go:34-40) | **org-scoped** by `WHERE org_id = $1` (table: migrations/0001_init.up.sql:1812-1821) | configuration |
| `rules[].match_expr` | string | same query | org-scoped | configuration |
| `rules[].target_model` | string | same query | org-scoped | configuration |
| `rules[].priority` | integer (sort key) | same query | org-scoped | configuration |
| `rules[].enabled` | boolean | same query | org-scoped | configuration |
| `warnings[]` (`code`, `scope`, `source`, `target?`, `message`) | computed array | `computeRoutingWarnings(models, aliasRows, rules)` (pkg/adminstore/routing_map.go:156-246), attached at pkg/adminstore/routing_map.go:141; stable codes declared at pkg/adminstore/routing_map.go:65-73 | pure function over the three sections above; recomputed per read, never persisted | configuration-derived (computed at read time) |

Warnings are derived, not observed: a `chain_cycle` warning describes what
the gateway's `buildChain` skip logic would do with the current chain
(pkg/adminstore/routing_map.go:148-155, 173-209); it is not a record of any
request. `RoutingMapModel` deliberately excludes `upstream_url` and
`upstream_api_key` so the map can never carry upstream credentials
(pkg/adminstore/routing_map.go:13-15).

Client-side, `buildRoutingGraph` (web/dashboard/src/lib/routingGraph.ts:84)
renders only this payload, draws unknown targets as dashed phantom nodes, and
never mixes in recorded aggregates (honest-data contract,
web/dashboard/src/lib/routingGraph.ts:3-14).

## (b) Request detail fields

Chain: `getRequestDetail` (web/dashboard/src/api/requests.ts:187) calls
`GET /api/organizations/{id}/requests/{request_id}` (registered
services/admin/handlers/router_analytics.go:46) and is served by
`AdminHandlers.apiOrgRequestDetail` (services/admin/handlers/request_list.go:29),
which calls `Store.GetRequestDetail` (pkg/adminstore/request_detail.go:189) and
its executor variant `getRequestDetailOn`
(pkg/adminstore/request_detail.go:199), whose single row query is
`SELECT ... FROM request_logs WHERE org_id = $1::uuid AND request_id = $2`
(pkg/adminstore/request_detail.go:212-247).

Persistence: one row in `request_logs`
(migrations/0001_init.up.sql:1698-1760), written asynchronously by loggerd's
`fullRequestLogRow` INSERT projection
(services/loggerd/consumer/event_mapper.go:557-604) from the gateway event
stream. Producer chain for the recorded values: gateway completion/failure
`eventBase` (pkg/gateway/events.go:234 onwards, populated at e.g.
pkg/gateway/chat.go:1063-1085 and pkg/gateway/stream.go:1511 area) and
`eventpub` payload (pkg/eventpublisher/publisher.go:154-162) serialized by the
Redis publisher (pkg/eventpublisher/redis_publisher.go:249-251), then mapped by
`parseRequestEvent` (services/loggerd/consumer/event_mapper.go:329).

Authorization actually applied (this endpoint is not `requireOrgRead`-gated;
visibility is decided inside the store query and post-read checks):

- Row visibility: org scoping is in the SQL (`WHERE org_id = $1`); a row is
  returned only when the caller owns it (`user_id` match), acts under a live
  delegation pinned to `agent_id`, holds a redeemed payload grant, or has
  org-wide `requests.read`; otherwise `ErrNotFound` → 404 with no existence
  leak (pkg/adminstore/request_detail.go:277-285; role check
  `hasOrgWideRequestMetadata` at services/admin/handlers/request_list.go:365-368).
- Payload columns (`error`, `response`) are selected only for owners, valid
  grants or delegated own rows (CASE expressions,
  pkg/adminstore/request_detail.go:223-226); `upstream_url`,
  `upstream_request`, `upstream_response` additionally require an
  **originals** grant gated on the org retention setting
  (pkg/adminstore/request_detail.go:217, 227-228; gate at
  services/admin/handlers/request_list.go:69-91).
- Deny-own-history removes the resource itself, returning 404
  (pkg/adminstore/request_detail.go:277-281).
- One-time grant redemption is journalled via `auditRequestDetailDecision`
  (services/admin/handlers/request_list.go:201-224).

| JSON field | Kind / units | Producer (file:line) | Persistence | Data class |
| --- | --- | --- | --- | --- |
| `request_id` | string | gateway request id on the event; column `request_logs.request_id` (migrations/0001_init.up.sql:1713) | request_logs row | recorded |
| `org_id` | string (uuid) | `ev.orgIDValue` set by loggerd (services/loggerd/consumer/event_mapper.go:560); scanned at pkg/adminstore/request_detail.go:259 | request_logs | recorded |
| `model_requested` | string | client-requested model from the gateway event (`eventBase.ModelRequested`, e.g. pkg/gateway/chat.go:1070); mapped at services/loggerd/consumer/event_mapper.go:561 | request_logs (migrations/0001_init.up.sql:1702) | recorded |
| `model_used` | string | model that actually served (or `''` on pre-upstream termination, e.g. the 429 budget projection forces `''`, services/loggerd/consumer/event_mapper.go:662) | request_logs (migrations/0001_init.up.sql:1703) | recorded |
| `upstream_url` | string, `omitempty`; **originals-gated** | winning hop URL from the event; selected only under originals access (pkg/adminstore/request_detail.go:217) | request_logs (migrations/0001_init.up.sql:1704) | recorded (may be redacted to `''`) |
| `method` | string (default `POST`) | event `Method` (pkg/gateway/chat.go:1074); scan default at pkg/adminstore/request_detail.go:218 | request_logs (migrations/0001_init.up.sql:1705) | recorded |
| `status_code` | integer (HTTP) | event `StatusCode` (pkg/gateway/chat.go:1071-1072) | request_logs (migrations/0001_init.up.sql:1706) | recorded |
| `duration_ms` | integer, milliseconds | total request wall duration on the event (`DurationMs`, pkg/gateway/chat.go:1073) | request_logs (migrations/0001_init.up.sql:1707) | recorded; a real 0 exists only where a producer writes it (budget-blocked rows use literal 0, services/loggerd/consumer/event_mapper.go:665) |
| `tokens_in`, `tokens_out` | integers | upstream usage accounting on the event | request_logs (migrations/0001_init.up.sql:1708-1709) | recorded |
| `error` | string, `omitempty`; owner/grant/delegation-gated | event `Error` (pkg/gateway/chat.go:1078); column selection CASE (pkg/adminstore/request_detail.go:223) | request_logs (migrations/0001_init.up.sql:1710) | recorded |
| `created_at` | RFC3339 timestamp (raw JSON via `to_jsonb`) | event business time (`created_at`, services/loggerd/consumer/event_mapper.go:602-603; parser at :472) | request_logs (migrations/0001_init.up.sql:1711) | recorded |
| `prompt_hash` | string, `omitempty` | one-way prompt hash on the event | request_logs (migrations/0001_init.up.sql:1714) | recorded |
| `response` | raw JSON (redacted/truncated snapshot), payload-gated | processed response sample; selection CASE (pkg/adminstore/request_detail.go:226) | request_logs (migrations/0001_init.up.sql:1715) | recorded sample, not the full body |
| `upstream_request`, `upstream_response` | raw JSON, **originals-gated** | upstream captures on the event (`UpstreamPayload`/`UpstreamResponse`, pkg/gateway/events.go:221-222); selected only under originals (pkg/adminstore/request_detail.go:227-228) | request_logs (migrations/0001_init.up.sql:1731-1732) | recorded sample |
| `cache_hit_type` | string, `omitempty` (`exact` / `semantic` known values) | cache outcome on the event | request_logs (migrations/0001_init.up.sql:1716) | recorded |
| `counterfactual_cost_usd` | decimal (numeric(12,6) scanned as float64) | cost the un-cached equivalent would have incurred | request_logs (migrations/0001_init.up.sql:1718) | recorded |
| `cost_in_usd` | decimal (numeric(12,6) scanned as float64) | priced usage cost on the event | request_logs (migrations/0001_init.up.sql:1719) | recorded |
| `classifier_class` | string, `omitempty` | classifier outcome (`ClassifierClass`, pkg/gateway/chat.go:1080) | request_logs (migrations/0001_init.up.sql:1720) | recorded |
| `classifier_confidence` | float32, `omitempty` | as above (pkg/gateway/chat.go:1081) | request_logs (migrations/0001_init.up.sql:1721) | recorded |
| `classifier_source` | string, `omitempty` | as above | request_logs (migrations/0001_init.up.sql:1722) | recorded |
| `tier_used` | string, `omitempty` | serving tier on the event (pkg/gateway/chat.go:1079) | request_logs (migrations/0001_init.up.sql:1723) | recorded |
| `ab_group` | string, `omitempty` (`shadow` marks mirror rows) | canary/shadow arm (`ABGroup`, pkg/gateway/events.go:314); shadow rows forced to `shadow` (services/loggerd/consumer/event_mapper.go:634) | request_logs (migrations/0001_init.up.sql:1724) | recorded |
| `task_id` | string, `omitempty` | G2 fields parsed from the event (services/loggerd/consumer/event_mapper.go:113-133, set at :586) | request_logs (migrations/0001_init.up.sql:1728) | recorded |
| `agent_id` | string (uuid), `omitempty` | as above (set at :587) | request_logs (migrations/0001_init.up.sql:1729) | recorded |
| `session_id` | string (uuid), `omitempty` | session resolution in loggerd (column migrations/0001_init.up.sql:1700) | request_logs | recorded |
| `routing_decision` | string (JSON document), `omitempty` | `gateway.decisionJSON` marshals the `routingDecision` struct (pkg/gateway/decision.go:38-96; marshal at pkg/gateway/gateway.go:1911-1921); persisted via loggerd (services/loggerd/consumer/event_mapper.go:588). Payload: `source` (`cache_exact`, `cache_semantic`, `tier_router`, `rule_override`, `passthrough`, `quality_eval`), classifier `class`/`confidence`/`threshold`, session `affinity`/`preferred`, `from`/`to` models, `effort`, canary `arm`/`rollout_id`/`rollout_version`/`canary_percent`, `reason`, `quality_version`, `downgrade`, and `rule` (`DecisionRuleRef`: namespace/id/version captured at match time, pkg/gateway/decision.go:88-98) | request_logs (migrations/0001_init.up.sql:1730) | recorded decision snapshot for this one request |
| `home_region` | string (always present) | database default `current_setting('app.region', true)` at insert time (migrations/0001_init.up.sql:1727); not set by the loggerd projection | request_logs | recorded (log-storage region of the writer, not inference-region provenance) |
| `first_token_ms` | nullable integer (`*int64`), milliseconds | measured in the gateway from request start to the first upstream SSE byte; `0` for non-streaming and streams that died tokenless (documented at pkg/eventpublisher/publisher.go:150-153; assigned e.g. pkg/gateway/stream.go:913); persisted as nullable (services/loggerd/consumer/event_mapper.go:589); scanned as pointer (pkg/adminstore/request_detail.go:242) — null means unknown (legacy row or non-streaming), never a fake 0 | request_logs (migrations/0001_init.up.sql:1733) | recorded; **nullable timing: absent stays absent** |
| `attempt_count` | nullable integer (`*int64`) | `len(attempts)` at completion (pkg/gateway/chat.go:1083, pkg/gateway/stream.go:698, :907); semantics: fallback-chain hops tried, 1 = primary only (pkg/eventpublisher/publisher.go:154-158) | request_logs (migrations/0001_init.up.sql:1734) | recorded summary counter only |
| `retry_count` | nullable integer (`*int64`) | intra-model retries across all hops (pkg/gateway/chat.go:1084; semantics at pkg/eventpublisher/publisher.go:159-162) | request_logs (migrations/0001_init.up.sql:1735) | recorded summary counter only |
| `tool_calls` | array of `tool_name` (always a list) | second query `SELECT tool_name FROM tool_calls WHERE org_id = $1 AND request_id = $2` (pkg/adminstore/request_detail.go:299-302); names extracted by loggerd from the pre-truncation sample (table migrations/0001_init.up.sql:2087) | tool_calls table | recorded; empty list = none recorded |
| `tool_call_invocations` | array of `seq`/`call_id`/`tool_name`/`arguments` (always a list) | third query on `tool_call_invocations` (pkg/adminstore/request_detail.go:320-323; table migrations/0001_init.up.sql:2057); rows exist only for requests logged after the invocation-capture feature landed — earlier requests return an empty list | tool_call_invocations table | recorded |
| `labels` | object (string → string) | attribution labels on the event (services/loggerd/consumer/event_mapper.go:597) | request_logs (migrations/0001_init.up.sql:1741) | recorded |
| `response_view` | object, `omitempty` | `ParseResponseEnvelope(d.Response)` projection of the stored sample (pkg/adminstore/request_detail.go:276, :183); nil for legacy or non-envelope rows | derived at read time from request_logs.response | recorded-derived |

Columns that exist in `request_logs` but are **not selected** by the detail
query (present in storage, absent from this API): `updated_at`
(migrations/0001_init.up.sql:1712), `cache_similarity` (:1717),
`endpoint` (:1736), `usage_source` (:1737), `cost_status` (:1738),
`cache_read_tokens` / `cache_creation_tokens` (:1739-1740), `user_id`,
`api_key_id`, `session_key_id` (:1742-1744; `user_id` is scanned only as the
ownership oracle at pkg/adminstore/request_detail.go:245, :257 and is never
serialized). The request body is not stored at all (PH.1; struct comment
pkg/adminstore/request_detail.go:128-132).

Retention (evident from source): `request_logs` rows are deleted only by the
loggerd retention worker under an enabled team policy, export-before-delete,
with no deletion when no cold destination is configured
(services/loggerd/consumer/retention.go:381-399 and the runOnce pass at :399
onwards; policy surface `OrgRetention` / `ListEnabledTeamRetentionAssignments`
at pkg/adminstore/retention.go:78-108, :217-219). `request_lineage` is
append-only and archive-only (services/loggerd/consumer/retention.go:37-41).
`policy_decisions` rows are purged on a fixed 90-day hot window
(`PolicyDecisionsRetentionDays`,
services/loggerd/consumer/policy_decisions.go:441-442).

Related explorer endpoints (same family, same store):
`GET /api/organizations/{id}/requests` list served by `apiOrgRequests` →
`Store.ListRequests` (services/admin/handlers/request_list.go:305;
pkg/adminstore/request_list.go:286) returns a subset per row
(`RequestListRow`, pkg/adminstore/request_list.go:74-105) and
`GET .../requests/stats` served by `apiOrgRequestStats` → `Store.RequestStats`
(services/admin/handlers/request_list.go:342) returns the aggregate block
(`RequestListStats`, pkg/adminstore/request_list.go:108 area) over the same
filters (shared parser `parseRequestListFilters`,
services/admin/handlers/request_list.go:233).

## (c) Provider health aggregates

Chain: `getProviderHealth` (web/dashboard/src/api/routing.ts:93) calls
`GET /api/providers/health?org_id=&period=` (registered
services/admin/handlers/router_models.go:57) and is served by
`AdminHandlers.ProviderHealth` (services/admin/handlers/provider_health.go:60),
gated by `requireOrgRead` with `PermAnalyticsRead`
(services/admin/handlers/routing_map.go:29-45). The `period` param is resolved
by `parseHealthPeriod` (services/admin/handlers/provider_health.go:30-56):
presets `1h`, `24h`, `1d`, `7d`, `30d` or any Go duration string, default
`24h`, hard-capped at 90 days (`maxProviderHealthPeriod`, :19). The store
method is `Store.GetProviderHealth` (pkg/adminstore/provider_health.go:55),
one aggregate query over `request_logs` (SQL at
pkg/adminstore/provider_health.go:59-76), folded by `groupProviderHealth`
(pkg/adminstore/provider_health.go:97-137).

This is **recorded/observed** data with these dimensions and metrics:

| JSON field | Kind / units | Producer (file:line) | Scoping actually applied | Data class |
| --- | --- | --- | --- | --- |
| `org_id`, `period`, `from`, `to` | scope echo; `from`/`to` RFC3339, window is `[from, to)` | handler envelope (services/admin/handlers/provider_health.go:87-93) | org gate `PermAnalyticsRead`; window from `parseHealthPeriod` | observed-scope metadata |
| `providers[].provider` | string | `COALESCE(mr.provider, '')` from `LEFT JOIN models_registry mr ON mr.model_name = rl.model_used` (pkg/adminstore/provider_health.go:60, :70); empty folds to `"unknown"` (pkg/adminstore/provider_health.go:101-104) | `WHERE rl.org_id = $1::uuid AND rl.created_at >= $2 AND rl.created_at < $3` (:71-73) — org- and time-scoped | recorded counts under a **current-configuration provider attribution** (see guardrails) |
| `providers[].requests` / `models[].requests` | integer count of request_logs rows | `COUNT(*)` (pkg/adminstore/provider_health.go:62) | org/time window; shadow traffic excluded (`AND COALESCE(rl.ab_group, '') <> 'shadow'`, :74) | recorded |
| `providers[].errors` / `models[].errors` | integer count | `SUM(CASE WHEN rl.status_code >= 400 ...)` (pkg/adminstore/provider_health.go:63) | same | recorded |
| `providers[].error_rate` / `models[].error_rate` | fraction 0..1 | `safeRate(errors, total)` (pkg/adminstore/provider_health.go:140-145) | same | recorded-derived |
| `models[].model` | string | `rl.model_used` group key (pkg/adminstore/provider_health.go:61, :75) | same | recorded |
| `models[].p50_ms`, `models[].p95_ms` | milliseconds | `PERCENTILE_CONT(0.50/0.95) WITHIN GROUP (ORDER BY rl.duration_ms)` (pkg/adminstore/provider_health.go:64-65) | same | recorded-derived |
| `models[].last_error`, `models[].last_error_at` | string, nullable timestamp | `MAX(rl.created_at) FILTER (WHERE rl.status_code >= 400)` and the most recent error text by `created_at` (pkg/adminstore/provider_health.go:66-68) | same | recorded |

What this aggregate does **not** contain, relative to a full
client → requested model → chosen model → provider flow: no client/agent/user
dimension (no `user_id`, `agent_id`, `task_id` group keys), no
`model_requested` dimension (only `model_used`), therefore no
requested-to-chosen edges; no attempt or retry measures (those columns exist
per row but are not selected here); no cache/classifier splits, no token or
cost metrics, no coverage/unknown counts. The provider attribution also joins
the **current** registry at query time (models can be re-filed under a
different provider after the fact; a model missing from the registry lands in
`"unknown"`).

## (d) Absent producers (evidence from source)

1. **Per-attempt spans do not exist.** The complete migrations set contains no
   attempt/span table: the only `attempt` occurrences are the
   `request_logs.attempt_count` / `retry_count` summary columns
   (migrations/0001_init.up.sql:1734-1735) and queue-machinery columns on
   unrelated job tables (`attempts` / `next_attempt_at`,
   migrations/0001_init.up.sql:195, :1930, :2149; migrations/0006_batch_files.up.sql:46-47).
   The gateway producers emit only totals (`AttemptCount: len(attempts)`,
   `RetryCount: totalRetries` — pkg/gateway/chat.go:1083-1084,
   pkg/gateway/stream.go:698-699, :907-908), carried as scalars through
   pkg/gateway/events.go:319-320 and
   pkg/eventpublisher/redis_publisher.go:249-251, and persisted as nullable
   scalars (services/loggerd/consumer/event_mapper.go:589-591). The detail
   struct exposes only those pointers
   (`FirstTokenMs`/`AttemptCount`/`RetryCount *int64`,
   pkg/adminstore/request_detail.go:163-168) — no per-attempt identifiers,
   ordinals, timings, outcomes or provider-per-attempt exist anywhere in the
   persisted schema.
2. **No full flow aggregation producer.** The provider-health query groups
   only by `(models_registry.provider, rl.model_used)`
   (pkg/adminstore/provider_health.go:59-76). There is no server-side
   aggregate keyed by client → `model_requested` → `model_used` → provider in
   this endpoint; a Sankey over those stages cannot be sourced from it.
3. **Region provenance beyond `home_region` is not in the request record.**
   The rich region fields (`inference_region`, `region_evidence`,
   `model_origin_country`, `log_storage_region`,
   `provider_entity_jurisdiction`) exist on the gateway **event**
   (pkg/eventpublisher/publisher.go:137-146) and are persisted in the separate
   `request_lineage` table (migrations/0001_init.up.sql:1653-1672; writers
   pkg/lineage/outbox.go:208, pkg/lineage/ledger.go:79), which is append-only,
   archive-only (services/loggerd/consumer/retention.go:37-41) and readable
   only through the separately permissioned lineage routes
   (`GET /api/lineage/{request_id}`, `GET /api/organizations/{id}/lineage`,
   services/admin/handlers/router_analytics.go:48-51; store
   pkg/adminstore/lineage.go:13, :36, :78). `RequestDetail`
   (pkg/adminstore/request_detail.go:133-184) has no lineage field, and the
   detail query never touches `request_lineage`.
4. **Policy step records are not part of request detail.** Per-policy-step
   records exist — table `policy_decisions` with a `request_id` join column
   (migrations/0001_init.up.sql:1444-1460), written by loggerd
   (`StreamConsumer.insertPolicyDecision`,
   services/loggerd/consumer/policy_decisions.go:403) from the event's
   `policy` JSON array (pkg/eventpublisher/publisher.go:175-199) and served by
   the separately mounted decision-log routes
   (services/admin/handlers/policy_decisions.go:65 onwards) — but
   `RequestDetail` has no policy field and the detail query does not select
   from `policy_decisions`. Only the summarized `routing_decision` document
   travels with the row. Note also the 90-day purge window
   (services/loggerd/consumer/policy_decisions.go:441-442): joining old
   requests to policy steps can legitimately find nothing.

## (e) Semantics guardrails

- **Configuration edges are never recorded traffic.** Every field in section
  (a) is configuration-time; `warnings` are computed per read
  (`computeRoutingWarnings`, pkg/adminstore/routing_map.go:156). A configured
  failover/fallback edge expresses a possibility; no request ever traversed it
  in this payload. The existing graph module already enforces this split
  (web/dashboard/src/lib/routingGraph.ts:3-14) and its tests must keep
  passing; any visualizer that renders both must keep an explicit
  configured/observed mode (V16 boundary).
- **Unknown is not zero.** `first_token_ms`, `attempt_count`, `retry_count`
  are nullable pointers (pkg/adminstore/request_detail.go:163-168): null means
  unknown (legacy row, non-streaming request), and the API must not render it
  as 0 ms or 1 attempt. Empty `tool_calls` / `tool_call_invocations` lists
  mean "none recorded", a positive fact, not missing data. Conversely, an
  empty `rules` array is a confirmed zero (the org configured no rules), not
  an unknown. A real numeric zero appears only where a producer wrote one
  (e.g. `duration_ms` literal 0 for budget-blocked rows,
  services/loggerd/consumer/event_mapper.go:665).
- **Logical requests are rows; attempts are counters.** One `request_logs` row
  is one logical request (including failed and budget-blocked projections).
  Shadow traffic creates additional mirror rows discriminated by
  `ab_group = 'shadow'` (services/loggerd/consumer/event_mapper.go:611-641);
  recorded aggregates exclude them explicitly
  (pkg/adminstore/provider_health.go:74). Attempt volume exists only as
  `attempt_count` / `retry_count` scalars per row: attempts must never be
  counted as rows, and summing counters across rows estimates attempt volume
  without any per-attempt detail.
- **Provider attribution in health is a current-config join.** The provider
  column comes from joining `models_registry` at query time
  (pkg/adminstore/provider_health.go:70): re-filing a model under a different
  provider retroactively moves historical counts; models absent from the
  registry fall into `"unknown"`. Flow views must not present this as
  recorded-at-request-time provenance.
- **Credentials and payloads are never labels.** The routing map excludes
  `upstream_url` / `upstream_api_key` by construction
  (pkg/adminstore/routing_map.go:13-15); payload columns in detail are
  grant-gated and redacted (pkg/adminstore/request_detail.go:217-228). Graph
  labels, node text and warning messages render operator-controlled names,
  never key material, credentials or payload content.
- **Timing that is absent stays absent.** Per-attempt timing does not exist
  (section (d) item 1); TTFT and total duration are the only timing fields,
  and TTFT itself is nullable. A waterfall of attempts cannot be derived from
  summary counters and must wait for the reviewed CV-03 contract.
