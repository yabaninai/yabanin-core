# Visualizer field provenance inventory

Task slice: **CV-00-02** (visualizer family; successor inventory to
[field-matrix.md](field-matrix.md), CV-00-01). Audited at product TASK_BASE
`243ab5b34d04ba0e83fb10df7b206f88e42629d7`, branch `task/cv00-02`. All
`file:line` citations in this document resolve to the named symbols at that
revision. The Go package under `pkg/gateway` declares the historical package
identifier `cli` (pkg/gateway/gateway.go:1); symbols are cited by file path
regardless of package name.

Method: backend-first provenance. For each of the six families (attempt,
tool, policy, region, price/cost, aggregate) the chain is traced from the
**producer** (the gateway statement that originates the value) through the
**wire** (the Redis eventpub field map) to **persistence** (the loggerd
projection and the physical column, with its DDL default) and finally to the
**read views** (admin store query, handler, route). The inventory is derived
from producers and migrations alone, independent of any frontend type; a
frontend module is never the authority for what a field means. Absence claims
are negative controls: each cites the exhaustive search that established the
absence.

## (a) Attempt family

Fields: `first_token_ms`, `attempt_count`, `retry_count` on the request
record; derived read-side metrics `retried_requests`, `fallback_requests`.

| Stage | Where (file:line) | Fact |
| --- | --- | --- |
| Event fields | `eventBase.FirstTokenMs` / `.AttemptCount` / `.RetryCount` (pkg/gateway/events.go:237, :235, :236) | scalars per request; semantics documented on the wire struct (pkg/eventpublisher/publisher.go:150-153 TTFT, :155-158 fallback-chain hops, :159-162 intra-model retries) |
| Producers (totals only) | chat pipeline: failure pkg/gateway/chat.go:1083-1084, success :1588-1589, policy-denied :1712-1713; stream pipeline: pkg/gateway/stream.go:698-699, :907-908, :1392-1393, :1503-1504 | `AttemptCount: len(attempts)`, `RetryCount: totalRetries`; `totalRetries` declared at pkg/gateway/chat.go:807 and accumulated per attempt (`totalRetries += attemptNum - 1`, pkg/gateway/chat.go:944); the `attempts` slice comes from the fallback executor (`executeFallback`, pkg/gateway/gateway_policy.go:300) |
| Wire | Redis field map `attempt_count` / `retry_count` (pkg/eventpublisher/redis_publisher.go:250-251) | plain stringified integers |
| Persistence | bound in the full projection via `nullableInt64` (services/loggerd/consumer/event_mapper.go:589-591; helper :755 — absent **or zero** binds SQL NULL); columns `first_token_ms` (migrations/0001_init.up.sql:1733), `attempt_count integer DEFAULT 1` (:1734), `retry_count integer DEFAULT 0` (:1735) | nullable scalars; the DDL defaults never fire for full rows because the projection always binds explicitly (NULL or value) — they fire only for the reduced projections below |
| Reduced projections | shadow mirror `shadowRequestLogRow` (services/loggerd/consumer/event_mapper.go:612) and budget-blocked `budgetRequestLogRow` (:656) omit all three keys | these rows carry **no attempt observability**: the omitted columns fall back to the DDL defaults (`attempt_count` 1, `retry_count` 0, `first_token_ms` NULL) |
| Read views | request detail SELECT + nullable pointers (pkg/adminstore/request_detail.go:264 scan; struct :166-168); request list row (pkg/adminstore/request_list.go:329; struct :89-91); analytics raw metrics `retried_requests` = `retry_count > 0`, `fallback_requests` = `attempt_count > 1` (pkg/adminstore/analytics_query_sql.go:29-30); rollup columns (services/loggerd/consumer/rollup.go:76-79) | null means unknown (legacy row, non-streaming request), never 0 ms / 1 attempt; the derived counters are row counts filtered on the stored scalars |

## (b) Tool family

Fields: `tool_calls` rows (one per distinct tool name per request),
`tool_call_invocations` rows (`seq`, `call_id`, `tool_name`, `arguments`),
and the tool-policy gate that can deny a call before it is made.

| Stage | Where (file:line) | Fact |
| --- | --- | --- |
| Sample capture | the upstream response sample rides the event (`eventBase.UpstreamResponse`, pkg/gateway/events.go:222) | pre-truncation raw sample; the gateway's tool-policy gate runs on the live JSON, not on this sample |
| Policy gate | `gateToolCallsJSON` (pkg/gateway/toolgate.go:47), SSE wrapper `sseToolGateWriter` (:182), rule match `policyDeniesTool` (:507), denial event `publishToolPolicyDenial` (:539); namespace constant `ruleNamespaceToolPolicy = "tool-policy"` (pkg/gateway/gateway_policy.go:1019); counter `ToolPolicyDeniedTotal` (pkg/gateway/toolgate.go:83, :93, :302, :414, :515) | a denied call is recorded as a **policy decision** (see (c)), never as a `tool_calls` row |
| Persistence gate | loggerd binds `ev.upstreamResponse` **only** under explicit org originals retention (services/loggerd/consumer/event_mapper.go:418 `retainOriginal`; the default-off contract is stated at :425) | with retention off the sample stays empty, so no tool rows are extracted — see negative control NC6 |
| Extraction | `extractToolCallNames` (services/loggerd/consumer/tool_calls.go:25) → `insertToolCalls` (:118, `INSERT INTO tool_calls` :130); `extractToolCallInvocations` (services/loggerd/consumer/tool_call_invocations.go:33) with per-call argument cap `maxInvocationArgsChars = 2000` (:14); fail-soft call site inside the log transaction (services/loggerd/consumer/stream.go:1062) | a tool-extraction failure never breaks the request log |
| Tables | `tool_calls` (migrations/0001_init.up.sql:2087), `tool_call_invocations` (:2057); both carry `request_id` + `org_id` | org-scoped by construction; invocation `arguments` are secrets-scrubbed (`ScrubSecrets`) then truncated at the 2000-char cap before insert |
| Read views | request detail second/third queries (pkg/adminstore/request_detail.go:300, :321; struct :172, :176); request list correlated org-scoped subquery (pkg/adminstore/request_list.go:330); org report `GetToolCallsReport` (pkg/adminstore/tool_calls.go:36) → `apiOrgToolCalls` (services/admin/handlers/request_list.go:406) → `GET /api/organizations/{id}/tool-calls` (services/admin/handlers/router_analytics.go:60) | empty list = none recorded (positive fact); the list subquery is org-scoped twice (`tc.org_id = rl.org_id`) so mirror rows of a foreign org can never leak names |

## (c) Policy family

Fields: the `routing_decision` JSON document on the request row; the `policy`
JSON array on the event (OP-8), persisted one row per decision into
`policy_decisions` (OP-9).

| Stage | Where (file:line) | Fact |
| --- | --- | --- |
| Decision document | `routingDecision` wire struct (pkg/gateway/decision.go:38) with the rule-identity triple `DecisionRuleRef` (:94); marshalled by `decisionJSON` only when decision events are enabled (pkg/gateway/gateway.go:1911) | compact per-request snapshot: source, classifier class/confidence/threshold, affinity, from/to, effort, canary arm/rollout, reason, downgrade, rule ref |
| Policy events | `appendPolicyEvents` / `policyEventFrom` (pkg/gateway/gateway_policy.go:1320, :1356); stamped on the event at pkg/gateway/chat.go:1305, :1356, :1592, :1716 and the stream pipeline's `streamPolicyJSON()` at pkg/gateway/stream.go:701, :910, :1395, :1508; generic namespace `ruleNamespacePolicy` (pkg/gateway/gateway_policy.go:1018) | JSON array of decision objects carried as `eventBase.Policy` (pkg/gateway/events.go:251) |
| Wire→row | parsed by `parsePolicyDecision` (services/loggerd/consumer/policy_decisions.go:149) into `policyDecisionWire` (:121); content evidence is stripped on the wire struct (`Evidence string json:"-"`, :105) | findings never persist content evidence, only vocabulary |
| Persistence | `insertPolicyDecision` (services/loggerd/consumer/policy_decisions.go:403) inside the **same delivery transaction** as the request log (call sites services/loggerd/consumer/stream.go:643, :733, :843, :1066); table `policy_decisions` with mode/verdict CHECKs (migrations/0001_init.up.sql:1444) and `FORCE ROW LEVEL SECURITY` (:1462); hot window 90 days (`PolicyDecisionsRetentionDays`, services/loggerd/consumer/policy_decisions.go:442) | columns: `org_id`, `request_id`, `policy_id`, `policy_version`, `mode` (shadow/enforce), `verdict`, `findings jsonb`, `duration_ms` |
| Read views | decision log: `ListPolicyDecisions` (pkg/adminstore/policydecisions.go:95) → `GET /api/organizations/{id}/policy-decisions` (mount services/admin/handlers/policy_decisions.go:67, handler :345; mount point services/admin/handlers/router.go:713). Routing side: `routing_decision` column (migrations/0001_init.up.sql:1730) exposed in request detail (field pkg/adminstore/request_detail.go:161, scanned :264) and usable **only as a filter** in the list (`RuleID`, pkg/adminstore/request_list.go:151) | the request detail struct has no policy field — the decision log is a separate, separately permissioned surface (field-matrix.md §(d) item 4) |

## (d) Region family

Fields: `home_region` on the request row; the lineage attestation fields
`inference_region`, `model_origin_country`, `log_storage_region`,
`provider_entity_jurisdiction` (+ `region_evidence`).

| Stage | Where (file:line) | Fact |
| --- | --- | --- |
| Resolver | `attachLineage` (pkg/gateway/lineage.go:21) resolves the winning hop via `ResolveInferenceRegionWithEvidence` (:31) and stamps the event fields (pkg/gateway/lineage.go:79; fields at pkg/gateway/events.go:264-267); call site pkg/gateway/events.go:490 | inputs: `provider_jurisdictions.default_inference_region` (migrations/0001_init.up.sql:1608; seeded migrations/0005_cloud_providers.up.sql:24), `models_registry.model_origin_country` (migrations/0001_init.up.sql:1107), org default from `org_home_region` (table migrations/0001_init.up.sql:1224; accessor pkg/adminstore/region.go:24) |
| Persistence (request row) | `home_region text DEFAULT current_setting('app.region', true) NOT NULL` (migrations/0001_init.up.sql:1727) — set by the **database default**, not by any projection statement | it is the log-storage region of the writer, not inference-region provenance |
| Persistence (lineage) | outbox row `INSERT INTO lineage_outbox` (pkg/lineage/outbox.go:90; DDL migrations/0001_init.up.sql:817, nullable region columns :822) → relay → `INSERT INTO request_lineage` (pkg/lineage/outbox.go:208; DDL migrations/0001_init.up.sql:1653 with NOT NULL region columns :1659, hash-chain columns, indexes :4252 and :4560) | append-only, archive-only: the retention worker copies expired rows to cold storage and never deletes hot ones (services/loggerd/consumer/retention.go:37, :219) |
| Read views | `GET /api/lineage/{request_id}` and `GET /api/organizations/{id}/lineage` (handler services/admin/handlers/lineage.go:93, :132; store `GetLineageByRequestID` pkg/adminstore/lineage.go:13, `ListLineageByOrgFiltered` :36); `home_region` in request detail (struct pkg/adminstore/request_detail.go:162) | the rich fields are readable **only** through the lineage routes; request detail and analytics never select them (negative control NC3) |
| Aggregates | `home_region` is part of the rollup identity: `analytics_rollup_hourly` (migrations/0001_init.up.sql:302) and `label_rollup_hourly` (:774) | rollup rows are per-region partitions; region is an identity key, not a served analytics dimension |

## (e) Price / cost family

Fields: `estimated_cost_usd` (persisted as `cost_in_usd`),
`counterfactual_cost_usd`, `resale_cost_usd` (event-only),
`usage_source`, `cost_status`, `cache_read_tokens`,
`cache_creation_tokens`.

| Stage | Where (file:line) | Fact |
| --- | --- | --- |
| Price inputs | offline embedded catalog via `pricing.DefaultLookup` (pkg/pricing/interface.go:106; embedded bytes + sha256 provenance pkg/pricing/provenance.go:10, :38); DB side: `models_pricing` (migrations/0001_init.up.sql:1049) materialized from the promoted rates-catalog state (deployment-global activation record, migrations/0019_rates_catalog_state.up.sql:4) and read by `DBPricer` (pkg/pricing/db_pricer.go:31, :39; wired at services/run/admin.go:307) | two durable price sources: bundled pack (genesis) and promoted catalog (DBPricer, TTL-bounded propagation) |
| Cost compute | `ComputeCost` (pkg/provider/usage.go:54): local runtime providers fail closed (`PriceKnown=false`, :55); cache tokens billed at their own rates; usage-source constants `provider`/`estimated`/`none` (:89) | unknown price is a status, never a fabricated 0 |
| Statuses | `usageSourceOrNone` / `costStatus` / `costStatusUnit` (pkg/gateway/cost_status.go:8, :15, :33); event fields `EstimatedCostUSD`/`ResaleCostUSD`/`CounterfactualCostUSD`/`UsageSource`/`CostStatus` (pkg/gateway/events.go:210-214) | cost_status vocabulary is CHECK-constrained in storage (migrations/0001_init.up.sql:1745) |
| Counterfactual | `effectiveCounterfactual` prices the routing baseline when a classifier tier move happened, else passes the actual cost through (pkg/gateway/chat.go:1759) | "what the un-routed request would have cost" |
| Resale | `resaleCostUSD` (pkg/gateway/events.go:365) computed per request via the markup pricer (`Quote`, `ComputeResaleAmount`, override lookup over `reseller_pricing` — pkg/pricing/markup.go:91, :179, :190, :208; rules table migrations/0001_init.up.sql:1775); stamped at pkg/gateway/chat.go:1425/:1580 and the stream drain paths pkg/gateway/stream.go:1352/:1383, :1469/:1496 | the org-facing charge, distinct from base cost |
| Persistence | full projection binds `cost_in_usd` ← event `estimated_cost_usd` and `counterfactual_cost_usd` (services/loggerd/consumer/event_mapper.go:382-383); accounting defaults `endpoint='chat.completions'`, `usage_source='provider'`, `cost_status='legacy'` (:104-106); columns `counterfactual_cost_usd` (migrations/0001_init.up.sql:1718), `cost_in_usd` (:1719), `usage_source` (:1737), `cost_status` (:1738), `cache_read_tokens`/`cache_creation_tokens` (:1739-1740, bound via `nullableInt64` services/loggerd/consumer/event_mapper.go:595-596) | **`resale_cost_usd` is not persisted in `request_logs`** — see negative control NC2 |
| Resale consumer | wallet charge only: `resaleDeductionMicro` at both completion projections (services/loggerd/consumer/stream.go:689, :1028); semantics documented at services/loggerd/consumer/settlement.go:28 (resale wins over base for the `resale_deduction` charge kind, services/loggerd/consumer/stream.go:109) | settlement/budget side effect, never an admin read field |
| Read views | request detail `counterfactual_cost_usd`/`cost_in_usd` (pkg/adminstore/request_detail.go:151-152, scanned :262); list stats `TotalCostUSD` (pkg/adminstore/request_list.go:381); analytics `cost_usd` (FILTER `cost_status IN ('priced','cache_hit','legacy')`), `unpriced_requests` (`'unknown_price','no_usage'`), `cost_per_request` (pkg/adminstore/analytics_query_sql.go:26-27, :34); cost report SUMs + pricing-as-of/coverage metadata (pkg/adminstore/cost_analytics.go:62, :156, :168); savings report (pkg/adminstore/savings.go:199-200) | $0-unknown is kept distinct from $0-free by the status filters; coverage is measured against current price sources and says so |

## (f) Aggregate family

Fields: hourly rollup sums, derived ratios, and the percentile family
(`latency_p50/p95`, `ttft_p50/p95`, list `p95`, health `p50/p95`, stats
`p50/p90/p95/p99`).

| Stage | Where (file:line) | Fact |
| --- | --- | --- |
| Rollup producer | `RollupRefresher` (services/loggerd/consumer/rollup.go:55), advisory lock `rollupLockID 18018` (:21), recent-window refresh cadence (:24); `INSERT INTO analytics_rollup_hourly` (:76) and `INSERT INTO label_rollup_hourly` (:97, :116) | additive columns only: requests, tokens, errors, `retried_requests`, `fallback_requests`, cache hits, cost |
| Rollup tables | `analytics_rollup_hourly` (migrations/0001_init.up.sql:301, identity includes `home_region` :302), `label_rollup_hourly` (:773, :774) | pre-aggregated per hour × org × model × endpoint × team × agent × status_class × cache_type (× label key/value) |
| Source selection | `analyticsSource` (pkg/adminstore/analytics_query_sql.go:243): rollups apply only with an empty filter, additive metrics (map :208), known dimensions (map :224) and a calendar granularity — anything else falls back to raw | the source is a **derived property of the query**, not a stored fact about the data |
| Raw-only metrics | percentile family in the raw metric map: `latency_p50/p95` over `duration_ms`, `ttft_p50/p95` over `first_token_ms` (pkg/adminstore/analytics_query_sql.go:35-38); list stats p95 (pkg/adminstore/request_list.go:391, func :381); provider health p50/p95 (pkg/adminstore/provider_health.go:64-65, struct :36); request stats p50/p90/p95/p99 (pkg/adminstore/request_stats.go:216-219, struct :210) | **no percentile is ever served from a rollup** — negative control NC4 |

## (g) Negative controls (evidence from source)

Each control states the exhaustive search that established the absence.

1. **NC1 — no per-attempt storage exists.**
   `grep -rni attempt migrations/*.sql` returns only the request summary
   columns (`attempt_count`/`retry_count`, migrations/0001_init.up.sql:1734-1735)
   and delivery-queue counters on unrelated job tables (`attempts` on
   `admin_audit_outbox` :195, `settlement_jobs` :1930,
   `webhook_deliveries` :2149, `batch_jobs` migrations/0006_batch_files.up.sql:46);
   no `INSERT INTO` statement in the Go tree targets any attempt journal.
   The gateway emits only the two totals (§a). Per-attempt identifiers,
   ordinals, timings, outcomes and provider-per-attempt do not exist in the
   persisted schema.
2. **NC2 — `resale_cost_usd` is not persisted and has no admin read view.**
   `grep -rni resale migrations/*.sql` finds no column (the only durable
   resale object is the **rules** table `reseller_pricing`,
   migrations/0001_init.up.sql:1775, managed through
   pkg/adminstore/resale_pricing.go). The event field is parsed
   (services/loggerd/consumer/event_mapper.go:436) but consumed solely by the
   settlement/wallet path (services/loggerd/consumer/stream.go:689, :1028).
   No adminstore SELECT mentions it: a visualizer cannot show per-request
   resale cost from today's schema.
3. **NC3 — lineage region fields are not in the request record.** The
   `request_logs` column list (migrations/0001_init.up.sql:1698 onwards)
   contains exactly one region column, `home_region` (:1727).
   `inference_region` / `model_origin_country` / `log_storage_region` /
   `provider_entity_jurisdiction` exist only on `lineage_outbox`
   (migrations/0001_init.up.sql:822) and `request_lineage` (:1659), and a
   search of `pkg/adminstore`/`services/admin` for those names matches only
   `lineage.go` and tests. Request detail, request list and analytics never
   select them; the lineage routes (§d) are the only surface.
4. **NC4 — percentiles are never served from rollups.**
   `grep -ni 'percentile\|_p50\|_p95' migrations/0001_init.up.sql` returns
   nothing: no rollup (or any) table stores a percentile. The rollup metric
   map (pkg/adminstore/analytics_query_sql.go:208) contains no percentile
   keys, so any query asking for one fails the `analyticsSource` additive
   test (:243) and runs raw; `percentile_cont` appears only in the raw-path
   files (analytics_query_sql.go, provider_health.go, request_list.go,
   request_stats.go).
5. **NC5 — shadow and budget rows carry no attempt observability.** The
   shadow projection (services/loggerd/consumer/event_mapper.go:612) and the
   budget-blocked projection (:656) omit `first_token_ms`, `attempt_count`
   and `retry_count` entirely; those rows inherit the DDL defaults (1 / 0 /
   NULL). Attempt aggregates computed over all rows silently include these
   nominal values; filter `ab_group <> 'shadow'` as the health query does
   (pkg/adminstore/provider_health.go:74) and remember budget rows cannot be
   distinguished by attempt columns at all.
6. **NC6 — tool rows cannot exist without originals retention.** The sample
   that feeds `insertToolCalls` is bound only under `retainOriginal`
   (services/loggerd/consumer/event_mapper.go:418; contract comment :425:
   with retention off "the tool-call arguments derived from them never reach
   the durable write"). Empty `tool_calls` on an org with retention off means
   **structurally none**, not "not captured this time".

## (h) Cross-family guardrails

- **Unknown is not zero.** Nullable scalars (`first_token_ms`,
  `attempt_count`, `retry_count`, cache token columns) mean unknown when
  NULL; the cost status vocabulary exists precisely to keep $0-unknown
  (`unknown_price`, `no_usage`) distinct from $0-free
  (pkg/adminstore/analytics_query_sql.go:26-27). Render unknowns as unknown.
- **Defaults are facts about the writer, not the request.** Three layers of
  defaults exist: mapper fallbacks (`endpoint`, `usage_source`,
  `cost_status` — services/loggerd/consumer/event_mapper.go:104-106), the
  `home_region` database default (writer region,
  migrations/0001_init.up.sql:1727), and DDL attempt defaults that fire only
  for reduced projections (NC5). A visualizer must not present a defaulted
  value as an observed one.
- **Forced literals stay visible.** The budget-blocked projection forces
  `model_used=''`, `method='POST'`, `duration_ms=0`, `tokens_in/out=0`,
  `status_code=429` and prefixes the error `budget_exceeded:`
  (services/loggerd/consumer/event_mapper.go:656 onwards); the shadow
  projection forces `ab_group='shadow'` (:634) and NULLs the cache and
  classifier columns. These rows are real rows with synthetic content —
  budget rows must never be charted as latency or token observations.
- **Same-transaction guarantees.** Policy decision rows commit in the same
  delivery transaction as the request row
  (services/loggerd/consumer/stream.go:643, :733, :843, :1066): a request row
  without its policy row was not lost in transit — the event carried no
  decision, or the row is older than the 90-day hot window
  (services/loggerd/consumer/policy_decisions.go:442).
- **Rollups trade detail for speed, and say so.** Rollup-served queries are
  additive-only over calendar buckets with empty filters
  (pkg/adminstore/analytics_query_sql.go:243); anything filtered, sampled or
  percentile-shaped is computed from raw `request_logs`. Surfaces should
  expose which source served a number (`raw` vs `rollup`), matching
  `analyticsPublicSource`.
- **Resale is a wallet fact, not an analytics fact.** The per-request resale
  price exists only on the event and in settlement jobs (NC2); base cost
  (`cost_in_usd`) is the only per-request cost an analytics surface may
  chart. Resale **rules** (markup percents, fixed per-M rates) are
  configuration and belong to a configuration view, never merged into
  recorded traffic.

This inventory covers the six families at the audited revision; the frozen
twenty-view matrix and producer-gap assignments are follow-up slices and are
not pre-decided here.
