# Producer-gap child assignments — backend leaves bound to real sources

Task: CV-00-04 (`plans/CORE.md`), frozen at product base
`6da73e63ec580812204a8e01bd07e9fc3f2e3954` (branch `task/cv00-04`).

This document enumerates the producer gaps implied by
`docs/visualizers/view-contract-matrix.md` (CV-00-03) and publishes a bounded
child-assignment draft for each gap that does not already own a planned leaf.
Rules obeyed throughout:

1. **No invented endpoint names.** Every backend surface named here is a real
   registered route, handler, store function or column verified at the frozen
   base, cited `path:line`. Where no producer exists the document says
   **"no producer; new contract leaf required"** and names nothing.
2. **Reuse accepted scope.** Gaps whose producer leaf is already planned in
   `plans/CORE.md` (CV-03a/b for attempts, CV-04a/b for flow aggregation) get
   a binding addendum with the verified today-inventory, not a duplicate leaf.
3. Every draft follows the `V06-D` child idiom (view id + kind suffix) and
   stays inside the 4h child bound; ids marked *suggestion* are allocated by
   the owner in `plans/CORE.md`, not by this document.
4. Contract questions use the frozen matrix grammar: **UNITS**, **IDENTITY**,
   **COVERAGE**, **MISSING-STATE** (plus retention where it shapes the
   contract), as defined in `view-contract-matrix.md` §1.

Inputs: the three frozen CV-00 documents (`field-matrix.md` CV-00-01,
`field-provenance.md` CV-00-02, `view-contract-matrix.md` CV-00-03) and the
verified source tree at the frozen base. Section 6 records the mechanical
verification.

---

## 1. Selection rule

A **producer gap** is a fact a bound view or planned visualizer view needs
where the CV-00 freeze already established that no serving producer exists, or
that the only serving producer cannot carry the view's frozen contract. The
gap register below is the closure of three verified inputs:

- `field-matrix.md` §(d) "Absent producers (evidence from source)" — items 1–4
  (per-attempt spans, full flow aggregation, region provenance, policy steps
  outside request detail).
- `field-provenance.md` negative controls NC1–NC6 (attempts, resale cost,
  region fields, rollup percentiles, shadow/budget observability,
  originals-retention gate on tool rows).
- `view-contract-matrix.md` per-view COVERAGE/MISSING-STATE admissions that
  name absent producers or absent cross-surface joins (V-12 tool calls
  "absence is absence", V-17 exports "no delivery signal", §7 retention
  under-reporting residual).

Views fed exclusively by existing surfaces (configuration topology, request
explorer detail, feedback, audit log, credits, rates, models) raise no gap and
appear here only as consumers.

## 2. Gap register

| # | Gap | Consumers (planned views) | Today's exact surface | Disposition |
| --- | --- | --- | --- | --- |
| G1 | Full traffic-flow aggregation (client/agent → requested → chosen → provider) with provider attribution and covered/unknown counts | V02, V06, V09, V13, V16 | Partial: analytics query engine dims (no provider dim); provider health groups `(provider, model_used)` only | Binding addendum → planned CV-04a/CV-04b (§3.1) |
| G2 | Per-attempt records (ids, ordinals, timings, outcomes, per-attempt provider) | V03, V04, V10, V14, V18 | **No producer; new contract leaf required** — summary scalars only | Binding addendum → planned CV-03a/CV-03b (§3.2) |
| G3 | Latency/cost distribution: histogram, sketch or bounded paired samples | V07, V08, V17 | Partial: percentile aggregates only (p50/p90/p95/p99 family); per-request rows bounded 25/page | **New child assignment** `V07-P` (§4.1) |
| G4 | Region/destination provenance per recorded request (observed vs configured vs unknown) | V12 | Partial: endpoint dim in analytics; rich region fields only on separately permissioned lineage routes | **New child assignment** `V12-P` (§4.2) |
| G5 | Policy steps joined to the request journey (link, permission alignment, retention mismatch) | V03, V11 | Partial: policy-decision log exists with steps + request_id filter; not part of request detail; 90-day purge | **New child assignment** `V11-P` (§4.3) |
| G6 | Tool execution outcome, timing and parentage beyond per-request occurrences | V05, V15, V18 | Partial: per-request invocations in request detail (no outcome/duration/span); 30d cross-request aggregates | **New child assignment** `V05-P` (§4.4) |
| G7 | Hot-row retention coverage signal for a queried window (under-reporting honesty) | V06, V10, V13, V17; matrix V-10/V-11 | **No producer; new contract leaf required** — pricing coverage only; retention config not surfaced per query | **New child assignment** `V06-P` (§4.5) |
| G8 | Receiver delivery outcomes and an admin read for WORM lineage export | matrix V-17 (exports page) | Partial: spend-alert settings only, `last_alert_at` as the sole delivery signal; WORM export is trcli-only | **New child assignment** `EXP-P` (§4.6; id pending owner allocation) |

Gaps deliberately **not** drafted are in §5 with reasons (Enterprise-owned
producers, wallet facts, by-design absence).

## 3. Binding addenda to planned leaves (no duplicate drafts)

### 3.1 G1 → CV-04a/CV-04b (full traffic aggregation)

CV-04a "Specify full traffic aggregation" and CV-04b "Implement bounded
traffic read API" are the planned owners (`plans/CORE.md` leaf table). This
addendum records the verified inventory the contract review must start from —
nothing here is a new leaf.

**What exists today (verified):**

- The analytics query engine serves multi-dimension grouping over recorded
  rows: dimensions `model`, `model_requested`, `endpoint`, `team`, `agent`,
  `task`, `status_class`, `cache`, `label:*`
  (pkg/adminstore/analytics_query_sql.go:42-51; rollup dimension subset at
  :224-231), metrics incl. additive counts/cost and ratios
  (pkg/adminstore/analytics_query_sql.go:21-40), shadow rows excluded
  (pkg/adminstore/analytics_query_sql.go:69). A joint
  `agent × model_requested × model` grouping already yields the recorded
  stage-tuple distribution a Sankey needs — **except provider**, which is not
  an engine dimension.
- Provider attribution exists only in provider health, as a **query-time join
  against the current registry**: `LEFT JOIN models_registry mr ON
  mr.model_name = rl.model_used`, grouped `(mr.provider, rl.model_used)`
  (pkg/adminstore/provider_health.go:59-76), 90-day-clamped window
  (services/admin/handlers/provider_health.go:19, :51-52), shadow excluded
  (pkg/adminstore/provider_health.go:74).
- Pricing-coverage counters exist per analytics result
  (`coverage.unpriced_requests`/`unpriced_share`/`legacy_rows`,
  web/dashboard/src/lib/analyticsQuery.ts:188) but no covered/unknown counts
  per flow stage.

**Contract questions the CV-04a review must close (recorded, not decided):**

- UNITS: logical requests vs attempts as separate measures (VISUALIZERS
  aggregation rule — retries must not double the logical count); which
  additive metrics the width encoding may use.
- IDENTITY: stable node/edge ids for stages; Unknown/Other buckets;
  `missing:` phantom nodes stay a configured-mode concept
  (web/dashboard/src/lib/routingGraph.ts) and never enter observed flows.
- COVERAGE: provider attribution semantics — current-registry join
  (provider health behavior) vs provider recorded at request time; the
  former retroactively re-files history when a model moves provider. Whether
  a `provider` engine dimension is added or the CV-04b read model owns the
  join is a schema decision inside CV-04a, not a separate leaf.
- COVERAGE: classifier split — `classifier_distribution` exists only as a
  cost-payload aggregate (web/dashboard/src/api/analytics.ts:79), not as an
  engine dimension; in-scope as a CV-04a dimension question.
- MISSING-STATE: covered/unknown counts per stage; deleted/renamed models get
  an Unknown bucket, never a zero.

### 3.2 G2 → CV-03a/CV-03b (per-attempt telemetry)

CV-03a "Specify per-attempt telemetry contract" and CV-03b "Persist and
expose bounded attempt records" are the planned owners. Verified absence, so
the contract leaf starts from zero schema:

- **No producer; new contract leaf required.** The migrations contain no
  attempt/span table; the only attempt columns are the request summary
  scalars `attempt_count`/`retry_count`
  (migrations/0001_init.up.sql:1734-1735), written as event totals and
  persisted as nullable pointers (full evidence chain in
  `field-matrix.md` §(d) item 1; nullable pointers at
  pkg/adminstore/request_detail.go:163-168).
- Budget-blocked rows carry a literal `duration_ms = 0` producer zero
  (services/loggerd/consumer/event_mapper.go:665) — the attempt contract must
  keep "real zero" distinct from "unknown".

**Open contract questions the matrix/NCs add to CV-03a (recorded):**

- Shadow and budget mirror rows carry no attempt observability at all
  (`field-provenance.md` NC5) — decide whether CV-03a attempts cover them or
  the views render them as explicitly unknown.
- Per-attempt provider/model (V04 bars, V10 attempt errors) and monotonic
  vs wall-clock timing with hedged-overlap ordering are already in the
  VISUALIZERS attempt schema; the addendum adds only the NC5 attribution
  question and the zero-vs-unknown rule above.

## 4. New child-assignment drafts

Each draft below is bounded contract-specification work: bind the consumer,
freeze the today-inventory, write the reviewed contract. Implementation of any
resulting producer is a separate backend leaf with Go/security/test skills, as
the VISUALIZERS contract work section requires.

### 4.1 V07-P — Bounded latency/cost distribution read (suggestion)

- **Gap:** G3. No producer serves a latency distribution or bounded paired
  samples; percentiles only.
- **Consumers:** V07 (histogram + ECDF + p50/p95/p99 marks), V08
  (cost × latency paired points), V17 (tail-cohort members). Today they can
  only read: engine percentiles `latency_p50/p95`, `ttft_p50/p95` served by
  `GET /api/analytics/query` (registration
  services/admin/handlers/router_analytics.go:26;
  pkg/adminstore/analytics_query_sql.go:35-38); the latency report
  p50/p90/p95/p99 via `GET /api/analytics/latency`
  (services/admin/handlers/router_analytics.go:24;
  pkg/adminstore/request_stats.go:210-219); list stats average + p95 only
  (web/dashboard/src/api/requests.ts:59-67); per-request `duration_ms`
  samples bounded 25/page through the request explorer
  (services/admin/handlers/request_list.go:305) with latency/cost range
  filters (min/max at :255-256). "Never synthesize a distribution from
  percentiles" is the frozen V07 boundary; rollups never serve percentiles
  (`field-provenance.md` NC4).
- **Assignment:** specify the reviewed distribution read — server-side
  histogram/sketch or a seeded, bounded, window+filter-scoped sample export
  of paired `(duration_ms, first_token_ms, cost_in_usd, cost_status)` rows —
  including sample/coverage disclosure and the drill predicate contract so a
  selected bin opens exactly the contributing requests.
- **Contract questions:**
  - UNITS: ms for duration and TTFT (nullable TTFT stays unknown, never 0);
    USD only for rows with priced `cost_status`; unknown-cost rows excluded
    with an exact count, never zero-cost.
  - IDENTITY: sample seed + window + filter triple as the reproducible
    identity; bucket edges server-defined and echoed.
  - COVERAGE: bounded sample size or sketch error declared; relation to the
    100k-row label-keys bound (pkg/adminstore/analytics_query_sql.go:197)
    for cardinality discipline; hot-row coverage rides G7.
  - MISSING-STATE: one sample, identical values, timeout rows, missing TTFT
    and mixed streaming/non-streaming are named states; ECDF may not imply
    unobserved precision between buckets.
- **Oracle (frozen from the view spec):** a known deterministic sample yields
  expected bucket counts and quantiles within the declared error; a
  percentile-of-percentiles shortcut must fail.
- **Estimate:** 4h. **Prerequisites:** CV-00 (this family); QG-C01 before any
  implementation leaf.

### 4.2 V12-P — Region and destination provenance join (suggestion)

- **Gap:** G4. No served producer carries request-time region provenance.
- **Consumers:** V12 (region lanes + destination matrix). Today: `endpoint`
  is an analytics dimension on raw and rollup sources
  (pkg/adminstore/analytics_query_sql.go:45); the rich region fields
  (`inference_region`, `region_evidence`, `model_origin_country`,
  `log_storage_region`, `provider_entity_jurisdiction`) are persisted only in
  `request_lineage` and readable only through the separately permissioned
  lineage routes `GET /api/lineage/{request_id}` and
  `GET /api/organizations/{id}/lineage`
  (services/admin/handlers/router_analytics.go:48-51; handlers
  services/admin/handlers/lineage.go:38, :58, :94; full evidence in
  `field-matrix.md` §(d) item 3 and NC3); request detail carries only the
  writer `home_region` (pkg/adminstore/request_detail.go:162), which is the
  ingest region, not an inference region.
- **Assignment:** specify how a destination/region view may join recorded
  traffic to region provenance — either an analytics-side dimension over
  recorded region fields or a documented cross-surface link keyed by
  `request_id` — with provenance labels configured/observed/unknown and
  redacted endpoint labels. No URL geolocation inference (frozen boundary).
- **Contract questions:**
  - UNITS: regions/jurisdictions are labels with provenance marks, never
    coordinates; counts per (region, destination) cell.
  - IDENTITY: cell = (region value, redacted endpoint, provenance class);
    `request_id` remains the drill identity.
  - COVERAGE: lineage retention is append-only/archive-only while
    `request_logs` deletes under per-team windows — a join can legitimately
    find nothing for old requests; the org lineage list caps at 1000
    (services/admin/handlers/lineage.go:104-110) and is not an aggregation
    surface.
  - MISSING-STATE: unknown region stays unknown; secret/credential canaries
    never appear in labels, tooltips, URLs or exports (frozen oracle).
- **Oracle (frozen from the view spec):** unknown geography remains unknown;
  canaries never surface.
- **Estimate:** 4h. **Prerequisites:** CV-04b for the flow substrate;
  `lineage.read` permission interplay reviewed with the owner.

### 4.3 V11-P — Policy steps ↔ request journey join and coverage (suggestion)

- **Gap:** G5. The decision log exists; the join to a single request's
  journey, its permission shape and its retention mismatch do not.
- **Consumers:** V03 (journey decision cards), V11 (recorded policy
  explanation graph). Today: `GET /api/organizations/{id}/policy-decisions`
  serves decision rows with the CORE-TRACE-05 envelope — steps with order,
  action and version (services/admin/handlers/policy_decisions.go:144-149),
  two-way filters incl. `request_id` and `step`, `entity=decisions|requests`
  (route mount services/admin/handlers/policy_decisions.go:65-67); request
  detail has **no** policy field and never selects `policy_decisions`
  (`field-matrix.md` §(d) item 4); the mount gates on
  `policies.manage` (services/admin/handlers/policy_decisions.go:66) while
  the journey view gates on `requests.read` — a member can see a request but
  not its recorded explanation; the 90-day hot purge
  (services/loggerd/consumer/policy_decisions.go:443) can make old requests
  legitimately explanation-less.
- **Assignment:** specify the join contract — a request-detail reference
  (ids only) plus a documented cross-surface link, or an embedded summary —
  and decide the permission question (viewer-readable recorded steps vs
  manage-gated) and the purge-vs-retention disclosure.
- **Contract questions:**
  - UNITS: `duration_ms` per decision; counts of steps/findings.
  - IDENTITY: decision id + `request_id` + `policy_id`/`policy_version`;
    step order comes from the recorded envelope, never from component order
    (frozen V03 oracle).
  - COVERAGE: envelope absence (`envelope_version 0`, junk findings) is
    unknown, visibly degraded — the read model already guarantees this
    (services/admin/handlers/policy_decisions.go:220-229).
  - MISSING-STATE: rows older than the 90-day window render "no recorded
    explanation (purged)", distinct from "no policy ran"; 503 unwired is a
    deployment state (services/admin/handlers/policy_decisions.go:366).
- **Oracle (frozen from the view spec):** recorded deny ordering and action
  match durable decisions; selection never triggers enforcement.
- **Estimate:** 4h. **Prerequisites:** CV-02 (journey view).

### 4.4 V05-P — Tool execution outcome, timing and parentage (suggestion)

- **Gap:** G6. Per-request occurrences exist; execution outcome, per-call
  timing, proposal-vs-execution distinction and span parentage do not.
- **Consumers:** V05 (swimlanes with proposal/execution/result marks), V15
  (dependency neighborhood), V18 (icicle spans). Today: request detail serves
  per-request occurrences `seq`/`call_id`/`tool_name`/`arguments`
  (pkg/adminstore/request_detail.go:20-26, :176, :321-333) from
  `tool_call_invocations` (migrations/0001_init.up.sql:2057-2064) whose only
  timing is `created_at`; the cross-request surface is the fixed-30-day
  aggregate report `GET /api/organizations/{id}/tool-calls` (route
  services/admin/handlers/router_analytics.go:60;
  handler services/admin/handlers/request_list.go:395; wire
  web/dashboard/src/api/requests.ts:89-110) over `tool_calls`
  (migrations/0001_init.up.sql:2087-2096) which adds `task_id`/`model_used`.
  No outcome/status or duration column exists anywhere; no request-list
  filter selects by tool name (filter vocabulary at
  services/admin/handlers/request_list.go:229-256). Tool rows exist only
  under originals retention (`field-provenance.md` NC6) — absence is a
  possible honest state per org.
- **Assignment:** specify the bounded execution-read contract: per-occurrence
  outcome class, optional duration with clock definition, proposal-vs-
  execution semantics, parent linkage (request always; nested span for V18
  only if a producer is authorized), and a tool-name cohort filter bound to
  the existing request-list filter grammar.
- **Contract questions:**
  - UNITS: durations ms with declared clock; counts of proposals vs
    executions vs results.
  - IDENTITY: `(request_id, seq, call_id)` occurrence identity; two
    identically named tools stay separate by id (frozen oracle).
  - COVERAGE: originals-retention off ⇒ "none recorded" is a positive fact
    for that org, rendered as such; 30-day aggregate window stays fixed
    until this leaf or CV-06 changes it.
  - MISSING-STATE: proposal without execution never renders as an execution;
    orphan results and unknown outcomes are named states.
- **Oracle (frozen from the view spec):** no execution is created for a
  proposal; table and graphical chronology agree on recorded ordinals.
- **Estimate:** 4h. **Prerequisites:** CV-02; QG-C01 before implementation.

### 4.5 V06-P — Hot-row coverage signal for queried windows (suggestion)

- **Gap:** G7. Queries over windows older than an org's hot `request_logs`
  rows under-report silently; no surface tells the view.
- **Consumers:** V06 (hatched gaps), V10 (missing collection windows), V13
  (coverage differences between compared windows), V17 (absent baseline);
  matrix V-10/V-11 (the §7 residual names this exact honesty gap). Today the
  analytics result carries **pricing** coverage only
  (web/dashboard/src/lib/analyticsQuery.ts:188); retention configuration
  exists as effective org windows (pkg/adminstore/retention.go:84-102) and an
  originals-retention toggle route
  `GET/PATCH /api/organizations/{id}/original-retention`
  (services/admin/handlers/router_orgs.go:32-34), but nothing serves
  per-table hot-row reachability (oldest retained row / delete watermark)
  for a queried window; deletes happen only after archive
  (services/loggerd/consumer/retention.go:24-27, :197-204).
- **Assignment:** specify a bounded coverage read — per (org, table family)
  oldest-hot-row or watermark plus the applied retention window — and how
  query responses disclose "window partially/entirely beyond retained rows"
  so hatched gaps and coverage deltas render facts, not inferences.
- **Contract questions:**
  - UNITS: timestamps (RFC3339) and row counts; no percentages without a
    declared denominator.
  - IDENTITY: (org, table family, watermark) as the stable fact; rollup
    tables have no age cutoff and need their own signal class
    (`view-contract-matrix.md` §2.3).
  - COVERAGE: cheap enough to join every analytics response (no per-query
    table scan — watermark or min on an indexed column, decided here);
    policy_decisions' independent 90-day window must be coverable too
    (services/loggerd/consumer/policy_decisions.go:443).
  - MISSING-STATE: "no rows retained in window" is distinct from "no traffic
    in window"; a missing bucket never becomes zero (frozen V06 oracle).
- **Oracle:** an org with a known deletion boundary shows exact
  under-reporting disclosure for a pre-boundary window, and none for a
  post-boundary window; swapping them must fail the check.
- **Estimate:** 4h. **Prerequisites:** CV-00; aligns with CV-04b coverage
  counts (G1 addendum) but is independent of the flow API.

### 4.6 EXP-P — Receiver delivery outcomes and WORM export admin read (id pending owner allocation)

- **Gap:** G8. The exports page is the only bound view whose primary facts
  are receiver configuration/delivery, and its producers are absent.
- **Consumers:** matrix V-17 (exports page,
  web/dashboard/src/pages/ExportsPage.tsx:71). Today: the only wired receiver
  surface is `GET/PATCH /api/organizations/{id}/spend-alert`
  (mount services/admin/handlers/router_billing.go:58-59; handlers
  services/admin/handlers/spend_alert_handlers.go:13, :31) where
  `last_alert_at` is the **only** delivery signal — no delivery
  success/failure tracking, no connection test, no receiver inventory beyond
  this pair (verified receiver inventory recorded at
  web/dashboard/src/api/exports.ts:2-15; wire shape
  web/dashboard/src/api/budgets.ts:41-49). WORM lineage export has **no
  admin API** — export/verify run via the trcli binary
  (pkg/trcli/lineage_export.go:26, :81). OTLP/SIEM rows are planned, without
  data.
- **Assignment:** specify (a) a delivery-outcome read for the spend-alert
  webhook (bounded history of delivery attempts with outcome classes) and
  (b) an admin read for WORM lineage-export state (last export/verify, archive
  destination presence — destination semantics already exist in
  pkg/adminstore/retention.go:84-102), both fail-closed and root-scoped like
  the surfaces they extend. The existing page already renders honest
  "not configured via API" states; this leaf replaces those with real reads
  or keeps them by decision. The page's own inventory comment already marks
  a connection-test/receiver-config API as a needs-lease — this draft is
  that lease's contract input, not an authorization.
- **Contract questions:**
  - UNITS: timestamps; outcome classes as labels; `threshold_usd` null
    renders "disabled", never 0 (validation already rejects non-positive
    values, services/admin/handlers/spend_alert_handlers.go:48-51).
  - IDENTITY: one config per org; delivery events keyed by attempt time;
    export state keyed by org + archive destination.
  - COVERAGE: bounded delivery history (window/limit decided here); export
    state reflects the trcli-run archives only — no synthetic status.
  - MISSING-STATE: "never delivered" ≠ "delivery failed"; unknown receiver
    reachability stays unknown until a tested delivery exists.
- **Oracle:** a recorded delivery failure renders as failure with evidence;
  absent history renders unknown, not zero deliveries.
- **Estimate:** 4h. **Prerequisites:** owner allocates the id (no visualizer
  view card owns it); deployment/write surfaces stay out of scope — reads
  only.

## 5. Residual — deliberately unassigned, with reasons

1. **V19/V20 producers (runtime signals, forecasts):** owned by Enterprise
   leaves RG-C01/RG-C02/RG-C03 (E11-P01..P03) per the catalog's data
   boundary; Core drafts would duplicate authorized Enterprise scope.
2. **Resale per-request cost (`resale_cost_usd`):** not persisted in
   `request_logs` and has no admin read view (`field-provenance.md` NC2);
   it is a wallet/ledger fact ("resale is a wallet fact, not an analytics
   fact", `field-provenance.md`). Assigning it to a request-grain producer is
   an owner accounting decision, so no leaf is drafted here.
3. **Request bodies:** not stored by design (PH.1,
   web/dashboard/src/api/requests.ts:114-116); a gap that must stay a gap.
4. **Provider attribution recorded at request time:** if the owner rejects
   the current-registry join semantics recorded in §3.1, that becomes a
   CV-03a/CV-04a schema decision (persist provider per row/attempt), not a
   separate leaf from this document.
5. **The 16 residual matrix views** (configuration/account screens,
   `view-contract-matrix.md` §1) share these producer gaps only where they
   reuse the same components; freezing their contracts is the matrix's own
   residual, not this one.
6. **`beta_*` startup views and raw-vs-rollup per-field selection:** remain
   specified by the field-matrix/provenance documents; no producer gap
   beyond G1/G7 applies.

## 6. Mechanical verification record

Executed against the working tree of `task/cv00-04` at the frozen base
`6da73e63ec580812204a8e01bd07e9fc3f2e3954` (only this document differs from
the base).

1. Every citation was extracted with the CV-00-03 grammar: a full citation is
   a repo-relative path (containing `/` and a file extension) immediately
   followed by `:N` or `:N-M`, optionally with comma-separated continuation
   specs in the same parenthetical; a bare `:N`/`:N-M` binds to the most
   recent preceding full citation's path. Each anchor was checked: the file
   exists, every cited line/range falls inside the file, and the load-bearing
   anchors were additionally grep-verified to contain the named symbol/route
   string at authoring time.
   Result: **68 citation instances, 57 distinct (file,line-range) anchors,
   0 bad.**
2. Endpoint-name discipline: every route string in this document
   (`/api/analytics/query`, `/api/analytics/latency`,
   `/api/lineage/{request_id}`, `/api/organizations/{id}/lineage`,
   `/api/organizations/{id}/tool-calls`,
   `/api/organizations/{id}/policy-decisions`,
   `/api/organizations/{id}/spend-alert`,
   `/api/organizations/{id}/original-retention`) was matched against its
   registration line cited in the same section. No other endpoint name
   appears; absent producers are stated as "no producer; new contract leaf
   required".
