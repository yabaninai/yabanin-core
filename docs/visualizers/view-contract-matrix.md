# View contract matrix — units, identity, coverage, missing-state, retention

Task: CV-00-03 (`plans/CORE.md`), frozen at product base
`34eb9783af26e7780d4ffa8a7c3e2deaf7593428` (branch `task/cv00-03`).

This matrix freezes five contracts for twenty dashboard views:

1. **UNITS** — the unit vocabulary each view renders (currency, ms, counts,
   fractions/percent, cents) and the formatting engine that renders it.
2. **IDENTITY** — the row/grain identity: what one row is, its stable id, and
   how selection/drill binds to it.
3. **COVERAGE** — the served scope: source operation, window, filters,
   pagination/caps, and what the scope note promises.
4. **MISSING-STATE** — the empty/error/stale/not-loaded vocabulary and the
   null-vs-zero honesty rules the view obeys.
5. **RETENTION** — how long the underlying rows survive and what deletion
   policy governs them.

Per-field provenance (wire type → source column/lineage) is already frozen in
`docs/visualizers/field-provenance.md` (CV-00-02) and
`docs/visualizers/field-matrix.md` (CV-00-01); this matrix cites and extends
those contracts at view grain and does not re-derive field lineage.

Every citation is `path:line` at the frozen base. Section 6 records the
mechanical verification.

---

## 1. Scope and selection rule

The dashboard routes are the `Page` union in `web/dashboard/src/App.tsx:68-80`
— 36 route ids. Twenty views are bound here under this selection rule:

- **R1 — recorded traffic surfaces (17):** every route whose primary content
  is recorded request traffic or traffic-derived records or aggregates:
  `overview`, `cost`, `compare`, `credits`, `classifier`, `cache`,
  `feedback`, `lineage`, `requests-explorer`, `analytics`, `dashboards`,
  `tool-calls`, `tasks`, `policy-decisions`, `audit-log`, `budgets`,
  `exports`.
- **R2 — routing topology (1):** `routing-map` — configuration topology
  joined with observed provider health (a task-named source surface).
- **R3 — data catalogs feeding recorded-data semantics (2):** `rates` (the
  sealed reference-rate catalog that prices recorded traffic) and `models`
  (the model registry that recorded rows join against for provider/pricing
  attribution).

**Residual (16, not bound here):** pure configuration/account screens and
flows whose primary content is mutable configuration rather than recorded
data — `keys`, `agents`, `orgs`, `rules`, `tool-policy`, `policy-editor`,
`prompts`, `label-policy`, `guardrails`, `guard-packs`, `model-access`,
`members`, `admin-users`, `org-settings`, `mcp-credentials`, `onboarding`.
They inherit the shared contracts in section 2 where they use the same
components; freezing their five contracts is residual work (section 7).

Route → nav gate: each view's header below cites its gate line in
`web/dashboard/src/App.tsx` (lines 117-222).

---

## 2. Shared contracts (bind once; per-view sections cite exceptions)

### 2.1 Units engine

- Every table cell renders through `web/dashboard/src/lib/columnFormat.ts`:
  `MISSING_VALUE = '—'` for absent values
  (web/dashboard/src/lib/columnFormat.ts:26); money renders with 2
  decimals and sub-cent amounts as `"<$0.01"` with the exact value in the
  cell's `title` hint (FE-07) (web/dashboard/src/lib/columnFormat.ts:47,
  62-64).
- Free-text money uses `formatMoney` from `web/dashboard/src/i18n/format`
  (org currency from `useOrgPresentation`); tabular numbers use
  `font-variant-numeric: tabular-nums` (e.g. `web/dashboard/src/pages/ComparePage.tsx:85-87`).
- DataTable columns declare `type` plus optional `unit` metadata
  (`web/dashboard/src/components/astra/DataTable.tsx:20, 66-67`) — the unit story is header metadata, not
  per-cell invention.

### 2.2 Missing-state engine

- `ScreenState = 'not-loaded' | 'loading' | 'empty' | 'stale' | 'ready' |
  'error'` (`web/dashboard/src/hooks/useScopedQuery.ts:28`); `'not-loaded'`
  = nothing fetched yet, `'empty'` = fetched but no records in scope,
  `'stale'` = shown data belongs to a previous scope
  (`web/dashboard/src/hooks/useScopedQuery.ts:31-32, :43`). The notice vocabulary adds `'partial'`
  and `'warning'` (`web/dashboard/src/components/astra/StateNotice.tsx:9`).
- Aborts are silence; a superseded scope can never settle state
  (`web/dashboard/src/hooks/useScopedQuery.ts` generation discipline; explicit in
  `web/dashboard/src/pages/CreditsPage.tsx:49-60`).
- Pagination is external for server-paged tables
  (`web/dashboard/src/components/astra/DataTable.tsx:29, 105`); sort is
  `'client' | 'server'` (web/dashboard/src/components/astra/DataTable.tsx:122).
- Reads arm a 30s timeout; mutations do not auto-retry
  (`web/dashboard/src/api/http.ts:11-13`); `DEFAULT_PAGE_SIZE = 50`
  (web/dashboard/src/api/http.ts:63).
- Access-shaped responses are distinct states, not errors-as-data: 403 =
  member without permission, 404 = org invisible (never "no access to org
  X"), 501 = deployment predates the program ("not available"), 503 = route
  mounted but store unwired (`web/dashboard/src/api/currencies.ts:12-15`;
  `services/admin/handlers/policy_decisions.go:366`;
  `services/admin/handlers/feedback_handler.go:144-152`).
- Null-means-unknown: money/measure pointers render "unknown"/"not
  configured", never a fabricated zero (`web/dashboard/src/api/currencies.ts:9-11`;
  `web/dashboard/src/pages/OverviewPage.tsx:366` for `t('common.unknown')` on Overview).

### 2.3 Retention substrate (shared facts)

| Substrate | Retention contract | Citation |
| --- | --- | --- |
| `request_logs` | Per-team hot windows; export-before-delete — a batch is deleted only after its JSONL+sha256 archive writes; no destination ⇒ no delete | `services/loggerd/consumer/retention.go:26, 199, 203` (NEXT-21 contract) |
| `cache_entries` | Org-scoped window delete (same export-before-delete family) | `services/loggerd/consumer/retention.go:215` |
| `request_lineage` | Append-only (PB1.2 trigger blocks UPDATE/DELETE); expired rows are archived to cold buckets but never deleted from hot storage | `services/loggerd/consumer/retention.go:217-219` |
| `policy_decisions` | 90-day hot window (owner decision), purged in batches | `services/loggerd/consumer/policy_decisions.go:431, 441-442, 459, 504` |
| `admin_audit_logs` | Durable journal (seq-keyed table); no production purge path exists (verified by search — only test fixtures delete) | `migrations/0001_init.up.sql:149` |
| `classifier_feedback` | No purge path; entries persist (CSV export rides the same rows) | `pkg/feedback/collector.go:40` |
| `analytics_rollup_hourly` / `label_rollup_hourly` | Deleted only inside the recomputed window (idempotent refresh), no age cutoff | `services/loggerd/consumer/rollup.go:166, 169-170` |
| `beta_*` metrics views | SQL views over `request_logs` created/replaced at admin startup (not migrations); retention rides `request_logs` | `pkg/feedback/views.go` (see field-matrix audit) |
| Credit ledger | Append-only transactions; wallet balance derives from the ledger, ledger consistency surfaced (`ledger_consistent`) | `web/dashboard/src/api/currencies.ts:96-105` |
| Rates catalog | Sealed versioned packs (version + digest + generated_at); promotion is durable and audited | `web/dashboard/src/api/currencies.ts:107-160, 182-201` |

---

## 3. View contracts

### V-01 Overview (`overview`, root-only, `web/dashboard/src/App.tsx:117`)

- **Source:** `useOverviewReport` → `fetchSavingsReport({days, org_id})`
  (`web/dashboard/src/pages/hooks/useOverviewReport.ts:26, 46-49`) → `GET /api/analytics/cost`
  (`web/dashboard/src/api/analytics.ts:90-93`); pinned board panels render at
  `web/dashboard/src/pages/OverviewPage.tsx:482`; pricing coverage resolves per window
  (`web/dashboard/src/pages/OverviewPage.tsx:16, 58-59`; coverage semantics `web/dashboard/src/api/analytics.ts:30-34`:
  `complete | partial | unknown | empty`).
- **UNITS:** money via `formatMoney` (org currency) and `formatMoneyCell`
  (2dp, sub-cent `"<$0.01"`) (`web/dashboard/src/pages/OverviewPage.tsx:366, 456, 466`); counts via
  `formatNumber`; unknown money renders `t('common.unknown')`, not 0
  (`web/dashboard/src/pages/OverviewPage.tsx:366`).
- **IDENTITY:** aggregate surface (no row identity); daily/metric rows are
  window-bucket rows; pinned panels carry the pin id (AUX-07) and re-fetch at
  the operator's exact window.
- **COVERAGE:** window = the applied `days` selection (default 7;
  `services/admin/handlers/cost_handlers.go:25-26`), org = applied org scope;
  the report is the cost analytics payload (`CostAnalyticsData`,
  `web/dashboard/src/api/analytics.ts:54-79`: totals, `daily_breakdown`,
  `classifier_distribution`).
- **MISSING-STATE:** `useScopedQuery` lifecycle (`loading/empty/stale/error`,
  `web/dashboard/src/hooks/useScopedQuery.ts:28`); pricing coverage degrades to `unknown` when it
  cannot be quantified and `empty` when there were no requests — both render
  labeled, never as 0% (`web/dashboard/src/api/analytics.ts:30-34`).
- **RETENTION:** rides `request_logs` per-team export-before-delete
  (§2.3); daily aggregates are computed over live rows, not stored.

### V-02 Cost (`cost`, root-only, `web/dashboard/src/App.tsx:118`)

- **Source:** `useCostReport` → `GET /api/analytics/{org}/cost?days=&provider=`
  (`web/dashboard/src/pages/hooks/useCostReport.ts:24, 33-35`) with provider filter and
  `days` selector (default 7, `services/admin/handlers/cost_handlers.go:25-27`).
- **UNITS:** USD money through the shared engine (§2.1); token pairs as
  "input / output" (field-matrix freeze).
- **IDENTITY:** aggregate + daily rows (`daily_breakdown`,
  `web/dashboard/src/api/analytics.ts:72-76`); row grain = (day, provider) as served.
- **COVERAGE:** applied org × days × provider; the served window is what the
  response carries (display the response's window, never the request's).
- **MISSING-STATE:** `useScopedQuery` states (§2.2); pricing coverage banner
  (`complete/partial/unknown/empty`, `web/dashboard/src/api/analytics.ts:30-34`).
- **RETENTION:** rides `request_logs` (§2.3).

### V-03 Compare (`compare`, root-only, `web/dashboard/src/App.tsx:138`)

- **Source:** `useCompareReports` (shadow backbone + latency/quality
  supplements) → `GET /api/analytics/shadow` (+ latency, quality);
  window default 30d (`services/admin/handlers/cost_handlers.go:77, 101`);
  endpoint named at `web/dashboard/src/pages/ComparePage.tsx:23`.
- **UNITS:** money `type: 'money', unit: 'USD'` via `formatMoney`
  (`web/dashboard/src/pages/ComparePage.tsx:86-87`); `delta_pct` renders signed with one decimal
  (`+x.x%`, `web/dashboard/src/pages/ComparePage.tsx:97-99`); overlap is a plain count (:85, :143);
  quality scores two decimals with a `title` carrying the exact inputs
  (web/dashboard/src/pages/ComparePage.tsx:131).
- **IDENTITY:** one row per (primary, shadow) model pair; pair identity +
  shared-request `overlap` define comparability (`web/dashboard/src/pages/ComparePage.tsx:23, 85`).
- **COVERAGE:** window = applied `days` (default 30); rows exist only where
  both sides have traffic; the request-ids intersection is the honesty bound
  (`overlap`).
- **MISSING-STATE:** `insufficient_data` verdict renders the string "unknown"
  — never a fabricated `+0.0%` (`web/dashboard/src/pages/ComparePage.tsx:38, 97-99`); missing
  comparison window disables deltas rather than showing ±0.
- **RETENTION:** rides `request_logs` (§2.3).

### V-04 Credits (`credits`, anyOrg `budgets.manage`, `web/dashboard/src/App.tsx:121`)

- **Source:** wallet pair `fetchCreditBalance` + `fetchCreditTransactions`
  (`web/dashboard/src/pages/CreditsPage.tsx:96` Promise.all; `web/dashboard/src/api/credits.ts:36-45`, limit 50
  default) and the ledger audit view `getCreditsLedger(org, 50)`
  (`web/dashboard/src/pages/CreditsPage.tsx:83`; `web/dashboard/src/api/currencies.ts:212-218`); handler limit
  default 50 (`services/admin/handlers/credit_handlers.go:247, 254-261`).
- **UNITS:** cents are the wire unit (`balance_cents`,
  `amount_cents`, `balance_after` — `web/dashboard/src/api/currencies.ts:74-94`); panels divide
  by 100 and render via `formatMoney`, `credits_scale` renders verbatim next
  to every amount (`web/dashboard/src/pages/credits/LedgerPanel.tsx:23, 46-47, 87`); raw cents
  surface in the sum's source note (`web/dashboard/src/pages/credits/LedgerPanel.tsx:59`).
- **IDENTITY:** wallet = org; transaction id (`LedgerTransaction.id`,
  `web/dashboard/src/api/currencies.ts:85-94`) with `balance_after` forming the auditable
  chain; `request_id`/`invoice_ref` bind a txn to its cause.
- **COVERAGE:** newest-first transactions capped by `limit` (frontend 50,
  `web/dashboard/src/pages/CreditsPage.tsx:83`); the ledger view additionally returns
  `ledger_sum_cents`, `transaction_count`, `ledger_consistent`
  (`web/dashboard/src/api/currencies.ts:96-105`) — the count is the honest total behind the
  capped list.
- **MISSING-STATE:** wallet and ledger are separate surfaces: a ledger
  failure must not fail the wallet and vice versa; ledger 501 = "not
  available in this deployment" (`web/dashboard/src/pages/CreditsPage.tsx:30-31, 49-60`;
  `web/dashboard/src/api/currencies.ts:14-15`); empty org input resets to not-loaded (never
  keeps the previous org's wallet).
- **RETENTION:** ledger is append-only; no purge path (§2.3).

### V-05 Classifier (`classifier`, root-only, `web/dashboard/src/App.tsx:145`)

- **Source:** `fetchSavingsReport({days})` (`web/dashboard/src/pages/ClassifierPage.tsx:8, 29`,
  days default 7 at web/dashboard/src/pages/ClassifierPage.tsx:12) → cost analytics payload's
  `classifier_distribution` (`web/dashboard/src/api/analytics.ts:79`).
- **UNITS:** share/distribution per class (counts and fractions as served);
  money only through the shared engine.
- **IDENTITY:** one row per classifier class; class name is the identity.
- **COVERAGE:** applied `days` window, org-scoped; distribution covers
  requests present in the window only.
- **MISSING-STATE:** `not-loaded` before first load, `empty` when the window
  has no rows, `error` with retry (`web/dashboard/src/pages/ClassifierPage.tsx` state machine, §2.2);
  absent distribution is absence (no zero-class rows invented).
- **RETENTION:** rides `request_logs` (§2.3).

### V-06 Cache (`cache`, root-only, `web/dashboard/src/App.tsx:144`)

- **Source:** `fetchSavingsReport({days})` (`web/dashboard/src/pages/CachePage.tsx:9, 35`, days
  default 7 at web/dashboard/src/pages/CachePage.tsx:18) — cache section of the cost analytics payload
  (`cache_hits`, `web/dashboard/src/api/analytics.ts:61`).
- **UNITS:** cache hits are counts; ratios (hit-rate style metrics) are
  fractions of requests; money via shared engine.
- **IDENTITY:** daily rows (`daily_breakdown` grain, §V-02).
- **COVERAGE:** applied `days` window, org-scoped.
- **MISSING-STATE:** as V-05 (same fetch lifecycle, §2.2).
- **RETENTION:** rides `request_logs` (§2.3); the `cache_entries` substrate
  itself has its own org-scoped window delete (`services/loggerd/consumer/retention.go:215`) — the page
  reports on logs, not on the live cache store.

### V-07 Feedback (`feedback`, root-only, `web/dashboard/src/App.tsx:147`)

- **Source:** `GET /api/feedback` via `listFeedback` (`web/dashboard/src/api/feedback.ts:39`,
  params web/dashboard/src/api/feedback.ts:25-35) — root-only handler
  (`services/admin/handlers/feedback_handler.go:153-160`); CSV export
  `feedbackExportUrl` rides the same filters, server ignores pagination
  (`web/dashboard/src/api/feedback.ts:43-46`).
- **UNITS:** ratings are ordinal labels (thumbs), timestamps via
  `formatDateTime`; no money.
- **IDENTITY:** one row per `classifier_feedback` entry; `prompt_hash` +
  `request_id` + `org_id` bind it to the recorded request
  (`web/dashboard/src/api/feedback.ts:8-18`; `pkg/feedback/collector.go:40`).
- **COVERAGE:** filters `org_id`, `rating`; page default 1, page size default
  50 / max 200 (`services/admin/handlers/feedback_handler.go:114-143`;
  `pkg/feedback/list.go:16-17`); page renders 50/page
  (`web/dashboard/src/pages/FeedbackPage.tsx:12, 39, 68`).
- **MISSING-STATE:** 503 "lister unwired" is a distinct deployment state
  (`services/admin/handlers/feedback_handler.go:144-152`); empty filter result is `empty`, not
  "no feedback exists".
- **RETENTION:** `classifier_feedback` has no purge path — entries persist
  (§2.3).

### V-08 Lineage (`lineage`, anyOrg `lineage.read`, `web/dashboard/src/App.tsx:137`)

- **Source:** list `GET /api/organizations/{id}/lineage?limit=` via
  `listLineageByOrg` (`web/dashboard/src/api/lineage.ts:40-42`) — a plain array capped by
  `limit`, no total, no cursor (`web/dashboard/src/api/lineage.ts:25`); point lookup
  `getLineage` + `verifyLineage` (`web/dashboard/src/pages/LineagePage.tsx:121, 142`).
- **UNITS:** no money; timestamps `formatDateTime`; region/jurisdiction
  fields are labels; verification result is boolean + request id.
- **IDENTITY:** attestation identity = `request_id` (row key
  `web/dashboard/src/pages/LineagePage.tsx:288`); the hash chain (`record_hash`/`prev_hash`)
  is the tamper-evidence identity of the ledger itself
  (`services/loggerd/consumer/retention.go:217-219`).
- **COVERAGE:** frontend fetches `SERVER_LIMIT = 50`
  (`web/dashboard/src/pages/LineagePage.tsx:31, 121`) and paginates client-side at 20/page
  (web/dashboard/src/pages/LineagePage.tsx:30, :290); server limit default 50, cap 1000, `model` + RFC3339
  `[from,to]` filters (`services/admin/handlers/lineage.go:104-111`); the
  scope note states the cap explicitly (web/dashboard/src/pages/LineagePage.tsx:296) — the table never claims
  completeness beyond 50.
- **MISSING-STATE:** `not-loaded` / `empty` distinct
  (`web/dashboard/src/pages/LineagePage.tsx:259-262`); verify failure renders `error`,
  success renders `partial` notice (web/dashboard/src/pages/LineagePage.tsx:349-351); 503 when the store is
  unwired (handler family, §2.2).
- **RETENTION:** append-only, archive-only — expired rows go to cold buckets
  and hot rows stay (§2.3, `services/loggerd/consumer/retention.go:217-219`).

### V-09 Requests explorer (`requests-explorer`, anyOrg `requests.read`, `web/dashboard/src/App.tsx:127`)

- **Source:** `listRequests` (`web/dashboard/src/pages/RequestExplorerPage.tsx:721, 758`) with
  `PAGE_SIZE = 25` (web/dashboard/src/pages/RequestExplorerPage.tsx:44, :1288, :1305); stats strip `requestStats`
  (`web/dashboard/src/api/requests.ts:216`; fields :60-63, shape-guard :76-79); detail
  `getRequestDetail` (web/dashboard/src/pages/RequestExplorerPage.tsx:862); CSV export
  of selected rows (:925-927, :1273);
  cross-links to the policy decision log (web/dashboard/src/pages/RequestExplorerPage.tsx:6).
- **UNITS:** money USD via `formatMoneyCell` (web/dashboard/src/pages/RequestExplorerPage.tsx:981;
  import :14; definition `web/dashboard/src/lib/columnFormat.ts:55`); latency ms;
  success rate = fraction × 100 at one decimal (web/dashboard/src/pages/RequestExplorerPage.tsx:1093); latency stats
  rounded ms with `ms` unit (web/dashboard/src/pages/RequestExplorerPage.tsx:1094-1095); token pairs "input / output".
- **IDENTITY:** row identity = `request_id` (wire row `RequestRow`,
  `web/dashboard/src/api/requests.ts`); selection/bulk export bind ids
  (web/dashboard/src/pages/RequestExplorerPage.tsx:625-646 —
  stale ids never export silently); detail binds the same id
  (web/dashboard/src/pages/RequestExplorerPage.tsx:862).
- **COVERAGE:** server-paged at 25/page with URL state; filters = the YQL
  filter vocabulary (field-matrix freeze); stats cover the same filtered
  scope (`statsSource` label web/dashboard/src/pages/RequestExplorerPage.tsx:1092).
- **MISSING-STATE:** privacy mode is a `partial` notice, not hidden rows
  (web/dashboard/src/pages/RequestExplorerPage.tsx:1190); `warning` for unknown request in detail (:1353); stats degrade to
  `loading`/`unknown` metric states rather than fake zeros (web/dashboard/src/pages/RequestExplorerPage.tsx:1081-1095);
  load error retries from page 1 (:1257).
- **RETENTION:** rides `request_logs` per-team export-before-delete (§2.3);
  detail bodies are the stored (redacted/truncated) snapshot — the request
  body is not stored by design (`web/dashboard/src/api/requests.ts:114-116`).

### V-10 Analytics (`analytics`, anyOrg `analytics.read`, `web/dashboard/src/App.tsx:128`)

- **Source:** the analytics query engine (`web/dashboard/src/lib/analyticsQuery.ts`) —
  metrics/groupBy/granularity/filter/top over `GET /api/analytics/query`;
  field-level raw/rollup source selection is frozen in
  `docs/visualizers/field-provenance.md` (CV-00-02) and is not re-derived
  here.
- **UNITS:** result columns carry their own typed unit story — money,
  percent, counts — never a raw `String(number)` (AUX-06,
  `web/dashboard/src/pages/AnalyticsExplorerPage.tsx:464`); time columns are bucket
  timestamps; deltas are per-column percents (web/dashboard/src/pages/AnalyticsExplorerPage.tsx:93-94).
- **IDENTITY:** row key = (time bucket, dimension values) via `rowKey`
  (web/dashboard/src/pages/AnalyticsExplorerPage.tsx:87); null cells are
  `string | number | null` by contract (:80).
- **COVERAGE:** org + explicit window + metric/segment selection; query state
  lives in the URL hash (web/dashboard/src/pages/AnalyticsExplorerPage.tsx:64); compare mode fetches the previous equal
  window (:222-229) — deltas exist only where both buckets exist.
- **MISSING-STATE:** null delta = unknown (missing bucket, non-finite, or
  prev = 0) — never 0% (web/dashboard/src/pages/AnalyticsExplorerPage.tsx:93-94,
  :451-456); null cells render the missing glyph + copy (:486, :495).
- **RETENTION:** raw/rollup mixed — rollups recompute in-window only, raw
  rows ride `request_logs` retention (§2.3); queries over windows older than
  the org's hot rows honestly under-report (coverage note, §7).

### V-11 Dashboards (`dashboards`, root-only, `web/dashboard/src/App.tsx:133`)

- **Source:** built-in panels (`web/dashboard/src/lib/boards.ts:36-41, 45-49, 53-56, 60-63`)
  fetched through `loadPanels` → `fetchAnalyticsQuery` at the operator's
  exact window (`web/dashboard/src/lib/boardPanels.ts:16-17, 27-37` — "never a drifting
  preset"); scope from the GlobalScope store
  (`web/dashboard/src/pages/DashboardsPage.tsx:56, 90-92`).
- **UNITS:** per-panel metric units as in V-10 (cost_usd money, tokens,
  ratios as fractions, latency ms).
- **IDENTITY:** panel id (`cost-client`, `tokens-model`, …) is the stable
  identity; a chart point binds (window bucket, dimension) and drills to the
  requests behind it (AUX-09, `web/dashboard/src/lib/boardPanels.ts:50-65`).
- **COVERAGE:** the applied concrete window (hash-pinned custom range or
  preset resolved at write time) — panels fetch exactly it
  (`web/dashboard/src/pages/DashboardsPage.tsx:90-92`); `top` caps per panel (20/50 in
  `web/dashboard/src/lib/boards.ts`); label-dependent panels hide unless the label key exists
  (`requires`, `web/dashboard/src/lib/boards.ts:36-63`).
- **MISSING-STATE:** panel payload is `AnalyticsResult | ApiError`
  (`web/dashboard/src/lib/boardPanels.ts:14`) — one failed panel is its own notice, never a
  failed board; label-absent panels are hidden, not empty.
- **RETENTION:** as V-10 (same engine and substrate).

### V-12 Tool calls (`tool-calls`, root-only, `web/dashboard/src/App.tsx:135`)

- **Source:** `getToolCallsReport` → `GET /api/organizations/{id}/tool-calls?days=`
  (`web/dashboard/src/api/requests.ts:109`), page always fetches the last 30 days ending at
  load time (`web/dashboard/src/pages/ToolCallsPage.tsx:55`).
- **UNITS:** calls/counts; `share` is a fraction of total calls; timestamps
  `formatDateTime`.
- **IDENTITY:** tool name (`tool_name`, `web/dashboard/src/api/requests.ts:88-92`) and model
  (`by_model`, web/dashboard/src/api/requests.ts:95-100).
- **COVERAGE:** fixed 30d window, org-scoped; totals (`total_calls`,
  `distinct_tools`, `requests_using_tools`, web/dashboard/src/api/requests.ts:102-107) quantify the scope.
- **MISSING-STATE:** `top_tools`/`by_model` are `| null` — calls exist only
  when parsed from the stored sample; absence is absence, never zero-usage
  (`web/dashboard/src/api/requests.ts:87` comment); page states `not-loaded`/`error`/`empty`
  (`web/dashboard/src/pages/ToolCallsPage.tsx:124-133`).
- **RETENTION:** rides `request_logs` (§2.3).

### V-13 Tasks (`tasks`, anyOrg `analytics.read`, `web/dashboard/src/App.tsx:134`)

- **Source:** `useTaskReport` → `fetchTaskAnalytics({... limit: 500})`
  (`web/dashboard/src/pages/hooks/useTaskReport.ts:32`) → `GET /api/analytics/tasks` — cost /
  counterfactual / savings / cache per task_id|session_id|agent_id
  (`web/dashboard/src/pages/TasksPage.tsx:29-32`; `web/dashboard/src/api/analytics.ts:230-240`).
- **UNITS:** money USD (cost, counterfactual, savings — CSV headers
  `web/dashboard/src/pages/TasksPage.tsx:91-96`); counts (requests, cache hits).
- **IDENTITY:** group identity = the grouping key (task/session/agent id)
  with `group` column first (web/dashboard/src/pages/TasksPage.tsx:91); groups map
  1:1 onto request-side YQL fields (web/dashboard/src/pages/TasksPage.tsx:106).
- **COVERAGE:** applied org × days × groupBy; the applied summary renders the
  fetched grouping, not the live selector (web/dashboard/src/pages/TasksPage.tsx:77,
  :110); server caps
  limit at 500 (default 100), from/to RFC3339 default last 24h
  (`services/admin/handlers/analytics.go:274-276`).
- **MISSING-STATE:** `useScopedQuery` lifecycle (§2.2); CSV mirrors exactly
  the visible columns — hidden columns stay out (AUX-22,
  web/dashboard/src/pages/TasksPage.tsx:86).
- **RETENTION:** rides `request_logs` (§2.3).

### V-14 Policy decisions (`policy-decisions`, anyOrg `policies.manage`, `web/dashboard/src/App.tsx:196`)

- **Source:** `listPolicyDecisions` / `listPolicyDecisionRequests`
  (`web/dashboard/src/api/policyDecisions.ts:111, 128`) → `GET /api/organizations/{id}/policy-decisions`
  — read-only over the loggerd consumer's rows; two-way search filters
  (verdict/mode/policy_id/policy_version/request_id/step/created_from/to)
  and `entity=decisions|requests` (`services/admin/handlers/policy_decisions.go:1-15`;
  `web/dashboard/src/api/policyDecisions.ts:38, 59`).
- **UNITS:** `duration_ms` as a duration column with `ms` unit
  (`web/dashboard/src/pages/PolicyDecisionsPage.tsx:141`); timestamps `format` 'date' (:113,
  web/dashboard/src/pages/PolicyDecisionsPage.tsx:116); counts of findings/steps are ints.
- **IDENTITY:** decision id, `request_id`, `policy_id` + `policy_version`
  (wire row `web/dashboard/src/api/policyDecisions.ts:22-25`); the `requests` view re-keys rows
  to distinct `request_id` with first/last seen
  (`web/dashboard/src/pages/PolicyDecisionsPage.tsx:113-114`; `web/dashboard/src/api/policyDecisions.ts:62-69`).
- **COVERAGE:** `DEFAULT_PAGE_SIZE` (50) server-paged
  (`web/dashboard/src/pages/PolicyDecisionsPage.tsx:16, 65-66, 211-221`); gate: member without
  `policies.manage` = 403, foreign org = 404, root passes
  (`services/admin/handlers/policy_decisions.go:12-14`).
- **MISSING-STATE:** envelope fields use absence-is-unknown semantics —
  `envelope_version 0` / empty strings / null `matched` mean the information
  does not exist, never a fabricated value; `trace_completeness` ∈
  `full | partial | absent | unknown`, junk findings degrade visibly with
  `findings_valid=false` (`services/admin/handlers/policy_decisions.go:117-149`); 503 while unwired
  (services/admin/handlers/policy_decisions.go:366); page states
  `not-loaded`/`error`/`empty` (web/dashboard/src/pages/PolicyDecisionsPage.tsx:199-203).
- **RETENTION:** 90-day hot window, batched purge
  (`services/loggerd/consumer/policy_decisions.go:431, 441-442, 459, 504`) —
  the page reads hot rows only.

### V-15 Audit log (`audit-log`, anyOrgRole `security_auditor`, `web/dashboard/src/App.tsx:211`)

- **Source:** `listAuditLogs` → `GET /api/audit-logs`
  (`web/dashboard/src/api/audit.ts:37-38`); handler pagination page 1 / page size 50 cap 100
  (`services/admin/handlers/audit_logs.go:40-50`).
- **UNITS:** timestamps `formatDateTime` (`web/dashboard/src/pages/AuditLogPage.tsx:10`,
  columns :155); `before`/`after` snapshots render as entity JSON, not numbers.
- **IDENTITY:** `seq`-ordered journal entries (`id/action/resource/
  admin_id/admin_name/ip_address/timestamp`, `web/dashboard/src/api/audit.ts:16-26`; seq table
  `migrations/0001_init.up.sql:149`); rollback replays the recorded reverse
  call on the same resource (AUX-14b, `web/dashboard/src/api/audit.ts:41-58`).
- **COVERAGE:** page 50/page (`web/dashboard/src/pages/AuditLogPage.tsx:16, 61, 81-87`) with URL
  sort state; `total ?? 0` fallback computes last page honestly (:85).
- **MISSING-STATE:** unknown sort columns are the handler's own shape, not
  invented (`web/dashboard/src/api/audit.ts:8-13`); rollback conflicts surface current state
  (`web/dashboard/src/api/audit.ts:151`).
- **RETENTION:** durable, no purge path (§2.3).

### V-16 Budgets (`budgets`, anyOrg `[budgets.manage, agent_keys.manage, analytics.read]`, `web/dashboard/src/App.tsx:162`)

- **Source:** composite page — team/agent budget settings + org caps
  `GET /api/budgets` (`web/dashboard/src/api/currencies.ts:208-210`; month-to-date window
  `services/admin/handlers/currencies_handlers.go:241-245`) + unit spend
  `GET /api/units/spend` (`web/dashboard/src/api/currencies.ts:229-236`; default window last
  30d UTC, `services/admin/handlers/currencies_handlers.go:216-238`) + low-balance orgs
  (`fetchLowBalanceOrgs`, default threshold −500¢ = $5 below zero,
  `services/admin/handlers/credit_handlers.go:277-278`) + spend alert read
  (`web/dashboard/src/pages/BudgetsPage.tsx:4-5` imports).
- **UNITS:** `Measure.amount` null = unknown — a null carbon limit renders
  "not configured", never "0 g" (`web/dashboard/src/api/currencies.ts:9-11`); every money
  payload carries `credits_scale` rendered verbatim (:6-8); mixed families
  (tokens, USD, credits, gCO2e) each carry `unit` + `fidelity` +
  `provenance` (:24-31, :33-54).
- **IDENTITY:** budget line id (`BudgetCapLine.id`,
  web/dashboard/src/api/currencies.ts:57-64); unit-spend line
  = measure family within the served window.
- **COVERAGE:** caps = month-to-date org window; unit spend = requested
  RFC3339 window (default 30d) with the SERVED window echoed for display
  (`web/dashboard/src/api/currencies.ts:224-228`); rollup discloses pricing provenance
  (`pricing.pricing_as_of` + catalog digest, :48-54) and honest accounting
  of `unknown_usage_rows` / `unmodeled_carbon_rows` / `legacy_cost_rows`
  (:51-53).
- **MISSING-STATE:** 501 = deployment predates the currencies program
  (`web/dashboard/src/api/currencies.ts:14-15`); per-section notices isolate failures
  (`web/dashboard/src/pages/budgets/UnitsSpendSection` etc.,
  web/dashboard/src/pages/BudgetsPage.tsx:26-30).
- **RETENTION:** ledger append-only (§2.3); rollups recompute in-window
  only.

### V-17 Exports / receivers (`exports`, anyOrg `budgets.read`, `web/dashboard/src/App.tsx:163`)

- **Source:** spend-alert receiver `GET/PATCH /api/organizations/{id}/spend-alert`
  (`web/dashboard/src/pages/ExportsPage.tsx:71`; mount `services/admin/handlers/router_billing.go:58-59`)
  — GET returns `threshold_usd`, `webhook_url`, `last_alert_at`, and the
  computed `spend_today` (`web/dashboard/src/api/budgets.ts:41-52`; handler doc
  `services/admin/handlers/spend_alert_handlers.go:12`).
- **UNITS:** `threshold_usd` USD, where null disables alerts — the PATCH
  validation rejects anything but "positive or null (to disable)"
  (`services/admin/handlers/spend_alert_handlers.go:48-51`);
  `spend_today` USD computed server-side; `last_alert_at` datetime.
- **IDENTITY:** one receiver config per org; the webhook URL is the receiver
  identity (must be http(s), `web/dashboard/src/api/exports.ts` `isValidWebhookUrl`).
- **COVERAGE:** receiver inventory is verified and honest: the spend-alert
  webhook is the only wired receiver; WORM lineage export has NO admin API
  (trcli only — page renders "not configured via API", nothing invented);
  OTLP/SIEM are planned rows without data (`web/dashboard/src/api/exports.ts:2-14`).
- **MISSING-STATE:** `last_alert_at` is the ONLY delivery signal — no
  delivery success/failure tracking exists and none is fabricated
  (`web/dashboard/src/api/exports.ts:2-14`); threshold null renders "disabled", not 0.
- **RETENTION:** receiver config is live state, not retained records;
  `spend_today` derives from recorded traffic (rides `request_logs`, §2.3).

### V-18 Routing map (`routing-map`, anyOrg `routing.manage`, `web/dashboard/src/App.tsx:189`)

- **Source:** `getRoutingMap` (registry topology, `web/dashboard/src/pages/RoutingMapPage.tsx:88`)
  + `getProviderHealth(org, period)` (:111) with the period derived from the
  shared GlobalScope period — no second period control (:68-70,
  `web/dashboard/src/api/routing.ts:15-18`).
- **UNITS:** provider health `error_rate` is a fraction 0..1 (rendered %,
  never a raw float), `p50_ms`/`p95_ms` in ms (`web/dashboard/src/api/routing.ts:12-13,
  70-71, 81`); chain hops are config labels.
- **IDENTITY:** graph node ids `model:<name>` / `alias:<name>` / `rule:<id>`
  / `missing:<name>` (`web/dashboard/src/lib/routingGraph.ts:22-23`); provider×model health
  rows join on model name; drill binds model rows to the request explorer
  (`web/dashboard/src/pages/RoutingMapPage.tsx:7-10`).
- **COVERAGE:** health `period` vocabulary `1h | 24h | 7d | 30d` | Go
  duration, clamped server-side to 90d
  (`web/dashboard/src/api/routing.ts:15`; `services/admin/handlers/provider_health.go:19,
  51-52`); an empty window serializes as honest zeros for the served window
  (`web/dashboard/src/api/routing.ts:13-14`); topology = the org's registry at read time.
- **MISSING-STATE:** a chain/alias/rule target NOT in the registry becomes a
  `missing` phantom node — visible, never silently dropped or guessed
  (`web/dashboard/src/lib/routingGraph.ts:14, 20`); foreign org = 404 invisible
  (`web/dashboard/src/api/routing.ts:3-6`).
- **RETENTION:** topology is live config; health aggregates are computed
  over the requested window from recorded traffic (rides `request_logs`,
  §2.3).

### V-19 Rates (`rates`, any session, `web/dashboard/src/App.tsx:222`)

- **Source:** `getRatesCatalog` → `GET /api/rates/catalog`
  (`web/dashboard/src/api/currencies.ts:220-222`; `web/dashboard/src/pages/RatesPage.tsx:40`); diff/promote are
  root-only mutations on the same catalog family
  (`web/dashboard/src/api/currencies.ts:162-201, 244-258`).
- **UNITS:** per-axis `RefRateAxis` carries `unit` and `amount` where null =
  explicitly unpriced (known axis, no verified price — never free)
  (`web/dashboard/src/api/currencies.ts:118-126`); currency per entry (:135).
- **IDENTITY:** catalog identity = `version` + `digest` + `generated_at`
  (`RatesCatalogRef`, web/dashboard/src/api/currencies.ts:108-116); entry
  identity = provider + model (+ region/
  tier band); the digest renders copyable as the audit anchor
  (`web/dashboard/src/pages/RatesPage.tsx:21-22`).
- **COVERAGE:** the whole sealed catalog (no org scope,
  web/dashboard/src/api/currencies.ts:107); effective
  windows `effective_from → effective_to` and `verified_at` columns render
  per entry (`web/dashboard/src/pages/RatesPage.tsx:107-123`).
- **MISSING-STATE:** 501 = "not available in this deployment" rendered as an
  empty-state notice, distinct from error (`web/dashboard/src/pages/RatesPage.tsx:138-148`;
  `web/dashboard/src/api/currencies.ts:14-15`); a 422 refusal carries the full report as data
  — surfaced whole via `parseRatesRefusal`, never re-requested
  (`web/dashboard/src/api/currencies.ts:261-283`).
- **RETENTION:** sealed versioned packs; promotion is durable (active-of-record
  + priced models in one transaction, `persisted`/`materialization`,
  `web/dashboard/src/api/currencies.ts:182-201`) — prior versions remain citable by digest.

### V-20 Models (`models`, root-only, `web/dashboard/src/App.tsx:185`)

- **Source:** `listModels` / `listAllModels` → `GET /api/models`
  (`web/dashboard/src/api/models.ts:40, 50`; mount
  `services/admin/handlers/router_models.go:11`; lazy import
  `web/dashboard/src/App.tsx:31`); the routed page is
  `web/dashboard/src/pages/models/ModelsPage.tsx:40` — page and sort live in
  the URL (`useTableUrlState('models')`, AUX-02, :47) and the list fetches
  paged with server sort and `PAGE_SIZE = 25` (:61, :29); a header click
  re-asks the backend and resets the page (AUX-12, :256-261).
- **UNITS:** price in/out per 1M render via `formatMoneyCell`
  (`web/dashboard/src/pages/models/ModelsPage.tsx:311-329`) with the exact
  `input / output USD / 1M` in the cell `title` (:324); an unmatched pricing
  row renders `—`, never a zero price (:320); 7-day stats columns are
  locale-grouped counts plus `p95_ms` (:265-288); `upstream_timeout_ms`
  renders with an explicit `ms` unit (:584); tier is a label vocabulary
  (`MODEL_TIERS = easy|medium|hard|premium`, `web/dashboard/src/api/models.ts:38`).
- **IDENTITY:** `model_name` is the registry key — create/update/delete/
  set-enabled all bind it on the wire (`web/dashboard/src/api/models.ts:61-113`);
  in the page, the row id and the row-click inspector bind it
  (`web/dashboard/src/pages/models/ModelsPage.tsx:500, :510`); row order is
  the server's — sort key/dir pass through to `listModels` (:61) and the
  table runs `sortMode="server"` (:506); chain chips validate targets
  against the loaded registry index (`listAllModels` :80, :85-89).
- **COVERAGE:** the registry list is server-paged at 25/page
  (`web/dashboard/src/pages/models/ModelsPage.tsx:504-505` —
  `pagination="external"` with the served `total`; a URL-restored page
  beyond the served last page steps back :75-77); provider/tier/status
  filters are client-side on the loaded page and labeled as such (AUX-04,
  :127-134, :405-407, :457-461); the registry index walks server pages
  capped at 10×100 (`web/dashboard/src/api/models.ts:47-48, 50`); the 7-day
  stats columns cover the selected org only and stay hidden with a one-line
  reason when no org is selected
  (`web/dashboard/src/pages/models/ModelsPage.tsx:118-124`). Every dashboard
  model attribution joins this registry (the pricing/registry join is the
  reason this catalog is in scope, §1 R3).
- **MISSING-STATE:** `empty` is computed from `!listLoading && !list.error &&
  list.data != null && rows.length === 0`
  (`web/dashboard/src/pages/models/ModelsPage.tsx:365-366`); a list body
  without `data` degrades to an honest empty table, never a fabricated
  registry (`resp.data ?? []` :63); first-load error renders error + retry
  (:488-493) while a failed reload keeps the last good rows with the notice
  above them (:478-483); mutation failures surface as an error notice via
  `setActionError` (:177, :222, :237; rendered :380) and success is a plain
  muted line, not a status banner (:377-379); unavailable stats columns are
  hidden with a reason (:463-471).
- **RETENTION:** live configuration (no retention semantics); the pricing
  columns read the live pricing registry read-only
  (`web/dashboard/src/pages/models/ModelsPage.tsx:91-96`) — pricing
  materialization from the rates catalog is versioned separately (V-19).

---

## 4. Selection-rule proof obligations

- The `Page` union enumerates 36 ids; 20 are bound above and 16 are residual
  — the split is exhaustive and disjoint (`web/dashboard/src/App.tsx:68-80`).
- Every bound view cites at least one concrete source operation (fetch or
  handler) at `file:line` — see section 6 for the mechanical count.
- Views sharing a fetch family (overview/cost/classifier/cache over cost
  analytics; analytics/dashboards over the query engine) intentionally share
  substrate contracts; their differences are window, filters, and rendered
  units, stated per view.

## 5. What this matrix does NOT freeze

- Per-field wire→column lineage: frozen in `field-provenance.md` /
  `field-matrix.md` (CV-00-01/02) and cited, not re-derived.
- The 16 residual views (section 1) and any future route.
- Backend privilege wiring beyond the nav gates cited (handler-level gates
  are cited where they shape a view contract, e.g. V-14).

## 6. Mechanical verification record

Re-verification after the independent-review fixes (V-20 rebound to the
routed `pages/models/ModelsPage.tsx`, citation and count corrections),
executed against the working tree of `task/cv00-03`; the product tree is
identical to the frozen base `34eb9783af26e7780d4ffa8a7c3e2deaf7593428`
(only this document differs).

1. Every citation in this document was extracted and re-checked with this
   grammar: a full citation is a repo-relative path (containing `/` and a
   file extension) immediately followed by `:N` or `:N-M`, optionally with
   comma-separated continuation specs (`:M`, `M`, `M-M`) in the same
   parenthetical; a bare `:N`/`:N-M` (or comma list of `:M`) binds to the
   most recent preceding full citation's path. Each resolved line or range
   counts as one citation instance; distinct anchors are unique
   (file, first-line, last-line) triples. Each anchor was checked: the cited
   file exists and every cited line/range falls inside the file.
   Result: **339 citation instances, 304 distinct (file,line-range) anchors,
   0 bad.**
2. Content spot-verification: the load-bearing lines (state-machine
   definitions, limits/defaults, retention deletes, gate mounts, unit
   formatters) were additionally grep-verified to contain the named symbols
   during authoring — every handler default, page size and window cited in
   sections §2-3 was read from the tree, not from memory. The review-fixed
   facts (V-20 rebinding, §2.2 Overview unknown-money line, V-09
   `formatMoneyCell` import/definition, V-03 window defaults, V-17 threshold
   validation, `Page`-union range) were each re-read from the cited source
   lines after the fix pass.

The `Page`-union split (section 1) was enumerated mechanically: 36 ids in
`web/dashboard/src/App.tsx:68-80`, 20 bound + 16 residual, disjoint and
exhaustive.

## 7. Residual and limits

- Residual views: 16 (section 1) — configuration/account screens and flows.
- Coverage-vs-retention honesty: analytics queries over windows older than
  an org's hot `request_logs` rows under-report silently at the SQL layer;
  the UI surfaces served windows, not retention gaps (tracked as residual
  work with the rollup coverage note in V-10).
- `beta_*` startup views and per-field source selection (raw vs rollup)
  remain specified in the field-matrix/provenance docs.
- This matrix freezes UI-facing contracts only; it does not change behavior,
  endpoints or retention policies.
