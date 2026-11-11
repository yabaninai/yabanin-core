# Frozen independent acceptance — workflow 01: per-user MCP credential administration (MC-4)

Task: **CUI-00-04** (coordination plan `plans/CORE.md`) · base commit `6da73e6` (`6da73e63ec580812204a8e01bd07e9fc3f2e3954`) · frozen 2026-11-11.

**Status: acceptance contract frozen before implementation. Not executed.** This document freezes the independent acceptance for the first unsupported workflow selected from `docs/ui-missing-actions-binding.md`. It contains requirements and verifiable citations only — no test runs, no evidence claims, no fabricated outcomes (per `standards/integration-acceptance.md`). Profile: **IP-SCOPE** (`plans/ui-delivery-20261110/INTEGRATION-PROFILES.json`). Nothing here authorizes the implementation leaf, publication or deployment by itself.

---

## 1. Selection

**Rule (explicit, mechanical).** The binding doc orders its families by ascending MA id; its Family summary table (`docs/ui-missing-actions-binding.md:26-50`), the order of its body sections and the `families` array in `docs/ui-missing-actions-binding.json` (key at `:78`) all carry the same order, so the doc's own ordering is unambiguous and no fallback rule is needed. Walk that order and select the **first family whose actions are all `residual-only`** (verdict rule at `docs/ui-missing-actions-binding.md:20`). Families skipped because they contain `bound-in-full` actions do not qualify.

**Result.**

1. Family 1 `warts/exports-nav` (MA-01, MA-02) — skipped: both rows are `bound-in-full` (`docs/ui-missing-actions-binding.md:56-57`).
2. Family 2 `unavailable/mc-4-user-credentials` (MA-03, MA-04) — **selected**: summary row `docs/ui-missing-actions-binding.md:29` (2 actions, 0 bound, 2 residual), rows `:66-67`, residual notes `:69-70`.

**Selected workflow.** *The operator administers per-user MCP credentials on the dashboard (the MC-4 user-credentials registry): list the masked per-user credential rows for an organization (MA-03) and revoke one row (MA-04).* The two client target endpoints — already coded in the dashboard client, deliberately unregistered server-side — are the workflow's machine contract:

- **MA-03 list** — `GET /api/organizations/{org}/mcp/user-credentials` (client `web/dashboard/src/api/mcpCredentials.ts:142`, path `:145`, `/api` prefix `web/dashboard/src/api/http.ts:33`)
- **MA-04 delete** — `DELETE /api/organizations/{org}/mcp/user-credentials/{server}/{agent_id}` (client `web/dashboard/src/api/mcpCredentials.ts:163`, path `:165`, transport `web/dashboard/src/api/http.ts:36-44`)

No endpoint name is invented by this document: both paths are the existing client's real targets and are already pinned as `unserved` by the drift gate (`services/admin/handlers/ui_actions_inventory_test.go:847-850`).

**Out of scope for this workflow.** Family 3 `unavailable/mc-3-gateway-flows` (MA-05, MA-06 — gateway submit/OAuth begin for the same rows) remains residual for a later leaf (`docs/ui-missing-actions-binding.md:72`); it shares this page's row actions but is the gateway plane, not the admin list/delete plane. The 22 out-of-matrix handlers recorded as an owner follow-up are not absorbed either (`docs/ui-missing-actions-binding.md:9-18`).

## 2. Workflow chain at HEAD `6da73e6`

| Link | Status at HEAD | Citation |
|---|---|---|
| Route registration (page) | present | `web/dashboard/src/App.tsx:64` (lazy import), `:219` (nav entry, root-only gate), `:532` (render) |
| Page caller | present, fail-closed | `web/dashboard/src/pages/McpCredentialsPage.tsx:264`; root gate `:298` and `:516`; org epoch guard `:283-289`; list call `:309`; delete call `:426` |
| API client (list) | present; 404 → `null` → explicit unavailable UI | `web/dashboard/src/api/mcpCredentials.ts:142`, `:145`, `:147`, `:151-154` |
| API client (delete) | present; void result | `web/dashboard/src/api/mcpCredentials.ts:163-166` |
| Admin route + handler | **absent** — `mountMCP` registers servers/grants/MC-1 credential only | `services/admin/handlers/router_mcp.go:12`, `:16-20`, `:47-50`, `:54-56`; unknown `/api/` path answers JSON 404 `services/admin/handlers/router.go:750-759` |
| OpenAPI entries | **absent** — zero `user-credentials` matches in `docs/api/admin.openapi.yaml`; MC-1 shape to follow at `:1640` | — |
| Store methods | present: list + delete + masked columns | `pkg/adminstore/mcpcreds.go:594-596` (list), `:598-601` (org predicate), `:628-630` (delete), `:649-651` (`ErrNotFound`), `:93-99` (masked column set), `:77-91` (row struct) |
| Guard chain (target mount point) | present around `mountMCP` | `services/admin/handlers/router.go:768-780`: session re-validation `:747`, CSRF `:748` (`pkg/adminauth/auth.go:558`), `MustBeRoot` `:770` (`pkg/adminauth/auth.go:466`), `OrgScopeMiddleware` `:777` (`services/admin/handlers/authz.go:323`) |
| Org-scope mutation list | MC-1 pattern present; user-credentials DELETE must join it | `services/admin/handlers/authz.go:295` (`orgScopedPaths`), MC-1 entry `:318`, MCP server entries `:315-316` |
| Producer (row creation) | gateway plane: agent submit + OAuth begin | `pkg/gateway/gateway.go:2011-2012`, `pkg/gateway/mcpcredflow.go:78`, `:120`, `pkg/gateway/mcpcreds.go:828-846` (upsert + audit `:838`) |
| Gateway cache invalidation | version bump contract | `services/admin/handlers/mcp_credentials_handlers.go:264-274`; gateway bumper `pkg/gateway/mcpcreds.go:1146` |
| Orphan hook | grant delete orphans user credentials | `services/admin/handlers/mcp_servers_handlers.go:476` |
| Durable audit sink | hash-chained admin audit journal | `services/admin/handlers/audit_handler.go:97` (`recordAudit`), `:137` (`persistAudit`); read surface `services/admin/handlers/audit_logs.go:75`; producer parity `pkg/gateway/mcpcreds.go:741-759` |
| i18n copy | unavailable + empty + revoke strings pinned | `web/dashboard/src/i18n/en.json:2349` (`userEmpty`), `:2351-2352` (`userUnavailable`/`Details`), `:2356-2357` (`revokeUserConfirm`/`revokeUserImpact`) |
| Drift gates pinning the hole | inventory `unserved` tier + page tests | `services/admin/handlers/ui_actions_inventory_test.go:836-840`, `:847-850`; `web/dashboard/src/pages/r101FailureStates.test.ts:65-76`; `web/dashboard/src/i18n/failureCopy.test.ts:60-61`; nav gate `web/dashboard/src/App.navGates.test.ts:112` |

### 2.1 Baseline behavior observable today (verifiable at HEAD now)

- Both client targets answer `404 {"error":"not found"}` (JSON, not HTML) for authenticated sessions (`services/admin/handlers/router.go:750-759`).
- The list client maps 404 → `null` (`web/dashboard/src/api/mcpCredentials.ts:147`); the page renders the **explicit unavailable notice** — not an empty table, not a spinner (`web/dashboard/src/pages/McpCredentialsPage.tsx:575-580`; copy `web/dashboard/src/i18n/en.json:2351-2352`). The server-credential and grant tables above it stay functional.
- Fail-closed UI: non-root sessions never issue the list call (`web/dashboard/src/pages/McpCredentialsPage.tsx:298`) and see the no-access notice (`:516`).
- Store rows are untouched by the UI path — no list/delete store method is reachable through the admin plane today (absent route; the store methods exist for the gateway plane).

## 3. Frozen target contract

The implementation leaf (separate task; this document freezes acceptance only) must install, without inventing endpoint names:

1. **Routes.** `GET` and `DELETE` on the two client-target paths, mounted inside the `mountRootAdmin` group via `mountMCP` so they inherit the exact guard chain: session re-validation, CSRF, `MustBeRoot`, org scope (`services/admin/handlers/router.go:768-780`; `services/admin/handlers/router_mcp.go:12`).
2. **Org-scope parity.** The DELETE route pattern joins `orgScopedPaths` (`services/admin/handlers/authz.go:295`, pattern parity with the MC-1 entry at `:318`). Root-operator semantics stay as documented: root is an operator over any org; the scope header is an audit hint (`services/admin/handlers/authz.go:335-352`).
3. **Handlers.** List reads via `ListMCPUserCredentials` (`pkg/adminstore/mcpcreds.go:594-596` — org-predicated `:598-601`), delete via `DeleteMCPUserCredential` (`:628-630`) with `ErrNotFound` → 404 parity (`pkg/adminstore/mcpcreds.go:649-651`; error mapping shape `services/admin/handlers/mcp_credentials_handlers.go:236-239`). Store-unwired → 503 parity (`services/admin/handlers/mcp_credentials_handlers.go:90-96`).
4. **Empty list normalization.** An org with zero rows answers `200 []` — never `null` — matching the MC-1-era list parity (`services/admin/handlers/mcp_servers_handlers.go:331-333`), so the client's array check (`web/dashboard/src/api/mcpCredentials.ts:151-154`) renders the empty state (`web/dashboard/src/pages/McpCredentialsPage.tsx:587`), not the unavailable notice.
5. **Wire masking.** The response carries exactly the masked row shape (`pkg/adminstore/mcpcreds.go:77-91`): identity fields plus `secret_last4` and boolean `has_secret` (computed in SQL `:93-99`); secret ciphertext is never selected, never marshaled.
6. **Durable audit.** Every successful delete appends one hash-chained journal entry (resource parity `mcp_user_credential`; producer precedent `pkg/gateway/mcpcreds.go:741-759`, `:864`) with masked details (`services/admin/handlers/mcp_credentials_handlers.go:220-229` is the masking precedent). Operator reason, when collected, rides `X-Audit-Reason` (`services/admin/handlers/audit_handler.go:20`). The current revoke dialog collects no reason (`web/dashboard/src/pages/McpCredentialsPage.tsx:418-430` passes no request options) — reason collection is an optional leaf addition, not a frozen requirement; the audit entry itself is frozen.
7. **Cache invalidation parity.** A successful delete bumps the org's MCP creds version (`services/admin/handlers/mcp_credentials_handlers.go:264-274`; contract `:60-65`), degrading to the documented TTL bound on bump failure — the same contract as MC-1 deletes.
8. **Parity of surfaces.** OpenAPI entries for both paths land in the same change as the routes (today zero `user-credentials` references exist; MC-1 entries at `docs/api/admin.openapi.yaml:1640` are the shape). UI and direct machine clients must expose equivalent scope and facts — no UI-only operation without a documented contract.
9. **Baseline cleanup.** Landing the routes flips the `unserved` inventory tier and the unavailable-state page tests; the leaf must update `services/admin/handlers/ui_actions_inventory_test.go:847-850`, `web/dashboard/src/pages/r101FailureStates.test.ts:65-76` and `web/dashboard/src/i18n/failureCopy.test.ts:60-61` in the same change (they are drift gates, not permanent fixtures). The unavailable copy (`web/dashboard/src/i18n/en.json:2351-2352`) is removed or repurposed with its tests in the same change.

## 4. Frozen acceptance cases (stable IDs — never renumbered)

### 4.1 Baseline (runnable at HEAD today, before any implementation)

| ID | Case | Frozen expected observable effect |
|---|---|---|
| WFA1-B01 | Root session, org A carrying ≥1 produced user-credential row, dashboard MCP credentials page | Server-credential and grant tables populate; the per-user section renders the explicit unavailable notice (`web/dashboard/src/pages/McpCredentialsPage.tsx:575-580`; `web/dashboard/src/i18n/en.json:2351-2352`); the row exists in the store (SQL oracle) and is never displayed, mutated or deleted. |
| WFA1-B02 | Direct machine GET of `…/mcp/user-credentials` with a valid session | `404` with JSON body `{"error":"not found"}` (`services/admin/handlers/router.go:750-759`); no store read (row set unchanged; SQL oracle before/after). |
| WFA1-B03 | Non-root session on the same page | No list request leaves the browser (`web/dashboard/src/pages/McpCredentialsPage.tsx:298`); the no-access notice renders (`web/dashboard/src/pages/McpCredentialsPage.tsx:516`); direct machine GET never reaches the store. |
| WFA1-B04 | Drift gates at HEAD | `services/admin/handlers/ui_actions_inventory_test.go` `unserved` tier holds both endpoints (`services/admin/handlers/ui_actions_inventory_test.go:847-850`); unavailable-branch page tests pass (`web/dashboard/src/pages/r101FailureStates.test.ts:65-76`; `web/dashboard/src/i18n/failureCopy.test.ts:60-61`). These pins are the tripwire that forces baseline cleanup when the leaf lands. |

### 4.2 Positive target (run when the implementation leaf lands)

| ID | Case | Frozen expected observable effect |
|---|---|---|
| WFA1-P01 | **List, tenant-isolated.** IP-SCOPE fixture: orgs A and B, same server display names, unique canary rows (A: 2 rows, B: 1 row). Root lists org A via the dashboard. | 200 array with exactly org A's 2 rows — fields limited to the masked shape (`pkg/adminstore/mcpcreds.go:77-91`, `pkg/adminstore/mcpcreds.go:93-99`); UI table renders exactly those rows; org B's canary appears nowhere (no row, count, tooltip or export). Oracle: read-only SQL `mcp_user_credentials ⋈ mcp_servers` with the org predicate, expected set computed from the fixture manifest. |
| WFA1-P02 | **Masked wire.** Raw response bytes captured at the transport. | Body contains no field outside the masked set; grep for each canary secret's full value and for every 8+-char secret substring yields zero matches; `has_secret` true/false matches the fixture. |
| WFA1-P03 | **Delete via UI.** Root revokes org A row (server S, agent K) through the revoke action. | Typed-name confirmation gate (entity `S/K`, `web/dashboard/src/pages/McpCredentialsPage.tsx:420`; high-risk dialog contract); DELETE returns 2xx; exactly that row disappears from the SQL oracle (org B untouched); the reloaded UI table no longer lists it; audit journal gains one `mcp_user_credential` delete entry with masked details and zero secret material. |
| WFA1-P04 | **Revoke takes effect without restart.** Immediately after P03, the affected agent invokes the gateway using the revoked per-user credential. | The invoke fails at the gateway auth step (auth-required), with no process restart; immediate when the version bump succeeds, bounded by the documented gateway TTL at most when the bump fails (`services/admin/handlers/mcp_credentials_handlers.go:264-274`). Oracle: scripted upstream MCP server with a recipient recorder — zero successful upstream calls after revoke; audit journal records the failure-side entry per existing gateway behavior. |
| WFA1-P05 | **Durable audit.** Read the journal after P03 via read-only SQL and via the admin audit read surface (`services/admin/handlers/audit_logs.go:75`). | Both reads agree: one delete entry, correct org/server/agent identity, masked details, admin identity of the operator, hash chain intact. |
| WFA1-P06 | **UI/machine parity.** Repeat list and delete with an authenticated API client (session cookie + CSRF token), no UI. | Same facts both ways: identical row sets and masked fields; identical delete effect; identical 404/503 error codes and bodies for the negative cases below. OpenAPI documents both paths (`docs/api/admin.openapi.yaml`, MC-1 shape `:1640`). |
| WFA1-P07 | **Cache isolation on delete.** After P03, org B's agent invokes with its own still-valid credential. | Succeeds — org A's version bump invalidated only org A's cache entries; no cross-org cache purge effect. |

### 4.3 Negative controls

| ID | Case | Frozen expected observable effect |
|---|---|---|
| WFA1-N01 | No session: GET and DELETE on both paths. | 401 before any store access; row set unchanged (SQL oracle); no partial audit entry. |
| WFA1-N02 | Authenticated non-root session: GET and DELETE. | 403 at `MustBeRoot` (`pkg/adminauth/auth.go:466`); no store access; no audit entry. |
| WFA1-N03 | Root session, DELETE without CSRF token. | 403 at CSRF validation (`pkg/adminauth/auth.go:558`); row survives (SQL oracle); no audit entry. |
| WFA1-N04 | Cross-tenant probe: list org A, then delete an org B row's (server, agent) coordinates under org A's path. | The org A list never returns org B rows (store org predicate `pkg/adminstore/mcpcreds.go:598-601`); the cross-org delete targets org A coordinates that do not exist → 404 `ErrNotFound` (`pkg/adminstore/mcpcreds.go:649-651`); org B's row survives (SQL oracle). Root's operator reach over any org is by-design (`services/admin/handlers/authz.go:335-352`) and is exercised only through that org's own path in P01/P03. |
| WFA1-N05 | Absent producer: org C with no MCP servers and no rows. | 200 `[]` (nil-normalization parity `services/admin/handlers/mcp_servers_handlers.go:331-333`); UI renders the empty state (`web/dashboard/src/i18n/en.json:2349`), never the unavailable notice and never an error. |
| WFA1-N06 | Partial failure: admin build with the store unwired. | 503 JSON, error parity with MC-1 (`services/admin/handlers/mcp_credentials_handlers.go:90-96`); UI shows the honest error notice with retry (`web/dashboard/src/pages/McpCredentialsPage.tsx:520-521`); no fake empty state. |
| WFA1-N07 | Delete a nonexistent (server, agent) pair. | 404 (`pkg/adminstore/mcpcreds.go:649-651`); row set unchanged; UI surfaces the backend error; no audit entry for a no-op delete. |
| WFA1-N08 | IP-SCOPE delayed old-tenant reply: switch org A → B while A's list is in flight. | The late A reply never renders into B's table — epoch + abort guard (`web/dashboard/src/pages/McpCredentialsPage.tsx:283-289`, guard at `web/dashboard/src/pages/McpCredentialsPage.tsx:311`); B's table shows only B's rows once B's own reply lands. |
| WFA1-N09 | Stale browser URL: deep-link/reload the page with a stale org hash after a delete. | Fresh list for the URL's org; the deleted row does not resurrect (no client cache); a nonexistent org yields the honest error/empty state for that org, never another org's cached rows. |
| WFA1-N10 | Mutation no-retry: force a transport failure after the DELETE reached the server. | The client fires no automatic second DELETE (`web/dashboard/src/api/http.ts:15-20`); a manual retry that arrives after commit sees 404 — the honest terminal state, not a second mutation effect. |

### 4.4 Mutation controls (each must FAIL the named frozen assertion; run in a disposable worktree, never merged)

| ID | Mutant | Must fail |
|---|---|---|
| WFA1-M01 | Remove the org predicate from the list SQL (`pkg/adminstore/mcpcreds.go:598-601`). | WFA1-P01 isolation assertion — foreign canary rows leak into org A's list. |
| WFA1-M02 | Skip the version bump after delete (contract `services/admin/handlers/mcp_credentials_handlers.go:264-274`). | WFA1-P04 — the revoked credential keeps working beyond the documented bound. |
| WFA1-M03 | Skip the audit append on delete. | WFA1-P05 — journal missing the delete entry. |
| WFA1-M04 | Add `secret_ct` to the selected column set (`pkg/adminstore/mcpcreds.go:93-99`). | WFA1-P02 — secret ciphertext appears on the wire. |

## 5. Independent oracle (no self-computed expectations)

- **Fixture DB, read-only**: `psql` role with SELECT only; expected row sets, counts, masked values and org membership are hand-computed from the fixture manifest's inserted canaries (UUIDs, server names, agent ids, secret prefixes chosen by the tester), never from the implementation's output, helpers or the UI under test.
- **Wire capture**: raw HTTP bodies captured at the transport (authenticated API client or logging proxy); mask/field assertions run over raw bytes, not over parsed client types.
- **Durable audit journal**: read via read-only SQL and via the existing admin read surface (`services/admin/handlers/audit_logs.go:75`); the two reads must agree.
- **Outbound effect**: controlled gateway invoke against a scripted upstream MCP server with a recipient recorder; authorized-call counts distinguish valid vs revoked credentials.
- **UI observation**: DOM assertions for notice/empty/table states; every displayed row is cross-checked field-by-field against the SQL oracle.
- **Tamper cursor: N/A, with reason** — the list is unpaginated (no cursor parameter; the client fetches the full list and pages client-side, `web/dashboard/src/pages/McpCredentialsPage.tsx:589`). Recorded as not-applicable rather than silently dropped; the delayed-reply and stale-URL faults (N08/N09) cover the adjacent state-confusion class.
- **Seeds/IDs**: run-specific UUID canaries for orgs, servers, agents and secret prefixes; ≥3 distinct generated seeds for the stateful/isolation cases plus 1 fixed reproducer seed; the independent reviewer adds further permutations when the implementation candidate is built.

## 6. Evidence manifest (per executed run, when the leaf lands)

Per `standards/integration-acceptance.md`: source commit and task base; artifact digest; fixture and oracle hashes; run IDs with exact case counts executed/passed/failed; commands and exit codes (including the negative and mutation runs, with the assertion-failure evidence for M01–M04); raw evidence digests; independent reviewer identity — review of threshold-relevant or security-adjacent behavior by a more capable model than the implementation model, per `standards/maintainability.md` routing. A permissive probe, empty suite or self-computed expected result is a failed run, not a pass.

## 7. Residual scope (explicitly left for later leaves)

- The implementation leaf itself (routes, handlers, OpenAPI, golden/baseline updates, page test flips) — this document freezes its acceptance, not its implementation.
- The remaining 66 residual actions in families 3–23 of binding-doc order (`docs/ui-missing-actions-binding.md:22`, `:26-50`); the next family in order is `unavailable/mc-3-gateway-flows` (`:72`), which shares this page's row actions.
- The 22 out-of-matrix admin handlers — owner follow-up, not absorbed here (`docs/ui-missing-actions-binding.md:9-18`).
- No publication, deployment or licensing change is authorized by this document.

## 8. Citation verification

Every `file:line` citation above was resolved mechanically against worktree `task/cui00-04` at HEAD `6da73e63ec580812204a8e01bd07e9fc3f2e3954`: **62 distinct citations checked, 0 bad**, plus a content re-read of every citation whose target was not already quoted in full during preparation. The absence claims (`services/admin/handlers/router_mcp.go` has no user-credentials route — 0 matches; `docs/api/admin.openapi.yaml` has 0 `user-credentials` references) were verified by exhaustive search over the full files at the same HEAD.
