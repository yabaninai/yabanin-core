# Missing/partial dashboard operator actions — handler/route/spec/client/evidence binding

Task: **CUI-00-03** (coordination plan plans/CORE.md) · base commit `34eb9783af26` · generated 2026-11-11.

This file binds every operator action the accepted grant-scope matrix marks missing or partial on the dashboard to the full existing chain — handler function, route registration, OpenAPI entry, dashboard API client and accepted evidence — or records the residual where a chain link genuinely does not exist. It is documentation only: no endpoint, UI element or permission is invented, and no implementation claim is made.

**Method.** Rows derive from the accepted `ui-grant-scope-matrix` inputs — its 5 warts, its unavailable org-scope rows and its 17 CLI/config-only groups — plus the 4 unavailable records in `ui-capability-matrix`; MA-60..62 (SCIM token admin) and MA-73..75 (policy-packs) come from the task-brief verification set, not the matrix inputs.

**Scope limit (review follow-up).** The binding set is exactly the inputs above. Independent review found 22 further live admin handlers with no dashboard caller that are absent from those inputs and from this enumeration; they are out of scope here and recorded as a follow-up gap for the owner (no binding work done for them in this document):

- org-scoped analytics aggregates ×4 — `services/admin/handlers/router_analytics.go:19-22` (stats, top-models, time-series, error-breakdown)
- cross-org top-orgs aggregate ×1 — `services/admin/handlers/router_audit.go:26`
- routing actual/snapshot views ×2 — `services/admin/handlers/router_models.go:55-56`
- self password change ×1 — `services/admin/handlers/router_console.go:26`
- agent-key delegate + delegations ×4 — `services/admin/handlers/router_keys.go:29,38-40`
- model bump-version ×1 — `services/admin/handlers/router_models.go:34`
- canary-rollouts ×6 — `services/admin/handlers/canary_rollouts.go:114-119`
- security-inbox reads + operator patch ×3 — `services/admin/handlers/security_inbox_handlers.go:551-554`

**Verdict rule.** *bound-in-full*: handler, route, OpenAPI entry, dashboard client and accepted evidence all have citations at HEAD — the operator can drive the action from the dashboard today. *residual-only*: at least one link is absent; the residual names it. Deliberate non-dashboard surfaces (IdP protocol, agent data plane, opt-in portal UI, gateway plane) are recorded as residual with the design disposition named, not as missing implementation.

**Counts.** 75 actions enumerated — **7 bound-in-full**, **68 residual-only**.

## Family summary

| Family | Actions | Bound | Residual |
|---|---|---|---|
| `warts/exports-nav` | 2 | 2 | 0 |
| `unavailable/mc-4-user-credentials` | 2 | 0 | 2 |
| `unavailable/mc-3-gateway-flows` | 2 | 0 | 2 |
| `cli-only/cli-pricing-sync` | 2 | 1 | 1 |
| `cli-only/requests-archive-exports` | 2 | 0 | 2 |
| `warts/guard-packs-cross-gate` | 1 | 1 | 0 |
| `cli-only/cli-service-api` | 3 | 0 | 3 |
| `cli-only/cache-ops` | 6 | 0 | 6 |
| `cli-only/regions-catalog` | 1 | 0 | 1 |
| `cli-only/verticals` | 3 | 0 | 3 |
| `cli-only/templates` | 3 | 0 | 3 |
| `cli-only/retrain-status` | 1 | 0 | 1 |
| `cli-only/inventory` | 3 | 0 | 3 |
| `cli-only/fleet-registry` | 2 | 0 | 2 |
| `cli-only/entitlement-diagnostics` | 1 | 0 | 1 |
| `cli-only/sovereign-marketplace` | 4 | 0 | 4 |
| `cli-only/resale-pricing` | 5 | 0 | 5 |
| `cli-only/root-payload-grants` | 1 | 0 | 1 |
| `cli-only/feedback-data-plane` | 1 | 0 | 1 |
| `cli-only/scim-protocol` | 14 | 0 | 14 |
| `finding/scim-token-admin` | 3 | 0 | 3 |
| `cli-only/developer-portal` | 10 | 0 | 10 |
| `bound/policy-packs` | 3 | 3 | 0 |

## Family `warts/exports-nav`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-01 | Operator reads the org spend alert (exports screen) | `services/admin/handlers/spend_alert_handlers.go:13` | `services/admin/handlers/router_billing.go:58` | `docs/api/admin.openapi.yaml:2110` | `web/dashboard/src/api/budgets.ts:51` | `web/dashboard/src/App.navGates.test.ts:43`;`services/admin/handlers/handler_test.go:2083`;`services/admin/handlers/testdata/routes_admin.golden:182` | **bound-in-full** |
| MA-02 | Operator updates the org spend alert (exports screen) | `services/admin/handlers/spend_alert_handlers.go:31` | `services/admin/handlers/router_billing.go:59` | `docs/api/admin.openapi.yaml:2117` | `web/dashboard/src/api/budgets.ts:60` | `services/admin/handlers/handler_test.go:2086`;`web/dashboard/src/api/exports.ts:19`;`services/admin/handlers/testdata/routes_admin.golden:183` | **bound-in-full** |

- **MA-01** — note: Matrix wart 1: nav gate references budgets.read (App.tsx:163); budgets.read is not a served permission — the wart is documented in App.navGates.test.ts — the item is effectively root-only although the endpoint chain is complete.
- **MA-02** — note: Same wart-1 nav gate as MA-01; both client functions are re-exported through the exports client (exports.ts:18-19).

## Family `unavailable/mc-4-user-credentials`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-03 | Operator lists per-user MCP credentials | — | — | absent | `web/dashboard/src/api/mcpCredentials.ts:142` | `services/admin/handlers/ui_actions_inventory_test.go:848`;`pkg/adminstore/mcpcreds.go:596` | residual-only |
| MA-04 | Operator deletes a per-user MCP credential | — | — | absent | `web/dashboard/src/api/mcpCredentials.ts:163` | `services/admin/handlers/ui_actions_inventory_test.go:849`;`pkg/adminstore/mcpcreds.go:630` | residual-only |

- **MA-03** — residual: handler absent, route absent (deliberately unregistered MC-4 proposal), OpenAPI absent — client and store method already exist — note: The UI renders the explicit unavailable state on JSON 404; the page caller is McpCredentialsPage.tsx (listMcpUserCredentials call).
- **MA-04** — residual: handler absent, route absent, OpenAPI absent — client exists and the store lifecycle methods exist.

## Family `unavailable/mc-3-gateway-flows`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-05 | Agent submits per-user header credential via gateway plane | `pkg/gateway/mcpcredflow.go:78` | `pkg/gateway/gateway.go:2011` | absent — `services/admin/handlers/ui_actions_inventory_test.go:835` | `web/dashboard/src/api/mcpCredentials.ts:174` | `services/admin/handlers/ui_actions_inventory_test.go:835` | residual-only |
| MA-06 | Agent starts per-user OAuth credential flow via gateway plane | `pkg/gateway/mcpcredflow.go:120` | `pkg/gateway/gateway.go:2012` | absent — `services/admin/handlers/ui_actions_inventory_test.go:835` | `web/dashboard/src/api/mcpCredentials.ts:181` | `services/admin/handlers/ui_actions_inventory_test.go:835` | residual-only |

- **MA-05** — residual: OpenAPI entry absent (deliberate gateway-plane exclusion, pinned); dashboard reachability is deployment-dependent (no reverse-proxy decision at HEAD) — note: Mounted under the gateway's /api/mcp group (gateway.go:2011); the dashboard client targets the same path.
- **MA-06** — residual: OpenAPI entry absent (deliberate); dashboard reachability deployment-dependent.

## Family `cli-only/cli-pricing-sync`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-07 | Operator reads the model catalogue (pricing-sync read leg; shared with the models page) | `services/admin/handlers/crud.go:849` | `services/admin/handlers/router_models.go:13` | `docs/api/admin.openapi.yaml:1810` | `web/dashboard/src/api/models.ts:40` | `services/admin/handlers/handler_test.go:2650`;`pkg/trcli/pricing_sync_test.go:44`;`services/admin/handlers/testdata/routes_admin.golden:90` | **bound-in-full** |
| MA-08 | Operator imports/syncs pricing (yb pricing sync) | `services/admin/handlers/pricing_handlers.go:139` | `services/admin/handlers/router_billing.go:64` | `docs/api/admin.openapi.yaml:2795` | absent (neg: `web/dashboard/src` :: `/pricing/import`) | `services/admin/handlers/pricing_handlers_test.go:35`;`pkg/trcli/pricing_sync_test.go:17`;`pkg/trcli/pricing_sync_day0_test.go:28`;`docs/analytics.md:72`;`docs/getting-started-reseller.md:27`;`services/admin/handlers/testdata/routes_admin.golden:220` | residual-only |

- **MA-07** — note: Not dashboard-missing: the models page drives the same endpoint. Bound here because the accepted matrix lists it as the pricing-sync read leg.
- **MA-08** — residual: no dashboard client (CLI-only at HEAD) and the CLI's X-Admin-Key credential is accepted only on /internal (internal_api.go), not on the session-authenticated admin router — matrix wart 3 — note: CLI consumer: pkg/trcli/pricing_sync.go:201 sends the admin header set in pkg/trcli/adminclient.go:21; server-side X-Admin-Key parsing lives in services/admin/handlers/internal_api.go:86 while the admin surface takes sessions (services/admin/handlers/router.go:422).

## Family `cli-only/requests-archive-exports`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-09 | Operator exports org request history | `services/admin/handlers/request_export.go:28` | `services/admin/handlers/router_analytics.go:44` | `docs/api/admin.openapi.yaml:1246` | absent (neg: `web/dashboard/src` :: `/requests/export`) | `services/admin/handlers/request_export_test.go:79`;`services/admin/handlers/testdata/routes_admin.golden:169` | residual-only |
| MA-10 | Operator searches the org request archive | `services/admin/handlers/request_archive_search.go:18` | `services/admin/handlers/router_analytics.go:45` | `docs/api/admin.openapi.yaml:1309` | absent (neg: `web/dashboard/src` :: `/archive-search`) | `services/admin/handlers/request_export_test.go:108`;`services/admin/handlers/testdata/routes_admin.golden:168` | residual-only |

- **MA-09** — residual: registered and OpenAPI-documented but no dashboard caller at HEAD (matrix wart 4) — curl/direct API only.
- **MA-10** — residual: registered and OpenAPI-documented but no dashboard caller at HEAD (matrix wart 4).

## Family `warts/guard-packs-cross-gate`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-11 | Platform security auditor reads the guard-pack activation journal | `services/admin/handlers/audit_logs.go:75` | `services/admin/handlers/router_audit.go:19` | `docs/api/admin.openapi.yaml:1461` | `web/dashboard/src/api/audit.ts:37` | `services/admin/handlers/audit_gate_auth01_test.go:30`;`services/admin/handlers/audit_gate_auth01_test.go:50`;`services/admin/handlers/testdata/routes_admin.golden:54` | **bound-in-full** |

- **MA-11** — note: Matrix wart 5: the server grant is the global audit role (router_audit.go:19) but the guard-packs nav gate is rootOnly (App.tsx:184), so a non-root auditor cannot reach this caller from the dashboard. The guard-pack lifecycle endpoints themselves are bound and are not re-enumerated (guardpacks.go:118-123).

## Family `cli-only/cli-service-api`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-12 | Service reads org API keys (yb keys list) | `services/admin/handlers/internal_api.go:38` | `services/admin/handlers/internal_api.go:29` | `docs/api/admin.openapi.yaml:375` | absent (neg: `web/dashboard/src` :: `/internal/`) | `services/admin/handlers/internal_api_test.go:102`;`docs/cli.md:44`;`services/admin/handlers/testdata/routes_admin.golden:280` | residual-only |
| MA-13 | Service reads org savings analytics (yb spend) | `services/admin/handlers/internal_api.go:61` | `services/admin/handlers/internal_api.go:30` | `docs/api/admin.openapi.yaml:381` | absent (neg: `web/dashboard/src` :: `/internal/`) | `services/admin/handlers/internal_api_test.go:122`;`docs/cli.md:118`;`services/admin/handlers/testdata/routes_admin.golden:279` | residual-only |
| MA-14 | Service reads org cost report | `services/admin/handlers/internal_api.go:88` | `services/admin/handlers/internal_api.go:31` | `docs/api/admin.openapi.yaml:387` | absent (neg: `web/dashboard/src` :: `/internal/`) | `services/admin/handlers/internal_api_test.go:122`;`services/admin/handlers/testdata/routes_admin.golden:278` | residual-only |

- **MA-12** — residual: no dashboard client — root service-key plane (X-Admin-Key), CLI by design at HEAD — note: CLI consumer: pkg/trcli/adminclient.go:93 (yb keys list, docs/cli.md:44).
- **MA-13** — residual: no dashboard client — service-key plane, CLI by design (the session-authenticated twin GET /api/analytics/savings is a different endpoint and IS bound, analytics.ts:95) — note: CLI consumer: pkg/trcli/adminclient.go:108 (yb spend, docs/cli.md:118).
- **MA-14** — residual: no dashboard client and no CLI consumer at HEAD (endpoint + OpenAPI + auth tests exist; unused service plane).

## Family `cli-only/cache-ops`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-15 | Operator flushes the org cache | `services/admin/handlers/cache_handlers.go:96` | `services/admin/handlers/router_ops.go:18` | `docs/api/admin.openapi.yaml:2698` | absent (neg: `web/dashboard/src` :: `/cache/flush`) | `services/admin/handlers/cache_handlers_test.go:133`;`docs/api/cache-admin-api.md:37`;`services/admin/handlers/testdata/routes_admin.golden:60` | residual-only |
| MA-16 | Operator reads cache analytics | `services/admin/handlers/cache_handlers.go:144` | `services/admin/handlers/router_ops.go:19` | `docs/api/admin.openapi.yaml:2704` | absent (neg: `web/dashboard/src` :: `/cache/analytics`) | `services/admin/handlers/cache_handlers_test.go:168`;`docs/api/cache-admin-api.md:42`;`services/admin/handlers/testdata/routes_admin.golden:56` | residual-only |
| MA-17 | Operator warms the cache (deprecated) | `services/admin/handlers/cache_handlers.go:189` | `services/admin/handlers/router_ops.go:20` | `docs/api/admin.openapi.yaml:2710` | absent (neg: `web/dashboard/src` :: `/cache/warm`) | `docs/api/cache-admin-api.md:47`;`services/admin/handlers/testdata/routes_admin.golden:61` | residual-only |
| MA-18 | Operator creates a cache A/B experiment | `services/admin/handlers/cache_handlers.go:269` | `services/admin/handlers/router_ops.go:23` | `docs/api/admin.openapi.yaml:2734` | absent (neg: `web/dashboard/src` :: `/cache/experiments`) | `docs/api/cache-admin-api.md:84`;`services/admin/handlers/testdata/routes_admin.golden:58` | residual-only |
| MA-19 | Operator lists cache experiments | `services/admin/handlers/cache_handlers.go:305` | `services/admin/handlers/router_ops.go:24` | `docs/api/admin.openapi.yaml:2729` | absent (neg: `web/dashboard/src` :: `/cache/experiments`) | `docs/api/cache-admin-api.md:98`;`services/admin/handlers/testdata/routes_admin.golden:57` | residual-only |
| MA-20 | Operator reads cache experiment results | `services/admin/handlers/cache_handlers.go:329` | `services/admin/handlers/router_ops.go:25` | `docs/api/admin.openapi.yaml:2740` | absent (neg: `web/dashboard/src` :: `/cache/experiments`) | `docs/api/cache-admin-api.md:103`;`services/admin/handlers/testdata/routes_admin.golden:59` | residual-only |

- **MA-15** — residual: no dashboard client — CLI/curl operator surface at HEAD.
- **MA-16** — residual: no dashboard client — CLI/curl operator surface at HEAD.
- **MA-17** — residual: no dashboard client — CLI/curl operator surface at HEAD — note: Endpoint is documented as deprecated (docs/api/cache-admin-api.md:47).
- **MA-18** — residual: no dashboard client — CLI/curl operator surface at HEAD — note: No dedicated handler unit test at HEAD; the operator contract is carried by docs/api/cache-admin-api.md.
- **MA-19** — residual: no dashboard client — CLI/curl operator surface at HEAD — note: No dedicated handler unit test at HEAD.
- **MA-20** — residual: no dashboard client — CLI/curl operator surface at HEAD — note: No dedicated handler unit test at HEAD.

## Family `cli-only/regions-catalog`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-21 | Operator reads the region catalogue | `services/admin/handlers/region_handlers.go:94` | `services/admin/handlers/router_ops.go:29` | absent | absent (neg: `web/dashboard/src` :: `/api/regions`) | `services/admin/handlers/testdata/routes_admin.golden:227` | residual-only |

- **MA-21** — residual: no dashboard client and no OpenAPI snapshot entry — note: The org-scoped region endpoints are bound elsewhere (region-settings surface); the global catalogue has no dedicated handler unit test at HEAD (the region tests exercise the org-scoped paths).

## Family `cli-only/verticals`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-22 | Operator lists enabled vertical packs | `services/admin/handlers/vertical_handlers.go:29` | `services/admin/handlers/router_ops.go:36` | `docs/api/admin.openapi.yaml:2843` | absent (neg: `web/dashboard/src` :: `/verticals`) | `services/admin/handlers/vertical_handlers_test.go:29`;`services/admin/handlers/testdata/routes_admin.golden:195` | residual-only |
| MA-23 | Operator enables a vertical pack | `services/admin/handlers/vertical_handlers.go:46` | `services/admin/handlers/router_ops.go:37` | `docs/api/admin.openapi.yaml:2851` | absent (neg: `web/dashboard/src` :: `/verticals`) | `services/admin/handlers/vertical_handlers_test.go:73`;`services/admin/handlers/testdata/routes_admin.golden:197` | residual-only |
| MA-24 | Operator disables a vertical pack | `services/admin/handlers/vertical_handlers.go:83` | `services/admin/handlers/router_ops.go:38` | `docs/api/admin.openapi.yaml:2859` | absent (neg: `web/dashboard/src` :: `/verticals`) | `services/admin/handlers/vertical_handlers_test.go:100`;`services/admin/handlers/testdata/routes_admin.golden:196` | residual-only |

- **MA-22** — residual: no dashboard client — CLI/config surface at HEAD.
- **MA-23** — residual: no dashboard client — CLI/config surface at HEAD.
- **MA-24** — residual: no dashboard client — CLI/config surface at HEAD — note: VerticalHandlers.ListMarketplace (vertical_handlers.go:101) has no route registration at HEAD; it is recorded here because the accepted matrix's sovereign-marketplace group is the mounted marketplace surface.

## Family `cli-only/templates`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-25 | Operator exports the org policy as a template | `services/admin/handlers/policy_template_handlers.go:24` | `services/admin/handlers/router_ops.go:43` | absent | absent (neg: `web/dashboard/src` :: `/templates`) | `services/admin/handlers/policy_template_handlers_test.go:28`;`services/admin/handlers/testdata/routes_admin.golden:193` | residual-only |
| MA-26 | Operator lists marketplace policy templates | `services/admin/handlers/policy_template_handlers.go:60` | `services/admin/handlers/router_ops.go:44` | absent | absent (neg: `web/dashboard/src` :: `/templates`) | `services/admin/handlers/policy_template_handlers_test.go:56`;`services/admin/handlers/testdata/routes_admin.golden:255` | residual-only |
| MA-27 | Operator subscribes the org to a template | `services/admin/handlers/policy_template_handlers.go:74` | `services/admin/handlers/router_ops.go:45` | absent | absent (neg: `web/dashboard/src` :: `/templates`) | `services/admin/handlers/policy_template_handlers_test.go:70`;`services/admin/handlers/testdata/routes_admin.golden:194` | residual-only |

- **MA-25** — residual: no dashboard client and no OpenAPI snapshot entry.
- **MA-26** — residual: no dashboard client and no OpenAPI snapshot entry.
- **MA-27** — residual: no dashboard client and no OpenAPI snapshot entry.

## Family `cli-only/retrain-status`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-28 | Operator reads classifier retrain status | `services/admin/handlers/retrain_handlers.go:40` | `services/admin/handlers/router_ops.go:74` | absent | absent (neg: `web/dashboard/src` :: `/retrain`) | `services/admin/handlers/retrain_handlers_test.go:15`;`services/admin/handlers/retrain_handlers_test.go:29`;`services/admin/handlers/testdata/routes_admin.golden:231` | residual-only |

- **MA-28** — residual: no dashboard client and no OpenAPI snapshot entry.

## Family `cli-only/inventory`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-29 | Operator lists the org registry inventory | `services/admin/handlers/inventory_handlers.go:151` | `services/admin/handlers/router_inventory.go:52` | absent — `docs/api/OPENAPI-DELTA.md:35` | absent (neg: `web/dashboard/src` :: `/inventory`) | `services/admin/handlers/inventory_handlers_test.go:69`;`docs/api/OPENAPI-DELTA.md:35`;`services/admin/handlers/testdata/routes_admin.golden:118` | residual-only |
| MA-30 | Operator imports MCP inventory | `services/admin/handlers/inventory_handlers.go:120` | `services/admin/handlers/router_inventory.go:53` | absent — `docs/api/OPENAPI-DELTA.md:56` | absent (neg: `web/dashboard/src` :: `/inventory`) | `services/admin/handlers/inventory_handlers_test.go:242`;`docs/api/OPENAPI-DELTA.md:56`;`services/admin/handlers/testdata/routes_admin.golden:119` | residual-only |
| MA-31 | Operator imports models from inventory | `services/admin/handlers/inventory_handlers.go:260` | `services/admin/handlers/router_inventory.go:54` | absent — `docs/api/OPENAPI-DELTA.md:117` | absent (neg: `web/dashboard/src` :: `/inventory`) | `services/admin/handlers/inventory_handlers_test.go:336`;`docs/api/OPENAPI-DELTA.md:117`;`services/admin/handlers/testdata/routes_admin.golden:120` | residual-only |

- **MA-29** — residual: no dashboard client; spec carried by OPENAPI-DELTA.md rather than the snapshot.
- **MA-30** — residual: no dashboard client; spec carried by OPENAPI-DELTA.md rather than the snapshot.
- **MA-31** — residual: no dashboard client; spec carried by OPENAPI-DELTA.md rather than the snapshot.

## Family `cli-only/fleet-registry`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-32 | Operator lists fleet installations | `services/admin/handlers/fleet_handlers.go:158` | `services/admin/handlers/fleet_handlers.go:232` | `docs/api/admin.openapi.yaml:878` | absent (neg: `web/dashboard/src` :: `/fleet`) | `services/admin/handlers/fleet_handlers_test.go:107`;`docs/api/OPENAPI-DELTA.md:199`;`services/admin/handlers/testdata/routes_admin.golden:198` | residual-only |
| MA-33 | Operator reads one fleet installation | `services/admin/handlers/fleet_handlers.go:188` | `services/admin/handlers/fleet_handlers.go:233` | `docs/api/admin.openapi.yaml:911` | absent (neg: `web/dashboard/src` :: `/fleet`) | `services/admin/handlers/fleet_handlers_test.go:107`;`docs/api/OPENAPI-DELTA.md:199`;`services/admin/handlers/testdata/routes_admin.golden:199` | residual-only |

- **MA-32** — residual: no dashboard client — read-only root registry surface at HEAD.
- **MA-33** — residual: no dashboard client — read-only root registry surface at HEAD.

## Family `cli-only/entitlement-diagnostics`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-34 | Operator runs entitlement diagnostics | `services/admin/handlers/entitlement_diagnostics_handlers.go:70` | `services/admin/handlers/entitlement_diagnostics_handlers.go:101` | `docs/api/admin.openapi.yaml:352` | absent (neg: `web/dashboard/src` :: `/entitlements`) | `services/admin/handlers/entitlement_diagnostics_handlers_test.go:58`;`services/admin/handlers/entitlement_diagnostics_handlers_test.go:86`;`services/admin/handlers/testdata/routes_admin.golden:65` | residual-only |

- **MA-34** — residual: no dashboard client — operator diagnostics surface at HEAD.

## Family `cli-only/sovereign-marketplace`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-35 | Operator lists sovereign models | `services/admin/handlers/sovereign_handlers.go:25` | `services/admin/handlers/router_models.go:38` | absent | absent (neg: `web/dashboard/src` :: `/sovereign`) | `docs/sovereign-models.md:3`;`services/admin/handlers/testdata/routes_admin.golden:243`;`services/admin/handlers/testdata/routes_admin.golden:244`;`services/admin/handlers/testdata/routes_admin.golden:245`;`services/admin/handlers/testdata/routes_admin.golden:246` | residual-only |
| MA-36 | Operator toggles a sovereign model | `services/admin/handlers/sovereign_handlers.go:39` | `services/admin/handlers/router_models.go:39` | absent | absent (neg: `web/dashboard/src` :: `/sovereign`) | `docs/sovereign-models.md:3`;`services/admin/handlers/testdata/routes_admin.golden:243`;`services/admin/handlers/testdata/routes_admin.golden:244`;`services/admin/handlers/testdata/routes_admin.golden:245`;`services/admin/handlers/testdata/routes_admin.golden:246` | residual-only |
| MA-37 | Operator reads the sovereign policy | `services/admin/handlers/sovereign_handlers.go:60` | `services/admin/handlers/router_models.go:40` | absent | absent (neg: `web/dashboard/src` :: `/sovereign`) | `docs/sovereign-models.md:3`;`services/admin/handlers/testdata/routes_admin.golden:243`;`services/admin/handlers/testdata/routes_admin.golden:244`;`services/admin/handlers/testdata/routes_admin.golden:245`;`services/admin/handlers/testdata/routes_admin.golden:246` | residual-only |
| MA-38 | Operator updates the sovereign policy | `services/admin/handlers/sovereign_handlers.go:77` | `services/admin/handlers/router_models.go:41` | absent | absent (neg: `web/dashboard/src` :: `/sovereign`) | `docs/sovereign-models.md:3`;`services/admin/handlers/testdata/routes_admin.golden:243`;`services/admin/handlers/testdata/routes_admin.golden:244`;`services/admin/handlers/testdata/routes_admin.golden:245`;`services/admin/handlers/testdata/routes_admin.golden:246` | residual-only |

- **MA-35** — residual: no dashboard client and no OpenAPI snapshot entry — note: Routing is pinned by the golden router inventory and the operator contract by docs/sovereign-models.md; no dedicated sovereign handler unit test exists at HEAD (adapters are tested per sovereign_adapters_test.go).
- **MA-36** — residual: no dashboard client and no OpenAPI snapshot entry — note: Routing is pinned by the golden router inventory and the operator contract by docs/sovereign-models.md; no dedicated sovereign handler unit test exists at HEAD (adapters are tested per sovereign_adapters_test.go).
- **MA-37** — residual: no dashboard client and no OpenAPI snapshot entry — note: Routing is pinned by the golden router inventory and the operator contract by docs/sovereign-models.md; no dedicated sovereign handler unit test exists at HEAD (adapters are tested per sovereign_adapters_test.go).
- **MA-38** — residual: no dashboard client and no OpenAPI snapshot entry — note: Routing is pinned by the golden router inventory and the operator contract by docs/sovereign-models.md; no dedicated sovereign handler unit test exists at HEAD (adapters are tested per sovereign_adapters_test.go).

## Family `cli-only/resale-pricing`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-39 | Operator upserts resale pricing | `services/admin/handlers/resale_handlers.go:52` | `services/admin/handlers/router_billing.go:78` | absent | absent (neg: `web/dashboard/src` :: `/resale`) | `services/admin/handlers/resale_handlers_test.go:66`;`docs/getting-started-reseller.md:23`;`services/admin/handlers/testdata/routes_admin.golden:215` | residual-only |
| MA-40 | Operator lists resale pricing | `services/admin/handlers/resale_handlers.go:92` | `services/admin/handlers/router_billing.go:79` | absent | absent (neg: `web/dashboard/src` :: `/resale`) | `services/admin/handlers/resale_handlers_test.go:101`;`docs/getting-started-reseller.md:23`;`services/admin/handlers/testdata/routes_admin.golden:228` | residual-only |
| MA-41 | Operator reads one resale price | `services/admin/handlers/resale_handlers.go:139` | `services/admin/handlers/router_billing.go:80` | absent | absent (neg: `web/dashboard/src` :: `/resale`) | `services/admin/handlers/resale_handlers_test.go:119`;`docs/getting-started-reseller.md:23`;`services/admin/handlers/testdata/routes_admin.golden:230` | residual-only |
| MA-42 | Operator deletes a resale price | `services/admin/handlers/resale_handlers.go:111` | `services/admin/handlers/router_billing.go:81` | absent | absent (neg: `web/dashboard/src` :: `/resale`) | `services/admin/handlers/resale_handlers_test.go:144`;`docs/getting-started-reseller.md:23`;`services/admin/handlers/testdata/routes_admin.golden:229` | residual-only |
| MA-43 | Operator reads an org's resale pricing | `services/admin/handlers/resale_handlers.go:176` | `services/admin/handlers/router_billing.go:82` | absent | absent (neg: `web/dashboard/src` :: `/resale`) | `services/admin/handlers/resale_handlers_test.go:157`;`docs/getting-started-reseller.md:23`;`services/admin/handlers/testdata/routes_admin.golden:214` | residual-only |

- **MA-39** — residual: no dashboard client and no OpenAPI snapshot entry (integration variants also cover the handlers).
- **MA-40** — residual: no dashboard client and no OpenAPI snapshot entry (integration variants also cover the handlers).
- **MA-41** — residual: no dashboard client and no OpenAPI snapshot entry (integration variants also cover the handlers).
- **MA-42** — residual: no dashboard client and no OpenAPI snapshot entry (integration variants also cover the handlers).
- **MA-43** — residual: no dashboard client and no OpenAPI snapshot entry (integration variants also cover the handlers).

## Family `cli-only/root-payload-grants`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-44 | Root operator self-grants a single-use payload grant | `services/admin/handlers/request_payload_grants.go:25` | `services/admin/handlers/router_console.go:33` | `docs/api/admin.openapi.yaml:1397` | absent (neg: `web/dashboard/src` :: `/payload-grants`) | `services/admin/handlers/request_payload_grants_test.go:97`;`services/admin/handlers/request_payload_grants_test.go:152`;`services/admin/handlers/testdata/routes_admin.golden:232` | residual-only |

- **MA-44** — residual: no dashboard client — root console surface at HEAD.

## Family `cli-only/feedback-data-plane`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-45 | Agent submits classifier feedback (data plane) | `services/admin/handlers/feedback_handler.go:35` | `services/admin/handlers/router_ops.go:85` | absent — `services/admin/handlers/routes_contract_matrix_test.go:33` | absent — no client function performs the POST — only comments and i18 | `services/admin/handlers/routes_contract_matrix_test.go:33`;`services/admin/handlers/routes_contract_matrix_test.go:133`;`web/dashboard/src/api/feedback.ts:39`;`services/admin/handlers/testdata/routes_admin.golden:303` | residual-only |

- **MA-45** — residual: no dashboard/CLI client by design (agent data plane; only i18n descriptions reference it); collector enablement is config-gated, not an endpoint — note: The admin read side (GET /api/feedback) IS bound on the dashboard (feedback.ts) — this row binds only the data-plane submit.

## Family `cli-only/scim-protocol`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-46 | IdP discovers SCIM service provider config | `services/admin/handlers/scim.go:544` | `services/admin/handlers/router_scim.go:23` | `docs/api/admin.openapi.yaml:1043` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:845`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:296` | residual-only |
| MA-47 | IdP discovers SCIM schemas | `services/admin/handlers/scim.go:672` | `services/admin/handlers/router_scim.go:26` | `docs/api/admin.openapi.yaml:1049` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:1033`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:295` | residual-only |
| MA-48 | IdP discovers SCIM resource types | `services/admin/handlers/scim.go:698` | `services/admin/handlers/router_scim.go:27` | `docs/api/admin.openapi.yaml:1055` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:1089`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:294` | residual-only |
| MA-49 | IdP lists users | `services/admin/handlers/scim.go:769` | `services/admin/handlers/router_scim.go:29` | `docs/api/admin.openapi.yaml:1061` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:927`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:297` | residual-only |
| MA-50 | IdP creates a user | `services/admin/handlers/scim.go:856` | `services/admin/handlers/router_scim.go:30` | `docs/api/admin.openapi.yaml:1066` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:395`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:298` | residual-only |
| MA-51 | IdP reads a user | `services/admin/handlers/scim.go:886` | `services/admin/handlers/router_scim.go:31` | `docs/api/admin.openapi.yaml:1074` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:895`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:300` | residual-only |
| MA-52 | IdP replaces a user | `services/admin/handlers/scim.go:903` | `services/admin/handlers/router_scim.go:32` | `docs/api/admin.openapi.yaml:1083` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:490`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:302` | residual-only |
| MA-53 | IdP patches a user | `services/admin/handlers/scim.go:953` | `services/admin/handlers/router_scim.go:33` | `docs/api/admin.openapi.yaml:1092` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:460`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:301` | residual-only |
| MA-54 | IdP deactivates a user | `services/admin/handlers/scim.go:1077` | `services/admin/handlers/router_scim.go:34` | `docs/api/admin.openapi.yaml:1101` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:516`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:299` | residual-only |
| MA-55 | IdP lists groups | `services/admin/handlers/scim.go:1128` | `services/admin/handlers/router_scim.go:36` | `docs/api/admin.openapi.yaml:1111` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:1001`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:289` | residual-only |
| MA-56 | IdP creates a group | `services/admin/handlers/scim.go:1177` | `services/admin/handlers/router_scim.go:37` | `docs/api/admin.openapi.yaml:1116` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:559`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:290` | residual-only |
| MA-57 | IdP reads a group | `services/admin/handlers/scim.go:1154` | `services/admin/handlers/router_scim.go:38` | `docs/api/admin.openapi.yaml:1124` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:1263`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:292` | residual-only |
| MA-58 | IdP patches a group | `services/admin/handlers/scim.go:1217` | `services/admin/handlers/router_scim.go:39` | `docs/api/admin.openapi.yaml:1133` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:559`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:293` | residual-only |
| MA-59 | IdP deletes a group | `services/admin/handlers/scim.go:1341` | `services/admin/handlers/router_scim.go:40` | `docs/api/admin.openapi.yaml:1142` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:895`;`docs/security.md:17`;`services/admin/handlers/testdata/routes_admin.golden:291` | residual-only |

- **MA-46** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-47** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-48** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-49** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-50** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17) — note: End-to-end token mint to user create is pinned by scim_deploy_int_test.go:56.
- **MA-51** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-52** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-53** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-54** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-55** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-56** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-57** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-58** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).
- **MA-59** — residual: no dashboard client — customer-IdP-driven protocol by design (bearer-authenticated provisioning server, docs/security.md:17).

## Family `finding/scim-token-admin`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-60 | Operator issues a SCIM provisioning token | `services/admin/handlers/scim_tokens_admin.go:28` | `services/admin/handlers/router_scim.go:49` | `docs/api/admin.openapi.yaml:1022` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_deploy_int_test.go:56`;`services/admin/handlers/testdata/routes_admin.golden:177` | residual-only |
| MA-61 | Operator lists SCIM tokens | `services/admin/handlers/scim_tokens_admin.go:66` | `services/admin/handlers/router_scim.go:48` | `docs/api/admin.openapi.yaml:1015` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:674`;`services/admin/handlers/testdata/routes_admin.golden:176` | residual-only |
| MA-62 | Operator revokes a SCIM token | `services/admin/handlers/scim_tokens_admin.go:88` | `services/admin/handlers/router_scim.go:50` | `docs/api/admin.openapi.yaml:1031` | absent (neg: `web/dashboard/src` :: `scim`) | `services/admin/handlers/scim_test.go:674`;`services/admin/handlers/testdata/routes_admin.golden:178` | residual-only |

- **MA-60** — residual: registered, permission-gated (members.manage, router_scim.go:47) and OpenAPI-documented, but NO dashboard or CLI caller exists at HEAD — operator token lifecycle is curl-only — note: Verified by exhaustive case-insensitive search: zero 'scim' references anywhere in web/dashboard/src and pkg/trcli.
- **MA-61** — residual: registered, permission-gated (members.manage, router_scim.go:47) and OpenAPI-documented, but NO dashboard or CLI caller exists at HEAD — operator token lifecycle is curl-only — note: Verified by exhaustive case-insensitive search: zero 'scim' references anywhere in web/dashboard/src and pkg/trcli.
- **MA-62** — residual: registered, permission-gated (members.manage, router_scim.go:47) and OpenAPI-documented, but NO dashboard or CLI caller exists at HEAD — operator token lifecycle is curl-only — note: Verified by exhaustive case-insensitive search: zero 'scim' references anywhere in web/dashboard/src and pkg/trcli.

## Family `cli-only/developer-portal`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-63 | Developer starts OIDC login | `services/admin/handlers/portal.go:94` | `services/admin/handlers/router_portal.go:17` | `docs/api/admin.openapi.yaml:217` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_test.go:18`;`services/admin/handlers/testdata/routes_admin.golden:287` | residual-only |
| MA-64 | Developer completes OIDC callback | `services/admin/handlers/portal.go:117` | `services/admin/handlers/router_portal.go:18` | `docs/api/admin.openapi.yaml:224` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_test.go:18`;`services/admin/handlers/testdata/routes_admin.golden:284` | residual-only |
| MA-65 | Developer opens the portal home page | `services/admin/handlers/portal_page.go:179` | `services/admin/handlers/router_portal.go:19` | `docs/api/admin.openapi.yaml:231` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_page_test.go:16`;`services/admin/handlers/testdata/routes_admin.golden:283` | residual-only |
| MA-66 | Developer creates a personal key (page flow) | `services/admin/handlers/portal_page.go:186` | `services/admin/handlers/router_portal.go:20` | `docs/api/admin.openapi.yaml:238` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_page_test.go:28`;`services/admin/handlers/testdata/routes_admin.golden:285` | residual-only |
| MA-67 | Developer revokes a key (page flow) | `services/admin/handlers/portal_page.go:209` | `services/admin/handlers/router_portal.go:21` | `docs/api/admin.openapi.yaml:245` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_page_test.go:28`;`services/admin/handlers/testdata/routes_admin.golden:286` | residual-only |
| MA-68 | Developer logs out of the portal | `services/admin/handlers/portal.go:241` | `services/admin/handlers/router_portal.go:23` | `docs/api/admin.openapi.yaml:256` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_page_test.go:108`;`services/admin/handlers/testdata/routes_admin.golden:288` | residual-only |
| MA-69 | Developer reads own profile | `services/admin/handlers/portal.go:262` | `services/admin/handlers/router_portal.go:24` | `docs/api/admin.openapi.yaml:262` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_test.go:101`;`services/admin/handlers/testdata/routes_admin.golden:80` | residual-only |
| MA-70 | Developer lists own keys | `services/admin/handlers/portal.go:278` | `services/admin/handlers/router_portal.go:25` | `docs/api/admin.openapi.yaml:268` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_test.go:101`;`services/admin/handlers/testdata/routes_admin.golden:81` | residual-only |
| MA-71 | Developer creates a key (JSON API) | `services/admin/handlers/portal.go:332` | `services/admin/handlers/router_portal.go:26` | `docs/api/admin.openapi.yaml:273` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_test.go:101`;`services/admin/handlers/testdata/routes_admin.golden:82` | residual-only |
| MA-72 | Developer deletes a key (JSON API) | `services/admin/handlers/portal.go:365` | `services/admin/handlers/router_portal.go:27` | `docs/api/admin.openapi.yaml:279` | absent — no dashboard API client — the portal is its own server-rende | `services/admin/handlers/portal_test.go:101`;`services/admin/handlers/testdata/routes_admin.golden:83` | residual-only |

- **MA-63** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-64** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-65** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-66** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-67** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-68** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-69** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-70** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-71** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.
- **MA-72** — residual: not a dashboard surface — opt-in developer portal UI by design; the dashboard does not duplicate these actions.

## Family `bound/policy-packs`

| ID | Action | Handler | Route | OpenAPI | Dashboard client | Evidence | Verdict |
|---|---|---|---|---|---|---|---|
| MA-73 | Operator lists policy packs | `services/admin/handlers/policy_pack_handlers.go:45` | `services/admin/handlers/router_orgs.go:70` | `docs/api/admin.openapi.yaml:2036` | `web/dashboard/src/api/orgSettings.ts:198` | `services/admin/handlers/policy_pack_handlers_test.go:180`;`services/admin/handlers/testdata/routes_admin.golden:156` | **bound-in-full** |
| MA-74 | Operator upserts a policy pack | `services/admin/handlers/policy_pack_handlers.go:98` | `services/admin/handlers/router_orgs.go:71` | `docs/api/admin.openapi.yaml:2044` | `web/dashboard/src/api/orgSettings.ts:211` | `services/admin/handlers/policy_pack_handlers_test.go:151`;`services/admin/handlers/policy_pack_handlers_test.go:142`;`services/admin/handlers/policy_pack_handlers_test.go:167`;`services/admin/handlers/testdata/routes_admin.golden:158` | **bound-in-full** |
| MA-75 | Operator deletes a policy pack | `services/admin/handlers/policy_pack_handlers.go:159` | `services/admin/handlers/router_orgs.go:72` | `docs/api/admin.openapi.yaml:2053` | `web/dashboard/src/api/orgSettings.ts:219` | `web/dashboard/src/pages/OrgSettingsPage.tsx:413`;`services/admin/handlers/router_orgs.go:72`;`services/admin/handlers/testdata/routes_admin.golden:157` | **bound-in-full** |

- **MA-73** — note: Task-brief example correction: policy-pack editing is NOT CLI-only at this base — OrgSettingsPage drives all three operations through orgSettings.ts.
- **MA-75** — note: No dedicated DELETE handler unit test at HEAD; the binding cites the verified page caller and the route registration.

## Scope notes

- **MC-1 admin server credentials are bound and not re-enumerated**: router_mcp.go lines 54-56 mount GET/PUT/DELETE with the McpCredentialsPage callers; handler tests at mcp_credentials_handlers_test.go:138.
- **Guard-pack lifecycle operations are bound and not re-enumerated**: guardpacks.go lines 118-123; only the cross-gate journal read (MA-11) carries wart 5.
- **GET /api/models is shared**: the models page drives it (MA-07); it is bound here only as the pricing-sync read leg.
- **Task-brief example correction**: `policy-pack editing CLI-only` does not hold at this base — MA-73..75 bind the complete dashboard chain (orgSettings.ts clients, OrgSettingsPage callers).
- **SCIM token lifecycle (MA-60..62) is a finding**: registered, permission-gated and documented, yet no dashboard or CLI caller exists at HEAD (verified by case-insensitive search over web/dashboard/src and pkg/trcli).
- **VerticalHandlers.ListMarketplace** (vertical_handlers.go:101) has no route registration at HEAD; the mounted marketplace surface is the sovereign-marketplace group.

## Citation verification

All file:line citations in this document and its JSON mirror were resolved mechanically from the source at the recorded base commit and re-verified line-by-line (file exists, line in range, expected content at the line, negative checks re-run). Per the convention established for `ui-grant-scope-matrix.md`, the checker itself is kept outside this repository.

## Evidence durability

The base-reproduction logs behind the recorded pre-existing GO-2026-6859 gate failures were verified present in scratch and copied into this worktree's gitignored `artifacts/quality/cui-00-03-base-repro/` (hashes recorded here; raw logs stay out of Git):

- `base-security.log` — sha256 `c1fa5d1d384c221bc49d18c95ae8b1db10a4e035d85fb50dd342bd5c3c008404` — `go mod verify` clean; govulncheck disposition scan BLOCKED (`analyze-security` Error 3) on GO-2026-6859 REACHABLE findings; GO-2026-6909 NOT_AFFECTED; SAML disposition expires 2026-12-09.
- `base-deps.log` — sha256 `cf580c6b43bf48ea67392ae9253c55a6419223aec4b3f15c13c4795405007a8e` — dependency audit: 7 govulncheck module failures (reachable GO-2026-6859); trivy high/critical 0.

