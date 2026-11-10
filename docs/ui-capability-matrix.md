# Admin capability matrix — CUI-00-01 source audit

Static reconciliation of every route registration on the Yabanin admin service
against the published OpenAPI snapshot and the dashboard client surface.
The authoritative full record set is `docs/ui-capability-matrix.json`;
this file is the human-readable summary and the drift register.

## Sources and method

- Product tree: `yabanin-core` worktree `/home/ubuntu/dev/core-cui00-a`, branch `task/cui00-01`, task base `ffc01005dfde91953161ea02b96feae8756c0e1c`.
- Routes: every `Get/Post/Put/Patch/Delete/Method/Handle` registration literal in `services/admin/handlers/*.go` (303 registration sites, 301 unique method+path pairs).
  Normalizations: `router_console.go:33` `.Method(http.MethodPost, …)` counted as POST; `router_public.go:71` `/metrics` `Handle` + GET/HEAD guard counted as GET; the `/auth` subrouter literals (`/login`, `/logout`, `/csrf`, `/ee/session`) expanded to their mounted paths.
- OpenAPI: `docs/api/admin.openapi.yaml` — 273 operations across 183 paths, all with `operationId` (byte-frozen spec; deltas live in `docs/api/OPENAPI-DELTA.md`).
- UI: `web/dashboard/src/App.tsx` (36 hash routes, nav access gates) and `web/dashboard/src/api/*.ts` (endpoint call sites, path-template matched; best effort at path level).
- Guards: derived from the mount call graph in `router.go` (protected group = session+CSRF; `mountRootAdmin` group = MustBeRoot + S01 org scope) plus each domain mount's `With(...)` gates.
- No requests were executed against a running server (static audit — see Limits).

## State definitions

| state | meaning |
|---|---|
| `verified` | registered on the admin router AND present in the OpenAPI snapshot (source-level consistency only — workflow acceptance unverified) |
| `partial` | registered but absent from the snapshot; the registration is authoritative. Includes conditional registrations |
| `missing` | in the snapshot but not registered (stale spec) — **none found** |
| `protocol_only` | transport/protocol/health/data-plane endpoint excluded from the admin capability surface (per-entry reason below) |
| `unavailable` | surface referenced by the dashboard (or gateway) with no admin-route registration |

## Summary

| metric | value |
|---|---|
| route registration sites | 303 |
| unique method+path pairs | 301 |
| capability records (incl. 4 UI/gateway-only) | 307 |
| OpenAPI operations | 273 |
| snapshot ops with no registration (stale spec) | 0 |
| registered but absent from snapshot | 28 (18 admin-scope, 10 protocol/transport) |
| states | `partial` 19, `protocol_only` 36, `unavailable` 4, `verified` 248 |
| snapshot ops covered by a registration | 273 of 273 |
| registration records carrying an operationId | 274 (GET /api/me is covered by both its mounts, see R4) |

Reconciliation identity: 248 `verified` + 26 `protocol_only` records carry
operationIds and cover all 273 distinct snapshot operations exactly, except
`GET /api/me`, which two mounts cover (R4). The remaining 10 `protocol_only`
entries (metrics, OIDC×2, SAML×5, EE session, `/v1/feedback`) and 18 `partial` pairs are
registered but undocumented.

## Drift register

### R1 — 15 admin operations absent from the frozen OpenAPI snapshot

All registered (registration wins), none documented in `admin.openapi.yaml` or
`OPENAPI-DELTA.md`. Families: sovereign marketplace (4), reseller/resale pricing (5),
region list (1), policy-template marketplace (3), retrain status (1), feedback
export (1). Full list with `handler_ref` in the JSON (`state: "partial"`).
Suggested leaf: one spec-delta update in `docs/api/OPENAPI-DELTA.md`.

### R2 — Inventory trio documented only in the delta record

`GET /api/organizations/{id}/inventory`, `POST …/inventory/import/mcp`,
`POST …/inventory/import/models` are registered (root-only, `SetInventory`-gated)
and documented in `OPENAPI-DELTA.md` (2026-11-07) rather than the frozen snapshot —
known, deliberate drift; recorded as `partial` with `spec_delta` evidence.

### R3 — Dual registration of `GET /api/feedback/export`

Two conditionally-exclusive wirings register the same method+path:
`router_ops.go:50` (inline closure over `feedback.exporter`; JSON envelope) and
`router_ops.go:69` (`h.ExportFeedbackHandler()` over `feedback.lister`; CSV).
chi v5.5.0 does not panic on the overlap — if both dependencies were ever wired
simultaneously the later registration would silently win. Distinct response shapes
for one path is a contract hazard worth resolving in a follow-up leaf.

### R4 — Dual mount of `GET /api/me` (by design)

`router_console.go:22` `h.Me()` (admin session) and `router_portal.go:24`
`h.PortalMe()` (portal session) share the path on different subrouters; the
snapshot has a single `me` operation. Both records are kept with their distinct
grant scopes; no action needed beyond keeping both documented.

### R5 — MCP user-credentials: dashboard calls with no admin route

`mcpCredentials.ts` calls `GET`/`DELETE /api/organizations/{id}/mcp/user-credentials`.
No admin route mounts them (verified across `services/`); the store method
(`adminstore.Store.ListMCPUserCredentials`) exists and the client renders an honest
"endpoint not available" state on 404. Recorded as `unavailable` (cap-u01/u02);
suggested leaf: mount the read root-only+S01 or retire the client call.

### R6 — Dashboard depends on gateway agent-principal MCP flows

The same page exposes `POST /api/mcp/credentials/{server}` and
`POST /api/mcp/auth/{server}/begin` (`pkg/gateway/mcpcredflow.go`, mounted in
`pkg/gateway/gateway.go:2018`). These are gateway (yag_ principal) surfaces, not
admin routes; reachability from the dashboard origin is deployment-dependent and
the client fails honestly when unproxied (`unavailable`, cap-u03/u04). Needs an
explicit proxy decision; flagged for CUI-00-02 scope mapping.

### R7 — Nav gates are consistent with root-only mounts (positive)

Every root-only endpoint family consumed by the dashboard is reached only from
`rootOnly`-gated nav items (`cost`, `dashboards`, `tool-calls`, `compare`, `cache`,
`classifier`, `overview`), and org-permission-gated clients map to `anyOrg` items.
The full grant×page×endpoint mapping remains CUI-00-02 work; nothing observed here
contradicts it.

### R8 — Snapshot hygiene (positive)

Zero stale operations: every one of the 273 snapshot operations has a live
registration. The drift is entirely in the undocumented-registered direction (R1/R2).

## Protocol-only exclusions (36)

| method | path | reason |
|---|---|---|
| GET | `/` | admin dashboard HTML shell (UI transport) |
| GET | `/auth/csrf` | browser session transport (login/logout/CSRF) |
| POST | `/auth/ee/session` | EE internal session bootstrap (transport) |
| GET | `/auth/login` | browser session transport (login/logout/CSRF) |
| POST | `/auth/login` | browser session transport (login/logout/CSRF) |
| GET | `/auth/logout` | browser session transport (login/logout/CSRF) |
| POST | `/auth/logout` | browser session transport (login/logout/CSRF) |
| GET | `/auth/oidc/callback` | SSO protocol redirect flow (conditional on OIDC config) |
| GET | `/auth/oidc/login` | SSO protocol redirect flow (conditional on OIDC config) |
| POST | `/auth/saml/acs` | SSO protocol flow (conditional on SAML config) |
| GET | `/auth/saml/login` | SSO protocol flow (conditional on SAML config) |
| GET | `/auth/saml/metadata` | SSO protocol flow (conditional on SAML config) |
| GET | `/auth/saml/slo` | SSO protocol flow (conditional on SAML config) |
| POST | `/auth/saml/slo` | SSO protocol flow (conditional on SAML config) |
| GET | `/health` | liveness probe; not an admin capability |
| GET | `/internal/analytics/cost` | service-to-service read API (internal key; CLI/automation) |
| GET | `/internal/analytics/savings` | service-to-service read API (internal key; CLI/automation) |
| GET | `/internal/api-keys` | service-to-service read API (internal key; CLI/automation) |
| GET | `/invite/{token}` | invite acceptance flow (public token) |
| POST | `/invite/{token}` | invite acceptance flow (public token) |
| GET | `/metrics` | ops metrics (bearer token, GET/HEAD) |
| GET | `/scim/v2/Groups` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| POST | `/scim/v2/Groups` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| DELETE | `/scim/v2/Groups/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| GET | `/scim/v2/Groups/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| PATCH | `/scim/v2/Groups/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| GET | `/scim/v2/ResourceTypes` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| GET | `/scim/v2/Schemas` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| GET | `/scim/v2/ServiceProviderConfig` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| GET | `/scim/v2/Users` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| POST | `/scim/v2/Users` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| DELETE | `/scim/v2/Users/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| GET | `/scim/v2/Users/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| PATCH | `/scim/v2/Users/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| PUT | `/scim/v2/Users/{id}` | SCIM protocol server (IdP principal; admin surface is …/scim/tokens) |
| POST | `/v1/feedback` | public agent feedback ingest (data plane; API-key auth) |

## Partial records (19 registration sites / 18 unique pairs)

| method | path | handler_ref | spec delta |
|---|---|---|---|
| GET | `/api/feedback/export` | `services/admin/handlers/router_ops.go:50` | — |
| GET | `/api/feedback/export` | `services/admin/handlers/router_ops.go:69` | — |
| GET | `/api/organizations/{id}/inventory` | `services/admin/handlers/router_inventory.go:52` | OPENAPI-DELTA.md 2026-11-07 INVENTORY-LIST |
| POST | `/api/organizations/{id}/inventory/import/mcp` | `services/admin/handlers/router_inventory.go:53` | OPENAPI-DELTA.md 2026-11-07 INVENTORY-IMPORT |
| POST | `/api/organizations/{id}/inventory/import/models` | `services/admin/handlers/router_inventory.go:54` | OPENAPI-DELTA.md 2026-11-07 INVENTORY-MODELS-IMPORT |
| POST | `/api/organizations/{orgID}/templates/export` | `services/admin/handlers/router_ops.go:43` | — |
| PUT | `/api/organizations/{orgID}/templates/{templateID}/subscribe` | `services/admin/handlers/router_ops.go:45` | — |
| GET | `/api/orgs/{id}/resale-pricing` | `services/admin/handlers/router_billing.go:82` | — |
| PUT | `/api/orgs/{id}/resale-pricing` | `services/admin/handlers/router_billing.go:78` | — |
| GET | `/api/regions` | `services/admin/handlers/router_ops.go:29` | — |
| GET | `/api/reseller-pricing` | `services/admin/handlers/router_billing.go:79` | — |
| DELETE | `/api/reseller-pricing/{id}` | `services/admin/handlers/router_billing.go:81` | — |
| GET | `/api/reseller-pricing/{id}` | `services/admin/handlers/router_billing.go:80` | — |
| GET | `/api/retrain/status` | `services/admin/handlers/router_ops.go:74` | — |
| GET | `/api/sovereign/models` | `services/admin/handlers/router_models.go:38` | — |
| PUT | `/api/sovereign/models/{name}` | `services/admin/handlers/router_models.go:39` | — |
| GET | `/api/sovereign/policy/{org_id}` | `services/admin/handlers/router_models.go:40` | — |
| PUT | `/api/sovereign/policy/{org_id}` | `services/admin/handlers/router_models.go:41` | — |
| GET | `/api/templates/marketplace` | `services/admin/handlers/router_ops.go:44` | — |

## Unavailable records (4)

| id | method | path | why |
|---|---|---|---|
| cap-u01-GET-api-organizations-id-mcp-user-credentials | GET | `/api/organizations/{id}/mcp/user-credentials` | no admin route; store method exists |
| cap-u02-DELETE-api-organizations-id-mcp-user-credentials-server-agent | DELETE | `/api/organizations/{id}/mcp/user-credentials/{server}/{agentId}` | no admin route; store method exists |
| cap-u03-POST-api-mcp-credentials-server | POST | `/api/mcp/credentials/{server}` | gateway surface, not an admin route |
| cap-u04-POST-api-mcp-auth-server-begin | POST | `/api/mcp/auth/{server}/begin` | gateway surface, not an admin route |

## Capability families (all 307 records)

| mount (guard family) | records | states |
|---|---|---|
| `mountMCP` — MCP servers, grants, credentials, tool policies, A2A agents (root-only + S01; 503 without DB) | 25 | verified 25 |
| `mountOrgsRoot` — Root-only org CRUD/settings (retention, residency, cache-settings, region, verticals, templates) | 24 | verified 24 |
| `mountModels` — Models, aliases, routing rules, version bumps, sovereign marketplace (root-only) | 20 | partial 4, verified 16 |
| `mountOps` — Root-only ops (cache, experiments, regions, verticals, templates, feedback export, retrain) | 19 | partial 7, verified 12 |
| `mountKeys` — Org key management (keys.manage / agent-keys.manage) | 18 | verified 18 |
| `mountAnalytics` — Org analytics (analytics.read) + label policy (policies.manage) | 17 | verified 17 |
| `mountPublic` — Public session transport (/health, /metrics, /auth login/logout/CSRF/OIDC/SAML, /invite) | 17 | protocol_only 17 |
| `mountBillingRoot` — Root-only billing (spend alerts, pricing, reseller credits, resale pricing) | 15 | partial 5, verified 10 |
| `mountOrgs` — Org members/invites/whitelists (members.manage; developers need portal store) | 14 | verified 14 |
| `mountSCIM` — SCIM v2 protocol server (IdP principal, bearer token) | 14 | protocol_only 14 |
| `mountKeysRoot` — Root-only key operations (rotate-all, expiry sweeps, ...) | 11 | verified 11 |
| `mountPortal` — Developer portal (opt-in): SSO pages + self-service key lifecycle | 10 | verified 10 |
| `mountPromptStudio` — Prompt studio (policies.manage) | 10 | verified 10 |
| `mountConsole` — Console session surface (/api/me, version, client-config, dashboard shell, root payload-grants) | 8 | protocol_only 1, verified 7 |
| `mountExplorer` — Request explorer (requests.read) + lineage (lineage.read/verify) | 8 | verified 8 |
| `mountAnalyticsRoot` — Root-only analytics aggregates (tool-calls, cache/cost per org, savings, shadow, quality) | 7 | verified 7 |
| `mountPolicyPipelines` — Policy pipelines (policies.manage) | 7 | verified 7 |
| `mountCurrenciesRoutes` — Currencies/units/rates (in-handler org gates) | 6 | verified 6 |
| `mountGuard` — Guard packs lifecycle (root-only) | 6 | verified 6 |
| `mountCanaryRollouts` — Canary rollouts (routing.manage) | 6 | verified 6 |
| `mountBilling` — Org budgets (budgets.manage) + credits reads (credits.read) | 6 | verified 6 |
| `mountOrgCredentials` — Org provider credentials BYOK (keys.manage variant) | 6 | verified 6 |
| `mountOrgBudgetSettingsRoutes` — Org budget settings (in-handler org gates) | 4 | verified 4 |
| `mountRoutingViews` — Org routing views (in-handler org gates) | 4 | verified 4 |
| `UI/gateway-only (no admin route)` —  | 4 | unavailable 4 |
| `mountInventory` — Asset registry inventory (root-only; delta-documented) | 3 | partial 3 |
| `mountSCIMAdmin` — SCIM token issue/list/revoke (members.manage) | 3 | verified 3 |
| `mountSecurityInbox` — Security inbox reads (security.read) | 3 | verified 3 |
| `mountInternalAPI` — Internal read API for CLI/automation (service key) | 3 | protocol_only 3 |
| `mountAudit` — Audit journal (global audit read) + top-orgs (root) | 2 | verified 2 |
| `mountFleet` — Fleet registry reads (root-only, read-only) | 2 | verified 2 |
| `mountOrgCapsRoutes` — Org caps (in-handler org gates) | 2 | verified 2 |
| `mountEntitlementDiagnostics` — Entitlement diagnostics (root-only) | 1 | verified 1 |
| `mountPolicyDecisions` — Policy decision log (policies.manage) | 1 | verified 1 |
| `mountFeedback` — Classifier feedback ingest (API-key data plane) | 1 | protocol_only 1 |

Per-record detail (handler, `handler_ref`, grant scope, UI evidence, conditionality,
`next_leaf`) is in `docs/ui-capability-matrix.json`.

## Limits (honest scope of this audit)

- Static source audit at one commit; no server was started and no endpoint was called.
  Per `plans/CORE.md` baseline policy, existing UI workflows remain "source present,
  workflow acceptance unverified".
- UI surface mapping is best-effort at path level (client template literals matched to
  normalized route templates); helper modules shared by pages (e.g. `requests.ts`) are
  credited to every page family that imports them indirectly where known.
- Conditional registrations (portal, DB-gated stores, optional handlers) are recorded
  via an `availability` evidence note; a build without those dependencies registers
  fewer routes than listed here.
- The dashboard's 36 hash routes and their nav permission gates are enumerated for
  cross-reference only; the grant×page×endpoint matrix is CUI-00-02.
- Method counts treat the two normalized registrations (`payload-grants`, `/metrics`)
  as POST and GET respectively; both carry an `availability`-style note in evidence.

## Regeneration

Re-run the extraction against the same base: registration literals from
`services/admin/handlers/*.go`, operations from `docs/api/admin.openapi.yaml`,
client calls from `web/dashboard/src/api/*.ts`; then join on normalized
(method, path-template) pairs. This file and the JSON are generated together and
must not be edited apart.
