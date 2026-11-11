# Dashboard grant & scope matrix

This matrix answers two questions for every admin dashboard capability: **which
grant does the server actually require**, and **which organization dimension
does the request carry**. It is the companion of `ui-capability-matrix.md`
(endpoint inventory) and `ui-surface-catalog.md` (screen inventory).

**Citation policy.** Every `file:line` citation below resolves exactly at base
commit `243ab5b34d04ba0e83fb10df7b206f88e42629d7`. Citations point at
registrations, guards or denial paths in the server implementation, never at UI
labels alone. Inside tables, file names already introduced with their full path
in the same cell or row are abbreviated on repeat (for example
`router_analytics.go:68` after `services/admin/handlers/router_analytics.go`);
every abbreviation resolves to exactly one file under `services/admin/handlers/`,
`pkg/adminauth/`, `pkg/adminstore/`, `pkg/trcli/`, `pkg/gateway/` or
`web/dashboard/src/`. The machine-readable mirror `ui-grant-scope-matrix.json`
carries the same facts with full paths; its citations were mechanically
re-resolved against HEAD before commit (the checker itself is kept outside
this repository).

**Derivation.** Grant and scope facts come from the admin server's mount and
middleware chain (`services/admin/handlers/router.go` and the per-domain mount
files) plus the guard helpers they invoke. The dashboard nav gates
(`web/dashboard/src/App.tsx` `NAV_SECTIONS`) are recorded as UI facts and
cross-checked against the server chain; where they disagree, the server chain is
authoritative and the disagreement is listed under [Warts](#warts).

---

## Vocabulary

### Grants

| Grant | Meaning | Enforcement |
|---|---|---|
| `root-session` | Admin session with the root flag | `adminauth.MustBeRoot` — `pkg/adminauth/auth.go:466`, 403 at `pkg/adminauth/auth.go:471` |
| `org-permission` | Root passes; otherwise the caller's role on the target org must carry the permission | `services/admin/handlers/roles_authz.go:138`; 400 `org target required` at `:147`; 403 `insufficient permission for this organization` at `:152`. Constants: `pkg/adminstore/permissions.go:37-58` |
| `org-role` | Root passes; otherwise the caller's org role must rank at or above the minimum | `services/admin/handlers/roles_authz.go:113`; 403 at `:127`. Roles: `pkg/adminstore/roles.go:24-32` |
| `global-audit-role` | Root or a root-authorized platform `security_auditor`; org memberships are deliberately not consulted | `services/admin/handlers/roles_authz.go:186`; 403 at `:204` |
| `any-admin-session` | Any authenticated admin session; no org or root gate beyond the session chain | session `services/admin/handlers/router.go:747` + CSRF `:748` |
| `internal-service-key` | `X-Admin-Key` header compared in constant time; only `/internal` accepts it | `services/admin/handlers/internal_api.go:28`, `pkg/adminauth/auth.go:496` |
| `scim-bearer` | Per-org SCIM bearer token | `services/admin/handlers/router_scim.go:48-50` |
| `api-key` | Gateway API-key data plane, outside the admin session surface | `services/admin/handlers/router_ops.go:85` |

Every dashboard route rides the protected chain (session re-validation
`services/admin/handlers/router.go:747`, CSRF `:748`) before its specific
grant. The root CRUD group adds `MustBeRoot` (`router.go:770`) plus
`OrgScopeMiddleware` for org-scoped mutations (`router.go:777`).

### Org scopes

| Scope | Meaning |
|---|---|
| `org-bound` | Target org is part of the request (path param or `org_id` query); a foreign org is rejected or hidden |
| `orgless` | No org dimension: platform-global resource |
| `cross-org` | Response aggregates multiple orgs |
| `unavailable` | In the route inventory but not mounted at this commit; the protected router answers a JSON 404 (`services/admin/handlers/router.go:753`) |
| `deployment-dependent` | Mounted and guarded, reachable only where a gateway deployment exposes the plane |
| `none` | The page performs no API calls (launcher) |

---

## Route matrix (36 routes)

The `Page` union is `web/dashboard/src/App.tsx:69`. Nav-gate citations point at
the `NAV_SECTIONS` entry for the route.

| Route | Nav gate | Server grant (citations) | Org scope | Bound operations (citations) |
|---|---|---|---|---|
| `overview` | rootOnly `App.tsx:117` | root-session | cross-org | `GET /api/analytics/savings` `router_analytics.go:68` (root group via `router.go:783`) |
| `cost` | rootOnly `App.tsx:118` | root-session | cross-org | `GET /api/analytics/{org_id}/cost` `router_analytics.go:66`; `GET /api/analytics/cost/global` `:67`. Query built by `web/dashboard/src/pages/hooks/useCostReport.ts:33` |
| `compare` | rootOnly `App.tsx:138` | root-session for shadow/quality; org-permission `analytics.read` for latency | cross-org | `GET /api/analytics/shadow` `router_analytics.go:70`; `GET /api/analytics/quality` `:73`; `GET /api/analytics/latency` `:24` |
| `credits` | anyOrg `budgets.manage` `App.tsx:121` | `RequireOrgPermissionCreditsRead` (root passes; non-member 404 `credit_handlers.go:386`; member without `budgets.manage` 403 `:390`); ledger/wallet reads via `currenciesBudgetsRead` (404 `currencies_handlers.go:134`, 403 `:138`) | org-bound | `GET /api/orgs/{id}/credits/balance\|transactions` `router_billing.go:47-48`; `GET /api/credits/ledger` `currencies_handlers.go:114`; `GET /api/budgets`, `GET /api/units/spend` `:112-113` |
| `classifier` | rootOnly `App.tsx:145` | root-session | cross-org | `GET /api/analytics/savings` `router_analytics.go:68`. Data plane `POST /v1/feedback` is API-key auth (`router_ops.go:85`) |
| `cache` | rootOnly `App.tsx:144` | root-session | cross-org | `GET /api/analytics/savings` `router_analytics.go:68`. Cache management endpoints have no dashboard caller (see [CLI/config-only](#cli-config-only-capabilities)) |
| `feedback` | rootOnly `App.tsx:147` | root-session; list/export group mounts only when the lister is wired | cross-org | `GET /api/feedback` `router_ops.go:68`; `GET /api/feedback/export` `:69` |
| `orgs` | rootOnly `App.tsx:207` | root-session | cross-org | `GET/POST /api/organizations`, `GET/PUT/DELETE /api/organizations/{id}` `router_orgs.go:41-45` |
| `keys` | anyOrg `keys.manage\|agent_keys.manage` `App.tsx:155` | org-permission `keys.manage` (`router_keys.go:16`); `agent_keys.manage` (`:25`); root-session for agent profiles (`:47-51`) | org-bound (profiles orgless-root) | `/api/api-keys*` `router_keys.go:17-23`; `/api/agent-keys*`, budgets, delegations `:26-40`; `/api/agent-profiles*` `:47-51` |
| `agents` | anyOrg `keys.manage\|agent_keys.manage` `App.tsx:158` | any-admin-session for config render; key lookups per `keys.manage` | orgless | `GET /api/client-config/{agent}` `router_console.go:41` |
| `budgets` | anyOrg `budgets.manage\|agent_keys.manage\|analytics.read` `App.tsx:162` | mixed by section: team budgets `budgets.manage` `router_billing.go:35`; agent budgets `agent_keys.manage` `router_keys.go:25`; wallet credits gate `credit_handlers.go:372`; org caps budgets.manage in-handler (`caps_handlers.go:55`, 404 `:70`, 403 `:74`); grace/output-cap `orgBudgetAccess` `org_settings_handlers.go:93-97`; reservations-mode root-only 403 `:86`; topup/low-balance root-only `router_billing.go:72`,`:75`; spend-alert root-only `:58-59` | org-bound (root-only sections) | team budgets `router_billing.go:36-39`; agent budgets `router_keys.go:32-34`; org caps `caps_handlers.go:49-50`; grace/output-cap/reservations `org_settings_handlers.go:65-68` |
| `models` | rootOnly `App.tsx:185` | root-session | orgless | `/api/models*`, `/api/model-aliases*` `router_models.go:13-20` |
| `rules` | rootOnly `App.tsx:186` | root-session | orgless | `/api/rules*`, `POST /api/rules/preview` `router_models.go:25-31` |
| `routing-map` | anyOrg `routing.manage` `App.tsx:189` | in-handler `requireOrgRead` with `routing.manage` (foreign org or missing permission → 404 `services/admin/handlers/routing_map.go:39`); `analytics.read` for provider health | org-bound | `GET /api/routing/map` `router_models.go:51`; `GET /api/providers/health` `:57` |
| `lineage` | anyOrg `lineage.read` `App.tsx:137` | org-permission `lineage.read` (`router_analytics.go:48`); verify needs `lineage.verify` `:51` | org-bound | `GET /api/lineage/{request_id}`, `GET /api/organizations/{id}/lineage` `router_analytics.go:49-50`; `POST .../verify` `:51` |
| `requests-explorer` | anyOrg `requests.read` `App.tsx:127` | org-permission `requests.read` | org-bound | `GET /api/organizations/{id}/requests`, `/requests/stats`, `/requests/{request_id}` `router_analytics.go:42-46` |
| `analytics` | anyOrg `analytics.read` `App.tsx:128` | org-permission `analytics.read` (group `router_analytics.go:18`); savings CSV button rides root-only `:68` | org-bound (savings export root-only) | stats, time-series, top-models, error-breakdown, recent-errors, query, label-keys, views CRUD `router_analytics.go:19-31` |
| `dashboards` | rootOnly `App.tsx:133` | root-session (`GET /api/organizations/{id}` is root-only `router_orgs.go:43`) | cross-org | `GET /api/organizations/{id}` `router_orgs.go:43` |
| `tool-calls` | rootOnly `App.tsx:135` | root-session | org-bound via `{id}` path param, root-only gate | `GET /api/organizations/{id}/tool-calls` `router_analytics.go:60` |
| `tasks` | anyOrg `analytics.read` `App.tsx:134` | org-permission `analytics.read` (group `router_analytics.go:18`) | org-bound | `GET /api/analytics/tasks` `router_analytics.go:23` (caller `analytics.ts:270`) |
| `tool-policy` | rootOnly `App.tsx:190` | root-session (root group + org scope S01) | org-bound (root operator) | `/api/organizations/{id}/tool-policies*`, `POST /api/tool-policies` `router_mcp.go:30-37` |
| `policy-editor` | anyOrg `policies.manage` `App.tsx:193` | org-permission `policies.manage` (`policy_pipelines.go:126`) | org-bound | `/api/organizations/{id}/policies*`, validate, drift `policy_pipelines.go:161-170` |
| `policy-decisions` | anyOrg `policies.manage` `App.tsx:196` | org-permission `policies.manage` | org-bound | `GET /api/organizations/{id}/policy-decisions` `policy_decisions.go:67` |
| `prompts` | anyOrg `policies.manage` `App.tsx:198` | org-permission `policies.manage` (`prompt_studio.go:113`) | org-bound | `/api/organizations/{id}/prompts*`, `/partials*` `prompt_studio.go:114-123` |
| `label-policy` | anyOrg `analytics.read` `App.tsx:200` | `analytics.read` for read/test (`router_analytics.go:32-33`); `policies.manage` for write (`:34-35`) | org-bound | read/test `router_analytics.go:32-33`; `PUT/DELETE` `:34-35` |
| `guardrails` | anyOrg `analytics.read` `App.tsx:179` | none (launcher; per-card links carry their own gates) | none | — (no API calls) |
| `guard-packs` | rootOnly `App.tsx:184` | root-session (mount `guardpacks.go:117`); the activation journal read rides global-audit-role (`router_audit.go:19`) | orgless | `/api/guard-packs*` family `guardpacks.go:118-123`; `GET /api/audit-logs` `router_audit.go:19` (imported at `web/dashboard/src/pages/GuardPacksPage.tsx:11`) |
| `audit-log` | anyOrgRole `security_auditor` `App.tsx:211` | global-audit-role (`roles_authz.go:186`, 403 `:204`); rollback mutations re-execute through each target endpoint's own gate | cross-org | `GET /api/audit-logs` `router_audit.go:19` |
| `exports` | anyOrg `budgets.read` `App.tsx:163` (wart) | root-session for the bound spend-alert endpoints (`router_billing.go:58-59`); team budgets `budgets.manage` (`:36-39`) | org-bound (spend-alert root-only) | `GET/PATCH /api/organizations/{id}/spend-alert` `router_billing.go:58-59` |
| `model-access` | rootOnly `App.tsx:166` | root-session | orgless (per-key/team targets) | `/api/whitelist/api-keys/*`, `/api/whitelist/teams/*` `router_keys.go:54-59`; `GET /api/teams` `router_orgs.go:48` |
| `members` | anyOrg `members.manage` `App.tsx:167` | org-permission `members.manage` (`router_orgs.go:15`); SCIM tokens same gate (`router_scim.go:47`) | org-bound | members/invites `router_orgs.go:16-25`; SCIM tokens `router_scim.go:48-50`; developer CRUD only when the portal store is wired `router_orgs.go:26-30` |
| `admin-users` | rootOnly `App.tsx:212` | root-session | orgless | `/api/admin-users*` `router_orgs.go:55-59` |
| `org-settings` | rootOnly `App.tsx:216` | root-session for the settings tabs (cache-settings `router_orgs.go:62`; routing `:66`; policy-packs `:70-72`; residency `:73-74`; region `router_ops.go:30-31`; MCP server list/update `router_mcp.go:17`,`:19` — this page calls no grant or credential routes, MC-1 belongs to `mcp-credentials`; A2A list/update `:42`,`:44`; pricing `router_billing.go:62-67`); org-permission `keys.manage` for BYOK provider credentials (`org_credentials.go:266`); `org.update` for original-retention (`router_orgs.go:32`) | mixed: root-only org-scoped settings; BYOK org-bound | settings tabs `router_orgs.go:62-74`; region `router_ops.go:30-31`; provider credentials `org_credentials.go:268-273`; MCP server list/update `router_mcp.go:17`,`:19`; A2A list/update `router_mcp.go:42`,`:44` |
| `mcp-credentials` | rootOnly `App.tsx:219` | root-session for the mounted admin surfaces the page drives — MC-1 server credentials `router_mcp.go:54-56` (callers `McpCredentialsPage.tsx:307`,`:345`,`:362`; 503 when the credential store is unwired) plus the server-registry and grant reads it rides (`:17`, `:47`); unavailable for the MC-4 user-credentials registry (route deliberately not registered; JSON 404 `router.go:753`); deployment-dependent for the gateway flows (agent-key auth, MC-3) | mixed: mounted admin calls org-bound (root-only); MC-4 registry unavailable; gateway flows deployment-dependent | MC-1 `GET/PUT/DELETE /api/organizations/{id}/mcp/servers/{name}/credential` `router_mcp.go:54-56` (callers `McpCredentialsPage.tsx:307`,`:345`,`:362`); `GET/DELETE /api/organizations/{id}/mcp/user-credentials` (unmounted, `web/dashboard/src/api/mcpCredentials.ts`); `POST /api/mcp/credentials/{server}` `pkg/gateway/gateway.go:2011`; `POST /api/mcp/auth/{server}/begin` `:2012` |
| `rates` | anySession `App.tsx:222` | any-admin-session for catalog (`currencies_handlers.go:319`); root-session for diff/promote (`requireRootForRates` `:147`, 403 `:151`) | orgless | `GET /api/rates/catalog` `currencies_handlers.go:115`; `POST /api/rates/diff`, `/api/rates/promote` `:116-117` |
| `onboarding` | not in nav (`App.tsx:69`) | org-role reader or above for the flow state (`router_console.go:51-52` group); step endpoints use their own gates | org-bound | `GET/POST /api/me/onboarding` `router_console.go:51-52`; key step `router_keys.go:18`; credential step `org_credentials.go:269` |

Notes retained from the JSON mirror: the `requests-explorer` registered
`/requests/export` and `/requests/archive-search` (`router_analytics.go:44-45`)
have no dashboard caller at this commit; the `dashboards` nav comment records
the root-only org read as a known wart; `guardrails` fetches nothing and the
server stays the arbiter behind every linked surface.

---

## CLI/config-only capabilities

Capabilities driven only from the CLI or config at this commit — no dashboard
screen exercises them. Most member endpoint families also have **no dashboard
caller**; where an endpoint is shared with a dashboard surface (the
`cli-pricing-sync` pair), the row says so explicitly. The `/internal` trio
authenticates with the `X-Admin-Key` service key (`YABANIN_ADMIN_API_KEY` in
run configuration); the group is unmounted when the key is unset
(`internal_api.go:24-28`).

| Group | Grant | Scope | Endpoints (citations) |
|---|---|---|---|
| `cli-service-api` | internal-service-key | org-bound | `GET /internal/api-keys` `internal_api.go:29` (consumer `pkg/trcli/keys.go:33`; mandatory `org_id` prevents cross-org listing); `GET /internal/analytics/savings` `:30` (`pkg/trcli/spend.go:23`); `GET /internal/analytics/cost` `:31` (automation; no `yb` consumer yet) |
| `cli-pricing-sync` | root-session (intended) — credential wart | orgless | Capability is CLI-only (`yb pricing sync`): `GET /api/models` (`pkg/trcli/pricing_sync.go:179`); `POST /api/pricing/import?mode=apply` (`:201`, server mount `router_billing.go:64`). The endpoints are not dashboard-orphans — `GET /api/models` also serves the `models` page (`router_models.go:13`) and the `/api/pricing` CRUD family serves the org-settings pricing tab (`router_billing.go:62-67`) — but no dashboard screen drives the sync, and the import itself has no dashboard caller |
| `cache-ops` | root-session | orgless | flush/analytics/warm `router_ops.go:18-20`; experiments `:23-25` |
| `regions-catalog` | root-session | orgless | `GET /api/regions` `router_ops.go:29` (per-org region endpoints are bound to `org-settings`) |
| `verticals` | root-session (wired unit) | org-bound | enable/list/disable `router_ops.go:36-38` |
| `templates` | root-session (wired unit) | org-bound / orgless mix | export/marketplace/subscribe `router_ops.go:43-45` |
| `retrain-status` | root-session (wired unit) | orgless | `GET /api/retrain/status` `router_ops.go:74` |
| `inventory` | root-session; dark when unwired | org-bound | list + imports `router_inventory.go:52-54` |
| `fleet-registry` | root-session | org-bound | installations list/detail `fleet_handlers.go:232-233` |
| `entitlement-diagnostics` | root-session | orgless | `GET /api/entitlement/diagnostics` `entitlement_diagnostics_handlers.go:101` |
| `sovereign-marketplace` | root-session (wired unit) | orgless (policy rows per org) | models + policy `router_models.go:38-41` |
| `resale-pricing` | root-session (wired unit) | org-bound (list cross-org) | resale/reseller family `router_billing.go:78-82` |
| `root-payload-grants` | root-session inline | orgless | `POST /api/root/payload-grants` `router_console.go:33` |
| `requests-archive-exports` | org-permission `requests.read` | org-bound | `GET .../requests/export`, `.../requests/archive-search` `router_analytics.go:44-45` (registered, no dashboard caller) |
| `feedback-data-plane` | api-key | org-bound (caller's org) | `POST /v1/feedback` `router_ops.go:85` (mounted only when the collector is wired) |
| `scim-protocol` | scim-bearer | org-bound | `/scim/v2` ServiceProviderConfig, Schemas, ResourceTypes, Users×6, Groups×5 — 14 endpoints (`r.Route` at `router_scim.go:20`; no `/Me` or `/Bulk` routes); token lifecycle is the `members` route |
| `developer-portal` | portal session (opt-in `SetPortal` config) | org-bound | portal pages + `portalAuthed /api/me`, `/api/me/keys*` `router_portal.go:15-27` — separate portal UI, not the dashboard |

---

## Negative controls

Each control names the claim, the probe, the exact denial path, and — where one
exists — the test that already pins the behavior.

1. **Root-only aggregates.** `GET /api/analytics/savings` without the root flag
   → 403 `forbidden` at `pkg/adminauth/auth.go:471` via the root group chain
   (`router.go:770`, `router.go:783`). Covers `overview`, `cost`, `cache`,
   `classifier`, `compare`.
2. **Org permission.** `GET /api/organizations/{id}/requests` as a member whose
   role lacks `requests.read` → 403 `insufficient permission for this
   organization` at `roles_authz.go:152` (400 `org target required` at `:147`
   when no org target resolves). Pinned by the route×role×org matrix
   `authz_test.go:67`.
3. **Global audit role.** `GET /api/audit-logs` as an org-granted
   `security_auditor` member (same or foreign org) → 403 `insufficient role for
   the platform audit` at `roles_authz.go:204`; memberships are deliberately
   not consulted by `RequireGlobalAuditRead` (`:186`). Pinned by
   `audit_gate_auth01_test.go:50`, `:63`, `:100`.
4. **Hidden routing map.** `GET /api/routing/map?org_id={foreign}` without
   membership/permission → 404 at `services/admin/handlers/routing_map.go:39`
   (`requireOrgRead` `services/admin/handlers/routing_map.go:29`):
   membership-blind existence hiding, not 403. Pinned by
   `services/admin/handlers/routing_map_test.go:104`.
5. **Wallet org scoping.** `GET /api/orgs/{id}/credits/balance` as non-member →
   404 `credit_handlers.go:386`; as member without `budgets.manage` → 403
   `:390` (gate at `:372`). Pinned by `credits_org_view_test.go`.
6. **Rates mutation.** `POST /api/rates/promote` as non-root → 403 `root
   session is required for the rates catalog` at `currencies_handlers.go:151`
   (`requireRootForRates` `:147`; promote mounted at `:117`). Pinned by the
   rates section of `currencies_handlers_test.go` (`:534` root happy path,
   `:713` fail-closed sibling).

---

## Warts

1. **`exports` nav permission.** The exports nav gate references `budgets.read`
   (`App.tsx:163`), which no server permission defines
   (`permissions.go:37-58`); `/api/me` never serves it, so the entry is hidden
   for every non-root admin and the bound spend-alert endpoints are root-only
   anyway. Tracked as `DOCUMENTED_WARTS` in `App.navGates.test.ts:43`.
2. **MCP credential endpoints.** The `mcp-credentials` screen targets
   `GET/DELETE /api/organizations/{id}/mcp/user-credentials`, deliberately not
   registered (MC-4 contract hole; the UI renders an explicit unavailable state
   on 404 — `ui_actions_inventory_test.go:848`); JSON 404 via `router.go:753`.
   The gateway flows (`gateway.go:2011`, `:2012`) exist only on deployments
   exposing the gateway plane. The admin-side MC-1 server credential IS mounted
   (`router_mcp.go:54-56`) and its dashboard caller is the `mcp-credentials`
   screen itself (`McpCredentialsPage.tsx:307`, `:345`, `:362`); org-settings
   calls only the server list/update endpoints (`router_mcp.go:17`, `:19`).
3. **`yb pricing sync` credential.** The command sends the `X-Admin-Key`
   service key against `GET /api/models` and `POST /api/pricing/import`
   (`pricing_sync.go:179`, `:201`), but only `/internal` accepts that header
   (`internal_api.go:28`); the session surface answers 401
   (`router.go:747`). Needs a server-side resolution (internal mirrors or
   documented session use).
4. **Requests export/archive-search without a caller.** Registered and
   `requests.read`-gated (`router_analytics.go:44-45`) but no dashboard module
   calls them at this commit.
5. **Guard-packs cross-gate read.** The screen also lists the audit journal
   (`GuardPacksPage.tsx:11` → `router_audit.go:19`): a platform
   `security_auditor` without root can see the journal through this screen but
   not the guard-pack endpoints themselves (`guardpacks.go:118-123`).

---

## Counts

- 36 routes total; 35 with bound operations; 1 launcher (`guardrails`);
  `mcp-credentials` is mixed — mounted root-only admin calls (MC-1) plus the
  unmounted MC-4 registry and the deployment-dependent gateway flows.
- 17 CLI/config-only groups covering 62 endpoints (the config-gated developer
  portal contributes 10 of them in its own UI).
- 6 negative controls; 5 documented warts.
