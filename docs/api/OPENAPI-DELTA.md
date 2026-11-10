# OpenAPI delta record

This page describes API additions not fully represented in
`admin.openapi.yaml`. The inventory routes described below are mounted when the
admin service has a database pool; their current authorization is root-only plus
organization scope. Earlier unmounted designs are not installation requirements.

## 2026-11-02 — RESPONSE-HISTORY

- Endpoint: `GET /api/organizations/{id}/requests/{request_id}`
  (admin request detail).
- Change: new OPTIONAL response field
  `response_view?: ResponseView` on the request-detail body. `ResponseView`
  is the parsed envelope of the processed, client-facing model response:
  - `status`: `"complete" | "partial"` (required when present)
  - `reason?`: string — one of `capture_limit`, `client_cancel`,
    `idle_timeout`, `upstream_error`, `missing_done_frame` (partial only)
  - `model?`: string — the model name as served to the client
  - `content`: string (always present, may be empty — e.g. tool-call-only
    answers)
  - `reasoning_content?`: string
  - `tool_calls?`: array of `{index, id?, name?, arguments?}`
  - `finish_reason?`: string
  - `truncated?`: boolean
- Absence semantics: the field is ABSENT (never null) for rows logged
  before response capture was supported, for rows whose producer captured no response content, and
  whenever the payload grant does not allow the `response` column. The
  pre-existing raw `response` field is unchanged in shape and gating; the
  new field is derived from it server-side and carries no additional
  exposure.
- No endpoint, parameter, status code, or error-shape changes.
- Backwards compatibility: additive optional field; existing clients that
  ignore unknown fields are unaffected.

## 2026-11-07 — INVENTORY-LIST

- Endpoint: `GET /api/organizations/{id}/inventory` with query
  parameters `org_id` (required for root callers, target org), `kind?`
  (`agent|service|mcp_server|tool|model|provider`), `limit?` (positive
  integer; server caps at 500), `cursor?` (opaque page cursor),
  `include_tombstoned?` (`true|1`).
- Change: new endpoint — read access to the observable asset registry
  (org-scoped rows: asset_key, kind, payload, source, confidence,
  first_seen, last_seen, tombstone, tombstoned_at). Response:
  `{"assets": AssetRow[], "next_cursor"?: string}`; an empty registry is
  `200 {"assets":[]}` — never 404, never null.
- Status codes: 200 (page), 400 (bad kind/limit/org_id missing for root),
  403 (org-scope mismatch / no scope / no role on org — every denial is
  journaled as `inventory_read.denied` with org_id+scope), 500 (store
  failure), 503 (store not wired).
- Permission: root-only access with organization-scope checks; see the mounting
  details below.
- Backwards compatibility: purely additive; no existing route, field, or
  status code changes.

## 2026-11-07 — INVENTORY-IMPORT

- Endpoint:
  `POST /api/organizations/{id}/inventory/import/mcp` with query `org_id`
  (required for root callers, target org). No request body.
- Change: new endpoint — one incremental MCP registry import pass for the
  org. Incrementality is registry-state-driven: a server whose
  config_version and allowed_tools are unchanged since the last synced
  snapshot skips the tool re-listing (its server row still refreshes
  last_seen); a pass that missed a server's upstream leaves the snapshot
  unsynced so the next pass retries. Response: the import report
  `{"servers": [{name, config_version, tools_seen, tools_imported,
  dropped_tools, skipped?, error?}], "counts": {created, updated,
  unchanged}}`. A tool miss is a reported per-server entry, never a
  failed import; an empty org is a successful no-op report.
- Status codes: 200 (report), 403 (org-scope mismatch / no scope / no
  role — journaled as `inventory_import.denied` with org_id+scope), 500
  (import failure), 503 (importer not wired).
- Permission: root-only access with organization-scope checks; see the mounting
  details below.
- Backwards compatibility: purely additive.

## 2026-11-07 — GUARD-PACK COVERAGE LISTING

- Endpoint: `GET /api/guard-packs` (admin guard pack inventory; host API =
  the ADMIN contract — `docs/api/admin.openapi.yaml` `listGuardPacks`,
  version 1.2.0; the gateway contract hosts no
  guard-packs paths).
- Change: new OPTIONAL response field on each row of `packs[]`:
  `coverage?: CoverageEntry[]` where each entry is
  - `rule_id`: string — the pack's own detector rule the claim is about
  - `ev_ids`: string[] — scenario ids from the closed registry
    `EV-A01`…`EV-A08` (OWASP scenario map)
  - `evidence_test`: string — the live test carrying the evidence
    (test name or file:line)
- Absence semantics: the field is ABSENT (never null) for packs whose
  manifest declares no coverage — absence means "coverage unknown", NOT
  "full coverage". Enforcement is two-level, matching where data lives:
  - manifest decode failures (unknown scenario id, malformed row,
    duplicate rule_id, limit overflow) list the pack as an ERROR row with
    the `error` field and no coverage claim, exactly like any other
    unloadable pack;
  - a `rule_id` not declared by the pack's own detector.json passes decode
    (the listing is manifest-level and surfaces the declaration verbatim)
    and is rejected at LOAD: `POST /api/guard-packs/validate` (the
    activate dry run) and activation return 409
    `not declared by this pack's detector.json`, so no UI preview can pass
    where activation would fail.
- Integrity: coverage is part of the signed manifest payload — for signed
  packs the block is covered by the pack signature (tampering fails
  verification); unsigned local packs carry the declaration unsigned, like
  the rest of their manifest.
- Permissions: no new permission surface — the field rides the existing
  root-only mount of all six `/api/guard-packs` endpoints
  (`x-permission: root` in the specification); unauthenticated and
  non-root callers never see coverage (401/403 unchanged).
- No endpoint, parameter, status code, or error-shape changes.
- Backwards compatibility: additive optional field; existing clients that
  ignore unknown fields are unaffected.


## 2026-11-07 — INVENTORY-MODELS-IMPORT

- Endpoint:
  `POST /api/organizations/{id}/inventory/import/models` with query `org_id`
  (required for root callers, target org). No request body.
- Change: new endpoint — one model/provider catalog import pass for the
  org. The pass reads the deployment's GLOBAL models_registry plus the
  reference planes (process model catalog and bundled pricing refpack) and
  materializes them into the org's asset rows (kind=model
  `model:<provider>/<model>`, kind=provider `provider:<provider>`). A pair
  known to only one side is imported with a `discrepancy` flag
  (`registry_only` / `reference_only`) — a flag is data, never a failed
  import. Response: the pass report `{"counts": {created, updated,
  unchanged}, "models": int, "providers": int, "discrepancies": int,
  "catalog_version"?, "pricing_version"?, "pricing_digest"?,
  "pricing_as_of"?, "skips": [{plane, ref, reason}]}`. Identity-defective
  upstream entries are skipped and reported, never fatal for their
  siblings; an empty registry snapshot is a no-op pass (never a wipe —
  assets shrink only through tombstones).
- Status codes: 200 (report), 400 (org_id missing for root), 403
  (org-scope mismatch / no scope — journaled as
  `inventory_models_import.denied` with org_id+scope), 500 (import
  failure), 503 (model importer not wired).
- Permission: root-only access with organization-scope checks; see the mounting
  details below.
- Backwards compatibility: purely additive.

## 2026-11-08 — WIRING: asset-registry routes MOUNTED (root-only)

- Converts the three initial contracts above to MOUNTED: `GET /api/organizations/{id}/inventory`,
  `POST /api/organizations/{id}/inventory/import/mcp` and
  `POST /api/organizations/{id}/inventory/import/models` register on the
  admin control plane in every deployment with a database pool. Contracts,
  status codes and response shapes are exactly the previews above; the
  503 `not wired` codes remain reachable only per-seam (an importer whose
  construction failed answers 503 while the read surface stays up).
- Guard chain (pinned in `testdata/routes_admin.golden`, 290 → 293 routes):
  `session+csrf+root+orgscope` — the root-only CRUD group
  (MustBeRoot + OrgScopeMiddleware); the org dimension is enforced by the
  handlers (requireOrgScope: 400 root without `org_id`, 403 scope
  mismatch), matching the previews' permission rules.
- Specification coverage: these routes are implemented but not yet listed in
  `admin.openapi.yaml`. Route and authorization tests cover the mounted paths;
  API consumers should use the contracts on this page for these additions.
- Current limitations:
  - `admin.inventory.read` / `admin.inventory.import` closed-matrix
    registration — delivered enforcement is the root gate + org-scope
    middleware (root is an operator, any org in scope); the named matrix
    entries are the intended future state.
  - Tool listing behavior: the MCP import proxy runs with an EMPTY
    identity, so per-server tool listing is a reported miss
    (`ToolsSynced` false / `tools_seen` 0) until the importer identity
    carries list grants — an operator configuration item; server and
    config snapshots import regardless.
  - The Observer (runtime observation fold) has no HTTP surface by
    design: it is wired as an internal SPI (`SetCatalog`) consumed by the
    gateway runtime, not the admin plane.
- Backwards compatibility: purely additive routes; no existing route,
  field, or status code changes.
## 2026-11-08 — SECURITY-INBOX LIST FILTERS

- Endpoint: `GET /api/organizations/{id}/security-inbox` (admin security
  inbox list).
- Change: new OPTIONAL query parameters (v1, handler-level):
  - `severity` — exact match against the incident severity dictionary
    `low|medium|high`. Any other value (including different casing) is a
    400.
  - `confidence_min` — inclusive lower bound on the incident confidence
    (`[0,1]`). Non-numeric or out-of-range values are a 400.
  - `confidence_max` — inclusive upper bound, same validation;
    `confidence_min > confidence_max` is a 400.
  - `sort` — `last_seen` (default) | `severity` | `confidence`. Every key
    sorts DESCENDING (worst/newest first); equal keys break deterministically
    by incident id. Unknown keys are a 400.
- Absence semantics: a request with none of these parameters behaves exactly
  as an unfiltered request (unfiltered list, newest first) — byte-for-byte.
- Filtering happens after the org-scoped listing (v1); `rows` in the audit
  journal detail reflects the post-filter count.
- No endpoint path, method, status-code or body-shape changes; these parameters are described here rather than in
  `admin.openapi.yaml`.


## 2026-11-08 — FLEET-REGISTRY READS (root-only, read-only)

- Endpoints (host API = the ADMIN contract —
  `docs/api/admin.openapi.yaml` `listOrgFleetInstallations` /
  `getOrgFleetInstallation`; the gateway contract hosts no fleet paths):
  - `GET /api/organizations/{org_id}/fleet/installations`
  - `GET /api/organizations/{org_id}/fleet/installations/{deployment_id}`
- Change: new read-only endpoints over the fleet registry
  (migration 0024, RLS org isolation). `org_id` is the LICENSE org
  coordinate — the TEXT identity enrollments and heartbeats are signed
  for — carried verbatim in the path; it is not an
  adminstore uuid and no uuid parsing happens. Rows return the stored
  negotiated caps document (`format_version`, `capabilities[]`,
  `unsupported[]` — the visible negotiation remainder is never silently
  dropped), the lifecycle `state` (enrolled|active|stale|revoked), the
  enrollment/caps/heartbeat stamps, and the EXPLICIT revoked marker:
  `revoked: true` exactly when `state=revoked`, with `revoked_at` and
  `revocation_reason`. List order is deterministic (deployment_id).
- Mutations: N/A by design — the plane is GET-only; enrollment,
  heartbeats and revocation flow through their own signed seams
  (Ed25519 license PKI), and lifecycle writes never ride the admin API.
- Status codes: 200, 400 (org/deployment coordinate fails the registry's
  structural law — empty, padded, oversized, control characters), 401
  (no session), 403 (non-root — root-only plane, `x-permission: root`),
  404 (unknown or foreign-org deployment; indistinguishable by design),
  500 (registry read failure), 503 (fleet store not wired).
- Permissions: no new org-permission surface — the registry is an
  operator plane mounted in the root-only group (MustBeRoot chain); non-root callers are 403 before the
  handler runs, and reads are journaled (`fleet_registry`,
  `fleet_registry.not_found`).
- Backwards compatibility: purely additive (admin.openapi.yaml stays
  1.2.0; the two paths and the `FleetInstallation` schema are new).
