package handlers

// E02-P01 W01-C03: admin API read access to the observable asset registry.
//
// The handler is delivered SPI-first after the pkg/secevents precedent:
// ListInventory takes the registry read seam as a parameter (nothing is
// added to AdminHandlers — the router wiring card mounts the route when
// the release hardening window closes). The admin.openapi.yaml surface is
// FROZEN for the window, so the endpoint is contract-documented as a delta
// entry in docs/api/OPENAPI-DELTA.md (format: the FIX-20 entry), including
// the permission name the wiring card will register
// (admin.inventory.read — not yet in the closed permission matrix, which
// lives outside this delivery's write scope; until then the org-scope
// gate below is the enforcement: root operators and org-scoped admins on
// their own org).

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/reireirei/yabanin/pkg/inventory"
)

// InventoryLister is the read seam the inventory API needs from the
// registry. *inventory.Store satisfies it; the narrow interface keeps the
// handler testable without a database.
type InventoryLister interface {
	ListAssets(ctx context.Context, orgID string, p inventory.ListParams) ([]inventory.Row, string, error)
}

// inventoryListResponse is the listing envelope. An empty registry is a
// successful empty page (assets: []), never 404 — absence of observations
// is not an error (W01 rule «пустое upstream»).
type inventoryListResponse struct {
	Assets     []inventory.Row `json:"assets"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// inventoryReadAuditDetail is the journal payload of one read decision.
// It must be serialized with json.Marshal, never fmt.Sprintf %q: org_id
// and cursor are query-controlled and may carry control characters, and
// %q emits escapes strict JSON parsers reject (the request_export rule).
type inventoryReadAuditDetail struct {
	OrgID             string `json:"org_id"`
	Scope             string `json:"scope,omitempty"`
	Kind              string `json:"kind,omitempty"`
	Outcome           string `json:"outcome"`
	Rows              int    `json:"rows"`
	IncludeTombstoned bool   `json:"include_tombstoned,omitempty"`
	Cursor            bool   `json:"cursor,omitempty"`
}

// auditInventoryRead journals allowed reads and every authorization
// denial (the request_export pattern: allowed streams and fail-closed
// denials both land in the durable journal). Parameter noise (400s) and
// store failures (500s) do not journal — they are not authorization
// decisions.
func auditInventoryRead(h *AdminHandlers, r *http.Request, orgID, scope, kind, outcome string, rows int, includeTombstoned, cursor bool) {
	action := "inventory_read"
	if outcome != "ok" {
		action = "inventory_read.denied"
	}
	details, err := json.Marshal(inventoryReadAuditDetail{
		OrgID:             orgID,
		Scope:             scope,
		Kind:              kind,
		Outcome:           outcome,
		Rows:              rows,
		IncludeTombstoned: includeTombstoned,
		Cursor:            cursor,
	})
	if err != nil {
		// Unreachable for this all-scalar struct; fall back to a fixed,
		// valid-JSON marker rather than ever storing malformed JSON.
		details = []byte(`{"outcome":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID, string(details))
}

// InventoryImporter runs an MCP registry import pass for one org
// (satisfied by *inventory.ImportRunner; narrow seam for testing).
type InventoryImporter interface {
	Run(ctx context.Context, orgID string) (*inventory.MCPImportReport, error)
}

// inventoryImportAuditDetail is the journal payload of one import
// decision (the json.Marshal rule applies — org_id is request-derived).
type inventoryImportAuditDetail struct {
	OrgID     string `json:"org_id"`
	Scope     string `json:"scope,omitempty"`
	Outcome   string `json:"outcome"`
	Created   int    `json:"created,omitempty"`
	Updated   int    `json:"updated,omitempty"`
	Unchanged int    `json:"unchanged,omitempty"`
}

// auditInventoryImport journals allowed imports and authorization
// denials (same posture as auditInventoryRead).
func auditInventoryImport(h *AdminHandlers, r *http.Request, orgID, scope, outcome string, c inventory.ImportCounts) {
	action := "inventory_import"
	if outcome != "ok" {
		action = "inventory_import.denied"
	}
	details, err := json.Marshal(inventoryImportAuditDetail{
		OrgID: orgID, Scope: scope, Outcome: outcome,
		Created: c.Created, Updated: c.Updated, Unchanged: c.Unchanged,
	})
	if err != nil {
		details = []byte(`{"outcome":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID, string(details))
}

// ImportMCPInventory serves POST /api/organizations/{id}/inventory/import/mcp
// (delta-documented, unmounted SPI — same posture as ListInventory).
// One pass imports the org's MCP registry incrementally (config_version +
// allowed_tools driven); the report is returned, the decision journaled.
func (h *AdminHandlers) ImportMCPInventory(runner InventoryImporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runner == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "inventory importer is not wired"})
			return
		}
		q := r.URL.Query()
		providedOrg := q.Get("org_id")
		if providedOrg == "" {
			providedOrg = r.PathValue("id")
		}
		orgID := h.requireOrgScope(w, r, providedOrg)
		if orgID == "" {
			auditInventoryImport(h, r, providedOrg, OrgScopeFromRequest(r), "forbidden", inventory.ImportCounts{})
			return
		}
		report, err := runner.Run(r.Context(), orgID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "inventory import failed"})
			return
		}
		auditInventoryImport(h, r, orgID, OrgScopeFromRequest(r), "ok", report.Counts)
		writeJSON(w, http.StatusOK, report)
	}
}

// ListInventory serves the org inventory listing
// (GET /api/organizations/{id}/inventory?kind=&limit=&cursor=&include_tombstoned=).
// Root may target any org (org_id required); an org-scoped admin is pinned
// to the middleware scope — a foreign org is 403 with a denied audit
// entry. Empty registry → 200 {"assets":[]}.
func (h *AdminHandlers) ListInventory(store InventoryLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "inventory store is not wired"})
			return
		}
		q := r.URL.Query()
		providedOrg := q.Get("org_id")
		if providedOrg == "" {
			providedOrg = r.PathValue("id")
		}
		var kind inventory.AssetKind
		if k := q.Get("kind"); k != "" {
			kind = inventory.AssetKind(k)
			if !inventory.ValidAssetKind(kind) {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "unknown kind"})
				return
			}
		}
		limit := 0
		if ls := q.Get("limit"); ls != "" {
			n, err := strconv.Atoi(ls)
			if err != nil || n < 1 {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "limit must be a positive integer"})
				return
			}
			limit = n
		}
		includeTombstoned := q.Get("include_tombstoned") == "true" || q.Get("include_tombstoned") == "1"
		cursor := q.Get("cursor")

		orgID := h.requireOrgScope(w, r, providedOrg)
		if orgID == "" {
			auditInventoryRead(h, r, providedOrg, OrgScopeFromRequest(r), string(kind), "forbidden", 0, includeTombstoned, cursor != "")
			return
		}

		rows, next, err := store.ListAssets(r.Context(), orgID, inventory.ListParams{
			Kind:              kind,
			After:             cursor,
			Limit:             limit,
			IncludeTombstoned: includeTombstoned,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "inventory listing failed"})
			return
		}
		if rows == nil {
			rows = []inventory.Row{} // empty registry marshals as [], never null
		}
		auditInventoryRead(h, r, orgID, OrgScopeFromRequest(r), string(kind), "ok", len(rows), includeTombstoned, cursor != "")
		writeJSON(w, http.StatusOK, inventoryListResponse{Assets: rows, NextCursor: next})
	}
}

// --- E02-P01 W03-C02 (batch B): model/provider catalog import -------------
//
// Same SPI-first posture as the batch A sections above: the route is delta-
// documented in docs/api/OPENAPI-DELTA.md (admin.openapi.yaml stays FROZEN
// for the window) and mounted by the wiring card. Discrepancy is data, not
// an error: a registry_only/reference_only flag never fails the pass.

// InventoryModelImporter runs a model/provider import pass for one org
// (satisfied by *inventory.ModelImportRunner; narrow seam for testing).
type InventoryModelImporter interface {
	Run(ctx context.Context, orgID string) (*inventory.ModelImportReport, error)
}

// inventoryModelsImportAuditDetail is the journal payload of one model
// import decision (json.Marshal rule — org_id is request-derived).
type inventoryModelsImportAuditDetail struct {
	OrgID         string `json:"org_id"`
	Scope         string `json:"scope,omitempty"`
	Outcome       string `json:"outcome"`
	Created       int    `json:"created,omitempty"`
	Updated       int    `json:"updated,omitempty"`
	Unchanged     int    `json:"unchanged,omitempty"`
	Discrepancies int    `json:"discrepancies,omitempty"`
}

// auditInventoryModelsImport journals allowed model imports and
// authorization denials (same posture as auditInventoryImport).
func auditInventoryModelsImport(h *AdminHandlers, r *http.Request, orgID, scope, outcome string, rep *inventory.ModelImportReport) {
	action := "inventory_models_import"
	if outcome != "ok" {
		action = "inventory_models_import.denied"
	}
	var detail inventoryModelsImportAuditDetail
	if rep != nil {
		detail = inventoryModelsImportAuditDetail{
			Created: rep.Counts.Created, Updated: rep.Counts.Updated,
			Unchanged: rep.Counts.Unchanged, Discrepancies: rep.Discrepancies,
		}
	}
	detail.OrgID, detail.Scope, detail.Outcome = orgID, scope, outcome
	details, err := json.Marshal(detail)
	if err != nil {
		details = []byte(`{"outcome":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID, string(details))
}

// ImportModelsInventory serves POST /api/organizations/{id}/inventory/import/models
// (delta-documented, unmounted SPI — same posture as ImportMCPInventory).
// One pass materializes the GLOBAL models_registry plus the reference
// planes into the org's asset rows; the report (counts, versions journal,
// discrepancy flags, skipped entries) is returned and the decision
// journaled. Empty-org targeting is refused by requireOrgScope (obligation
// ②: 400 for root without org_id, 403 without an org scope).
func (h *AdminHandlers) ImportModelsInventory(runner InventoryModelImporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runner == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "model importer is not wired"})
			return
		}
		q := r.URL.Query()
		providedOrg := q.Get("org_id")
		if providedOrg == "" {
			providedOrg = r.PathValue("id")
		}
		orgID := h.requireOrgScope(w, r, providedOrg)
		if orgID == "" {
			auditInventoryModelsImport(h, r, providedOrg, OrgScopeFromRequest(r), "forbidden", nil)
			return
		}
		report, err := runner.Run(r.Context(), orgID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "model inventory import failed"})
			return
		}
		auditInventoryModelsImport(h, r, orgID, OrgScopeFromRequest(r), "ok", report)
		writeJSON(w, http.StatusOK, report)
	}
}
