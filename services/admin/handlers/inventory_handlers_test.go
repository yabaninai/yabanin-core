package handlers

// E02-P01 W01-C03: inventory listing handler battery. The registry seam is
// a fake InventoryLister (the handler takes the store as a parameter — the
// SPI-unmounted posture of this delivery; mounting + permission matrix
// registration land with the wiring card after the release hardening
// window).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/inventory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeInventoryLister records the calls and answers from a fixed table.
type fakeInventoryLister struct {
	calls []struct {
		orgID  string
		params inventory.ListParams
	}
	rows []inventory.Row
	next string
	err  error
}

func (f *fakeInventoryLister) ListAssets(_ context.Context, orgID string, p inventory.ListParams) ([]inventory.Row, string, error) {
	f.calls = append(f.calls, struct {
		orgID  string
		params inventory.ListParams
	}{orgID, p})
	return f.rows, f.next, f.err
}

func invRow(org, key string, kind inventory.AssetKind, ts bool) inventory.Row {
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	r := inventory.Row{Asset: inventory.Asset{
		OrgID: org, AssetKey: key, Kind: kind,
		Payload: json.RawMessage(`{"n":1}`), Source: inventory.SourceMCPRegistry,
		Confidence: inventory.ConfidenceHigh, FirstSeen: at, LastSeen: at,
	}}
	r.Tombstone = ts
	if ts {
		r.TombstonedAt = at
	}
	return r
}

func newInventoryH(fake *fakeInventoryLister) *AdminHandlers {
	h := New(nil, "", "", []string{})
	_ = fake
	return h
}

func TestInventory_NoStore_503(t *testing.T) {
	h := New(nil, "", "", []string{})
	req := rootRequest(http.MethodGet, "/api/organizations/org-1/inventory?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ListInventory(nil)(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestInventory_ListsOrgScoped(t *testing.T) {
	fake := &fakeInventoryLister{rows: []inventory.Row{
		invRow("org-1", "mcp_server:fs", inventory.KindMCPServer, false),
		invRow("org-1", "mcp_tool:fs/read", inventory.KindTool, false),
	}}
	h := newInventoryH(fake)

	req := rootRequest(http.MethodGet, "/api/organizations/org-1/inventory?org_id=org-1&kind=tool&limit=10", "")
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Assets     []inventory.Row `json:"assets"`
		NextCursor string          `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Assets, 2)
	assert.Equal(t, "mcp_server:fs", resp.Assets[0].AssetKey)
	assert.Equal(t, "mcp_server", string(resp.Assets[0].Kind))
	assert.JSONEq(t, `{"n":1}`, string(resp.Assets[0].Payload))

	require.Len(t, fake.calls, 1)
	assert.Equal(t, "org-1", fake.calls[0].orgID)
	assert.Equal(t, inventory.KindTool, fake.calls[0].params.Kind)
	assert.Equal(t, 10, fake.calls[0].params.Limit)
	assert.False(t, fake.calls[0].params.IncludeTombstoned)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_read", entry.Action)
	assert.Equal(t, "organization:org-1", entry.Resource)
	var d struct {
		OrgID   string `json:"org_id"`
		Outcome string `json:"outcome"`
		Kind    string `json:"kind"`
		Rows    int    `json:"rows"`
	}
	require.NoError(t, json.Unmarshal([]byte(entry.Details), &d))
	assert.Equal(t, "org-1", d.OrgID)
	assert.Equal(t, "ok", d.Outcome)
	assert.Equal(t, "tool", d.Kind)
	assert.Equal(t, 2, d.Rows)
}

func TestInventory_EmptyRegistryIs200EmptyArray(t *testing.T) {
	fake := &fakeInventoryLister{rows: nil} // empty registry
	h := newInventoryH(fake)

	req := rootRequest(http.MethodGet, "/api/organizations/org-empty/inventory?org_id=org-empty", "")
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"assets":[]}`, w.Body.String(), "empty registry must be 200 [] — never null, never 404")
}

func TestInventory_CursorPassthrough(t *testing.T) {
	fake := &fakeInventoryLister{next: "tool\x1fmcp_tool:fs/read"}
	h := newInventoryH(fake)

	req := rootRequest(http.MethodGet, "/api/organizations/org-1/inventory?org_id=org-1&cursor=tool%1Fmcp_tool%3Afs%2Fread&include_tombstoned=true", "")
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp inventoryListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "tool\x1fmcp_tool:fs/read", resp.NextCursor)
	require.Len(t, fake.calls, 1)
	assert.Equal(t, "tool\x1fmcp_tool:fs/read", fake.calls[0].params.After)
	assert.True(t, fake.calls[0].params.IncludeTombstoned)
}

func TestInventory_ForeignOrg_403WithDeniedAudit(t *testing.T) {
	fake := &fakeInventoryLister{rows: []inventory.Row{invRow("org-1", "mcp_server:fs", inventory.KindMCPServer, false)}}
	h := newInventoryH(fake)

	// Non-root admin scoped to org-1 (middleware-pinned context value),
	// requesting the foreign org-2 registry.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-2/inventory?org_id=org-2", nil)
	req = req.WithContext(withOrgScope(req.Context(), "org-1"))
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, fake.calls, "a denied request must never reach the store")

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_read.denied", entry.Action)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry.Details), &d))
	assert.Equal(t, "org-2", d["org_id"], "the attempted foreign org is journaled")
	assert.Equal(t, "org-1", d["scope"], "the caller's pinned scope is journaled")
	assert.Equal(t, "forbidden", d["outcome"])
}

func TestInventory_NonRootNoScope_403WithAudit(t *testing.T) {
	fake := &fakeInventoryLister{}
	h := newInventoryH(fake)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-1/inventory?org_id=org-1", nil)
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_read.denied", entry.Action)
}

func TestInventory_RootOrgRequired(t *testing.T) {
	fake := &fakeInventoryLister{}
	h := newInventoryH(fake)

	req := rootRequest(http.MethodGet, "/api/organizations//inventory", "")
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "root without an org target is a 400, not a wildcard listing")
}

func TestInventory_BadParams_400(t *testing.T) {
	fake := &fakeInventoryLister{}
	h := newInventoryH(fake)

	cases := []struct {
		name, query string
	}{
		{"unknown kind", "org_id=org-1&kind=vendor"},
		{"zero limit", "org_id=org-1&limit=0"},
		{"non-numeric limit", "org_id=org-1&limit=many"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := rootRequest(http.MethodGet, "/api/organizations/org-1/inventory?"+tc.query, "")
			w := httptest.NewRecorder()
			h.ListInventory(fake)(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
	assert.Empty(t, fake.calls, "parameter noise must never reach the store")
}

func TestInventory_StoreError_500(t *testing.T) {
	fake := &fakeInventoryLister{err: context.DeadlineExceeded}
	h := newInventoryH(fake)

	req := rootRequest(http.MethodGet, "/api/organizations/org-1/inventory?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ListInventory(fake)(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "inventory listing failed")
}

// withOrgScope pins the middleware org scope in a request context
// (white-box, the boundary_corpus_test pattern).
func withOrgScope(ctx context.Context, org string) context.Context {
	return context.WithValue(ctx, ctxKeyOrgScope{}, org)
}

// fakeInventoryImporter answers one org with a fixed report.
type fakeInventoryImporter struct {
	orgID   string
	report  *inventory.MCPImportReport
	err     error
	calls   int
	lastOrg string
}

func (f *fakeInventoryImporter) Run(_ context.Context, orgID string) (*inventory.MCPImportReport, error) {
	f.calls++
	f.lastOrg = orgID
	return f.report, f.err
}

func TestInventoryImport_RunsAndAudits(t *testing.T) {
	fake := &fakeInventoryImporter{orgID: "org-1", report: &inventory.MCPImportReport{
		Servers: []inventory.ServerImportResult{{Name: "fs", ConfigVersion: 3, ToolsImported: 2}},
		Counts:  inventory.ImportCounts{Created: 3},
	}}
	h := newInventoryH(nil)

	req := rootRequest(http.MethodPost, "/api/organizations/org-1/inventory/import/mcp?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ImportMCPInventory(fake)(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp inventory.MCPImportReport
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Servers, 1)
	assert.Equal(t, "fs", resp.Servers[0].Name)
	assert.Equal(t, 3, resp.Counts.Created)
	assert.Equal(t, 1, fake.calls)
	assert.Equal(t, "org-1", fake.lastOrg)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_import", entry.Action)
	assert.Equal(t, "organization:org-1", entry.Resource)
	var d struct {
		OrgID   string `json:"org_id"`
		Outcome string `json:"outcome"`
		Created int    `json:"created"`
	}
	require.NoError(t, json.Unmarshal([]byte(entry.Details), &d))
	assert.Equal(t, "org-1", d.OrgID)
	assert.Equal(t, "ok", d.Outcome)
	assert.Equal(t, 3, d.Created)
}

func TestInventoryImport_ForeignOrg_403WithDeniedAudit(t *testing.T) {
	fake := &fakeInventoryImporter{}
	h := newInventoryH(nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/organizations/org-2/inventory/import/mcp?org_id=org-2", nil)
	req = req.WithContext(withOrgScope(req.Context(), "org-1"))
	w := httptest.NewRecorder()
	h.ImportMCPInventory(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, fake.calls, "a denied import must never run")

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_import.denied", entry.Action)
	var d struct {
		OrgID   string `json:"org_id"`
		Scope   string `json:"scope"`
		Outcome string `json:"outcome"`
	}
	require.NoError(t, json.Unmarshal([]byte(entry.Details), &d))
	assert.Equal(t, "org-2", d.OrgID)
	assert.Equal(t, "org-1", d.Scope)
	assert.Equal(t, "forbidden", d.Outcome)
}

func TestInventoryImport_NoRunner_503(t *testing.T) {
	h := New(nil, "", "", []string{})
	req := rootRequest(http.MethodPost, "/api/organizations/org-1/inventory/import/mcp?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ImportMCPInventory(nil)(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestInventoryImport_RunError_500(t *testing.T) {
	fake := &fakeInventoryImporter{err: context.DeadlineExceeded}
	h := newInventoryH(nil)
	req := rootRequest(http.MethodPost, "/api/organizations/org-1/inventory/import/mcp?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ImportMCPInventory(fake)(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "inventory import failed")
}

// --- E02-P01 W03-C02 (batch B): model/provider import handler battery ---
// Disjoint additions to the batch A file (the shared-anchor rule): only new
// functions, no edits to the sections above.

type fakeInventoryModelImporter struct {
	report  *inventory.ModelImportReport
	err     error
	calls   int
	lastOrg string
}

func (f *fakeInventoryModelImporter) Run(_ context.Context, orgID string) (*inventory.ModelImportReport, error) {
	f.calls++
	f.lastOrg = orgID
	return f.report, f.err
}

func TestInventoryModelsImport_RunsAndAudits(t *testing.T) {
	fake := &fakeInventoryModelImporter{report: &inventory.ModelImportReport{
		Counts: inventory.ImportCounts{Created: 8, Unchanged: 2},
		Models: 5, Providers: 3, Discrepancies: 4,
		CatalogVersion: "cat-v1", PricingVersion: "pack-v7", PricingDigest: "sha256:abc123",
	}}
	h := newInventoryH(nil)

	req := rootRequest(http.MethodPost, "/api/organizations/org-9/inventory/import/models?org_id=org-9", "")
	w := httptest.NewRecorder()
	h.ImportModelsInventory(fake)(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 1, fake.calls)
	assert.Equal(t, "org-9", fake.lastOrg)

	var got inventory.ModelImportReport
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, 8, got.Counts.Created)
	assert.Equal(t, "cat-v1", got.CatalogVersion)
	assert.Equal(t, "sha256:abc123", got.PricingDigest)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_models_import", entry.Action)
	var d struct {
		OrgID         string `json:"org_id"`
		Outcome       string `json:"outcome"`
		Created       int    `json:"created"`
		Discrepancies int    `json:"discrepancies"`
	}
	require.NoError(t, json.Unmarshal([]byte(entry.Details), &d))
	assert.Equal(t, "org-9", d.OrgID)
	assert.Equal(t, "ok", d.Outcome)
	assert.Equal(t, 8, d.Created)
	assert.Equal(t, 4, d.Discrepancies)
}

func TestInventoryModelsImport_ForeignOrg_403WithDeniedAudit(t *testing.T) {
	fake := &fakeInventoryModelImporter{}
	h := newInventoryH(nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/organizations/org-8/inventory/import/models?org_id=org-8", nil)
	req = req.WithContext(withOrgScope(req.Context(), "org-7"))
	w := httptest.NewRecorder()
	h.ImportModelsInventory(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, fake.calls, "a denied request must never reach the importer")
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_models_import.denied", entry.Action)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry.Details), &d))
	assert.Equal(t, "org-8", d["org_id"], "the attempted foreign org is journaled")
	assert.Equal(t, "org-7", d["scope"], "the caller's pinned scope is journaled")
}

func TestInventoryModelsImport_RootOrgRequired(t *testing.T) {
	fake := &fakeInventoryModelImporter{}
	h := newInventoryH(nil)

	// Root caller, no org target anywhere (obligation ②: 400, not a
	// wildcard global import).
	req := rootRequest(http.MethodPost, "/api/organizations//inventory/import/models", "")
	w := httptest.NewRecorder()
	h.ImportModelsInventory(fake)(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Zero(t, fake.calls)
}

func TestInventoryModelsImport_NonRootNoScope_403WithAudit(t *testing.T) {
	fake := &fakeInventoryModelImporter{}
	h := newInventoryH(nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/organizations/org-9/inventory/import/models?org_id=org-9", nil)
	w := httptest.NewRecorder()
	h.ImportModelsInventory(fake)(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "inventory_models_import.denied", entry.Action)
}

func TestInventoryModelsImport_NoRunner_503(t *testing.T) {
	h := newInventoryH(nil)
	req := rootRequest(http.MethodPost, "/api/organizations/org-9/inventory/import/models?org_id=org-9", "")
	w := httptest.NewRecorder()
	h.ImportModelsInventory(nil)(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestInventoryModelsImport_RunError_500(t *testing.T) {
	fake := &fakeInventoryModelImporter{err: context.DeadlineExceeded}
	h := newInventoryH(nil)

	req := rootRequest(http.MethodPost, "/api/organizations/org-9/inventory/import/models?org_id=org-9", "")
	w := httptest.NewRecorder()
	h.ImportModelsInventory(fake)(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "model inventory import failed")
}
