package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chi "github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// mockPolicyPackStore implements PolicyPackStore.
type mockPolicyPackStore struct {
	upserts  []policystore.PackConfig
	listOut  []policystore.PackConfig
	getOut   *policystore.PackConfig
	delErr   error
	upsertFn func(c policystore.PackConfig) (policystore.PackConfig, error)
}

func (m *mockPolicyPackStore) Upsert(_ context.Context, c policystore.PackConfig) (policystore.PackConfig, error) {
	if m.upsertFn != nil {
		return m.upsertFn(c)
	}
	m.upserts = append(m.upserts, c)
	return policystore.PackConfig{ID: uuid.New(), Region: c.Region, PackID: c.PackID, Config: c.Config, Enabled: true, Version: 1}, nil
}
func (m *mockPolicyPackStore) GetByOrgRegion(_ context.Context, _, _ string) (*policystore.PackConfig, error) {
	return m.getOut, nil
}
func (m *mockPolicyPackStore) List(_ context.Context, _ string) ([]policystore.PackConfig, error) {
	return m.listOut, nil
}
func (m *mockPolicyPackStore) Delete(_ context.Context, _ uuid.UUID) error { return m.delErr }

// mockOrgResidency implements OrgResidencyStore.
type mockOrgResidency struct {
	region string
	set    string
	calls  int
}

func (m *mockOrgResidency) GetOrgResidencyRegion(_ context.Context, _ string) (string, error) {
	return m.region, nil
}
func (m *mockOrgResidency) UpdateOrgResidencyRegion(_ context.Context, _ string, region string) error {
	m.set = region
	m.calls++
	return nil
}

func newHandlerWithMocks() (*AdminHandlers, *mockPolicyPackStore, *mockOrgResidency) {
	h := New(nil, "secret", "localhost", nil)
	pp := &mockPolicyPackStore{}
	or := &mockOrgResidency{}
	h.SetPolicyPackStore(pp)
	h.SetOrgResidencyStore(or)
	return h, pp, or
}

// chiURLParams builds chi route params from a path like:
// /api/organizations/{uuid}/policy-packs/{region}
// /api/organizations/{uuid}/residency
// /api/organizations/{uuid}/policy-packs/{uuid} (delete)
func chiURLParams(target string) *chi.Context {
	rctx := chi.NewRouteContext()

	// Split by "/"
	parts := make([]string, 0)
	for i := 0; i < len(target); {
		end := i
		for end < len(target) && target[end] != '/' {
			end++
		}
		if end > i {
			parts = append(parts, target[i:end])
		}
		i = end + 1
	}

	// Find "organizations" index; everything after it is path params
	orgIdx := -1
	for i, p := range parts {
		if p == "organizations" {
			orgIdx = i
			break
		}
	}
	if orgIdx < 0 || orgIdx+1 >= len(parts) {
		return rctx
	}

	// First segment after organizations = id (UUID)
	rctx.URLParams.Add("id", parts[orgIdx+1])

	// Next segments depend on route:
	// policy-packs/{region}  -> region is the 2nd segment after orgs, short code
	// residency              -> no extra param
	// policy-packs/{packID}  -> packID (UUID)
	if orgIdx+3 >= len(parts) {
		return rctx
	}
	segment := parts[orgIdx+2] // e.g. "policy-packs" or "residency"

	if segment == "policy-packs" && orgIdx+3 < len(parts) {
		seg3 := parts[orgIdx+3]
		// Distinguish region (SG/IN/ID) from packID (UUID) by length
		if len(seg3) <= 3 {
			rctx.URLParams.Add("region", seg3)
		} else {
			rctx.URLParams.Add("packID", seg3)
		}
	}

	return rctx
}

// doReq creates a request with chi URL params populated from the target path.
func doReq(method, target string, body interface{}, h http.HandlerFunc) *httptest.ResponseRecorder {
	rctx := chiURLParams(target)

	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(b))
	} else {
		r = httptest.NewRequestWithContext(context.Background(), method, target, nil)
	}
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandler_UpsertPolicyPack_InvalidRegion_400(t *testing.T) {
	h, _, _ := newHandlerWithMocks()
	w := doReq("PUT", "/api/organizations/"+uuid.New().String()+"/policy-packs/US",
		upsertPolicyPackBody{PackID: "x"}, h.UpsertPolicyPack())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid region, got %d", w.Code)
	}
}

func TestHandler_UpsertPolicyPack_OK(t *testing.T) {
	h, store, _ := newHandlerWithMocks()
	org := uuid.New()
	w := doReq("PUT", "/api/organizations/"+org.String()+"/policy-packs/SG",
		upsertPolicyPackBody{PackID: "sg_pdpa_mas", Config: json.RawMessage(`{"a":1}`)}, h.UpsertPolicyPack())
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if len(store.upserts) != 1 {
		t.Fatalf("expected 1 upsert, got %d", len(store.upserts))
	}
	if store.upserts[0].Region != "SG" {
		t.Fatalf("expected region SG, got %s", store.upserts[0].Region)
	}
}

func TestHandler_UpsertPolicyPack_DefaultPackID(t *testing.T) {
	h, store, _ := newHandlerWithMocks()
	org := uuid.New()
	w := doReq("PUT", "/api/organizations/"+org.String()+"/policy-packs/IN",
		upsertPolicyPackBody{Config: json.RawMessage(`{"a":1}`)}, h.UpsertPolicyPack())
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.upserts[0].PackID != "in_dpdp_rbi" {
		t.Fatalf("expected default pack in_dpdp_rbi, got %s", store.upserts[0].PackID)
	}
}

func TestHandler_ListPolicyPacks_EmptyArray(t *testing.T) {
	h, _, _ := newHandlerWithMocks()
	w := doReq("GET", "/api/organizations/"+uuid.New().String()+"/policy-packs", nil, h.ListPolicyPacks())
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var arr []policystore.PackConfig
	if err := json.Unmarshal(w.Body.Bytes(), &arr); err != nil {
		t.Fatalf("body not an array: %s err=%v", w.Body.String(), err)
	}
	if arr == nil || len(arr) != 0 {
		t.Fatalf("expected [] not null, got %v", arr)
	}
}

func TestHandler_GetOrgResidency(t *testing.T) {
	h, _, or := newHandlerWithMocks()
	or.region = "SG"
	w := doReq("GET", "/api/organizations/"+uuid.New().String()+"/residency", nil, h.GetOrgResidency())
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["residency_region"] != "SG" {
		t.Fatalf("expected SG, got %v", resp)
	}
}

func TestHandler_UpdateOrgResidency_ClearsWithEmpty(t *testing.T) {
	h, _, or := newHandlerWithMocks()
	w := doReq("PUT", "/api/organizations/"+uuid.New().String()+"/residency",
		map[string]string{"residency_region": ""}, h.UpdateOrgResidency())
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if or.set != "" {
		t.Fatalf("expected cleared (empty), got %q", or.set)
	}
}

func TestHandler_UpdateOrgResidency_Invalid_400(t *testing.T) {
	h, _, _ := newHandlerWithMocks()
	w := doReq("PUT", "/api/organizations/"+uuid.New().String()+"/residency",
		map[string]string{"residency_region": "US"}, h.UpdateOrgResidency())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// doRawReq is doReq with a pre-encoded body ("" = empty body) so tests can
// pin exact wire bytes: unknown fields, nulls, trailing data.
func doRawReq(method, target, body string, h http.HandlerFunc) *httptest.ResponseRecorder {
	rctx := chiURLParams(target)
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestUpsertPolicyPack_Validation pins the request-body contract for
// PUT /api/organizations/{id}/policy-packs/{region}. The config column is
// NOT NULL, so a missing or null config must be rejected with 400 before
// the store is touched (a nil config used to surface as SQLSTATE 23502 →
// HTTP 500). Unknown fields and trailing data are rejected per the
// package-wide strict-decode convention.
func TestUpsertPolicyPack_Validation(t *testing.T) {
	org := uuid.New().String()
	cases := []struct {
		name  string
		body  string
		want  int
		saves int // expected number of store upserts (0 = store untouched)
	}{
		{"valid set with pack_id", `{"pack_id":"x","config":{"a":1},"enabled":false}`, http.StatusOK, 1},
		{"valid default pack id", `{"config":{"a":1}}`, http.StatusOK, 1},
		{"empty object config is valid json", `{"config":{}}`, http.StatusOK, 1},
		{"empty object body", `{}`, http.StatusBadRequest, 0},
		{"missing config", `{"pack_id":"x","enabled":true}`, http.StatusBadRequest, 0},
		{"null config", `{"config":null}`, http.StatusBadRequest, 0},
		{"null config with pack_id", `{"pack_id":"x","config":null}`, http.StatusBadRequest, 0},
		{"unknown field", `{"region":"SG"}`, http.StatusBadRequest, 0},
		{"unknown field with config", `{"region":"SG","config":{"a":1}}`, http.StatusBadRequest, 0},
		{"trailing data", `{"config":{"a":1}} {"x":1}`, http.StatusBadRequest, 0},
		{"no body", ``, http.StatusBadRequest, 0},
		{"not json", `not-json`, http.StatusBadRequest, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, store, _ := newHandlerWithMocks()
			w := doRawReq("PUT", "/api/organizations/"+org+"/policy-packs/SG", tc.body, h.UpsertPolicyPack())
			if w.Code != tc.want {
				t.Fatalf("got %d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
			if len(store.upserts) != tc.saves {
				t.Fatalf("store upserts = %d, want %d", len(store.upserts), tc.saves)
			}
		})
	}
}

// TestUpdateOrgResidency_Validation pins the residency-body contract:
// {"residency_region":"SG"} sets, {"residency_region":""} clears (documented
// contract, must keep working), {} clears via the legacy zero-value path,
// and unknown fields (the {"region":"SG"} harness bug) are rejected with 400
// before the store so no silent empty write can happen.
func TestUpdateOrgResidency_Validation(t *testing.T) {
	org := uuid.New().String()
	cases := []struct {
		name  string
		body  string
		want  int
		set   string
		calls int
	}{
		{"valid set", `{"residency_region":"SG"}`, http.StatusOK, "SG", 1},
		{"valid clear with empty string", `{"residency_region":""}`, http.StatusOK, "", 1},
		{"empty object clears (legacy zero-value)", `{}`, http.StatusOK, "", 1},
		{"unknown field rejected before store", `{"region":"SG"}`, http.StatusBadRequest, "", 0},
		{"unknown extra field rejected", `{"residency_region":"SG","note":"x"}`, http.StatusBadRequest, "", 0},
		{"trailing data", `{"residency_region":"SG"} x`, http.StatusBadRequest, "", 0},
		{"no body", ``, http.StatusBadRequest, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, or := newHandlerWithMocks()
			w := doRawReq("PUT", "/api/organizations/"+org+"/residency", tc.body, h.UpdateOrgResidency())
			if w.Code != tc.want {
				t.Fatalf("got %d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
			if or.calls != tc.calls || or.set != tc.set {
				t.Fatalf("store calls=%d set=%q, want calls=%d set=%q", or.calls, or.set, tc.calls, tc.set)
			}
		})
	}
}
