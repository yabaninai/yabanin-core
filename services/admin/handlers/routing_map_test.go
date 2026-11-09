package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// views. The org dimension is enforced in-handler: root sees any org, an
// org member with the permission sees their own org, and a foreign org is
// answered 404 with a bare {"error":"not found"} so its existence (and any
// of its data) never leaks. The store doubles embed the package mock, which
// satisfies StoreInterface; only the new capability methods are overridden.

type routingMapTestStore struct {
	*mockStore
	mapping *adminstore.RoutingMap
	err     error
	gotOrg  string
}

func (s *routingMapTestStore) GetRoutingMap(_ context.Context, orgID string) (*adminstore.RoutingMap, error) {
	s.gotOrg = orgID
	return s.mapping, s.err
}

type providerHealthTestStore struct {
	*mockStore
	health    []adminstore.ProviderHealth
	err       error
	gotOrg    string
	gotFromTo [2]time.Time
}

func (s *providerHealthTestStore) GetProviderHealth(_ context.Context, orgID string, from, to time.Time) ([]adminstore.ProviderHealth, error) {
	s.gotOrg = orgID
	s.gotFromTo = [2]time.Time{from, to}
	return s.health, s.err
}

func sampleRoutingMap() *adminstore.RoutingMap {
	return &adminstore.RoutingMap{
		OrgID:    "org-1",
		Models:   []adminstore.RoutingMapModel{{ModelName: "m1", Provider: "p1", Enabled: true, FailoverModels: []string{}, TierPool: []string{}}},
		Aliases:  []adminstore.RoutingMapAlias{},
		Rules:    []adminstore.RoutingMapRule{},
		Warnings: []adminstore.RoutingMapWarning{},
	}
}

func sampleHealth() []adminstore.ProviderHealth {
	return []adminstore.ProviderHealth{{
		Provider: "p1", Requests: 10, Errors: 1, ErrorRate: 0.1,
		Models: []adminstore.ProviderHealthModel{{Model: "m1", Requests: 10, Errors: 1, ErrorRate: 0.1}},
	}}
}

// callView serves the handler as an authenticated session (userID, root flag)
// with an optional org membership role; returns status and the decoded body.
func callView(t *testing.T, h *AdminHandlers, userID string, isRoot bool, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, userID)
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, isRoot)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.RoutingMap().ServeHTTP(rec, req)
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func callHealth(t *testing.T, h *AdminHandlers, userID string, isRoot bool, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, userID)
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, isRoot)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ProviderHealth().ServeHTTP(rec, req)
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func grantMembership(t *testing.T, st *mockStore, userID, org string, role adminstore.OrgRole) {
	t.Helper()
	_, err := st.SetOrgMembership(context.Background(), userID, org, role)
	if err != nil {
		t.Fatalf("grant membership: %v", err)
	}
}

func TestRoutingMap_RightsMatrix(t *testing.T) {
	st := &routingMapTestStore{mockStore: newMockStore(), mapping: sampleRoutingMap()}
	h := &AdminHandlers{store: st}

	// Root (platform operator): any org, including one it holds no membership on.
	code, body := callView(t, h, "admin-root", true, "/api/routing/map?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("root status = %d, want 200; body %v", code, body)
	}
	if st.gotOrg != "org-1" {
		t.Errorf("root store org = %q, want org-1", st.gotOrg)
	}
	if _, ok := body["models"]; !ok {
		t.Errorf("root body missing models section: %v", body)
	}

	// Org member with the routing permission: own org is readable.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleOperator)
	code, _ = callView(t, h, "admin-1", false, "/api/routing/map?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("member status = %d, want 200", code)
	}

	// Foreign organization: 404 without leaking that it exists.
	code, body = callView(t, h, "admin-1", false, "/api/routing/map?org_id=org-2")
	if code != http.StatusNotFound {
		t.Fatalf("foreign org status = %d, want 404", code)
	}
	if body["error"] != "not found" {
		t.Errorf("foreign org body = %v, want bare not found", body)
	}
	if len(body) != 1 {
		t.Errorf("foreign org body leaks data: %v", body)
	}

	// Member without the permission (partner grants nothing): also 404, no leak.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RolePartner)
	code, body = callView(t, h, "admin-1", false, "/api/routing/map?org_id=org-1")
	if code != http.StatusNotFound || body["error"] != "not found" {
		t.Fatalf("partner status/body = %d/%v, want 404/not found", code, body)
	}

	// Reader holds no routing.manage either.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleReader)
	if code, _ := callView(t, h, "admin-1", false, "/api/routing/map?org_id=org-1"); code != http.StatusNotFound {
		t.Fatalf("reader status = %d, want 404", code)
	}

	// Missing org_id → 400.
	if code, _ := callView(t, h, "admin-root", true, "/api/routing/map"); code != http.StatusBadRequest {
		t.Fatalf("missing org_id status = %d, want 400", code)
	}
}

func TestRoutingMap_StoreErrorAndCapability(t *testing.T) {
	st := &routingMapTestStore{mockStore: newMockStore(), err: context.DeadlineExceeded}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/routing/map?org_id=o", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminauth.ContextKeyIsRoot{}, true))
	rec := httptest.NewRecorder()
	h.RoutingMap().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error status = %d, want 500", rec.Code)
	}

	// A store without the capability answers 501, not a panic.
	if code, _ := callView(t, &AdminHandlers{store: newMockStore()}, "admin-root", true, "/api/routing/map?org_id=o"); code != http.StatusNotImplemented {
		t.Fatalf("capability-less store status = %d, want 501", code)
	}
}

func TestProviderHealth_RightsMatrix(t *testing.T) {
	st := &providerHealthTestStore{mockStore: newMockStore(), health: sampleHealth()}
	h := &AdminHandlers{store: st}

	// Root: any org.
	code, body := callHealth(t, h, "admin-root", true, "/api/providers/health?org_id=org-1&period=7d")
	if code != http.StatusOK {
		t.Fatalf("root status = %d, want 200; body %v", code, body)
	}
	if st.gotOrg != "org-1" {
		t.Errorf("root store org = %q", st.gotOrg)
	}
	providers, ok := body["providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Errorf("providers section = %v", body["providers"])
	}
	if body["period"] != "7d" {
		t.Errorf("period echo = %v, want 7d", body["period"])
	}

	// Org member with analytics.read (reader has it): own org OK.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleReader)
	if code, _ := callHealth(t, h, "admin-1", false, "/api/providers/health?org_id=org-1"); code != http.StatusOK {
		t.Fatalf("member status = %d, want 200", code)
	}

	// Foreign org: 404 without data leak.
	code, body = callHealth(t, h, "admin-1", false, "/api/providers/health?org_id=org-2")
	if code != http.StatusNotFound {
		t.Fatalf("foreign org status = %d, want 404", code)
	}
	if body["error"] != "not found" || len(body) != 1 {
		t.Errorf("foreign org body leaks data: %v", body)
	}

	// Missing org_id → 400; bad period → 400.
	if code, _ := callHealth(t, h, "admin-root", true, "/api/providers/health"); code != http.StatusBadRequest {
		t.Fatalf("missing org_id status = %d, want 400", code)
	}
	if code, _ := callHealth(t, h, "admin-root", true, "/api/providers/health?org_id=o&period=nonsense"); code != http.StatusBadRequest {
		t.Fatalf("bad period status = %d, want 400", code)
	}

	// Default period is 24h.
	if _, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil); err != nil {
		t.Fatal(err)
	}
	from, to, ok := parseHealthPeriod("", time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))
	if !ok || to.Sub(from) != 24*time.Hour {
		t.Fatalf("default period = %v…%v ok=%v, want 24h", from, to, ok)
	}
}

func TestProviderHealth_StoreErrorAndCapability(t *testing.T) {
	st := &providerHealthTestStore{mockStore: newMockStore(), err: context.DeadlineExceeded}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/providers/health?org_id=o", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminauth.ContextKeyIsRoot{}, true))
	rec := httptest.NewRecorder()
	h.ProviderHealth().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error status = %d, want 500", rec.Code)
	}

	if code, _ := callHealth(t, &AdminHandlers{store: newMockStore()}, "admin-root", true, "/api/providers/health?org_id=o"); code != http.StatusNotImplemented {
		t.Fatalf("capability-less store status = %d, want 501", code)
	}
}
