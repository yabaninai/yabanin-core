package handlers

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// routing views. The org dimension is enforced in-handler (root passes for
// any org; a member needs the view's permission; anyone else gets the
// membership-blind 404), and the recorded-paths view is gated by
// analytics.read while the snapshot is gated by routing.manage — the
// matrix below pins that split. The store doubles embed the package mock,
// which satisfies StoreInterface; only the new capability methods are
// overridden (routingMapTestStore from routing_map_test.go is reused for
// the snapshot).

type routingActualTestStore struct {
	*mockStore
	actual    *adminstore.RoutingActual
	err       error
	gotOrg    string
	gotFromTo [2]time.Time
}

func (s *routingActualTestStore) GetActualRouting(_ context.Context, orgID string, from, to time.Time) (*adminstore.RoutingActual, error) {
	s.gotOrg = orgID
	s.gotFromTo = [2]time.Time{from, to}
	return s.actual, s.err
}

func sampleActual() *adminstore.RoutingActual {
	// 3× m-a→m-a2, 1× m-b→m-b2, plus one row without a requested model:
	// 5 requests in the window, 4 attributed, coverage share 0.8.
	return &adminstore.RoutingActual{
		Edges: []adminstore.RoutingActualEdge{
			{From: "m-a", To: "m-a2", Requests: 3, Share: 0.75},
			{From: "m-b", To: "m-b2", Requests: 1, Share: 0.25},
		},
		Coverage: adminstore.RoutingActualCoverage{
			TotalRequests:        5,
			AttributedRequests:   4,
			UnattributedRequests: 1,
			Share:                0.8,
		},
	}
}

// callActualView serves RoutingActual as an authenticated session.
func callActualView(t *testing.T, h *AdminHandlers, userID string, isRoot bool, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, userID)
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, isRoot)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.RoutingActual().ServeHTTP(rec, req)
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

// callSnapshotView serves RoutingSnapshot as an authenticated session.
func callSnapshotView(t *testing.T, h *AdminHandlers, userID string, isRoot bool, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, userID)
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, isRoot)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.RoutingSnapshot().ServeHTTP(rec, req)
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func TestRoutingActual_RightsMatrix(t *testing.T) {
	st := &routingActualTestStore{mockStore: newMockStore(), actual: sampleActual()}
	h := &AdminHandlers{store: st}

	// Root (platform operator): any org, including one it holds no membership on.
	code, body := callActualView(t, h, "admin-root", true, "/api/routing/actual?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("root status = %d, want 200; body %v", code, body)
	}
	if st.gotOrg != "org-1" {
		t.Errorf("root store org = %q, want org-1", st.gotOrg)
	}
	if _, ok := body["edges"]; !ok {
		t.Errorf("root body missing edges section: %v", body)
	}
	if _, ok := body["coverage"]; !ok {
		t.Errorf("root body missing coverage section: %v", body)
	}

	// Org member with analytics.read (operator holds it): own org readable.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleOperator)
	if code, _ = callActualView(t, h, "admin-1", false, "/api/routing/actual?org_id=org-1"); code != http.StatusOK {
		t.Fatalf("operator member status = %d, want 200", code)
	}

	// Reader also holds analytics.read — traffic views stay readable for
	// readers, unlike the routing-manage configuration views.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleReader)
	if code, _ = callActualView(t, h, "admin-1", false, "/api/routing/actual?org_id=org-1"); code != http.StatusOK {
		t.Fatalf("reader status = %d, want 200 (analytics.read suffices)", code)
	}

	// Partner grants nothing: membership-blind 404.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RolePartner)
	code, body = callActualView(t, h, "admin-1", false, "/api/routing/actual?org_id=org-1")
	if code != http.StatusNotFound || body["error"] != "not found" {
		t.Fatalf("partner status/body = %d/%v, want 404/not found", code, body)
	}

	// Foreign organization: 404 without leaking that it exists.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleOperator)
	code, body = callActualView(t, h, "admin-1", false, "/api/routing/actual?org_id=org-2")
	if code != http.StatusNotFound {
		t.Fatalf("foreign org status = %d, want 404", code)
	}
	if body["error"] != "not found" || len(body) != 1 {
		t.Errorf("foreign org body leaks data: %v", body)
	}

	// Missing org_id → 400; bad period → 400.
	if code, _ := callActualView(t, h, "admin-root", true, "/api/routing/actual"); code != http.StatusBadRequest {
		t.Fatalf("missing org_id status = %d, want 400", code)
	}
	if code, _ := callActualView(t, h, "admin-root", true, "/api/routing/actual?org_id=o&period=nonsense"); code != http.StatusBadRequest {
		t.Fatalf("bad period status = %d, want 400", code)
	}
}

func TestRoutingActual_WindowAndDataHonesty(t *testing.T) {
	st := &routingActualTestStore{mockStore: newMockStore(), actual: sampleActual()}
	h := &AdminHandlers{store: st}

	// The default window is the shared 24h view window; the store sees the
	// [now-24h, now) bounds and the period echoes back as 24h.
	code, body := callActualView(t, h, "admin-root", true, "/api/routing/actual?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if span := st.gotFromTo[1].Sub(st.gotFromTo[0]); span != 24*time.Hour {
		t.Errorf("default window = %v, want 24h", span)
	}
	if body["period"] != "24h" {
		t.Errorf("period echo = %v, want 24h", body["period"])
	}
	if _, err := time.Parse(time.RFC3339, body["from"].(string)); err != nil {
		t.Errorf("from = %v, want RFC3339", body["from"])
	}

	// Data honesty: the unattributed row never becomes an edge but shows
	// up in coverage; shares are fractions of the attributed total.
	edges := body["edges"].([]any)
	if len(edges) != 2 {
		t.Fatalf("edges = %v, want 2 (the unattributed row forms no edge)", edges)
	}
	first := edges[0].(map[string]any)
	if first["from"] != "m-a" || first["to"] != "m-a2" {
		t.Errorf("edge[0] = %v, want m-a→m-a2", first)
	}
	if first["requests"].(float64) != 3 {
		t.Errorf("edge[0] requests = %v, want 3", first["requests"])
	}
	if math.Abs(first["share"].(float64)-0.75) > 1e-9 {
		t.Errorf("edge[0] share = %v, want 0.75", first["share"])
	}
	coverage := body["coverage"].(map[string]any)
	if coverage["total_requests"].(float64) != 5 {
		t.Errorf("coverage total = %v, want 5", coverage["total_requests"])
	}
	if coverage["attributed_requests"].(float64) != 4 {
		t.Errorf("coverage attributed = %v, want 4", coverage["attributed_requests"])
	}
	if coverage["unattributed_requests"].(float64) != 1 {
		t.Errorf("coverage unattributed = %v, want 1", coverage["unattributed_requests"])
	}
	if math.Abs(coverage["share"].(float64)-0.8) > 1e-9 {
		t.Errorf("coverage share = %v, want 0.8", coverage["share"])
	}

	// Empty window: edges serialize as [] (honest empty), never null.
	st.actual = &adminstore.RoutingActual{Edges: []adminstore.RoutingActualEdge{}}
	code, body = callActualView(t, h, "admin-root", true, "/api/routing/actual?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("empty status = %d, want 200", code)
	}
	if raw, err := json.Marshal(body["edges"]); err != nil || string(raw) != "[]" {
		t.Errorf("empty edges marshaled = %s (%v), want []", raw, err)
	}
}

func TestRoutingActual_StoreErrorAndCapability(t *testing.T) {
	st := &routingActualTestStore{mockStore: newMockStore(), err: context.DeadlineExceeded}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/routing/actual?org_id=o", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminauth.ContextKeyIsRoot{}, true))
	rec := httptest.NewRecorder()
	h.RoutingActual().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error status = %d, want 500", rec.Code)
	}

	// A store without the capability answers 501, not a panic.
	if code, _ := callActualView(t, &AdminHandlers{store: newMockStore()}, "admin-root", true, "/api/routing/actual?org_id=o"); code != http.StatusNotImplemented {
		t.Fatalf("capability-less store status = %d, want 501", code)
	}
}

func TestRoutingSnapshot_RightsMatrix(t *testing.T) {
	st := &routingMapTestStore{mockStore: newMockStore(), mapping: sampleRoutingMap()}
	h := &AdminHandlers{store: st}

	// Root: any org.
	code, body := callSnapshotView(t, h, "admin-root", true, "/api/routing/snapshot?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("root status = %d, want 200; body %v", code, body)
	}
	if _, ok := body["map"]; !ok {
		t.Errorf("root body missing map section: %v", body)
	}
	if _, ok := body["active_overrides"]; !ok {
		t.Errorf("root body missing active_overrides section: %v", body)
	}
	if _, err := time.Parse(time.RFC3339, body["captured_at"].(string)); err != nil {
		t.Errorf("captured_at = %v, want RFC3339", body["captured_at"])
	}

	// Org member with routing.manage (operator holds it): own org readable.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleOperator)
	if code, _ = callSnapshotView(t, h, "admin-1", false, "/api/routing/snapshot?org_id=org-1"); code != http.StatusOK {
		t.Fatalf("operator member status = %d, want 200", code)
	}

	// Reader holds no routing.manage — the snapshot is configuration state,
	// unlike the traffic views: membership-blind 404.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleReader)
	code, body = callSnapshotView(t, h, "admin-1", false, "/api/routing/snapshot?org_id=org-1")
	if code != http.StatusNotFound || body["error"] != "not found" {
		t.Fatalf("reader status/body = %d/%v, want 404/not found", code, body)
	}

	// Foreign organization: 404 without leaking that it exists.
	grantMembership(t, st.mockStore, "admin-1", "org-1", adminstore.RoleOperator)
	code, body = callSnapshotView(t, h, "admin-1", false, "/api/routing/snapshot?org_id=org-2")
	if code != http.StatusNotFound {
		t.Fatalf("foreign org status = %d, want 404", code)
	}
	if body["error"] != "not found" || len(body) != 1 {
		t.Errorf("foreign org body leaks data: %v", body)
	}

	// Missing org_id → 400.
	if code, _ := callSnapshotView(t, h, "admin-root", true, "/api/routing/snapshot"); code != http.StatusBadRequest {
		t.Fatalf("missing org_id status = %d, want 400", code)
	}
}

func TestRoutingSnapshot_ActiveOverridesProjection(t *testing.T) {
	st := &routingMapTestStore{mockStore: newMockStore(), mapping: sampleRoutingMap()}
	st.mapping.Rules = []adminstore.RoutingMapRule{
		{ID: "r-low", MatchExpr: "model == 'm-a'", TargetModel: "m-a2", Priority: 5, Enabled: true},
		{ID: "r-off", MatchExpr: "model == 'm-x'", TargetModel: "m-x2", Priority: 100, Enabled: false},
		{ID: "r-high", MatchExpr: "session starts 'agent-'", TargetModel: "m-b", Priority: 10, Enabled: true},
	}
	h := &AdminHandlers{store: st}

	code, body := callSnapshotView(t, h, "admin-root", true, "/api/routing/snapshot?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	// Evaluation order: priority DESC, disabled rules inert and absent.
	active := body["active_overrides"].([]any)
	if len(active) != 2 {
		t.Fatalf("active_overrides = %v, want 2 enabled rules", active)
	}
	if active[0].(map[string]any)["id"] != "r-high" || active[1].(map[string]any)["id"] != "r-low" {
		t.Errorf("active order = %v, want r-high (p10) before r-low (p5)", active)
	}

	// An org without rules: active_overrides stays [] (honest empty).
	st.mapping = sampleRoutingMap()
	code, body = callSnapshotView(t, h, "admin-root", true, "/api/routing/snapshot?org_id=org-1")
	if code != http.StatusOK {
		t.Fatalf("empty status = %d, want 200", code)
	}
	if raw, err := json.Marshal(body["active_overrides"]); err != nil || string(raw) != "[]" {
		t.Errorf("empty active_overrides marshaled = %s (%v), want []", raw, err)
	}
}

func TestRoutingSnapshot_StoreErrorAndCapability(t *testing.T) {
	st := &routingMapTestStore{mockStore: newMockStore(), err: context.DeadlineExceeded}
	h := &AdminHandlers{store: st}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/routing/snapshot?org_id=o", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminauth.ContextKeyIsRoot{}, true))
	rec := httptest.NewRecorder()
	h.RoutingSnapshot().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error status = %d, want 500", rec.Code)
	}

	if code, _ := callSnapshotView(t, &AdminHandlers{store: newMockStore()}, "admin-root", true, "/api/routing/snapshot?org_id=o"); code != http.StatusNotImplemented {
		t.Fatalf("capability-less store status = %d, want 501", code)
	}
}

func TestActiveRuleOverrides_OrderingAndInertRules(t *testing.T) {
	rules := []adminstore.RoutingMapRule{
		{ID: "a", Priority: 1, Enabled: true},
		{ID: "b", Priority: 10, Enabled: true},
		{ID: "c", Priority: 10, Enabled: true}, // tie with b: stable order kept
		{ID: "d", Priority: 50, Enabled: false},
	}
	got := activeRuleOverrides(rules)
	if len(got) != 3 {
		t.Fatalf("active = %d entries, want 3 (disabled rule never appears)", len(got))
	}
	wantIDs := []string{"b", "c", "a"}
	for i, w := range wantIDs {
		if got[i].ID != w {
			t.Errorf("active[%d].id = %q, want %q (priority DESC, stable ties)", i, got[i].ID, w)
		}
	}
	if got[0].Priority != 10 || got[2].Priority != 1 {
		t.Errorf("priorities = %d,%d,%d, want 10,10,1", got[0].Priority, got[1].Priority, got[2].Priority)
	}

	if empty := activeRuleOverrides(nil); empty == nil || len(empty) != 0 {
		t.Errorf("no rules = %#v, want empty non-nil slice", empty)
	}
}
