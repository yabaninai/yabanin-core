package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/fleet"
)

// E03-P01 W04-C03: fleet-registry read endpoints. The arms drive the
// real router with session cookies (same harness as the security-inbox
// battery, including its siSessionCookie/siSessionKey helpers): the
// root-only gate, the org-scoped list/detail, the EXPLICIT revoked
// marker, and the read-only plane are all exercised end-to-end.

// fleetFixture is the shared mockStore plus the fleetStore capability.
type fleetFixture struct {
	*mockStore
	rows    map[string][]fleet.StoredInstallation
	byDep   map[string]fleet.StoredInstallation // org_id+"/"+deployment_id
	listErr error
	getErr  error
}

func newFleetFixture() *fleetFixture {
	return &fleetFixture{
		mockStore: newMockStore(),
		rows:      map[string][]fleet.StoredInstallation{},
		byDep:     map[string]fleet.StoredInstallation{},
	}
}

func (f *fleetFixture) List(_ context.Context, orgID string) ([]fleet.StoredInstallation, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]fleet.StoredInstallation{}, f.rows[orgID]...), nil
}

func (f *fleetFixture) Get(_ context.Context, orgID, deploymentID string) (fleet.StoredInstallation, bool, error) {
	if f.getErr != nil {
		return fleet.StoredInstallation{}, false, f.getErr
	}
	inst, ok := f.byDep[orgID+"/"+deploymentID]
	return inst, ok, nil
}

func flStored(org, deploy, state string, revokedAt *time.Time, reason string, heartbeat *time.Time) fleet.StoredInstallation {
	return fleet.StoredInstallation{
		Identity: fleet.Identity{OrgID: org, DeploymentID: deploy},
		State:    fleet.State(state),
		Caps: fleet.NegotiatedCaps{
			FormatVersion: fleet.CapsFormatVersion,
			Capabilities:  []string{"caps.health.heartbeat"},
			Unsupported:   []string{"vendor.extra.feature"},
		},
		EnrolledAt:       time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC),
		CapsUpdatedAt:    time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC),
		LastHeartbeatAt:  heartbeat,
		RevokedAt:        revokedAt,
		RevocationReason: reason,
	}
}

func flSeed(f *fleetFixture) (orgA, orgB string) {
	orgA, orgB = "acme-license-org", "other-license-org"
	beat := time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC)
	revoked := time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC)
	f.rows[orgA] = []fleet.StoredInstallation{
		flStored(orgA, "deploy-dr", string(fleet.StateEnrolled), nil, "", nil),
		flStored(orgA, "deploy-prod", string(fleet.StateRevoked), &revoked, "operator audit", &beat),
	}
	for _, inst := range f.rows[orgA] {
		f.byDep[inst.OrgID+"/"+inst.DeploymentID] = inst
	}
	return orgA, orgB
}

// flServe builds the real router over the fixture and returns helpers.
func flServe(t *testing.T, f *fleetFixture) (get func(path string, cookie *http.Cookie) *httptest.ResponseRecorder, do func(method, path string, cookie *http.Cookie) *httptest.ResponseRecorder) {
	t.Helper()
	h := New(f, siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)
	do = func(method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	return func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		return do(http.MethodGet, path, cookie)
	}, do
}

func TestFleetHandlers_ListAndDetail(t *testing.T) {
	f := newFleetFixture()
	orgA, _ := flSeed(f)
	get, _ := flServe(t, f)
	root := siSessionCookie(t, "admin-root", true)

	w := get("/api/organizations/"+orgA+"/fleet/installations", root)
	require.Equal(t, http.StatusOK, w.Code)
	var list struct {
		Data []fleetInstallationJSON `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	if len(list.Data) != 2 {
		t.Fatalf("want 2 installations, got %d", len(list.Data))
	}
	// Deterministic store order (deployment_id), revoked explicitly
	// marked, caps document round-trips with the visible remainder.
	first, revokedRow := list.Data[0], list.Data[1]
	if first.DeploymentID != "deploy-dr" || revokedRow.DeploymentID != "deploy-prod" {
		t.Fatalf("unexpected order: %+v %+v", first, revokedRow)
	}
	if first.Revoked || first.RevokedAt != nil || first.RevocationReason != "" {
		t.Fatalf("live row must not carry revoked markers: %+v", first)
	}
	if !revokedRow.Revoked {
		t.Fatal("revoked row must carry the explicit revoked:true marker")
	}
	if revokedRow.RevokedAt == nil || revokedRow.RevocationReason != "operator audit" {
		t.Fatalf("revoked row must carry revoked_at and reason: %+v", revokedRow)
	}
	if revokedRow.State != "revoked" {
		t.Fatalf("state must be verbatim: %+v", revokedRow)
	}
	if revokedRow.Caps.FormatVersion != fleet.CapsFormatVersion ||
		len(revokedRow.Caps.Capabilities) != 1 || len(revokedRow.Caps.Unsupported) != 1 {
		t.Fatalf("caps document must round-trip: %+v", revokedRow.Caps)
	}
	if revokedRow.LastHeartbeatAt == nil {
		t.Fatal("heartbeat stamp must be visible when set")
	}

	// Detail: the one-installation arm.
	w = get("/api/organizations/"+orgA+"/fleet/installations/deploy-dr", root)
	require.Equal(t, http.StatusOK, w.Code)
	var one struct {
		Data fleetInstallationJSON `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &one))
	if one.Data.DeploymentID != "deploy-dr" || one.Data.State != "enrolled" {
		t.Fatalf("unexpected detail: %+v", one.Data)
	}
	if one.Data.LastHeartbeatAt != nil {
		t.Fatalf("no heartbeat observed yet: %+v", one.Data)
	}
}

func TestFleetHandlers_PermissionRefusal(t *testing.T) {
	f := newFleetFixture()
	orgA, _ := flSeed(f)
	get, _ := flServe(t, f)

	// Non-root (org admin session) is refused by the root-only gate.
	w := get("/api/organizations/"+orgA+"/fleet/installations", siSessionCookie(t, "admin-1", false))
	require.Equal(t, http.StatusForbidden, w.Code)

	// Anonymous: the session middleware answers first.
	w = get("/api/organizations/"+orgA+"/fleet/installations", nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	// The detail route carries the same gate.
	w = get("/api/organizations/"+orgA+"/fleet/installations/deploy-prod", siSessionCookie(t, "admin-1", false))
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestFleetHandlers_NotFoundAndForeignOrg(t *testing.T) {
	f := newFleetFixture()
	orgA, orgB := flSeed(f)
	get, _ := flServe(t, f)
	root := siSessionCookie(t, "admin-root", true)

	// Unknown deployment of a known org: 404.
	w := get("/api/organizations/"+orgA+"/fleet/installations/deploy-ghost", root)
	require.Equal(t, http.StatusNotFound, w.Code)

	// Foreign org: its list is empty and its lookups 404 — the store
	// scopes by (org_id, deployment_id), so existence never leaks.
	w = get("/api/organizations/"+orgB+"/fleet/installations", root)
	require.Equal(t, http.StatusOK, w.Code)
	var list struct {
		Data []fleetInstallationJSON `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	if len(list.Data) != 0 {
		t.Fatalf("foreign org list must be empty, got %d", len(list.Data))
	}
	w = get("/api/organizations/"+orgB+"/fleet/installations/deploy-prod", root)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestFleetHandlers_InvalidCoordinates(t *testing.T) {
	f := newFleetFixture()
	orgA, _ := flSeed(f)
	get, _ := flServe(t, f)
	root := siSessionCookie(t, "admin-root", true)

	// The path org and deployment coordinates follow the registry's
	// structural law (identity-model §3): padded values are 400s, not
	// store probes.
	w := get("/api/organizations/"+orgA+"%20/fleet/installations", root)
	require.Equal(t, http.StatusBadRequest, w.Code)
	w = get("/api/organizations/"+orgA+"/fleet/installations/deploy-prod%20", root)
	require.Equal(t, http.StatusBadRequest, w.Code)
	// Empty org coordinate: chi still matches the route, and the
	// handler's structural law refuses it (400 — «пустая — отказ»,
	// never a store probe).
	w = get("/api/organizations//fleet/installations", root)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFleetHandlers_ReadOnlyPlane(t *testing.T) {
	f := newFleetFixture()
	orgA, _ := flSeed(f)
	_, do := flServe(t, f)
	root := siSessionCookie(t, "admin-root", true)

	// «N/A мутаций»: no mutation route exists on this plane. A POST is
	// stopped by the CSRF middleware (403, token-less); with a CSRF
	// token chi would answer 405 — the routes inventory golden pins the
	// GET-only surface either way.
	w := do(http.MethodPost, "/api/organizations/"+orgA+"/fleet/installations", root)
	require.Equal(t, http.StatusForbidden, w.Code)
	w = do(http.MethodDelete, "/api/organizations/"+orgA+"/fleet/installations/deploy-prod", root)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestFleetHandlers_UnavailableAndStoreErrors(t *testing.T) {
	// Capability absent: plain mockStore exposes neither the fleet
	// capability nor a pool — the route answers honest 503.
	h := New(newMockStore(), siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/organizations/acme/fleet/installations", nil)
	req.AddCookie(siSessionCookie(t, "admin-root", true))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Store failures surface as 500s, never as empty successes.
	f := newFleetFixture()
	orgA, _ := flSeed(f)
	f.listErr = errors.New("boom")
	get, _ := flServe(t, f)
	w = get("/api/organizations/"+orgA+"/fleet/installations", siSessionCookie(t, "admin-root", true))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	f.listErr = nil
	f.getErr = errors.New("boom")
	w = get("/api/organizations/"+orgA+"/fleet/installations/deploy-prod", siSessionCookie(t, "admin-root", true))
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
