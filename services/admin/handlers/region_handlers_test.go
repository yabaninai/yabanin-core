package handlers

// Regression tests for the region-routing handlers' path-parameter plumbing.
// The routes register "/api/organizations/{id}/region" (router_ops.go), so
// chi exposes the org segment under the parameter name "id". When the
// handlers read a name that never matches the wildcard, the path org
// silently degrades to "" — GET always answers the "sg" default and PUT
// upserts an empty-org row. The recording stub pins the fix: the org
// segment of the URL must reach the storage call verbatim.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// recordingRegionStore captures the arguments the handlers pass down.
// DB() returns a non-nil zero pool so the wired-store probe passes without
// a live connection; the stub methods never touch it. getErr/upsertErr
// inject storage failures for the A04 honesty tests (zero values keep the
// happy-path behavior the earlier tests pin).
type recordingRegionStore struct {
	gotGetOrg    string
	gotUpsertOrg string
	gotRegion    string
	gotPinned    bool
	getErr       error
	upsertErr    error
}

func (s *recordingRegionStore) DB() *pgxpool.Pool { return &pgxpool.Pool{} }

func (s *recordingRegionStore) GetOrgHomeRegion(ctx context.Context, orgID string) (string, bool, error) {
	s.gotGetOrg = orgID
	return "eu", true, s.getErr
}

func (s *recordingRegionStore) UpsertOrgHomeRegion(ctx context.Context, orgID, homeRegion string, pinned bool) error {
	s.gotUpsertOrg = orgID
	s.gotRegion = homeRegion
	s.gotPinned = pinned
	return s.upsertErr
}

// regionTestRouter mounts the handlers with the exact route shape of
// router_ops.go's protected group (parameter names are what matters here).
func regionTestRouter(h *RegionHandlers) http.Handler {
	r := chi.NewRouter()
	r.Get("/api/organizations/{id}/region", h.GetOrgRegion)
	r.Put("/api/organizations/{id}/region", h.UpdateOrgRegion)
	return r
}

func TestRegionHandlers_PathOrgReachesStore(t *testing.T) {
	store := &recordingRegionStore{}
	router := regionTestRouter(NewRegionHandlers(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-7/region", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET region: status %d, want 200", rec.Code)
	}
	if store.gotGetOrg != "org-7" {
		t.Fatalf("GET region passed org %q to the store, want %q — the path org is being dropped", store.gotGetOrg, "org-7")
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/organizations/org-7/region",
		strings.NewReader(`{"home_region":"eu","residency_pinned":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT region: status %d, want 200", rec.Code)
	}
	if store.gotUpsertOrg != "org-7" {
		t.Fatalf("PUT region passed org %q to the store, want %q — the path org is being dropped", store.gotUpsertOrg, "org-7")
	}
	if store.gotRegion != "eu" || !store.gotPinned {
		t.Fatalf("PUT region body degraded: region=%q pinned=%v", store.gotRegion, store.gotPinned)
	}
}

func TestRegionHandlers_UnwiredStore503(t *testing.T) {
	router := regionTestRouter(NewRegionHandlers(nil, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-7/region", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET region with nil store: status %d, want 503", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/organizations/org-7/region",
		strings.NewReader(`{"home_region":"eu"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT region with nil store: status %d, want 503", rec.Code)
	}
}

func TestRegionHandlers_InvalidBody400(t *testing.T) {
	router := regionTestRouter(NewRegionHandlers(&recordingRegionStore{}, nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/organizations/org-7/region",
		strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT region with invalid body: status %d, want 400", rec.Code)
	}
}

// ── A04 honesty contract (audit artifacts/preview-audit-20261101/AUDIT.txt
// §A04; cards N09-P05-T05 / N07-P07 error-honesty aspect) ────────────────────
// The store distinguishes "org has no assignment row" (pgx.ErrNoRows — the
// legitimate default answer) from a store outage (any other error). The
// handler must never paper an outage over with the "sg" default: the API
// would report a residency the database never stated. GET outage → 503 with
// an apiError body and never the "sg" default; PUT outage → non-2xx.

func TestRegionHandlers_GetOrgRegion_NoRowAnswersDefault(t *testing.T) {
	router := regionTestRouter(NewRegionHandlers(&recordingRegionStore{getErr: pgx.ErrNoRows}, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-7/region", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET region with no assignment row: status %d, want 200 (a missing row is the documented default)", rec.Code)
	}
	var body struct {
		HomeRegion      string `json:"home_region"`
		ResidencyPinned bool   `json:"residency_pinned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET region no-row body %q: %v", rec.Body.String(), err)
	}
	if body.HomeRegion != "sg" || body.ResidencyPinned {
		t.Fatalf("GET region no-row answer: got (%q, %v), want (\"sg\", false)", body.HomeRegion, body.ResidencyPinned)
	}
}

func TestRegionHandlers_GetOrgRegion_OutageIs503NeverDefault(t *testing.T) {
	store := &recordingRegionStore{getErr: errors.New("simulated store outage: connection refused")}
	router := regionTestRouter(NewRegionHandlers(store, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-7/region", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET region during store outage: status %d, want 503 — an outage must not masquerade as the sg default", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sg") {
		t.Fatalf("GET region outage body %q must never answer the \"sg\" default", rec.Body.String())
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" {
		t.Fatalf("GET region outage body %q: want a non-empty apiError payload, unmarshal err %v", rec.Body.String(), err)
	}
	if strings.Contains(body.Error, "connection refused") {
		t.Fatalf("GET region outage body %q must not echo internal store error detail", body.Error)
	}
}

func TestRegionHandlers_GetOrgRegion_PinnedRowActualValues(t *testing.T) {
	router := regionTestRouter(NewRegionHandlers(&recordingRegionStore{}, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-7/region", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET region with assignment row: status %d, want 200", rec.Code)
	}
	var body struct {
		HomeRegion      string `json:"home_region"`
		ResidencyPinned bool   `json:"residency_pinned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET region body %q: %v", rec.Body.String(), err)
	}
	if body.HomeRegion != "eu" || !body.ResidencyPinned {
		t.Fatalf("GET region stored row: got (%q, %v), want (\"eu\", true)", body.HomeRegion, body.ResidencyPinned)
	}
}

func TestRegionHandlers_UpdateOrgRegion_OutageIsNon2xx(t *testing.T) {
	router := regionTestRouter(NewRegionHandlers(&recordingRegionStore{
		upsertErr: errors.New("simulated store outage: connection refused"),
	}, nil))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/organizations/org-7/region",
		strings.NewReader(`{"home_region":"eu","residency_pinned":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code < 400 || rec.Code > 599 {
		t.Fatalf("PUT region during store outage: status %d, want a 4xx/5xx error — silent success hides a failed residency write", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Fatalf("PUT region outage body %q must not echo internal store error detail", rec.Body.String())
	}
}
