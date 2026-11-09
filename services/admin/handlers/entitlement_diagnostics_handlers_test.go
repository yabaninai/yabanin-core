package handlers_test

// E01-P05 W04-C02: GET /api/entitlement/diagnostics asserted through the
// FULL SetupRouter (session auth, like client_config_handlers_test.go):
//
//	anon / non-root → 401 / 403 (root-only route, MustBeRoot chain)
//	root, wired     → 200 with the exact snapshot (1:1 copy, features
//	                  never null) — including the DARK snapshot of a
//	                  hard-expired or unconfigured contour: expiry never
//	                  gates the diagnostics endpoint itself
//	root, unwired   → 503 (honest absence, route still mounted)
//	mutations       → 405 (the plane is GET-only by design)
//
// The license boundary (license_boundary_test.go) is pinned separately:
// these tests exercise the seam through a fake, not a license import.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/services/admin/handlers"
)

const edSecret = "test-session-secret" // #nosec G101 -- test-only HMAC key

// fakeEntitlementDiagnostics arms the route with a fixed snapshot.
type fakeEntitlementDiagnostics struct {
	snap handlers.EntitlementDiagnosticsSnapshot
}

func (f fakeEntitlementDiagnostics) EntitlementDiagnostics() handlers.EntitlementDiagnosticsSnapshot {
	return f.snap
}

func entitlementRouter(t *testing.T, src handlers.EntitlementDiagnosticsSource) (*handlers.AdminHandlers, http.Handler) {
	t.Helper()
	h := handlers.New(&stubStore{}, edSecret, "localhost", nil)
	if src != nil {
		h.SetEntitlementDiagnostics(src)
	}
	t.Cleanup(h.Stop)
	return h, h.SetupRouter()
}

func entitlementGet(t *testing.T, router http.Handler, method, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "/api/entitlement/diagnostics", nil)
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestEntitlementDiagnostics_AuthBoundary(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, edSecret)
	plainCookie := makeSessionCookie(t, "ops@x.test", false, edSecret)
	_, router := entitlementRouter(t, fakeEntitlementDiagnostics{})

	t.Run("anon is 401", func(t *testing.T) {
		if w := entitlementGet(t, router, http.MethodGet, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET = %d, want 401", w.Code)
		}
	})
	t.Run("non-root session is 403", func(t *testing.T) {
		if w := entitlementGet(t, router, http.MethodGet, plainCookie); w.Code != http.StatusForbidden {
			t.Errorf("non-root GET = %d, want 403 (body: %s)", w.Code, w.Body.String())
		}
	})
	t.Run("mutations never reach the handler", func(t *testing.T) {
		// The session chain's CSRF middleware rejects unsafe methods
		// without a token (403) before routing; with a token chi would
		// answer 405 (GET-only registration, pinned by the routes
		// golden). Either way no mutation method is ever served.
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if w := entitlementGet(t, router, method, rootCookie); w.Code != http.StatusForbidden {
				t.Errorf("%s = %d, want 403 (CSRF gate; body: %s)", method, w.Code, w.Body.String())
			}
		}
	})
}

func TestEntitlementDiagnostics_Snapshots(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, edSecret)

	t.Run("active snapshot is served 1:1", func(t *testing.T) {
		src := fakeEntitlementDiagnostics{snap: handlers.EntitlementDiagnosticsSnapshot{
			Configured: true, Active: true, OrgID: "ex-org",
			Seats: 7, Features: []string{"protection-pack"}, ExpiresAt: "2027-05-01T00:00:00Z",
		}}
		_, router := entitlementRouter(t, src)
		w := entitlementGet(t, router, http.MethodGet, rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d (body: %s)", w.Code, w.Body.String())
		}
		var body struct {
			Data handlers.EntitlementDiagnosticsSnapshot `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := body.Data
		if !got.Configured || !got.Active || got.OrgID != "ex-org" || got.Seats != 7 ||
			got.ExpiresAt != "2027-05-01T00:00:00Z" || len(got.Features) != 1 || got.Features[0] != "protection-pack" {
			t.Errorf("snapshot drifted: %+v", got)
		}
	})

	t.Run("hard-expired dark snapshot is STILL served 200", func(t *testing.T) {
		// The packet law on this plane: operators need the diagnostics
		// MOST when the entitlement is degraded — expiry never gates it.
		src := fakeEntitlementDiagnostics{snap: handlers.EntitlementDiagnosticsSnapshot{
			Configured: true, HardExpired: true, OrgID: "ex-org",
		}}
		_, router := entitlementRouter(t, src)
		w := entitlementGet(t, router, http.MethodGet, rootCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("hard-expired GET = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var body struct {
			Data handlers.EntitlementDiagnosticsSnapshot `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body.Data.HardExpired != true || body.Data.Active != false {
			t.Errorf("dark snapshot drifted: %+v", body.Data)
		}
		if body.Data.Features == nil {
			t.Error("features must serialize as [], not null")
		}
	})

	t.Run("unwired contour answers 503", func(t *testing.T) {
		_, router := entitlementRouter(t, nil)
		if w := entitlementGet(t, router, http.MethodGet, rootCookie); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET = %d, want 503 (body: %s)", w.Code, w.Body.String())
		}
	})
}
