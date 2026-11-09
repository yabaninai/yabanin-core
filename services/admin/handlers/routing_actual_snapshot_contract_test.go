package handlers_test

// the FULL SetupRouter, the same way routing_views_routing_test.go pins
// routing/map and providers/health. The acceptance matrix per view:
//
//	anon                → 401 (session boundary)
//	root                → 200 (any org)
//	reader              → 200 actual (analytics.read) / 404 snapshot (routing.manage)
//	non-member          → 404 (membership-blind, no tenant leak)
//	missing store cap   → 501 (requireStore capability check)

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	routingActualOrg        = "org-ract"
	routingActualForeignOrg = "org-ract-foreign"

	routingActualPath          = "/api/routing/actual?org_id=" + routingActualOrg
	routingSnapshotPath        = "/api/routing/snapshot?org_id=" + routingActualOrg
	routingActualForeignPath   = "/api/routing/actual?org_id=" + routingActualForeignOrg
	routingSnapshotForeignPath = "/api/routing/snapshot?org_id=" + routingActualForeignOrg
)

// routingActualStore adds the capabilities the two views need on top of the
// shared stubStore. Membership lookup mirrors requireOrgRead's source.
type routingActualStore struct {
	stubStore
	roles map[string]adminstore.OrgRole
}

func (s *routingActualStore) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *routingActualStore) GetRoutingMap(context.Context, string) (*adminstore.RoutingMap, error) {
	return &adminstore.RoutingMap{}, nil
}

func (s *routingActualStore) GetActualRouting(context.Context, string, time.Time, time.Time) (*adminstore.RoutingActual, error) {
	return &adminstore.RoutingActual{Edges: []adminstore.RoutingActualEdge{}}, nil
}

func routingActualRouter(t *testing.T, store *routingActualStore) http.Handler {
	t.Helper()
	return handlers.New(store, orgRoutingSecret, "localhost", nil).SetupRouter()
}

func routingActualGet(t *testing.T, router http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		req.AddCookie(testCookie("yabanin_csrf_token", orgRoutingCSRF))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRoutingActualSnapshot_Contract(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, orgRoutingSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, orgRoutingSecret)

	t.Run("anon is 401 on both views (session boundary)", func(t *testing.T) {
		router := routingActualRouter(t, &routingActualStore{})
		if w := routingActualGet(t, router, routingActualPath, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET routing/actual = %d, want 401", w.Code)
		}
		if w := routingActualGet(t, router, routingSnapshotPath, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET routing/snapshot = %d, want 401", w.Code)
		}
	})

	t.Run("root reads both views for any org", func(t *testing.T) {
		router := routingActualRouter(t, &routingActualStore{})
		if w := routingActualGet(t, router, routingActualPath, rootCookie); w.Code != http.StatusOK {
			t.Errorf("root GET routing/actual = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := routingActualGet(t, router, routingSnapshotPath, rootCookie); w.Code != http.StatusOK {
			t.Errorf("root GET routing/snapshot = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("reader sees recorded traffic but not the configuration snapshot", func(t *testing.T) {
		// RoleReader holds analytics.read (recorded paths are traffic) but
		// not routing.manage (the snapshot is configuration state) — the
		// split the two views document.
		store := &routingActualStore{roles: map[string]adminstore.OrgRole{routingActualOrg: adminstore.RoleReader}}
		router := routingActualRouter(t, store)

		if w := routingActualGet(t, router, routingActualPath, adminCookie); w.Code != http.StatusOK {
			t.Errorf("reader GET routing/actual = %d, want 200 (analytics.read suffices)", w.Code)
		}
		if w := routingActualGet(t, router, routingSnapshotPath, adminCookie); w.Code != http.StatusNotFound {
			t.Errorf("reader GET routing/snapshot = %d, want 404 (routing.manage required)", w.Code)
		}
	})

	t.Run("non-member gets the blind 404 on both views", func(t *testing.T) {
		store := &routingActualStore{roles: map[string]adminstore.OrgRole{}}
		router := routingActualRouter(t, store)

		if w := routingActualGet(t, router, routingActualForeignPath, adminCookie); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign routing/actual = %d, want 404", w.Code)
		}
		if w := routingActualGet(t, router, routingSnapshotForeignPath, adminCookie); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign routing/snapshot = %d, want 404", w.Code)
		}
	})

	t.Run("store without the capabilities answers 501, not a panic", func(t *testing.T) {
		// A bare stubStore satisfies StoreInterface but neither view
		// capability; root passes the org gate, then the assertion fails.
		router := handlers.New(&stubStore{}, orgRoutingSecret, "localhost", nil).SetupRouter()
		if w := routingActualGet(t, router, routingActualPath, rootCookie); w.Code != http.StatusNotImplemented {
			t.Errorf("root GET routing/actual (capability-less store) = %d, want 501", w.Code)
		}
		if w := routingActualGet(t, router, routingSnapshotPath, rootCookie); w.Code != http.StatusNotImplemented {
			t.Errorf("root GET routing/snapshot (capability-less store) = %d, want 501", w.Code)
		}
	})
}
