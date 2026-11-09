package handlers_test

// implemented — handler, store capability, unit tests, frontend — but never
// mounted, so the HTTP boundary answered 404 while every test stayed green
// (unit tests call the handler directly; the browser e2e runs on stubs).
// This is the routing contract asserted through the FULL SetupRouter, the
//
//	anon              → 401 (session boundary)
//	root              → 200 (any org)
//	member, no perm   → 404 (membership-blind, no tenant leak)
//	non-member        → 404
//	missing store cap → 501 (requireStore capability check)

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
	routingViewsOrg     = "org-rmap"
	routingViewsForeign = "org-rmap-foreign"

	routingMapPath         = "/api/routing/map?org_id=" + routingViewsOrg
	routingMapForeignPath  = "/api/routing/map?org_id=" + routingViewsForeign
	providerHealthPath     = "/api/providers/health?org_id=" + routingViewsOrg + "&period=24h"
	providerHealthNoPeriod = "/api/providers/health?org_id=" + routingViewsOrg
)

// routingViewsStore adds the two narrow capabilities the views need on top of
// the shared stubStore. Membership lookup mirrors requireOrgRead's source.
type routingViewsStore struct {
	stubStore
	roles map[string]adminstore.OrgRole
}

func (s *routingViewsStore) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *routingViewsStore) GetRoutingMap(context.Context, string) (*adminstore.RoutingMap, error) {
	return &adminstore.RoutingMap{}, nil
}

func (s *routingViewsStore) GetProviderHealth(context.Context, string, time.Time, time.Time) ([]adminstore.ProviderHealth, error) {
	return []adminstore.ProviderHealth{}, nil
}

func routingViewsRouter(t *testing.T, store *routingViewsStore) http.Handler {
	t.Helper()
	return handlers.New(store, orgRoutingSecret, "localhost", nil).SetupRouter()
}

func routingViewsGet(t *testing.T, router http.Handler, path, cookie string) *httptest.ResponseRecorder {
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

func TestRoutingViews_RoutingContract(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, orgRoutingSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, orgRoutingSecret)

	t.Run("anon is 401 on both views (session boundary)", func(t *testing.T) {
		router := routingViewsRouter(t, &routingViewsStore{})
		if w := routingViewsGet(t, router, routingMapPath, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET routing/map = %d, want 401", w.Code)
		}
		if w := routingViewsGet(t, router, providerHealthPath, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET providers/health = %d, want 401", w.Code)
		}
	})

	t.Run("root reads both views for any org", func(t *testing.T) {
		router := routingViewsRouter(t, &routingViewsStore{})
		if w := routingViewsGet(t, router, routingMapPath, rootCookie); w.Code != http.StatusOK {
			t.Errorf("root GET routing/map = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := routingViewsGet(t, router, providerHealthPath, rootCookie); w.Code != http.StatusOK {
			t.Errorf("root GET providers/health = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := routingViewsGet(t, router, providerHealthNoPeriod, rootCookie); w.Code != http.StatusOK {
			t.Errorf("root GET providers/health without period = %d, want 200 (default 24h)", w.Code)
		}
	})

	t.Run("member without the permission gets the blind 404", func(t *testing.T) {
		// RoleReader lacks routing.manage (routing map) and is fine for
		// analytics.read (provider health) — assert each view against the
		// permission it documents.
		store := &routingViewsStore{roles: map[string]adminstore.OrgRole{routingViewsOrg: adminstore.RoleReader}}
		router := routingViewsRouter(t, store)

		if w := routingViewsGet(t, router, routingMapPath, adminCookie); w.Code != http.StatusNotFound {
			t.Errorf("reader GET routing/map = %d, want 404 (routing.manage required)", w.Code)
		}
		if w := routingViewsGet(t, router, providerHealthPath, adminCookie); w.Code != http.StatusOK {
			t.Errorf("reader GET providers/health = %d, want 200 (analytics.read suffices)", w.Code)
		}
	})

	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		store := &routingViewsStore{roles: map[string]adminstore.OrgRole{}}
		router := routingViewsRouter(t, store)

		if w := routingViewsGet(t, router, routingMapForeignPath, adminCookie); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign routing/map = %d, want 404", w.Code)
		}
	})
}
