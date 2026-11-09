package handlers_test

// never called, so the org budget settings API answered 404 at the HTTP
// boundary while its handler-level tests stayed green. This is the routing
// contract asserted through the FULL SetupRouter (session auth + CSRF chain,
// exactly like the neighboring mounts): the gates live in the handlers, so
// the matrix runs on plain session cookies —
//
//	anon                        → 401 (session boundary)
//	root                        → 200 read + write (any org)
//	member with budgets.manage  → 200 read + grace/output-cap write,
//	                              403 on the root-only reservations-mode
//	member with a lesser role   → 403 (the org is theirs, the setting is not)
//	no membership               → 404 (the org stays invisible)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	orgRoutingSecret = "test-session-secret" // #nosec G101 -- test-only HMAC key
	orgRoutingCSRF   = "csrf-token-value"    // #nosec G101 -- test-only value

	orgRoutingOwnOrg     = "org-a"
	orgRoutingForeignOrg = "org-foreign"
)

// orgRoutingStore is the stubStore surface plus the membership lookup and the
// NEXT-18f budget-settings capability the routing matrix exercises. The
// settings state is per-instance; tests run sequentially (no t.Parallel).
type orgRoutingStore struct {
	stubStore
	roles    map[string]adminstore.OrgRole
	settings map[string]*adminstore.OrgBudgetSettings
}

func newOrgRoutingStore(roles map[string]adminstore.OrgRole) *orgRoutingStore {
	return &orgRoutingStore{roles: roles, settings: map[string]*adminstore.OrgBudgetSettings{}}
}

func (s *orgRoutingStore) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *orgRoutingStore) get(orgID string) (*adminstore.OrgBudgetSettings, error) {
	settings, ok := s.settings[orgID]
	if !ok {
		return nil, fmt.Errorf("organization not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	return settings, nil
}

func (s *orgRoutingStore) GetOrgBudgetSettings(_ context.Context, orgID string) (*adminstore.OrgBudgetSettings, error) {
	return s.get(orgID)
}

func (s *orgRoutingStore) UpdateOrgGraceFloor(_ context.Context, orgID string, floorCents *int64) error {
	if _, err := s.get(orgID); err != nil {
		return err
	}
	s.settings[orgID].GraceFloorCents = floorCents
	return nil
}

func (s *orgRoutingStore) UpdateOrgReservationsMode(_ context.Context, orgID, mode string) error {
	if _, err := s.get(orgID); err != nil {
		return err
	}
	s.settings[orgID].ReservationsMode = mode
	return nil
}

func (s *orgRoutingStore) UpdateOrgDefaultOutputCap(_ context.Context, orgID string, capTokens *int64) error {
	if _, err := s.get(orgID); err != nil {
		return err
	}
	s.settings[orgID].DefaultOutputCapTokens = capTokens
	return nil
}

// orgRoutingSeed registers an org with default settings (the mode defaults to
// off, like the DB DEFAULT).
func orgRoutingSeed(s *orgRoutingStore, orgID string) {
	s.settings[orgID] = &adminstore.OrgBudgetSettings{OrgID: orgID, ReservationsMode: adminstore.ReservationsOff}
}

// orgRoutingRequest runs one request through the router with the session +
// CSRF double-submit pair (GETs ignore the CSRF token, like the middleware).
func orgRoutingRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		req.AddCookie(testCookie("yabanin_csrf_token", orgRoutingCSRF))
		req.Header.Set("X-CSRF-Token", orgRoutingCSRF)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func orgRoutingRouter(t *testing.T, store *orgRoutingStore) http.Handler {
	t.Helper()
	return handlers.New(store, orgRoutingSecret, "localhost", nil).SetupRouter()
}

// orgRoutingSettings decodes the GET /api/orgs/{id}/credits/grace payload.
type orgRoutingSettings struct {
	OrgID                  string `json:"org_id"`
	GraceFloorCents        *int64 `json:"grace_floor_cents"`
	ReservationsMode       string `json:"reservations_mode"`
	DefaultOutputCapTokens *int64 `json:"default_output_cap_tokens"`
}

func TestNEXT18f_OrgBudgetSettingsRoutingContract(t *testing.T) {
	const (
		gracePath  = "/api/orgs/" + orgRoutingOwnOrg + "/credits/grace"
		modePath   = "/api/orgs/" + orgRoutingOwnOrg + "/reservations-mode"
		capPath    = "/api/orgs/" + orgRoutingOwnOrg + "/output-cap"
		foreignGet = "/api/orgs/" + orgRoutingForeignOrg + "/credits/grace"
	)

	anonCookie := ""
	adminCookie := makeSessionCookie(t, "admin@x.test", false, orgRoutingSecret)
	rootCookie := makeSessionCookie(t, "root@x.test", true, orgRoutingSecret)

	t.Run("anon is 401 on read and write (session boundary)", func(t *testing.T) {
		store := newOrgRoutingStore(nil)
		orgRoutingSeed(store, orgRoutingOwnOrg)
		router := orgRoutingRouter(t, store)

		if w := orgRoutingRequest(t, router, http.MethodGet, gracePath, anonCookie, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET grace = %d, want 401", w.Code)
		}
		if w := orgRoutingRequest(t, router, http.MethodPut, gracePath, anonCookie, `{"grace_floor_cents":-500,"reason":"r"}`); w.Code != http.StatusUnauthorized {
			t.Errorf("anon PUT grace = %d, want 401", w.Code)
		}
	})

	t.Run("root reads and writes any org", func(t *testing.T) {
		store := newOrgRoutingStore(nil)
		orgRoutingSeed(store, orgRoutingOwnOrg)
		router := orgRoutingRouter(t, store)

		w := orgRoutingRequest(t, router, http.MethodGet, gracePath, rootCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("root GET grace = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		var got orgRoutingSettings
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode GET payload: %v", err)
		}
		if got.OrgID != orgRoutingOwnOrg || got.ReservationsMode != adminstore.ReservationsOff || got.GraceFloorCents != nil {
			t.Errorf("unexpected default payload: %+v", got)
		}

		w = orgRoutingRequest(t, router, http.MethodPut, gracePath, rootCookie, `{"grace_floor_cents":-500,"reason":"incident"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("root PUT grace = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		w = orgRoutingRequest(t, router, http.MethodGet, gracePath, rootCookie, "")
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode GET payload: %v", err)
		}
		if got.GraceFloorCents == nil || *got.GraceFloorCents != -500 {
			t.Errorf("grace floor after PUT = %v, want -500", got.GraceFloorCents)
		}

		if w := orgRoutingRequest(t, router, http.MethodPut, capPath, rootCookie, `{"default_output_cap_tokens":4096,"reason":"rollout"}`); w.Code != http.StatusOK {
			t.Errorf("root PUT output-cap = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := orgRoutingRequest(t, router, http.MethodPut, modePath, rootCookie, `{"mode":"enforce","reason":"adr-0001"}`); w.Code != http.StatusOK {
			t.Errorf("root PUT reservations-mode = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("budgets.manage member reads and writes grace/output-cap but not reservations-mode", func(t *testing.T) {
		store := newOrgRoutingStore(map[string]adminstore.OrgRole{orgRoutingOwnOrg: adminstore.RoleOperator})
		orgRoutingSeed(store, orgRoutingOwnOrg)
		router := orgRoutingRouter(t, store)

		if w := orgRoutingRequest(t, router, http.MethodGet, gracePath, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("member GET grace = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := orgRoutingRequest(t, router, http.MethodPut, gracePath, adminCookie, `{"grace_floor_cents":-100,"reason":"budget"}`); w.Code != http.StatusOK {
			t.Errorf("member PUT grace = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := orgRoutingRequest(t, router, http.MethodPut, capPath, adminCookie, `{"default_output_cap_tokens":2048,"reason":"cap"}`); w.Code != http.StatusOK {
			t.Errorf("member PUT output-cap = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if w := orgRoutingRequest(t, router, http.MethodPut, modePath, adminCookie, `{"mode":"shadow","reason":"try"}`); w.Code != http.StatusForbidden {
			t.Errorf("member PUT reservations-mode = %d, want 403 (root-only, §9)", w.Code)
		}
	})

	t.Run("lesser role member is 403", func(t *testing.T) {
		store := newOrgRoutingStore(map[string]adminstore.OrgRole{orgRoutingOwnOrg: adminstore.RoleReader})
		orgRoutingSeed(store, orgRoutingOwnOrg)
		router := orgRoutingRouter(t, store)

		if w := orgRoutingRequest(t, router, http.MethodGet, gracePath, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("reader GET grace = %d, want 403", w.Code)
		}
	})

	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		store := newOrgRoutingStore(map[string]adminstore.OrgRole{})
		orgRoutingSeed(store, orgRoutingForeignOrg)
		router := orgRoutingRouter(t, store)

		if w := orgRoutingRequest(t, router, http.MethodGet, foreignGet, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign org = %d, want 404 (resourceHidden)", w.Code)
		}
	})
}
