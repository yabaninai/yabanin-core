package handlers_test

// Routing contract, asserted through the FULL SetupRouter
// (session auth + CSRF chain, exactly like the neighboring mounts; the
// handler-level matrices live in currencies_handlers_test.go). The gates
// live in the handlers, so the matrix runs on plain session cookies:
//
//	anon                          → 401 on every route (session boundary)
//	POST without the CSRF pair    → 403 at the middleware, root or not
//	root + CSRF pair              → the handler runs (400/422/200 by body)
//	reader + analytics.read       → 200 units spend
//	reader on budgets/ledger      → 403 (budgets.manage is not held)
//	non-member                    → 404 (the org stays invisible)
//	store without the capability  → 501 (never a silent empty payload)

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const currenciesRoutingOwnOrg = "org-cur"

// currenciesRoutingStore is the stubStore surface plus the membership lookup
// and the three currencies capabilities (roles key on org id, exactly like
// GetUserOrgRoles' org→role contract).
type currenciesRoutingStore struct {
	stubStore
	roles map[string]adminstore.OrgRole
}

func (s *currenciesRoutingStore) GetUserOrgRoles(_ context.Context, _ string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func (s *currenciesRoutingStore) GetUnitSpendRollup(_ context.Context, orgID string, _, _ time.Time) (*adminstore.UnitSpendRollup, error) {
	return &adminstore.UnitSpendRollup{OrgID: orgID, CreditsScale: adminstore.WalletUnitScale}, nil
}

func (s *currenciesRoutingStore) GetBudgetCapsStatus(_ context.Context, orgID string, _ *float64) (*adminstore.BudgetCapsStatus, error) {
	return &adminstore.BudgetCapsStatus{OrgID: orgID, CreditsScale: adminstore.WalletUnitScale}, nil
}

func (s *currenciesRoutingStore) GetCreditsLedgerView(_ context.Context, orgID string, _ int) (*adminstore.CreditsLedgerView, error) {
	return &adminstore.CreditsLedgerView{OrgID: orgID, CreditsScale: adminstore.WalletUnitScale}, nil
}

// currenciesRoutingNoCapsStore predates the currencies program: no
// capabilities, only the membership lookup — the 501 probe identity.
type currenciesRoutingNoCapsStore struct {
	stubStore
}

func (s *currenciesRoutingNoCapsStore) GetUserOrgRoles(_ context.Context, _ string) (map[string]adminstore.OrgRole, error) {
	return map[string]adminstore.OrgRole{}, nil
}

// currenciesRoutingRequest runs one request through the router with the
// session + CSRF double-submit pair (GETs ignore the CSRF token, like the
// middleware).
func currenciesRoutingRequest(t *testing.T, router http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
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

func currenciesRoutingRouter(t *testing.T, store handlers.StoreInterface) http.Handler {
	t.Helper()
	return handlers.New(store, orgRoutingSecret, "localhost", nil).SetupRouter()
}

func TestCurrenciesRouting_SessionAndCSRFContract(t *testing.T) {
	anonCookie := ""
	adminCookie := makeSessionCookie(t, "admin@x.test", false, orgRoutingSecret)
	rootCookie := makeSessionCookie(t, "root@x.test", true, orgRoutingSecret)

	newStore := func() *currenciesRoutingStore {
		return &currenciesRoutingStore{
			roles: map[string]adminstore.OrgRole{
				currenciesRoutingOwnOrg: adminstore.RoleReader,
			},
		}
	}

	t.Run("anon is 401 on every route (session boundary)", func(t *testing.T) {
		router := currenciesRoutingRouter(t, newStore())
		targets := []struct{ method, path string }{
			{http.MethodGet, "/api/units/spend?org_id=" + currenciesRoutingOwnOrg},
			{http.MethodGet, "/api/budgets?org_id=" + currenciesRoutingOwnOrg},
			{http.MethodGet, "/api/credits/ledger?org_id=" + currenciesRoutingOwnOrg},
			{http.MethodGet, "/api/rates/catalog"},
			{http.MethodPost, "/api/rates/diff"},
			{http.MethodPost, "/api/rates/promote"},
		}
		for _, tt := range targets {
			if w := currenciesRoutingRequest(t, router, tt.method, tt.path, anonCookie, `{}`); w.Code != http.StatusUnauthorized {
				t.Errorf("anon %s %s = %d, want 401", tt.method, tt.path, w.Code)
			}
		}
	})

	t.Run("POST is CSRF-guarded even for root; with the pair the handler runs", func(t *testing.T) {
		router := currenciesRoutingRouter(t, newStore())

		// Root session, but no CSRF header: the middleware rejects before
		// the handler is reached.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/rates/diff", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(testCookie("yabanin_admin_session", rootCookie))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("root POST diff without CSRF = %d, want 403 at the middleware", w.Code)
		}

		// With the pair the handler runs and answers on the merits (an
		// empty pack object is a 400, not an auth failure).
		w = currenciesRoutingRequest(t, router, http.MethodPost, "/api/rates/diff", rootCookie, `{"pack":"{}"}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("root POST diff with CSRF pair = %d (%s), want 400 from the handler", w.Code, w.Body.String())
		}
	})

	t.Run("session reads: analytics.read on spend, rates catalog for any session", func(t *testing.T) {
		router := currenciesRoutingRouter(t, newStore())

		w := currenciesRoutingRequest(t, router, http.MethodGet, "/api/units/spend?org_id="+currenciesRoutingOwnOrg, adminCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("reader GET units spend = %d (%s), want 200", w.Code, w.Body.String())
		}
		var rollup adminstore.UnitSpendRollup
		if err := json.Unmarshal(w.Body.Bytes(), &rollup); err != nil {
			t.Fatalf("decode rollup: %v", err)
		}
		if rollup.OrgID != currenciesRoutingOwnOrg || rollup.CreditsScale != adminstore.WalletUnitScale {
			t.Errorf("unexpected rollup payload: %+v", rollup)
		}

		w = currenciesRoutingRequest(t, router, http.MethodGet, "/api/rates/catalog", adminCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("session GET rates catalog = %d, want 200 (public pricing data)", w.Code)
		}
		var cat struct {
			Ref adminstore.RatesCatalogRef `json:"ref"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &cat); err != nil {
			t.Fatalf("decode rates catalog: %v", err)
		}
		if cat.Ref.Version == "" || cat.Ref.Digest == "" {
			t.Errorf("rates catalog citation incomplete: %+v", cat.Ref)
		}
	})

	t.Run("budgets and ledger are budgets.manage-gated for sessions", func(t *testing.T) {
		router := currenciesRoutingRouter(t, newStore())

		// The session identity is a reader: analytics.read without
		// budgets.manage → 403 on both money views.
		if w := currenciesRoutingRequest(t, router, http.MethodGet, "/api/budgets?org_id="+currenciesRoutingOwnOrg, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("reader GET budgets = %d (%s), want 403", w.Code, w.Body.String())
		}
		if w := currenciesRoutingRequest(t, router, http.MethodGet, "/api/credits/ledger?org_id="+currenciesRoutingOwnOrg, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("reader GET credits ledger = %d (%s), want 403", w.Code, w.Body.String())
		}

		// Root passes the gate and reaches the capability.
		if w := currenciesRoutingRequest(t, router, http.MethodGet, "/api/budgets?org_id="+currenciesRoutingOwnOrg, rootCookie, ""); w.Code != http.StatusOK {
			t.Errorf("root GET budgets = %d (%s), want 200", w.Code, w.Body.String())
		}

		// A non-member session finds nothing (the routing store's role map
		// keys on test-admin; a foreign org id is invisible either way).
		w := currenciesRoutingRequest(t, router, http.MethodGet, "/api/units/spend?org_id=org-foreign", adminCookie, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("reader GET foreign org spend = %d, want 404", w.Code)
		}
	})

	t.Run("a store without the currencies capabilities answers 501", func(t *testing.T) {
		router := currenciesRoutingRouter(t, &currenciesRoutingNoCapsStore{})
		for _, path := range []string{
			"/api/units/spend?org_id=" + currenciesRoutingOwnOrg,
			"/api/budgets?org_id=" + currenciesRoutingOwnOrg,
			"/api/credits/ledger?org_id=" + currenciesRoutingOwnOrg,
		} {
			w := currenciesRoutingRequest(t, router, http.MethodGet, path, rootCookie, "")
			if w.Code != http.StatusNotImplemented {
				t.Errorf("root GET %s on a capability-less store = %d (%s), want 501", path, w.Code, w.Body.String())
			}
		}
	})
}
