package handlers

// W-CRED: the org-admin view of the credit wallet plus the starter-grant
// wiring. The authz matrix runs on the mock store (no DB): root passes,
// a member with budgets.manage reads their own org, a member without it is
// 403, and a caller with no membership on the target org gets 404 (a foreign
// wallet must not reveal that it exists). The grant tests run on the
// disposable stand: exactly one grant per org, one journal entry.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// creditsViewRouter mounts the two org-scoped wallet reads exactly like
// mountBilling does (route-scoped middleware so chi resolves {id}).
func creditsViewRouter(t *testing.T, store *mockStore) (*testAdminHandlers, *chi.Mux) {
	t.Helper()
	h := newTestAdminH(store)
	h.SetCreditStore(credits.NewStore(nil, slog.Default()), nil)
	h.initBillingHandlers()
	require.NotNil(t, h.billing.credit)

	r := chi.NewRouter()
	r.With(h.RequireOrgPermissionCreditsRead()).Get("/api/orgs/{id}/credits/balance", h.billing.credit.HandleGetBalance)
	r.With(h.RequireOrgPermissionCreditsRead()).Get("/api/orgs/{id}/credits/transactions", h.billing.credit.HandleGetTransactions)
	return h, r
}

func TestCreditsOrgView_AuthzMatrix(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u-admin/org-1"] = &adminstore.OrgMembership{UserID: "u-admin", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	store.orgMembers["u-operator/org-1"] = &adminstore.OrgMembership{UserID: "u-operator", OrgID: "org-1", Role: adminstore.RoleOperator}
	store.orgMembers["u-reader/org-1"] = &adminstore.OrgMembership{UserID: "u-reader", OrgID: "org-1", Role: adminstore.RoleReader}
	_, r := creditsViewRouter(t, store)

	get := func(req *http.Request) *httptest.ResponseRecorder {
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, req)
		return rw
	}

	// Root (platform operator) passes on any org.
	rec := get(sessionRequest("root-1", true, "/api/orgs/org-9/credits/balance"))
	assert.Equal(t, http.StatusOK, rec.Code, "root must keep the operator view")

	// Org-admin reads their own org's wallet.
	rec = get(sessionRequest("u-admin", false, "/api/orgs/org-1/credits/balance"))
	assert.Equal(t, http.StatusOK, rec.Code, "org-admin must see their own balance")
	assert.Contains(t, rec.Body.String(), `"org_id":"org-1"`)

	// Operator holds budgets.manage too.
	rec = get(sessionRequest("u-operator", false, "/api/orgs/org-1/credits/transactions"))
	assert.Equal(t, http.StatusOK, rec.Code, "operator (budgets.manage) must see their own ledger")

	// Member without budgets.manage: 403, authenticated but not allowed.
	rec = get(sessionRequest("u-reader", false, "/api/orgs/org-1/credits/balance"))
	assert.Equal(t, http.StatusForbidden, rec.Code, "reader (no budgets.manage) must be 403")

	// No membership on the target org: 404 — a foreign wallet must not be
	// distinguishable from a missing one (org A never sees org B's wallet).
	rec = get(sessionRequest("u-admin", false, "/api/orgs/org-2/credits/balance"))
	assert.Equal(t, http.StatusNotFound, rec.Code, "foreign-org balance must 404")
	assert.Contains(t, rec.Body.String(), "not found")
	rec = get(sessionRequest("u-admin", false, "/api/orgs/org-2/credits/transactions"))
	assert.Equal(t, http.StatusNotFound, rec.Code, "foreign-org transactions must 404")

	// Unauthenticated (no session user): fail-closed 404 like any stranger.
	anon := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/orgs/org-1/credits/balance", nil)
	rec = get(anon)
	assert.Equal(t, http.StatusNotFound, rec.Code, "a caller without a session has no membership")
}

// TestGrantBetaStarterCredits_ExactlyOnceWithAudit drives the admin
// create-org hook against the disposable stand: repeated invocations (the
// create+invite replay) grant exactly once and journal exactly one entry
// with the fixed "beta-starter-grant" motive.
func TestGrantBetaStarterCredits_ExactlyOnceWithAudit(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, "4321")
	org := fmt.Sprintf("wcred-h-%x", time.Now().UnixNano())
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM credit_transactions WHERE org_id = $1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM org_credits WHERE org_id = $1`, org)
	}
	cleanup()
	t.Cleanup(cleanup)

	h := newTestAdminH(newMockStore())
	h.SetCreditStore(credits.NewStore(pool, slog.Default()), pool)
	h.initBillingHandlers()
	lg := newRecordingAuditLogger()
	h.billing.credit.SetAuditLogger(lg, nil)

	req := sessionRequest("root-1", true, "/api/organizations")
	h.GrantBetaStarterCredits(req, org)
	h.GrantBetaStarterCredits(req, org) // re-invoked on a re-create replay: no-op
	h.GrantBetaStarterCredits(req, org)

	var rows int64
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'topup' AND invoice_ref = $2`,
		org, credits.StarterGrantReason).Scan(&rows))
	require.Equal(t, int64(1), rows, "the grant must stay exactly one per org")

	var balance int64
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, org).Scan(&balance))
	require.Equal(t, int64(4321), balance)

	rec := waitAuditRecord(t, lg)
	assert.Equal(t, "credit_starter_grant", rec.Action)
	assert.Equal(t, credits.StarterGrantReason, rec.Reason, "the fixed server motive must reach the journal")
	assert.Equal(t, fmt.Sprintf("org:%s", org), rec.Resource)
	assert.Contains(t, rec.Details, "amount_cents=4321")

	// The no-op calls must not journal.
	select {
	case extra := <-lg.records:
		t.Fatalf("the idempotent replays must not journal: %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestGrantBetaStarterCredits_DisabledByZero pins the env kill-switch: no
// ledger row, no audit entry.
func TestGrantBetaStarterCredits_DisabledByZero(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, "0")
	org := fmt.Sprintf("wcred-h-off-%x", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM credit_transactions WHERE org_id = $1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM org_credits WHERE org_id = $1`, org)
	})

	h := newTestAdminH(newMockStore())
	h.SetCreditStore(credits.NewStore(pool, slog.Default()), pool)
	h.initBillingHandlers()
	lg := newRecordingAuditLogger()
	h.billing.credit.SetAuditLogger(lg, nil)

	h.GrantBetaStarterCredits(sessionRequest("root-1", true, "/api/organizations"), org)

	var rows int64
	require.NoError(t, pool.QueryRow(t.Context(),
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1`, org).Scan(&rows))
	require.Equal(t, int64(0), rows)
	select {
	case extra := <-lg.records:
		t.Fatalf("a disabled grant must not journal: %+v", extra)
	default:
	}
}

// TestCreateOrganization_BalanceMovedByGrant is the store-level complement:
// on the real pool the wallet the CRUD flow creates (balance 0 via
// adminstore.CreateOrganization) ends at the granted amount after the hook.
func TestCreateOrganization_BalanceMovedByGrant(t *testing.T) {
	pool := testdb.Postgres(t)
	t.Setenv(credits.StarterGrantEnvVar, "5000")
	org := fmt.Sprintf("wcred-h-bal-%x", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM credit_transactions WHERE org_id = $1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM org_credits WHERE org_id = $1`, org)
	})

	h := newTestAdminH(newMockStore())
	h.SetCreditStore(credits.NewStore(pool, slog.Default()), pool)
	h.initBillingHandlers()

	h.GrantBetaStarterCredits(sessionRequest("root-1", true, "/api/organizations"), org)
	st := h.billing.credit
	bal, err := st.store.GetBalance(t.Context(), org)
	require.NoError(t, err)
	assert.Equal(t, int64(5000), bal.BalanceCents)
}
