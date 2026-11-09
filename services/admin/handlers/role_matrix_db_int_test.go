//go:build integration

package handlers

// REAL SQL boundary. The deny-sweep and the role-matrix sweep
// pin the same routes over the in-memory fixture store; this file re-runs the
// JOIN axis (privileged route × tenant role) and the contract A–D examples
// against a disposable, fully migrated Postgres (testdb.Postgres), so the
// session revalidation (TP-02), the membership lookups (GetUserOrgRoles) and
// the membership CRUD run as production SQL — the consumer entry point, not
// a helper call.
//
// Expectations mirror the committed in-memory sweeps exactly (acceptance:
// "таблица ролей согласована с deny tests на API" on the same tree): a role
// holding the route permission never gets 401/403; a member lacking it gets
// exactly 403. The fail-closed unknown role ("nope") is seeded via raw SQL —
// the store correctly refuses to create it (TestOrgMembership_InvalidRole)
// and the DB carries no CHECK constraint, so the app-layer rank-0 fallback is
// what this probe exercises end-to-end.
//
// Skipped under -short like every testdb consumer; Docker is required
// (QG2-B3). Synthetic data only, disposable container, never the live stand.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// dbRBACRouter builds the FULLY-WIRED router over the real adminstore — the
// golden fixture wiring with the primary store swapped for production SQL.
// Optional DB-gated groups stay on nil/zero pools: their gates fire before
// the handlers, so deny probes are unaffected and allowed probes may 503
// after the gate (accepted, identical to the in-memory sweep contract).
func dbRBACRouter(tb testing.TB, pool *pgxpool.Pool) (*AdminHandlers, *adminstore.Store) {
	tb.Helper()
	store := adminstore.New(pool, slog.Default(), nil)
	h := New(store, "test-session-key", "dbint.test", []string{})
	h.SetVerticalHandlers(NewVerticalHandlers(newMockStore(), nil))
	h.SetInternalServiceKey("internal-test-key")
	h.SetPortal(PortalOptions{Enabled: true, Store: newMemPortal()})
	h.SetOIDCClient(&adminauth.OIDCClient{})
	h.SetSAMLSP(&adminauth.SAMLSP{})
	h.SetSovereignHandlers(NewSovereignHandlers(nil, nil))
	h.SetRegionHandlers(NewRegionHandlers(nil, nil))
	h.SetTemplateHandlers(NewPolicyTemplateHandlers(policy.NewTemplateMarketplace(nil), nil))
	h.SetFeedbackExporter(feedback.NewExporter(nil))
	h.SetRetrainHandlers(NewRetrainHandlers(feedback.NewExporter(nil), nil))
	h.SetCreditStore(credits.NewStore(nil, nil), &pgxpool.Pool{})
	h.SetFeedbackCollector(feedback.NewCollector(nil, nil), nil)
	h.SetFeedbackLister(feedback.NewLister(nil))
	tb.Cleanup(h.Stop)
	return h, store
}

// dbSweepIdentity seeds one admin user + one membership row via the real
// store (raw SQL for the unknown role the store rejects) and returns the
// signed session cookie for it.
func dbSweepIdentity(t *testing.T, pool *pgxpool.Pool, store *adminstore.Store, run, orgID, role string) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	id, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("r031-%s-%s-%d@sweep.test", run, role, time.Now().UnixNano()),
		"r031 "+role, "integration-hash-not-used-for-login", false)
	require.NoError(t, err, "seed admin user %s", role)
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, id.ID) })
	if adminstore.ValidOrgRole(adminstore.OrgRole(role)) {
		_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{UserID: id.ID, OrgID: orgID, Role: adminstore.OrgRole(role)})
		require.NoError(t, err, "seed membership %s", role)
	} else {
		// Unknown role: the store layer rejects it by design; the raw row
		// proves the app-layer fail-closed path over the real DB.
		_, err = pool.Exec(ctx,
			`INSERT INTO admin_org_memberships (user_id, org_id, role) VALUES ($1, $2, $3)`,
			id.ID, orgID, role)
		require.NoError(t, err, "seed unknown-role membership")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_org_memberships WHERE user_id = $1 AND org_id = $2`, id.ID, orgID)
	})
	return sweepSessionCookie(t, "test-session-key", id.ID)
}

// the real SQL boundary: every org/global-gated route × every tenant-role
// identity (member of the target org), expectations from the same matrix
// helpers the gates dispatch through.
func TestOrgRoutes_RoleMatrixSweep_RealStore(t *testing.T) {
	pool := testdb.Postgres(t)
	h, store := dbRBACRouter(t, pool)
	router := h.SetupRouter()
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	org, err := store.CreateOrganization(ctx, "r031 sweep org "+run, "r031-sweep-"+run)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteOrganization(ctx, org.ID) })

	roles := append([]adminstore.OrgRole{}, adminstore.AllOrgRoles()...)
	roles = append(roles, adminstore.OrgRole("nope"))
	cookies := make(map[adminstore.OrgRole]*http.Cookie, len(roles))
	for _, role := range roles {
		cookies[role] = dbSweepIdentity(t, pool, store, run, org.ID, string(role))
	}

	specs, err := walkRoutes(router)
	require.NoError(t, err)
	documented := parseOpenAPIRoutes(t, adminOpenAPISpec)

	probe := func(spec routeSpec, cookie *http.Cookie) int {
		path := sweepPlaceholder.ReplaceAllString(spec.Pattern, org.ID)
		req := httptest.NewRequestWithContext(t.Context(), spec.Method, path, nil)
		req.Host = "dbint.test"
		req.Header.Set(OrgHeader, org.ID)
		req.AddCookie(cookie)
		if spec.Method != http.MethodGet && spec.Method != http.MethodHead && spec.Method != http.MethodOptions {
			const csrf = "dbint-csrf-token"
			req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf,
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			req.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	var failures []string
	swept := 0
	for _, spec := range specs {
		switch spec.Permission {
		case "global":
			// AUTH-01: org roles never admit the global journal — admission
			// comes only from admin_users.global_role or root, and the probe
			// identities are plain members. Every probe expects exactly 403.
			swept++
			for _, role := range roles {
				code := probe(spec, cookies[role])
				if code != http.StatusForbidden {
					failures = append(failures, fmt.Sprintf("%s %s as %q: %d, want 403 (org roles never admit the global audit journal — AUTH-01)",
						spec.Method, spec.Pattern, role, code))
				}
			}
		case "org":
			swept++
			doc, ok := documented[spec.key()]
			permName := ""
			if ok && strings.HasPrefix(doc.Permission, "org:") {
				permName = strings.TrimPrefix(doc.Permission, "org:")
			} else {
				permName = specPermissionFallback[spec.key()]
			}
			if permName == "" {
				t.Errorf("%s: org-class route without a documented org:<perm> permission", spec.key())
				continue
			}
			perm := adminstore.Permission(permName)
			for _, role := range roles {
				code := probe(spec, cookies[role])
				if adminstore.RoleHas(string(role), perm) {
					if code == http.StatusUnauthorized || code == http.StatusForbidden {
						failures = append(failures, fmt.Sprintf("%s %s as %q: %d, want org:%s to pass (real membership)",
							spec.Method, spec.Pattern, role, code, perm))
					}
				} else if code != http.StatusForbidden {
					failures = append(failures, fmt.Sprintf("%s %s as %q: %d, want 403 (real membership lacks org:%s)",
						spec.Method, spec.Pattern, role, code, perm))
				}
			}
		}
	}
	if swept < 25 {
		t.Fatalf("real-store sweep covered only %d gated routes — the walk or the class filter is broken", swept)
	}
	t.Logf("real-store role-matrix sweep: %d org/global-gated routes × %d tenant-role identities (SQL memberships)", swept, len(roles))
	if len(failures) > 0 {
		t.Errorf("real-SQL role matrix disagrees with the API gates on %d route×role probes:\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
}

// TestRBAC_ContractExamples_RealStore replays the contract examples A–D and
// with validation/rank rules, the INV-2 resourceHidden surfaces, and the
// audit event trail.
func TestRBAC_ContractExamples_RealStore(t *testing.T) {
	pool := testdb.Postgres(t)
	h, store := dbRBACRouter(t, pool)
	router := h.SetupRouter()
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	acme, err := store.CreateOrganization(ctx, "r031 acme "+run, "r031-acme-"+run)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteOrganization(ctx, acme.ID) })
	beta, err := store.CreateOrganization(ctx, "r031 beta "+run, "r031-beta-"+run)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteOrganization(ctx, beta.ID) })

	seedMember := func(orgID, role string) (*adminstore.AdminUser, *http.Cookie) {
		t.Helper()
		u, err := store.CreateAdminUser(ctx,
			fmt.Sprintf("r031-%s-%s-%d@sweep.test", run, role+orgID[:8], time.Now().UnixNano()),
			"r031 "+role, "integration-hash-not-used-for-login", false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, u.ID) })
		_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{UserID: u.ID, OrgID: orgID, Role: adminstore.OrgRole(role)})
		require.NoError(t, err)
		return u, sweepSessionCookie(t, "test-session-key", u.ID)
	}
	rootUser, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("r031-root-%d@sweep.test", time.Now().UnixNano()), "r031 root", "integration-hash-not-used-for-login", true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, rootUser.ID) })
	rootCookie := func() *http.Cookie {
		cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
			UserID: rootUser.ID, Email: rootUser.Email, IsRoot: true,
			SessionID: "dbint-root", ExpiresAt: time.Now().Add(time.Hour),
		}, "test-session-key")
		require.NoError(t, err)
		return cookie
	}

	adminUser, adminCookie := seedMember(acme.ID, string(adminstore.RoleOrgAdmin))
	readerAcme, readerCookie := seedMember(acme.ID, string(adminstore.RoleReader))
	_, auditorCookie := seedMember(acme.ID, string(adminstore.RoleSecurityAuditor))
	_, partnerCookie := seedMember(acme.ID, string(adminstore.RolePartner))
	_, readerBetaCookie := seedMember(beta.ID, string(adminstore.RoleReader))
	operatorBeta, _ := seedMember(beta.ID, string(adminstore.RoleOperator))

	call := func(method, path, body string, cookie *http.Cookie, extraHeaders map[string]string) (int, string) {
		t.Helper()
		var rd *strings.Reader
		if body == "" {
			rd = strings.NewReader("")
		} else {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequestWithContext(t.Context(), method, path, rd)
		req.Host = "dbint.test"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			const csrf = "dbint-csrf-token"
			req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf,
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			req.Header.Set("X-CSRF-Token", csrf)
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	// ── Example A — org-admin grants operator: 201 + real membership row.
	target, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("r031-target-%d@sweep.test", time.Now().UnixNano()), "r031 target", "x", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, target.ID) })
	code, body := call(http.MethodPost, "/api/organizations/"+acme.ID+"/members",
		fmt.Sprintf(`{"user_id":%q,"role":"operator"}`, target.ID), adminCookie, nil)
	require.Equal(t, http.StatusCreated, code, "A: create member as org-admin: %s", body)
	members, err := store.ListOrgMembers(ctx, acme.ID)
	require.NoError(t, err)
	found := false
	for _, m := range members {
		if m.UserID == target.ID && m.Role == adminstore.RoleOperator {
			found = true
		}
	}
	require.True(t, found, "A: operator membership row must exist after 201")
	var auditRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE action='create' AND resource='org_member' AND details LIKE '%'||$1||'%'`,
		acme.ID).Scan(&auditRows))
	require.Positive(t, auditRows, "A: the member grant must leave an audit-trail row")

	// ── Example B — differentiated validation and rank/self rejections.
	code, _ = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members",
		fmt.Sprintf(`{"user_id":%q,"role":"operator"}`, target.ID), readerCookie, nil)
	require.Equal(t, http.StatusForbidden, code, "B: reader (no members.manage) must be 403")
	code, body = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members",
		`{"user_id":"u_x","role":"root"}`, adminCookie, nil)
	require.Equal(t, http.StatusBadRequest, code, "B: invalid role must be 400: %s", body)
	require.Contains(t, body, "role must be one of", "B: invalid-role error enumerates valid roles")
	code, body = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members",
		`{"user_id":"u_x","role":"reader","is_root":true}`, adminCookie, nil)
	require.Equal(t, http.StatusBadRequest, code, "B: is_root on a membership must be 400: %s", body)
	require.Contains(t, body, "is_root cannot be set", "B: is_root rejection message")
	code, body = call(http.MethodPut, "/api/organizations/"+acme.ID+"/members/"+adminUser.ID,
		`{"role":"reader"}`, adminCookie, nil)
	require.Equal(t, http.StatusForbidden, code, "B: self role change must be 403: %s", body)
	require.Contains(t, body, "cannot change your own role", "B: self-change message")
	code, _ = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members",
		fmt.Sprintf(`{"user_id":%q,"role":"org-admin"}`, target.ID), adminCookie, nil)
	require.Equal(t, http.StatusConflict, code, "B: duplicate membership must be 409")
	partnerGrant := fmt.Sprintf(`{"user_id":%q,"role":"operator"}`, target.ID)
	code, _ = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members", partnerGrant, partnerCookie, nil)
	require.Equal(t, http.StatusForbidden, code, "B: partner (no members.manage) must never grant")

	// ── Example C — cross-org identity through the same boundary (INV-2).
	// Base org gates deny a foreign-org member with 403 (path-priority
	// targetOrgID; the reader holds no acme membership).
	code, body = call(http.MethodGet, "/api/organizations/"+acme.ID+"/members", "", readerBetaCookie,
		map[string]string{OrgHeader: beta.ID})
	require.Equal(t, http.StatusForbidden, code, "C: foreign-org reader on members must be denied: %s", body)
	require.NotContains(t, body, "user_id", "C: deny body must not leak member data")
	// resourceHidden variant (credits reads): a foreign org is 404 —
	// indistinguishable from a missing org, never 403/500.
	code, _ = call(http.MethodGet, "/api/orgs/"+acme.ID+"/credits/balance", "", readerBetaCookie,
		map[string]string{OrgHeader: beta.ID})
	require.Equal(t, http.StatusNotFound, code, "C: foreign-org credits read must be 404 resourceHidden")
	// INV-2 on the org itself: foreign org settings reads stay 404-shaped for
	// the resourceHidden family (routing map requireOrgRead).
	code, _ = call(http.MethodGet, "/api/routing/map?org_id="+acme.ID, "", readerBetaCookie,
		map[string]string{OrgHeader: beta.ID})
	require.Equal(t, http.StatusNotFound, code, "C: foreign-org routing map must be 404 resourceHidden")
	// Header↔path mismatch on an org-scoped mutation: org-scoped paths are
	// gated server-side; the members grant from a beta operator against the
	// acme path must be denied regardless of the scope hint.
	code, _ = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members",
		partnerGrant, sweepSessionCookie(t, "test-session-key", operatorBeta.ID),
		map[string]string{OrgHeader: beta.ID})
	require.Equal(t, http.StatusForbidden, code, "C: cross-org mutation attempt must be 403")
	// Member without the permission on their OWN org: exactly 403.
	code, _ = call(http.MethodGet, "/api/organizations/"+acme.ID+"/members", "", readerCookie,
		map[string]string{OrgHeader: acme.ID})
	require.Equal(t, http.StatusForbidden, code, "C: own-org reader without members.manage must be 403")

	// ── Example D — the invite surface sits behind the same members gate.
	code, _ = call(http.MethodPost, "/api/organizations/"+acme.ID+"/members/invite",
		`{"email":"x@y.z"}`, readerCookie, nil)
	require.Equal(t, http.StatusForbidden, code, "D: reader must not reach the invite surface")

	// ── Global audit journal over real memberships and the real global_role.
	code, _ = call(http.MethodGet, "/api/audit-logs", "", nil, nil)
	require.Equal(t, http.StatusUnauthorized, code, "D1: anonymous must be 401")
	code, _ = call(http.MethodGet, "/api/audit-logs", "", readerBetaCookie, nil)
	require.Equal(t, http.StatusForbidden, code, "D1: plain org member must be 403")
	// AUTH-01: an org security_auditor membership is NOT admission over real
	// SQL either — the grant lives in one org, the journal is cross-org.
	code, _ = call(http.MethodGet, "/api/audit-logs", "", auditorCookie, nil)
	require.Equal(t, http.StatusForbidden, code, "D1: org security_auditor member must stay 403 (membership never admits the global journal)")
	// The admitted identity: operator-provisioned admin_users.global_role
	// (raw SQL — handlers never mint it), no org membership at all.
	platformAuditor, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("r031-platform-auditor-%d@sweep.test", time.Now().UnixNano()),
		"r031 platform auditor", "integration-hash-not-used-for-login", false)
	require.NoError(t, err, "seed platform auditor")
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, platformAuditor.ID) })
	_, err = pool.Exec(ctx, `UPDATE admin_users SET global_role = 'security_auditor' WHERE id = $1`, platformAuditor.ID)
	require.NoError(t, err, "seed global_role for platform auditor")
	code, body = call(http.MethodGet, "/api/audit-logs", "", sweepSessionCookie(t, "test-session-key", platformAuditor.ID), nil)
	require.Equal(t, http.StatusOK, code, "D1: platform security_auditor (admin_users.global_role) must read the audit journal: %s", body)
	var auditPayload struct {
		Data []json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &auditPayload), "D1: audit payload must be JSON")
	code, _ = call(http.MethodGet, "/api/audit-logs", "", rootCookie(), nil)
	require.Equal(t, http.StatusOK, code, "D1: root must still read the audit journal")
	_ = readerAcme
}
