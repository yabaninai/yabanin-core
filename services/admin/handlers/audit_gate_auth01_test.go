package handlers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// AUTH-01 regression: the platform-wide audit gate (/api/audit-logs) admits
// ONLY root and root-authorized platform security auditors
// (admin_users.global_role) — never org memberships. Org admins can grant the
// org security_auditor role inside their own org through several write paths
// (member create/update, invite accept, SCIM), so admission derived from
// org_memberships.role is a cross-org escalation to the global audit journal:
// any org admin could mint a reader of every org's journal.
//
// All probes go through the real router and gate; mockStore carries the
// platform-level global_role map the gate must consult.

func auth01SeedUser(t *testing.T, store *mockStore, id string) *http.Cookie {
	t.Helper()
	store.adminUsers[id] = &adminstore.AdminUser{ID: id, Email: id + "@sweep.test", DisplayName: id, Active: true}
	return sweepSessionCookie(t, "test-session-key", id)
}

func auth01ProbeAudit(t *testing.T, h *AdminHandlers, cookie *http.Cookie) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs", nil)
	req.Host = "sweep.test"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.SetupRouter().ServeHTTP(w, req)
	return w.Code
}

// An org security_auditor membership must not admit the global audit route:
// the org admin who granted it could read every other org's journal.
func TestGlobalAudit01_OrgSecurityAuditorMembership_Denied(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	auditor := auth01SeedUser(t, store, "auth01-org-auditor")
	store.orgMembers["auth01-org-auditor/"+sweepOrg] =
		&adminstore.OrgMembership{UserID: "auth01-org-auditor", OrgID: sweepOrg, Role: adminstore.RoleSecurityAuditor}

	if code := auth01ProbeAudit(t, h, auditor); code != http.StatusForbidden {
		t.Fatalf("GET /api/audit-logs as org security_auditor member = %d, want 403 (membership must never admit the global journal)", code)
	}
}

// The same org role granted in a DIFFERENT org must not leak admission either
// (the baseline gate accepted any membership anywhere).
func TestGlobalAudit01_CrossOrgSecurityAuditorMembership_Denied(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	auditor := auth01SeedUser(t, store, "auth01-other-org-auditor")
	store.orgMembers["auth01-other-org-auditor/auth01-other-org"] =
		&adminstore.OrgMembership{UserID: "auth01-other-org-auditor", OrgID: "auth01-other-org", Role: adminstore.RoleSecurityAuditor}

	if code := auth01ProbeAudit(t, h, auditor); code != http.StatusForbidden {
		t.Fatalf("GET /api/audit-logs as other-org security_auditor member = %d, want 403", code)
	}
}

// The real grant path: an org admin grants security_auditor inside their own
// org via POST /api/organizations/{id}/members; the granted member still gets
// 403 on the global journal. Baseline behavior: grant succeeds (fine — org
// scope) AND the member reads the global journal (the escalation).
func TestGlobalAudit01_OrgAdminGrantPath_CannotEscalateMember(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	router := h.SetupRouter()

	orgAdminCookie := auth01SeedUser(t, store, "auth01-orgadmin")
	store.orgMembers["auth01-orgadmin/"+sweepOrg] =
		&adminstore.OrgMembership{UserID: "auth01-orgadmin", OrgID: sweepOrg, Role: adminstore.RoleOrgAdmin}

	memberID := "auth01-granted-member"
	store.adminUsers[memberID] = &adminstore.AdminUser{ID: memberID, Email: memberID + "@sweep.test", DisplayName: memberID, Active: true}

	body := []byte(`{"user_id":"` + memberID + `","role":"security_auditor"}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/organizations/"+sweepOrg+"/members", bytes.NewReader(body))
	req.Host = "sweep.test"
	req.Header.Set(OrgHeader, sweepOrg)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(orgAdminCookie)
	const csrf = "auth01-csrf-token"
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST members as org admin = %d, want 201 (the grant itself is in-scope for the org admin): %s", w.Code, w.Body.String())
	}

	memberCookie := sweepSessionCookie(t, "test-session-key", memberID)
	if code := auth01ProbeAudit(t, h, memberCookie); code != http.StatusForbidden {
		t.Fatalf("GET /api/audit-logs as member granted security_auditor by org admin = %d, want 403 (escalation closed)", code)
	}
}

// A root-authorized platform security auditor (admin_users.global_role) keeps
// global journal access without any org membership.
func TestGlobalAudit01_PlatformGlobalRole_Admitted(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	auditor := auth01SeedUser(t, store, "auth01-platform-auditor")
	store.globalRoles["auth01-platform-auditor"] = adminstore.GlobalRoleSecurityAuditor

	if code := auth01ProbeAudit(t, h, auditor); code != http.StatusOK {
		t.Fatalf("GET /api/audit-logs as platform security_auditor = %d, want 200 (root-authorized global role retains access)", code)
	}
}

// Fail-closed states: a store error on the global-role lookup and an unknown
// user must both deny. The capability-less store is pinned in the external
// test package (audit_gate_auth01_ext_test.go) where the full stub store lives.
func TestGlobalAudit01_FailClosed_StoreStates(t *testing.T) {
	t.Run("store error on global role", func(t *testing.T) {
		h, store := goldenHandlersWithStore(t)
		cookie := auth01SeedUser(t, store, "auth01-err-user")
		store.globalRoles["auth01-err-user"] = adminstore.GlobalRoleSecurityAuditor
		store.globalRoleErr = errors.New("global role lookup failed")
		if code := auth01ProbeAudit(t, h, cookie); code != http.StatusForbidden {
			t.Fatalf("GET /api/audit-logs with store error = %d, want 403", code)
		}
	})
	t.Run("unknown user at the gate", func(t *testing.T) {
		// Session revalidation passes (user row exists), but the store has no
		// global_role row for the caller → ErrNotFound → 403, never 200.
		h, store := goldenHandlersWithStore(t)
		cookie := auth01SeedUser(t, store, "auth01-no-global-role")
		if code := auth01ProbeAudit(t, h, cookie); code != http.StatusForbidden {
			t.Fatalf("GET /api/audit-logs for user without a global_role row = %d, want 403", code)
		}
	})
}
