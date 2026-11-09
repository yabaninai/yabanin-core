package handlers

//
// deny tests on the API". Its two halves are pinned elsewhere — the table by
// TestRoleHas_Matrix (5 tenant roles × 13 permissions, store level) and the
// deny behavior of every privileged route by TestPrivilegedRoutes_DenyWithoutRights
// is the JOIN: every middleware-gated org route must enforce the concrete
// permission documented in docs/api/admin.openapi.yaml (x-permission:
// org:<perm>) for EVERY tenant role. Both walks classify such a route as
// plain "org", so a route wired with the WRONG permission is invisible to the
// inventory tests — only a per-role probe through the wired router can tell
// the miswiring apart (the mutation check in
//
// Expected outcomes come from adminstore.RoleHas — the same function the
// gates call. That is deliberate: this test does not re-pin the matrix, it
// proves the ROUTES dispatch through it. The matrix itself stays pinned by
// TestRoleHas_Matrix, the spec's permission names by TestAdminRoutesInventory
// (permissionProblems).
//
// Current gate semantics for a MEMBER of the target org (contract §2.3):
// holding the permission → the gate passes; lacking it → exactly 403
// ("insufficient permission for this organization"). The resourceHidden
// variants (keys.manage, policies.manage, credits reads) 404 only callers
// with NO membership — this sweep probes members, so the deny expectation is
// exactly 403 on every org-class route. Handler outcomes after a passed gate
// (2xx, 400/404 on missing probe resources, 5xx on unwired DB-backed stores)
// all prove the gate passed and are accepted.
//
// Handler-gated org surfaces (routing map, caps, settings, budgets) classify
// "session" in the walk and keep their dedicated RightsMatrix tests
// (TestRoutingMap_RightsMatrix, TestOrgCaps_RightsMatrix, org settings).
//
// walk class "global", guard RequireGlobalAuditRead) admits ONLY root and a
// caller holding the operator-provisioned platform global_role
// (admin_users.global_role — AUTH-01). Org memberships are never consulted:
// an org admin can grant security_auditor inside their own org, so
// membership-sourced admission was a cross-org escalation. Every probe
// identity here is a plain org member, so every global-route probe expects
// 403; the admitted identities are pinned in TestGlobalAudit_RoleGate.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// sweepOrg is the org every probe identity is a member of. The probe path
// substitutes every chi placeholder with this segment, so path-resolved and
// header-resolved org targets both land in the seeded membership.
const sweepOrg = "sweep-target"

// specPermissionFallback pins the org permission for org-class routes whose
// documentation carries no machine-readable x-permission: the two DB-gated
// wallet reads live only in docs/api/openapi.yaml (the gateway contract — no
// Their gate is RequireOrgPermissionCreditsRead (budgets.manage), whose
// route-level behavior TestCreditsOrgView_AuthzMatrix pins independently; the
// fallback lets the sweep probe them per role instead of skipping silently.
var specPermissionFallback = map[string]string{
	"GET /api/organizations/{id}/original-retention":   string(adminstore.PermOrgUpdate),
	"PATCH /api/organizations/{id}/original-retention": string(adminstore.PermOrgUpdate),
	"GET /api/orgs/{id}/credits/balance":               string(adminstore.PermBudgetsManage),
	"GET /api/orgs/{id}/credits/transactions":          string(adminstore.PermBudgetsManage),
}

// sweepSessionCookie builds a session cookie for an arbitrary fixture user
// (makeSessionCookie only knows the two seeded admin identities). TP-02
// revalidation resolves the user through the store, so the sweep seeds every
// probe identity into the store it serves from.
func sweepSessionCookie(t *testing.T, secret, userID string) *http.Cookie {
	t.Helper()
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    userID,
		Email:     userID + "@sweep.test",
		IsRoot:    false,
		SessionID: "sweep-" + userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie(%s): %v", userID, err)
	}
	return cookie
}

func TestOrgRoutes_RoleMatrixSweep(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	router := h.SetupRouter()

	// One fixture identity per tenant role, plus the fail-closed unknown
	// role (mirrors TestRoleHas_Matrix's "nope"): every probe user is a
	// member of sweepOrg holding exactly that role.
	roles := append([]adminstore.OrgRole{}, adminstore.AllOrgRoles()...)
	roles = append(roles, adminstore.OrgRole("nope"))
	cookies := make(map[adminstore.OrgRole]*http.Cookie, len(roles))
	for _, role := range roles {
		id := "sweep-" + string(role)
		store.adminUsers[id] = &adminstore.AdminUser{ID: id, Email: id + "@sweep.test", DisplayName: id, Active: true}
		store.orgMembers[id+"/"+sweepOrg] = &adminstore.OrgMembership{UserID: id, OrgID: sweepOrg, Role: role}
		cookies[role] = sweepSessionCookie(t, "test-session-key", id)
	}

	specs, err := walkRoutes(router)
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}
	documented := parseOpenAPIRoutes(t, adminOpenAPISpec)

	probe := func(spec routeSpec, cookie *http.Cookie) int {
		path := sweepPlaceholder.ReplaceAllString(spec.Pattern, sweepOrg)
		req := httptest.NewRequestWithContext(t.Context(), spec.Method, path, nil)
		req.Host = "sweep.test"
		// Give the scope hint a concrete
		// (own) org so the gate sees membership instead of a 400; the header
		// matches the path org, so OrgScopeMiddleware cannot misread it.
		req.Header.Set(OrgHeader, sweepOrg)
		req.AddCookie(cookie)
		if spec.Method != http.MethodGet && spec.Method != http.MethodHead && spec.Method != http.MethodOptions {
			const csrf = "sweep-csrf-token"
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
		// The global audit gate: root is not a membership identity here
		// (covered by TestGlobalAudit_RoleGate). AUTH-01: org roles NEVER
		// admit the global journal — admission comes only from
		// admin_users.global_role or root, and the probe identities are
		// plain members, so every probe expects exactly 403.
		if spec.Permission == "global" {
			swept++
			for _, role := range roles {
				code := probe(spec, cookies[role])
				if code != http.StatusForbidden {
					failures = append(failures, fmt.Sprintf("%s %s as %q: %d, want 403 (org roles never admit the global audit journal — AUTH-01)",
						spec.Method, spec.Pattern, role, code))
				}
			}
			continue
		}
		if spec.Permission != "org" {
			continue
		}
		doc, ok := documented[spec.key()]
		permName := ""
		if ok && strings.HasPrefix(doc.Permission, "org:") {
			permName = strings.TrimPrefix(doc.Permission, "org:")
		} else {
			permName = specPermissionFallback[spec.key()]
		}
		if permName == "" {
			t.Errorf("%s: org-class route without a documented org:<perm> permission — the role matrix cannot be verified for it", spec.key())
			continue
		}
		perm := adminstore.Permission(permName)
		swept++
		for _, role := range roles {
			code := probe(spec, cookies[role])
			if adminstore.RoleHas(string(role), perm) {
				if code == http.StatusUnauthorized || code == http.StatusForbidden {
					failures = append(failures, fmt.Sprintf("%s %s as %q: %d, want the org:%s gate to pass (RoleHas = true)",
						spec.Method, spec.Pattern, role, code, perm))
				}
			} else {
				// Members lacking the permission are always 403 (the 404
				// resourceHidden branch is for non-members only). 2xx would
				// be a hole; 400/5xx mean the gate did not run.
				if code != http.StatusForbidden {
					failures = append(failures, fmt.Sprintf("%s %s as %q: %d, want 403 (member without org:%s)",
						spec.Method, spec.Pattern, role, code, perm))
				}
			}
		}
	}
	// Floor guard: a walk or class-filter regression must not silently empty
	// the sweep (root+global+org).
	if swept < 25 {
		t.Fatalf("sweep covered only %d gated routes — the walk or the class filter is broken", swept)
	}
	t.Logf("role-matrix sweep: %d org/global-gated routes × %d tenant-role identities", swept, len(roles))
	if len(failures) > 0 {
		t.Errorf("role matrix disagrees with the API gates on %d route×role probes:\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
}

// journal on the fully-wired router: root 200, a security_auditor member 200,
// any other org member 403, a memberless admin 403, anonymous 401.
func TestGlobalAudit_RoleGate(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	router := h.SetupRouter()

	seed := func(role adminstore.OrgRole) *http.Cookie {
		t.Helper()
		id := "gate-" + string(role)
		store.adminUsers[id] = &adminstore.AdminUser{ID: id, Email: id + "@sweep.test", DisplayName: id, Active: true}
		store.orgMembers[id+"/"+sweepOrg] = &adminstore.OrgMembership{UserID: id, OrgID: sweepOrg, Role: role}
		return sweepSessionCookie(t, "test-session-key", id)
	}
	auditor := seed(adminstore.RoleSecurityAuditor)
	reader := seed(adminstore.RoleReader)

	probe := func(cookie *http.Cookie) int {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs", nil)
		req.Host = "sweep.test"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	// Anonymous: 401 behind the session boundary.
	if code := probe(nil); code != http.StatusUnauthorized {
		t.Errorf("GET /api/audit-logs anon = %d, want 401", code)
	}
	// Memberless non-root admin: 403.
	if code := probe(makeSessionCookie(false, "test-session-key")); code != http.StatusForbidden {
		t.Errorf("GET /api/audit-logs memberless admin = %d, want 403", code)
	}
	// Org member without the global role: 403 — membership alone grants nothing.
	if code := probe(reader); code != http.StatusForbidden {
		t.Errorf("GET /api/audit-logs reader member = %d, want 403", code)
	}
	// AUTH-01: an org security_auditor membership is NOT admission — the org
	// admin who granted it could read every org's journal. Exactly 403.
	if code := probe(auditor); code != http.StatusForbidden {
		t.Errorf("GET /api/audit-logs security_auditor member = %d, want 403 (org membership must never admit the global journal)", code)
	}
	// Root-authorized platform security auditor (admin_users.global_role,
	// operator-provisioned; no membership anywhere): 200.
	platformAuditor := "gate-platform-auditor"
	store.adminUsers[platformAuditor] = &adminstore.AdminUser{ID: platformAuditor, Email: platformAuditor + "@sweep.test", DisplayName: platformAuditor, Active: true}
	store.globalRoles[platformAuditor] = adminstore.GlobalRoleSecurityAuditor
	if code := probe(sweepSessionCookie(t, "test-session-key", platformAuditor)); code != http.StatusOK {
		t.Errorf("GET /api/audit-logs platform security_auditor = %d, want 200", code)
	}
	// Root: still 200.
	if code := probe(makeSessionCookie(true, "test-session-key")); code != http.StatusOK {
		t.Errorf("GET /api/audit-logs root = %d, want 200", code)
	}
}
