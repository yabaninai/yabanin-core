package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/lineage"
)

// RM-42: each moved route is allowed for a member who holds the permission,
// hidden from the same user on another org, forbidden without the permission,
// and still allowed for root.

func TestRM42_MovedRoutes(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	store := newMockStore()
	org1, org2 := "org-1", "org-2"
	store.apiKeys["k1"] = &adminstore.APIKey{ID: "k1", Name: "key-a", OrgID: &org1, Active: true, KeyHash: "hash-1"}
	store.apiKeys["k2"] = &adminstore.APIKey{ID: "k2", Name: "key-b", OrgID: &org2, Active: true, KeyHash: "hash-2"}
	store.agentKeys["ag1"] = &adminstore.AgentKey{ID: "ag1", Name: "agent-a", OrgID: org1, Active: true, KeyHash: "ahash-1"}
	store.agentKeys["ag2"] = &adminstore.AgentKey{ID: "ag2", Name: "agent-b", OrgID: org2, Active: true, KeyHash: "ahash-2"}
	store.teams["team-a"] = &adminstore.Team{ID: "team-a", OrgID: org1, Name: "A"}
	store.teams["team-b"] = &adminstore.Team{ID: "team-b", OrgID: org2, Name: "B"}

	lines := &rm42Lineage{byID: map[string]lineage.Attestation{
		"req-a": {RequestID: "req-a", OrgID: org1},
		"req-b": {RequestID: "req-b", OrgID: org2},
	}}
	ver := &rm42Verifier{src: lines}
	h := New(store, secret, "", nil)
	h.SetLineageStore(lines)
	h.SetLineageVerifier(ver)
	router := h.SetupRouter()

	setRole := func(org string, role adminstore.OrgRole) {
		t.Helper()
		for k, mem := range store.orgMembers {
			if mem.UserID == "admin-1" {
				delete(store.orgMembers, k)
			}
		}
		if org == "" {
			return
		}
		store.orgMembers["admin-1/"+org] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: org, Role: role}
	}
	call := func(method, path, body string, root bool, orgHeader string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequestWithContext(t.Context(), method, path, rdr)
		req.AddCookie(makeSessionCookie(root, secret))
		req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "csrf-rm42", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		req.Header.Set("X-CSRF-Token", "csrf-rm42")
		if orgHeader != "" {
			req.Header.Set(OrgHeader, orgHeader)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	want := func(name string, code int, body string, status int, has, lacks string) {
		t.Helper()
		if code != status {
			t.Errorf("%s: status %d, want %d; body %s", name, code, status, body)
		}
		if has != "" && !strings.Contains(body, has) {
			t.Errorf("%s: body missing %q: %s", name, has, body)
		}
		if lacks != "" && strings.Contains(body, lacks) {
			t.Errorf("%s: body leaked %q: %s", name, lacks, body)
		}
	}

	setRole(org1, adminstore.RoleReader)
	code, body := call(http.MethodGet, "/api/analytics/stats?org_id=org-1", "", false, "")
	want("analytics own", code, body, http.StatusOK, "", "")
	code, body = call(http.MethodGet, "/api/analytics/stats?org_id=org-2", "", false, "")
	want("analytics other org", code, body, http.StatusForbidden, "", "")
	setRole(org1, adminstore.RolePartner)
	code, body = call(http.MethodGet, "/api/analytics/stats?org_id=org-1", "", false, "")
	want("analytics without permission", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodGet, "/api/analytics/stats?org_id=org-2", "", true, "")
	want("analytics root", code, body, http.StatusOK, "", "")

	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodGet, "/api/organizations/org-1/requests", "", false, "")
	want("requests own", code, body, http.StatusOK, "req-1", "")
	code, body = call(http.MethodGet, "/api/organizations/org-2/requests", "", false, "")
	want("requests other org", code, body, http.StatusForbidden, "", "req-1")
	setRole(org1, adminstore.RolePartner)
	code, body = call(http.MethodGet, "/api/organizations/org-1/requests", "", false, "")
	want("requests without permission", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodGet, "/api/organizations/org-2/requests", "", true, "")
	want("requests root", code, body, http.StatusOK, "", "")

	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodGet, "/api/organizations/org-1/requests/req-1", "", false, "")
	want("detail reader strips payload", code, body, http.StatusOK, "req-1", `"response"`)
	setRole(org1, adminstore.RoleOperator)
	code, body = call(http.MethodGet, "/api/organizations/org-1/requests/req-1", "", false, "")
	want("detail operator strips payload", code, body, http.StatusOK, "req-1", `"response"`)
	setRole(org1, adminstore.RoleSecurityAuditor)
	code, body = call(http.MethodGet, "/api/organizations/org-1/requests/req-1", "", false, "")
	want("detail auditor has no scoped grant", code, body, http.StatusOK, "req-1", `"response"`)
	code, body = call(http.MethodGet, "/api/organizations/org-1/requests/req-1", "", true, "")
	want("detail root has no implicit grant", code, body, http.StatusOK, "req-1", `"response"`)

	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodGet, "/api/lineage/req-a", "", false, org1)
	want("lineage own", code, body, http.StatusOK, "req-a", "")
	code, body = call(http.MethodGet, "/api/lineage/req-b", "", false, org1)
	want("lineage other org", code, body, http.StatusNotFound, "", "req-b")
	code, body = call(http.MethodGet, "/api/organizations/org-1/lineage", "", false, "")
	want("lineage list own", code, body, http.StatusOK, "req-a", "")
	code, body = call(http.MethodGet, "/api/organizations/org-2/lineage", "", false, "")
	want("lineage list other org", code, body, http.StatusForbidden, "", "req-b")
	setRole(org1, adminstore.RolePartner)
	code, body = call(http.MethodGet, "/api/lineage/req-a", "", false, org1)
	want("lineage without permission", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodGet, "/api/lineage/req-b", "", true, "")
	want("lineage root", code, body, http.StatusOK, "req-b", "")

	setRole(org1, adminstore.RoleReader)
	ver.ids = nil
	code, body = call(http.MethodPost, "/api/lineage/req-a/verify", "", false, org1)
	want("verify without permission", code, body, http.StatusForbidden, "", "")
	if len(ver.ids) != 0 {
		t.Errorf("verify without permission called verifier: %v", ver.ids)
	}
	setRole(org1, adminstore.RoleOperator)
	ver.ids = nil
	code, body = call(http.MethodPost, "/api/lineage/req-a/verify", "", false, org1)
	want("verify own", code, body, http.StatusOK, "req-a", "")
	ver.ids = nil
	code, body = call(http.MethodPost, "/api/lineage/req-b/verify", "", false, org1)
	want("verify other org", code, body, http.StatusNotFound, "", "req-b")
	if len(ver.ids) != 0 {
		t.Errorf("verify of another org called verifier: %v", ver.ids)
	}
	code, body = call(http.MethodPost, "/api/lineage/req-b/verify", "", true, "")
	want("verify root", code, body, http.StatusOK, "req-b", "")

	setRole(org1, adminstore.RoleOperator)
	code, body = call(http.MethodGet, "/api/api-keys", "", false, org1)
	want("keys list own", code, body, http.StatusOK, "key-a", "key-b")
	code, body = call(http.MethodGet, "/api/api-keys?org_id=org-2", "", false, org1)
	want("keys list other org", code, body, http.StatusForbidden, "", "key-b")
	code, body = call(http.MethodGet, "/api/api-keys/k2", "", false, org1)
	want("keys get other org", code, body, http.StatusNotFound, "", "key-b")
	code, body = call(http.MethodPut, "/api/api-keys/k2", `{"active":false}`, false, org1)
	want("keys update other org", code, body, http.StatusNotFound, "", "")
	if !store.apiKeys["k2"].Active {
		t.Error("update of another org's key changed active")
	}
	code, body = call(http.MethodPost, "/api/api-keys/k2/rotate", `{"key_hash":"rotated"}`, false, org1)
	want("keys rotate other org", code, body, http.StatusNotFound, "", "")
	if store.apiKeys["k2"].KeyHash != "hash-2" {
		t.Error("rotate of another org's key changed the hash")
	}
	code, body = call(http.MethodDelete, "/api/api-keys/k2", "", false, org1)
	want("keys delete other org", code, body, http.StatusNotFound, "", "")
	if _, ok := store.apiKeys["k2"]; !ok {
		t.Error("delete of another org's key removed it")
	}
	code, body = call(http.MethodPost, "/api/api-keys", `{"name":"nope","org_id":"org-2","key_hash":"zzz"}`, false, org1)
	want("keys create other org", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodPost, "/api/api-keys", `{"name":"ok","org_id":"org-1","key_hash":"zzz"}`, false, org1)
	want("keys create own", code, body, http.StatusCreated, "org-1", "")
	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodGet, "/api/api-keys", "", false, org1)
	want("keys without permission", code, body, http.StatusForbidden, "", "key-a")
	code, body = call(http.MethodGet, "/api/api-keys/k2", "", true, "")
	want("keys root", code, body, http.StatusOK, "key-b", "")

	setRole(org1, adminstore.RoleOperator)
	code, body = call(http.MethodGet, "/api/agent-keys?org_id=org-1", "", false, org1)
	want("agent keys list own", code, body, http.StatusOK, "agent-a", "agent-b")
	code, body = call(http.MethodGet, "/api/agent-keys/ag2", "", false, org1)
	want("agent keys get other org", code, body, http.StatusNotFound, "", "agent-b")
	code, body = call(http.MethodPost, "/api/agent-keys/ag2/revoke", "", false, org1)
	want("agent keys revoke other org", code, body, http.StatusNotFound, "", "")
	if !store.agentKeys["ag2"].Active {
		t.Error("revoke of another org's agent key deactivated it")
	}
	code, body = call(http.MethodGet, "/api/agent-keys/ag2/budget", "", false, org1)
	want("agent budget other org", code, body, http.StatusNotFound, "", "")
	code, body = call(http.MethodPut, "/api/agent-keys/ag1/budget", `{"daily_limit_cents":6000}`, false, org1)
	want("agent budget update own", code, body, http.StatusOK, "6000", "")
	if got := store.agentBudgets["ag1"].DailyLimitCents; got != 6000 {
		t.Errorf("update of own agent budget stored %d cents, want 6000", got)
	}
	code, body = call(http.MethodDelete, "/api/agent-keys/ag1/budget", "", false, org1)
	want("agent budget delete own", code, body, http.StatusOK, "deleted", "")
	if _, ok := store.agentBudgets["ag1"]; ok {
		t.Error("delete of own agent budget left the budget configured")
	}
	store.agentBudgets["ag2"] = &adminstore.AgentBudget{AgentID: "ag2", DailyLimitCents: 7000}
	code, body = call(http.MethodPut, "/api/agent-keys/ag2/budget", `{"daily_limit_cents":9000}`, false, org1)
	want("agent budget update other org", code, body, http.StatusNotFound, "not found", "ag2")
	if strings.Contains(body, "agent-b") || strings.Contains(body, "7000") {
		t.Errorf("update of another org's agent budget disclosed foreign data: %s", body)
	}
	if got := store.agentBudgets["ag2"].DailyLimitCents; got != 7000 {
		t.Errorf("update of another org's agent budget changed the limit to %d", got)
	}
	if _, ok := store.agentBudgets["ag1"]; ok {
		t.Error("update of another org's agent budget created a budget for the caller's agent key")
	}
	code, body = call(http.MethodDelete, "/api/agent-keys/ag2/budget", "", false, org1)
	want("agent budget delete other org", code, body, http.StatusNotFound, "not found", "ag2")
	if strings.Contains(body, "agent-b") || strings.Contains(body, "7000") {
		t.Errorf("delete of another org's agent budget disclosed foreign data: %s", body)
	}
	if got := store.agentBudgets["ag2"].DailyLimitCents; got != 7000 {
		t.Errorf("delete of another org's agent budget changed the limit to %d", got)
	}
	code, body = call(http.MethodPost, "/api/agent-keys", `{"name":"child","org_id":"org-2"}`, false, org1)
	want("agent keys create other org", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodPost, "/api/agent-keys", `{"name":"mine","org_id":"org-1"}`, false, org1)
	want("agent keys create own", code, body, http.StatusCreated, "", "")
	code, body = call(http.MethodPost, "/api/agent-keys/delegate", `{"parent_agent":"ag2","name":"kid","ttl":60,"org_id":"org-1"}`, false, org1)
	want("agent delegate other org", code, body, http.StatusNotFound, "", "agent-b")
	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodGet, "/api/agent-keys?org_id=org-1", "", false, org1)
	want("agent keys without permission", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodGet, "/api/agent-keys/ag2", "", true, "")
	want("agent keys root", code, body, http.StatusOK, "agent-b", "")

	setRole(org1, adminstore.RoleOperator)
	code, body = call(http.MethodGet, "/api/teams/team-a/budget", "", false, org1)
	want("team budget own", code, body, http.StatusOK, "team-a", "")
	code, body = call(http.MethodPut, "/api/teams/team-a/budget", `{"monthly_limit_usd":125,"hard_limit":true}`, false, org1)
	want("team budget update own", code, body, http.StatusOK, "ok", "")
	if got := store.teamBudgets["team-a"]; got == nil || got.MonthlyLimitUSD != 125 || !got.HardLimit {
		t.Errorf("update of own team budget stored %+v, want 125 USD hard limit", got)
	}
	code, body = call(http.MethodDelete, "/api/teams/team-a/budget", `{"expected":{"monthly_limit_usd":125,"hard_limit":true}}`, false, org1)
	want("team budget delete own", code, body, http.StatusOK, "ok", "")
	if _, ok := store.teamBudgets["team-a"]; ok {
		t.Error("delete of own team budget left the budget configured")
	}
	code, body = call(http.MethodGet, "/api/teams/team-b/budget", "", false, org1)
	want("team budget other org", code, body, http.StatusNotFound, "", "team-b")
	code, body = call(http.MethodPut, "/api/teams/team-b/budget", `{"monthly_limit_usd":10,"hard_limit":true}`, false, org1)
	want("team budget update other org", code, body, http.StatusNotFound, "", "")
	store.teamBudgets["team-b"] = &adminstore.TeamBudget{TeamID: "team-b", MonthlyLimitUSD: 250, HardLimit: true}
	code, body = call(http.MethodDelete, "/api/teams/team-b/budget", `{"expected":{"monthly_limit_usd":250,"hard_limit":true}}`, false, org1)
	want("team budget delete other org", code, body, http.StatusNotFound, "not found", "team-b")
	if strings.Contains(body, "250") {
		t.Errorf("delete of another org's team budget disclosed the limit: %s", body)
	}
	if got := store.teamBudgets["team-b"]; got == nil || got.MonthlyLimitUSD != 250 || !got.HardLimit {
		t.Errorf("delete of another org's team budget changed it: %+v", got)
	}
	code, body = call(http.MethodGet, "/api/organizations/org-1/team-budgets", "", false, "")
	want("team budgets list own", code, body, http.StatusOK, "", "")
	code, body = call(http.MethodGet, "/api/organizations/org-2/team-budgets", "", false, "")
	want("team budgets list other org", code, body, http.StatusForbidden, "", "")
	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodGet, "/api/teams/team-a/budget", "", false, org1)
	want("team budget without permission", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodGet, "/api/teams/team-b/budget", "", true, "")
	want("team budget root", code, body, http.StatusOK, "team-b", "")

	setRole(org1, adminstore.RoleOrgAdmin)
	code, body = call(http.MethodPost, "/api/organizations/org-1/members", `{"user_id":"u2","role":"operator"}`, false, "")
	want("members create own", code, body, http.StatusCreated, "u2", "")
	code, body = call(http.MethodPost, "/api/organizations/org-2/members", `{"user_id":"u9","role":"reader"}`, false, "")
	want("members create other org", code, body, http.StatusForbidden, "", "")
	code, body = call(http.MethodPut, "/api/organizations/org-1/members/admin-1", `{"role":"reader"}`, false, "")
	want("members cannot change own role", code, body, http.StatusForbidden, "cannot change your own role", "")
	if store.orgMembers["admin-1/org-1"].Role != adminstore.RoleOrgAdmin {
		t.Error("self role change applied")
	}
	setRole(org1, adminstore.RoleReader)
	code, body = call(http.MethodPost, "/api/organizations/org-1/members", `{"user_id":"u4","role":"reader"}`, false, "")
	want("members without permission", code, body, http.StatusForbidden, "", "")
	if _, created := store.orgMembers["u4/org-1"]; created {
		t.Error("reader denied from creating an org member still created the membership")
	}
	code, body = call(http.MethodPost, "/api/organizations/org-2/members", `{"user_id":"u3","role":"reader"}`, true, "")
	want("members root", code, body, http.StatusCreated, "u3", "")
	code, body = call(http.MethodPost, "/api/organizations/org-1/members", `{"user_id":"u5","role":"reader","is_root":true}`, true, "")
	want("members reject is_root", code, body, http.StatusBadRequest, "is_root", "")
	if _, ok := store.orgMembers["u5/org-1"]; ok {
		t.Error("is_root membership was created")
	}
}

func TestRM42_CannotGrantAboveOwnRank(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u-reader/org-1"] = &adminstore.OrgMembership{UserID: "u-reader", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)
	req := sessionRequest("u-reader", false, "/api/organizations/org-1/members")
	role := adminstore.RoleOrgAdmin
	rec := httptest.NewRecorder()
	if !h.rejectMemberChange(rec, req, "org-1", "u-other", &role) {
		t.Fatal("reader was allowed to grant org-admin")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body %s", rec.Code, rec.Body.String())
	}
}

type rm42Lineage struct {
	byID map[string]lineage.Attestation
}

func (s *rm42Lineage) GetLineageByRequestID(_ context.Context, id string) (lineage.Attestation, error) {
	att, ok := s.byID[id]
	if !ok {
		return lineage.Attestation{}, fmt.Errorf("not found")
	}
	return att, nil
}

func (s *rm42Lineage) ListLineageByOrg(_ context.Context, orgID string, limit int) ([]lineage.Attestation, error) {
	var out []lineage.Attestation
	for _, att := range s.byID {
		if att.OrgID == orgID {
			out = append(out, att)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *rm42Lineage) ListLineageByOrgFiltered(ctx context.Context, orgID, _ string, _, _ time.Time, limit int) ([]lineage.Attestation, error) {
	return s.ListLineageByOrg(ctx, orgID, limit)
}

type rm42Verifier struct {
	src *rm42Lineage
	ids []string
}

func (v *rm42Verifier) VerifyRequest(_ context.Context, id string) (bool, error) {
	v.ids = append(v.ids, id)
	if _, ok := v.src.byID[id]; !ok {
		return false, fmt.Errorf("missing")
	}
	return true, nil
}
