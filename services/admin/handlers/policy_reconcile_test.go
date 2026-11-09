package handlers_test

// drift behind the same org gate as the rest of the policy surface, with the
// DB-side classification: managed (newest version authored by git) /
// drift (edited past git after a reconcile) / unmanaged (never reconciled).
// Handler tests run over the in-memory policyStoreStub; the store-side

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

func seedDriftPolicies(t *testing.T, store *policyStoreStub) {
	t.Helper()
	ctx := t.Context()
	// managed: v1 authored by a git reconcile.
	if _, _, err := store.CreatePolicy(ctx, polOrgA, "managed", polYAMLOK, "abc1234", "policies-reconcile"); err != nil {
		t.Fatalf("seed managed: %v", err)
	}
	// drift: v1 git-authored, v2 (latest) edited outside git.
	p, _, err := store.CreatePolicy(ctx, polOrgA, "drifted", polYAMLOK, "abc1234", "policies-reconcile")
	if err != nil {
		t.Fatalf("seed drifted: %v", err)
	}
	if _, err := store.CreatePolicyVersion(ctx, polOrgA, p.ID, polYAMLOK+"# ui\n", "", "admin@ui"); err != nil {
		t.Fatalf("seed ui edit: %v", err)
	}
	// unmanaged: never reconciled (no git-authored version at all).
	if _, _, err := store.CreatePolicy(ctx, polOrgA, "unmanaged", polYAMLOK, "", "admin@ui"); err != nil {
		t.Fatalf("seed unmanaged: %v", err)
	}
}

func decodeDriftReport(t *testing.T, body string) handlers.PolicyDriftReport {
	t.Helper()
	var report handlers.PolicyDriftReport
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("decode drift report: %v\nbody: %s", err, body)
	}
	return report
}

func TestPolicyDrift_Report(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, polSecret)
	store := newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin})
	seedDriftPolicies(t, store)
	router := policyRouter(t, store)

	w := policyRequest(t, router, http.MethodGet, polPathBase+"/drift", rootCookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("root GET drift = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	report := decodeDriftReport(t, w.Body.String())
	if report.OrgID != polOrgA || report.Count != 3 || report.DriftCount != 1 {
		t.Fatalf("report counters wrong: %+v", report)
	}
	byName := map[string]handlers.PolicyDriftEntry{}
	for _, e := range report.Data {
		byName[e.Name] = e
	}
	if got := byName["managed"].Status; got != handlers.PolicyDriftManaged {
		t.Errorf("managed status = %q, want %q", got, handlers.PolicyDriftManaged)
	}
	if got := byName["drifted"].Status; got != handlers.PolicyDriftDiverged {
		t.Errorf("drifted status = %q, want %q", got, handlers.PolicyDriftDiverged)
	}
	drifted := byName["drifted"]
	if drifted.LatestVersion != 2 || drifted.LatestGitSHA != "" || drifted.LatestAuthor != "admin@ui" {
		t.Errorf("drifted latest fields wrong: %+v", drifted)
	}
	if drifted.LatestEditedAt == "" {
		t.Errorf("drifted latest_edited_at must be set (the since-when of a drift)")
	}
	if got := byName["unmanaged"].Status; got != handlers.PolicyDriftUnmanaged {
		t.Errorf("unmanaged status = %q, want %q", got, handlers.PolicyDriftUnmanaged)
	}
}

func TestPolicyDrift_RoutingContract(t *testing.T) {
	rootCookie := makeSessionCookie(t, "root@x.test", true, polSecret)
	adminCookie := makeSessionCookie(t, "admin@x.test", false, polSecret)
	driftPath := polPathBase + "/drift"

	t.Run("anon is 401 (session boundary)", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(nil))
		if w := policyRequest(t, router, http.MethodGet, driftPath, "", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("anon GET drift = %d, want 401", w.Code)
		}
	})
	t.Run("org-admin member passes; operator is 403 (policies.manage)", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOrgAdmin}))
		if w := policyRequest(t, router, http.MethodGet, driftPath, adminCookie, ""); w.Code != http.StatusOK {
			t.Errorf("org-admin GET drift = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		operatorRouter := policyRouter(t, newPolicyStoreStub(map[string]adminstore.OrgRole{polOrgA: adminstore.RoleOperator}))
		if w := policyRequest(t, operatorRouter, http.MethodGet, driftPath, adminCookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("operator GET drift = %d, want 403", w.Code)
		}
	})
	t.Run("non-member gets 404 without revealing the org", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(map[string]adminstore.OrgRole{}))
		foreign := "/api/organizations/" + polOrgB + "/policies/drift"
		if w := policyRequest(t, router, http.MethodGet, foreign, adminCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("non-member GET foreign drift = %d, want 404", w.Code)
		}
	})
	t.Run("empty org reports an honest empty list", func(t *testing.T) {
		router := policyRouter(t, newPolicyStoreStub(nil))
		w := policyRequest(t, router, http.MethodGet, driftPath, rootCookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET drift empty org = %d, want 200", w.Code)
		}
		report := decodeDriftReport(t, w.Body.String())
		if report.Count != 0 || report.Data == nil || len(report.Data) != 0 {
			t.Errorf("empty org must report count=0 with a stable empty list: %+v", report)
		}
	})
	t.Run("unwired store answers 503 with the route still mounted", func(t *testing.T) {
		h := handlers.New(newPolicyStoreStub(nil), polSecret, "localhost", nil)
		router := h.SetupRouter() // SetPolicyPipelineHandlers never called
		if w := policyRequest(t, router, http.MethodGet, driftPath, rootCookie, ""); w.Code != http.StatusServiceUnavailable {
			t.Errorf("unwired GET drift = %d, want 503", w.Code)
		}
	})
}
