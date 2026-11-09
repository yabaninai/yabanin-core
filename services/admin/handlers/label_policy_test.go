package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

func TestLabelPolicy_PermissionsAndTestDoesNotWrite(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	store := &memLabelPolicies{}
	cache := &memResolverCache{}
	h := New(newMockStore(), secret, "", nil)
	h.SetLabelPolicyStore(store)
	h.SetResolverCache(cache)
	ms := h.store.(*mockStore)
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleReader}
	router := h.SetupRouter()

	code, body := labelCall(t, router, secret, false, http.MethodGet, "/api/label-policy?org_id=org-1", "")
	if code != http.StatusOK || !strings.Contains(body, `"is_default":true`) {
		t.Fatalf("get default: %d %s", code, body)
	}
	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/label-policy?org_id=org-1", `{"allowed_keys":["*"]}`)
	if code != http.StatusForbidden {
		t.Fatalf("reader put: %d %s", code, body)
	}
	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/label-policy?org_id=org-2", `{"allowed_keys":["*"]}`)
	if code != http.StatusForbidden {
		t.Fatalf("idor: %d %s", code, body)
	}

	ms.orgMembers["admin-1/org-1"].Role = adminstore.RoleOrgAdmin
	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/label-policy?org_id=org-1",
		`{"derive":[{"from":"issue","regex":"(","to":"issue.project","template":"$1"}]}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "invalid_policy") {
		t.Fatalf("bad regex: %d %s", code, body)
	}
	if store.writes != 0 {
		t.Fatal("invalid policy was stored")
	}

	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/label-policy?org_id=org-1",
		`{"allowed_keys":["issue"],"on_missing":"reject","required_keys":["issue"]}`)
	if code != http.StatusOK {
		t.Fatalf("put: %d %s", code, body)
	}
	if store.writes != 1 || len(cache.keys) != 1 || cache.keys[0] != "yb:labelpolicy:org-1" {
		t.Fatalf("writes %d cache %v", store.writes, cache.keys)
	}

	before := store.writes
	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/label-policy/test?org_id=org-1",
		`{"headers":{"X-Yabanin-Labels":"issue=PAY-1"}}`)
	if code != http.StatusOK || !strings.Contains(body, "PAY-1") || store.writes != before {
		t.Fatalf("test: %d writes %d %s", code, store.writes, body)
	}
}

type memLabelPolicies struct {
	raw    []byte
	writes int
}

func (m *memLabelPolicies) GetLabelPolicy(context.Context, string) (adminstore.LabelPolicyRow, bool, error) {
	if m.raw == nil {
		return adminstore.LabelPolicyRow{}, false, nil
	}
	return adminstore.LabelPolicyRow{Policy: m.raw, UpdatedAt: time.Now(), UpdatedBy: "a@b.c"}, true, nil
}

func (m *memLabelPolicies) UpsertLabelPolicy(_ context.Context, _ string, policy []byte, _ string) error {
	m.raw = append([]byte(nil), policy...)
	m.writes++
	return nil
}

func (m *memLabelPolicies) DeleteLabelPolicy(context.Context, string) error {
	m.raw = nil
	m.writes++
	return nil
}

func labelCall(t *testing.T, router http.Handler, secret string, root bool, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.AddCookie(makeSessionCookie(root, secret))
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "csrf-admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	req.Header.Set("X-CSRF-Token", "csrf-admin")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}
