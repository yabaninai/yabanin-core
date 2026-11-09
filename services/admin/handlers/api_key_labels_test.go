package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateAPIKeyLabels_ValidatePurgeAndPermission(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	org := "org-1"
	other := "org-2"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org}
	ms.apiKeys["key-2"] = &adminstore.APIKey{ID: "key-2", KeyHash: "hash-2", Name: "other", OrgID: &other}
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: org, Role: adminstore.RoleReader}
	cache := &memResolverCache{}
	h := New(ms, secret, "", nil)
	h.SetResolverCache(cache)
	router := h.SetupRouter()

	code, body := keyLabelCall(t, router, secret, "/api/api-keys/key-1/labels?org_id=org-1", `{"labels":{"team":"payments"}}`)
	assert.Equal(t, http.StatusForbidden, code, body)

	ms.orgMembers["admin-1/org-1"].Role = adminstore.RoleOperator
	code, body = keyLabelCall(t, router, secret, "/api/api-keys/key-1/labels?org_id=org-1", `{"labels":{"1bad":"x"},"labels_locked":false}`)
	assert.Equal(t, http.StatusBadRequest, code, body)
	assert.Contains(t, body, "invalid_key")
	assert.Empty(t, ms.apiKeys["key-1"].Labels)

	leak := "sk-" + strings.Repeat("A", 40)
	code, body = keyLabelCall(t, router, secret, "/api/api-keys/key-1/labels?org_id=org-1", `{"labels":{"token":"`+leak+`"}}`)
	assert.Equal(t, http.StatusBadRequest, code, body)
	assert.Contains(t, body, "secret_like")
	assert.NotContains(t, body, leak)

	code, body = keyLabelCall(t, router, secret, "/api/api-keys/key-1/labels?org_id=org-1",
		`{"labels":{"team":"payments"},"labels_locked":true,"can_mint_sessions":true,"can_read_usage":false,"extra":1}`)
	assert.Equal(t, http.StatusBadRequest, code, body)

	code, body = keyLabelCall(t, router, secret, "/api/api-keys/key-1/labels?org_id=org-1",
		`{"labels":{"team":"payments"},"labels_locked":true,"can_mint_sessions":true,"can_read_usage":false}`)
	require.Equal(t, http.StatusOK, code, body)
	assert.Equal(t, "payments", ms.apiKeys["key-1"].Labels["team"])
	assert.True(t, ms.apiKeys["key-1"].LabelsLocked)
	assert.True(t, ms.apiKeys["key-1"].CanMintSessions)
	assert.Contains(t, cache.keys, "org:resolve:hash-1")
	require.Equal(t, 1, auditJournalDepth(h))
	details := lastAuditEntry(t, h).Details
	assert.Contains(t, details, "keys=team")
	assert.Contains(t, details, "labels_locked=true")
	assert.NotContains(t, details, "payments")

	code, body = keyLabelCall(t, router, secret, "/api/api-keys/key-2/labels?org_id=org-1", `{"labels":{"team":"nope"}}`)
	assert.Equal(t, http.StatusNotFound, code, body)
	assert.Empty(t, ms.apiKeys["key-2"].Labels)
}

func keyLabelCall(t *testing.T, router http.Handler, secret, path, body string) (int, string) {
	t.Helper()
	code, raw := labelCall(t, router, secret, false, http.MethodPut, path, body)
	return code, raw
}
