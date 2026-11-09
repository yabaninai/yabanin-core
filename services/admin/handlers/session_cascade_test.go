package handlers

import (
	"net/http"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParentKeyMutation_RevokesSessionKeys(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-parent", Name: "demo", OrgID: &org, Active: true}
	ms.sessionHashes = map[string][]string{"key-1": {"hash-sess"}}
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: org, Role: adminstore.RoleOperator}
	cache := &memResolverCache{}
	h := New(ms, secret, "", nil)
	h.SetResolverCache(cache)
	router := h.SetupRouter()

	code, body := labelCall(t, router, secret, false, http.MethodPut, "/api/api-keys/key-1?org_id=org-1", `{"active":false}`)
	require.Equal(t, http.StatusOK, code, body)
	assert.Equal(t, []string{"key-1"}, ms.revokedParents)
	assert.Contains(t, cache.keys, "org:resolve:hash-sess")
	assert.Contains(t, cache.keys, "org:resolve:hash-parent")
}
