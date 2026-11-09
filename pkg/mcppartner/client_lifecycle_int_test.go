//go:build integration

package mcp

// The partner key lifecycle across the real HTTP boundary — the
// GatewayClient's actual transport against a stateful control-plane stand
// evidence pins single-hop failure postures and hostile bodies; what this
// adds is the temporal contract: a rotated key serves on the very next call
// and the old key never completes a hop again, a revoked key fails closed
// repeatedly with the categorized status-only error, the admin hop carries
// the admin key and never the partner key (and vice versa) across the whole
// flow, and no key material ever reaches the client errors or the MCP tool
// output.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lifecycleControlPlane is the stateful stand: the currently-valid
// partner/admin keys, a journal of every credential-bearing hop (attempts),
// and a count of authorized hops per credential (successes).
type lifecycleControlPlane struct {
	mu           sync.Mutex
	srv          *httptest.Server
	validPartner map[string]bool
	validAdmin   map[string]bool
	hops         []string // "path|authHeader|adminKeyHeader" (every attempt)
	successes    map[string]int
}

func newLifecycleControlPlane(t *testing.T) *lifecycleControlPlane {
	t.Helper()
	cp := &lifecycleControlPlane{
		validPartner: map[string]bool{},
		validAdmin:   map[string]bool{},
		successes:    map[string]int{},
	}
	mux := http.NewServeMux()
	record := func(r *http.Request, authorized bool, cred string) {
		cp.mu.Lock()
		cp.hops = append(cp.hops, fmt.Sprintf("%s|%s|%s", r.URL.Path,
			r.Header.Get("Authorization"), r.Header.Get("X-Admin-Key")))
		if authorized {
			cp.successes[cred]++
		}
		cp.mu.Unlock()
	}
	partnerAuthorized := func(r *http.Request) (string, bool) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		cp.mu.Lock()
		defer cp.mu.Unlock()
		return key, cp.validPartner[key]
	}
	adminAuthorized := func(r *http.Request) (string, bool) {
		key := r.Header.Get("X-Admin-Key")
		cp.mu.Lock()
		defer cp.mu.Unlock()
		return key, cp.validAdmin[key]
	}
	reject := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		//nolint:gosec // G705: the hostile stand deliberately echoes both credentials — the test proves the client and tool handlers redact them
		_, _ = fmt.Fprintf(w, `{"error":"tenant mismatch; credential=%s admin=%s body-detail"}`,
			r.Header.Get("Authorization"), r.Header.Get("X-Admin-Key"))
	}
	chat := func(w http.ResponseWriter, r *http.Request) {
		key, ok := partnerAuthorized(r)
		record(r, ok, key)
		if !ok {
			reject(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"routed"}}],"model":"m"}`))
	}
	adminReport := func(w http.ResponseWriter, r *http.Request) {
		key, ok := adminAuthorized(r)
		record(r, ok, key)
		if !ok {
			reject(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_cost":1.25,"days":7}`))
	}
	lineage := func(w http.ResponseWriter, r *http.Request) {
		key, ok := partnerAuthorized(r)
		record(r, ok, key)
		if !ok {
			reject(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"valid":true,"request_id":"req-1"}`))
	}
	mux.HandleFunc("/v1/chat/completions", chat)
	mux.HandleFunc("/internal/analytics/cost", adminReport)
	mux.HandleFunc("/api/lineage/", lineage)
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *lifecycleControlPlane) issuePartner(key string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.validPartner[key] = true
}

func (cp *lifecycleControlPlane) revokePartner(key string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	delete(cp.validPartner, key)
}

func (cp *lifecycleControlPlane) issueAdmin(key string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.validAdmin[key] = true
}

func (cp *lifecycleControlPlane) revokeAdmin(key string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	delete(cp.validAdmin, key)
}

// hopsSoFar snapshots the attempt journal; successCount reads the authorized
// hop counter for one credential.
func (cp *lifecycleControlPlane) hopsSoFar() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	out := make([]string, len(cp.hops))
	copy(out, cp.hops)
	return out
}

func (cp *lifecycleControlPlane) successCount(credential string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.successes[credential]
}

// assertNoKeyMaterial fails the test when any key or hostile echo fragment
// surfaces in one of the given surfaces.
func assertNoKeyMaterial(t *testing.T, keys []string, surfaces ...string) {
	t.Helper()
	for _, surface := range surfaces {
		for _, key := range keys {
			assert.NotContains(t, surface, key)
		}
		assert.NotContains(t, surface, "body-detail")
		assert.NotContains(t, surface, "tenant mismatch")
	}
}

// TestGatewayClient_KeyLifecycle_RotateRevokeAcrossHops: issue → route →
// rotate (the new key serves, the old key never completes a hop again) →
// revoke (the old key fails closed repeatedly) with the admin-hop isolation
// held across the whole flow, and zero key material on any error or tool
// surface.
func TestGatewayClient_KeyLifecycle_RotateRevokeAcrossHops(t *testing.T) {
	const ( //nolint:gosec // G101 false positives: synthetic test literals, not credentials
		partnerV1 = "pk-intlc-partner-v1-aaaa"
		partnerV2 = "pk-intlc-partner-v2-bbbb"
		adminV1   = "svc-intlc-admin-v1-cccc"
		adminV2   = "svc-intlc-admin-v2-dddd"
	) //nolint:gosec // G101 false positives: synthetic test literals, not credentials
	allKeys := []string{partnerV1, partnerV2, adminV1, adminV2}
	cp := newLifecycleControlPlane(t)
	cp.issuePartner(partnerV1)
	cp.issueAdmin(adminV1)
	clientV1 := NewGatewayClient(cp.srv.URL, cp.srv.URL, partnerV1, adminV1)
	ctx := context.Background()

	// Working input — the issued partner key routes, and the tool output
	// carries the routed result, never the key.
	out, err := clientV1.Route(ctx, "model", "prompt")
	require.NoError(t, err)
	choices, ok := out["choices"].([]any)
	require.True(t, ok)
	content, ok := choices[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	require.True(t, ok)
	assert.Equal(t, "routed", content)
	result, err := handleRoute(clientV1)(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"model": "model", "prompt": "prompt"}},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	assertNoKeyMaterial(t, []string{partnerV1, adminV1}, toolText(result))

	// The gateway hops completed with the partner key and never carried an
	// admin key; the admin key has not left the client at all yet.
	assert.Equal(t, 2, cp.successCount(partnerV1), "one client + one tool hop")
	assert.Zero(t, cp.successCount(adminV1))
	for _, hop := range cp.hopsSoFar() {
		parts := strings.SplitN(hop, "|", 3)
		if strings.HasPrefix(parts[0], "/v1/") {
			assert.Empty(t, parts[2], "the gateway hop must not carry an admin key: %q", hop)
		}
	}

	// Rotation — the new partner key serves on its first call; the old key
	// never completes another hop and fails closed on any stale client,
	// repeatedly, with the categorized status-only error.
	cp.revokePartner(partnerV1)
	cp.issuePartner(partnerV2)
	clientV2 := NewGatewayClient(cp.srv.URL, cp.srv.URL, partnerV2, adminV1)
	_, err = clientV2.Route(ctx, "model", "prompt")
	require.NoError(t, err)
	assert.Equal(t, 2, cp.successCount(partnerV1), "the rotated-out key must never complete a hop again")

	for range 2 {
		_, err = clientV1.Route(ctx, "model", "prompt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gateway 401")
		assertNoKeyMaterial(t, allKeys, err.Error())
		result, err := handleRoute(clientV1)(ctx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{Arguments: map[string]any{"model": "model", "prompt": "prompt"}},
		})
		require.NoError(t, err)
		assert.True(t, result.IsError, "a revoked key must read as a tool error, never success")
		assert.Contains(t, toolText(result), "gateway 401")
		assertNoKeyMaterial(t, allKeys, toolText(result))
	}
	assert.Equal(t, 2, cp.successCount(partnerV1), "revocation must hold across repeated attempts")

	// Admin hop lifecycle — the admin key rides ONLY the /internal hop (no
	// partner Bearer on it), rotates the same way, and its revocation fails
	// closed on both the client and tool surfaces.
	out, err = clientV2.SpendReport(ctx, "org-1", 7)
	require.NoError(t, err)
	assert.NotZero(t, out["total_cost"])
	cp.revokeAdmin(adminV1)
	cp.issueAdmin(adminV2)
	adminClient2 := NewGatewayClient(cp.srv.URL, cp.srv.URL, partnerV2, adminV2)
	_, err = adminClient2.SpendReport(ctx, "org-1", 7)
	require.NoError(t, err, "the rotated admin key must serve on its first call")
	stale := NewGatewayClient(cp.srv.URL, cp.srv.URL, partnerV2, adminV1)
	_, err = stale.SpendReport(ctx, "org-1", 7)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin 401")
	assertNoKeyMaterial(t, allKeys, err.Error())
	result, err = handleSpendReport(stale)(ctx,
		mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]any{"org_id": "org-1"}}})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	assert.Contains(t, toolText(result), "admin 401")
	assertNoKeyMaterial(t, allKeys, toolText(result))
	assert.Equal(t, 1, cp.successCount(adminV1), "the revoked admin key completed exactly its one live hop")

	// Hop isolation across the whole journal: internal hops never carried a
	// partner Bearer; gateway hops never carried an admin key.
	for _, hop := range cp.hopsSoFar() {
		parts := strings.SplitN(hop, "|", 3)
		switch {
		case strings.HasPrefix(parts[0], "/internal/"):
			assert.Empty(t, parts[1], "the internal hop must not carry a partner key: %q", hop)
		case strings.HasPrefix(parts[0], "/v1/"):
			assert.Empty(t, parts[2], "the gateway hop must not carry an admin key: %q", hop)
		}
	}
}

// TestGatewayClient_LineageVerify_LifecycleSuccessCarriesNoKey: the happy
// path of the remaining gateway-hop tool also stays material-free end to
// end (request, response decoding, tool text).
func TestGatewayClient_LineageVerify_LifecycleSuccessCarriesNoKey(t *testing.T) {
	const partnerKey = "pk-intlc-lineage-eeee" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	cp := newLifecycleControlPlane(t)
	cp.issuePartner(partnerKey)
	client := NewGatewayClient(cp.srv.URL, cp.srv.URL, partnerKey, "")
	out, err := client.LineageVerify(context.Background(), "req-1")
	require.NoError(t, err)
	assert.Equal(t, true, out["valid"])
	body, mErr := json.Marshal(out)
	require.NoError(t, mErr)
	assert.NotContains(t, string(body), partnerKey)
	result, err := handleLineageVerify(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"request_id": "req-1"}},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	assertNoKeyMaterial(t, []string{partnerKey}, toolText(result))
	assert.Equal(t, 2, cp.successCount(partnerKey))
}
