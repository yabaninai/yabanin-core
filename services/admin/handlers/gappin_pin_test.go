package handlers

// Pins for handler-level export/detail authorization cells that previously
// had no test:
//
//   - export + originals-scope grant + original retention OFF (the DETAIL
//     cell was pinned; the EXPORT cell was not);
//   - grant_unusable denials must never burn the token — a bearer grant is
//     a root self-grant, never a delegation (non-root human cell,
//     deny-own-history cell);
//   - the agent-subject DETAIL contract at handler level. The real store
//     answers 404 (pkg/adminstore/request_detail.go: !owned && !grant &&
//     !org-wide ⇒ ErrNotFound) while this package's mock answered 200
//     metadata-only. PRODUCT-CONTRACT §5 closes stored history to agent/CI
//     by default and cross-org detail is a 404 no-existence-oracle, so 404
//     is the contract; the mock now mirrors the real store and this test
//     pins the shape at handler level. Presenting a bearer grant token is
//     refused loudly instead (403 grant_unusable, FIX-08 detail symmetry
//     (a+), mirroring export; the token stays redeemable). The real-store
//     half lives in gappin_pin_int_test.go.
//
// These tests PIN current deliberate behavior; a red run is a regression,
// not a license to change production.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

// GAP-A4: root presents a VALID originals-scope grant while original payload
// retention is disabled for the org. The retention check precedes the grant
// consume: 403 "original payload retention is disabled", nothing streams,
// and the token stays redeemable — it succeeds once retention is enabled,
// still exactly once.
func TestGapPinExportOriginalsGrantWithRetentionOff(t *testing.T) {
	store := &exportRetentionStore{mockStore: newMockStore(), enabled: false}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)
	target := "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant=" + token + "&scope=payload.read_originals"

	rec := runRootExport(h, target)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "original payload retention is disabled")
	require.NotContains(t, rec.Body.String(), "application/x-ndjson", "no stream may start on a retention denial")
	require.NotContains(t, rec.Body.String(), "upstream_request", "retention-OFF must never stream originals")
	require.NotContains(t, rec.Body.String(), `"content":"source"`)
	require.NotContains(t, rec.Body.String(), `"arguments"`)
	require.True(t, grantAlive(store.mockStore, token), "the retention denial fires before the consume; the token must stay redeemable")

	// The audit records the retention outcome without token or content.
	denied := false
	for _, r := range store.auditRecords {
		if r.Action == "request_export.denied" {
			denied = true
			require.Contains(t, r.Details, `"outcome":"original_retention_disabled"`)
			require.Contains(t, r.Details, `"originals":false`)
			require.NotContains(t, r.Details, token)
		}
	}
	require.True(t, denied, "the retention denial must be journalled")

	// Once retention is enabled the SAME token redeems — exactly once.
	store.enabled = true
	rec = runRootExport(h, target)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"upstream_request":{"messages":[{"content":"source"}`)
	require.False(t, grantAlive(store.mockStore, token), "the redemption must consume the grant")
	rec = runRootExport(h, target)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

// GAP-A5: a bearer grant is a root self-grant. A non-root human (with or
// without an allowing role) and a deny-own-history subject are refused with
// "grant_unusable" BEFORE the consume — 403, and the root's token survives.
func TestGapPinGrantUnusableWithoutBurn(t *testing.T) {
	// subject builds the denied caller's context; the grant is issued inside
	// run so the audit-consumed state is observable.
	run := func(t *testing.T, subject func() context.Context) {
		t.Helper()
		store := newMockStore()
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		req := httptest.NewRequestWithContext(subject(), http.MethodGet,
			"/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token, nil)
		rec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "request payload grant cannot be used")
		require.NotContains(t, rec.Body.String(), `"arguments"`, "grant_unusable must not stream payload")
		require.True(t, grantAlive(store, token), "grant_unusable must not burn the root's one-time token")
		unusable := false
		for _, r := range store.auditRecords {
			if r.Action == "request_export.denied" {
				require.Contains(t, r.Details, `"outcome":"grant_unusable"`)
				if strings.Contains(r.Details, `"outcome":"grant_unusable"`) {
					unusable = true
				}
				require.NotContains(t, r.Details, token, "the token must never reach the journal")
			}
		}
		require.True(t, unusable, "the grant_unusable denial must be journalled")
	}

	t.Run("non-root human bearer", func(t *testing.T) {
		// Own-history access would be allowed for this human, but the token
		// is not theirs to redeem: never a delegation.
		run(t, func() context.Context {
			return context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-bearer")
		})
	})

	t.Run("deny-own-history with token", func(t *testing.T) {
		// Org-admin passes the list gate via org-wide metadata, then hits the
		// explicit-deny guard: deny must not burn the token either.
		run(t, func() context.Context {
			ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "denied-human")
			ctx = adminstore.WithRequestPayloadDenyOwnHistory(ctx, true)
			ctx = adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{Type: adminstore.RequestPayloadHuman})
			return WithOrgRole(ctx, "org-1", adminstore.RoleOrgAdmin)
		})
	})
}

// GAP-A1 (mock half): the agent-subject DETAIL contract at handler level —
// the mock store now mirrors the real store's fail-closed 404 (no
// existence oracle) for a non-human subject without a verified grant.
func TestGapPinAgentDetailMockMatchesRealStore(t *testing.T) {
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	agentCtx := func() context.Context {
		ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")
		return adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{
			Type: adminstore.RequestPayloadAgent, AgentID: "agent-1", APIKeyID: "key-1",
		})
	}
	detail := func(ctx context.Context, target string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(rec, req)
		return rec
	}

	// Without a token: the row does not exist for an agent — 404, the same
	// no-existence-oracle shape as a cross-org request.
	rec := detail(agentCtx(), "/api/organizations/org-1/requests/req-1")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	require.NotContains(t, strings.ToLower(rec.Body.String()), "choices")

	// With a VALID, unconsumed grant: loud 403 grant_unusable (FIX-08
	// detail symmetry (a+): a bearer grant is a root self-grant, never a
	// delegation to an agent subject — the same fail-closed refusal as the
	// export endpoint), and it must not be burned by the denied attempt.
	rec = detail(agentCtx(), "/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "request payload grant cannot be used")
	require.NotContains(t, strings.ToLower(rec.Body.String()), "choices")
	require.True(t, grantAlive(store, token), "a denied agent detail must not consume the grant")
	found := false
	for _, r := range store.auditRecords {
		if r.Action == "request_detail.denied" && strings.Contains(r.Details, `"outcome":"grant_unusable"`) {
			found = true
			require.NotContains(t, r.Details, token, "the token must never reach the journal")
		}
	}
	require.True(t, found, "the agent grant_unusable denial must be journalled")

	// Contrast: the issuing root redeems the same, still-alive token and
	// receives the processed payload — the agent 403 is a subject contract,
	// not a broken grant.
	rec = detail(rootPayloadRequest(http.MethodGet, "/", "").Context(),
		"/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "choices")
}
