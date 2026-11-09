package handlers

// GAP-A3 (RV-1 invariant audit, Table 2 row 17): cross-ROOT redemption on the
// REAL database through the full handler stack. A request payload grant is a
// root SELF-grant: the durable row binds grantee to the issuing root, so a
// second root presenting the same valid token (same org, same request) fails
// closed with the generic grant-invalid 403 and the token stays redeemable by
// its issuer — exactly once. The store-level "wrong grantee must fail" cell
// was pinned only behind the Docker-gated integration tag
// (pkg/adminstore/integration_requests_test.go); this pin runs in the normal
// suite (testdb.Postgres) so the contract cannot drift unnoticed.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

func TestGapPinCrossRootGrantRedemptionBoundToIssuer(t *testing.T) {
	g := gapPinSeedReal(t)

	// A second root identity: root-B is is_root but is NOT the grant's
	// grantee — only the issuing root-A is.
	ctx := context.Background()
	var rootB string
	require.NoError(t, g.pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ($1, 'gappin-not-a-hash', true) RETURNING id::text`,
		fmt.Sprintf("gappin-rootb-%d@test.local", time.Now().UnixNano())).Scan(&rootB))
	t.Cleanup(func() {
		_, _ = g.pool.Exec(ctx, `DELETE FROM admin_users WHERE id=$1::uuid`, rootB)
	})

	grant, err := g.store.CreateRequestPayloadGrantScope(g.orgID, g.reqID,
		g.rootID, adminstore.RequestPayloadScopeRead, time.Minute, time.Now().UTC())
	require.NoError(t, err)
	target := "/api/organizations/" + g.orgID + "/requests/export?request_id=" + g.reqID +
		"&payload_grant=" + grant.Token
	export := func(rootID string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		wrapWithParams(g.h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
			rec, gapPinRootRequest(rootID, http.MethodGet, target))
		return rec
	}
	tokenAlive := func() bool {
		t.Helper()
		hash := sha256.Sum256([]byte(grant.Token))
		var unconsumed int
		require.NoError(t, g.pool.QueryRow(ctx,
			`SELECT count(*) FROM request_payload_grants WHERE token_hash=$1 AND consumed_at IS NULL`,
			hash[:]).Scan(&unconsumed))
		return unconsumed == 1
	}

	// (1) Root-B presents root-A's valid token: fail closed with the generic
	// grant-invalid 403 — never an existence oracle, never payload bytes.
	recB := export(rootB)
	require.Equal(t, http.StatusForbidden, recB.Code, recB.Body.String())
	require.Contains(t, recB.Body.String(), "grant is invalid or unavailable")
	require.NotContains(t, recB.Body.String(), "payload-secret")

	// (2) The failed redemption did NOT burn the token: it stays redeemable
	// by its issuer.
	require.True(t, tokenAlive(), "a wrong-grantee consume must leave the grant unconsumed")

	// (3) The issuing root redeems the SAME, still-alive token: 200 with the
	// granted payload.
	recA := export(g.rootID)
	require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
	require.Contains(t, recA.Body.String(), "payload-secret")

	// (4) One-use: a replay — by either root — fails closed.
	require.Equal(t, http.StatusForbidden, export(g.rootID).Code)
	require.Equal(t, http.StatusForbidden, export(rootB).Code)

	// (5) Durable state: exactly one consumption is recorded.
	hash := sha256.Sum256([]byte(grant.Token))
	var consumed int
	require.NoError(t, g.pool.QueryRow(ctx,
		`SELECT count(*) FROM request_payload_grants WHERE token_hash=$1 AND consumed_at IS NOT NULL`,
		hash[:]).Scan(&consumed))
	require.Equal(t, 1, consumed, "the durable row must record exactly one consumption")
}
