package cli

// real AES-GCM encryptor + the MC-2 source): scoped retrieval (user →
// server, foreign org miss), rotation (headers re-submit, oauth token
// rotation), scheduled revocation (expires_at miss — lazy expiry acts as
// revocation, the probe cache never resurrects it), explicit revoke (source
// delete → version bump + audit row → immediate miss), and non-visibility
// (masked reads, audit details carry last4 only).
//
// Cache polarity under test follows the orgCredsProbe policy (upstream.go):
// a cached negative load-sheds within the TTL (a newly added credential
// stays invisible at most mcpCredsProbeTTL), while every positive decision
// re-resolves the store per request — so rotation and revocation are visible
// immediately and a revoked token is never served from cache.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestMCPCredsSource_ScopedRetrieveRotateRevoke_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	now := time.Now()
	clock := func() time.Time { return now }

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("r034-%d", suffix), fmt.Sprintf("r034-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
	})
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("r034b-%d", suffix), fmt.Sprintf("r034b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgB.ID)
	})

	serverName := fmt.Sprintf("r034-srv-%d", suffix)
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)
	seedMCPServerRow(t, pool, orgB.ID, serverName)
	agentB := seedMCPAgentWithGrant(t, pool, orgB.ID, serverName)

	versions := &stubMCPCredsVersions{versions: map[string]int64{}}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, Versions: versions, TTL: mcpCredsProbeTTL, Now: clock,
	})

	userToken1 := "r034-user-token-aaaa"    //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	userToken2 := "r034-user-token-bbbb"    //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	oauthToken := "r034-oauth-access-cccc"  //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	serverToken := "r034-server-token-dddd" //nolint:gosec // G101 false positive: synthetic test literal, not a credential

	// Scoped retrieval: no credential anywhere → miss in both orgs.
	h, kind, err := src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)
	h, kind, err = src.AuthHeaders(ctx, orgB.ID, serverName, agentB)
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// Submit (headers kind) through the source: the readback is masked — the
	// wire-visible row never carries the token — and the org version bumps.
	row, err := src.SubmitUserHeaders(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, userToken1), "r034 setup")
	require.NoError(t, err)
	assert.Equal(t, "aaaa", row.SecretLast4)
	assert.True(t, row.HasSecret)
	masked, mErr := json.Marshal(row)
	require.NoError(t, mErr)
	assert.NotContains(t, string(masked), userToken1, "the masked row must not carry the token")
	assert.NotZero(t, versions.versions[org.ID], "the submit must bump the org version")

	// The fresh negative load-sheds within the TTL (documented polarity)…
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Nil(t, h, "a fresh negative decision load-sheds within the TTL")

	// …and never outlives it: after the TTL lapse the new credential is
	// served, and the plaintext only ever surfaces as the outbound header.
	now = now.Add(mcpCredsProbeTTL + time.Second)
	h, kind, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + userToken1}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// Rotation: re-submit → the very next resolve serves the new value on
	// the same instance (the store read stays authoritative per request).
	_, err = src.SubmitUserHeaders(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, userToken2), "r034 rotate")
	require.NoError(t, err)
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + userToken2}, h["Authorization"])
	assert.NotContains(t, fmt.Sprint(h), userToken1, "the old token must be gone after rotation")

	// Server-level credential beneath the user row (the documented chain).
	_, err = store.UpsertMCPServerCredential(ctx, org.ID, serverName, adminstore.MCPCredKindHeaders,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, serverToken))
	require.NoError(t, err)

	// Scheduled revocation: an oauth credential with a future expiry works…
	future := now.Add(time.Hour)
	_, err = store.UpsertMCPUserCredential(ctx, org.ID, serverName, agentID, adminstore.MCPCredKindOAuth,
		fmt.Sprintf(`{"access_token":%q,"refresh_token":"r034-refresh","token_type":"Bearer"}`, oauthToken), &future)
	require.NoError(t, err)
	h, kind, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + oauthToken}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindOAuth, kind)

	// …and the SAME row past its expires_at misses on the next request
	// without any cache resurrect: the runtime falls through to the
	// server-level credential (lazy expiry = revocation on schedule).
	expired := now.Add(-time.Minute)
	_, err = store.UpdateMCPUserOAuthTokens(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer"}`, oauthToken), &expired)
	require.NoError(t, err)
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + serverToken}, h["Authorization"])
	assert.NotContains(t, fmt.Sprint(h), oauthToken, "the expired oauth token must not resolve")

	// Re-activation returns the row to service (expires_at cleared).
	_, err = store.UpdateMCPUserOAuthTokens(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer"}`, oauthToken), nil)
	require.NoError(t, err)
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + oauthToken}, h["Authorization"])

	// Explicit revoke through the source: audit row + version bump, the row
	// is gone, and the next resolve never serves the revoked token again.
	now = now.Add(time.Second)
	before := versions.versions[org.ID]
	require.NoError(t, src.DeleteUserCredential(ctx, org.ID, serverName, agentID, "r034 revoke"))
	after := versions.versions[org.ID]
	assert.NotEqual(t, before, after, "the revoke must bump the org version")
	var auditCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE action = $1 AND admin_id = $2`,
		"mcp_user_credential_delete", agentID).Scan(&auditCount))
	assert.Equal(t, 1, auditCount, "the revoke must land in the audit journal")
	_, err = store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.True(t, adminstore.IsNotFound(err), "the revoked row must be gone")
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + serverToken}, h["Authorization"], "the runtime falls back to the server level")
	assert.NotContains(t, fmt.Sprint(h), oauthToken, "the revoked token must not resolve")
	err = src.DeleteUserCredential(ctx, org.ID, serverName, agentID, "r034 revoke again")
	require.True(t, adminstore.IsNotFound(err), "a second revoke misses")

	// Foreign tenant: org B resolves the same server name under its own org
	// pin; past its cached negative's TTL the authoritative re-probe still
	// sees none of org A's credential material.
	now = now.Add(mcpCredsProbeTTL + time.Second)
	h, kind, err = src.AuthHeaders(ctx, orgB.ID, serverName, agentB)
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)
	for _, leak := range []string{userToken1, userToken2, oauthToken, serverToken} {
		assert.NotContains(t, fmt.Sprint(h), leak)
	}

	// Audit details are mask-only: no token material in the journal.
	var auditDetails []string
	rows, err := pool.Query(ctx,
		`SELECT details FROM admin_audit_logs WHERE admin_id = $1 AND action LIKE 'mcp_user_credential%'`,
		agentID)
	require.NoError(t, err)
	for rows.Next() {
		var d string
		require.NoError(t, rows.Scan(&d))
		auditDetails = append(auditDetails, d)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.NotEmpty(t, auditDetails)
	for _, d := range auditDetails {
		for _, leak := range []string{userToken1, userToken2, oauthToken, serverToken, "r034-refresh"} {
			assert.NotContains(t, d, leak, "audit details must not carry token material")
		}
	}
	assert.Contains(t, fmt.Sprint(auditDetails), "last4=bbbb", "the upsert audit carries the mask")
}
