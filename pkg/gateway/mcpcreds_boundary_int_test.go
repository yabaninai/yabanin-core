package cli

// failure/boundary integration proofs on the real stack (disposable
// migrated Postgres + real AES-GCM encryptor):
//   - Foreign-tenant denies on the server-level (org credential) surface and
//     on the revocation path: an org-pinned transaction cannot see or delete
//     another org's rows even with colliding server/agent identifiers — the
//     refusal is a diagnosable ErrNotFound, never silent success.
//   - Rotation race: concurrent resolves during a rotation each see exactly
//     ONE credential version (old or new, never nil, never mixed), and after
//     the rotation lands every resolve serves the new token.
//   - Cancel/interrupt of an in-flight resolve: fail-closed error, no cache
//     poisoning, no sticky status flip.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// boundaryOrg is one tenant with its own mcp_servers row (same name in both
// orgs is the point) and one agent holding an enabled grant.
type boundaryOrg struct {
	org     *adminstore.Organization
	server  string
	agentID string
}

func newBoundaryOrg(t *testing.T, store *adminstore.Store, pool *pgxpool.Pool, suffix int64, tag string, serverName string) boundaryOrg {
	t.Helper()
	org, err := store.CreateOrganization(context.Background(), fmt.Sprintf("r034b-%s-%d", tag, suffix), fmt.Sprintf("r034b-%s-%d", tag, suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
	})
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)
	return boundaryOrg{org: org, server: serverName, agentID: agentID}
}

// TestMCPCredsSource_ForeignTenant_ServerLevelAndRevoke_Integration: org B
// (same server name, its own pin) resolves nothing of org A's server-level
// credential, reads nothing of org A's rows, and org B's delete lands as a
// diagnosable ErrNotFound that leaves org A's credential in service.
func TestMCPCredsSource_ForeignTenant_ServerLevelAndRevoke_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	now := time.Now()
	clock := func() time.Time { return now }
	suffix := time.Now().UnixNano()
	serverName := fmt.Sprintf("r034-boundary-%d", suffix)

	orgA := newBoundaryOrg(t, store, pool, suffix, "a", serverName)
	orgB := newBoundaryOrg(t, store, pool, suffix, "b", serverName)

	orgToken := "r034-orgtok-aaaa" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	foreignTok := "r034-usertok-bbbb"

	// Org A holds ONLY a server-level (org) credential.
	_, err := store.UpsertMCPServerCredential(ctx, orgA.org.ID, serverName, adminstore.MCPCredKindHeaders,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, orgToken))
	require.NoError(t, err)
	// Org B holds only its own per-user credential on the colliding name.
	versions := &stubMCPCredsVersions{versions: map[string]int64{}}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, Versions: versions, TTL: mcpCredsProbeTTL, Now: clock,
	})
	_, err = src.SubmitUserHeaders(ctx, orgB.org.ID, serverName, orgB.agentID,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, foreignTok), "r034 boundary setup")
	require.NoError(t, err)

	// The org-credential surface stays org-scoped: org B's resolve serves
	// org B's own row and never a byte of org A's server-level secret —
	// immediately and past every cache horizon.
	now = now.Add(mcpCredsProbeTTL + time.Second)
	h, kind, err := src.AuthHeaders(ctx, orgB.org.ID, serverName, orgB.agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + foreignTok}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)
	assert.NotContains(t, fmt.Sprint(h), orgToken, "org B must never see org A's org-level credential")

	// Org A still resolves its own server-level credential.
	h, kind, err = src.AuthHeaders(ctx, orgA.org.ID, serverName, orgA.agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + orgToken}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// Foreign reads are diagnosable misses, not silent successes.
	_, _, _, ok, err := store.ResolveMCPServerSecret(ctx, orgB.org.ID, serverName)
	require.NoError(t, err)
	assert.False(t, ok, "org B must not resolve org A's org-level credential")
	_, err = store.GetMCPUserCredential(ctx, orgB.org.ID, serverName, orgA.agentID)
	assert.True(t, adminstore.IsNotFound(err), "org B cannot read org A's row")

	// Foreign revoke: org B's pin cannot delete org A's credential — the
	// refusal is ErrNotFound, and org A keeps serving its credential.
	err = store.DeleteMCPUserCredential(ctx, orgB.org.ID, serverName, orgA.agentID)
	assert.True(t, adminstore.IsNotFound(err), "a cross-org revoke must be a diagnosable refusal")
	h, _, err = src.AuthHeaders(ctx, orgA.org.ID, serverName, orgA.agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + orgToken}, h["Authorization"],
		"the refused foreign revoke must not have touched org A's credential")

	// Org B revoking its OWN credential works and stays scoped.
	require.NoError(t, src.DeleteUserCredential(ctx, orgB.org.ID, serverName, orgB.agentID, "r034 boundary self-revoke"))
	h, _, err = src.AuthHeaders(ctx, orgB.org.ID, serverName, orgB.agentID)
	require.NoError(t, err)
	assert.Nil(t, h, "the own revoke must take effect for org B")
	h, _, err = src.AuthHeaders(ctx, orgA.org.ID, serverName, orgA.agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + orgToken}, h["Authorization"], "org A stays untouched by org B's lifecycle")
}

// TestMCPCredsSource_RotationRace_ConcurrentResolvesSeeOneVersion_Integration:
// resolves racing a rotation each observe exactly one version of the
// credential (old or new — never nil, never a mix), and once the rotation is
// complete every resolve serves the new token.
func TestMCPCredsSource_RotationRace_ConcurrentResolvesSeeOneVersion_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	now := time.Now()
	clock := func() time.Time { return now }
	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("r034race-%d", suffix), fmt.Sprintf("r034race-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM organizations WHERE id = $1", org.ID) })
	serverName := fmt.Sprintf("r034-race-%d", suffix)
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)

	token1 := "r034-race-token-v1" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	token2 := "r034-race-token-v2" //nolint:gosec // G101 false positive: synthetic test literal, not a credential

	versions := &stubMCPCredsVersions{versions: map[string]int64{}}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, Versions: versions, TTL: mcpCredsProbeTTL, Now: clock,
	})
	_, err = src.SubmitUserHeaders(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, token1), "r034 race v1")
	require.NoError(t, err)

	const workers = 6
	const iterations = 30
	stop := make(chan struct{})
	var wg sync.WaitGroup
	observed := make(chan string, workers*iterations)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				select {
				case <-stop:
					return
				default:
				}
				h, _, err := src.AuthHeaders(ctx, org.ID, serverName, agentID)
				if err != nil {
					errs <- err
					return
				}
				if h == nil {
					errs <- fmt.Errorf("a rotation race must never resolve to NO credential")
					return
				}
				vals := h["Authorization"]
				if len(vals) != 1 {
					errs <- fmt.Errorf("a resolve must observe exactly one version, got %v", vals)
					return
				}
				observed <- vals[0]
			}
		}()
	}

	// Rotate mid-flight; the version bump must switch every resolve over.
	// (The pinned clock never moves here: rotation visibility must come from
	// the version bump, exactly as in production.)
	time.Sleep(50 * time.Millisecond)
	_, err = src.SubmitUserHeaders(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, token2), "r034 race v2")
	require.NoError(t, err)
	close(stop)
	wg.Wait()
	close(observed)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	allowed := map[string]bool{"Bearer " + token1: true, "Bearer " + token2: true}
	seen := map[string]int{}
	for v := range observed {
		require.True(t, allowed[v], "a racing resolve observed a foreign/mixed credential: %q", v)
		seen[v]++
	}
	require.NotEmpty(t, seen, "the race window must have produced observations")

	// Post-rotation: the new version is the only one in service.
	for i := 0; i < 5; i++ {
		h, _, err := src.AuthHeaders(ctx, org.ID, serverName, agentID)
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Equal(t, []string{"Bearer " + token2}, h["Authorization"], "the rotation must be complete for every resolve")
	}
}

// TestMCPCredsSource_CancelledResolve_RealStack_Integration: a resolve
// interrupted mid-flight (cancelled context into the real pgx stack) fails
// closed, poisons neither the negative nor positive probe cache, and leaves
// no sticky status flip behind.
func TestMCPCredsSource_CancelledResolve_RealStack_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	now := time.Now()
	clock := func() time.Time { return now }
	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("r034cancel-%d", suffix), fmt.Sprintf("r034cancel-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM organizations WHERE id = $1", org.ID) })
	serverName := fmt.Sprintf("r034-cancel-%d", suffix)
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)

	userToken := "r034-cancel-token" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	versions := &stubMCPCredsVersions{versions: map[string]int64{}}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, Versions: versions, TTL: mcpCredsProbeTTL, Now: clock,
	})
	_, err = src.SubmitUserHeaders(ctx, org.ID, serverName, agentID,
		fmt.Sprintf(`{"Authorization":"Bearer %s"}`, userToken), "r034 cancel setup")
	require.NoError(t, err)

	// Interrupted resolve: error, no headers, diagnosable as cancellation.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	h, kind, err := src.AuthHeaders(cancelled, org.ID, serverName, agentID)
	require.Error(t, err, "an interrupted resolve must fail closed")
	assert.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "cancel"),
		"the interruption must stay diagnosable, got %v", err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// Interrupted unauthorized-recovery: error, no retry, no sticky flip.
	h, retry, err := src.OnUpstreamUnauthorized(cancelled, org.ID, serverName, agentID, mcpagg.CredKindHeaders)
	require.Error(t, err, "an interrupted recovery must surface, not silently pass")
	assert.Nil(t, h)
	assert.False(t, retry)
	row, err := store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Equal(t, adminstore.MCPUserCredStatusActive, row.Status,
		"an interrupted recovery must not flip the sticky status")

	// No cache poison in either direction: the healthy request resolves the
	// credential again.
	h, kind, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer " + userToken}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)
}
