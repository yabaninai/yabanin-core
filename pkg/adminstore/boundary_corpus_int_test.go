//go:build integration

package adminstore

// N04-P06 T07/T08 boundary corpus on a REAL Postgres (N04-P06 packet).
//
//   T07a — root self-grant boundaries: exact expiry edges (consume must fail
//          at and after expires_at), revoked-then-consume, cross-request
//          reuse, scope exclusivity (payload.read never implies
//          payload.read_originals), the issuing-root binding (a grant is a
//          self-grant: grantee == grantor, no other root can redeem or
//          revoke it), and the per-root active-grant cap (10 OK, 11th
//          rejected, revoking one frees the slot).
//   T07b — no-account-limits edges: provisioning under concurrent invites
//          and developer creations (no seat/license gate anywhere), with
//          the duplicate-active-invite uniqueness enforced per email.
//   T08  — interruption/restart/retry/resume: issuance interrupted while
//          blocked in the mandatory audit write (token must not escape
//          before the audit commits; completion converges), the audit-
//          failure resume state (a compensated grant is unredeemable and
//          does not consume the cap), and root settings writes that are
//          interrupted or aborted — never a partial settings pair.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corpusOrg seeds an organization plus two root admin identities, returning
// (orgID, rootA, rootB).
func corpusOrg(t *testing.T, store *Store, ctx context.Context, slug string) (string, string, string) {
	t.Helper()
	orgID := qaOrg(t, store, ctx)
	var rootA, rootB string
	require.NoError(t, store.db.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ($1, 'x', true) RETURNING id::text`,
		"root-a-"+slug+"@example.test").Scan(&rootA))
	require.NoError(t, store.db.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ($1, 'x', true) RETURNING id::text`,
		"root-b-"+slug+"@example.test").Scan(&rootB))
	t.Cleanup(func() {
		_, _ = store.db.Exec(context.Background(), `DELETE FROM admin_users WHERE id::text = ANY($1)`, []string{rootA, rootB})
	})
	return orgID, rootA, rootB
}

// auditRowCount counts durable audit rows by the grant audit entry id
// (grant.ID + "-" + action).
func auditRowCount(t *testing.T, store *Store, ctx context.Context, id string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, store.db.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, id).Scan(&n))
	return n
}

func TestIntegration_RootSelfGrantBoundaryCorpus(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID, rootA, rootB := corpusOrg(t, store, ctx, "boundary")

	const requestID = "boundary-request"

	// --- expiry edges -----------------------------------------------------
	now := time.Now().UTC()
	tiny, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, time.Second, now)
	require.NoError(t, err)
	assert.True(t, store.ConsumeRequestPayloadGrant(tiny.Token, orgID, requestID, rootA, now.Add(time.Millisecond)),
		"consume one millisecond before expiry must succeed")

	atEdge, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, time.Second, now)
	require.NoError(t, err)
	assert.False(t, store.ConsumeRequestPayloadGrant(atEdge.Token, orgID, requestID, rootA, atEdge.ExpiresAt),
		"consume exactly at expires_at must fail (durable predicate is strict)")
	assert.False(t, store.ConsumeRequestPayloadGrant(atEdge.Token, orgID, requestID, rootA, atEdge.ExpiresAt.Add(time.Nanosecond)),
		"consume one nanosecond after expiry must fail")
	// The probes above passed a future consume timestamp: in wall-clock
	// terms the grant is still live — retire it so the cap section below
	// starts from a deterministic quota.
	require.NoError(t, store.RevokeRequestPayloadGrant(atEdge.Token, rootA))

	maxTTL, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, MaxRequestPayloadGrantTTL, now)
	require.NoError(t, err)
	require.NoError(t, store.RevokeRequestPayloadGrant(maxTTL.Token, rootA), "the exact 15m bound is a valid grant")

	// --- revoked-then-consume --------------------------------------------
	revoked, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, time.Minute, now)
	require.NoError(t, err)
	require.NoError(t, store.RevokeRequestPayloadGrant(revoked.Token, rootA))
	assert.False(t, store.ConsumeRequestPayloadGrant(revoked.Token, orgID, requestID, rootA, time.Now().UTC()),
		"revoked grant must fail")
	assert.Error(t, store.RevokeRequestPayloadGrant(revoked.Token, rootA),
		"revoking an already-revoked grant fails closed")
	assert.Error(t, store.RevokeRequestPayloadGrant(revoked.Token, rootB),
		"another root cannot revoke a grant it did not issue")

	// --- cross-request reuse ----------------------------------------------
	active, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, time.Minute, now)
	require.NoError(t, err)
	assert.False(t, store.ConsumeRequestPayloadGrant(active.Token, orgID, "another-request", rootA, time.Now().UTC()),
		"a grant bound to one request cannot be reused against another")
	// The failed reuse left the grant live — retire it for the cap section.
	require.NoError(t, store.RevokeRequestPayloadGrant(active.Token, rootA))

	// --- scope exclusivity -------------------------------------------------
	readOnly, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, time.Minute, now)
	require.NoError(t, err)
	assert.Error(t, store.ConsumeRequestPayloadGrantScope(readOnly.Token, orgID, requestID, rootA, RequestPayloadScopeOriginals, time.Now().UTC()),
		"payload.read must never imply payload.read_originals")
	assert.NoError(t, store.ConsumeRequestPayloadGrantScope(readOnly.Token, orgID, requestID, rootA, RequestPayloadScopeRead, time.Now().UTC()))

	originals, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeOriginals, time.Minute, now)
	require.NoError(t, err)
	assert.Error(t, store.ConsumeRequestPayloadGrantScope(originals.Token, orgID, requestID, rootA, RequestPayloadScopeRead, time.Now().UTC()),
		"payload.read_originals must never imply payload.read")
	assert.NoError(t, store.ConsumeRequestPayloadGrantScope(originals.Token, orgID, requestID, rootA, RequestPayloadScopeOriginals, time.Now().UTC()))

	// The used-audit entry shares the issuance prefix (canonical grant id).
	assert.Equal(t, int64(1), auditRowCount(t, store, ctx, readOnly.ID+"-request_payload.grant_used"),
		"consumption audited exactly once under the same canonical grant id")

	// --- issuing-root binding: a self-grant serves no other root ----------
	bound, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootA, RequestPayloadScopeRead, time.Minute, now)
	require.NoError(t, err)
	assert.Equal(t, rootA, bound.RootID, "the grant is stored with the issuing root as its grantee")
	assert.False(t, store.ConsumeRequestPayloadGrant(bound.Token, orgID, requestID, rootB, time.Now().UTC()),
		"root B cannot redeem root A's self-grant — no grant into another root's context")

	// --- audit rows: exactly one per lifecycle action ----------------------
	assert.Equal(t, int64(1), auditRowCount(t, store, ctx, bound.ID+"-request_payload.grant_issued"),
		"issuance audited exactly once")
	assert.Equal(t, int64(0), auditRowCount(t, store, ctx, bound.ID+"-request_payload.grant_used"),
		"an unredeemed grant is never audited as used")
	require.NoError(t, store.RevokeRequestPayloadGrant(bound.Token, rootA))
	assert.Equal(t, int64(1), auditRowCount(t, store, ctx, bound.ID+"-request_payload.grant_revoked"),
		"revocation audited exactly once")

	// --- per-root active cap (10 OK, 11th rejected, revoke frees a slot) --
	// Every earlier grant is by now consumed, revoked or expired, so the
	// quota starts empty for rootA.
	var capTokens []string
	for i := 0; i < MaxActiveRequestGrants; i++ {
		g, err := store.CreateRequestPayloadGrant(orgID, fmt.Sprintf("cap-request-%d", i), rootA, time.Minute, time.Now().UTC())
		require.NoError(t, err, "active grant %d within the cap must issue", i+1)
		capTokens = append(capTokens, g.Token)
	}
	_, err = store.CreateRequestPayloadGrant(orgID, "cap-request-over", rootA, time.Minute, time.Now().UTC())
	assert.ErrorIs(t, err, ErrInvalidRequestPayloadGrant, "the 11th concurrent grant is rejected")
	require.NoError(t, store.RevokeRequestPayloadGrant(capTokens[0], rootA))
	_, err = store.CreateRequestPayloadGrant(orgID, "cap-request-over", rootA, time.Minute, time.Now().UTC())
	assert.NoError(t, err, "revoking one grant frees an active slot")

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM request_payload_grants WHERE org_id = $1::uuid`, orgID)
	})
}

// TestIntegration_GrantIssuanceInterruptedMidAudit pins the T08 mid-flow
// interruption on the real durable plane: the grant row commits first, then
// the mandatory audit write serializes on the append advisory lock. While
// that write is blocked, the bearer token has NOT escaped the issuer; once
// the interruption clears, issuance completes and the grant is audited
// exactly once and redeemable (a retry in front of a still-blocked audit
// would block identically — no second usable grant can exist).
func TestIntegration_GrantIssuanceInterruptedMidAudit(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID, rootA, _ := corpusOrg(t, store, ctx, "interrupt")

	// Hold the audit append lock from a foreign transaction: the issuance's
	// audit write will block after the grant row has already committed.
	lockTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = lockTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(current_database() || ':admin_audit_logs:append'))`)
	require.NoError(t, err)

	type issued struct {
		grant RequestPayloadGrant
		err   error
	}
	done := make(chan issued, 1)
	go func() {
		g, err := store.CreateRequestPayloadGrant(orgID, "interrupted-request", rootA, time.Minute, time.Now().UTC())
		done <- issued{g, err}
	}()

	select {
	case res := <-done:
		t.Fatalf("issuance returned while its mandatory audit write was still blocked: grant=%+v err=%v", res.grant, res.err)
	case <-time.After(600 * time.Millisecond):
		// Still blocked inside the audit write — the token has not escaped.
	}

	// The interruption clears; issuance converges.
	require.NoError(t, lockTx.Rollback(context.Background()), "releasing the append lock")
	var res issued
	select {
	case res = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("issuance never completed after the audit interruption cleared")
	}
	require.NoError(t, res.err)
	assert.Equal(t, int64(1), auditRowCount(t, store, ctx, res.grant.ID+"-request_payload.grant_issued"),
		"the completed issuance is audited exactly once")
	assert.True(t, store.ConsumeRequestPayloadGrant(res.grant.Token, orgID, "interrupted-request", rootA, time.Now().UTC()),
		"the grant that survived the interruption is redeemable exactly once")

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM request_payload_grants WHERE org_id = $1::uuid`, orgID)
	})
}

// TestIntegration_AuditFailureResumeState pins the T08 post-interruption
// resume state on the real durable plane: a grant whose audit failed and
// that was compensated (revoked_at set) can never be redeemed and never
// counts toward the per-root active cap — a retry starts clean.
func TestIntegration_AuditFailureResumeState(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID, rootA, _ := corpusOrg(t, store, ctx, "resume")

	now := time.Now().UTC()
	compensated, err := store.CreateRequestPayloadGrantScope(orgID, "resume-request", rootA, RequestPayloadScopeRead, time.Minute, now)
	require.NoError(t, err)
	// Emulate the completed compensating revoke (the exact statement the
	// issuance path runs when its audit write fails after the commit).
	tag, err := pool.Exec(ctx,
		`UPDATE request_payload_grants SET revoked_at=$2 WHERE id=$1::uuid AND revoked_at IS NULL`,
		compensated.ID, now)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())

	assert.False(t, store.ConsumeRequestPayloadGrant(compensated.Token, orgID, "resume-request", rootA, time.Now().UTC()),
		"the compensated grant is unredeemable after a restart")

	// The compensated row does not count toward the active cap.
	for i := 0; i < MaxActiveRequestGrants; i++ {
		_, err := store.CreateRequestPayloadGrant(orgID, fmt.Sprintf("resume-cap-%d", i), rootA, time.Minute, time.Now().UTC())
		require.NoError(t, err, "active grant %d must issue despite the compensated row", i+1)
	}
	_, err = store.CreateRequestPayloadGrant(orgID, "resume-cap-over", rootA, time.Minute, time.Now().UTC())
	assert.ErrorIs(t, err, ErrInvalidRequestPayloadGrant, "the cap counts only live grants, not compensated rows")

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM request_payload_grants WHERE org_id = $1::uuid`, orgID)
	})
}

// TestIntegration_RootSettingsWriteInterruptedNoPartialState pins the T08
// settings property: the root-only settings pair (cache_enabled, cache_mode)
// is one statement — an aborted, interrupted or concurrent write can never
// leave a half-applied pair, and an unknown organization is an error, never
// a silent success.
func TestIntegration_RootSettingsWriteInterruptedNoPartialState(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	cs, err := store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	assert.True(t, cs.CacheEnabled, "fresh org baseline cache_enabled")
	assert.Equal(t, "semantic", cs.CacheMode, "fresh org baseline cache_mode")

	// Aborted write: a mode violating the durable CHECK rejects the whole
	// statement — cache_enabled must NOT have flipped while the mode failed.
	err = store.UpdateOrgCacheSettings(ctx, orgID, false, "bogus")
	require.Error(t, err, "the settings CHECK aborts the write")
	cs, err = store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	assert.True(t, cs.CacheEnabled, "no partial write: enabled unchanged")
	assert.Equal(t, "semantic", cs.CacheMode, "no partial write: mode unchanged")

	// Interrupted write: hold the org row lock from a foreign transaction;
	// the settings UPDATE blocks; canceling the caller's context aborts the
	// call. Context cancellation of a lock-blocked statement is inherently
	// racy at the wire level (pgx sends a cancel request, but the deadline
	// path may surface first and the server-side statement can still commit
	// once the lock frees) — the durable guarantees that ARE contract are:
	// (1) the interrupted caller NEVER receives silent success, (2) the
	// stored pair is always exactly one writer's complete pair, and (3) the
	// next healthy write converges the row deterministically.
	lockTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = lockTx.Exec(ctx, `SELECT id FROM organizations WHERE id = $1::uuid FOR UPDATE`, orgID)
	require.NoError(t, err)

	updCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- store.UpdateOrgCacheSettings(updCtx, orgID, false, "exact") }()
	time.Sleep(300 * time.Millisecond) // the UPDATE is now blocked on the row lock
	cancel()
	select {
	case err := <-done:
		require.Error(t, err, "the interrupted settings write must fail, not silently succeed")
	case <-time.After(15 * time.Second):
		t.Fatal("interrupted settings write never returned")
	}
	require.NoError(t, lockTx.Rollback(ctx), "release the row lock")

	cs, err = store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	type settingsPair struct {
		enabled bool
		mode    string
	}
	landed := settingsPair{cs.CacheEnabled, cs.CacheMode}
	completePairs := []settingsPair{{true, "semantic"}, {false, "exact"}}
	assert.Contains(t, completePairs, landed,
		"an interrupted write can only leave the baseline pair or one writer's full pair, never a mixture, got (%v, %s)", cs.CacheEnabled, cs.CacheMode)

	// Convergence: the next healthy write fully replaces whatever landed.
	require.NoError(t, store.UpdateOrgCacheSettings(ctx, orgID, false, "exact"))
	cs, err = store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	assert.False(t, cs.CacheEnabled)
	assert.Equal(t, "exact", cs.CacheMode)

	// Concurrent writers: the final state is exactly one writer's pair —
	// never a mixture of two writers' fields.
	type write struct {
		enabled bool
		mode    string
	}
	writes := []write{{true, "off"}, {false, "exact"}, {true, "semantic"}, {false, "off"}, {true, "exact"}, {false, "semantic"}}
	var wg sync.WaitGroup
	for _, w := range writes {
		wg.Add(1)
		go func(w write) {
			defer wg.Done()
			assert.NoError(t, store.UpdateOrgCacheSettings(context.Background(), orgID, w.enabled, w.mode))
		}(w)
	}
	wg.Wait()
	cs, err = store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	var matched bool
	for _, w := range writes {
		if cs.CacheEnabled == w.enabled && cs.CacheMode == w.mode {
			matched = true
		}
	}
	assert.True(t, matched, "final settings must be one writer's full pair, got (%v, %s)", cs.CacheEnabled, cs.CacheMode)

	// Unknown organization: an error (never a silent 0-row success).
	err = store.UpdateOrgCacheSettings(ctx, uuid.New().String(), true, "off")
	assert.ErrorIs(t, err, ErrNotFound, "settings write to a nonexistent org must not report success")
	err = store.UpdateOrgRoutingSettings(ctx, uuid.New().String(), "auto", 0.6)
	assert.ErrorIs(t, err, ErrNotFound, "routing settings write to a nonexistent org must not report success")
}

// TestIntegration_ProvisioningUnderConcurrentInvites pins the T07b edge:
// concurrent member invites and developer creations all provision with no
// license or seat gate anywhere, and the only limiting rule is the
// per-(org,email) uniqueness of ACTIVE invites — enforced under concurrency.
func TestIntegration_ProvisioningUnderConcurrentInvites(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)
	team, err := store.GetDefaultTeam(ctx, orgID)
	require.NoError(t, err)

	var inviterID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ('n04p6-inviter@example.test', 'x', false) RETURNING id::text`).Scan(&inviterID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_users WHERE id::text = $1`, inviterID)
	})

	const perKind = 10
	stamp := time.Now().UnixNano()

	// Concurrent distinct invites and developer accounts: every single one
	// provisions — no account-count or license gate exists.
	var wg sync.WaitGroup
	inviteErrs := make([]error, perKind)
	devErrs := make([]error, perKind)
	for i := 0; i < perKind; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := store.CreateMemberInvite(ctx, orgID,
				fmt.Sprintf("n04p6-invite-%d-%d@example.test", stamp, i), RoleReader, inviterID)
			inviteErrs[i] = err
		}(i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.CreateDeveloper(ctx, DeveloperUser{
				Email:       fmt.Sprintf("n04p6-dev-%d-%d@example.test", stamp, i),
				DisplayName: fmt.Sprintf("N04-P06 concurrent dev %d", i),
				OrgID:       orgID,
				TeamID:      team.ID,
				Active:      true,
			})
			devErrs[i] = err
		}(i)
	}
	wg.Wait()
	for i := 0; i < perKind; i++ {
		require.NoError(t, inviteErrs[i], "concurrent invite %d must provision", i)
		require.NoError(t, devErrs[i], "concurrent developer %d must provision", i)
	}

	invites, err := store.ListMemberInvites(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, invites, perKind, "every concurrent invite is live — no seat cap declined any")
	developers, err := store.ListDevelopers(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, developers, perKind, "every concurrent developer account is live")

	// The one real limit: an ACTIVE invite is unique per (org, email), and
	// that uniqueness holds under a concurrent duplicate race.
	dupEmail := fmt.Sprintf("n04p6-dup-%d@example.test", stamp)
	dupErrs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := store.CreateMemberInvite(ctx, orgID, dupEmail, RoleReader, inviterID)
			dupErrs[i] = err
		}(i)
	}
	wg.Wait()
	var successes, pendingErrs int
	for _, err := range dupErrs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvitePending):
			pendingErrs++
		default:
			t.Fatalf("unexpected duplicate-invite error: %v", err)
		}
	}
	assert.Equal(t, 1, successes, "exactly one duplicate-race invite wins")
	assert.Equal(t, 1, pendingErrs, "the loser is rejected as a duplicate active invite")

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM member_invites WHERE org_id = $1::uuid`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM developer_users WHERE org_id = $1`, orgID)
	})
}
