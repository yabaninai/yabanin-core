package adminstore

// stand (testcontainers). Covers: rollout CRUD round-trip (versions, atomic
// activation, rollback flip, delete cascade), percent bounds at the DB CHECK
// level, org RLS isolation (a foreign org sees nothing — the 0003 posture
// with the app.current_org GUC), the version-key bump contract on every
// mutation, the snapshot projection (enabled + active version only), the
// Redis canary version-cache contract, and the auto-Recommendation evidence
// query over request_logs.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// canaryFixture seeds two orgs and a canary store (policyFixture parity).
type canaryFixture struct {
	store *Store
	pool  *pgxpool.Pool
	orgA  string
	orgB  string
}

func newCanaryFixture(t *testing.T) canaryFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("can-a-%d", suffix), fmt.Sprintf("can-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("can-b-%d", suffix), fmt.Sprintf("can-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})
	return canaryFixture{store: store, pool: pool, orgA: orgA.ID, orgB: orgB.ID}
}

// TestCanaryRollout_CRUD_Integration: create appends version 1 (draft), new
// versions append monotonically, activation flips labels and current_version
// in one transaction, the rollback flip is atomic, delete cascades.
func TestCanaryRollout_CRUD_Integration(t *testing.T) {
	fx := newCanaryFixture(t)
	ctx := context.Background()

	r, v1, err := fx.store.CreateCanaryRollout(ctx, fx.orgA, "glm-migration", "glm-4.5", "glm-5.3", 10, "admin@x.test")
	require.NoError(t, err)
	require.NotEmpty(t, r.ID)
	assert.Equal(t, fx.orgA, r.OrgID)
	assert.False(t, r.Enabled, "a new rollout starts detached")
	assert.Equal(t, 0, r.CurrentVersion, "no active version until activation")
	assert.Equal(t, 1, v1.Version)
	assert.Equal(t, CanaryLabelDraft, v1.Label)
	assert.Equal(t, "glm-4.5", v1.BaseModel)
	assert.Equal(t, "glm-5.3", v1.CanaryModel)
	assert.Equal(t, 10, v1.Percent)

	// Ramp append: v2 at 25 percent, stays draft.
	v2, err := fx.store.CreateCanaryRolloutVersion(ctx, fx.orgA, r.ID, "glm-4.5", "glm-5.3", 25, "admin@x.test")
	require.NoError(t, err)
	assert.Equal(t, 2, v2.Version)
	assert.Equal(t, CanaryLabelDraft, v2.Label)

	// Versions list: newest first.
	versions, err := fx.store.ListCanaryRolloutVersions(ctx, fx.orgA, r.ID)
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, 2, versions[0].Version)

	// Atomic activation: current_version moves, labels follow.
	r, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.orgA, r.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, r.CurrentVersion)
	v1After, err := fx.store.GetCanaryRolloutVersion(ctx, fx.orgA, r.ID, 1)
	require.NoError(t, err)
	assert.Equal(t, CanaryLabelDraft, v1After.Label, "the previously active label demotes to draft")
	v2After, err := fx.store.GetCanaryRolloutVersion(ctx, fx.orgA, r.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, CanaryLabelActive, v2After.Label)

	// Activating a missing version is ErrNotFound.
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.orgA, r.ID, 99)
	require.True(t, IsNotFound(err))

	// Attach + the manual rollback flip (enabled=false, D3).
	r, err = fx.store.UpdateCanaryRollout(ctx, fx.orgA, r.ID, true)
	require.NoError(t, err)
	assert.True(t, r.Enabled)
	r, err = fx.store.UpdateCanaryRollout(ctx, fx.orgA, r.ID, false)
	require.NoError(t, err)
	assert.False(t, r.Enabled, "rollback = enabled=false; history intact")
	history, err := fx.store.ListCanaryRolloutVersions(ctx, fx.orgA, r.ID)
	require.NoError(t, err)
	require.Len(t, history, 2, "rollback never touches version history")

	// Snapshot: only enabled rollouts with an active version resolve.
	snap, err := fx.store.LoadCanarySnapshot(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, snap.Rollouts, 1)
	_, ok := snap.Versions[r.ID]
	assert.False(t, ok, "a disabled rollout contributes no active version (rolled back)")

	r, err = fx.store.UpdateCanaryRollout(ctx, fx.orgA, r.ID, true)
	require.NoError(t, err)
	snap, err = fx.store.LoadCanarySnapshot(ctx, fx.orgA)
	require.NoError(t, err)
	active, ok := snap.Versions[r.ID]
	require.True(t, ok)
	assert.Equal(t, 2, active.Version)
	assert.Equal(t, 25, active.Percent, "the snapshot carries the ACTIVE version's percent")

	// Store-level validation: 0 and 100 are rejected before SQL.
	_, _, err = fx.store.CreateCanaryRollout(ctx, fx.orgA, "bad-bounds", "a", "b", 0, "")
	require.ErrorContains(t, err, "between 1 and 99")
	_, _, err = fx.store.CreateCanaryRollout(ctx, fx.orgA, "bad-bounds", "a", "b", 100, "")
	require.ErrorContains(t, err, "between 1 and 99")

	// Duplicate name inside the org is rejected; a different name is fine.
	_, _, err = fx.store.CreateCanaryRollout(ctx, fx.orgA, "glm-migration", "a", "b", 10, "")
	require.ErrorContains(t, err, "already exists")
	_, _, err = fx.store.CreateCanaryRollout(ctx, fx.orgA, "other-migration", "a", "b", 10, "")
	require.NoError(t, err)

	// Delete cascades: versions are gone with the rollout.
	require.NoError(t, fx.store.DeleteCanaryRollout(ctx, fx.orgA, r.ID))
	_, err = fx.store.GetCanaryRollout(ctx, fx.orgA, r.ID)
	require.True(t, IsNotFound(err))
	_, err = fx.store.GetCanaryRolloutVersion(ctx, fx.orgA, r.ID, 2)
	require.True(t, IsNotFound(err))

	err = fx.store.DeleteCanaryRollout(ctx, fx.orgA, r.ID)
	require.True(t, IsNotFound(err))
}

// TestCanaryRollout_PercentBounds_DBLevel: the CHECK constraint is the last
// line of defense — 0 and 100 and base==canary never persist even through
// raw SQL.
func TestCanaryRollout_PercentBounds_DBLevel(t *testing.T) {
	fx := newCanaryFixture(t)
	ctx := context.Background()
	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.orgA, "bounds", "a-model", "b-model", 50, "")
	require.NoError(t, err)

	for _, bad := range []int{0, 100, -1} {
		_, err := fx.pool.Exec(ctx,
			`INSERT INTO canary_rollout_versions (rollout_id, org_id, version, base_model, canary_model, percent)
			 VALUES ($1::uuid, $2::uuid, 9, 'a', 'b', $3)`, r.ID, fx.orgA, bad)
		require.Error(t, err, "percent %d must be rejected by the CHECK constraint", bad)
	}
	_, err = fx.pool.Exec(ctx,
		`INSERT INTO canary_rollout_versions (rollout_id, org_id, version, base_model, canary_model, percent)
		 VALUES ($1::uuid, $2::uuid, 9, 'same', 'same', 10)`, r.ID, fx.orgA)
	require.Error(t, err, "base == canary must be rejected by the CHECK constraint")
}

// TestCanaryRollout_RLS_OrgIsolation_Integration: under the application
// posture (SET ROLE yabanin_app + app.current_org GUC) a foreign org's
// rollouts are invisible and unwritable, and an unbound session sees nothing
// (fail closed) — the 0003 posture mirrors policy_*.
func TestCanaryRollout_RLS_OrgIsolation_Integration(t *testing.T) {
	fx := newCanaryFixture(t)
	ctx := context.Background()

	rollA, _, err := fx.store.CreateCanaryRollout(ctx, fx.orgA, "rls-a", "a1", "a2", 10, "")
	require.NoError(t, err)
	_, _, err = fx.store.CreateCanaryRollout(ctx, fx.orgB, "rls-b", "b1", "b2", 20, "")
	require.NoError(t, err)

	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()

	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	bindOrg := func(orgID string) {
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgID)
		require.NoError(t, err)
	}

	rlsAdapter := rlsConnAdapter{conn.Conn()}
	rls := newForTest(rlsAdapter, slog.New(slog.DiscardHandler), nil)

	// Org A sees only its own rollout.
	bindOrg(fx.orgA)
	seen, err := rls.ListCanaryRollouts(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.Equal(t, rollA.ID, seen[0].ID)

	// Cross-org reads/writes are ErrNotFound — a foreign rollout id is
	// indistinguishable from a missing one under the pinned GUC.
	bVersions, err := rls.ListCanaryRolloutVersions(ctx, fx.orgA, "00000000-0000-0000-0000-000000000000")
	require.True(t, IsNotFound(err))
	assert.Empty(t, bVersions)
	_, err = rls.UpdateCanaryRollout(ctx, fx.orgA, "00000000-0000-0000-0000-000000000000", true)
	require.True(t, IsNotFound(err))
	err = rls.DeleteCanaryRollout(ctx, fx.orgA, "00000000-0000-0000-0000-000000000000")
	require.True(t, IsNotFound(err))

	// Raw SQL WITHOUT the org GUC (empty binding): nothing is visible —
	// the FORCE policy is the isolation boundary.
	bindOrg("")
	none, err := rlsAdapter.Query(ctx, `SELECT id FROM canary_rollouts`)
	require.NoError(t, err)
	assert.False(t, none.Next(), "an unbound raw session must not see any org's rollouts")
	none.Close()

	// Direct cross-org INSERT violates the WITH CHECK arm on both tables.
	bindOrg(fx.orgA)
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO canary_rollouts (org_id, name) VALUES ($1::uuid, 'evil')`, fx.orgB)
	require.Error(t, err, "cross-org rollout insert must be rejected by the org_isolation policy")
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO canary_rollout_versions (rollout_id, org_id, version, base_model, canary_model, percent)
		 VALUES (gen_random_uuid(), $1::uuid, 1, 'x', 'y', 10)`, fx.orgB)
	require.Error(t, err, "cross-org version insert must be rejected by the org_isolation policy")
}

// TestCanaryRollout_VersionBump_OnEveryMutation: the store bumps the org's
// canary version key after EVERY successful mutation, never after a failed
// one; a failing bumper never fails the mutation.
func TestCanaryRollout_VersionBump_OnEveryMutation(t *testing.T) {
	fx := newCanaryFixture(t)
	ctx := context.Background()

	bumper := newRecordingCanaryBumper()
	fx.store.SetCanaryVersionBumper(bumper)

	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.orgA, "bump", "a", "b", 10, "")
	require.NoError(t, err)
	require.Equal(t, 1, bumper.count(fx.orgA), "create bumps")

	_, err = fx.store.CreateCanaryRolloutVersion(ctx, fx.orgA, r.ID, "a", "b", 20, "")
	require.NoError(t, err)
	require.Equal(t, 2, bumper.count(fx.orgA), "new version bumps")

	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.orgA, r.ID, 2)
	require.NoError(t, err)
	require.Equal(t, 3, bumper.count(fx.orgA), "activation bumps")

	_, err = fx.store.UpdateCanaryRollout(ctx, fx.orgA, r.ID, true)
	require.NoError(t, err)
	require.Equal(t, 4, bumper.count(fx.orgA), "rollback/attach flip bumps")

	// A foreign-org mutation fails and must NOT bump.
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.orgB, r.ID, true)
	require.True(t, IsNotFound(err))
	require.Equal(t, 0, bumper.count(fx.orgB), "a failed foreign-org mutation must not bump")

	// A failing bumper degrades to a warning, never fails the mutation.
	bumper.fail = true
	err = fx.store.DeleteCanaryRollout(ctx, fx.orgA, r.ID)
	require.NoError(t, err, "a failed version bump must not fail the committed mutation")
}

// recordingCanaryBumper counts canary bump calls per org.
type recordingCanaryBumper struct {
	mu     sync.Mutex
	called map[string]int
	fail   bool
}

func newRecordingCanaryBumper() *recordingCanaryBumper {
	return &recordingCanaryBumper{called: map[string]int{}}
}

func (b *recordingCanaryBumper) SetCanaryVersion(_ context.Context, orgID string, _ int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return fmt.Errorf("redis down (simulated)")
	}
	b.called[orgID]++
	return nil
}

func (b *recordingCanaryBumper) count(orgID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.called[orgID]
}

// — exact key "canarystore:ver:<orgID>", decimal int64 value, ~7d TTL,
// missing key reads as 0.
func TestCanaryVersionCache_Redis_Contract(t *testing.T) {
	rdb := testdb.Redis(t)
	ctx := context.Background()
	vc := NewCanaryVersionCache(rdb, slog.New(slog.DiscardHandler))

	const orgID = "org-canary-redis-contract"
	key := CanaryVersionKeyPrefix + orgID
	require.Equal(t, "canarystore:ver:"+orgID, key, "the R106 contract pins the exact key format")
	require.NotEqual(t, PolicyVersionKeyPrefix, CanaryVersionKeyPrefix, "canary and policy namespaces must be separate")

	got, err := vc.GetCanaryVersion(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got, "missing key reads as version 0")

	now := time.Now().UnixNano()
	require.NoError(t, vc.SetCanaryVersion(ctx, orgID, now))
	raw, err := rdb.Get(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", now), raw, "value format: decimal int64 nanos")

	got, err = vc.GetCanaryVersion(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, now, got)

	ttl, err := rdb.TTL(ctx, key).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, 6*24*time.Hour)
	assert.LessOrEqual(t, ttl, CanaryVersionTTL)

	require.NoError(t, rdb.Del(ctx, key).Err())
}

// TestCanaryRolloutEvidence_Integration: the D3 auto-Recommendation hook
// measures the actual split and per-arm failures from request_logs'
// routing_decision payload and computes the advice.
func TestCanaryRolloutEvidence_Integration(t *testing.T) {
	fx := newCanaryFixture(t)
	ctx := context.Background()

	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.orgA, "evidence", "glm-4.5", "glm-5.3", 50, "")
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.orgA, r.ID, 1)
	require.NoError(t, err)
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.orgA, r.ID, true)
	require.NoError(t, err)

	insert := func(arm, model string, status int) {
		_, err := fx.pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, routing_decision, endpoint, home_region)
			VALUES ($1::uuid, 'glm-4.5', $2, $3, 5, $4, 'chat.completions', 'eu')`,
			fx.orgA, model, status,
			fmt.Sprintf(`{"source":"tier_router","to":%q,"arm":%q,"rollout_id":%q,"canary_percent":50}`, model, arm, r.ID))
		require.NoError(t, err)
	}
	insert("canary", "glm-5.3", 200)
	insert("canary", "glm-5.3", 500)
	insert("canary", "glm-5.3", 500)
	insert("base", "glm-4.5", 200)
	insert("base", "glm-4.5", 200)
	insert("base", "glm-4.5", 500)

	ev, err := fx.store.CanaryRolloutEvidence(ctx, fx.orgA, r.ID, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, r.ID, ev.RolloutID)
	assert.Equal(t, int64(3), ev.CanaryTotal)
	assert.Equal(t, int64(2), ev.CanaryErrors)
	assert.Equal(t, int64(3), ev.BaseTotal)
	assert.Equal(t, int64(1), ev.BaseErrors)
	assert.Equal(t, "rollback-recommended", ev.Recommendation, "canary 67% errors vs base 33% must recommend rollback (evidence only)")

	// A foreign org cannot read the rollout's evidence.
	_, err = fx.store.CanaryRolloutEvidence(ctx, fx.orgB, r.ID, 24*time.Hour)
	require.True(t, IsNotFound(err))
}
