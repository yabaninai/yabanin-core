package adminstore

// OP-0b integration tests against the disposable, fully migrated Postgres
// stand (testcontainers). Covers: policy CRUD round-trip (versions,
// activation, attachments), per-org name uniqueness, up/down migration
// cleanliness, org RLS isolation (a foreign org sees nothing — the
// 0002/0007 posture with the app.current_org GUC), and the version-key bump
// contract (store → bumper on every mutation; Redis round-trip against a
// real container, no miniredis in this repo).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const policyTestYAML = `apiVersion: ypp/v1
kind: Policy
name: test-policy
mode: enforce
steps:
  - id: scan
    detector: builtin/secrets
`

// policyFixture seeds two orgs and a policy store. Cleanup removes the
// orgs; policies cascade (FK policy).
type policyFixture struct {
	store *Store
	pool  *pgxpool.Pool
	orgA  string
	orgB  string
}

func newPolicyFixture(t *testing.T) policyFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("pol-a-%d", suffix), fmt.Sprintf("pol-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("pol-b-%d", suffix), fmt.Sprintf("pol-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})
	return policyFixture{store: store, pool: pool, orgA: orgA.ID, orgB: orgB.ID}
}

// TestPolicy_CRUD_Integration: create appends version 1 (draft), new
// versions append monotonically, activation flips labels and
// current_version, attachments replace atomically, enabled flips, delete
// cascades.
func TestPolicy_CRUD_Integration(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()

	p, v1, err := fx.store.CreatePolicy(ctx, fx.orgA, "pii-guard", policyTestYAML, "", "admin@x.test")
	require.NoError(t, err)
	require.NotEmpty(t, p.ID)
	assert.Equal(t, fx.orgA, p.OrgID)
	assert.False(t, p.Enabled, "a new pipeline starts detached")
	assert.Equal(t, 0, p.CurrentVersion, "no active version until activation")
	assert.Equal(t, 1, v1.Version)
	assert.Equal(t, PolicyLabelDraft, v1.Label)
	assert.YAMLEq(t, policyTestYAML, v1.YAML)
	assert.Equal(t, "admin@x.test", v1.CreatedBy)

	// Second version appends (max+1), stays draft.
	v2, err := fx.store.CreatePolicyVersion(ctx, fx.orgA, p.ID, policyTestYAML+"# v2\n", "abc1234", "admin@x.test")
	require.NoError(t, err)
	assert.Equal(t, 2, v2.Version)
	assert.Equal(t, PolicyLabelDraft, v2.Label)
	assert.Equal(t, "abc1234", v2.GitSHA)

	// Versions list: newest first.
	versions, err := fx.store.ListPolicyVersions(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, 2, versions[0].Version)

	// Activation: current_version moves, labels follow (active + demoted).
	p, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, p.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, p.CurrentVersion)
	v1After, err := fx.store.GetPolicyVersion(ctx, fx.orgA, p.ID, 1)
	require.NoError(t, err)
	assert.Equal(t, PolicyLabelDraft, v1After.Label, "the previously active label demotes to draft")
	v2After, err := fx.store.GetPolicyVersion(ctx, fx.orgA, p.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, PolicyLabelActive, v2After.Label)

	// Activating a missing version is ErrNotFound.
	_, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, p.ID, 99)
	require.True(t, IsNotFound(err))

	// Attachments: replace-all semantics; key_label "" stores as NULL and
	// reads back as "".
	atts, err := fx.store.SetPolicyAttachments(ctx, fx.orgA, p.ID, []PolicyAttachment{
		{KeyLabel: "prod", ModelPattern: "gpt*", Endpoint: "chat", Priority: 10},
		{ModelPattern: "*", Endpoint: "mcp.invoke", Priority: 20},
	})
	require.NoError(t, err)
	require.Len(t, atts, 2)
	assert.Empty(t, atts[1].KeyLabel)
	assert.Equal(t, 10, atts[0].Priority)

	atts, err = fx.store.ListPolicyAttachments(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	require.Len(t, atts, 2, "list reflects the replace-all set")

	// Replace with one row: the old set is gone.
	_, err = fx.store.SetPolicyAttachments(ctx, fx.orgA, p.ID, []PolicyAttachment{
		{KeyLabel: "prod", ModelPattern: "claude*", Endpoint: "messages", Priority: 5},
	})
	require.NoError(t, err)
	atts, err = fx.store.ListPolicyAttachments(ctx, fx.orgA, p.ID)
	require.NoError(t, err)
	require.Len(t, atts, 1)
	assert.Equal(t, "claude*", atts[0].ModelPattern)

	// Enabled flag flips.
	p, err = fx.store.UpdatePolicy(ctx, fx.orgA, p.ID, true)
	require.NoError(t, err)
	assert.True(t, p.Enabled)

	// Duplicate name inside the org is rejected; a different name is fine.
	_, _, err = fx.store.CreatePolicy(ctx, fx.orgA, "pii-guard", policyTestYAML, "", "")
	require.ErrorContains(t, err, "already exists")
	_, _, err = fx.store.CreatePolicy(ctx, fx.orgA, "other-guard", policyTestYAML, "", "")
	require.NoError(t, err)

	// Delete cascades: versions and attachments are gone with the pipeline.
	require.NoError(t, fx.store.DeletePolicy(ctx, fx.orgA, p.ID))
	_, err = fx.store.GetPolicy(ctx, fx.orgA, p.ID)
	require.True(t, IsNotFound(err))
	_, err = fx.store.GetPolicyVersion(ctx, fx.orgA, p.ID, 2)
	require.True(t, IsNotFound(err))
	_, err = fx.store.ListPolicyAttachments(ctx, fx.orgA, p.ID)
	require.True(t, IsNotFound(err), "a deleted pipeline's attachments list is ErrNotFound")

	// Delete of a missing pipeline is ErrNotFound.
	err = fx.store.DeletePolicy(ctx, fx.orgA, p.ID)
	require.True(t, IsNotFound(err))
}

// TestPolicy_RLS_OrgIsolation_Integration: under the application posture
// (SET ROLE yabanin_app + app.current_org GUC) a foreign org's policies are
// invisible and unwritable across ALL THREE tables, and an unbound session
// sees nothing at all (fail closed).
func TestPolicy_RLS_OrgIsolation_Integration(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()

	polA, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "rls-a", policyTestYAML, "", "")
	require.NoError(t, err)
	polB, _, err := fx.store.CreatePolicy(ctx, fx.orgB, "rls-b", policyTestYAML, "", "")
	require.NoError(t, err)
	_, err = fx.store.SetPolicyAttachments(ctx, fx.orgB, polB.ID, []PolicyAttachment{
		{ModelPattern: "*", Endpoint: "chat", Priority: 1},
	})
	require.NoError(t, err)

	conn, err := fx.pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()

	// Downgrade to the NOBYPASSRLS application role and pin the production
	// row_security posture (the shared stand's migration session leaks
	// row_security=off; see orgcredentials_int_test.go).
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	bindOrg := func(orgID string) {
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgID)
		require.NoError(t, err)
	}

	rlsAdapter := rlsConnAdapter{conn.Conn()}
	rls := newForTest(rlsAdapter, slog.New(slog.DiscardHandler), nil)

	// Org A sees only its own pipeline.
	bindOrg(fx.orgA)
	seen, err := rls.ListPolicies(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.Equal(t, polA.ID, seen[0].ID)

	// Cross-org reads of versions and attachments are ErrNotFound — a
	// foreign policy id is indistinguishable from a missing one under the
	// pinned GUC (the getPolicyTx probe precedes every list).
	bVersions, err := rls.ListPolicyVersions(ctx, fx.orgA, polB.ID)
	require.True(t, IsNotFound(err), "a foreign org's versions must be invisible")
	assert.Empty(t, bVersions)
	bAtts, err := rls.ListPolicyAttachments(ctx, fx.orgA, polB.ID)
	require.True(t, IsNotFound(err), "a foreign org's attachments must be invisible")
	assert.Empty(t, bAtts)

	// Cross-org writes through the store are ErrNotFound: the WHERE clause
	// pins (id, org) and the org_isolation policy denies the foreign row.
	_, err = rls.UpdatePolicy(ctx, fx.orgA, polB.ID, true)
	require.True(t, IsNotFound(err), "cross-org update must not touch the foreign row")
	_, err = rls.CreatePolicyVersion(ctx, fx.orgA, polB.ID, policyTestYAML, "", "")
	require.True(t, IsNotFound(err), "cross-org version append must not touch the foreign row")
	_, err = rls.SetActivePolicyVersion(ctx, fx.orgA, polB.ID, 1)
	require.True(t, IsNotFound(err), "cross-org activation must not touch the foreign row")
	_, err = rls.SetPolicyAttachments(ctx, fx.orgA, polB.ID, []PolicyAttachment{{ModelPattern: "*", Endpoint: "chat"}})
	require.True(t, IsNotFound(err), "cross-org attachment write must not touch the foreign row")
	err = rls.DeletePolicy(ctx, fx.orgA, polB.ID)
	require.True(t, IsNotFound(err), "cross-org delete must not touch the foreign row")

	// Raw SQL WITHOUT the org GUC (only role downgrade): nothing is visible
	// and nothing resolves — the FORCE policy is the isolation boundary.
	rawForeign, err := rlsAdapter.Query(ctx,
		`SELECT id FROM policy_pipelines WHERE org_id = $1::uuid`, fx.orgB)
	require.NoError(t, err)
	assert.False(t, rawForeign.Next(), "an unbound raw session must not see any org's rows")
	rawForeign.Close()

	// Direct cross-org INSERT violates the WITH CHECK arm on every table.
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO policy_pipelines (org_id, name) VALUES ($1::uuid, 'evil')`, fx.orgB)
	require.Error(t, err, "cross-org pipeline insert must be rejected by the org_isolation policy")
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO policy_versions (policy_id, org_id, version, yaml) VALUES (gen_random_uuid(), $1::uuid, 1, 'x')`, fx.orgB)
	require.Error(t, err, "cross-org version insert must be rejected by the org_isolation policy")
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO policy_attachments (policy_id, org_id, model_pattern, endpoint) VALUES (gen_random_uuid(), $1::uuid, '*', 'chat')`, fx.orgB)
	require.Error(t, err, "cross-org attachment insert must be rejected by the org_isolation policy")

	// Unbound raw session (empty GUC): nothing is visible — fail closed.
	bindOrg("")
	none, err := rlsAdapter.Query(ctx,
		`SELECT id FROM policy_pipelines WHERE org_id = $1::uuid`, fx.orgA)
	require.NoError(t, err)
	assert.False(t, none.Next(), "an unbound session must see no policies at all")
	none.Close()
}

// recordingBumper counts bump calls per org (the store-side half of the
// version-key contract).
type recordingBumper struct {
	mu     sync.Mutex
	called map[string]int
	fail   bool
}

func newRecordingBumper() *recordingBumper {
	return &recordingBumper{called: map[string]int{}}
}

func (b *recordingBumper) SetPolicyVersion(_ context.Context, orgID string, _ int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return fmt.Errorf("redis down (simulated)")
	}
	b.called[orgID]++
	return nil
}

func (b *recordingBumper) count(orgID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.called[orgID]
}

// TestPolicy_VersionBump_OnEveryMutation: the store bumps the org's version
// key after EVERY successful mutation, and never on failed (foreign-org)
// attempts. A failing bumper never fails the mutation (TTL-bounded
// staleness is the documented degradation).
func TestPolicy_VersionBump_OnEveryMutation(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()

	bumper := newRecordingBumper()
	fx.store.SetPolicyVersionBumper(bumper)

	p, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "bump-policy", policyTestYAML, "", "")
	require.NoError(t, err)
	require.Equal(t, 1, bumper.count(fx.orgA), "create bumps")

	_, err = fx.store.CreatePolicyVersion(ctx, fx.orgA, p.ID, policyTestYAML, "", "")
	require.NoError(t, err)
	require.Equal(t, 2, bumper.count(fx.orgA), "new version bumps")

	_, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, p.ID, 2)
	require.NoError(t, err)
	require.Equal(t, 3, bumper.count(fx.orgA), "activation bumps")

	_, err = fx.store.SetPolicyAttachments(ctx, fx.orgA, p.ID, []PolicyAttachment{{ModelPattern: "*", Endpoint: "chat"}})
	require.NoError(t, err)
	require.Equal(t, 4, bumper.count(fx.orgA), "attachments bump")

	_, err = fx.store.UpdatePolicy(ctx, fx.orgA, p.ID, true)
	require.NoError(t, err)
	require.Equal(t, 5, bumper.count(fx.orgA), "enabled flip bumps")

	// A foreign-org mutation fails and must NOT bump either org.
	_, err = fx.store.CreatePolicyVersion(ctx, fx.orgB, p.ID, policyTestYAML, "", "")
	require.True(t, IsNotFound(err))
	require.Equal(t, 0, bumper.count(fx.orgB), "a failed foreign-org mutation must not bump")
	require.Equal(t, 5, bumper.count(fx.orgA), "the failed foreign attempt leaves the org count untouched")

	// A failing bumper degrades to a warning, never fails the mutation.
	bumper.fail = true
	err = fx.store.DeletePolicy(ctx, fx.orgA, p.ID)
	require.NoError(t, err, "a failed version bump must not fail the committed mutation")
}

// TestPolicyVersionCache_Redis_Contract: the Redis half of the OP-8
// contract — exact key "policystore:ver:<orgID>", decimal int64 value
// (UnixNano), 7-day TTL refreshed by Set, missing key reads as 0.
func TestPolicyVersionCache_Redis_Contract(t *testing.T) {
	rdb := testdb.Redis(t)
	ctx := context.Background()
	vc := NewPolicyVersionCache(rdb, slog.New(slog.DiscardHandler))

	const orgID = "org-redis-contract"
	key := PolicyVersionKeyPrefix + orgID
	require.Equal(t, "policystore:ver:"+orgID, key, "the OP-8 contract pins the exact key format")

	// Missing key reads as version 0, not an error.
	got, err := vc.GetPolicyVersion(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got)

	// Set records a decimal int64 under the exact key with a ~7d TTL.
	now := time.Now().UnixNano()
	require.NoError(t, vc.SetPolicyVersion(ctx, orgID, now))
	raw, err := rdb.Get(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", now), raw, "value format: decimal int64 nanos")

	got, err = vc.GetPolicyVersion(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, now, got)

	ttl, err := rdb.TTL(ctx, key).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, 6*24*time.Hour, "TTL must be ~7 days, got %v", ttl)
	assert.LessOrEqual(t, ttl, PolicyVersionTTL)

	// A second Set refreshes the value (monotonic per org, no RMW race).
	next := now + 1
	require.NoError(t, vc.SetPolicyVersion(ctx, orgID, next))
	got, err = vc.GetPolicyVersion(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, next, got)

	require.NoError(t, rdb.Del(ctx, key).Err())
}

// preconditioned PUT is atomic and race-free against the real store. The
// token is the pipeline's current_version (COALESCE: NULL = 0); the row is
// locked FOR UPDATE inside the same transaction as the writes.
func TestPolicy_UpdatePolicyCAS_Integration(t *testing.T) {
	fx := newPolicyFixture(t)
	ctx := context.Background()

	p, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "cas-guard", policyTestYAML, "", "a@x.test")
	require.NoError(t, err)
	_, err = fx.store.CreatePolicyVersion(ctx, fx.orgA, p.ID, policyTestYAML+"# v2\n", "", "b@x.test")
	require.NoError(t, err)
	p, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, p.ID, 1)
	require.NoError(t, err)
	require.Equal(t, 1, p.CurrentVersion)

	strPtr := func(s string) *string { return &s }
	boolPtr := func(b bool) *bool { return &b }
	intPtr := func(i int) *int { return &i }

	t.Run("nil expectation keeps the unconditional semantics", func(t *testing.T) {
		got, _, err := fx.store.UpdatePolicyCAS(ctx, fx.orgA, p.ID, PolicyUpdate{Enabled: boolPtr(true)}, nil, "c@x.test")
		require.NoError(t, err)
		assert.True(t, got.Enabled)
	})

	t.Run("stale token applies nothing and reports the live row", func(t *testing.T) {
		// Move current_version underneath (operator B activates v2).
		_, err := fx.store.SetActivePolicyVersion(ctx, fx.orgA, p.ID, 2)
		require.NoError(t, err)

		before, err := fx.store.GetPolicy(ctx, fx.orgA, p.ID)
		require.NoError(t, err)
		versionsBefore, err := fx.store.ListPolicyVersions(ctx, fx.orgA, p.ID)
		require.NoError(t, err)

		// Operator A still holds version 1 and sends yaml+enabled+activate.
		got, _, err := fx.store.UpdatePolicyCAS(ctx, fx.orgA, p.ID, PolicyUpdate{
			YAML: strPtr(policyTestYAML + "# A's draft\n"), Enabled: boolPtr(false), ActiveVersion: intPtr(1),
		}, intPtr(1), "a@x.test")
		require.ErrorIs(t, err, ErrPreconditionFailed)
		assert.Equal(t, 2, got.CurrentVersion, "the conflict carries the live row")

		after, err := fx.store.GetPolicy(ctx, fx.orgA, p.ID)
		require.NoError(t, err)
		assert.Equal(t, before, after, "a stale PUT must not touch the pipeline row")
		versionsAfter, err := fx.store.ListPolicyVersions(ctx, fx.orgA, p.ID)
		require.NoError(t, err)
		assert.Len(t, versionsAfter, len(versionsBefore), "a stale PUT must not append a version")
	})

	t.Run("fresh token applies the whole body atomically", func(t *testing.T) {
		got, appended, err := fx.store.UpdatePolicyCAS(ctx, fx.orgA, p.ID, PolicyUpdate{
			YAML: strPtr(policyTestYAML + "# v3\n"), ActiveVersion: intPtr(3), Enabled: boolPtr(true),
		}, intPtr(2), "a@x.test")
		require.NoError(t, err)
		assert.Equal(t, 3, got.CurrentVersion)
		assert.True(t, got.Enabled)
		assert.Equal(t, 3, appended.Version, "the appended draft version rides the result")
		v3, err := fx.store.GetPolicyVersion(ctx, fx.orgA, p.ID, 3)
		require.NoError(t, err)
		assert.Equal(t, "a@x.test", v3.CreatedBy)
		assert.Equal(t, PolicyLabelActive, v3.Label, "active_version labels the appended version")
	})

	t.Run("version 0 is the never-activated token", func(t *testing.T) {
		fresh, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "cas-fresh", policyTestYAML, "", "")
		require.NoError(t, err)
		require.Equal(t, 0, fresh.CurrentVersion)
		_, _, err = fx.store.UpdatePolicyCAS(ctx, fx.orgA, fresh.ID, PolicyUpdate{Enabled: boolPtr(true)}, intPtr(0), "a@x.test")
		require.NoError(t, err, "token 0 matches a never-activated row")
		_, _, err = fx.store.UpdatePolicyCAS(ctx, fx.orgA, fresh.ID, PolicyUpdate{Enabled: boolPtr(false)}, intPtr(1), "a@x.test")
		require.ErrorIs(t, err, ErrPreconditionFailed, "0 vs a moved token must conflict, not silently pass")
	})

	t.Run("foreign org is the 404, never a token answer", func(t *testing.T) {
		_, _, err := fx.store.UpdatePolicyCAS(ctx, fx.orgB, p.ID, PolicyUpdate{Enabled: boolPtr(true)}, intPtr(2), "a@x.test")
		require.True(t, IsNotFound(err))
	})

	t.Run("concurrent writers serialize on the row lock", func(t *testing.T) {
		// Two writers both holding token 1: exactly one applies, the other
		// gets the precondition failure (the lock makes the check+write
		// indivisible — a plain read-then-write would let both through).
		// The racing mutation includes an ACTIVATION: appends alone do not
		// move the token by design (immutable, append-only rows).
		target, _, err := fx.store.CreatePolicy(ctx, fx.orgA, "cas-race", policyTestYAML, "", "")
		require.NoError(t, err)
		_, err = fx.store.CreatePolicyVersion(ctx, fx.orgA, target.ID, policyTestYAML+"# v2\n", "", "b@x.test")
		require.NoError(t, err)
		_, err = fx.store.SetActivePolicyVersion(ctx, fx.orgA, target.ID, 1)
		require.NoError(t, err)

		const writers = 4
		start := make(chan struct{})
		results := make(chan error, writers)
		for i := range writers {
			go func(i int) {
				<-start
				_, _, err := fx.store.UpdatePolicyCAS(ctx, fx.orgA, target.ID, PolicyUpdate{
					YAML:          strPtr(policyTestYAML + fmt.Sprintf("# writer %d\n", i)),
					ActiveVersion: intPtr(2),
				}, intPtr(1), fmt.Sprintf("w%d@x.test", i))
				results <- err
			}(i)
		}
		close(start)
		var okCount, conflictCount int
		for range writers {
			err := <-results
			switch {
			case err == nil:
				okCount++
			case errors.Is(err, ErrPreconditionFailed):
				conflictCount++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		assert.Equal(t, 1, okCount, "exactly one writer may apply")
		assert.Equal(t, writers-1, conflictCount, "every other writer must see the conflict")
	})
}
