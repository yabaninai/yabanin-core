package adminstore

// (ListActiveOrgCredentials / ResolveKeyEntry / QuarantineOrgCredential)
// against the disposable, fully migrated Postgres stand: pool listing and
// pinned resolution, version-scoped quarantine semantics (expiry, rotation
// return), frozen-contract preservation, and the org_credential_pool_state
// RLS posture (migration 0003).

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPoolEndpoint creates three enabled credentials for one endpoint of
// org A (deterministic created_at spacing: c1 oldest), one disabled, and
// one credential of another endpoint. Returns them in creation order.
func seedPoolEndpoint(t *testing.T, fx orgCredFixture, ctx context.Context) []string {
	t.Helper()
	ids := make([]string, 3)
	for i, name := range []string{"pool-k1", "pool-k2", "pool-k3"} {
		c, err := fx.store.Create(ctx, fx.orgA, name, "openai-compat", "https://pool.test/v1",
			"sk-pool-integration-key-000"+string(rune('1'+i)))
		require.NoError(t, err)
		ids[i] = c.ID
	}
	_, err := fx.store.Create(ctx, fx.orgA, "pool-disabled", "openai-compat", "https://pool.test/v1", "sk-pool-integration-key-OFF")
	require.NoError(t, err)
	_, err = fx.store.Update(ctx, fx.orgA, mustCredentialID(ctx, t, fx, "pool-disabled"), OrgCredential{
		Name: "pool-disabled", Provider: "openai-compat", BaseURL: "https://pool.test/v1", Enabled: false,
	}, "")
	require.NoError(t, err)
	_, err = fx.store.Create(ctx, fx.orgA, "pool-root", "openai-compat", "https://root.test", "sk-pool-integration-key-ROOT")
	require.NoError(t, err)
	return ids
}

func mustCredentialID(ctx context.Context, t *testing.T, fx orgCredFixture, name string) string {
	t.Helper()
	list, err := fx.store.List(ctx, fx.orgA)
	require.NoError(t, err)
	for _, c := range list {
		if c.Name == name {
			return c.ID
		}
	}
	t.Fatalf("credential %q not found", name)
	return ""
}

// TestOrgCredentialPool_ListAndPinnedResolve_Integration: the pool read
// returns exactly the enabled credentials of the endpoint in deterministic
// order, the pinned resolve decrypts only the requested credential, and
// the frozen ResolveKey stays newest-first (byte-for-bit contract).
func TestOrgCredentialPool_ListAndPinnedResolve_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()
	ids := seedPoolEndpoint(t, fx, ctx)

	entries, err := fx.store.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entries, 3, "enabled endpoint credentials only: disabled and other-endpoint rows stay out")
	for i, id := range ids {
		assert.Equal(t, id, entries[i].ID, "deterministic created_at ASC order (stable round-robin input)")
		assert.True(t, entries[i].Enabled)
		assert.Equal(t, "000"+string(rune('1'+i)), entries[i].KeyLast4, "display mask only")
		assert.True(t, entries[i].QuarantinedUntil.IsZero())
	}

	// /v1 normalization parity with the frozen ResolveKey (W-VER): a
	// credential registered at the host root serves a /v1-suffixed lookup.
	rootEntries, err := fx.store.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://root.test/v1")
	require.NoError(t, err)
	require.Len(t, rootEntries, 1)
	assert.Equal(t, "pool-root", rootEntries[0].Name)

	// Pinned resolve: the exact pinned credential's plaintext, per call.
	plain, ok, err := fx.store.ResolveKeyEntry(ctx, fx.orgA, "openai-compat", "https://pool.test/v1", ids[0])
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "sk-pool-integration-key-0001", plain)

	// Wrong org: invisible (routing miss, not an error).
	_, ok, err = fx.store.ResolveKeyEntry(ctx, fx.orgB, "openai-compat", "https://pool.test/v1", ids[0])
	require.NoError(t, err)
	assert.False(t, ok, "a foreign org must never resolve another org's credential")

	// Frozen contract: ResolveKey keeps its newest-first LIMIT 1 semantics.
	newest, ok, err := fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "sk-pool-integration-key-0003", newest)
}

// TestOrgCredentialPool_QuarantineRotationExpiry_Integration: quarantine
// removes a credential from the pool until the deadline; an expired row
// returns it; a rotation (Update + newPlaintextKey, key_version++) lifts a
// STILL-ACTIVE quarantine implicitly (version scoping, D-3) and serves the
// rotated key. The frozen ResolveKey ignores quarantine entirely.
func TestOrgCredentialPool_QuarantineRotationExpiry_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()
	ids := seedPoolEndpoint(t, fx, ctx)
	k1, k2, k3 := ids[0], ids[1], ids[2]

	// Quarantine k1 until tomorrow: the listing still HOLDS the row (with
	tomorrow := time.Now().UTC().Add(18 * time.Hour).Truncate(time.Second)
	require.NoError(t, fx.store.QuarantineOrgCredential(ctx, fx.orgA, k1, tomorrow))

	entries, err := fx.store.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entries, 3, "a quarantined credential stays HELD with its deadline; eligibility is the caller's")
	assert.Equal(t, k1, entries[0].ID, "store order stays created_at ASC: the quarantined row keeps its slot")
	assert.Equal(t, k2, entries[1].ID)
	assert.Equal(t, k3, entries[2].ID)
	assert.True(t, entries[1].QuarantinedUntil.IsZero())
	assert.True(t, entries[0].QuarantinedUntil.Equal(tomorrow), "the deadline rides the entry verbatim")

	_, ok, err := fx.store.ResolveKeyEntry(ctx, fx.orgA, "openai-compat", "https://pool.test/v1", k1)
	require.NoError(t, err)
	assert.False(t, ok, "a quarantined credential must not resolve for new attempts")

	// The row is version-scoped and re-quarantine refreshes the deadline.
	require.NoError(t, fx.store.QuarantineOrgCredential(ctx, fx.orgA, k1, tomorrow.Add(time.Hour)))

	// Rotation lifts the active quarantine: key_version++ makes the stored
	// row stale, and the NEW key serves.
	rotated, err := fx.store.Update(ctx, fx.orgA, k1, OrgCredential{
		Name: "pool-k1", Provider: "openai-compat", BaseURL: "https://pool.test/v1", Enabled: true,
	}, "sk-pool-integration-key-ROTATED")
	require.NoError(t, err)
	assert.Equal(t, 2, rotated.KeyVersion)

	entries, err = fx.store.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, e := range entries {
		assert.True(t, e.QuarantinedUntil.IsZero(), "after rotation no stored quarantine matches the live key_version")
	}
	plain, ok, err := fx.store.ResolveKeyEntry(ctx, fx.orgA, "openai-compat", "https://pool.test/v1", k1)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "sk-pool-integration-key-ROTATED", plain)

	// Expired quarantine (yesterday's row): the credential stays held AND
	// reads as eligible through its past deadline.
	yesterday := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	require.NoError(t, fx.store.QuarantineOrgCredential(ctx, fx.orgA, k2, yesterday))
	entries, err = fx.store.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	assert.Len(t, entries, 3, "an expired quarantine must not hold the credential out of rotation")
	for _, e := range entries {
		if e.ID == k2 {
			assert.True(t, e.QuarantinedUntil.Before(time.Now().UTC()), "the expired deadline stays visible for diagnosis")
		}
	}

	// Frozen contract stays quarantine-blind: ResolveKey answers the newest
	// ENABLED credential (here: the rotated k1) regardless of pool state.
	// Quarantine that same newest credential and the frozen path must STILL
	before, ok, err := fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "sk-pool-integration-key-ROTATED", before)
	require.NoError(t, fx.store.QuarantineOrgCredential(ctx, fx.orgA, k1, tomorrow))
	after, ok, err := fx.store.ResolveKey(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, before, after, "the frozen ResolveKey must keep its exact pre-R107 semantics")

	// Not-found / validation edges.
	err = fx.store.QuarantineOrgCredential(ctx, fx.orgA, "00000000-0000-0000-0000-000000000000", tomorrow)
	assert.True(t, IsNotFound(err), "an unknown credential id is ErrNotFound")
	err = fx.store.QuarantineOrgCredential(ctx, fx.orgB, k1, tomorrow)
	assert.True(t, IsNotFound(err), "a foreign org's credential is invisible: ErrNotFound, never a quarantine")
	err = fx.store.QuarantineOrgCredential(ctx, fx.orgA, k1, time.Time{})
	assert.Error(t, err, "a zero deadline is rejected")
}

// TestOrgCredentialPool_StateRowLifecycle_Integration: the persisted row is
// bookkeeping only (id, org, version, deadline — no key material), refreshed
// on re-quarantine and removed with the credential (cascade).
func TestOrgCredentialPool_StateRowLifecycle_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()
	ids := seedPoolEndpoint(t, fx, ctx)

	until := time.Now().UTC().Add(6 * time.Hour).Truncate(time.Second)
	require.NoError(t, fx.store.QuarantineOrgCredential(ctx, fx.orgA, ids[0], until))

	var version int
	var storedUntil time.Time
	var ctCount int
	err := fx.pool.QueryRow(ctx,
		`SELECT key_version, quarantined_until, 0 FROM org_credential_pool_state WHERE credential_id = $1::uuid`, ids[0]).
		Scan(&version, &storedUntil, &ctCount)
	require.NoError(t, err)
	assert.Equal(t, 1, version)
	assert.True(t, storedUntil.Equal(until), "deadline persisted verbatim (got %s want %s)", storedUntil, until)
	assert.Equal(t, 0, ctCount, "the state table carries no key-material column at all")

	// Re-quarantine after a rotation: the row follows the new version.
	_, err = fx.store.Update(ctx, fx.orgA, ids[0], OrgCredential{
		Name: "pool-k1", Provider: "openai-compat", BaseURL: "https://pool.test/v1", Enabled: true,
	}, "sk-pool-integration-key-ROTATED2")
	require.NoError(t, err)
	later := until.Add(2 * time.Hour)
	require.NoError(t, fx.store.QuarantineOrgCredential(ctx, fx.orgA, ids[0], later))
	err = fx.pool.QueryRow(ctx,
		`SELECT key_version, quarantined_until FROM org_credential_pool_state WHERE credential_id = $1::uuid`, ids[0]).
		Scan(&version, &storedUntil)
	require.NoError(t, err)
	assert.Equal(t, 2, version, "the row re-pins the credential's current key_version")
	assert.True(t, storedUntil.Equal(later))

	// Deleting the credential cascades the state row away.
	require.NoError(t, fx.store.Delete(ctx, fx.orgA, ids[0]))
	var n int
	require.NoError(t, fx.pool.QueryRow(ctx,
		`SELECT count(*) FROM org_credential_pool_state WHERE credential_id = $1::uuid`, ids[0]).Scan(&n))
	assert.Zero(t, n)
}

// TestOrgCredentialPool_RLS_Integration: under the application posture
// (SET ROLE yabanin_app + app.current_org GUC) the pool reads and the
// quarantine write are org-isolated: a foreign org's credentials never
// enter the pool, a cross-org quarantine is ErrNotFound, an unbound session
// sees nothing (fail closed), and a direct cross-org INSERT into the state
// table is rejected by the org_isolation WITH CHECK arm.
func TestOrgCredentialPool_RLS_Integration(t *testing.T) {
	fx := newOrgCredFixture(t)
	ctx := context.Background()

	idsA := seedPoolEndpoint(t, fx, ctx)
	_, err := fx.store.Create(ctx, fx.orgB, "pool-b", "openai-compat", "https://pool.test/v1", "sk-pool-integration-key-ORG-B")
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
	require.NoError(t, err)

	bindOrg := func(orgID string) {
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgID)
		require.NoError(t, err)
	}

	rlsAdapter := rlsConnAdapter{conn.Conn()}
	rls := newForTest(rlsAdapter, slog.New(slog.DiscardHandler), fx.enc)

	// Org A's pool: only org A's credentials — never org B's.
	bindOrg(fx.orgA)
	entries, err := rls.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, e := range entries {
		assert.Equal(t, fx.orgA, e.OrgID)
	}

	// Quarantine works under the app posture for the bound org...
	tomorrow := time.Now().UTC().Add(12 * time.Hour).Truncate(time.Second)
	require.NoError(t, rls.QuarantineOrgCredential(ctx, fx.orgA, idsA[0], tomorrow))
	entries, err = rls.ListActiveOrgCredentials(ctx, fx.orgA, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entries, 3, "R107-03: the quarantined row stays held under RLS, deadline visible")
	quarantinedSeen := false
	for _, e := range entries {
		if e.ID == idsA[0] {
			quarantinedSeen = e.QuarantinedUntil.Equal(tomorrow)
		}
	}
	assert.True(t, quarantinedSeen, "the quarantine deadline must ride the held row")

	// ...and a cross-org quarantine of org B's credential is ErrNotFound.
	bID := mustCredentialIDFor(ctx, t, fx, fx.orgB, "pool-b")
	err = rls.QuarantineOrgCredential(ctx, fx.orgA, bID, tomorrow)
	assert.True(t, IsNotFound(err), "org A must not quarantine org B's credential")

	// Raw SQL without the org GUC: nothing is visible, fail closed.
	bindOrg("")
	none, err := rlsAdapter.Query(ctx, `SELECT credential_id FROM org_credential_pool_state`)
	require.NoError(t, err)
	assert.False(t, none.Next(), "an unbound raw session must see no pool state rows")
	none.Close()

	// Direct cross-org INSERT violates the WITH CHECK arm.
	bindOrg(fx.orgA)
	_, err = rlsAdapter.Exec(ctx,
		`INSERT INTO org_credential_pool_state (credential_id, org_id, key_version, quarantined_until)
		 VALUES ($1::uuid, $2::uuid, 1, now() + interval '1 hour')`, bID, fx.orgB)
	require.Error(t, err, "a cross-org pool-state insert must be rejected by the org_isolation policy")

	// Org B's own pool: its credential is quarantinable only by itself.
	bindOrg(fx.orgB)
	entriesB, err := rls.ListActiveOrgCredentials(ctx, fx.orgB, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entriesB, 1)
	assert.Equal(t, bID, entriesB[0].ID)
	require.NoError(t, rls.QuarantineOrgCredential(ctx, fx.orgB, bID, tomorrow))
	entriesB, err = rls.ListActiveOrgCredentials(ctx, fx.orgB, "openai-compat", "https://pool.test/v1")
	require.NoError(t, err)
	require.Len(t, entriesB, 1, "the held row stays listed with its deadline (all-quarantined is the caller's verdict)")
	assert.True(t, entriesB[0].QuarantinedUntil.Equal(tomorrow))
}

func mustCredentialIDFor(ctx context.Context, t *testing.T, fx orgCredFixture, orgID, name string) string {
	t.Helper()
	list, err := fx.store.List(ctx, orgID)
	require.NoError(t, err)
	for _, c := range list {
		if c.Name == name {
			return c.ID
		}
	}
	t.Fatalf("credential %q of org %s not found", name, orgID)
	return ""
}
