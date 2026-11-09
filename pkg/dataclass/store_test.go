package dataclass

import (
	"context"
	"testing"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// newTestStore boots the disposable Postgres container with the FULL
// production migration set (through 0025_dataclass_taxonomies — the
// table exists only through migrations, there is no EnsureSchema path).
func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(testdb.Postgres(t))
}

// testOrg inserts a fresh organization and returns its uuid (the row's
// org scope must reference the tenant dimension the rest of the schema
// uses; the store itself never checks FK, RLS is the boundary).
func testOrg(t *testing.T, slug string) string {
	t.Helper()
	pool := testdb.Postgres(t)
	var id string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug) VALUES ('dc-`+slug+`', 'dc-`+slug+`') RETURNING id::text`).Scan(&id))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM dataclass_taxonomies WHERE org_id::text = $1`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, id)
	})
	return id
}

func sampleTaxonomy() Taxonomy {
	return Taxonomy{Labels: []Label{
		{Key: "billing", Synonyms: map[string][]string{
			LocaleRU: {"оплата", "счёт"},
		}},
		{Key: "billing.invoice", Parent: "billing"},
		{Key: "support"},
	}}
}

func TestStorePutGetRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := testOrg(t, "roundtrip")

	stored, changed, err := s.PutTaxonomy(ctx, org, sampleTaxonomy(), "root")
	require.NoError(t, err)
	require.True(t, changed, "first write is a change")
	require.Equal(t, int64(1), stored.Version, "first write starts the version at 1")
	require.Equal(t, org, stored.OrgID)

	got, found, err := s.GetTaxonomy(ctx, org)
	require.NoError(t, err)
	require.True(t, found)
	want := sampleTaxonomy()
	want.OrgID = org
	require.True(t, want.Equal(got), "roundtrip preserves the label set")
	require.Equal(t, int64(1), got.Version, "an unchanged read keeps the version")

	// Canonical form comes back (sorted keys, non-nil maps).
	require.Equal(t, got.Canonical().Labels, got.Labels, "stored form is canonical")
}

func TestStorePutIdempotentVersionBumpsOnlyOnChange(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := testOrg(t, "idempotent")

	// Identical re-write (same labels, differently ordered map/slice and
	// source order — canonical compare, not byte compare).
	_, changed, err := s.PutTaxonomy(ctx, org, sampleTaxonomy(), "root")
	require.NoError(t, err)
	require.True(t, changed)

	shuffled := Taxonomy{Labels: []Label{
		{Key: "support"},
		{Key: "billing.invoice", Parent: "billing"},
		{Key: "billing", Synonyms: map[string][]string{LocaleEN: {}, LocaleRU: {"счёт", "оплата"}}},
	}}
	stored, changed, err := s.PutTaxonomy(ctx, org, shuffled, "root")
	require.NoError(t, err)
	require.False(t, changed, "a canonically identical set is a no-op")
	require.Equal(t, int64(1), stored.Version, "no-op keeps the version")

	// Real change: add one label — version bumps by exactly one.
	grown := sampleTaxonomy()
	grown.Labels = append(grown.Labels, Label{Key: "sales"})
	stored, changed, err = s.PutTaxonomy(ctx, org, grown, "root")
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, int64(2), stored.Version, "one real change bumps the version by one")

	// Actor and bookkeeping ride along on change, untouched on no-op.
	stored, changed, err = s.PutTaxonomy(ctx, org, grown, "someone-else")
	require.NoError(t, err)
	require.False(t, changed)
}

func TestStoreGetMissingOrgIsEmptyNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := testOrg(t, "getmissing")

	got, found, err := s.GetTaxonomy(ctx, org)
	require.NoError(t, err)
	require.False(t, found, "a never-written org reports not-found")
	require.Empty(t, got.Labels, "the not-found taxonomy is empty (a valid state per W02-C01)")
	require.Equal(t, int64(0), got.Version)

	// Storing an explicitly EMPTY taxonomy is valid and distinguishable
	// from never-written.
	stored, changed, err := s.PutTaxonomy(ctx, org, Taxonomy{Labels: []Label{}}, "root")
	require.NoError(t, err)
	require.True(t, changed, "writing an empty list over nothing is a change")
	require.Empty(t, stored.Labels)
	require.Equal(t, int64(1), stored.Version)

	got, found, err = s.GetTaxonomy(ctx, org)
	require.NoError(t, err)
	require.True(t, found, "explicitly empty is found")
	require.Empty(t, got.Labels)
}

func TestStoreRefusesBadOrgIDsBeforeAnyDBCall(t *testing.T) {
	// A nil DB proves the refusals happen before any database access.
	s := NewStore(nil)
	ctx := context.Background()

	_, _, err := s.GetTaxonomy(ctx, "")
	require.ErrorIs(t, err, ErrEmptyOrgID)

	_, _, err = s.PutTaxonomy(ctx, "org-1", sampleTaxonomy(), "root")
	require.ErrorIs(t, err, ErrInvalidOrgID, "a non-uuid org scope is refused before the GUC cast can confuse")

	_, _, err = s.GetTaxonomy(ctx, "not-a-uuid")
	require.ErrorIs(t, err, ErrInvalidOrgID)

	// A syntactically valid but nonexistent org is not an error on GET:
	// the store reports the empty not-found taxonomy (RLS keeps it that
	// way for foreign orgs too — see the RLS test).
	missing := "11111111-1111-1111-1111-111111111111"
	got, found, err := NewStore(testdb.Postgres(t)).GetTaxonomy(ctx, missing)
	require.NoError(t, err)
	require.False(t, found)
	require.Empty(t, got.Labels)
}

func TestStorePutValidatesBeforeWriting(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org := testOrg(t, "validate")

	bad := sampleTaxonomy()
	bad.Labels = append(bad.Labels, Label{Key: "cycle", Parent: "cycle"}) // self-parent
	_, _, err := s.PutTaxonomy(ctx, org, bad, "root")
	require.Error(t, err, "invalid taxonomy never reaches the DB")
	var verr *ValidationError
	require.ErrorAs(t, err, &verr)

	_, found, err := s.GetTaxonomy(ctx, org)
	require.NoError(t, err)
	require.False(t, found, "the refused write left no row behind")
}

func TestStoreOrgsAreIsolated(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	orgA := testOrg(t, "iso-a")
	orgB := testOrg(t, "iso-b")

	_, _, err := s.PutTaxonomy(ctx, orgA, sampleTaxonomy(), "root")
	require.NoError(t, err)
	taxB := Taxonomy{Labels: []Label{{Key: "private-b"}}}
	_, _, err = s.PutTaxonomy(ctx, orgB, taxB, "root")
	require.NoError(t, err)

	gotA, found, err := s.GetTaxonomy(ctx, orgA)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, gotA.Labels, 3, "orgA sees exactly its own labels")

	gotB, found, err := s.GetTaxonomy(ctx, orgB)
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, gotB.Labels, 1, "orgB sees exactly its own labels")
}

// TestStore_RLS_OrgIsolation_Integration pins the tenant boundary at the
// POLICY level (0025's org_isolation): under the
// application posture (SET ROLE yabanin_app, NOBYPASSRLS) a foreign org's
// row is invisible and a cross-tenant write is rejected; an unbound
// session sees nothing at all (fail closed). The store path keeps working
// because every operation pins app.current_org transaction-locally.
func TestStore_RLS_OrgIsolation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgA := testOrg(t, "rls-a")
	orgB := testOrg(t, "rls-b")

	super := NewStore(pool)
	_, _, err := super.PutTaxonomy(ctx, orgA, sampleTaxonomy(), "root")
	require.NoError(t, err, "store (tx-pinned GUC) must write under the RLS policy")

	appStore := NewStore(testdb.PostgresApp(t, "test"))

	t.Run("app role: store path stays org-scoped", func(t *testing.T) {
		got, found, err := appStore.GetTaxonomy(ctx, orgA)
		require.NoError(t, err)
		require.True(t, found)
		want := sampleTaxonomy()
		want.OrgID = orgA
		require.True(t, want.Equal(got), "the pinned-GUC store path reads its own org")

		_, found, err = appStore.GetTaxonomy(ctx, orgB)
		require.NoError(t, err)
		require.False(t, found, "a foreign never-written org stays not-found (not an error)")
	})

	t.Run("app role: raw session bound to orgA sees only orgA", func(t *testing.T) {
		conn := rlsAppRoleConn(t, ctx, pool)
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgA)
		require.NoError(t, err)
		var seen int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM dataclass_taxonomies WHERE org_id = $1::uuid`, orgA).Scan(&seen))
		require.Equal(t, 1, seen, "the bound org's row is visible")
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM dataclass_taxonomies WHERE org_id = $1::uuid`, orgB).Scan(&seen))
		require.Zero(t, seen, "a bound session must not see the foreign org's row")

		// Cross-org INSERT violates the WITH CHECK arm.
		_, err = conn.Exec(ctx, `
			INSERT INTO dataclass_taxonomies (org_id, labels) VALUES ($1::uuid, '[]'::jsonb)`, orgB)
		require.Error(t, err, "cross-org insert must be rejected by the org_isolation policy")

		// Cross-org UPDATE is rejected too (USING arm hides the row).
		tag, err := conn.Exec(ctx,
			`UPDATE dataclass_taxonomies SET labels = '[]'::jsonb WHERE org_id = $1::uuid`, orgB)
		require.NoError(t, err)
		require.Zero(t, tag.RowsAffected(), "a hidden row cannot be updated")
	})

	t.Run("app role: unbound session sees nothing (fail closed)", func(t *testing.T) {
		conn := rlsAppRoleConn(t, ctx, pool)
		var seen int
		require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM dataclass_taxonomies`).Scan(&seen))
		require.Zero(t, seen, "an unbound session must see no taxonomy rows at all")
	})
}

// rlsAppRoleConn downgrades one pooled connection to the application role
// (the production posture) and returns it with a cleanup that resets the
// session. The app.current_org GUC stays UNBOUND — callers bind their own
// (the pkg/toolpolicy rls_int_test.go parity).
func rlsAppRoleConn(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *pgxpool.Conn {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "RESET ROLE")
		_, _ = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	})
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	return conn
}
