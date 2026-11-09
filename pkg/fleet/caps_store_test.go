// Caps store battery (E03-P01 card W03-C03, batch B): the persistence
// acceptance arms against the REAL migration 0024 table (house-RLS
// org_isolation, TEXT-org NULLIF form) on a real stand, under the real
// yabanin_app role — mirroring the E06 inbox store battery shape:
//
//   - org-scoped write/read: a negotiated caps document round-trips
//     (capabilities AND unsupported survive), a new row is born enrolled,
//     a refresh moves only the caps document and its stamp;
//   - cross-org isolation: another org's scope sees nothing (Get
//     not-found, List empty), the policy refuses a cross-org write, an
//     unbound session sees nothing (fail-closed NULLIF shape);
//   - empty org: refused BEFORE any statement (refusing fake);
//   - revoked is terminal at the persistence layer: a caps refresh on a
//     revoked installation is refused, the document never moves;
//   - down.sql cleanly rolls back: the table, the policy and the RLS
//     posture drop together and the re-up leaves a working registry.
//
// Deterministic: fixed anchor timestamps, per-run org tokens so
// concurrent suites coexist, no sleeps. Docker-backed stands skip under
// -short like every disposable stand (testdb law).
package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// refusingFleetDB fails the test on ANY statement: the store's refusal
// arms must not touch the database (empty-org/invalid-coordinate checks
// happen BEFORE Begin — the reader law's refuse-before-SQL shape).
type refusingFleetDB struct {
	t *testing.T
}

func (d *refusingFleetDB) touch(method string) {
	d.t.Helper()
	d.t.Fatalf("refusingFleetDB: unexpected %s call — refusal must happen before any statement", method)
}

func (d *refusingFleetDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	d.touch("Exec")
	panic("unreachable: touch fails the test")
}
func (d *refusingFleetDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	d.touch("Query")
	panic("unreachable: touch fails the test")
}
func (d *refusingFleetDB) QueryRow(context.Context, string, ...any) pgx.Row {
	d.touch("QueryRow")
	panic("unreachable: touch fails the test")
}
func (d *refusingFleetDB) Begin(context.Context) (pgx.Tx, error) {
	d.touch("Begin")
	panic("unreachable: touch fails the test")
}

// fsCapsStoreFixture returns superuser and app-role pools over the full
// migration set (the app role is NOBYPASSRLS: RLS is genuinely enforced
// for everything it does).
func fsCapsStoreFixture(t *testing.T) (su, app *pgxpool.Pool) {
	t.Helper()
	return testdb.Postgres(t), testdb.PostgresApp(t, "test")
}

// fsTestCaps builds a well-formed negotiated document for the store arms.
func fsTestCaps(t *testing.T) NegotiatedCaps {
	t.Helper()
	core, err := NewCoreCaps(CapsFormatVersion, []string{"caps.health.heartbeat", "caps.inventory.upload"})
	require.NoError(t, err)
	got, err := NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.health.heartbeat", "vendor.extra.feature"},
	})
	require.NoError(t, err)
	return got
}

func TestCapsStore_RefusalsBeforeAnyStatement(t *testing.T) {
	store := NewCapsStore(&refusingFleetDB{t: t})
	ctx := context.Background()
	caps := fsTestCaps(t)

	// Empty org: refused before any statement, never "all rows".
	err := store.UpsertCaps(ctx, "", "deploy-1", caps, time.Unix(0, 0).UTC())
	require.ErrorIs(t, err, ErrFleetStoreOrgRequired)
	_, _, err = store.Get(ctx, "", "deploy-1")
	require.ErrorIs(t, err, ErrFleetStoreOrgRequired)
	_, err = store.List(ctx, "")
	require.ErrorIs(t, err, ErrFleetStoreOrgRequired)

	// Invalid coordinates: the identity sentinels, still before any
	// statement (structural law precedes I/O).
	err = store.UpsertCaps(ctx, " padded-org", "deploy-1", caps, time.Unix(0, 0).UTC())
	require.ErrorIs(t, err, ErrInvalidOrg)
	err = store.UpsertCaps(ctx, "org-a", "padded-deploy\x00", caps, time.Unix(0, 0).UTC())
	require.ErrorIs(t, err, ErrInvalidDeploymentID)
	_, _, err = store.Get(ctx, "org-a", "")
	require.ErrorIs(t, err, ErrInvalidDeploymentID)
	_, err = store.List(ctx, "org\nbad")
	require.ErrorIs(t, err, ErrInvalidOrg)

	// The store persists only negotiable documents: a caps version
	// outside the matrix is refused before any statement too.
	bad := caps
	bad.FormatVersion = "9"
	err = store.UpsertCaps(ctx, "org-a", "deploy-1", bad, time.Unix(0, 0).UTC())
	require.ErrorIs(t, err, ErrUnknownCapsVersion)
}

func TestCapsStore_OrgScopedWriteRead(t *testing.T) {
	su, app := fsCapsStoreFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	org := "fsorg" + time.Now().Format("150405.000000000")

	store := NewCapsStore(app)
	caps := fsTestCaps(t)
	require.NoError(t, store.UpsertCaps(ctx, org, "deploy-prod", caps, base))

	// The document round-trips exactly: capabilities AND the visible
	// unsupported remainder survive persistence (the drift seam reads
	// what was honestly negotiated).
	got, ok, err := store.Get(ctx, org, "deploy-prod")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, org, got.OrgID)
	assert.Equal(t, "deploy-prod", got.DeploymentID)
	assert.Equal(t, StateEnrolled, got.State, "a new row is born enrolled")
	assert.Equal(t, caps, got.Caps)
	assert.True(t, got.EnrolledAt.Equal(base))
	assert.True(t, got.CapsUpdatedAt.Equal(base))
	assert.Nil(t, got.LastHeartbeatAt)
	assert.Nil(t, got.RevokedAt)
	assert.Empty(t, got.RevocationReason)

	// A refresh moves ONLY the caps document and its stamp: identity,
	// state and enrollment stamp survive (deterministic injected clock).
	refreshed := fsTestCaps(t)
	refreshed.Capabilities = []string{"caps.inventory.upload"}
	later := base.Add(2 * time.Hour)
	require.NoError(t, store.UpsertCaps(ctx, org, "deploy-prod", refreshed, later))
	got, ok, err = store.Get(ctx, org, "deploy-prod")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, StateEnrolled, got.State)
	assert.Equal(t, refreshed, got.Caps)
	assert.True(t, got.EnrolledAt.Equal(base), "enrollment stamp is monotone")
	assert.True(t, got.CapsUpdatedAt.Equal(later))

	// The org list sees the installation; a second contour of the same
	// org is a separate row (one org, many contours — identity-model).
	require.NoError(t, store.UpsertCaps(ctx, org, "deploy-dr", fsTestCaps(t), later))
	list, err := store.List(ctx, org)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []string{"deploy-dr", "deploy-prod"}, []string{list[0].DeploymentID, list[1].DeploymentID},
		"deterministic deployment_id order")

	_ = su // superuser pool held for symmetry with the isolation battery
}

func TestCapsStore_CrossOrgIsolation(t *testing.T) {
	su, app := fsCapsStoreFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 8, 11, 0, 0, 0, time.UTC)
	token := time.Now().Format("150405.000000000")
	orgA, orgB := "isoa"+token, "isob"+token

	store := NewCapsStore(app)
	require.NoError(t, store.UpsertCaps(ctx, orgA, "deploy-prod", fsTestCaps(t), now))

	// Cross-org read: another org's scope sees NOTHING (Get not-found,
	// List empty) — predicate and policy agree.
	_, ok, err := store.Get(ctx, orgB, "deploy-prod")
	require.NoError(t, err)
	assert.False(t, ok, "an installation of another org must not resolve")
	list, err := store.List(ctx, orgB)
	require.NoError(t, err)
	assert.Empty(t, list)

	// Cross-org write refused by the policy itself: a session pinned to
	// org B inserting an org A row violates WITH CHECK (raw SQL — the
	// store API never produces this shape; the battery pins the POLICY).
	tx, err := app.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT set_config('app.current_org', $1, true)`, orgB)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO fleet_installations (org_id, deployment_id, state, caps, enrolled_at, caps_updated_at)
		  VALUES ($1, 'deploy-hoist', 'enrolled', '{}'::jsonb, now(), now())`, orgA)
	require.Error(t, err, "RLS WITH CHECK must refuse a cross-org write")
	_ = tx.Rollback(ctx)

	// Unbound session sees nothing: no GUC → NULLIF reads NULL → zero
	// rows, even for the superuser-granted app role (fail-closed shape).
	var n int
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM fleet_installations`).Scan(&n))
	assert.Zero(t, n, "an unbound session must see no installations at all")

	// The superuser side (bypass) still sees the row: the boundary is
	// the GUC, not blindness of the whole stand.
	require.NoError(t, su.QueryRow(ctx, `SELECT count(*) FROM fleet_installations WHERE org_id = $1`, orgA).Scan(&n))
	assert.Equal(t, 1, n)

	// Posture pins: the migration's RLS shape is live (ENABLE + FORCE +
	// exactly the org_isolation policy, the 0002:11/:13/:15 posture).
	var rowsec, forcesec bool
	require.NoError(t, su.QueryRow(ctx,
		`SELECT c.relrowsecurity, c.relforcerowsecurity
		 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relname = 'fleet_installations' AND n.nspname = 'public'`,
	).Scan(&rowsec, &forcesec))
	assert.True(t, rowsec, "RLS enabled")
	assert.True(t, forcesec, "RLS forced")
	var policies int
	require.NoError(t, su.QueryRow(ctx,
		`SELECT count(*) FROM pg_policies WHERE tablename = 'fleet_installations' AND policyname = 'org_isolation'`,
	).Scan(&policies))
	assert.Equal(t, 1, policies, "exactly one org_isolation policy")
}

func TestCapsStore_RevokedIsTerminal(t *testing.T) {
	su, app := fsCapsStoreFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	org := "term" + time.Now().Format("150405.000000000")

	store := NewCapsStore(app)
	caps := fsTestCaps(t)
	require.NoError(t, store.UpsertCaps(ctx, org, "deploy-prod", caps, base))

	// Plant the terminal state the way the revocation machinery will
	// (W02-C02 owns the transition; here the row shape is the input).
	_, err := su.Exec(ctx, `
		UPDATE fleet_installations
		SET state = 'revoked', revoked_at = $1, revocation_reason = 'operator'
		WHERE org_id = $2 AND deployment_id = 'deploy-prod'`, base.Add(time.Hour), org)
	require.NoError(t, err)

	// A caps refresh on a revoked installation is REFUSED (terminality
	// at the persistence layer) — never a silent overwrite.
	later := fsTestCaps(t)
	later.Capabilities = []string{"caps.inventory.upload"}
	err = store.UpsertCaps(ctx, org, "deploy-prod", later, base.Add(2*time.Hour))
	require.ErrorIs(t, err, ErrRevoked)

	// The document never moved.
	got, ok, err := store.Get(ctx, org, "deploy-prod")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, StateRevoked, got.State)
	assert.Equal(t, caps, got.Caps, "the caps document must survive the refused refresh unchanged")
	require.NotNil(t, got.RevokedAt)
	assert.Equal(t, "operator", got.RevocationReason)
}

func TestCapsStore_DownCleansUpAndUpRestores(t *testing.T) {
	su, _ := fsCapsStoreFixture(t)
	ctx := context.Background()
	down, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0024_fleet_registry.down.sql"))
	require.NoError(t, err)
	up, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0024_fleet_registry.up.sql"))
	require.NoError(t, err)

	tableThere := func() bool {
		var there bool
		require.NoError(t, su.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relname = 'fleet_installations')`,
		).Scan(&there))
		return there
	}

	// Up is already applied by the stand; drop via the SHIPPED down and
	// verify it removes the table, the policy and the posture together.
	require.True(t, tableThere())
	_, err = su.Exec(ctx, string(down))
	require.NoError(t, err, "the shipped down.sql must apply cleanly")
	require.False(t, tableThere(), "down must remove the registry table")
	var policies int
	require.NoError(t, su.QueryRow(ctx,
		`SELECT count(*) FROM pg_policies WHERE tablename = 'fleet_installations'`).Scan(&policies))
	assert.Zero(t, policies, "down must remove the policy with the table")

	// The re-up restores a working registry (structure only — data is
	// gone, the rollback contract) and the store works against it.
	_, err = su.Exec(ctx, string(up))
	require.NoError(t, err, "the shipped up.sql must re-apply cleanly")
	require.True(t, tableThere())

	store := NewCapsStore(su) // superuser: bypass path of the writer law
	now := time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)
	require.NoError(t, store.UpsertCaps(ctx, "reup-org", "deploy-1", fsTestCaps(t), now))
	got, ok, err := store.Get(ctx, "reup-org", "deploy-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, StateEnrolled, got.State)
}
