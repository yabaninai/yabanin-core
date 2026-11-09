//go:build integration

package migrate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestRunURIBoundaryCorpus is the live arm of the connection-seam boundary
// corpus (the static arm is boundary_corpus_test.go): every connection DSN
// boundary is driven through the real runner against a real stand. The
// end-to-end row uses a stand whose password contains the characters that
// force percent-encoding (@ : /) and applies the full embedded set through
// the encoded DSN — the whole upgrade must succeed over a DSN that used to
// be corrupted into an unparseable URL by the seam. The remaining rows pin
// the observable failure messages: a malformed DSN fails at parse time, a
// unix-socket directory host is refused with a diagnosable message (it can
// never travel through a postgres:// URL), and an unreachable host fails at
// the ping gate. An empty region string is accepted like any other region
// value (the region is only carried into the session, never defaulted).
func TestRunURIBoundaryCorpus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	// Observable failure boundaries: no stand needed, the runner must reject
	// each of these before touching a database. The socket-DSN row stays an
	// error either way: without a local socket the ping gate refuses it, and
	// with one the connection seam itself refuses the unix-socket host.
	for _, tc := range []struct {
		name    string
		uri     string
		wantErr string
	}{
		{"malformed dsn fails at parse", "not-a-uri", "parse pg_uri"},
		{"unreachable host fails at the ping gate", "postgres://postgres:postgres@127.0.0.1:1/yabanin?sslmode=disable", "database ping failed"},
		{"authority-less uri fails before any database contact", "postgres://postgres@/tmp/yabanin", "no host authority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run(ctx, tc.uri, "sg")
			require.Error(t, err, "the boundary DSN must fail observably")
			require.Contains(t, err.Error(), tc.wantErr,
				"the failure must carry the diagnosable boundary message")
		})
	}
	t.Run("unix socket directory host never silently redirects", func(t *testing.T) {
		_, err := Run(ctx, "host=/tmp user=postgres dbname=yabanin", "sg")
		require.Error(t, err, "a socket-directory DSN must fail observably")
		require.True(t,
			strings.Contains(err.Error(), "database ping failed") || strings.Contains(err.Error(), "unix-socket"),
			"the failure must come from the ping gate or the seam refusal, got: %v", err)
	})

	// End-to-end boundary: a role whose password contains the URI-significant
	// characters (@ : /), reached through its percent-encoded DSN. The role is
	// created via SQL on a normally-booted stand because the container driver
	// cannot pass special-character passwords through its own readiness
	// probes; the migration session itself must speak the encoded DSN to a
	// real SCRAM-authenticated server.
	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers must be available for the connection-seam boundary corpus")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")

	ownerDSN := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])
	ownerPool, err := pgxpool.New(ctx, ownerDSN)
	require.NoError(t, err)
	waitForDBReady(t, ctx, ownerPool)
	_, err = ownerPool.Exec(ctx,
		`CREATE ROLE boundary_fancy LOGIN SUPERUSER PASSWORD 'p@ss:wo/rd'`)
	require.NoError(t, err, "creating the special-character role must succeed")
	ownerPool.Close()

	encodedDSN := fmt.Sprintf("postgres://boundary_fancy:p%%40ss%%3Awo%%2Frd@%s:%s/yabanin?sslmode=disable", host, parts[0])

	t.Run("encoded credentials upgrade end to end", func(t *testing.T) {
		up, err := Run(ctx, encodedDSN, "")
		require.NoError(t, err, "the full embedded set must apply through a percent-encoded DSN with special characters in the password")
		require.Equal(t, int64(27), up.Version,
			"embedded head moved: re-pin the corpus probes in the same change")

		// The same encoded DSN must also open a plain pool: the credentials
		// round-trip through every consumer of the DSN.
		pool, err := pgxpool.New(ctx, encodedDSN)
		require.NoError(t, err)
		defer pool.Close()
		var version int64
		require.NoError(t, pool.QueryRow(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&version))
		require.Equal(t, int64(27), version, "the encoded-DSN session must see the applied head")
	})
}

// TestDownTargetBoundaryCorpus walks the version-space boundary of the
// downgrade target on real stands, one subtest per boundary value, in a
// deterministic order per stand (Down only ever moves down; each row re-ups
// before the next target). The structural stand proves target placement
// without data probes; the data stand proves that the baseline-set probe row
// survives every intermediate downgrade target, that zero and negative
// targets both mean full revert, and that no target restores deleted data.
func TestDownTargetBoundaryCorpus(t *testing.T) {
	if dups := duplicateUpVersions(); len(dups) > 0 {
		t.Skipf("skipping: embedded migrations have duplicate version(s) %s — fix the numbering first", dups)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	// --- Structural stand: target placement at and past the head, and exact
	// intermediate landings. Bookkeeping probe: the golang-migrate postgres
	// driver keeps schema_migrations single-row (TRUNCATE + INSERT of the
	// current version), so exactly 1 row is recorded at every versioned
	// position and 0 rows after a full revert — `Applied` pins that
	// contract, not a cumulative count of applied migrations.
	t.Run("structural targets", func(t *testing.T) {
		dsn, pool, _ := spinBaselineStand(t, ctx)
		up, err := Run(ctx, dsn, "sg")
		require.NoError(t, err, "initial upgrade must reach the embedded head")
		require.Equal(t, int64(27), up.Version,
			"embedded head moved: re-pin the corpus targets in the same change")

		t.Run("target above head is a no-op", func(t *testing.T) {
			res, err := Down(ctx, dsn, "sg", 28)
			require.NoError(t, err)
			require.Equal(t, int64(27), res.Version)
			require.Equal(t, 1, res.Applied)
		})
		t.Run("target at current is a no-op", func(t *testing.T) {
			res, err := Down(ctx, dsn, "sg", 27)
			require.NoError(t, err)
			require.Equal(t, int64(27), res.Version)
			require.Equal(t, 1, res.Applied)
		})
		t.Run("target 14 reverts the 0015..0018 alterations", func(t *testing.T) {
			res, err := Down(ctx, dsn, "sg", 14)
			require.NoError(t, err)
			require.Equal(t, int64(14), res.Version)
			require.Equal(t, 1, res.Applied)
			// The 0015/0016/0017/0018 downs undo the alterations above 14,
			// the 0014 table itself stays: landing on N removes exactly
			// what sits above N.
			requireTableExists(t, dsn, "principal_delegations")
		})
		reup, err := Run(ctx, dsn, "sg")
		require.NoError(t, err, "re-upgrade between targets must succeed")
		require.Equal(t, int64(27), reup.Version)
		t.Run("target 11 reverts the 0012..0027 span (reserved gaps skipped)", func(t *testing.T) {
			res, err := Down(ctx, dsn, "sg", 11)
			require.NoError(t, err)
			require.Equal(t, int64(11), res.Version)
			require.Equal(t, 1, res.Applied)
			requireTableMissing(t, ctx, pool, "sso_group_role_rules",
				"the 0012 tables must be gone at version 11")
			requireTableExists(t, dsn, "policy_prompt_pins")
		})
	})

	// --- Data stand: baseline-data and full-revert boundaries.
	t.Run("data targets", func(t *testing.T) {
		dsn, pool, _ := spinBaselineStand(t, ctx)
		up, err := Run(ctx, dsn, "sg")
		require.NoError(t, err)
		require.Equal(t, int64(27), up.Version)
		_, err = pool.Exec(ctx,
			`INSERT INTO organizations (name, slug) VALUES ('Boundary Org', 'boundary-org')`)
		require.NoError(t, err, "seeding the baseline probe row must succeed")
		requireRowCount(t, ctx, pool, "organizations", 1, "after seeding")

		t.Run("target 1 keeps baseline data", func(t *testing.T) {
			res, err := Down(ctx, dsn, "sg", 1)
			require.NoError(t, err)
			require.Equal(t, int64(1), res.Version)
			require.Equal(t, 1, res.Applied)
			requireRowCount(t, ctx, pool, "organizations", 1,
				"the 0001 baseline data must survive a downgrade to the baseline itself")
			requireTableMissing(t, ctx, pool, "guard_pack_state",
				"incremental structures must be gone at version 1")
			reup, err := Run(ctx, dsn, "sg")
			require.NoError(t, err)
			require.Equal(t, int64(27), reup.Version)
			requireRowCount(t, ctx, pool, "guard_pack_state", 0,
				"re-created structures start empty: deleted probe data is not restored")
		})

		t.Run("target zero reverts everything", func(t *testing.T) {
			res, err := Down(ctx, dsn, "sg", 0)
			require.NoError(t, err)
			require.Equal(t, int64(0), res.Version)
			require.Equal(t, 0, res.Applied)
			var rows int
			require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&rows))
			require.Equal(t, 0, rows, "after a full revert the bookkeeping table must be empty")
			requireTableMissing(t, ctx, pool, "organizations",
				"the 0001 down must drop the baseline tables on a full revert")
			reup, err := Run(ctx, dsn, "sg")
			require.NoError(t, err)
			require.Equal(t, int64(27), reup.Version)
		})

		t.Run("negative target full-reverts and zero is a no-op at zero", func(t *testing.T) {
			_, err := pool.Exec(ctx,
				`INSERT INTO organizations (name, slug) VALUES ('Negative Arm', 'negative-arm')`)
			require.NoError(t, err, "seeding the full-revert probe row must succeed")
			res, err := Down(ctx, dsn, "sg", -1)
			require.NoError(t, err)
			require.Equal(t, int64(0), res.Version,
				"a negative target must mean full revert, like zero")
			res, err = Down(ctx, dsn, "sg", 0)
			require.NoError(t, err)
			require.Equal(t, int64(0), res.Version,
				"downgrading from zero must stay a no-op success")
			reup, err := Run(ctx, dsn, "sg")
			require.NoError(t, err)
			require.Equal(t, int64(27), reup.Version)
			requireRowCount(t, ctx, pool, "organizations", 0,
				"the full-revert probe row must not come back: no migration restores data")
		})
	})
}
