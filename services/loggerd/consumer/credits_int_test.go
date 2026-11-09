package consumer

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// QG2-B3 (owner decision 2026-09-13: Docker required for tests): the shared
// dev-Postgres DSN is replaced by the package-wide disposable, fully
// migrated stand from pkg/testdb — no skip when the stand is down, no
// cross-package table conflicts. Tests still serialize on this mutex
// because they share the stand and recreate schema pieces per test.
//
// A05 (audit §A05): since the fixture-ownership fix the destructive credit
// suites no longer recreate schema pieces in the SHARED public schema at
// all — they run on a fixture-owned schema (setupOwnedCreditsDB) — but the
// mutex discipline stays: the reporting suites on this list still observe
// the shared public schema and must not interleave with any credit-table
// fixture lifecycle.
var creditsIntegrationMu sync.Mutex

// setupOwnedCreditsDB returns a pool pinned (search_path, startup param) to
// a fixture-owned schema on the shared disposable stand (A05, audit §A05).
// The destructive credit-table suites — the ones that CREATE and DROP
// org_credits/credit_transactions via setupCreditTables/teardownCreditTables
// — run on this pool, so their DROPs can only ever land inside the fixture:
// the shared stand's public schema stays product-like for every later suite
// (the SQLSTATE 42P01 class is impossible by construction, no
// sleep/retry/skip involved). The fixture is torn down guaranteed
// (DROP SCHEMA ... CASCADE) by the pkg/testdb helper.
func setupOwnedCreditsDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Fixture first (may boot the shared stand), then the mutex — the same
	// order and cleanup discipline as setupTestDBForCredits.
	pool := testdb.PostgresOwnedSchema(t, "credits")
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)
	return pool
}

// TestA05_DestructiveCreditFixture_ThenReportingSharedStand is the audit's
// A05 regression, run in ONE process: a destructive credit-table cycle
// executes BEFORE the joint reporting scenario, deterministically (the
// wrapper forces the phase order regardless of -shuffle). On the pre-fix
// base this exact pairing failed the reporting phase with SQLSTATE 42P01 —
// the credit teardown had dropped credit_transactions/org_credits from the
// shared stand's public schema. With fixture-owned schemas the DROP hits
// only the fixture and the shared schema stays intact, so the reporting
// phase observes the product-like migrated container unchanged.
func TestA05_DestructiveCreditFixture_ThenReportingSharedStand(t *testing.T) {
	if testing.Short() {
		t.Skip("disposable stands are skipped in -short mode (fast loop stays Dockerless)")
	}

	// Phase 1 — the destructive credit integration path, now fixture-owned:
	// it CREATEs the credit tables, deducts against them, and DROPs them at
	// teardown. Every statement lands in the fixture schema only.
	t.Run("phase1_destructive_credit_cycle", TestDeductor_Idempotency_Integration)

	// Phase 2 — the joint reporting scenario on the SHARED migrated
	// container, UNCHANGED: it seeds and reads credit_transactions in the
	// public schema and must never see the phase-1 teardown (42P01 here
	// would be the audited defect back).
	t.Run("phase2_reporting_shared_stand", TestN06P6T06RealPG_JointReportingScenario)

	// Explicit ownership pins on the shared stand after the destructive
	// cycle, so the invariant holds even without phase 2's success detail:
	// (a) both public credit tables survived — 42P01 cannot appear for any
	// later suite; (b) no fixture-schema residue was left behind — the
	// guaranteed teardown actually ran.
	pool := testdb.Postgres(t)
	ctx := context.Background()

	var publicTables int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'public'
		   AND table_name IN ('credit_transactions', 'org_credits')`,
	).Scan(&publicTables))
	require.Equal(t, 2, publicTables,
		"destructive credit cycle must leave the shared public schema intact")

	var fixtureResidue int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_namespace WHERE nspname ~ '^fx_'`,
	).Scan(&fixtureResidue))
	require.Equal(t, 0, fixtureResidue,
		"fixture-owned schemas (any fx_ label) must be torn down (guaranteed restore)")
}
