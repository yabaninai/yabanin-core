//go:build integration

package migrate

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The packet's joint scenario, executed on the agreed environment: real
// pgvector/pgvector:pg16 stands of the same class every live check in this
// package uses. One ordered chain exercises all three packet claims on shared
// stands instead of in isolation:
//
//	fresh install ── Run ────────────────────────────────► head ──┐
//	stamp-1 cohort ─ baseline-only stamp ── Run ─────────► head ──┤ byte-identical schema
//	                                                              │ (packet acceptance)
//	cohort stand, continued:                                      │
//	  seed probe row → Down(target) → exact landing at the        │ (packet negative holds
//	  target, probe structure gone, below-target set intact →     │ inside the joint chain,
//	  re-Run → head → probe data still deleted) ──────────────────┘ not only in isolation)
//	  → and the round-tripped cohort still dumps byte-identical to the
//	  fresh install: the post-round-trip parity closure.
//
// Real vs structural: THIS test is the real arm — live Postgres, shipped
// seams only (Run, Down, and the golang-migrate subset source that lands the
// stamp-1 cohort state, exactly as the parity test does). No mocks stand in
// for the database anywhere in it. The structural arm without a database is
// TestJointScenarioAnchorsPresent, which pins the versions and probe tables
// this chain walks and fails first when the embedded set moves.
func TestRun_JointScenarioFreshUpgradeDownReUpIdenticalSchema(t *testing.T) {
	if dups := duplicateUpVersions(); len(dups) > 0 {
		t.Skipf("skipping: embedded migrations have duplicate version(s) %s — fix the numbering first", dups)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	// Stand 1 — fresh install: the whole embedded set applies in one Run and
	// lands on the pinned head (the anchor test guarantees the pin matches
	// the embedded set on this tree).
	freshDSN, _, freshStand := spinBaselineStand(t, ctx)
	upFresh, err := Run(ctx, freshDSN, "sg")
	require.NoError(t, err, "fresh-DB apply of the full embedded set must succeed")
	require.Equal(t, 1, upFresh.Applied)
	require.Equal(t, int64(jointScenario.headVersion), upFresh.Version)
	freshDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, freshStand))
	require.Contains(t, string(freshDump), "CREATE TABLE public.organizations",
		"the dump must carry the real schema, not an empty DB (non-vacuity guard)")

	// Stand 2 — stamp-1 upgrade cohort: baseline stamp first, then the
	// shipped Run applies the shared 0002..head incrementals.
	stampDSN, stampPool, stampStand := spinBaselineStand(t, ctx)
	stamp1CohortApply(t, ctx, stampDSN)
	var version int64
	var dirty bool
	require.NoError(t, stampPool.QueryRow(ctx,
		`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty))
	require.Equal(t, int64(jointScenario.cohortStamp), version, "the cohort stand must be recorded at the stamp version")
	require.False(t, dirty)
	upStamp, err := Run(ctx, stampDSN, "sg")
	require.NoError(t, err, "the stamp-1 cohort must upgrade over the shared incrementals")
	require.Equal(t, int64(jointScenario.headVersion), upStamp.Version, "the upgraded cohort must converge to the head")

	// Acceptance: fresh install and the supported upgrade converge to one and
	// the same schema, byte for byte (modulo per-run guard tokens).
	stampDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, stampStand))
	require.Equal(t, string(freshDump), string(stampDump),
		"fresh install and the stamp-1 supported upgrade must yield the identical schema")

	// The joint chain continues on the cohort stand: seed a probe row the
	// downgrade must not restore.
	_, err = stampPool.Exec(ctx,
		`INSERT INTO guard_pack_state (id, active_version) VALUES (1, 'joint-scenario-probe')`)
	require.NoError(t, err, "seeding the probe row into the probe table must succeed")
	requireRowCount(t, ctx, stampPool, jointScenario.probeTable, 1, "after seeding")

	// Downgrade to the pinned intermediate target: exact landing, probe
	// structure gone (its structural reverse), below-target set intact.
	down1, err := Down(ctx, stampDSN, "sg", jointScenario.downTarget)
	require.NoError(t, err, "downgrade to the intermediate target should succeed")
	require.Equal(t, int64(jointScenario.downTarget), down1.Version,
		"the downgrade must land exactly on the requested version")
	requireTableMissing(t, ctx, stampPool, jointScenario.probeTable,
		"the probe version's down must drop the probe table (structural reverse)")
	requireTableExists(t, stampDSN, jointScenario.belowTargetTable)

	// Re-upgrade: the structure returns, the probe row does not — the packet
	// negative holds inside the joint chain, not only in isolation.
	up2, err := Run(ctx, stampDSN, "sg")
	require.NoError(t, err, "re-upgrade should succeed")
	require.Equal(t, int64(jointScenario.headVersion), up2.Version)
	requireTableExists(t, stampDSN, jointScenario.probeTable)
	requireRowCount(t, ctx, stampPool, jointScenario.probeTable, 0,
		"deleted data must stay deleted across down → re-up inside the joint chain")

	// Joint closure: the round-tripped cohort (upgrade → downgrade →
	// re-upgrade) still dumps byte-identical to the fresh install.
	roundTripDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, stampStand))
	require.Equal(t, string(freshDump), string(roundTripDump),
		"the cohort stand must converge back to the fresh-install schema after the down/up round trip")

	// Sensitivity arm: the closure comparison must be able to fail. Mutate
	// the cohort stand (both stands are disposable) and require divergence.
	_, err = stampPool.Exec(ctx,
		`COMMENT ON TABLE public.organizations IS 'joint scenario sensitivity probe'`)
	require.NoError(t, err)
	mutatedDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, stampStand))
	require.Contains(t, string(mutatedDump), "joint scenario sensitivity probe")
	require.NotEqual(t, string(freshDump), string(mutatedDump),
		"the byte comparison must notice a schema difference (sensitivity proof)")
}
