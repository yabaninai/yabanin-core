package consumer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-16 (handed off by AF-06): the durable settlement queue gets a bounded
// retention for terminal 'settled' rows. This is a money-adjacent DELETE (the
// settled row is the exactly-once authority for the agent-spend side effect),
// so the contract is pinned at unit level here and by live acceptance in
// af16_retention_live_test.go: only settled rows past the window, bounded
// batches, cadence-gated, errors never fatal.

func TestDefaultSettlementConfig_SettledRetentionDefaults(t *testing.T) {
	cfg := DefaultSettlementConfig()
	assert.Equal(t, 90*24*time.Hour, cfg.SettledRetention)
	assert.Equal(t, time.Hour, cfg.SettledCleanupEvery)
	assert.Equal(t, int64(500), cfg.SettledCleanupBatch)
	assert.Equal(t, 40, cfg.SettledCleanupPasses)

	// A zero-value config falls back to the same production defaults.
	filled := SettlementConfig{}.withDefaults()
	assert.Equal(t, cfg.SettledRetention, filled.SettledRetention)
	assert.Equal(t, cfg.SettledCleanupEvery, filled.SettledCleanupEvery)
	assert.Equal(t, cfg.SettledCleanupBatch, filled.SettledCleanupBatch)
	assert.Equal(t, cfg.SettledCleanupPasses, filled.SettledCleanupPasses)
}

// The DELETE statement itself must only ever target terminal 'settled' rows:
// pending/retry/processing are live work and requires_attention rows are
// durable debts that must stay visible for reconciliation.
func TestSettledRetentionQuery_DeletesOnlySettledRows(t *testing.T) {
	q := settledRetentionDeleteQuery
	assert.Contains(t, q, "DELETE FROM settlement_jobs")
	assert.Contains(t, q, "status = 'settled'")
	assert.Contains(t, q, "LIMIT $2", "per-statement delete bound")
	for _, live := range []string{"pending", "processing", "retry", "requires_attention"} {
		assert.NotContains(t, q, "'"+live+"'",
			"retention must never name the non-settled state %q", live)
	}
}

func TestCleanupSettledJobs_BoundedPassesAndCadence(t *testing.T) {
	db := &fakeSettlementDB{tagRows: 10} // DB always reports a full batch deleted
	w := newUnitWorker(db).WithConfig(SettlementConfig{
		SettledCleanupBatch:  10,
		SettledCleanupPasses: 2,
		SettledCleanupEvery:  time.Hour,
		SettledRetention:     90 * 24 * time.Hour,
		Interval:             time.Hour,
	})
	now := time.Now()
	w.cleanupNower = func() time.Time { return now }

	// The DB always reports a full batch deleted: the pass bound (2×10=20)
	// caps the deletes regardless of how many rows qualify.
	w.cleanupSettledJobs(context.Background())
	deletes := db.execsBySubstring("DELETE FROM settlement_jobs")
	require.Len(t, deletes, 2, "cleanup stops at SettledCleanupPasses")
	require.Len(t, deletes[0].args, 2)
	assert.InDelta(t, float64(90*24*3600), deletes[0].args[0], 0.001, "retention window is passed in seconds")
	assert.Equal(t, int64(10), deletes[0].args[1], "per-statement batch bound")

	// Same cadence window: the gate suppresses a second run.
	w.cleanupSettledJobs(context.Background())
	assert.Len(t, db.execsBySubstring("DELETE FROM settlement_jobs"), 2)

	// A later tick (cadence elapsed) runs again, still bounded.
	w.cleanupNower = func() time.Time { return now.Add(2 * time.Hour) }
	w.cleanupSettledJobs(context.Background())
	assert.Len(t, db.execsBySubstring("DELETE FROM settlement_jobs"), 4)
}

// A failed retention pass must never be fatal: the worker logs and retries
// on the next cadence window.
func TestCleanupSettledJobs_ErrorNotFatalRetriedNextCadence(t *testing.T) {
	db := &fakeSettlementDB{
		failNext: map[string]int{"DELETE FROM settlement_jobs": 1},
		failErr:  errors.New("pg: connection reset by peer"),
	}
	w := newUnitWorker(db).WithConfig(SettlementConfig{
		SettledCleanupBatch:  10,
		SettledCleanupPasses: 2,
		SettledCleanupEvery:  time.Hour,
		SettledRetention:     90 * 24 * time.Hour,
		Interval:             time.Hour,
	})
	now := time.Now()
	w.cleanupNower = func() time.Time { return now }

	require.NotPanics(t, func() { w.cleanupSettledJobs(context.Background()) })
	assert.Empty(t, db.execsBySubstring("DELETE FROM settlement_jobs"),
		"a failed pass is abandoned, not fatal")

	w.cleanupNower = func() time.Time { return now.Add(2 * time.Hour) }
	w.cleanupSettledJobs(context.Background())
	assert.Len(t, db.execsBySubstring("DELETE FROM settlement_jobs"), 1,
		"the failed pass is retried after the cadence elapses")
}

// The worker tick drives the settled retention through the same cadence
// plumbing as the event_inbox retention — not a separate loop.
func TestTick_RunsSettledRetention(t *testing.T) {
	db := &fakeSettlementDB{tagRows: 1}
	w := newUnitWorker(db).WithConfig(SettlementConfig{
		SettledCleanupBatch:  10,
		SettledCleanupPasses: 2,
		SettledCleanupEvery:  time.Hour,
		SettledRetention:     90 * 24 * time.Hour,
	})

	w.tick(context.Background())

	assert.NotEmpty(t, db.execsBySubstring("DELETE FROM settlement_jobs"),
		"tick must run the settled-jobs retention")
}
