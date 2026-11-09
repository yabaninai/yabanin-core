package adminstore

// N10-P04-T04 acceptance against a real PostgreSQL (disposable testcontainers
// stand): the outbox replay is dedup-safe (a lost delete after a committed
// journal append converges instead of retrying forever), concurrent admin
// instances drain exactly once and converge, and the durability status shows
// gaps, dead letters and the recovery path end to end. The permission to
// lose request HISTORY never reaches this durability class: every scenario
// below keeps the strict commit/outbox/dedup rules (owner decision I44).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flakyBeginDB injects transient journal-append failures (the simulated
// outage) while every other statement flows through to the real stand.
type flakyBeginDB struct {
	pgxdb
	mu    sync.Mutex
	fails int
}

func (f *flakyBeginDB) BeginAuditTx(ctx context.Context) (auditTx, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return nil, errors.New("simulated transient outage: journal append refused")
	}
	return f.pgxdb.BeginAuditTx(ctx)
}

func n10p04t4Cleanup(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_outbox WHERE id LIKE 'n10p04t4-%'`)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_logs WHERE action LIKE 'n10p04t4.%'`)
	})
}

// TestAuditOutbox_ReplayAfterLostDelete_DedupExactlyOnce: the strict dedup
// rule. A drain delivers the journal append but crashes before deleting the
// outbox intent (the commit/delete statement pair is not atomic). The next
// replay hits the journal's primary key on the same entry id — that is
// proof of durable delivery, not a failure: the replay deletes the intent
// and converges, never failing the row into an eternal retry loop, and the
// journal keeps exactly one copy of the entry.
func TestAuditOutbox_ReplayAfterLostDelete_DedupExactlyOnce(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	resetAuditTable(t, pool)
	n10p04t4Cleanup(t, pool)

	id := fmt.Sprintf("n10p04t4-replay-%d", time.Now().UnixNano())
	rec := AuditLogEntryRecord{
		ID: id, Action: "n10p04t4.replay", Resource: "journal", AdminID: "root",
		Before: `{"a":1}`, Reason: "lost delete replay",
	}
	require.NoError(t, store.EnqueueAuditOutbox(ctx, rec))

	delivered, err := store.DrainAuditOutbox(ctx, 100)
	require.NoError(t, err)
	require.Equal(t, 1, delivered)

	var journalCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, id).Scan(&journalCount))
	require.Equal(t, 1, journalCount)

	// Crash simulation: the journal row is committed, but the outbox intent
	// survived (the delete was lost). Payload bytes identical to the
	// original enqueue.
	payload, err := json.Marshal(rec)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO admin_audit_outbox (id, payload) VALUES ($1, $2::jsonb)`, id, string(payload))
	require.NoError(t, err)

	delivered, err = store.DrainAuditOutbox(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, delivered,
		"the replay must count as delivered (dedup), not fail into backoff")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, id).Scan(&journalCount))
	assert.Equal(t, 1, journalCount, "the entry stays exactly-once in the journal")

	var pending int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_outbox WHERE id = $1`, id).Scan(&pending))
	assert.Zero(t, pending, "the replayed intent converges: the gap closes")

	assertChainIntact(t, store)
}

// TestAuditOutbox_ConcurrentDrains_ExactlyOnceAndConverge: two admin
// instances pick the same due rows (no cross-instance claim protocol). The
// dedup rule arbitrates: every entry lands in the journal exactly once and
// both instances converge to an empty outbox.
func TestAuditOutbox_ConcurrentDrains_ExactlyOnceAndConverge(t *testing.T) {
	pool := openAdminTestPool(t)
	ctx := context.Background()
	resetAuditTable(t, pool)
	n10p04t4Cleanup(t, pool)

	storeA := New(pool, slog.Default(), nil)
	storeB := New(pool, slog.Default(), nil)

	const n = 20
	stamp := time.Now().UnixNano()
	for i := 0; i < n; i++ {
		require.NoError(t, storeA.EnqueueAuditOutbox(ctx, AuditLogEntryRecord{
			ID:       fmt.Sprintf("n10p04t4-conc-%d-%d", stamp, i),
			Action:   "n10p04t4.concurrent",
			Resource: "journal",
			AdminID:  "root",
			Details:  fmt.Sprintf(`{"i":%d}`, i),
		}))
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	delivered := make([]int, 2)
	errs := make([]error, 2)
	stores := [2]*Store{storeA, storeB}
	for k := 0; k < 2; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			<-start
			delivered[k], errs[k] = stores[k].DrainAuditOutbox(ctx, 100)
		}(k)
	}
	close(start)
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	var journalCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE action = 'n10p04t4.concurrent'`).Scan(&journalCount))
	assert.Equal(t, n, journalCount,
		"every entry persisted exactly once across the concurrent drains (got delivered=%v)", delivered)

	var pending int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_outbox`).Scan(&pending))
	assert.Zero(t, pending, "concurrent replays converge: no row survives as an eternal retry")

	assertChainIntact(t, storeA)
}

// TestAuditOutboxStatus_GapsDeadLettersAndRecovery: the observable durability
// story on the real stand — the gap (durable intent not yet journaled), a
// real recorded failure, the dead-letter classification, and the recovery
// primitive delivering the entry once the outage ends.
func TestAuditOutboxStatus_GapsDeadLettersAndRecovery(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	resetAuditTable(t, pool)
	n10p04t4Cleanup(t, pool)

	id := fmt.Sprintf("n10p04t4-dead-%d", time.Now().UnixNano())
	rec := AuditLogEntryRecord{
		ID: id, Action: "n10p04t4.deadletter", Resource: "journal", AdminID: "root",
		Reason: "recovery story",
	}
	require.NoError(t, store.EnqueueAuditOutbox(ctx, rec))

	// GAP: the intent is durable, the journal does not have it yet.
	report, err := store.AuditOutboxStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), report.Pending, "the gap is visible")
	assert.Equal(t, int64(1), report.Due)
	assert.Zero(t, report.DeadLetters)
	assert.Empty(t, report.LastError)
	assert.GreaterOrEqual(t, report.OldestPendingAge, time.Duration(0))

	// TRANSIENT OUTAGE: the journal append fails; the intent survives and
	// the failure is recorded (never a quiet drop).
	outageStore := newForTest(&flakyBeginDB{pgxdb: store.db, fails: 1}, slog.Default(), nil)
	delivered, err := outageStore.DrainAuditOutbox(ctx, 100)
	require.NoError(t, err)
	assert.Zero(t, delivered)

	var attempts int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempts FROM admin_audit_outbox WHERE id = $1`, id).Scan(&attempts))
	assert.Equal(t, 1, attempts, "the real failure is recorded on the row")

	report, err = store.AuditOutboxStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), report.Pending)
	assert.Zero(t, report.Due, "the failed row backs off into the future")
	assert.Equal(t, int64(1), report.Retrying)
	assert.NotEmpty(t, report.LastError, "the persisted failure reason is surfaced")
	assert.Equal(t, id, report.LastErrorID)

	// Hours of continuous failure: the row crosses the dead-letter
	// threshold (the attempt schedule is compressed by the test; the real
	// drain produces the same state over time).
	_, err = pool.Exec(ctx,
		`UPDATE admin_audit_outbox SET attempts = $2 WHERE id = $1`, id, AuditOutboxDeadLetterAttempts)
	require.NoError(t, err)
	report, err = store.AuditOutboxStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), report.DeadLetters, "the dead letter is classified")
	assert.Zero(t, report.Retrying)

	// RECOVERY: the outage ended; the dead letter is requeued and the next
	// drain delivers it into the hash-chained journal.
	requeued, err := store.RequeueAuditOutboxDeadLetter(ctx, id)
	require.NoError(t, err)
	require.True(t, requeued)

	delivered, err = store.DrainAuditOutbox(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, delivered, "recovery delivers the requeued entry")

	report, err = store.AuditOutboxStatus(ctx)
	require.NoError(t, err)
	assert.Zero(t, report.Pending, "the gap closed")
	assert.Zero(t, report.DeadLetters)
	assert.Empty(t, report.LastError, "no failure remains")

	var journalCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE id = $1`, id).Scan(&journalCount))
	assert.Equal(t, 1, journalCount, "delivered exactly once")
	assertChainIntact(t, store)

	// Surface honesty: requeue is a dead-letter-only action.
	requeued, err = store.RequeueAuditOutboxDeadLetter(ctx, id)
	require.NoError(t, err)
	assert.False(t, requeued, "nothing left to requeue")
	requeued, err = store.RequeueAuditOutboxDeadLetter(ctx, "does-not-exist")
	require.NoError(t, err)
	assert.False(t, requeued, "unknown ids do not pretend recovery happened")
}
