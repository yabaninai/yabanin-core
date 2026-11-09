package consumer

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-LOGG chaos acceptance (scaled timeline): a full Postgres outage spanning
// far more than maxRetries attempts must NOT dead-letter live billing
// traffic — the consumer pauses, the messages wait in the PEL, and after
// recovery EVERY event lands in request_logs with its settlement intent and
// the DLQ stays empty.
//
// The 10-minute production outage is compressed to a sub-second window here
// (same code path, injected at the DB boundary — the exact pattern of
// inbox_live_test.go: from the database's point of view an unreachable
// server is a failed connection, and the consumer cannot tell a killed
// postmaster from a refused dial). See the W-LOGG handoff for the scaling
// note.
type outageDB struct {
	inner DBOps
	fail  *atomic.Bool
}

func (w outageDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if w.fail.Load() {
		return pgconn.CommandTag{}, errors.New("chaos: dial tcp: connection refused")
	}
	return w.inner.Exec(ctx, query, args...)
}

func (w outageDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if w.fail.Load() {
		return errRow{err: errors.New("chaos: dial tcp: connection refused")}
	}
	return w.inner.QueryRow(ctx, query, args...)
}

func (w outageDB) BeginTx(ctx context.Context) (InboxTx, error) {
	if w.fail.Load() {
		return nil, errors.New("chaos: dial tcp: connection refused")
	}
	return w.inner.BeginTx(ctx)
}

func chaosEvent(t *testing.T, rdb *redis.Client, stream, id string, tsMs int64) {
	t.Helper()
	values := map[string]interface{}{
		"event_type":         "request.completed",
		"source":             "gateway-chaos",
		"request_id":         "req-chaos-" + id,
		"org_id":             inboxLiveOrgID,
		"session_id":         "ses_live_af04",
		"model_requested":    "gpt-4",
		"model_used":         "gpt-4-turbo",
		"status_code":        "200",
		"duration_ms":        "10",
		"tokens_in":          "5",
		"tokens_out":         "7",
		"estimated_cost_usd": "0.05",
		"resale_cost_usd":    "0.07",
		"method":             "POST",
	}
	if tsMs > 0 {
		values["ts"] = strconv.FormatInt(tsMs, 10)
	}
	require.NoError(t, rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: stream, Values: values}).Err())
}

func chaosCount(t *testing.T, ctx context.Context, pool poolQuerier, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

// poolQuerier is the read slice the chaos assertions need (satisfied by
// *pgxpool.Pool).
type poolQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func TestChaosLive_DBOutageDeliversEverythingWithoutDLQ(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	const stream = "events:chaos-w-logg"
	outage := &atomic.Bool{}
	wrapped := outageDB{inner: NewDBOps(pool), fail: outage}

	// Business time of event A: two hours before the run (delayed delivery
	// proof — created_at must stay on the event clock).
	business := time.Now().Add(-2 * time.Hour).Truncate(time.Millisecond)
	chaosEvent(t, rdb, stream, "200-0", business.UnixMilli())

	c := NewWithCreditStore(NewRedisOps(rdb), wrapped, stream, silentLogger(), credits.NewStore(pool, silentLogger()))
	// Scaled timeline seams (production defaults: 2s pause / 5min+5min
	// reclaim — the same logic, compressed ~10^3x).
	c.outagePause = 30 * time.Millisecond
	c.reclaimIdle = 200 * time.Millisecond
	c.reclaimEvery = 300 * time.Millisecond

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = c.Start(runCtx) }()
	t.Cleanup(c.Stop)

	// Healthy path first: event A is logged with its charge intent.
	require.Eventually(t, func() bool {
		return chaosCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE request_id='req-chaos-200-0'`) == 1
	}, 10*time.Second, 50*time.Millisecond, "event A must log on the healthy path")

	// --- full DB outage ---
	outage.Store(true)
	chaosEvent(t, rdb, stream, "200-1", 0)
	chaosEvent(t, rdb, stream, "200-2", 0)

	// During the outage: consumption pauses — nothing is dead-lettered, no
	// retry budget burns, and the affected messages stay PENDING (kept, not
	// lost). The outage window here is orders of magnitude longer than
	// maxRetries processing attempts, the exact shape of the 10-minute loss.
	require.Eventually(t, func() bool {
		pending, err := rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
			Stream: stream, Group: consumerGroup, Start: "-", End: "+", Count: 100,
		}).Result()
		if err != nil {
			return false
		}
		return len(pending) == 2 &&
			chaosCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE request_id LIKE 'req-chaos-200-%'`) == 1
	}, 10*time.Second, 50*time.Millisecond, "outage messages must stay pending and undelivered")

	dlqLen, err := rdb.XLen(ctx, dlqStreamName).Result()
	require.NoError(t, err)
	assert.Zero(t, dlqLen, "a DB outage must not dead-letter live billing traffic")
	retryKeys, err := rdb.Keys(ctx, dlqRetryKeyPrefix+":*").Result()
	require.NoError(t, err)
	assert.Empty(t, retryKeys, "an outage must not consume the retry budget")

	// Hold the outage a moment longer than the reclaim cycle to prove the
	// reclaim path also refuses to DLQ during unavailability.
	time.Sleep(700 * time.Millisecond)
	dlqLen, err = rdb.XLen(ctx, dlqStreamName).Result()
	require.NoError(t, err)
	assert.Zero(t, dlqLen, "reclaimed outage failures must not dead-letter either")

	// --- recovery ---
	outage.Store(false)

	require.Eventually(t, func() bool {
		return chaosCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE request_id LIKE 'req-chaos-200-%'`) == 3
	}, 20*time.Second, 100*time.Millisecond, "after recovery every event must be logged")

	require.Eventually(t, func() bool {
		return chaosCount(t, ctx, pool,
			`SELECT count(*) FROM settlement_jobs WHERE request_id LIKE 'req-chaos-200-%'`) == 3
	}, 20*time.Second, 100*time.Millisecond, "after recovery every charge intent must exist")

	require.Eventually(t, func() bool {
		pending, err := rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
			Stream: stream, Group: consumerGroup, Start: "-", End: "+", Count: 100,
		}).Result()
		return err == nil && len(pending) == 0
	}, 20*time.Second, 100*time.Millisecond, "the PEL drains after recovery")

	dlqLen, err = rdb.XLen(ctx, dlqStreamName).Result()
	require.NoError(t, err)
	assert.Zero(t, dlqLen, "the DLQ stays empty across the whole scenario")

	// Delayed delivery kept the business clock: event A logs with the
	// producer ts as created_at, not the outage-recovery moment.
	var createdAt time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT created_at FROM request_logs WHERE request_id='req-chaos-200-0'`).Scan(&createdAt))
	assert.WithinDuration(t, business.UTC(), createdAt.UTC(), 2*time.Second,
		"created_at is the producer ts even though delivery was delayed by the outage")
}
