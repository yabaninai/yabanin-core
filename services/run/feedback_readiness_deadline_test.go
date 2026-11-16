package run

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// heldViewLock records the confirmed independent view lock: the granted lock
// mode and holder PID observed from pg_locks.
type heldViewLock struct {
	pid  uint32
	mode string
}

// holdBetaRequestsDailyLock holds public.beta_requests_daily under a real
// ACCESS EXCLUSIVE lock from a connection+transaction independent of the
// readiness probe, confirming the granted mode and holder PID from pg_locks.
// Resource cleanup is registered as it is acquired — conn.Release right after
// Acquire, then the explicit rollback — so a failure in Begin, LOCK or the
// pg_locks confirmation still releases everything; t.Cleanup's LIFO order
// runs the rollback before the connection release.
func holdBetaRequestsDailyLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *heldViewLock {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire independent lock connection: %v", err)
	}
	t.Cleanup(conn.Release)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin independent lock transaction: %v", err)
	}
	t.Cleanup(func() {
		// Rollback reporting pgx.ErrTxClosed is the already-completed case;
		// every other cleanup error fails the test instead of being discarded.
		// WithoutCancel keeps the fixture ctx's values but sheds its
		// cancellation, so cleanup survives any caller cancellation.
		if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatalf("release held view lock: rollback: %v", err)
		}
	})
	if _, err := tx.Exec(ctx, "LOCK TABLE public.beta_requests_daily IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("hold beta_requests_daily with an independent database lock: %v", err)
	}
	lock := &heldViewLock{pid: tx.Conn().PgConn().PID()}
	if err := pool.QueryRow(ctx, `SELECT mode FROM pg_locks
		WHERE pid = $1 AND relation = 'public.beta_requests_daily'::regclass AND granted`,
		lock.pid).Scan(&lock.mode); err != nil {
		t.Fatalf("confirm independent view lock: %v", err)
	}
	if lock.mode != "AccessExclusiveLock" {
		t.Fatalf("independent view lock mode = %s, want AccessExclusiveLock", lock.mode)
	}
	return lock
}

// wiringOutcome captures one bounded readiness attempt: the collector
// adminWireFeedback returned (wiring must complete before the probe) and how
// long the whole call took.
type wiringOutcome struct {
	collector *feedback.Collector
	elapsed   time.Duration
}

// startReadinessWiring runs adminWireFeedback on a cancellable context in a
// background goroutine; the outcome is delivered on the returned channel
// exactly once.
func startReadinessWiring(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) <-chan wiringOutcome {
	done := make(chan wiringOutcome, 1)
	started := time.Now()
	go func() {
		collector := adminWireFeedback(ctx, &handlers.AdminHandlers{}, pool, logger)
		done <- wiringOutcome{collector: collector, elapsed: time.Since(started)}
	}()
	return done
}

// assertBoundedDegradedReadiness enforces the corrected-source contract on the
// pass path: wiring returned within the 15s bound (16s outer guard), the
// collector/lister wiring completed (non-nil collector), the degraded
// readiness failure was logged explicitly, and the ready line never fired.
func assertBoundedDegradedReadiness(t *testing.T, outcome wiringOutcome, logs string) {
	t.Helper()
	t.Logf("QS-STARTUP-READINESS-DEADLINE: wiring returned in %s", outcome.elapsed)
	if outcome.elapsed > 16*time.Second {
		t.Fatalf("wiring returned after %s, want within the 15s readiness deadline (<=16s)", outcome.elapsed)
	}
	if outcome.collector == nil {
		t.Fatal("wiring returned a nil collector; collector/lister wiring must complete before the readiness probe")
	}
	if !strings.Contains(logs, "beta metrics views readiness check failed") {
		t.Fatalf("wiring returned without an explicit readiness failure while the view lock remained held: %s", logs)
	}
	// The ready message is a prefix of the failure message, so match the full
	// quoted msg to assert the success line never fired.
	if strings.Contains(logs, `msg="beta metrics views ready"`) {
		t.Fatalf("wiring reported the views ready while the view lock remained held: %s", logs)
	}
}

// requireIndependentLockWait observes the latest active non-test backend in
// pg_stat_activity and requires a Lock wait: without an observed relation
// Lock the timeout cannot be attributed to the held view lock, and the run is
// inconclusive (harness failure), not a valid negative proof and not a pass.
// A failed observation leaves waitType empty and fails the same check.
func requireIndependentLockWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var query, waitType, waitEvent string
	err := pool.QueryRow(ctx, `SELECT query, coalesce(wait_event_type, ''), coalesce(wait_event, '')
		FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND state = 'active'
		ORDER BY query_start DESC LIMIT 1`).Scan(&query, &waitType, &waitEvent)
	if err != nil {
		t.Logf("independent database wait observation failed: %v", err)
	} else {
		t.Logf("independent database wait: type=%s event=%s query=%s", waitType, waitEvent, query)
	}
	if waitType != "Lock" {
		t.Fatal("QS-STARTUP-READINESS-DEADLINE: no independent Lock wait observed; cannot attribute the timeout to the held view lock")
	}
}

// awaitWiringStopped waits for the readiness goroutine to return after caller
// cancellation; still running past the guard window fails the test.
func awaitWiringStopped(t *testing.T, done <-chan wiringOutcome) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop after caller cancellation")
	}
}

// QS-STARTUP-READINESS-DEADLINE retained regression guard: adminWireFeedback
// must bound the beta metrics views readiness probe (CheckMetricsViews) with
// a 15s deadline derived from the caller context. While an independent
// transaction holds ACCESS EXCLUSIVE on public.beta_requests_daily, wiring
// must return within the bound, log the explicit readiness failure, keep the
// degraded path nonfatal (collector/lister wiring already completed), and
// never report the views ready. The 18s branch is the broken-control proof:
// source without the bound must fail there with a real observed Lock wait.
func TestFeedbackStartupReadinessDeadline(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	if err := feedback.EnsureMetricsViews(ctx, pool); err != nil {
		t.Fatalf("provision real metrics views: %v", err)
	}
	lock := holdBetaRequestsDailyLock(t, ctx, pool)
	t.Logf("independent lock confirmed: relation=beta_requests_daily mode=%s holder_pid=%d", lock.mode, lock.pid)

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	wireCtx, cancelWire := context.WithCancel(context.Background())
	defer cancelWire()
	done := startReadinessWiring(wireCtx, pool, logger)

	select {
	case outcome := <-done:
		assertBoundedDegradedReadiness(t, outcome, logs.String())
	case <-time.After(18 * time.Second):
		requireIndependentLockWait(t, ctx, pool)
		cancelWire()
		awaitWiringStopped(t, done)
		t.Logf("readiness log after cleanup: %s", logs.String())
		t.Fatal("deadline not enforced")
	}
}
