package run

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// QS-STARTUP-READINESS-DEADLINE retained regression guard: adminWireFeedback
// must bound the beta metrics views readiness probe (CheckMetricsViews) with
// a 15s deadline derived from the caller context. While an independent
// transaction holds ACCESS EXCLUSIVE on public.beta_requests_daily, wiring
// must return within the bound, log the explicit readiness failure, keep the
// degraded path nonfatal (collector/lister wiring already completed), and
// never report the views ready.
func TestFeedbackStartupReadinessDeadline(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	if err := feedback.EnsureMetricsViews(ctx, pool); err != nil {
		t.Fatalf("provision real metrics views: %v", err)
	}
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire independent lock connection: %v", err)
	}
	defer lockConn.Release()
	tx, err := lockConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin independent lock transaction: %v", err)
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE public.beta_requests_daily IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("hold beta_requests_daily with an independent database lock: %v", err)
	}
	defer tx.Rollback(context.Background())
	var lockMode string
	if err := pool.QueryRow(ctx, `SELECT mode FROM pg_locks
		WHERE pid = $1 AND relation = 'public.beta_requests_daily'::regclass AND granted`,
		tx.Conn().PgConn().PID()).Scan(&lockMode); err != nil {
		t.Fatalf("confirm independent view lock: %v", err)
	}
	if lockMode != "AccessExclusiveLock" {
		t.Fatalf("independent view lock mode = %s, want AccessExclusiveLock", lockMode)
	}
	t.Logf("independent lock confirmed: relation=beta_requests_daily mode=%s holder_pid=%d", lockMode, tx.Conn().PgConn().PID())

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	wireCtx, cancelWire := context.WithCancel(context.Background())
	defer cancelWire()
	type wireResult struct {
		collector *feedback.Collector
		elapsed   time.Duration
	}
	done := make(chan wireResult, 1)
	started := time.Now()
	go func() {
		collector := adminWireFeedback(wireCtx, &handlers.AdminHandlers{}, pool, logger)
		done <- wireResult{collector: collector, elapsed: time.Since(started)}
	}()

	select {
	case result := <-done:
		t.Logf("QS-STARTUP-READINESS-DEADLINE: wiring returned in %s", result.elapsed)
		if result.elapsed > 16*time.Second {
			t.Fatalf("wiring returned after %s, want within the 15s readiness deadline (<=16s)", result.elapsed)
		}
		if result.collector == nil {
			t.Fatal("wiring returned a nil collector; collector/lister wiring must complete before the readiness probe")
		}
		if !strings.Contains(logs.String(), "beta metrics views readiness check failed") {
			t.Fatalf("wiring returned without an explicit readiness failure while the view lock remained held: %s", logs.String())
		}
		// The ready message is a prefix of the failure message, so match the
		// full quoted msg to assert the success line never fired.
		if strings.Contains(logs.String(), `msg="beta metrics views ready"`) {
			t.Fatalf("wiring reported the views ready while the view lock remained held: %s", logs.String())
		}
	case <-time.After(18 * time.Second):
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
			t.Fatalf("QS-STARTUP-READINESS-DEADLINE: no independent Lock wait observed; cannot attribute the timeout to the held view lock")
		}
		cancelWire()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("did not stop after caller cancellation")
		}
		t.Logf("readiness log after cleanup: %s", logs.String())
		t.Fatal("deadline not enforced")
	}
}
