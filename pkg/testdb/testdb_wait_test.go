package testdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// stubRow is a minimal pgx.Row over a canned value or error.
type stubRow struct {
	scan func(dest ...any) error
}

func (r stubRow) Scan(dest ...any) error { return r.scan(dest...) }
func (r stubRow) Err() error             { return nil }

// stubQuerier replays queued QueryRow results in order.
type stubQuerier struct {
	results []stubRow
	calls   int
}

func (q *stubQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if q.calls >= len(q.results) {
		return stubRow{scan: func(dest ...any) error { return errors.New("no more rows") }}
	}
	r := q.results[q.calls]
	q.calls++
	return r
}

func startTimes(t *testing.T, times ...time.Time) stubQuerier {
	t.Helper()
	q := stubQuerier{}
	for _, tm := range times {
		v := tm
		q.results = append(q.results, stubRow{scan: func(dest ...any) error {
			d, ok := dest[0].(*time.Time)
			if !ok {
				t.Fatalf("scan dest is not *time.Time")
			}
			*d = v
			return nil
		}})
	}
	return q
}

func TestWaitStablePostmaster_StableAcrossSettleReturns(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	q := startTimes(t, t0, t0)
	// First poll reads T0 (haveLast set), second poll reads the same → stable.
	if err := waitStablePostmasterQ(context.Background(), &q, time.Millisecond, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("stable start time must return nil, got %v", err)
	}
	if q.calls != 2 {
		t.Fatalf("want 2 polls, got %d", q.calls)
	}
}

func TestWaitStablePostmaster_ChangingStartTimesHitDeadline(t *testing.T) {
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	q := startTimes(t, base, base.Add(time.Second), base.Add(2*time.Second), base.Add(3*time.Second), base.Add(4*time.Second))
	err := waitStablePostmasterQ(context.Background(), &q, time.Millisecond, time.Now().Add(10*time.Millisecond))
	if err == nil {
		t.Fatalf("never-stable start times must hit the deadline with an error")
	}
}

func TestWaitStablePostmaster_RestartErrorsKeepWaiting(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	q := stubQuerier{}
	// Two polls erroring (server restarting), then a stable pair.
	for i := 0; i < 2; i++ {
		q.results = append(q.results, stubRow{scan: func(dest ...any) error { return errors.New("server closed the connection") }})
	}
	q.results = append(q.results, startTimes(t, t0).results...)
	q.results = append(q.results, startTimes(t, t0).results...)
	if err := waitStablePostmasterQ(context.Background(), &q, time.Millisecond, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("restart errors must not fail the wait, got %v", err)
	}
}

func TestWaitStablePostmaster_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	q := startTimes(t, base)
	if err := waitStablePostmasterQ(ctx, &q, time.Millisecond, time.Now().Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context must surface context.Canceled, got %v", err)
	}
}

func TestPostmasterStable(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	if postmasterStable(time.Time{}, false, t0) {
		t.Fatalf("first poll must not be stable")
	}
	if postmasterStable(t0.Add(time.Second), true, t0) {
		t.Fatalf("changed start time must not be stable")
	}
	if !postmasterStable(t0, true, t0) {
		t.Fatalf("repeated start time must be stable")
	}
}

func TestCoreTablesPresentQ(t *testing.T) {
	ctx := context.Background()
	ok := stubQuerier{results: []stubRow{{scan: func(dest ...any) error {
		n := dest[0].(*int)
		*n = 2
		return nil
	}}}}
	if !coreTablesPresentQ(ctx, &ok) {
		t.Fatalf("2 core tables must count as present")
	}
	missing := stubQuerier{results: []stubRow{{scan: func(dest ...any) error {
		n := dest[0].(*int)
		*n = 0
		return nil
	}}}}
	if coreTablesPresentQ(ctx, &missing) {
		t.Fatalf("0 core tables must count as absent")
	}
	broken := stubQuerier{results: []stubRow{{scan: func(dest ...any) error { return errors.New("relation does not exist") }}}}
	if coreTablesPresentQ(ctx, &broken) {
		t.Fatalf("query error must count as absent")
	}
}
