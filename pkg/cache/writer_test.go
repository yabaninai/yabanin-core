package cache

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
)

// TestWriter_Stats verifies Stats() returns correct counts.
func TestWriter_Stats(t *testing.T) {
	w := NewWriter(context.Background(), nil, nil, nil)

	q, d, wr := w.Stats()
	if q != 0 || d != 0 || wr != 0 {
		t.Errorf("initial stats: queued=%d dropped=%d written=%d, expected all 0", q, d, wr)
	}

	w.Submit(writerJob{orgID: "test"})
	q2, _, _ := w.Stats()
	if q2 != 1 {
		t.Errorf("after submit: expected queued=1, got %d", q2)
	}
	if d != 0 {
		t.Errorf("after submit: expected dropped=0, got %d", d)
	}

	w.Stop()
}

// TestWriter_StopDrainsAfterCtxCancel is the C2 guarantee: cancelling the
// lifecycle ctx must NOT cause queued jobs to be silently lost. Workers only
// exit on channel close, so Stop() drains the queue even after ctx is done.
func TestWriter_StopDrainsAfterCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := NewWriter(ctx, nil, nil, nil)

	const n = 50
	for i := 0; i < n; i++ {
		if !w.Submit(writerJob{orgID: "test"}) {
			t.Fatalf("Submit %d failed (queue full?)", i)
		}
	}

	// Cancel the lifecycle ctx while jobs are still queued, then stop.
	cancel()
	w.Stop()

	queued, dropped, _ := w.Stats()
	if queued != n {
		t.Errorf("queued = %d, want %d (every job must be accepted)", queued, n)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0 (no job may be lost to ctx cancel)", dropped)
	}
	if got := len(w.queue); got != 0 {
		t.Errorf("queue length after Stop = %d, want 0 (must be fully drained)", got)
	}
	failed, skipped := w.OutcomeStats()
	if skipped != n {
		t.Errorf("skipped = %d, want %d (response-less jobs must resolve to the RT-05 skip outcome)", skipped, n)
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}
}

// TestWriter_SubmitAfterStopDrops verifies Submit returns false and counts a
// drop once Stop has begun (no write to a closed channel).
func TestWriter_SubmitAfterStopDrops(t *testing.T) {
	w := NewWriter(context.Background(), nil, nil, nil)
	w.Stop()

	if w.Submit(writerJob{orgID: "test"}) {
		t.Error("Submit after Stop must return false")
	}
	_, dropped, _ := w.Stats()
	if dropped != 1 {
		t.Errorf("dropped = %d after post-Stop Submit, want 1", dropped)
	}
}

// blockingEmbedder blocks until its ctx is cancelled or it is released, so a
// job pins a worker and keeps other jobs queued. A realistic slow embedder
// respects the deadline carried by the context.
type blockingEmbedder struct {
	release chan struct{}
}

func (b *blockingEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	select {
	case <-b.release:
		return []float32{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// deadPool returns a pgx pool pointed at a refused port: Put always errors
// without hanging, which lets tests exercise the failed outcome.
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(),
		"host=127.0.0.1 port=1 user=cache dbname=cache sslmode=disable")
	if err != nil {
		t.Fatalf("dead pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestWriter_StopTimeoutCountsUndrained verifies the drain-timeout contract:
// when workers cannot drain within the timeout, StopWithTimeout reports an
// incomplete drain, the still-buffered jobs are counted as dropped exactly
// once (never written), and the call still waits for worker termination —
// bounded by the per-write deadline, so a pinned embedder cannot hang it.
func TestWriter_StopTimeoutCountsUndrained(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	w := NewWriter(context.Background(), deadPool(t), &blockingEmbedder{release: release},
		slog.New(slog.DiscardHandler))
	w.writeTimeout = 300 * time.Millisecond // bound the pinned in-flight writes

	// RT-05: every job carries a sealable response — a job without one is
	// skipped before the embedder and would never block a worker.
	blocker := writerJob{orgID: "blocker", response: json.RawMessage(`{"id":"b"}`)}
	queuedJob := writerJob{orgID: "queued", response: json.RawMessage(`{"id":"q"}`)}

	// 4 workers; submit one job that will block, then a burst that stays queued.
	if !w.Submit(blocker) {
		t.Fatal("first Submit failed")
	}
	// Let the blocker be picked up by a worker before the timeout window opens.
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 32; i++ {
		w.Submit(queuedJob)
	}

	_, droppedBefore, _ := w.Stats()
	if drained := w.StopWithTimeout(100 * time.Millisecond); drained {
		t.Error("StopWithTimeout must report an incomplete drain when the timeout elapses")
	}
	queued, droppedAfter, written := w.Stats()
	if droppedAfter <= droppedBefore {
		t.Errorf("dropped did not increase on timeout (before=%d after=%d); undrained jobs must be counted", droppedBefore, droppedAfter)
	}
	if written != 0 {
		t.Errorf("written = %d, want 0: abandoned jobs must never be counted as written", written)
	}
	// Workers have terminated: accepted = dequeued + abandoned, exactly.
	if _, skipped := w.OutcomeStats(); skipped != 0 {
		t.Errorf("skipped = %d, want 0 (sealable jobs must not resolve as skipped)", skipped)
	}
	if queued != 33 {
		t.Errorf("queued = %d, want 33 (1 blocker + 32 burst)", queued)
	}
	// Repeated Stop must stay safe and return the remembered wait-result.
	if drained := w.StopWithTimeout(time.Second); drained {
		t.Error("repeated StopWithTimeout must return the remembered incomplete-drain result")
	}
}

// TestWriter_WriteBoundedByDeadline verifies a hung embedder cannot pin a
// worker forever: the per-write deadline ends the job, which resolves to the
// failed outcome (never written), and Stop returns bounded.
func TestWriter_WriteBoundedByDeadline(t *testing.T) {
	w := NewWriter(context.Background(), deadPool(t), &blockingEmbedder{release: make(chan struct{})},
		slog.New(slog.DiscardHandler))
	w.writeTimeout = 100 * time.Millisecond

	if !w.Submit(writerJob{orgID: "hung", response: json.RawMessage(`{"id":"h"}`)}) {
		t.Fatal("Submit failed")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Stop()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return: the write deadline must end a hung embedder")
	}

	if _, _, written := w.Stats(); written != 0 {
		t.Errorf("written = %d, want 0 (deadline-canceled job is not persisted)", written)
	}
	if failed, _ := w.OutcomeStats(); failed != 1 {
		t.Errorf("failed = %d, want 1 (the job must resolve as failed)", failed)
	}
}

// TestWriter_WriteError_CountedFailedNotWritten verifies a persistence error
// lands in the distinct failed outcome and never in written.
func TestWriter_WriteError_CountedFailedNotWritten(t *testing.T) {
	w := NewWriter(context.Background(), deadPool(t), nil, slog.New(slog.DiscardHandler))

	if !w.Submit(writerJob{orgID: "org", response: json.RawMessage(`{"id":"1"}`)}) {
		t.Fatal("Submit failed")
	}
	w.Stop()

	_, _, written := w.Stats()
	failed, skipped := w.OutcomeStats()
	if written != 0 {
		t.Errorf("written = %d, want 0 (persistence error must not count as written)", written)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (a sealable job is not an RT-05 skip)", skipped)
	}
}

// TestWriter_StatsTransitions_QueuedToSkipped verifies the admission counter
// moves at Submit and every job resolves into exactly one outcome bucket.
func TestWriter_StatsTransitions_QueuedToSkipped(t *testing.T) {
	w := NewWriter(context.Background(), nil, nil, slog.New(slog.DiscardHandler))

	const n = 3
	for i := 0; i < n; i++ {
		if !w.Submit(writerJob{orgID: "t"}) { // no response: RT-05 skip outcome
			t.Fatalf("Submit %d failed", i)
		}
	}
	q, d, wr := w.Stats()
	if q != n || d != 0 || wr != 0 {
		t.Fatalf("after submit: queued=%d dropped=%d written=%d, want %d/0/0", q, d, wr, n)
	}

	w.Stop()

	q, d, wr = w.Stats()
	failed, skipped := w.OutcomeStats()
	if q != n {
		t.Errorf("queued = %d, want %d (admission counter is stable)", q, n)
	}
	if d != 0 || wr != 0 || failed != 0 || skipped != n {
		t.Errorf("outcomes: dropped=%d written=%d failed=%d skipped=%d, want 0/0/0/%d (exactly one bucket per job)",
			d, wr, failed, skipped, n)
	}
}

// TestWriter_StatsTransition_QueueFullIsDropped verifies the queue-full
// rejection counts as dropped and never as queued.
func TestWriter_StatsTransition_QueueFullIsDropped(t *testing.T) {
	w := &Writer{queue: make(chan writerJob, 2)}

	for i := 0; i < 5; i++ {
		w.Submit(writerJob{orgID: "t"})
	}
	q, d, _ := w.Stats()
	if q != 2 || d != 3 {
		t.Errorf("queued=%d dropped=%d, want 2/3 (exactly one bucket per attempt)", q, d)
	}
}

// TestWriter_SubmitNonBlocking verifies Submit is non-blocking.
func TestWriter_SubmitNonBlocking(t *testing.T) {
	w := NewWriter(context.Background(), nil, nil, nil)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			w.Submit(writerJob{orgID: "test"})
		}
		close(done)
	}()

	select {
	case <-done:
		// All submits completed without blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("Submit appears to be blocking")
	}

	w.Stop()
}

// TestWriter_ConcurrentSubmits_AllCountedNoRace is the AF-02 regression
// (ported from the audit fixture): 32 goroutines submit 128 jobs each into a
// queue sized exactly 4096. Every accepted job must be counted queued exactly
// once — the old plain-int64 counter lost updates (queued=4001/4096) and the
// race detector flagged the non-atomic increment.
func TestWriter_ConcurrentSubmits_AllCountedNoRace(t *testing.T) {
	const goroutines, jobs = 32, 128
	w := &Writer{queue: make(chan writerJob, goroutines*jobs)}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < jobs; j++ {
				w.Submit(writerJob{orgID: "af02"})
			}
		}()
	}
	close(start)
	wg.Wait()

	queued, dropped, written := w.Stats()
	if queued != goroutines*jobs {
		t.Errorf("queued counter=%d, accepted jobs=%d", queued, goroutines*jobs)
	}
	if dropped != 0 {
		t.Errorf("dropped=%d, want 0 (queue sized for the whole burst)", dropped)
	}
	if written != 0 {
		t.Errorf("written=%d, want 0 (no workers attached)", written)
	}
	if got := len(w.queue); got != goroutines*jobs {
		t.Errorf("queue holds %d jobs, want %d", got, goroutines*jobs)
	}
}

// TestWriter_SubmitStop_EventBarriers_NoPanic is the AF-02 Submit×Stop
// regression: submitters released by an event barrier race with a concurrent
// Stop. The old check-then-act stopped flag let Submit send on the closed
// queue (panic) and raced the counters; the barrier maximizes the overlap.
// Each attempt must resolve to exactly one of queued/dropped — no lost or
// double-counted jobs — and a post-stop Submit must be rejected.
func TestWriter_SubmitStop_EventBarriers_NoPanic(t *testing.T) {
	const rounds, submitters = 64, 8

	for round := 0; round < rounds; round++ {
		w := NewWriter(context.Background(), nil, nil, nil)

		var accepted, rejected atomic.Int64
		entered := make(chan struct{}, submitters)
		release := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < submitters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				entered <- struct{}{}
				<-release
				if w.Submit(writerJob{orgID: "race"}) {
					accepted.Add(1)
				} else {
					rejected.Add(1)
				}
			}()
		}
		for i := 0; i < submitters; i++ {
			<-entered // every submitter is inside Submit's critical path
		}

		stopDone := make(chan struct{})
		go func() {
			defer close(stopDone)
			close(release)
			w.Stop()
		}()

		wg.Wait()
		<-stopDone

		if w.Submit(writerJob{orgID: "late"}) {
			t.Fatalf("round %d: Submit after Stop must be rejected", round)
		}

		queued, dropped, _ := w.Stats()
		if queued != accepted.Load() {
			t.Fatalf("round %d: queued=%d but %d submits reported accepted", round, queued, accepted.Load())
		}
		if dropped != rejected.Load()+1 {
			t.Fatalf("round %d: dropped=%d but %d submits reported rejected (+1 late)", round, dropped, rejected.Load())
		}

		w.Stop() // repeated Stop must stay safe
	}
}

// TestWriter_ConcurrentStop_SameWaitResult verifies repeated and concurrent
// Stop calls are safe, all observe the same wait-result, and a later Submit
// is always rejected.
func TestWriter_ConcurrentStop_SameWaitResult(t *testing.T) {
	w := NewWriter(context.Background(), nil, nil, nil)
	for i := 0; i < 10; i++ {
		if !w.Submit(writerJob{orgID: "t"}) {
			t.Fatalf("Submit %d failed", i)
		}
	}

	const stoppers = 8
	results := make([]bool, stoppers)
	var wg sync.WaitGroup
	for i := 0; i < stoppers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = w.StopWithTimeout(2 * time.Second)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if !r {
			t.Errorf("stopper %d: StopWithTimeout = false, want true (drain must complete)", i)
		}
	}
	if w.Submit(writerJob{orgID: "late"}) {
		t.Error("Submit after concurrent stops must be rejected")
	}
}
