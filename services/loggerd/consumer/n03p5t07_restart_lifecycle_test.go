package consumer

// N03-P05-T07 boundary corpus (loggerd entry path): consumer lifecycle
// under restart. The ENT-04 leader-election wiring (services/run/loggerd.go)
// re-invokes consumer.Start on the SAME StreamConsumer instance every time
// this replica re-acquires leadership: Lead cancels the term context, waits
// for Start to return, then loops and calls the closure again. Restart is
// therefore a supported lifecycle, and the corpus pins its boundary:
//
//   - a restarted term must be fully live: a transient XREADGROUP error is
//     retried (the consume loop does not silently die behind a live lock);
//   - shutting a second term down must be clean: no double-close of shared
//     lifecycle state (which would crash the whole loggerd process from the
//     leader goroutine).
//
// Both pins are red while the lifecycle state (c.done) is created once in
// New and closed in Start: after the first term the channel stays closed,
// so the restarted loop's error select short-circuits to `return` and the
// second term's shutdown panics with "close of closed channel".

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// busyGroupCmd returns the BUSYGROUP error the normal restart path expects
// (the consumer group persists in Redis across terms).
func busyGroupCmd(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(errors.New("BUSYGROUP Consumer Group name already exists"))
	return cmd
}

// TestN03P5T07_ConsumerRestart_TransientErrorDoesNotKillSecondTerm pins
// leader re-acquisition: after a restart, the consume loop must survive
// transient Redis errors and keep polling — a silently dead consumer behind
// a held leader lock is exactly the "stale lock residue" this card hunts.
func TestN03P5T07_ConsumerRestart_TransientErrorDoesNotKillSecondTerm(t *testing.T) {
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	var mu sync.Mutex
	var term int // current term under test: transient errors only in term 2
	var readsInTerm int
	rdb := &mockRedis{
		XGroupCreateMkStreamFn: func(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
			return busyGroupCmd(ctx)
		},
		XReadGroupFn: func(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
			mu.Lock()
			readsInTerm++
			n := readsInTerm
			curTerm := term
			mu.Unlock()
			cmd := redis.NewXStreamSliceCmd(ctx)
			if curTerm == 2 && n <= 3 {
				// Transient store errors in the restarted term: the healthy
				// contract retries them instead of dying behind the lock.
				cmd.SetErr(errors.New("injected: transient redis blip"))
				return cmd
			}
			// Settled: idle until the term context ends.
			<-ctx.Done()
			cmd.SetErr(redis.Nil)
			return cmd
		},
	}

	sc := New(rdb, &mockDB{}, "t07-restart", slog.Default())

	// Term 1: start and stop cleanly (the leadership term that closes the
	// shared lifecycle state under the current implementation).
	mu.Lock()
	term = 1
	readsInTerm = 0
	mu.Unlock()
	term1 := make(chan error, 1)
	go func() { term1 <- sc.Start(ctx1) }()
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return readsInTerm >= 1
	}, 5*time.Second, 5*time.Millisecond, "term 1 consume loop never polled")
	cancel1()
	select {
	case err := <-term1:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("term 1 Start did not return after cancel")
	}

	// Term 2: leader re-acquired, consumer restarted on the same instance.
	mu.Lock()
	term = 2
	readsInTerm = 0
	mu.Unlock()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	term2 := make(chan error, 1)
	go func() { term2 <- sc.Start(ctx2) }()

	// The restarted loop must survive the three transient errors and keep
	// polling (4th call = healthy idle path). Under the defect it dies on
	// the first transient error via the stale closed done channel.
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := readsInTerm
		mu.Unlock()
		if n >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarted consume loop died behind a live leader lock: stopped at %d read calls", n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel2()
	select {
	case err := <-term2:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("term 2 Start did not return after cancel")
	}
}

// TestN03P5T07_ConsumerSecondTermShutdown_NoDoubleClosePanic pins the
// shutdown boundary: completing a second term must not panic. Under leader
// election the Start call runs inside the Lead goroutine, so a panic here
// kills the whole loggerd process.
func TestN03P5T07_ConsumerSecondTermShutdown_NoDoubleClosePanic(t *testing.T) {
	type startOutcome struct {
		err   error
		panic any
	}
	runStart := func(sc *StreamConsumer, ctx context.Context) <-chan startOutcome {
		out := make(chan startOutcome, 1)
		go func() {
			var o startOutcome
			defer func() { o.panic = recover(); out <- o }()
			o.err = sc.Start(ctx)
		}()
		return out
	}

	rdb := &mockRedis{
		XGroupCreateMkStreamFn: func(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
			return busyGroupCmd(ctx)
		},
	}
	sc := New(rdb, &mockDB{}, "t07-twoterm", slog.Default())

	for term := 1; term <= 2; term++ {
		ctx, cancel := context.WithCancel(context.Background())
		out := runStart(sc, ctx)
		cancel() // any interleaving is valid: the term ends, Start must return cleanly
		select {
		case o := <-out:
			require.Nilf(t, o.panic, "term %d shutdown panicked: %v", term, o.panic)
			require.NoErrorf(t, o.err, "term %d Start failed: %v", term, o.err)
		case <-time.After(5 * time.Second):
			t.Fatalf("term %d Start did not return after cancel", term)
		}
	}
}
