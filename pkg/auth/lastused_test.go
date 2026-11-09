package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

// execStore is a fake LastUsedStore: it records every UPDATE's key ids.
type execStore struct {
	mu    sync.Mutex
	batch [][]string
	block chan struct{} // non-nil: Exec blocks until closed
	fail  bool
}

func (s *execStore) Exec(_ context.Context, _ string, args ...interface{}) (pgconn.CommandTag, error) {
	if s.block != nil {
		<-s.block
	}
	ids, _ := args[0].([]string)
	s.mu.Lock()
	s.batch = append(s.batch, ids)
	s.mu.Unlock()
	if s.fail {
		return pgconn.NewCommandTag(""), context.DeadlineExceeded
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (s *execStore) written() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, b := range s.batch {
		ids = append(ids, b...)
	}
	return ids
}

func (s *execStore) flushCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batch)
}

// waitFor calls f until it returns true or the deadline passes; usage
// recording is asynchronous, so tests poll instead of sleeping fixed amounts.
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within deadline")
}

// at most one last_used_at UPDATE — usage is never written per request.
func TestLastUsedTracker_ThrottlesBurstToOneWrite(t *testing.T) {
	store := &execStore{}
	tr := NewLastUsedTracker(context.Background(), store, 128, 1, time.Minute)
	defer tr.Close()

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Touch("key-burst")
		}()
	}
	wg.Wait()
	tr.Close()

	assert.Len(t, store.written(), 1, "1000 touches inside one minute must yield one UPDATE")
}

// After the throttle window a new use is recorded again.
func TestLastUsedTracker_AllowsSecondWriteAfterInterval(t *testing.T) {
	store := &execStore{}
	tr := NewLastUsedTracker(context.Background(), store, 16, 1, 20*time.Millisecond)
	defer tr.Close()

	tr.Touch("key-a")
	waitFor(t, func() bool { return store.flushCalls() >= 1 })
	time.Sleep(40 * time.Millisecond) // past the 20ms window
	tr.Touch("key-a")
	waitFor(t, func() bool { return store.flushCalls() >= 2 })

	ids := store.written()
	assert.Len(t, ids, 2)
	assert.Equal(t, "key-a", ids[0])
	assert.Equal(t, "key-a", ids[1])
}

// A full queue drops the sample instead of blocking the caller: Touch latency
// stays O(mutex) even when the DB is stuck.
func TestLastUsedTracker_NeverBlocksWhenDBStuck(t *testing.T) {
	store := &execStore{block: make(chan struct{})}
	tr := NewLastUsedTracker(context.Background(), store, 1, 1, time.Minute)
	defer func() {
		close(store.block) // unstick the worker so Close can drain
		tr.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			tr.Touch("key-stuck")
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Touch blocked on a full queue — latency impact regression")
	}
}

// Concurrent touches to distinct keys: each key is written at most once per
// window, and every key lands in some batch (deduped per batch).
func TestLastUsedTracker_ConcurrentDistinctKeys(t *testing.T) {
	store := &execStore{}
	tr := NewLastUsedTracker(context.Background(), store, 256, 2, time.Minute)

	const keys = 25
	var wg sync.WaitGroup
	for i := 0; i < keys; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("key-%d", n)
			for j := 0; j < 20; j++ {
				tr.Touch(id)
			}
		}(i)
	}
	wg.Wait()
	tr.Close()

	ids := store.written()
	seen := map[string]int{}
	for _, id := range ids {
		seen[id]++
	}
	assert.Len(t, seen, keys, "every distinct key must be recorded")
	for id, n := range seen {
		assert.Equal(t, 1, n, "key %q written %d times inside one window", id, n)
	}
}

// A failing UPDATE must not panic the worker; the tracker stays usable.
func TestLastUsedTracker_SurvivesDBErrors(t *testing.T) {
	store := &execStore{fail: true}
	tr := NewLastUsedTracker(context.Background(), store, 8, 1, time.Minute)
	tr.Touch("key-err")
	tr.Close() // drains the queue; the failing Exec happens inside

	assert.Equal(t, 1, store.flushCalls(), "the attempted write is recorded even on failure")
}

func TestLastUsedTracker_CloseDrainsBufferedBacklog(t *testing.T) {
	store := &execStore{}
	tr := &LastUsedTracker{
		db:       store,
		queue:    make(chan string, 3),
		writeTTL: time.Second,
	}
	tr.queue <- "key-a"
	tr.queue <- "key-b"
	tr.queue <- "key-a" // duplicate ids in one batch should still write once
	close(tr.queue)
	tr.wg.Add(1)

	done := make(chan struct{})
	go func() {
		tr.worker(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not finish draining a closed queue within the deadline")
	}

	assert.Equal(t, 1, store.flushCalls(), "the buffered backlog should be written as one batch")
	written := store.written()
	assert.Len(t, written, 2, "each distinct queued key should be written exactly once")
	assert.ElementsMatch(t, []string{"key-a", "key-b"}, written)
}

// Empty ids and a nil tracker are no-ops (the gateway may run trackerless).
func TestLastUsedTracker_NoopGuards(t *testing.T) {
	var nilTracker *LastUsedTracker
	nilTracker.Touch("key-x") // must not panic

	store := &execStore{}
	tr := NewLastUsedTracker(context.Background(), store, 8, 1, time.Minute)
	tr.Touch("")
	tr.Close()
	assert.Empty(t, store.written())
}
