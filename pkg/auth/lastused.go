package auth

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// LastUsedStore is the minimal write surface the tracker needs (*pgxpool.Pool
// satisfies it).
type LastUsedStore interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
}

// LastUsedTracker records api_keys.last_used_at without ever writing on the
// request path. Touch is non-blocking: it consults an in-memory
// throttle (one write per key per minInterval at most), then hands the key id
// to a bounded queue drained by a fixed worker pool. A full queue drops the
// sample — usage tracking must never add latency or backpressure to a
// request. Workers issue the UPDATE with an independent context so a slow DB
// cannot stall callers either.
type LastUsedTracker struct {
	// baseCtx anchors the asynchronous UPDATEs: they must not be cancelled
	// when the request that sampled the key ends.
	baseCtx     context.Context
	db          LastUsedStore
	queue       chan string
	workers     int
	minInterval time.Duration
	writeTTL    time.Duration

	mu       sync.Mutex
	lastSeen map[string]time.Time
	prunedAt time.Time
	wg       sync.WaitGroup
	closeOne sync.Once
}

// Default tracker parameters: 1 update per key per minute,
// a queue of 4096 samples, 2 workers, 5s per UPDATE.
const (
	DefaultLastUsedInterval = time.Minute
	DefaultLastUsedQueue    = 4096
	DefaultLastUsedWorkers  = 2
	DefaultLastUsedWriteTTL = 5 * time.Second
)

// NewLastUsedTracker starts a tracker whose workers write through db. The
// context becomes the base for the asynchronous UPDATEs (they must outlive
// any request); pass context.Background() for a process-lifetime tracker.
// It returns immediately; Close waits for in-flight samples to drain.
func NewLastUsedTracker(ctx context.Context, db LastUsedStore, queueSize, workers int, minInterval time.Duration) *LastUsedTracker {
	if queueSize <= 0 {
		queueSize = DefaultLastUsedQueue
	}
	if workers <= 0 {
		workers = DefaultLastUsedWorkers
	}
	if minInterval <= 0 {
		minInterval = DefaultLastUsedInterval
	}
	t := &LastUsedTracker{
		baseCtx:     ctx,
		db:          db,
		queue:       make(chan string, queueSize),
		workers:     workers,
		minInterval: minInterval,
		writeTTL:    DefaultLastUsedWriteTTL,
		lastSeen:    map[string]time.Time{},
	}
	for i := 0; i < t.workers; i++ {
		t.wg.Add(1)
		go t.worker(ctx)
	}
	return t
}

// Touch records a use of apiKeyID. It never blocks: a key inside its throttle
// window or hitting a full queue is silently skipped.
func (t *LastUsedTracker) Touch(apiKeyID string) {
	if t == nil || apiKeyID == "" {
		return
	}
	now := time.Now()
	t.mu.Lock()
	if last, ok := t.lastSeen[apiKeyID]; ok && now.Sub(last) < t.minInterval {
		t.mu.Unlock()
		return
	}
	t.lastSeen[apiKeyID] = now
	if now.Sub(t.prunedAt) > 10*t.minInterval {
		// Bound the map by dropping stale entries: anything older than the
		// throttle window is equivalent to absent.
		for id, last := range t.lastSeen {
			if now.Sub(last) > 2*t.minInterval {
				delete(t.lastSeen, id)
			}
		}
		t.prunedAt = now
	}
	t.mu.Unlock()

	select {
	case t.queue <- apiKeyID:
	default:
		// Queue full: drop the sample. Correctness (≤1 write/min/key) is
		// preserved; only the timestamp may lag by up to one interval.
	}
}

// Close stops accepting samples and waits for queued ones to flush. Touch
// must not be called after Close (it would panic on the closed queue), which
// matches the gateway's lifetime: the tracker is closed only at shutdown.
// Close is idempotent.
func (t *LastUsedTracker) Close() {
	t.closeOne.Do(func() { close(t.queue) })
	t.wg.Wait()
}

func (t *LastUsedTracker) worker(ctx context.Context) {
	// Batch a drain window: dedupe key ids so a burst for one key costs one
	// UPDATE, and cap the batch to keep single statements small.
	const maxBatch = 64
	for first := range t.queue {
		batch := map[string]struct{}{first: {}}
	drain:
		for len(batch) < maxBatch {
			select {
			case id, ok := <-t.queue:
				if !ok {
					break drain
				}
				batch[id] = struct{}{}
			default:
				break drain
			}
		}
		ids := make([]string, 0, len(batch))
		for id := range batch {
			ids = append(ids, id)
		}
		ctx, cancel := context.WithTimeout(ctx, t.writeTTL)
		_, err := t.db.Exec(ctx,
			"UPDATE api_keys SET last_used_at = now() WHERE id = ANY($1)", ids)
		cancel()
		if err != nil {
			// Fail soft: usage timestamping must never disturb request flow.
			// The next Touch after the throttle window retries the key.
			continue
		}
	}
	t.wg.Done()
}
