package cli

// Producer-side drop visibility (N12-P02, owner decision I40): an event
// that never leaves the gateway is the start of a history gap. publishEvent
// answers both drop classes with a silent-failure count — backlog_full when
// the in-process publish semaphore is saturated, publish_failed when the
// bounded retries against the stream are exhausted — so a queue/Redis
// outage is observable on /metrics instead of debug-log-only.

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
)

func publishDropEvent() *eventpub.Event {
	return &eventpub.Event{EventType: "request_completed", Source: "unit-test"}
}

func silentFailureValue(t *testing.T, place, reason string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.SilentFailuresTotal.WithLabelValues(place, reason))
}

// deadRedisPublisher is a publisher wired to a refused port: construction
// never dials, every Publish fails immediately — the unit shape of a queue
// outage, no Redis server needed. DialerRetries/MaxRetries pin that shape on
// go-redis >= 9.8, where the pool otherwise retries the dial (default 5
// attempts at 100ms backoff) and the command (default 3 retries with up to
// 1s backoff), stretching each Publish to the caller's context budget and
// blowing the bounded retry ladder's timing assumptions below.
func deadRedisPublisher() *eventpub.RedisPublisher {
	return eventpub.NewRedisPublisher(redis.NewClient(&redis.Options{
		Addr:          "127.0.0.1:1",
		DialerRetries: 1,
		MaxRetries:    -1,
	}), "events")
}

// requirePublishQuiescence pins the observation window for the shared
// drop-count metrics: every publish-worker slot is acquired (each worker
// holds its slot until after its counter increment, so a free slot means
// the goroutine finished) and then released, so a counter snapshot taken
// right after carries no contribution from a prior test's still-running
// publish. Package-random shuffle order exposed the race: a previous
// test's retry backoff landed its publish_failed increment after the next
// test's `before` snapshot, breaking exact delta assertions.
// The semaphore waits use a generous 10s deadline: the helper's job is to
// catch leaked tokens (a hang), not to bound publish latency, and the
// parallel -race quality gate can starve the retry ladder's ~650ms of
// backoff sleeps well past the old 1-2s deadlines.
func requirePublishQuiescence(t *testing.T) {
	t.Helper()
	for i := 0; i < cap(eventPublishSem); i++ {
		select {
		case eventPublishSem <- struct{}{}:
		case <-time.After(10 * time.Second):
			t.Fatalf("publish semaphore not empty at slot %d — leaked tokens", i)
		}
	}
	for i := 0; i < cap(eventPublishSem); i++ {
		<-eventPublishSem // cannot block: this helper holds every token
	}
}

// TestPublishEventBacklogFullCounted pins the synchronous drop path: a
// saturated in-process backlog skips the publish and increments
// event_publish{reason="backlog_full"} before publishEvent returns.
func TestPublishEventBacklogFullCounted(t *testing.T) {
	// Saturate the shared semaphore and HOLD the tokens for the whole test:
	// publishEvent must hit the full backlog, not a free slot. Fail cleanly
	// instead of deadlocking if a token leaked from another test's publish
	// goroutine.
	for i := 0; i < cap(eventPublishSem); i++ {
		select {
		case eventPublishSem <- struct{}{}:
		case <-time.After(10 * time.Second):
			t.Fatalf("publish semaphore not empty at slot %d — leaked tokens", i)
		}
	}
	defer func() {
		for i := 0; i < cap(eventPublishSem); i++ {
			select {
			case <-eventPublishSem:
			case <-time.After(10 * time.Second):
				t.Fatalf("publish semaphore did not drain at slot %d", i)
			}
		}
	}()

	before := silentFailureValue(t, "event_publish", "backlog_full")
	publishEvent(deadRedisPublisher(), testLogger(), publishDropEvent())
	require.InDelta(t, before+1, silentFailureValue(t, "event_publish", "backlog_full"),
		1e-9,
		"a backlog-full drop must be counted synchronously")
}

// TestPublishEventTerminalFailureCounted pins the exhausted-retries path:
// with every publish attempt refused, the drop is counted as
// event_publish{reason="publish_failed"} (asynchronously — the retries run
// on the publish goroutine).
func TestPublishEventTerminalFailureCounted(t *testing.T) {
	requirePublishQuiescence(t) // exact delta: no foreign publish may land after `before`
	before := silentFailureValue(t, "event_publish", "publish_failed")
	publishEvent(deadRedisPublisher(), testLogger(), publishDropEvent())
	require.Eventually(t, func() bool {
		return silentFailureValue(t, "event_publish", "publish_failed") == before+1
	}, 5*time.Second, 10*time.Millisecond,
		"a permanently failed publish (queue outage) must be counted")
}
