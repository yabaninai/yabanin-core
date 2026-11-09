package consumer

// N10-P04-T03 tests for the history admission signal publisher (owner
// decisions I40/I44). The publisher is the inter-process seam between the
// loggerd consumer (which owns the only direct view of durable-history
// health) and the gateway's budget.RedisHistoryProbe. These tests pin:
//
//   - worst-wins state priority: a durable WRITE outage (store refused a
//     write) outranks a saturated buffer, which outranks ok;
//   - the write-outage latch is cleared only by a successful delivery, and
//     ClearWriteOutage deliberately publishes nothing — the next gate
//     observation heartbeats recovery within one iteration (a stale outage
//     signal is the safe direction under the default reject policy);
//   - transition logs fire exactly once per state change; steady heartbeats
//     and steady outages are silent;
//   - a failed Set is loud ONCE per failure run (then quiet until a success
//     resets it) — losing the signal never takes delivery down, and the
//     gateway fails closed on the stale key under the default policy;
//   - the wire payload round-trips through budget.ParseHistorySignal with
//     the agreed key and TTL heartbeat;
//   - arming: mocks without Set (every pre-existing test mock) stay
//     disarmed with zero behavior change; the seam replaces/disarms via
//     SetHistorySignalPublisher like every other wire-before-Start seam.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
)

// signalWriterFake is a HistorySignalWriter double: it records every Set so
// payload, key, TTL and call counts can be asserted without a live Redis.
type signalWriterFake struct {
	mu      sync.Mutex
	setErr  error
	lastKey string
	lastVal string
	lastTTL time.Duration
	calls   int
}

func (f *signalWriterFake) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastKey = key
	if s, ok := value.(string); ok {
		f.lastVal = s
	}
	f.lastTTL = expiration
	if f.setErr != nil {
		cmd.SetErr(f.setErr)
		return cmd
	}
	cmd.SetVal("OK")
	return cmd
}

func (f *signalWriterFake) setCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *signalWriterFake) last() (string, string, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastKey, f.lastVal, f.lastTTL
}

func (f *signalWriterFake) failWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setErr = err
}

func TestHistorySignalPublisher_DisarmedIsZeroBehavior(t *testing.T) {
	buf, logger := testLogBuffer()
	ctx := context.Background()

	// Nil receiver: the advisory call sites in the consume loop must never
	// panic (a consumer without the seam behaves exactly as before T03).
	var nilPub *HistorySignalPublisher
	nilPub.ObserveGate(ctx, nil, 0)
	nilPub.ObserveWriteOutage(ctx)
	nilPub.ClearWriteOutage()

	// nil writer: armed shape but nothing to write — publish is a no-op.
	p := NewHistorySignalPublisher(nil, "events:queue", logger)
	p.ObserveGate(ctx, errors.New("gate boom"), 99)
	p.ObserveWriteOutage(ctx)
	p.ClearWriteOutage()
	assert.Empty(t, buf.String(), "a disarmed publisher logs nothing")
}

func TestHistorySignalPublisher_WorstWinsPriority(t *testing.T) {
	buf, logger := testLogBuffer()
	fake := &signalWriterFake{}
	p := NewHistorySignalPublisher(fake, "events:queue", logger)
	ctx := context.Background()

	// Healthy gate: armed (first observation, Info) with an ok payload.
	p.ObserveGate(ctx, nil, 5)
	key, val, ttl := fake.last()
	assert.Equal(t, budget.HistorySignalKey("events:queue"), key)
	sig, err := budget.ParseHistorySignal([]byte(val))
	require.NoError(t, err)
	assert.Equal(t, budget.HistoryStateOK, sig.State)
	assert.Equal(t, int64(5), sig.Depth)
	assert.Equal(t, historySignalTTL, ttl, "the heartbeat TTL lease is exactly the agreed constant")
	assert.Equal(t, 1, countLogs(buf, "history admission signal armed"))

	// Buffer outage: the gate error folds into buffer_full (any gate
	// failure means capacity is unverifiable — never advertised healthy).
	p.ObserveGate(ctx, ErrHistoryBufferFull, 100)
	_, val, _ = fake.last()
	sig, err = budget.ParseHistorySignal([]byte(val))
	require.NoError(t, err)
	assert.Equal(t, budget.HistoryStateBufferFull, sig.State)
	assert.Equal(t, int64(100), sig.Depth)
	assert.Contains(t, sig.Detail, ErrHistoryBufferFull.Error())
	assert.Equal(t, 1, countLogs(buf, "history admission signal raised"))

	// Durable WRITE outage outranks the buffer outage (worst wins).
	p.ObserveWriteOutage(ctx)
	_, val, _ = fake.last()
	sig, err = budget.ParseHistorySignal([]byte(val))
	require.NoError(t, err)
	assert.Equal(t, budget.HistoryStateWriteUnavailable, sig.State)
	assert.Equal(t, "durable write unavailable (store outage)", sig.Detail)
	assert.Equal(t, 2, countLogs(buf, "history admission signal raised"), "each degrade transition is loud exactly once")

	// ClearWriteOutage deliberately publishes nothing: the latch drop is
	// only observable at the NEXT gate observation (within one consume
	// iteration; a stale outage signal is the safe direction).
	callsBefore := fake.setCalls()
	p.ClearWriteOutage()
	assert.Equal(t, callsBefore, fake.setCalls(), "the latch clear never publishes by itself")

	// The next gate observation heartbeats the recovered buffer_full —
	// write_unavailable → buffer_full is still a degraded state, so it
	// raises (re-logs the degradation), it does not clear.
	p.ObserveGate(ctx, ErrHistoryBufferFull, 100)
	_, val, _ = fake.last()
	sig, err = budget.ParseHistorySignal([]byte(val))
	require.NoError(t, err)
	assert.Equal(t, budget.HistoryStateBufferFull, sig.State)
	assert.Equal(t, 3, countLogs(buf, "history admission signal raised"))

	// And a fully healthy gate clears the signal exactly once.
	p.ObserveGate(ctx, nil, 7)
	_, val, _ = fake.last()
	sig, err = budget.ParseHistorySignal([]byte(val))
	require.NoError(t, err)
	assert.Equal(t, budget.HistoryStateOK, sig.State)
	assert.Equal(t, int64(7), sig.Depth)
	assert.Equal(t, 1, countLogs(buf, "history admission signal cleared"))
}

func TestHistorySignalPublisher_SteadyHeartbeatsAreSilent(t *testing.T) {
	buf, logger := testLogBuffer()
	fake := &signalWriterFake{}
	p := NewHistorySignalPublisher(fake, "events:queue", logger)
	ctx := context.Background()

	// Steady healthy: every iteration re-publishes (the TTL heartbeat must
	// keep flowing) but logs nothing after the arm transition.
	p.ObserveGate(ctx, nil, 1)
	require.Equal(t, 1, fake.setCalls())
	for i := 0; i < 5; i++ {
		p.ObserveGate(ctx, nil, 2)
	}
	assert.Equal(t, 6, fake.setCalls(), "the heartbeat keeps refreshing the key")
	assert.Equal(t, 1, countLogs(buf, "history admission"), "steady state is silent after the arm log")

	// Steady outage: loud once at the transition, then quiet — no per-
	// iteration spam while the signal keeps beating (the TTL heartbeat
	// must keep flowing through an outage too, or the key would expire and
	// the gateway would re-read "loggerd down" forever).
	p.ObserveWriteOutage(ctx)
	for i := 0; i < 5; i++ {
		p.ObserveWriteOutage(ctx)
	}
	assert.Equal(t, 12, fake.setCalls(), "1 arm + 5 steady ok + 1 raise + 5 steady outage heartbeats")
	assert.Equal(t, 1, countLogs(buf, "history admission signal raised"), "a held outage does not re-log")
}

func TestHistorySignalPublisher_PublishFailureIsLoudOnceThenQuiet(t *testing.T) {
	buf, logger := testLogBuffer()
	fake := &signalWriterFake{setErr: errors.New("redis connection refused")}
	p := NewHistorySignalPublisher(fake, "events:queue", logger)
	ctx := context.Background()

	// First publish fails: one loud Warn (the gateway will fail closed on
	// the expired key under the default reject policy — never silently).
	p.ObserveGate(ctx, nil, 1)
	assert.Equal(t, 1, countLogs(buf, "publish FAILED"))

	// The failure run stays quiet: the signal key is already stale, so
	// repeating the Warn every iteration would only bury real transitions.
	for i := 0; i < 5; i++ {
		p.ObserveGate(ctx, nil, 1)
	}
	assert.Equal(t, 6, fake.setCalls(), "publishing keeps being attempted")
	assert.Equal(t, 1, countLogs(buf, "publish FAILED"), "one Warn per failure run")

	// Recovery resets the quieting; the success transition to ok logs the
	// armed Info (first successful publish), not a failure.
	fake.failWith(nil)
	p.ObserveGate(ctx, nil, 1)
	require.Equal(t, 7, fake.setCalls())
	assert.Equal(t, 1, countLogs(buf, "publish FAILED"), "still exactly the one failure (reset, no spurious log)")

	// A NEW failure run is loud again.
	fake.failWith(errors.New("redis down again"))
	p.ObserveGate(ctx, nil, 1)
	assert.Equal(t, 2, countLogs(buf, "publish FAILED"), "a new failure run is loud again")
}

func TestHistorySignalPublisher_ConcurrentObservationsAreSafe(t *testing.T) {
	fake := &signalWriterFake{}
	p := NewHistorySignalPublisher(fake, "events:queue", slog.New(slog.DiscardHandler))

	const workers, iters = 4, 100
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			for j := 0; j < iters; j++ {
				switch (i + j) % 3 {
				case 0:
					p.ObserveGate(ctx, nil, int64(j))
				case 1:
					p.ObserveGate(ctx, ErrHistoryBufferFull, int64(j))
				case 2:
					p.ObserveWriteOutage(ctx)
					p.ClearWriteOutage()
				}
			}
		}(i)
	}
	wg.Wait()

	// Every observation attempted a publish; whatever state won, the last
	// payload must parse and carry a known state (safety pin only — with
	// racing workers the transition-log counts are deliberately not
	// asserted here; TestHistorySignalPublisher_WorstWinsPriority owns the
	// serial transition ledger).
	_, val, _ := fake.last()
	sig, err := budget.ParseHistorySignal([]byte(val))
	require.NoError(t, err)
	assert.NotEmpty(t, sig.State)
}

// signalWriterMockRedis extends mockRedis with Set: it satisfies
// HistorySignalWriter the way the production redisXAckWrapper/*redis.Client
// does, so NewWithCreditStore arms the publisher for it.
type signalWriterMockRedis struct{ *mockRedis }

func (s *signalWriterMockRedis) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func TestNewWithCreditStore_SignalPublisherArming(t *testing.T) {
	// Mocks without Set — every pre-existing test mock — stay disarmed:
	// zero behavior change (same contract as the T02 BufferProber arming).
	c := New(&mockRedis{}, &mockDB{}, "events:queue", slog.Default())
	assert.Nil(t, c.historySignal, "a non-writing rdb must leave the signal disarmed")

	c = New(&signalWriterMockRedis{mockRedis: &mockRedis{}}, &mockDB{}, "events:queue", slog.Default())
	require.NotNil(t, c.historySignal)
	assert.Equal(t, budget.HistorySignalKey("events:queue"), c.historySignal.key)

	// An empty stream name is defaulted before the arming check — the
	// publisher heartbeats exactly the stream the consumer reads.
	c = New(&signalWriterMockRedis{mockRedis: &mockRedis{}}, &mockDB{}, "", slog.Default())
	require.NotNil(t, c.historySignal)
	assert.Equal(t, budget.HistorySignalKey(defaultStream), c.historySignal.key)

	// The wire-before-Start seam replaces or disarms the publisher.
	repl := NewHistorySignalPublisher(&signalWriterFake{}, "events:queue", slog.Default())
	c = New(&signalWriterMockRedis{mockRedis: &mockRedis{}}, &mockDB{}, "events:queue", slog.Default())
	c.SetHistorySignalPublisher(nil)
	assert.Nil(t, c.historySignal)
	c.SetHistorySignalPublisher(repl)
	assert.Same(t, repl, c.historySignal)
}
