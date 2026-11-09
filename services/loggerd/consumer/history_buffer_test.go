package consumer

// N10-P04-T02 tests for the durable history buffer (owner decisions I40/I44).
//
// The Redis stream IS the bounded durable buffer that survives restart; XACK
// after the durable Postgres commit is the explicit acknowledgement; the
// HistoryBufferGate's XLEN probe is the backpressure signal. These tests pin:
//
//   - saturation -> ErrHistoryBufferFull + exactly one loud log transition
//     (hysteresis: no flapping, no per-iteration log spam);
//   - probe failure (store seam: full disk / unreachable Redis) -> fail-closed
//     ErrHistoryBufferFull, never a quiet all-clear;
//   - disarmed (nil gate / nil prober / non-positive bound / mocks without
//     XLen) -> zero behavior change, zero probes, zero logs;
//   - bounded probing: exactly one probe per Evaluate, no goroutines;
//   - the consume loop evaluates the gate every iteration but never gates
//     consumption itself (admission wiring is deliberately N10-P04-T03);
//   - restart semantics: entries acked after their durable persist are never
//     re-consumed (consumer-group last-delivered-id), and an entry whose
//     store write failed stays unacked and recoverable in the PEL — a full
//     store outage never becomes a quiet successful save.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProber is a controllable BufferProber: XLen answers depth/err.
type fakeProber struct {
	mu    sync.Mutex
	depth int64
	err   error
	calls int
}

func (f *fakeProber) set(depth int64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.depth, f.err = depth, err
}

func (f *fakeProber) probeCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeProber) XLen(ctx context.Context, _ string) *redis.IntCmd {
	f.mu.Lock()
	f.calls++
	depth, perr := f.depth, f.err
	f.mu.Unlock()
	cmd := redis.NewIntCmd(ctx)
	if perr != nil {
		cmd.SetErr(perr)
		return cmd
	}
	cmd.SetVal(depth)
	return cmd
}

func testLogBuffer() (*bytes.Buffer, *slog.Logger) {
	buf := &bytes.Buffer{}
	return buf, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func countLogs(buf *bytes.Buffer, substr string) int {
	return strings.Count(buf.String(), substr)
}

func TestHistoryBufferGate_SaturationSignalsWithHysteresis(t *testing.T) {
	buf, logger := testLogBuffer()
	p := &fakeProber{depth: 50}
	g := NewHistoryBufferGate(p, "events:queue", 100, logger)
	ctx := context.Background()

	require.NoError(t, g.Evaluate(ctx))
	assert.False(t, g.Saturated())
	assert.Equal(t, int64(50), g.Depth())

	// Saturation at the bound: the sentinel fires, the gate latches and the
	// transition is logged exactly once.
	p.set(100, nil)
	err := g.Evaluate(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryBufferFull)
	assert.True(t, g.Saturated())
	assert.Equal(t, 1, countLogs(buf, "history buffer saturated"))

	// Hysteresis hold: between the recover floor (90%) and the bound the
	// signal stays active without a fresh transition log.
	p.set(95, nil)
	err = g.Evaluate(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryBufferFull)
	assert.True(t, g.Saturated())
	assert.Equal(t, 1, countLogs(buf, "history buffer saturated"), "no duplicate saturation log while holding")

	// Recovery only below the recover floor: signal clears, one Info.
	p.set(89, nil)
	require.NoError(t, g.Evaluate(ctx))
	assert.False(t, g.Saturated())
	assert.Equal(t, 1, countLogs(buf, "history buffer recovered"))

	// A second saturation is a new state transition and is observable too.
	p.set(100, nil)
	err = g.Evaluate(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryBufferFull)
	assert.Equal(t, 2, countLogs(buf, "history buffer saturated"))

	// Exactly one probe per Evaluate — bounded, no background sampler.
	assert.Equal(t, 5, p.probeCalls())
}

func TestHistoryBufferGate_ProbeFailureFailsClosed(t *testing.T) {
	buf, logger := testLogBuffer()
	p := &fakeProber{depth: 10}
	g := NewHistoryBufferGate(p, "events:queue", 100, logger)
	ctx := context.Background()
	require.NoError(t, g.Evaluate(ctx))

	// Simulated store-seam failure (full disk / unreachable Redis): the
	// buffer capacity can no longer be verified. I40 fail-closed: the
	// sentinel is the loud outcome, never a quiet all-clear.
	boom := errors.New("XLEN: NOGROUP disk full / connection refused")
	p.set(0, boom)
	err := g.Evaluate(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryBufferFull)
	assert.Contains(t, err.Error(), "capacity probe failed")
	assert.Contains(t, err.Error(), boom.Error())
	assert.True(t, g.Saturated())
	assert.Equal(t, 1, countLogs(buf, "history buffer saturated"))

	// The held signal repeats on every evaluation without new log spam.
	err = g.Evaluate(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryBufferFull)
	assert.True(t, g.Saturated())
	assert.Equal(t, 1, countLogs(buf, "history buffer saturated"))
}

func TestHistoryBufferGate_DisarmedIsZeroBehavior(t *testing.T) {
	buf, logger := testLogBuffer()
	ctx := context.Background()

	// nil prober: nothing to probe, nothing to signal.
	g := NewHistoryBufferGate(nil, "events:queue", 100, logger)
	require.NoError(t, g.Evaluate(ctx))
	assert.False(t, g.Saturated())

	// Non-positive bound: unmeasurable bound never fabricates saturation.
	p := &fakeProber{depth: 1_000_000}
	for _, bound := range []int64{0, -5} {
		g = NewHistoryBufferGate(p, "events:queue", bound, logger)
		require.NoError(t, g.Evaluate(ctx))
		assert.False(t, g.Saturated())
	}
	assert.Equal(t, 0, p.probeCalls(), "a disarmed gate never probes")

	// nil receiver is safe: advisory call sites must never panic.
	var ng *HistoryBufferGate
	require.NoError(t, ng.Evaluate(ctx))
	assert.False(t, ng.Saturated())
	assert.Equal(t, int64(-1), ng.Depth())

	assert.Empty(t, buf.String(), "a disarmed gate logs nothing")
}

// proberMockRedis extends mockRedis with XLen: it satisfies BufferProber the
// way the production *redis.Client does through redisXAckWrapper.
type proberMockRedis struct{ *mockRedis }

func (p *proberMockRedis) XLen(ctx context.Context, _ string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(1)
	return cmd
}

func TestNewWithCreditStore_BufferGateArming(t *testing.T) {
	// Mocks without XLen — every pre-existing test mock — stay disarmed:
	// zero behavior change.
	c := New(&mockRedis{}, &mockDB{}, "events:queue", slog.Default())
	assert.Nil(t, c.bufferGate, "a non-probing rdb must leave the gate disarmed")

	c = New(&proberMockRedis{mockRedis: &mockRedis{}}, &mockDB{}, "events:queue", slog.Default())
	require.NotNil(t, c.bufferGate)
	assert.Equal(t, "events:queue", c.bufferGate.stream)
	assert.Equal(t, int64(DefaultHistoryBufferMaxEntries), c.bufferGate.maxEntries)
	assert.False(t, c.bufferGate.Saturated())
	assert.Equal(t, int64(-1), c.bufferGate.Depth())

	// An empty stream name is defaulted to the default stream before the
	// arming check — the gate probes exactly the stream the consumer reads.
	c = New(&proberMockRedis{mockRedis: &mockRedis{}}, &mockDB{}, "", slog.Default())
	require.NotNil(t, c.bufferGate)
	assert.Equal(t, defaultStream, c.bufferGate.stream)

	// The wire-before-Start seam replaces or disarms the gate.
	small := NewHistoryBufferGate(&fakeProber{depth: 99}, "events:queue", 100, slog.Default())
	c = New(&proberMockRedis{mockRedis: &mockRedis{}}, &mockDB{}, "events:queue", slog.Default())
	c.SetHistoryBufferGate(nil)
	assert.Nil(t, c.bufferGate)
	c.SetHistoryBufferGate(small)
	assert.Same(t, small, c.bufferGate)
}

func TestHistoryBufferGate_BoundedProbingNoGoroutines(t *testing.T) {
	p := &fakeProber{depth: 1}
	g := NewHistoryBufferGate(p, "events:queue", 100, slog.New(slog.DiscardHandler))

	before := runtime.NumGoroutine()
	const workers, iters = 8, 250
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for j := 0; j < iters; j++ {
				_ = g.Evaluate(ctx)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, workers*iters, p.probeCalls(), "exactly one probe per Evaluate — bounded, no background sampling")

	assert.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= before+2
	}, 2*time.Second, 20*time.Millisecond, "the gate leaves no goroutines behind")
}

// groupStateRedis is a minimal in-memory consumer-group Redis: it models the
// group's last-delivered-id (">" reads), the PEL and XACK so restart
// semantics can be pinned without a live Redis. Methods not overridden are
// inherited from mockRedis (empty pending probes, no-op claim).
type groupStateRedis struct {
	*mockRedis

	mu               sync.Mutex
	entries          []redis.XMessage
	lastID           string
	pel              map[string]bool
	acks             []string
	groupCreated     bool
	groupCreateCalls int
	depth            int64
	xlenCalls        int
	ackWatch         func(id string)
}

func newGroupStateRedis(entries ...redis.XMessage) *groupStateRedis {
	return &groupStateRedis{
		mockRedis: &mockRedis{},
		entries:   entries,
		pel:       map[string]bool{},
		depth:     -1,
	}
}

func (g *groupStateRedis) setDepth(d int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.depth = d
}

func (g *groupStateRedis) addEntry(m redis.XMessage) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entries = append(g.entries, m)
}

func (g *groupStateRedis) XGroupCreateMkStream(ctx context.Context, stream, group, start string) *redis.StatusCmd {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.groupCreateCalls++
	cmd := redis.NewStatusCmd(ctx)
	if g.groupCreated {
		// The group persists in Redis across restarts: the restarted
		// consumer hits BUSYGROUP and must keep going.
		cmd.SetErr(errors.New("BUSYGROUP Consumer Group name already exists"))
		return cmd
	}
	g.groupCreated = true
	cmd.SetVal("OK")
	return cmd
}

func (g *groupStateRedis) XReadGroup(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
	cmd := redis.NewXStreamSliceCmd(ctx)
	g.mu.Lock()
	var out []redis.XMessage
	for _, e := range g.entries {
		if g.lastID == "" || e.ID > g.lastID {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		g.mu.Unlock()
		time.Sleep(time.Millisecond) // throttle: a block-ish read without a busy spin
		cmd.SetErr(redis.Nil)
		return cmd
	}
	g.lastID = out[len(out)-1].ID
	for _, e := range out {
		g.pel[e.ID] = true
	}
	cmd.SetVal([]redis.XStream{{Stream: args.Streams[0], Messages: out}})
	g.mu.Unlock()
	return cmd
}

func (g *groupStateRedis) XAck(ctx context.Context, stream, group string, ids []string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	g.mu.Lock()
	for _, id := range ids {
		delete(g.pel, id)
		g.acks = append(g.acks, id)
	}
	watch := g.ackWatch
	g.mu.Unlock()
	cmd.SetVal(int64(len(ids)))
	if watch != nil {
		for _, id := range ids {
			watch(id)
		}
	}
	return cmd
}

func (g *groupStateRedis) XLen(ctx context.Context, stream string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	g.mu.Lock()
	g.xlenCalls++
	d := g.depth
	g.mu.Unlock()
	cmd.SetVal(d)
	return cmd
}

// probeCalls reports how many XLEN probes the double has answered. The
// Eventually poller in TestConsume_EvaluatesGateWithoutGatingConsumption
// reads it while the consumer goroutine keeps probing, so the observation
// must share the double's mutex with the XLen increment — a direct field
// read races with it (BASE-FIX-6, caught by -race under load).
func (g *groupStateRedis) probeCalls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.xlenCalls
}

func (g *groupStateRedis) ackCount(id string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, a := range g.acks {
		if a == id {
			n++
		}
	}
	return n
}

func (g *groupStateRedis) pelContains(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pel[id]
}

// storeOutageRow is a pgx.Row whose Scan fails — a store that does not
// answer. Distinct from wlogg_stream_test.go's errRow on purpose: this one
// models the N10-P04 store-seam failure (full disk / unreachable store).
type storeOutageRow struct{ err error }

func (r *storeOutageRow) Scan(dest ...any) error { return r.err }

func TestConsume_EvaluatesGateWithoutGatingConsumption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := newGroupStateRedis(redis.XMessage{ID: "1-1", Values: map[string]interface{}{
		"event_type": "generic.event", "source": "test",
	}})
	g.setDepth(10) // way over the small test bound

	c := New(g, &mockDB{}, "events:queue", slog.Default())
	c.SetHistoryBufferGate(NewHistoryBufferGate(g, "events:queue", 5, slog.Default()))

	go func() { _ = c.Start(ctx) }()

	// The gate saturates AND the message is still delivered and acked: the
	// signal is advisory — the consume loop never gates consumption itself
	// (draining the backlog is the way out; admission is N10-P04-T03).
	assert.Eventually(t, func() bool {
		return c.bufferGate.Saturated() && g.ackCount("1-1") == 1 && g.probeCalls() > 0
	}, 3*time.Second, 20*time.Millisecond)

	c.Stop()
}

// TestGroupStateRedis_ProbeCounterSafeUnderConcurrentProbing pins the
// BASE-FIX-6 contract on the double: the probe counter is incremented by
// XLen (the consumer goroutine's per-iteration gate probe) and observed
// from another goroutine (the Eventually poller), so both sides must share
// the double's mutex. Without the lock this test fails under -race on
// essentially every run — millions of unordered read/write pairs — instead
// of by scheduler luck as the original unsynchronized closure read did
// (history_buffer_test.go:400, fired 10/10 at -race -count=20).
func TestGroupStateRedis_ProbeCounterSafeUnderConcurrentProbing(t *testing.T) {
	g := newGroupStateRedis()

	const writers, probes = 4, 2500
	var writersWG sync.WaitGroup
	for i := 0; i < writers; i++ {
		writersWG.Add(1)
		go func() {
			defer writersWG.Done()
			ctx := context.Background()
			for j := 0; j < probes; j++ {
				_ = g.XLen(ctx, "events:queue")
			}
		}()
	}

	// Poller side: exactly the access pattern the assertion closure uses
	// while the consume goroutine is still serving probes.
	done := make(chan struct{})
	go func() {
		writersWG.Wait()
		close(done)
	}()
	for {
		select {
		case <-done:
			assert.Equal(t, writers*probes, g.probeCalls(),
				"every probe is accounted: increment and observation share the mutex")
			return
		default:
			g.probeCalls()
			runtime.Gosched()
		}
	}
}

func TestRestart_AckedAfterDurablePersistNotReconsumed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logMu sync.Mutex
	var events []string
	add := func(s string) { logMu.Lock(); events = append(events, s); logMu.Unlock() }
	index := func(s string) int {
		logMu.Lock()
		defer logMu.Unlock()
		for i, e := range events {
			if e == s {
				return i
			}
		}
		return -1
	}

	completed := func(id string) redis.XMessage {
		return redis.XMessage{ID: id, Values: map[string]interface{}{
			"event_type": "request.completed", "source": "gateway",
			"session_id": "sess-1", "org_id": "org-abc",
			"request_id": "req-" + id, "model_used": "gpt-4",
		}}
	}
	g := newGroupStateRedis(completed("1-1"), completed("2-1"))
	g.ackWatch = func(id string) { add("ack:" + id) }

	// Store seam: req-acked's request_logs INSERT succeeds (marker recorded
	// in order); req-unacked's INSERT fails AND the liveness probe fails — a
	// full store outage. The failed entry must stay UNACKED in the PEL with
	// the consumer paused (loud), never a quiet ack-as-success.
	pool := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(query, "INSERT INTO request_logs") {
				if strings.Contains(fmt.Sprint(args), "req-2-1") {
					return pgconn.CommandTag{}, errors.New("simulated full disk: No space left on device")
				}
				add("persist:req-1-1")
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		QueryRowFn: func(_ context.Context, _ string, args ...any) pgx.Row {
			if len(args) == 0 {
				// The SELECT 1 probe answers nothing: the store is down.
				return &storeOutageRow{err: errors.New("simulated store outage")}
			}
			return &fakeRow{vals: []any{args[0]}}
		},
	}

	c1 := New(g, pool, "events:queue", slog.Default())
	c1.outagePause = time.Millisecond // shrink the outage backoff seam
	go func() { _ = c1.Start(ctx) }()

	// E1: acked exactly once, strictly after its durable write. The insert
	// marker is recorded inside the delivery transaction; a failed commit
	// would suppress the ack entirely (the delivery error path pauses and
	// never acks), so ack ⇒ committed, and marker < ack ⇒ the explicit XACK
	// acknowledgement happens only after the durable persist.
	assert.Eventually(t, func() bool { return g.ackCount("1-1") == 1 }, 3*time.Second, 20*time.Millisecond)
	c1.Stop()

	assert.Equal(t, 1, g.ackCount("1-1"))
	assert.GreaterOrEqual(t, index("persist:req-1-1"), 0)
	assert.Greater(t, index("ack:1-1"), index("persist:req-1-1"), "XACK must follow the durable persist, not precede it")

	// E2: full-disk write failure is loud — no ack, no DLQ shortcut; the
	// entry stays recoverable in the PEL.
	assert.Equal(t, 0, g.ackCount("2-1"), "a failed store write must never be acked as success")
	assert.True(t, g.pelContains("2-1"), "the failed entry stays pending and recoverable in the PEL")

	// Restart: a new consumer over the same persisted group state. The
	// group create hits BUSYGROUP (the group survived), acked E1 is never
	// re-consumed, E2 is not silently dropped (still pending), and new
	// entries keep flowing.
	g.addEntry(completed("3-1"))
	c2 := New(g, &mockDB{}, "events:queue", slog.Default())
	go func() { _ = c2.Start(ctx) }()

	assert.Eventually(t, func() bool { return g.ackCount("3-1") == 1 }, 3*time.Second, 20*time.Millisecond)
	c2.Stop()

	assert.Equal(t, 2, g.groupCreateCalls, "the restart path re-uses the persisted group (BUSYGROUP)")
	assert.Equal(t, 1, g.ackCount("1-1"), "acked durable history is never re-consumed after restart")
	assert.Equal(t, 0, g.ackCount("2-1"), "the unacked entry is not silently dropped either")
	assert.True(t, g.pelContains("2-1"), "the unacked entry remains in the PEL for the reclaim path")
	assert.Equal(t, 1, g.ackCount("3-1"), "new entries keep flowing after restart")
}
