package resolver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-03 regressions (follow-up to RT-06): a cold alias book and an alias
// outage are NOT authoritative misses. They must surface as an explicit
// unavailable error (wrapped in ErrModelUnavailable) instead of falling
// through to the registry lookup of the requested name, where pgx.ErrNoRows
// triggers the RM-09 fallback — a successful call on the default model that
// the client never asked for.
//
// These tests exercise the public ResolveChecked contract so they compile
// against the pre-fix API; the red state is behavioral, not a compile error.
// Ports of the audit reproductions TestReview_ColdAliasMustNotBecomeSuccessfulFallback
// and TestReview_InitialAliasOutageMustNotBecomeSuccessfulFallback plus the
// AF-00 §E scenarios.

// af03Outcome is one ResolveChecked result.
type af03Outcome struct {
	info ModelInfo
	err  error
}

// af03Row builds a models_registry row in SELECT column order.
func af03Row(name string) []any {
	return []any{name, name + " display", "standard", "http://" + name, "", "openai", nil, true, int64(0), "EU"}
}

func af03Pool() *mockPool {
	return &mockPool{rows: map[string][]any{
		"alias-target":  af03Row("alias-target"),
		"default-model": af03Row("default-model"),
	}}
}

// af03CheckOutcome classifies one ResolveChecked result against the AF-03
// contract: either the alias target, or an explicit unavailable error. A
// successful resolution to any other model (in particular the default) with
// or without the Fallback flag is the defect this card closes.
func af03CheckOutcome(t *testing.T, out af03Outcome) {
	t.Helper()
	if out.err != nil {
		require.ErrorIs(t, out.err, ErrModelUnavailable,
			"an unavailable alias book must surface as ErrModelUnavailable, got %v", out.err)
		return
	}
	assert.Equal(t, "alias-target", out.info.ModelName,
		"cold alias request resolved to a different model")
	assert.False(t, out.info.Fallback, "alias hit must not be flagged as a fallback")
	assert.Equal(t, "client-alias", out.info.Alias, "alias provenance must be preserved")
}

// af03GatePool parks every registry query on a gate so the test can observe
// that a caller is deterministically inside the (defective) registry fallback
// path before the alias load is released. Every park signals parkSignal
// (non-blocking; the parked counter stays the source of truth).
type af03GatePool struct {
	inner      *mockPool
	gate       chan struct{}
	parked     atomic.Int64
	parkSignal chan struct{}
}

func (p *af03GatePool) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	p.parked.Add(1)
	select {
	case p.parkSignal <- struct{}{}:
	default:
	}
	select {
	case <-p.gate:
	case <-ctx.Done():
		return mockRow{scanFn: func(...any) error { return ctx.Err() }}
	}
	return p.inner.QueryRow(ctx, q, args...)
}

func (p *af03GatePool) Close() {}

func TestAliasLookup_ConcurrentColdLoad_YieldsTargetOrUnavailableNeverDefault(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	book := NewAliasBook(time.Minute, func(context.Context) (map[string]string, error) {
		once.Do(func() { close(entered) })
		<-release
		return map[string]string{"client-alias": "alias-target"}, nil
	}, nil)
	const callers = 8
	gate := make(chan struct{})
	pool := &af03GatePool{
		inner:      af03Pool(),
		gate:       gate,
		parkSignal: make(chan struct{}, callers),
	}
	r := NewResolver(pool, "default-model", time.Minute, nil)
	r.UseAliases(book)

	var wg sync.WaitGroup
	outcomes := make(chan af03Outcome, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := r.ResolveChecked(context.Background(), "client-alias")
			outcomes <- af03Outcome{info: info, err: err}
		}()
	}

	<-entered // first load in flight; the book is cold for everyone else
	// Determinism: hold the release until callers that take the (defective)
	// registry path are parked inside it. A fixed book never parks there —
	// its callers wait for the shared load instead — so the budgeted wait
	// expires once and the wait stays bounded and harmless.
	budget := time.NewTimer(500 * time.Millisecond)
	defer budget.Stop()
waitParks:
	for pool.parked.Load() < callers-1 {
		select {
		case <-pool.parkSignal:
		case <-budget.C:
			break waitParks
		}
	}
	close(release)
	close(gate) // unblock any caller parked inside the registry fallback path
	wg.Wait()
	close(outcomes)

	for out := range outcomes {
		af03CheckOutcome(t, out)
	}
}

func TestAliasLookup_InitialLoadOutage_IsUnavailableNotFallback(t *testing.T) {
	book := NewAliasBook(time.Minute, func(context.Context) (map[string]string, error) {
		return nil, errors.New("alias database unavailable")
	}, nil)
	r := NewResolver(af03Pool(), "default-model", time.Minute, nil)
	r.UseAliases(book)

	info, err := r.ResolveChecked(context.Background(), "client-alias")
	af03CheckOutcome(t, af03Outcome{info: info, err: err})
}

func TestAliasLookup_CancelledCallerDoesNotAbortSharedLoad(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	book := NewAliasBook(time.Minute, func(ctx context.Context) (map[string]string, error) {
		close(entered)
		select {
		case <-release:
			return map[string]string{"client-alias": "alias-target"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, nil)
	r := NewResolver(af03Pool(), "default-model", time.Minute, nil)
	r.UseAliases(book)

	// First caller goes cold, then its request is cancelled while the shared
	// load is parked: the load must keep going for everybody else.
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan af03Outcome, 1)
	go func() {
		info, err := r.ResolveChecked(ctx1, "client-alias")
		done1 <- af03Outcome{info: info, err: err}
	}()
	<-entered
	cancel1()
	out1 := <-done1
	if out1.err == nil {
		t.Fatalf("cancelled cold caller was served model %q; want unavailable", out1.info.ModelName)
	}
	require.ErrorIs(t, out1.err, ErrModelUnavailable)

	close(release)
	info, err := r.ResolveChecked(context.Background(), "client-alias")
	af03CheckOutcome(t, af03Outcome{info: info, err: err})
}

func TestAliasLookup_DeadlineCallerGetsUnavailableNotDefault(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // unblock the (shared) load for exit
	book := NewAliasBook(time.Minute, func(ctx context.Context) (map[string]string, error) {
		select {
		case <-release:
			return map[string]string{"client-alias": "alias-target"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, nil)
	r := NewResolver(af03Pool(), "default-model", time.Minute, nil)
	r.UseAliases(book)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	info, err := r.ResolveChecked(ctx, "client-alias")
	assert.Less(t, time.Since(start), 5*time.Second, "no request may wait unbounded on the alias load")
	af03CheckOutcome(t, af03Outcome{info: info, err: err})
}

func TestAliasLookup_OutageRecoversAfterTTL(t *testing.T) {
	var (
		clock = newFakeClock()
		fail  = true
	)
	book := NewAliasBook(time.Minute, func(context.Context) (map[string]string, error) {
		if fail {
			return nil, errors.New("alias database unavailable")
		}
		return map[string]string{"client-alias": "alias-target"}, nil
	}, nil)
	book.now = clock.now
	r := NewResolver(af03Pool(), "default-model", time.Minute, nil)
	r.UseAliases(book)

	// Outage: explicit unavailable, never the default model.
	info, err := r.ResolveChecked(context.Background(), "client-alias")
	af03CheckOutcome(t, af03Outcome{info: info, err: err})

	// Within the backoff window the DB error is not retried per request.
	_, err = r.ResolveChecked(context.Background(), "client-alias")
	require.ErrorIs(t, err, ErrModelUnavailable)

	// Recovery: after the TTL the book loads again and serves the alias.
	fail = false
	clock.advance(2 * time.Minute)
	info, err = r.ResolveChecked(context.Background(), "client-alias")
	require.NoError(t, err)
	assert.Equal(t, "alias-target", info.ModelName)
	assert.False(t, info.Fallback)
}
