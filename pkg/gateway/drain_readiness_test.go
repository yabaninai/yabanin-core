package cli

//
// N12-P03-T03 — readiness managed before stop (drain sequence tests).
//
// Deterministic by construction: no real signals (the outer force-exit path
// is services/run's awaitShutdownExit suite, N12-P03-T02), no wall-clock
// budgets (the sequence takes injected millisecond budgets), controlled
// in-flight requests (handler blocks on a test channel). Order assertions use
// the gate state and per-stage event records, never sleeps.
//

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discardLogger keeps drain-sequence logs out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// --- env knob -------------------------------------------------------------

func TestReadinessDrainDelay(t *testing.T) {
	t.Run("unset and blank fall back to the default", func(t *testing.T) {
		t.Setenv("YABANIN_READINESS_DRAIN_DELAY", "placeholder")
		require.NoError(t, os.Unsetenv("YABANIN_READINESS_DRAIN_DELAY"))
		delay, err := ReadinessDrainDelay()
		require.NoError(t, err)
		assert.Equal(t, defaultReadinessDrainDelay, delay)

		for _, raw := range []string{"", "   "} {
			t.Setenv("YABANIN_READINESS_DRAIN_DELAY", raw)
			delay, err := ReadinessDrainDelay()
			require.NoError(t, err, "blank %q must mean default", raw)
			assert.Equal(t, defaultReadinessDrainDelay, delay)
		}
	})

	t.Run("valid values pass through", func(t *testing.T) {
		cases := []struct {
			raw  string
			want time.Duration
		}{
			{"0s", 0},
			{"0", 0},
			{"500ms", 500 * time.Millisecond},
			{"3s", 3 * time.Second},
			{"10s", maxReadinessDrainDelay},
			{"  2s  ", 2 * time.Second}, // trimmed like sibling knobs
		}
		for _, tc := range cases {
			t.Setenv("YABANIN_READINESS_DRAIN_DELAY", tc.raw)
			delay, err := ReadinessDrainDelay()
			require.NoError(t, err, "raw %q", tc.raw)
			assert.Equal(t, tc.want, delay, "raw %q", tc.raw)
		}
	})

	t.Run("invalid values fail with the env name", func(t *testing.T) {
		for _, raw := range []string{"bogus", "-1s", "11s", "1h", "3x", "s"} {
			t.Setenv("YABANIN_READINESS_DRAIN_DELAY", raw)
			_, err := ReadinessDrainDelay()
			require.Error(t, err, "raw %q", raw)
			assert.Contains(t, err.Error(), "YABANIN_READINESS_DRAIN_DELAY", "raw %q", raw)
		}
	})

	t.Run("constructor propagates the failure", func(t *testing.T) {
		t.Setenv("YABANIN_READINESS_DRAIN_DELAY", "not-a-duration")
		_, err := NewDrainReadiness()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "YABANIN_READINESS_DRAIN_DELAY")
	})
}

// --- gate ------------------------------------------------------------------

func TestDrainReadinessGate(t *testing.T) {
	t.Run("nil gate is always ready (pre-T03 compositions keep working)", func(t *testing.T) {
		var gate *DrainReadiness
		assert.True(t, gate.Ready())
		assert.False(t, gate.Draining())
		assert.Equal(t, time.Duration(0), gate.PropagationDelay())
		gate.SetDraining() // must be a no-op, not a panic
		assert.True(t, gate.Ready())
	})

	t.Run("flip is observable exactly once", func(t *testing.T) {
		gate := &DrainReadiness{delay: 2 * time.Second}
		assert.True(t, gate.Ready())
		assert.Equal(t, 2*time.Second, gate.PropagationDelay())
		gate.SetDraining()
		gate.SetDraining() // idempotent
		assert.True(t, gate.Draining())
		assert.False(t, gate.Ready())
	})

	t.Run("concurrent flip and reads are race-free and consistent", func(t *testing.T) {
		gate := &DrainReadiness{}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				gate.SetDraining()
			}()
		}
		// Each reader samples twice: the deterministic consistency property of
		// a one-way gate is MONOTONICITY — a reader that has observed
		// not-ready can never observe ready again. Whether the first sample
		// is true or false legitimately depends on the interleaving (readers
		// race the flippers here by construction; a shared WaitGroup cannot
		// order them), so no per-sample value is asserted.
		readySeen := make(chan [2]bool, 64)
		for range 64 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				readySeen <- [2]bool{gate.Ready(), gate.Ready()}
			}()
		}
		wg.Wait()
		close(readySeen)
		assert.False(t, gate.Ready(), "all flips ran before the readers joined the WaitGroup")
		assert.True(t, gate.Draining())
		for pair := range readySeen {
			assert.False(t, pair[0] == false && pair[1] == true,
				"gate un-drained mid-sequence: %v -> %v", pair[0], pair[1])
		}
	})
}

// --- drain sequence --------------------------------------------------------

// drainEvents records the observed stage order; all fake stages append here.
type drainEvents struct {
	mu     sync.Mutex
	events []string
}

func (e *drainEvents) add(event string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *drainEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

// fakeShutdowner is a stageShutdowner recording its invocation, optionally
// blocking or occupying its whole budget.
type fakeShutdowner struct {
	name    string
	events  *drainEvents
	gate    *DrainReadiness
	block   <-chan struct{}     // when non-nil, Shutdown blocks until closed
	consume time.Duration       // when > 0, Shutdown occupies the whole budget before returning
	budget  func(time.Duration) // records the ctx budget shape via deadline delta
}

func (f *fakeShutdowner) Shutdown(ctx context.Context) error {
	if f.budget != nil {
		if dl, ok := ctx.Deadline(); ok {
			f.budget(time.Until(dl))
		}
	}
	f.events.add(f.name + "-started")
	if f.consume > 0 {
		time.Sleep(f.consume)
	}
	if f.block != nil {
		// http.Server.Shutdown semantics: it returns ctx.Err() when its
		// budget expires with connections still active — the stage caller
		// never waits past the ctx.
		select {
		case <-f.block:
		case <-ctx.Done():
			f.events.add(f.name + "-abandoned")
			return ctx.Err()
		}
	}
	f.events.add(f.name + "-closed")
	return nil
}

// deadlineCapture records the escrow-context deadline for the not-starved pin.
type deadlineCapture struct {
	mu       sync.Mutex
	deadline time.Duration
	ctxErr   error
}

func (c *deadlineCapture) record(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		c.deadline = time.Until(dl)
	}
	c.ctxErr = ctx.Err()
}

// drainRun starts the sequence with injected budgets on its own goroutine.
func drainRun(t *testing.T, gate *DrainReadiness, budgets drainBudgets,
	srv, admin stageShutdowner, lineage func(time.Duration), escrow func(context.Context)) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runGatewayDrainBudgets(gate, srv, admin, lineage, escrow, budgets, discardLogger())
	}()
	return &wg
}

func TestRunGatewayDrain_SequenceOrder(t *testing.T) {
	events := &drainEvents{}
	gate := &DrainReadiness{delay: 30 * time.Millisecond}
	httpSrv := &fakeShutdowner{name: "http", events: events, gate: gate}
	adminSrv := &fakeShutdowner{name: "admin", events: events, gate: gate}

	var escrowSawDraining bool
	escrow := func(ctx context.Context) {
		escrowSawDraining = gate.Draining()
		events.add("escrow-released")
	}
	lineage := func(d time.Duration) {
		require.Positive(t, d)
		events.add("lineage-closed")
	}

	start := time.Now()
	wg := drainRun(t, gate, drainBudgets{http: 50 * time.Millisecond, admin: 50 * time.Millisecond, lineage: 50 * time.Millisecond, escrow: 50 * time.Millisecond},
		httpSrv, adminSrv, lineage, escrow)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drain sequence deadlocked")
	}
	elapsed := time.Since(start)

	assert.Equal(t, []string{
		"http-started", "http-closed",
		"admin-started", "admin-closed",
		"lineage-closed",
		"escrow-released",
	}, events.snapshot(), "drain must run: listeners → admin → lineage → lease release")
	assert.True(t, escrowSawDraining, "lease release runs after readiness=false")
	assert.GreaterOrEqual(t, elapsed, 30*time.Millisecond, "propagation window must elapse before the first stage")
	assert.Less(t, elapsed, 5*time.Second, "whole sequence stays far inside the outer grace")
}

func TestRunGatewayDrain_StuckStageIsBounded(t *testing.T) {
	events := &drainEvents{}
	gate := &DrainReadiness{delay: 0} // no propagation window in this test
	httpBlock := make(chan struct{})
	httpSrv := &fakeShutdowner{name: "http", events: events, block: httpBlock}

	// Captured at entry: the ctx keeps ticking after the sequence hands it
	// over, so late inspection would race the budget.
	capture := &deadlineCapture{}
	escrow := func(ctx context.Context) { capture.record(ctx) }
	lineage := func(time.Duration) { events.add("lineage-closed") }

	start := time.Now()
	wg := drainRun(t, gate, drainBudgets{http: 50 * time.Millisecond, admin: 50 * time.Millisecond, lineage: 50 * time.Millisecond, escrow: 50 * time.Millisecond},
		httpSrv, nil, lineage, escrow)

	waitWG(t, wg)
	elapsed := time.Since(start)

	// The stuck stage was abandoned; the later stages still ran (bounded
	// unfinished operations, lease release never starved).
	capture.mu.Lock()
	defer capture.mu.Unlock()
	require.NoError(t, capture.ctxErr, "escrow must get its own fresh budget, not the stuck stage's leftovers")
	assert.Less(t, elapsed, 2*time.Second, "a stage stuck past its budget must not extend the sequence")
	assert.Contains(t, events.snapshot(), "http-abandoned")
	assert.Contains(t, events.snapshot(), "lineage-closed")
}

func TestRunGatewayDrain_EscrowNotStarvedBySaturatedHTTP(t *testing.T) {
	// N12-P03-T01/T02 flagged gap: the old drain shared one 5s ctx across all
	// stages, so an http drain consuming its whole budget left the escrow
	// release with an already-expired deadline. Pin the per-stage fix.
	events := &drainEvents{}
	gate := &DrainReadiness{delay: 0}
	httpSrv := &fakeShutdowner{name: "http", events: events, consume: 50 * time.Millisecond}

	capture := &deadlineCapture{}
	escrow := func(ctx context.Context) { capture.record(ctx) }

	wg := drainRun(t, gate, drainBudgets{http: 50 * time.Millisecond, admin: 50 * time.Millisecond, lineage: 50 * time.Millisecond, escrow: 50 * time.Millisecond},
		httpSrv, nil, nil, escrow)

	waitWG(t, wg)
	capture.mu.Lock()
	defer capture.mu.Unlock()
	require.NoError(t, capture.ctxErr, "escrow ctx must be fresh at entry even after http consumed its whole budget")
	assert.Greater(t, capture.deadline, 25*time.Millisecond, "escrow keeps (most of) its own budget")
}

func TestRunGatewayDrain_NilStagesComplete(t *testing.T) {
	gate := &DrainReadiness{delay: 0}
	wg := drainRun(t, gate, defaultDrainBudgets(), nil, nil, nil, nil)
	waitWG(t, wg)
	assert.True(t, gate.Draining(), "readiness flips even when nothing else is wired")
}

// TestDrainServers_TypedNilServersDoNotPanic pins the production conversion:
// drainServers receives concrete *http.Server values that are nil when the
// corresponding listener was never started (e.g. no admin listen). Wrapping
// a typed-nil pointer into the stageShutdowner interface slips past the
// `srv == nil` interface check and panics inside http.Server.Shutdown — the
// exact ungraceful shutdown the golden SIGTERM test caught. The wiring must
// hand the sequence untyped nils instead.
func TestDrainServers_TypedNilServersDoNotPanic(t *testing.T) {
	gw := &gateway{}
	assert.NotPanics(t, func() {
		gw.drainServers(nil, nil, discardLogger())
	})
	assert.Nil(t, gw.drain, "a no-admin stand without a parsed knob keeps the nil gate (always-ready shape)")
}

// waitWG waits for wg with a hard timeout so a regression surfaces as a test
// failure, not a suite hang.
func waitWG(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("drain sequence did not finish")
	}
}

// --- the acceptance shape: readiness observable BEFORE stop, under load ----

func TestGatewayDrain_ReadinessFlipsBeforeListenersCloseUnderLoad(t *testing.T) {
	gate := &DrainReadiness{delay: 150 * time.Millisecond}

	inFlightStarted := make(chan struct{})
	release := make(chan struct{})
	var handlerOnce sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/work", func(w http.ResponseWriter, r *http.Request) {
		handlerOnce.Do(func() { close(inFlightStarted) })
		<-release // controlled in-flight request: blocked mid-handler
		w.WriteHeader(http.StatusOK)
	})
	// /healthz mirrors the gateway contract: draining ⇒ 503.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !gate.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	lc := &net.ListenConfig{}
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: mux} //nolint:gosec // test-only server on a loopback ephemeral port
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(l) }()
	baseURL := "http://" + l.Addr().String()

	workDone := make(chan error, 1)
	go func() {
		resp, err := http.Get(baseURL + "/v1/work") //nolint:noctx // controlled test request, bounded by the test deadline
		if err != nil {
			workDone <- err
			return
		}
		_ = resp.Body.Close() // error carries no signal here: the request outcome is what the channel forwards
		workDone <- nil
	}()
	select {
	case <-inFlightStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never started")
	}

	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		runGatewayDrainBudgets(gate, srv, nil, nil, nil,
			drainBudgets{http: 5 * time.Second, escrow: 5 * time.Second}, discardLogger())
	}()

	// During the propagation window the listener still ACCEPTS connections
	// and /healthz already reports not-ready: readiness is managed before
	// stop, with a real request still in flight.
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/healthz") //nolint:noctx // controlled test request
		if err != nil {
			return false
		}
		status := resp.StatusCode
		_ = resp.Body.Close() // explicit close inside the poll closure; bodyclose cannot track the deferred edge here
		return status == http.StatusServiceUnavailable
	}, 5*time.Second, 5*time.Millisecond, "/healthz must report 503 while the listener still accepts")

	// In-flight work is still draining (not yet released), bounded by the
	// http budget; release it and the sequence finishes cleanly.
	close(release)
	select {
	case err := <-workDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}
	select {
	case <-drainDone:
	case <-time.After(10 * time.Second):
		t.Fatal("drain did not complete after in-flight work finished")
	}
	// The listener is closed now: a new connection is refused.
	_, err = http.Get(baseURL + "/healthz") //nolint:noctx,bodyclose // controlled test request; resp is nil on the expected connection error
	require.Error(t, err, "listener must be closed after the drain")
}

// --- /healthz contract ------------------------------------------------------

func TestHealthHandlerDrainStates(t *testing.T) {
	cases := []struct {
		name       string
		gate       *DrainReadiness
		wantStatus int
		wantState  string
	}{
		{name: "nil gate keeps the always-ready shape", gate: nil, wantStatus: http.StatusOK, wantState: "ok"},
		{name: "ready gate serves the redis probe", gate: &DrainReadiness{}, wantStatus: http.StatusOK, wantState: "ok"},
		{name: "draining gate answers 503 immediately", gate: func() *DrainReadiness { g := &DrainReadiness{}; g.SetDraining(); return g }(), wantStatus: http.StatusServiceUnavailable, wantState: "draining"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gateway{gatewayCore: gatewayCore{drain: tc.gate}}
			router := chi.NewRouter()
			healthHandler(gw, router, discardLogger())
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
			require.Equal(t, tc.wantStatus, rec.Code)
			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, tc.wantState, body["status"])
			if tc.wantStatus == http.StatusOK {
				assert.Equal(t, "skipped", body["redis"], "nil rdb stays 'skipped'")
			}
		})
	}
}
