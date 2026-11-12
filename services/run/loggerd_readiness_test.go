package run

//
// N12-P03-T03 — loggerd readiness managed before stop.
//
// The loggerd health/metrics listener is bodyless GETs only, so the drain is
// a small deterministic sequence: readiness=false → bounded propagation
// window → listener close (bounded). Tests drive it with a real loopback
// listener, a controlled in-flight request and millisecond budgets — no real
// signals, no wall-clock waits (the signal select itself stays inline in
// Loggerd(); the outer force-exit contract is the gateway's, tested in
// gateway_shutdown_test.go).
//

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	gateway "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loggerdTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestLoggerdHealthHandler(t *testing.T) {
	draining := &gateway.DrainReadiness{}
	draining.SetDraining()

	cases := []struct {
		name       string
		gate       *gateway.DrainReadiness
		wantStatus int
		wantState  string
	}{
		{name: "nil gate keeps the always-ready shape", gate: nil, wantStatus: http.StatusOK},
		{name: "ready gate answers 200", gate: &gateway.DrainReadiness{}, wantStatus: http.StatusOK},
		{name: "draining gate answers 503 draining", gate: draining, wantStatus: http.StatusServiceUnavailable, wantState: "draining"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			loggerdHealthHandler(tc.gate).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
			require.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantState == "" {
				assert.Empty(t, rec.Body.String())
				return
			}
			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, tc.wantState, body["status"])
		})
	}
}

func TestNewLoggerdMuxHealthAndMetrics(t *testing.T) {
	mux := newLoggerdMux(nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	// /metrics stays mounted (shape only: the prometheus handler answers 200
	// with an exposition body).
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	assert.Equal(t, http.StatusOK, rec2.Code)
}

// TestLoggerdDrain_ReadinessBeforeStop is the loggerd acceptance shape:
// while a request is in flight, readiness flips false and is observable on
// /healthz BEFORE the listener closes; releasing the in-flight request lets
// the bounded drain finish.
func TestLoggerdDrain_ReadinessBeforeStop(t *testing.T) {
	t.Setenv("YABANIN_READINESS_DRAIN_DELAY", "100ms")
	gate, err := gateway.NewDrainReadiness()
	require.NoError(t, err)
	require.Equal(t, 100*time.Millisecond, gate.PropagationDelay())

	inFlightStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(inFlightStarted) })
		<-release
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/healthz", loggerdHealthHandler(gate))

	lc := &net.ListenConfig{}
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: mux} //nolint:gosec // test-only server on a loopback ephemeral port
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(l) }()
	baseURL := "http://" + l.Addr().String()

	workDone := make(chan error, 1)
	go func() {
		resp, err := http.Get(baseURL + "/slow") //nolint:noctx // controlled test request, bounded by the test deadline
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
		drainLoggerdHTTP(context.Background(), gate, srv, 5*time.Second, loggerdTestLogger())
	}()

	// Not-ready is observable while the listener still accepts: readiness
	// before stop, with a real in-flight request present.
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/healthz") //nolint:noctx // controlled test request
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusServiceUnavailable
	}, 5*time.Second, 5*time.Millisecond, "/healthz must report 503 while the listener still accepts")

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
		t.Fatal("loggerd drain did not complete")
	}
	_, err = http.Get(baseURL + "/healthz") //nolint:noctx,bodyclose // controlled test request; resp is nil on the expected connection error
	require.Error(t, err, "listener must be closed after the drain")
}

// TestLoggerdDrain_ZeroDelaySkipsWindow pins the 0s knob shape: the sequence
// completes immediately without the propagation sleep.
func TestLoggerdDrain_ZeroDelaySkipsWindow(t *testing.T) {
	gate := &gateway.DrainReadiness{}
	lc := &net.ListenConfig{}
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.NewServeMux()} //nolint:gosec // test-only server on a loopback ephemeral port
	go func() { _ = srv.Serve(l) }()

	start := time.Now()
	drainLoggerdHTTP(context.Background(), gate, srv, time.Second, loggerdTestLogger())
	elapsed := time.Since(start)

	assert.True(t, gate.Draining())
	assert.Less(t, elapsed, time.Second, "zero delay must not sleep")
}

// TestLoggerdDrain_BoundedByShutdownBudget pins the bound: an in-flight
// request that never finishes is abandoned at the budget, and the drain
// returns — bounded unfinished operations, not an unbounded wait.
func TestLoggerdDrain_BoundedByShutdownBudget(t *testing.T) {
	gate := &gateway.DrainReadiness{}
	// handlerEntered proves the wedged request is IN FLIGHT before the drain
	// starts: Shutdown only waits out the budget while a connection is
	// active. Without this, a drain that starts before the GET connects sees
	// zero active connections and returns instantly — the lower-bound
	// assertion below would measure scheduling, not the budget.
	handlerEntered := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/wedged", func(w http.ResponseWriter, r *http.Request) {
		handlerEntered <- struct{}{}
		// Simulates a handler stuck past any deadline: ignores its ctx.
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	})
	mux.HandleFunc("/healthz", loggerdHealthHandler(gate))

	lc := &net.ListenConfig{}
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: mux} //nolint:gosec // test-only server on a loopback ephemeral port
	go func() { _ = srv.Serve(l) }()
	go func() {
		resp, err := http.Get("http://" + l.Addr().String() + "/wedged") //nolint:noctx // controlled test request
		if err == nil {
			_ = resp.Body.Close() // best-effort cleanup; the handler-entered signal is the assertion
		}
	}()

	select {
	case <-handlerEntered:
	case <-time.After(5 * time.Second):
		require.Fail(t, "wedged handler never entered; drain bound cannot be observed")
	}

	start := time.Now()
	drainLoggerdHTTP(context.Background(), gate, srv, 200*time.Millisecond, loggerdTestLogger())
	elapsed := time.Since(start)

	assert.True(t, gate.Draining())
	assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond, "the budget is enforced")
	assert.Less(t, elapsed, 5*time.Second, "the drain returns at the budget even with a wedged handler")
}
