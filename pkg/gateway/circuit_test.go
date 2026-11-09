package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
)

// the real production chat/stream paths over two httptest upstream fixtures
// (rt03 pattern) with a bounded circuit.Map wired into the gateway.
//
// Endpoint identity is the normalized scheme://host of each fixture URL —
// two distinct servers are two independent breakers.

// circuitGateway wires the rt03 chat gateway with a circuit.Map in the given
// scope. Thresholds are small so tests can trip a circuit in 1-2 requests.
func circuitGateway(t *testing.T, baseURL string, resolvers stubModelResolver, scope circuit.Scope, threshold int) *gateway {
	t.Helper()
	return circuitGatewayWithOpenTimeout(t, baseURL, resolvers, scope, threshold, time.Minute)
}

func circuitGatewayWithOpenTimeout(t *testing.T, baseURL string, resolvers stubModelResolver, scope circuit.Scope, threshold int, openTimeout time.Duration) *gateway {
	t.Helper()
	gw := rt03Gateway(t, baseURL, resolvers, &rt02Access{})
	gw.circuitScope = scope
	gw.circuits = circuit.NewMap(circuit.Config{
		Enabled:          true,
		FailureThreshold: threshold,
		SuccessThreshold: 1,
		OpenTimeout:      openTimeout,
		Window:           time.Minute,
	}, circuit.DefaultMaxEndpoints, nil)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	return gw
}

// --- JSON path: flap of one endpoint opens only ITS breaker -------------------

func TestCircuit_PerEndpoint_PrimaryFlapOnlyItsBreakerOpens(t *testing.T) {
	primary, healthy := rt03Pair(t)
	gw := circuitGateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, circuit.ScopePerEndpoint, 2)

	epA := circuit.EndpointKey(primary.srv.URL)
	epB := circuit.EndpointKey(healthy.srv.URL)

	// Two requests flap endpoint A twice (one failure per request).
	for i := 0; i < 2; i++ {
		rec := rt02Post(t, gw, rt03ChatBody, nil)
		require.Equal(t, http.StatusOK, rec.Code, "request %d must be served by the fallback: %s", i, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "ok-from-f1")
	}
	require.Equal(t, circuit.StateOpen, gw.circuits.State(epA), "flapped endpoint must be open")
	require.Equal(t, circuit.StateClosed, gw.circuits.State(epB), "healthy endpoint must stay closed")

	// Third request: A's breaker rejects BEFORE any upstream call; the
	// fallback on the independent endpoint B still serves the request.
	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ok-from-f1")
	assert.Equal(t, 2, primary.totalCalls(), "open breaker must not touch its endpoint")
	assert.Equal(t, 3, healthy.totalCalls(), "independent endpoint keeps serving")
}

// --- JSON path: recovery through the half-open probe --------------------------

func TestCircuit_PerEndpoint_RecoveryAfterOpenTimeout(t *testing.T) {
	var primaryHealthy atomic.Bool
	primaryHealthy.Store(false)
	primary := newRT03Upstream(t, func(rt03Call) rt03Response {
		if primaryHealthy.Load() {
			return rt03Response{Status: http.StatusOK}
		}
		return rt03Down()
	})
	healthy := newRT03Upstream(t, nil)
	gw := circuitGatewayWithOpenTimeout(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, circuit.ScopePerEndpoint, 1, 40*time.Millisecond)

	epA := circuit.EndpointKey(primary.srv.URL)

	// One failing request opens A (threshold 1); fallback serves.
	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, circuit.StateOpen, gw.circuits.State(epA))

	// The endpoint heals; after the open timeout the half-open probe must
	// admit a real request that closes the circuit again.
	primaryHealthy.Store(true)
	time.Sleep(3 * 40 * time.Millisecond)

	rec = rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ok-from-m1", "the recovered primary serves the winning hop")
	assert.Equal(t, 2, primary.totalCalls(), "half-open probe must reach the endpoint")
	require.Equal(t, circuit.StateClosed, gw.circuits.State(epA))
}

// --- JSON path: every candidate open → 503 (terminal envelope) ---------------

func TestCircuit_PerEndpoint_AllEndpointsOpenFails503(t *testing.T) {
	primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	fallback := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	gw := circuitGateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: fallback.srv.URL, Enabled: true},
	}, circuit.ScopePerEndpoint, 1)

	epA := circuit.EndpointKey(primary.srv.URL)
	epB := circuit.EndpointKey(fallback.srv.URL)

	// Request 1 dials both endpoints (breakers still closed); both fail —
	// the exhaustion path maps upstream 5xx to 502, and both circuits open.
	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
	assert.Equal(t, 1, primary.totalCalls())
	assert.Equal(t, 1, fallback.totalCalls())
	require.Equal(t, circuit.StateOpen, gw.circuits.State(epA))
	require.Equal(t, circuit.StateOpen, gw.circuits.State(epB))

	// Second request: both breakers reject before dialing — the chain
	// exhausts without a single upstream call and answers the same 503
	// envelope the global entry gate produces.
	rec = rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, 1, primary.totalCalls(), "open breakers must not dial")
	assert.Equal(t, 1, fallback.totalCalls(), "open breakers must not dial")
}

func TestCircuit_GlobalScope_OldBehavior(t *testing.T) {
	var fallbackHealthy atomic.Bool
	fallbackHealthy.Store(false)
	primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	fallback := newRT03Upstream(t, func(rt03Call) rt03Response {
		if fallbackHealthy.Load() {
			return rt03Response{Status: http.StatusOK}
		}
		return rt03Down()
	})
	gw := circuitGateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: fallback.srv.URL, Enabled: true},
	}, circuit.ScopeGlobal, 2)

	// Two all-hops-fail requests trip the ONE shared breaker. The exhaustion
	// path maps upstream 5xx to 502 (pre-existing mapping); only the entry
	// gate rejects with 503.
	for i := 0; i < 2; i++ {
		rec := rt02Post(t, gw, rt03ChatBody, nil)
		require.Equal(t, http.StatusBadGateway, rec.Code, "request %d: %s", i, rec.Body.String())
	}
	require.Equal(t, 2, primary.totalCalls())
	require.Equal(t, 2, fallback.totalCalls())
	require.Equal(t, 1, gw.circuits.Len(), "global scope uses exactly one breaker")

	// Old behavior: the open GLOBAL breaker rejects the request at entry —
	// even though the fallback endpoint has since healed.
	fallbackHealthy.Store(true)
	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, 2, primary.totalCalls(), "entry gate must reject before dialing")
	assert.Equal(t, 2, fallback.totalCalls(), "the healthy fallback must NOT be consulted in global scope")
}

// --- Stream path: per-hop gating and attribution -------------------------------

func TestCircuit_PerEndpoint_StreamFallbackOnIndependentEndpoint(t *testing.T) {
	primary := newRT03Upstream(t, func(rt03Call) rt03Response { return rt03Down() })
	healthy := newRT03Upstream(t, func(rt03Call) rt03Response {
		return rt03Response{
			Status:      http.StatusOK,
			ContentType: "text/event-stream",
			Body:        "data: {\"id\":\"fb\",\"choices\":[{\"delta\":{\"content\":\"ok-from-f1\"}}]}\n\ndata: [DONE]\n\n",
		}
	})
	gw := circuitGateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, circuit.ScopePerEndpoint, 1)

	info := resolver.ModelInfo{
		ModelName:      "m1",
		Provider:       "openai",
		UpstreamURL:    primary.srv.URL,
		Enabled:        true,
		FailoverModels: []string{"f1"},
	}

	serve := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gw.serveStream(rec, context.Background(), info,
			streamBody(t, "m1", "hi"), false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)
		return rec
	}

	// Request 1: primary 503 at connect (failure 1 → A opens), fallback serves.
	rec := serve()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ok-from-f1")
	assert.Contains(t, rec.Body.String(), "data: [DONE]")
	require.Equal(t, circuit.StateOpen, gw.circuits.State(circuit.EndpointKey(primary.srv.URL)))

	// Request 2: A's breaker rejects the hop before dialing; B serves again.
	rec = serve()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "data: [DONE]")
	assert.Equal(t, 1, primary.totalCalls(), "open breaker must not touch its endpoint")
	assert.Equal(t, 2, healthy.totalCalls(), "independent endpoint keeps serving streams")
}

// --- Concurrency smoke through the real chat path (run under -race) ----------

func TestCircuit_PerEndpoint_ConcurrentRequests(t *testing.T) {
	primary, healthy := rt03Pair(t)
	gw := circuitGateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, circuit.ScopePerEndpoint, 2)

	var wg sync.WaitGroup
	codes := make([]int, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = rt02Post(t, gw, rt03ChatBody, nil).Code
		}(i)
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, code)
		}
	}
	// Every primary dial fails, so A's breaker must have tripped while B —
	// which served every winning hop — stays closed.
	require.Equal(t, circuit.StateOpen, gw.circuits.State(circuit.EndpointKey(primary.srv.URL)))
	require.Equal(t, circuit.StateClosed, gw.circuits.State(circuit.EndpointKey(healthy.srv.URL)))
}

// --- Wiring defaults: unwired gateways are inert ------------------------------

func TestCircuit_NilMapInert(t *testing.T) {
	primary, healthy := rt03Pair(t)
	gw := rt03Gateway(t, primary.srv.URL, stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: primary.srv.URL, Enabled: true, FailoverModels: []string{"f1"}},
		"f1": {ModelName: "f1", Provider: "openai", UpstreamURL: healthy.srv.URL, Enabled: true},
	}, &rt02Access{})

	rec := rt02Post(t, gw, rt03ChatBody, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	if !strings.Contains(rec.Body.String(), "ok-from-f1") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
