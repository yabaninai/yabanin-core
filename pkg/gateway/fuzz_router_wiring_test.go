package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/stretchr/testify/require"
)

type routerWiringProbe struct {
	handler   http.Handler
	timeouts  [2]string
	origin    string
	increment float64
}

const probeOrigin = "https://dashboard.example"

var probePaths = [2]string{"/router-wiring/", "/v1/router-wiring/"}

func probeRequestContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Probe-Request-Id", string(requestid.FromContext(r.Context())))
	w.Header().Set("Probe-Deadline", fmt.Sprint(r.Context().Value(httpmw.TimeoutKey)))
	w.WriteHeader(http.StatusNoContent)
}

func newRouterWiringProbe(f *testing.F, configured bool) routerWiringProbe {
	f.Helper()
	cfg := config.Gateway{}
	probe := routerWiringProbe{timeouts: [2]string{"1m0s", "30m0s"}}
	idleWant := 5 * time.Minute
	usageWant := map[string]bool{"openai": true, "openai-compat": true, "vllm": true, "ollama": true, "llamacpp": true, "mistral": true, "zai-coding": true}
	if configured {
		cfg.AllowedOrigins = []string{probeOrigin}
		cfg.MetricsEnabled = true
		cfg.Shadow.Enabled = true
		cfg.OTELTracingEndpoint = "localhost:4317"
		cfg.StreamUsageProviders = []string{" example "}
		cfg.RequestTimeout, cfg.StreamMaxDuration, cfg.StreamIdleTimeout = "19s", "83s", "7s"
		probe.timeouts, probe.origin, probe.increment = [2]string{"19s", "1m23s"}, probeOrigin, 1
		idleWant, usageWant = 7*time.Second, map[string]bool{"example": true}
	}
	router, idle, providers := newGatewayHTTPRouter(cfg, fuzzDiscardLogger())
	require.Equal(f, idleWant, idle)
	require.Equal(f, usageWant, providers)
	for _, prefix := range probePaths {
		router.Get(prefix+"{sample}", probeRequestContext)
	}
	probe.handler = router
	return probe
}

func (probe routerWiringProbe) check(t *testing.T, pathIndex int, sample uint64) {
	t.Helper()
	prefix := probePaths[pathIndex]
	value := strconv.FormatUint(sample, 16)
	id := "client-" + value
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, prefix+value, nil)
	req.Header.Set("Origin", probeOrigin)
	req.Header.Set("X-Request-ID", id)
	counter := metrics.RequestsTotal.WithLabelValues("GET", prefix+"{sample}", "204")
	before := testutil.ToFloat64(counter)
	reply := httptest.NewRecorder()
	probe.handler.ServeHTTP(reply, req)
	require.Equal(t, http.StatusNoContent, reply.Code)
	require.Equal(t, id, reply.Header().Get("X-Request-ID"))
	require.Equal(t, id, reply.Header().Get("Probe-Request-Id"))
	require.Equal(t, probe.timeouts[pathIndex], reply.Header().Get("Probe-Deadline"))
	require.Equal(t, probe.origin, reply.Header().Get("Access-Control-Allow-Origin"))
	require.InDelta(t, probe.increment, testutil.ToFloat64(counter)-before, 0)
}

func checkStartupConfigError(t *testing.T, port uint16, missingProvider bool) {
	t.Helper()
	// Both inputs stop at the public boot API's configuration check, before
	// either storage or a listener is needed.
	cfg := config.Gateway{Provider: "http://127.0.0.1:1"}
	want := "invalid gateway config: listen_address is required"
	if missingProvider {
		cfg = config.Gateway{ListenAddr: fmt.Sprintf("127.0.0.1:%d", port)}
		want = "invalid gateway config: provider address is required"
	}
	err := RunGatewayServerWithJWT(cfg, nil, nil, nil, fuzzDiscardLogger(), t.Context(), JWTWiring{}, CircuitScopeWiring{})
	require.EqualError(t, err, want)
}

func FuzzGatewayRouterWiring(f *testing.F) {
	defaults := newRouterWiringProbe(f, false)
	configured := newRouterWiringProbe(f, true)
	for _, custom := range []bool{false, true} {
		f.Add(custom, uint8(0), uint64(1))
		f.Add(custom, uint8(1), uint64(2))
	}
	// One router per configuration per process. Pace this client's requests
	// below the production middleware's sustained 50 requests/second.
	pace := time.NewTicker(30 * time.Millisecond)
	f.Cleanup(pace.Stop)
	f.Fuzz(func(t *testing.T, custom bool, route uint8, sample uint64) {
		<-pace.C
		probe := defaults
		if custom {
			probe = configured
		}
		checkStartupConfigError(t, uint16(sample&0xffff), custom)
		probe.check(t, int(route%2), sample)
	})
}
