package tracing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

// TestInit_NoopPath pins the no-endpoint contract: Init with an empty endpoint
// must be a no-op success (no exporter, no network), Tracer must still return
// a usable tracer, and Shutdown must not error when nothing was initialized.
func TestInit_NoopPath(t *testing.T) {
	require.NoError(t, Init(context.Background(), "test-svc", "", 0))

	// Out-of-range sample rates are clamped internally; the call must not fail.
	require.NoError(t, Init(context.Background(), "test-svc", "", 2.5))

	tr := Tracer("unit")
	require.NotNil(t, tr)

	assert.NoError(t, Shutdown(context.Background()))
}

// TestInit_SingletonGuard pins that a second Init is ignored (the provider is
// process-wide and must not be re-registered mid-run).
func TestInit_SingletonGuard(t *testing.T) {
	// A valid but unreachable endpoint must be harmless: once Init has run in
	// this process the guarded call returns immediately without dialing; and
	// even as the first call, exporter construction performs no network I/O.
	require.NoError(t, Init(context.Background(), "test-svc", "127.0.0.1:1", 0.5))
}

// otlpTraceCollector is a minimal OTLP/HTTP TRACES collector: it counts
// ExportTraceServiceRequest calls and the spans inside them.
// to prove egress lands only on the configured endpoint.
type otlpTraceCollector struct {
	mu    sync.Mutex
	reqs  int
	spans int
}

func newOTLPTraceCollector(t *testing.T) (*otlpTraceCollector, *httptest.Server) {
	t.Helper()
	c := &otlpTraceCollector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()
		var req collectortracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.reqs++
		for _, rs := range req.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				c.spans += len(ss.GetSpans())
			}
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *otlpTraceCollector) snapshot() (reqs, spans int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqs, c.spans
}

// Fresh-process subprocess hooks (test-only, never a production path).
const (
	freshProcessModeEnv     = "YABANIN_TRACING_FRESH_PROCESS_MODE"
	freshProcessEndpointEnv = "YABANIN_TRACING_FRESH_PROCESS_ENDPOINT"
)

// runFreshProcessInit is the child branch: a genuinely fresh process calling
// Init once, emitting one probe span, flushing via Shutdown, and exiting.
func runFreshProcessInit(mode string) {
	endpoint := os.Getenv(freshProcessEndpointEnv)
	ctx := context.Background()
	initEndpoint := ""
	if mode == "configured" {
		initEndpoint = endpoint
	}
	if err := Init(ctx, "fresh-process", initEndpoint, 1.0); err != nil {
		fmt.Fprintln(os.Stderr, "fresh-process Init:", err)
		os.Exit(3)
	}
	_, span := Tracer("fresh-process").Start(ctx, "yabanin.tracing.fresh-process.probe")
	span.End()
	if err := Shutdown(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "fresh-process Shutdown:", err)
		os.Exit(4)
	}
	os.Exit(0)
}

// TestInit_FreshProcessEgress proves, in a freshly started process (the
// package singleton makes an in-process second Init impossible), that an
// empty Init endpoint exports nothing even when the standard OTel env vars
// point at live local collectors (env cannot enable egress), and that a
// configured endpoint is the ONLY egress: the one probe span reaches it while
// the env-targeted listener stays silent. Counts are read after the child
// exited, so no sleeps are involved.
func TestInit_FreshProcessEgress(t *testing.T) {
	if mode := os.Getenv(freshProcessModeEnv); mode != "" {
		runFreshProcessInit(mode)
		return
	}
	collector, srv := newOTLPTraceCollector(t)
	stranger, strangerSrv := newOTLPTraceCollector(t)
	runChild := func(mode, endpoint string) {
		t.Helper()
		// G204 false positive: os.Args[0] is the test binary path this
		// process was launched with by the go test harness (never user
		// input) and every argument is a fixed literal; the child re-enters
		// this exact test as the fresh-process probe.
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestInit_FreshProcessEgress$", "-test.count", "1") //nolint:gosec // see invariant comment above
		cmd.Env = append(os.Environ(),
			freshProcessModeEnv+"="+mode,
			freshProcessEndpointEnv+"="+endpoint,
			"OTEL_EXPORTER_OTLP_ENDPOINT="+strangerSrv.URL,
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="+strangerSrv.URL,
		)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		require.NoError(t, cmd.Run(), "fresh-process child (%s) failed: %s", mode, stderr.String())
	}

	// Empty endpoint: no span may reach any listener despite live OTel env.
	runChild("empty", "")
	reqs, spans := collector.snapshot()
	assert.Zero(t, reqs, "empty endpoint must not send export requests")
	assert.Zero(t, spans)
	sReqs, sSpans := stranger.snapshot()
	assert.Zero(t, sReqs, "OTel env endpoints must not receive export requests")
	assert.Zero(t, sSpans)

	// Configured endpoint (explicit host:port wins over the env URLs; the
	// http:// env scheme supplies the insecure transport): exactly the probe
	// span arrives there, the env-targeted listener stays silent.
	runChild("configured", strings.TrimPrefix(srv.URL, "http://"))
	reqs, spans = collector.snapshot()
	assert.Positive(t, reqs, "configured endpoint must receive export requests")
	assert.Equal(t, 1, spans, "configured endpoint must receive exactly the one probe span")
	sReqs, sSpans = stranger.snapshot()
	assert.Zero(t, sReqs, "the env-targeted listener must stay silent")
	assert.Zero(t, sSpans)
}
