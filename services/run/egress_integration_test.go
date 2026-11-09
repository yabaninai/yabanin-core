package run

// service process, started exactly as production starts it (run.Loggerd over
// env-only configuration), proves its egress posture in two fresh OS child
// processes:
//
//   - NoConfiguredTelemetry: with NO Yabanin telemetry knob set — while the
//     standard OTel env vars POINT AT the live local collector — the service
//     makes zero collector requests. Standard env cannot enable egress.
//   - ConfiguredLoopbackTelemetry: with only YABANIN_OTEL_LOGS_ENDPOINT set
//     to the local collector, one synthetic gateway event produces the exact
//     configured-loopback export (the record arrives; graceful SIGTERM
//     shutdown flushes).
//
// Destination capture: the child wraps http.DefaultTransport's DialContext
// and reports every dial it sees as JSON on stdout; the parent asserts no
// dial reached the collector in the off mode. Honest limits recorded in
// integration.md: SDK-internal transports cloned before the override may
// bypass the wrapper, so the PARENT-SIDE collector counters are the
// authoritative destination capture; the AWS credential chain is pinned by
// construction (no bucket configured → no S3 uploader; AWS_EC2_METADATA_
// DISABLED=true → no IMDS), not by a network observer.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/reireirei/yabanin/pkg/testdb"
)

const egressChildModeEnv = "YABANIN_EGRESS_PROBE_CHILD_MODE"

// egressCollector is a minimal OTLP/HTTP logs collector with exact request
// and record counters (the authoritative destination capture).
type egressCollector struct {
	mu       sync.Mutex
	requests int
	records  int
	seenIDs  []string
	notify   chan struct{}
}

func newEgressCollector(t *testing.T) (*egressCollector, *httptest.Server) {
	t.Helper()
	c := &egressCollector{notify: make(chan struct{}, 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()
		var req collectorlogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.requests++
		for _, rl := range req.GetResourceLogs() {
			for _, sl := range rl.GetScopeLogs() {
				for _, rec := range sl.GetLogRecords() {
					c.records++
					for _, kv := range rec.GetAttributes() {
						if kv.GetKey() == "request.id" {
							c.seenIDs = append(c.seenIDs, kv.GetValue().GetStringValue())
						}
					}
				}
			}
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		select {
		case c.notify <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *egressCollector) snapshot() (requests, records int, ids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.records, append([]string(nil), c.seenIDs...)
}

// waitForExport waits until cond sees the expected collector state, bounded.
func (c *egressCollector) waitFor(t *testing.T, cond func(requests, records int, ids []string) bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond(c.snapshot()) {
			return
		}
		select {
		case <-c.notify:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// egressChildMain is the child branch: it wraps the default dialer, then runs
// the REAL service entrypoint exactly as production does (env-only config),
// and prints the dial capture as JSON after the graceful shutdown.
func egressChildMain(t *testing.T, mode string) {
	t.Helper()
	type dial struct{ Network, Address string }
	var mu sync.Mutex
	var dials []dial
	realTransport := http.DefaultTransport
	if tr, ok := realTransport.(*http.Transport); ok {
		original := tr.DialContext
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			dials = append(dials, dial{Network: network, Address: address})
			mu.Unlock()
			return original(ctx, network, address)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		// Bounded runaway guard: the parent normally sends SIGTERM.
		<-time.After(90 * time.Second)
		fmt.Fprintln(os.Stderr, "egress child: runaway guard fired")
		stop()
	}()

	if err := Loggerd(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "egress child: Loggerd: %v\n", err)
		os.Exit(3)
	}
	mu.Lock()
	out, _ := json.Marshal(dials)
	mu.Unlock()
	fmt.Println("EGRESS_DIALS " + string(out))
}

// startEgressChild spawns the fresh service process with the given env
// overrides and returns the command with captured output wired in.
func startEgressChild(t *testing.T, mode string, env map[string]string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	// G204 false positive: os.Args[0] is the test binary path handed to this
	// process by the go test harness (never user input) and every argument is
	// a fixed literal; the child re-enters this exact test as the fresh
	// service process (the same invariant as pkg/tracing's fresh-process
	// probe).
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count", "1", "-test.v") //nolint:gosec // see invariant comment above
	// The child CWD sits INSIDE the repo (testdb walks up to go.mod for the
	// migrations) but in its own directory without a config.yaml, so the
	// service runs on env-only configuration — the production K8s shape.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolve child cwd: %v", err)
	}
	childDir := filepath.Join(cwd, "..", "..", "artifacts", "egress-probe-cwd-"+mode)
	if err := os.MkdirAll(childDir, 0o750); err != nil {
		t.Fatalf("create child cwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(childDir) })
	cmd.Dir = childDir
	_ = err
	full := map[string]string{
		egressChildModeEnv:            mode,
		"YABANIN_PG_URI":              os.Getenv("YABANIN_EGRESS_PROBE_PG"),
		"YABANIN_REDIS_ADDR":          os.Getenv("YABANIN_EGRESS_PROBE_REDIS"),
		"YABANIN_LOGGERD_LISTEN":      "127.0.0.1:0",
		"YABANIN_LOGGERD_STREAM":      os.Getenv("YABANIN_EGRESS_PROBE_STREAM"),
		"YABANIN_LOGGERD_LOG_LEVEL":   "warn",
		"AWS_EC2_METADATA_DISABLED":   "true",
		"AWS_CONFIG_FILE":             "/nonexistent-yabanin-egress",
		"AWS_SHARED_CREDENTIALS_FILE": "/nonexistent-yabanin-egress",
		"YABANIN_CONFIG":              "",
	}
	for k, v := range env {
		full[k] = v
	}
	childEnv := os.Environ()
	for k, v := range full {
		childEnv = append(childEnv, k+"="+v)
	}
	cmd.Env = childEnv
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fresh egress child (%s): %v", mode, err)
	}
	return cmd, &out
}

func runEgressParent(t *testing.T, mode string) {
	t.Helper()
	ctx := context.Background()
	pg := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	collector, collectorSrv := newEgressCollector(t)

	orgID := "0195111c-0000-7000-8000-0000000000ef"
	_, err := pg.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'egress-live-org', 'egress-live')
		ON CONFLICT (id) DO NOTHING`, orgID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pg.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, orgID)
		_, _ = pg.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	const stream = "events:egress-probe"
	requestID := "req-egress-probe-1"
	values := map[string]interface{}{
		"event_type":         "request.completed",
		"source":             "gateway-egress-probe",
		"request_id":         requestID,
		"org_id":             orgID,
		"session_id":         "ses-egress-probe",
		"model_requested":    "gpt-5-mini",
		"model_used":         "gpt-5-mini",
		"status_code":        "200",
		"duration_ms":        "12",
		"tokens_in":          "11",
		"tokens_out":         "3",
		"estimated_cost_usd": "0.0001",
		"method":             "POST",
		"ts":                 strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
	env := map[string]string{}
	switch mode {
	case "off":
		// Standard OTel env points at the live collector; the Yabanin knobs
		// stay unset. The real service must still export nothing.
		env["OTEL_EXPORTER_OTLP_ENDPOINT"] = collectorSrv.URL
		env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = collectorSrv.URL
		env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = collectorSrv.URL
		env["YABANIN_OTEL_ENDPOINT"] = ""
		env["YABANIN_OTEL_LOGS_ENDPOINT"] = ""
	case "otel":
		env["YABANIN_OTEL_LOGS_ENDPOINT"] = collectorSrv.URL
		env["YABANIN_OTEL_ENDPOINT"] = ""
	default:
		t.Fatalf("unknown egress probe mode %q", mode)
	}

	t.Setenv("YABANIN_EGRESS_PROBE_PG", pg.Config().ConnString())
	t.Setenv("YABANIN_EGRESS_PROBE_REDIS", rdb.Options().Addr)
	t.Setenv("YABANIN_EGRESS_PROBE_STREAM", stream)
	cmd, childOut := startEgressChild(t, mode, env)
	// Give the real service a moment to boot, then enqueue so the consumer
	// group (created at start) observes the event.
	time.Sleep(1500 * time.Millisecond)
	require.NoError(t, rdb.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: values}).Err())

	if mode == "otel" {
		collector.waitFor(t, func(requests, records int, ids []string) bool {
			return records >= 1
		})
		requests, records, ids := collector.snapshot()
		require.Equal(t, 1, records, "exactly the one synthetic record must reach the configured loopback collector")
		require.Positive(t, requests)
		assert.Contains(t, ids, requestID, "the exported record must carry the synthetic request id")
	}
	// Bounded idle window for the off mode: the REAL service runs while the
	// collector stays at zero; then graceful shutdown.
	time.Sleep(4 * time.Second)
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	err = cmd.Wait()
	if err != nil {
		t.Logf("fresh egress child (%s) output:\n%s", mode, childOut.String())
	}
	if mode == "otel" {
		require.NoError(t, err, "child must shut down gracefully after the flush")
		requests, records, _ := collector.snapshot()
		assert.Equal(t, 1, records, "shutdown must not duplicate exports")
		assert.Positive(t, requests)
	} else {
		require.NoError(t, err)
		requests, records, _ := collector.snapshot()
		assert.Zero(t, records, "no telemetry configuration must export nothing — even with live OTel env")
		assert.Zero(t, requests, "the OTel-env-targeted collector must receive zero requests")
	}
}

// The two card-mandated tests. Each spawns the real service as a fresh OS
// child process (the singleton-heavy globals make an in-process second start
// impossible and would not be a fresh process anyway).
func TestEgressStartupFreshProcess_NoConfiguredTelemetry(t *testing.T) {
	if mode := os.Getenv(egressChildModeEnv); mode != "" {
		egressChildMain(t, mode)
		return
	}
	runEgressParent(t, "off")
}

func TestEgressStartupFreshProcess_ConfiguredLoopbackTelemetry(t *testing.T) {
	if mode := os.Getenv(egressChildModeEnv); mode != "" {
		egressChildMain(t, mode)
		return
	}
	runEgressParent(t, "otel")
}
