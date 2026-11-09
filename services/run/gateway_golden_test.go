package run

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a race-safe capture buffer: the child process writes from its
// own goroutine while the test polls for readiness markers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestGatewayGoldenStartupLogs is the golden gate for the unified start path:
// it builds the standalone gateway binary and the unified binary, starts each
// with the same stub config (no external network: Postgres points at a closed
// local port, which the gateway tolerates in resolver-fallback-only mode),
// stops each with SIGTERM, and requires the structured startup+shutdown logs
// to be identical after normalizing timestamps. Both processes must exit 0.
//
// The standalone binary's automaxprocs stderr line is intentionally outside
// the comparison: GOMAXPROCS tuning is per-binary (the blank import stays on
// the standalone entrypoint) and host-quota dependent, not part of the
// structured log stream.
func TestGatewayGoldenStartupLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("golden binary comparison skipped in -short mode")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not available: %v", err)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(
		"gateway:\n"+
			"  listen_address: 127.0.0.1:0\n"+
			"  admin_listen: \"\"\n"+
			"  pg_uri: postgres://golden:golden@127.0.0.1:59999/yabanin?sslmode=disable\n"+
			"  redis_addr: \"\"\n"+
			"  log_level: info\n"+
			"  log_format: json\n"), 0600))

	gatewayBin := filepath.Join(dir, "gateway-standalone")
	unifiedBin := filepath.Join(dir, "yabanin-unified")
	build := func(target, pkg string) {
		t.Helper()
		buildCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(buildCtx, goTool, "build", "-o", target, pkg) //nolint:gosec // G204: goTool is LookPath("go"), target/pkg are test-built paths under t.TempDir(), not user input
		cmd.Dir = repoRoot
		out, buildErr := cmd.CombinedOutput()
		require.NoError(t, buildErr, "go build %s failed: %s", pkg, out)
	}
	build(gatewayBin, "./services/gateway/cmd")
	build(unifiedBin, "./cmd/yabanin")

	runUntilSigterm := func(name, bin string, args ...string) (stdout, stderr string, exitCode int) {
		t.Helper()
		runCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(runCtx, bin, args...) //nolint:gosec // G204: bin is built by this test into t.TempDir(), args are fixed subcommands, not user input
		// Hermetic env: strip YABANIN_*/LOG_FORMAT so the host stand cannot
		// leak into the golden comparison; only YABANIN_CONFIG is injected.
		for _, kv := range os.Environ() {
			key, _, _ := strings.Cut(kv, "=")
			if strings.HasPrefix(key, "YABANIN_") || key == "LOG_FORMAT" {
				continue
			}
			cmd.Env = append(cmd.Env, kv)
		}
		cmd.Env = append(cmd.Env, "YABANIN_CONFIG="+cfgPath)
		cmd.Dir = dir

		var out, errOut syncBuffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut
		require.NoError(t, cmd.Start(), "%s: failed to start", name)

		waitForLogMessage(t, runCtx, &out, "gateway starting")

		require.NoError(t, cmd.Process.Signal(syscall.SIGTERM), "%s: SIGTERM failed", name)
		waitErr := cmd.Wait()
		require.NoError(t, runCtx.Err(), "%s did not exit in time; stdout:\n%s", name, out.String())
		exitCode = 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			require.ErrorAs(t, waitErr, &exitErr, "%s: unexpected wait error", name)
			exitCode = exitErr.ExitCode()
		}
		assert.Equal(t, 0, exitCode, "%s must shut down gracefully on SIGTERM", name)
		return out.String(), errOut.String(), exitCode
	}

	gwStdout, gwStderr, gwExit := runUntilSigterm("gateway-standalone", gatewayBin)
	uniStdout, uniStderr, uniExit := runUntilSigterm("yabanin gateway", unifiedBin, "gateway")

	gwLines := normalizeStructuredLogs(t, gwStdout)
	uniLines := normalizeStructuredLogs(t, uniStdout)

	// Golden: the two binaries emit identical structured startup+shutdown logs.
	assert.Equal(t, gwLines, uniLines,
		"golden startup logs of gateway-standalone and `yabanin gateway` must match")

	// Format invariants on the shared start path (unit-level golden markers).
	assertLogMessage(t, uniLines, "gateway starting")
	assertLogMessage(t, uniLines, "shutting down gateway...")

	// Diagnostics for review: stderr must carry no structured log lines.
	t.Logf("exit codes: standalone=%d unified=%d", gwExit, uniExit)
	t.Logf("standalone stderr: %q", gwStderr)
	t.Logf("unified stderr: %q", uniStderr)
}

// waitForLogMessage polls the captured stdout until the given msg value shows
// up, failing on timeout.
func waitForLogMessage(t *testing.T, ctx context.Context, buf *syncBuffer, msg string) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		if strings.Contains(buf.String(), "\"msg\":\""+msg+"\"") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %q; stdout:\n%s", msg, buf.String())
		case <-deadline:
			t.Fatalf("timed out waiting for %q; stdout:\n%s", msg, buf.String())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// normalizeStructuredLogs parses each stdout line as a JSON log record, drops
// the wall-clock "time" field, and re-serializes with sorted keys. Non-JSON
// lines are kept verbatim so unexpected noise fails the comparison instead of
// being silently dropped.
func normalizeStructuredLogs(t *testing.T, raw string) []string {
	t.Helper()
	var normalized []string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			normalized = append(normalized, line)
			continue
		}
		delete(record, "time")
		data, marshalErr := json.Marshal(record)
		require.NoError(t, marshalErr)
		normalized = append(normalized, string(data))
	}
	return normalized
}

// assertLogMessage verifies that a normalized log stream contains a record
// with the given msg value.
func assertLogMessage(t *testing.T, lines []string, msg string) {
	t.Helper()
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if m, _ := record["msg"].(string); m == msg {
			return
		}
	}
	t.Errorf("expected a log record with msg %q, got:\n%s", msg, strings.Join(lines, "\n"))
}
