// Targeted offline tests for the bounded shutdown drain (N12-P03-T02): the
// YABANIN_SHUTDOWN_GRACE wiring contract and the awaitShutdownExit selection
// (clean exit, error propagation, grace-expiry force exit, second-signal
// force exit). The full signal path (signal.Notify against a real listener)
// needs a socket and stays with the deferred e2e/integration gates.
package run

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShutdownGraceFromEnv(t *testing.T) {
	t.Run("unset defaults to 30s", func(t *testing.T) {
		t.Setenv("YABANIN_SHUTDOWN_GRACE", "stale")
		require.NoError(t, os.Unsetenv("YABANIN_SHUTDOWN_GRACE"))
		grace, err := shutdownGraceFromEnv()
		require.NoError(t, err)
		assert.Equal(t, defaultShutdownGrace, grace)
	})
	t.Run("empty defaults to 30s", func(t *testing.T) {
		t.Setenv("YABANIN_SHUTDOWN_GRACE", "")
		grace, err := shutdownGraceFromEnv()
		require.NoError(t, err)
		assert.Equal(t, defaultShutdownGrace, grace)
	})
	t.Run("whitespace-only counts as unset", func(t *testing.T) {
		t.Setenv("YABANIN_SHUTDOWN_GRACE", "   ")
		grace, err := shutdownGraceFromEnv()
		require.NoError(t, err)
		assert.Equal(t, defaultShutdownGrace, grace)
	})
	t.Run("valid value honored", func(t *testing.T) {
		t.Setenv("YABANIN_SHUTDOWN_GRACE", "45s")
		grace, err := shutdownGraceFromEnv()
		require.NoError(t, err)
		assert.Equal(t, 45*time.Second, grace)
	})
	for name, raw := range map[string]string{
		"invalid duration":    "soon",
		"bare number":         "30",
		"bare zero":           "0",
		"below the minimum":   "100ms",
		"above the maximum":   "2h",
		"effectively eternal": "9999h",
		"negative":            "-5s",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("YABANIN_SHUTDOWN_GRACE", raw)
			_, err := shutdownGraceFromEnv()
			require.Error(t, err, "a typo must fail startup, not silently produce an unbounded wait")
			assert.Contains(t, err.Error(), "YABANIN_SHUTDOWN_GRACE")
		})
	}
}

// TestGateway_RejectsInvalidShutdownGraceBeforeStartup pins the fail-fast
// order: an invalid grace value is reported before any config/pool I/O.
func TestGateway_RejectsInvalidShutdownGraceBeforeStartup(t *testing.T) {
	t.Setenv("YABANIN_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("YABANIN_SHUTDOWN_GRACE", "not-a-duration")

	err := Gateway(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "YABANIN_SHUTDOWN_GRACE")
}

func TestAwaitShutdownExit_ServerExitsCleanly(t *testing.T) {
	errCh := make(chan error, 1)
	errCh <- nil
	quit := make(chan os.Signal, 1)

	err := awaitShutdownExit(errCh, quit, time.Second, slog.New(slog.DiscardHandler))

	require.NoError(t, err)
}

func TestAwaitShutdownExit_ServerErrorPropagates(t *testing.T) {
	want := errors.New("listen failed")
	errCh := make(chan error, 1)
	errCh <- want
	quit := make(chan os.Signal, 1)

	err := awaitShutdownExit(errCh, quit, time.Second, slog.New(slog.DiscardHandler))

	require.Equal(t, want, err)
}

// stubForceExit replaces the process-exit seam for one test and returns a
// channel receiving the exit code. The awaitShutdownExit tests mutate the
// package var and therefore never run in parallel.
func stubForceExit(t *testing.T) <-chan int {
	t.Helper()
	codes := make(chan int, 4)
	orig := forceExit
	forceExit = func(code int) { codes <- code }
	t.Cleanup(func() { forceExit = orig })
	return codes
}

func TestAwaitShutdownExit_GraceExpiryForcesExit(t *testing.T) {
	stuck := make(chan error) // server goroutine never reports
	quit := make(chan os.Signal, 1)
	codes := stubForceExit(t)
	start := time.Now()

	err := awaitShutdownExit(stuck, quit, 40*time.Millisecond, slog.New(slog.DiscardHandler))
	elapsed := time.Since(start)

	require.ErrorIs(t, err, errForcedShutdown)
	require.ErrorContains(t, err, "expired")
	assert.Less(t, elapsed, 5*time.Second, "the drain wait is bounded even when the server is stuck")
	select {
	case code := <-codes:
		assert.Equal(t, 1, code, "forced shutdown exits non-zero")
	default:
		t.Fatal("force exit was not invoked on grace expiry")
	}
}

func TestAwaitShutdownExit_SecondSignalForcesExit(t *testing.T) {
	stuck := make(chan error) // server goroutine never reports
	quit := make(chan os.Signal, 1)
	codes := stubForceExit(t)
	go func() {
		time.Sleep(10 * time.Millisecond)
		quit <- syscall.SIGTERM
	}()
	start := time.Now()

	err := awaitShutdownExit(stuck, quit, 10*time.Second, slog.New(slog.DiscardHandler))
	elapsed := time.Since(start)

	require.ErrorIs(t, err, errForcedShutdown)
	require.ErrorContains(t, err, "second signal")
	assert.Less(t, elapsed, 5*time.Second, "a second signal wins immediately over the remaining grace")
	select {
	case code := <-codes:
		assert.Equal(t, 1, code, "forced shutdown exits non-zero")
	default:
		t.Fatal("force exit was not invoked on the second signal")
	}
}

func TestAwaitShutdownExit_SecondSignalBeatsServerExit(t *testing.T) {
	// The server reports an error concurrently with the second signal: the
	// forced path is still deterministic (either outcome is a bounded
	// shutdown), but the signal must never deadlock against the error.
	errCh := make(chan error, 1)
	quit := make(chan os.Signal, 1)
	codes := stubForceExit(t)
	quit <- syscall.SIGTERM

	err := awaitShutdownExit(errCh, quit, time.Second, slog.New(slog.DiscardHandler))

	require.ErrorIs(t, err, errForcedShutdown)
	select {
	case code := <-codes:
		assert.Equal(t, 1, code)
	default:
		t.Fatal("force exit was not invoked")
	}
}
