package run

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDev_CancelsAllOnFirstError(t *testing.T) {
	errBoom := errors.New("boom")
	var mu sync.Mutex
	arrived := 0
	barrier := make(chan struct{})
	cancelled := map[string]bool{}

	arrive := func() {
		mu.Lock()
		arrived++
		if arrived == 3 {
			close(barrier)
		}
		mu.Unlock()
	}
	block := func(name string) func(context.Context) error {
		return func(ctx context.Context) error {
			arrive()
			<-barrier
			<-ctx.Done()
			mu.Lock()
			cancelled[name] = true
			mu.Unlock()
			return nil
		}
	}

	err := Dev(context.Background(), DevFlags{}, DevRunners{
		Gateway: block("gateway"),
		Loggerd: func(context.Context) error {
			arrive()
			<-barrier
			return errBoom
		},
		Admin: block("admin"),
		Log:   slog.New(slog.DiscardHandler),
	})

	require.ErrorIs(t, err, errBoom)
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, cancelled["gateway"], "gateway must stop after the first failure")
	assert.True(t, cancelled["admin"], "admin must stop after the first failure")
}

func TestDev_StopsOnSignalContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	arrived := 0
	barrier := make(chan struct{})
	stopped := map[string]bool{}

	arrive := func() {
		mu.Lock()
		arrived++
		if arrived == 3 {
			close(barrier)
		}
		mu.Unlock()
	}
	runner := func(name string) func(context.Context) error {
		return func(ctx context.Context) error {
			arrive()
			<-ctx.Done()
			mu.Lock()
			stopped[name] = true
			mu.Unlock()
			return nil
		}
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	done := make(chan error, 1)
	go func() {
		done <- Dev(ctx, DevFlags{}, DevRunners{
			Gateway:        runner("gateway"),
			Loggerd:        runner("loggerd"),
			Admin:          runner("admin"),
			Log:            log,
			GatewayAddr:    ":8082",
			GatewayOpsAddr: ":9090",
			LoggerdAddr:    ":8085",
			AdminAddr:      ":8086",
		})
	}()

	<-barrier
	cancel()

	require.NoError(t, <-done)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, map[string]bool{"gateway": true, "loggerd": true, "admin": true}, stopped)
	text := buf.String()
	assert.Contains(t, text, "gateway=:8082")
	assert.Contains(t, text, "gateway_ops=:9090")
	assert.Contains(t, text, "loggerd=:8085")
	assert.Contains(t, text, "admin=:8086")
	assert.Contains(t, text, "service=gateway")
	assert.Contains(t, text, "service=loggerd")
	assert.Contains(t, text, "service=admin")
}

func TestDev_MigrateFailureStopsStart(t *testing.T) {
	started := map[string]int{}
	var mu sync.Mutex
	count := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			started[name]++
			mu.Unlock()
			return nil
		}
	}

	err := Dev(context.Background(), DevFlags{Migrate: true}, DevRunners{
		Migrate: func(context.Context) error { return errors.New("schema") },
		Gateway: count("gateway"),
		Loggerd: count("loggerd"),
		Admin:   count("admin"),
		Log:     slog.New(slog.DiscardHandler),
	})

	require.ErrorContains(t, err, "schema")
	assert.Empty(t, started)
}

func TestDev_SkipsDisabledServices(t *testing.T) {
	var mu sync.Mutex
	started := map[string]int{}
	count := func(name string) func(context.Context) error {
		return func(ctx context.Context) error {
			mu.Lock()
			started[name]++
			mu.Unlock()
			return nil
		}
	}

	err := Dev(context.Background(), DevFlags{NoAdmin: true, NoLoggerd: true}, DevRunners{
		Gateway: count("gateway"),
		Loggerd: count("loggerd"),
		Admin:   count("admin"),
		Log:     slog.New(slog.DiscardHandler),
	})

	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, map[string]int{"gateway": 1}, started)
}
