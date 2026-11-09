package run

import (
	"context"
	"log/slog"
	"testing"

	"github.com/reireirei/yabanin/pkg/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestOTelLogConfigFromEnv_DisabledWithoutEndpoint(t *testing.T) {
	cfg, ok := otelLogConfigFromEnv(func(string) string { return "" }, discardLogger())
	assert.False(t, ok, "no endpoint must disable export")
	assert.Empty(t, cfg.Endpoint)

	sink, enabled, err := newOTelLogSinkFromEnv(context.Background(), discardLogger())
	require.NoError(t, err)
	assert.False(t, enabled, "no endpoint → export off, consumer bit-for-bit unchanged")
	assert.Nil(t, sink)
}

func TestOTelLogConfigFromEnv_SampleRate(t *testing.T) {
	cases := []struct {
		raw  string
		want float64
	}{
		{"", 1.0},      // absent → default
		{"0", 0},       // explicit zero is a valid rate (suppress all)
		{"1", 1.0},     // explicit one is a valid rate (all)
		{"0.25", 0.25}, // fraction
		{"nan", 1.0},   // unparseable → default
		{"abc", 1.0},   // unparseable → default
		{"1.5", 1.0},   // out of range → default
		{"-1", 1.0},    // out of range → default
	}
	for _, tc := range cases {
		env := map[string]string{
			"YABANIN_OTEL_LOGS_ENDPOINT": "collector:4318",
			"YABANIN_OTEL_LOGS_SAMPLE":   tc.raw,
		}
		cfg, ok := otelLogConfigFromEnv(func(k string) string { return env[k] }, discardLogger())
		require.True(t, ok)
		assert.InDelta(t, tc.want, cfg.SampleRate, 1e-9, "YABANIN_OTEL_LOGS_SAMPLE=%q", tc.raw)
	}
}

func TestOTelLogConfigFromEnv_Headers(t *testing.T) {
	env := map[string]string{
		"YABANIN_OTEL_LOGS_ENDPOINT": "collector:4318",
		"YABANIN_OTEL_LOGS_HEADERS":  "Authorization: Bearer tok123, X-Tenant: acme ,, broken-header",
	}
	cfg, ok := otelLogConfigFromEnv(func(k string) string { return env[k] }, discardLogger())
	require.True(t, ok)
	assert.Equal(t, map[string]string{
		"Authorization": "Bearer tok123",
		"X-Tenant":      "acme",
	}, cfg.Headers, "valid K:V pairs parsed, malformed entries skipped")
}

func TestOTelLogConfigFromEnv_ServiceDefaults(t *testing.T) {
	env := map[string]string{"YABANIN_OTEL_LOGS_ENDPOINT": "https://collector.internal/v1/logs"}
	cfg, ok := otelLogConfigFromEnv(func(k string) string { return env[k] }, discardLogger())
	require.True(t, ok)
	assert.Equal(t, "loggerd", cfg.ServiceName)
	assert.False(t, cfg.IncludeContent, "content export must default to off")
}

// The full wiring: an endpoint produces a live (nil-check safe) sink whose
// config echoes the env values.
func TestNewOTelLogSinkFromEnv_EndpointBuildsSink(t *testing.T) {
	// Unreachable endpoint is fine: OTLP/HTTP connects lazily on export.
	t.Setenv("YABANIN_OTEL_LOGS_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("YABANIN_OTEL_LOGS_SAMPLE", "0.5")

	sink, enabled, err := newOTelLogSinkFromEnv(context.Background(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.True(t, enabled)
	require.NotNil(t, sink)
	e := sink.(*tracing.LogExporter)
	assert.Equal(t, "http://127.0.0.1:1", e.Config().Endpoint)
	assert.InDelta(t, 0.5, e.Config().SampleRate, 1e-9)
	assert.False(t, e.IncludeContent())
	require.NoError(t, sink.Shutdown(context.Background()))
}

// Standard OTel env vars must never enable the request-log sink: only the
// YABANIN_OTEL_LOGS_ENDPOINT knob decides (env isolation for the wiring).
func TestNewOTelLogSinkFromEnv_StandardOTelEnvCannotEnable(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://127.0.0.1:1")

	sink, enabled, err := newOTelLogSinkFromEnv(context.Background(), discardLogger())
	require.NoError(t, err)
	assert.False(t, enabled, "standard OTel env must not enable the sink")
	assert.Nil(t, sink)
}
