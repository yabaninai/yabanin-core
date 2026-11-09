package logctx

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestID_ReturnsIDFromChiContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "req-abc-123")
	assert.Equal(t, "req-abc-123", RequestID(ctx))
}

func TestRequestID_EmptyWhenAbsent(t *testing.T) {
	assert.Empty(t, RequestID(context.Background()))
}

func TestFrom_ReturnsFallbackWhenNoLoggerStored(t *testing.T) {
	var buf bytes.Buffer
	fallback := slog.New(slog.NewTextHandler(&buf, nil))
	l := From(context.Background(), fallback)
	require.NotNil(t, l)
	l.Info("hello")
	assert.Contains(t, buf.String(), "hello")
}

func TestWithLogger_AnnotatesWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "req-xyz-789")
	ctx = WithLogger(ctx, base)

	l := From(ctx, base)
	l.Info("correlated log line")

	out := buf.String()
	assert.Contains(t, out, "correlated log line")
	assert.Contains(t, out, "request_id=req-xyz-789")
}

func TestWithLogger_NoRequestID_StoresPlainLogger(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewTextHandler(&buf, nil))
	ctx := WithLogger(context.Background(), base)

	l := From(ctx, base)
	require.NotNil(t, l)
	l.Info("plain line")

	assert.Contains(t, buf.String(), "plain line")
	assert.NotContains(t, buf.String(), "request_id=",
		"no request_id key when ctx has no request id")
}

func TestWithLogger_IDempotentOverwrite(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "first-id")
	ctx = WithLogger(ctx, base)

	// Calling WithLogger again with the same context should still work.
	ctx2 := WithLogger(ctx, base)
	l := From(ctx2, base)
	l.Info("again")
	assert.Contains(t, buf.String(), "request_id=first-id")
}
