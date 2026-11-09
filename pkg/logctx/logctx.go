// Package logctx provides request-scoped logging helpers that bind a slog.Logger
// to a context so log lines automatically include the correlation ID
// (X-Request-ID) of the originating HTTP request.
package logctx

import (
	"context"
	"log/slog"

	"github.com/reireirei/yabanin/pkg/requestid"
)

type ctxKey struct{}

// WithLogger stores logger l in ctx. If the context already carries a request ID
// (via chi middleware.RequestID or pkg/requestid.Inject), the returned logger
// is annotated with request_id=<id> so every log line emitted from this context
// is correlatable.
func WithLogger(ctx context.Context, base *slog.Logger) context.Context {
	l := base
	if id := requestid.FromContext(ctx); id != "" {
		l = base.With("request_id", string(id))
	}
	return context.WithValue(ctx, ctxKey{}, l)
}

// From returns the logger stored in ctx via WithLogger, or fallback if absent.
func From(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return fallback
}

// RequestID returns the request ID stored in ctx, if any.
func RequestID(ctx context.Context) string {
	return string(requestid.FromContext(ctx))
}
