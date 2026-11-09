package requestid

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// RequestIDHeader is the header carrying the request ID both ways.
const RequestIDHeader = "X-Request-ID"

// contextKey is a custom type to avoid collisions when used as context keys.
type contextKey struct{ string }

// ContextKey is the context key under which the request ID is stored.
var ContextKey = contextKey{"request_id"}

// ID is a type-safe string wrapper for request IDs.
type ID string

// newID generates a 16-byte hex request ID.
func newID() ID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ID(fmt.Sprintf("unr_%d", timeNow()))
	}
	return ID(fmt.Sprintf("req_%x", b))
}

// timeNow returns current time (overridable for tests).
var timeNow = func() int64 { return time.Now().UnixNano() }

// FromContext extracts the request ID from context. Returns empty string if not found.
func FromContext(ctx context.Context) ID {
	if v, ok := ctx.Value(ContextKey).(ID); ok {
		return v
	}
	if id := middleware.GetReqID(ctx); id != "" {
		return ID(id)
	}
	return ""
}

// NewContext adds a request ID to context.
func NewContext(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, ContextKey, id)
}

// Extract retrieves the request ID from the request header.
// If absent, returns empty string.
func Extract(r *http.Request) ID {
	if id := r.Header.Get(RequestIDHeader); id != "" {
		return ID(strings.TrimSpace(id))
	}
	return FromContext(r.Context())
}

// Inject sets the request ID header on the response and adds it to context.
// If no ID is present in the request, generates a new one.
func Inject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := Extract(r)
		if id == "" {
			id = newID()
		}
		w.Header().Set(RequestIDHeader, string(id))
		r = r.WithContext(NewContext(r.Context(), id))
		next.ServeHTTP(w, r)
	})
}

// Propagate copies the request ID from the incoming request to an outgoing request.
func Propagate(out *http.Request, in *http.Request) {
	if id := Extract(in); id != "" {
		out.Header.Set(RequestIDHeader, string(id))
	}
}
