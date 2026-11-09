package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// newGatedPprofRouter wires the gated pprof routes exactly like Run() does.
func newGatedPprofRouter(gw *gateway) chi.Router {
	r := chi.NewRouter()
	gw.registerGatedPprof(r)
	return r
}

// TestGatedPprof_NonLocalhostRejected pins the C1 fix: an outside caller gets
// no pprof content, valid key or not.
func TestGatedPprof_NonLocalhostRejected(t *testing.T) {
	gw := &gateway{cfg: newGatewayConfig("header", "admin-key", "")}
	r := newGatedPprofRouter(gw)

	// Default httptest RemoteAddr is 192.0.2.1:1234 — not localhost.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/debug/pprof/", nil)
	req.Header.Set("Authorization", "Bearer admin-key")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestGatedPprof_LocalhostWithoutKeyRejected pins the second half of the gate:
// localhost alone is not enough. Status mirrors /debug/vars rejections (403).
func TestGatedPprof_LocalhostWithoutKeyRejected(t *testing.T) {
	gw := &gateway{cfg: newGatewayConfig("header", "admin-key", "")}
	r := newGatedPprofRouter(gw)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/debug/pprof/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestGatedPprof_LocalhostWithKeyServed pins that the gate does not block
// legitimate local debugging: localhost + key reaches the real pprof index.
func TestGatedPprof_LocalhostWithKeyServed(t *testing.T) {
	gw := &gateway{cfg: newGatewayConfig("header", "admin-key", "")}
	r := newGatedPprofRouter(gw)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/debug/pprof/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Authorization", "Bearer admin-key")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
