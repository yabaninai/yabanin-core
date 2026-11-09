package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestRegisterMetrics covers the /metrics bearer decision: empty key keeps the
// unauthenticated scrape path, a configured key requires "Bearer <key>".
func TestRegisterMetrics(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		authHeader string
		want       int
	}{
		{name: "no key configured allows unauthenticated", want: http.StatusOK},
		{name: "key set without header rejects", key: "scrape-secret", want: http.StatusUnauthorized},
		{name: "key set with wrong bearer rejects", key: "scrape-secret", authHeader: "Bearer wrong-token", want: http.StatusUnauthorized},
		{name: "key set with bare word rejects", key: "scrape-secret", authHeader: "Bearer", want: http.StatusUnauthorized},
		{name: "key set with matching bearer passes", key: "scrape-secret", authHeader: "Bearer scrape-secret", want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newGatewayConfig("header", "test-key", "")
			cfg.MetricsBearerKey = tt.key
			gw := &gateway{cfg: cfg}
			r := chi.NewRouter()
			gw.registerMetrics(r, testLogger())

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("want status %d, got %d (body: %s)", tt.want, rec.Code, rec.Body.String())
			}
		})
	}
}
