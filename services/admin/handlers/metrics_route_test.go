package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// exactly: the /metrics scrape endpoint is narrowed to GET/HEAD (RM-40 finding
// F2 — r.Handle accepted every method).
func mountMetricsHotPatch() http.Handler {
	r := chi.NewRouter()
	r.With(httpmw.MethodGuard(http.MethodGet, http.MethodHead)).Handle("/metrics", metrics.PrometheusHandler())
	return r
}

func TestMetricsRoute_PostRejected(t *testing.T) {
	router := mountMetricsHotPatch()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/metrics", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Fatalf("POST /metrics Allow header = %q, want %q", allow, "GET, HEAD")
	}

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, "/metrics", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /metrics: got %d, want 405", method, w.Code)
		}
	}
}

func TestMetricsRoute_GetHeadServed(t *testing.T) {
	router := mountMetricsHotPatch()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Error("GET /metrics: empty Content-Type, expected the Prometheus exposition format")
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("HEAD /metrics: got %d, want 200", w.Code)
	}
}

// --- W-SECADM: /metrics behind a bearer key -----------------------------------

const metricsTestKey = "wsecadm-metrics-scrape-key" // #nosec G101 -- test-only bearer value

// mountMetricsBearer builds a router with mountPublic on handlers carrying a
// configured bearer key (the production wiring in router_public.go).
func mountMetricsBearer(t *testing.T, key string) http.Handler {
	t.Helper()
	h := &AdminHandlers{metricsBearerKey: key, logger: quietLogger()}
	r := chi.NewRouter()
	h.mountPublic(r)
	return r
}

func TestMetricsBearer_RequiredWhenConfigured(t *testing.T) {
	router := mountMetricsBearer(t, metricsTestKey)

	// No Authorization header → 401 with a Bearer challenge, before any
	// method negotiation.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics without a key: got %d, want 401", w.Code)
	}
	if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", w.Header().Get("WWW-Authenticate"))
	}

	// Wrong token → 401.
	for _, auth := range []string{"Bearer wrong-key", "bearer " + metricsTestKey, "Basic dXNlcjpwYXNz", "Bearer "} {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", auth)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET /metrics with Authorization %q: got %d, want 401", auth, w.Code)
		}
	}

	// Correct token → 200, and non-GET/HEAD stays 405 (auth first, then the
	// method guard).
	w = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+metricsTestKey)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics with the key: got %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+metricsTestKey)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HEAD /metrics with the key: got %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+metricsTestKey)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics with the key: got %d, want 405", w.Code)
	}
}

// The legacy deployment contract holds: no key configured → the scrape stays
// open (protected at the network level, per config.yaml).
func TestMetricsBearer_UnsetKeepsLegacyOpenScrape(t *testing.T) {
	router := mountMetricsBearer(t, "")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics with no configured key: got %d, want 200", w.Code)
	}
}

// End-to-end through SetupRouter: SetMetricsBearerKey guards the public
// mount, and /health stays open next to it.
func TestMetricsBearer_SetupRouterWiring(t *testing.T) {
	h := &AdminHandlers{logger: quietLogger()}
	h.SetMetricsBearerKey(metricsTestKey)
	router := h.SetupRouter()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics without a key (SetupRouter): got %d, want 401", w.Code)
	}

	w = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+metricsTestKey)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics with the key (SetupRouter): got %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health must stay open: got %d, want 200", w.Code)
	}
}
