package pprof

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	// Check that the page has pprof content.
	body := rec.Body.String()
	if len(body) == 0 {
		t.Error("expected non-empty response body")
	}
}

func TestHandlerEndpoints(t *testing.T) {
	h := Handler()
	endpoints := []string{
		"/debug/pprof/",          // Index page
		"/debug/pprof/goroutine", // Goroutine profile
		"/debug/pprof/heap",      // Heap profile
	}
	for _, ep := range endpoints {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code < 200 || rec.Code > 399 {
			t.Errorf("endpoint %s: expected success, got %d", ep, rec.Code)
		}
	}
}
