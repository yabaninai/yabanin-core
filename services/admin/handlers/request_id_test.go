package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Regression (2026-09-15): gateway request ids contain a slash
// ("host/counter-000244"); clients encode it as %2F. chi routes on RawPath
// and hands the handler the STILL-ENCODED param — lookups 404'd and the
// explorer/lineage detail views rendered empty ("raw record null").
func TestRequestIDParamDecodesSlash(t *testing.T) {
	r := chi.NewRouter()
	var got string
	r.Get("/api/organizations/{id}/requests/{request_id}", func(w http.ResponseWriter, req *http.Request) {
		got = requestIDParam(req)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/organizations/org-a/requests/ReiReiReiMax.local%2F1tObQmk4CQ-000244", nil)
	// Force the same condition net/http produces for encoded slashes: a
	// non-empty RawPath (this is exactly what the browser fetch produced).
	if u := req.URL; u.RawPath == "" {
		u.RawPath = "/api/organizations/org-a/requests/ReiReiReiMax.local%2F1tObQmk4CQ-000244"
	}
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("route did not match encoded slash id: %d", rw.Code)
	}
	if got != "ReiReiReiMax.local/1tObQmk4CQ-000244" {
		t.Fatalf("requestIDParam = %q, want the DECODED id", got)
	}
}

func TestRequestIDParamPlainIdUnchanged(t *testing.T) {
	r := chi.NewRouter()
	var got string
	r.Get("/r/{request_id}", func(w http.ResponseWriter, req *http.Request) {
		got = requestIDParam(req)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/r/202609150043406c6f321531d94a0d", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	if got != "202609150043406c6f321531d94a0d" {
		t.Fatalf("plain id mangled: %q", got)
	}
}
