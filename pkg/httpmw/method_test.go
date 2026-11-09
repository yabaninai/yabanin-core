package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMethodGuard_AllowsListedMethods(t *testing.T) {
	called := false
	h := MethodGuard(http.MethodGet, http.MethodHead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, "/metrics", nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: got %d, want 200", method, w.Code)
		}
	}
	if !called {
		t.Fatal("wrapped handler was never called")
	}
}

func TestMethodGuard_RejectsOthersWith405AndAllow(t *testing.T) {
	h := MethodGuard(http.MethodGet, http.MethodHead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("wrapped handler must not run for a rejected method")
	}))

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, "TRACE"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, "/metrics", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d, want 405", method, w.Code)
		}
		if allow := w.Header().Get("Allow"); allow != "GET, HEAD" {
			t.Errorf("%s: Allow = %q, want %q", method, allow, "GET, HEAD")
		}
	}
}
