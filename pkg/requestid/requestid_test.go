package requestid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewID(t *testing.T) {
	id := newID()
	if len(id) == 0 {
		t.Fatal("expected non-empty ID")
	}
	if len(id) < 8 {
		t.Fatalf("expected ID to be at least 8 chars, got %d", len(id))
	}
}

func TestExtractFromHeader(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.Header.Set(RequestIDHeader, "test-req-id-123")
	got := Extract(r)
	if got != "test-req-id-123" {
		t.Fatalf("expected test-req-id-123, got %s", got)
	}
}

func TestExtractFromContext(t *testing.T) {
	ctx := NewContext(context.Background(), ID("ctx-id"))
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil).WithContext(ctx)
	got := Extract(r)
	if got != "ctx-id" {
		t.Fatalf("expected ctx-id, got %s", got)
	}
}

func TestExtractReturnsHeaderOverContext(t *testing.T) {
	ctx := NewContext(context.Background(), ID("ctx-id"))
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil).WithContext(ctx)
	r.Header.Set(RequestIDHeader, "header-id")
	got := Extract(r)
	if got != "header-id" {
		t.Fatalf("expected header-id to take precedence, got %s", got)
	}
}

func TestExtractEmpty(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	got := Extract(r)
	if got != "" {
		t.Fatalf("expected empty ID, got %s", got)
	}
}

func TestInjectGeneratesNewID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromContext(r.Context())
		if id == "" {
			t.Fatal("expected ID in context")
		}
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	Inject(next).ServeHTTP(w, req)

	got := w.Header().Get(RequestIDHeader)
	if got == "" {
		t.Fatal("expected X-Request-ID header on response")
	}
}

func TestInjectPreservesExistingID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromContext(r.Context())
		if id != "existing-id" {
			t.Fatalf("expected existing-id in context, got %s", id)
		}
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "existing-id")
	w := httptest.NewRecorder()
	Inject(next).ServeHTTP(w, req)

	got := w.Header().Get(RequestIDHeader)
	if got != "existing-id" {
		t.Fatalf("expected existing-id on response header, got %s", got)
	}
}

func TestPropagate(t *testing.T) {
	in := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	in.Header.Set(RequestIDHeader, "propagate-me")

	out := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/upstream", nil)
	Propagate(out, in)

	got := out.Header.Get(RequestIDHeader)
	if got != "propagate-me" {
		t.Fatalf("expected propagate-me, got %s", got)
	}
}

func TestPropagateEmpty(t *testing.T) {
	in := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	out := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/upstream", nil)
	Propagate(out, in)

	got := out.Header.Get(RequestIDHeader)
	if got != "" {
		t.Fatalf("expected empty header when no ID in request, got %s", got)
	}
}

func TestFromContext(t *testing.T) {
	ctx := NewContext(context.Background(), ID("from-ctx"))
	got := FromContext(ctx)
	if got != "from-ctx" {
		t.Fatalf("expected from-ctx, got %s", got)
	}
}

func TestFromContextEmpty(t *testing.T) {
	got := FromContext(context.Background())
	if got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}
