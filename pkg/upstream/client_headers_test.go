package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardJSONWithHeaders_CapturesResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Yabanin-Region", "JP")
		w.Header().Set("Cf-Ray", "84a1c-NRT")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion"}`))
	}))
	defer srv.Close()

	c, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "openai"})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}

	hdrs, body, err := c.ForwardJSONWithHeaders(context.Background(), []byte(`{"messages":[]}`), "", "", 0)
	if err != nil {
		t.Fatalf("ForwardJSONWithHeaders: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty response body")
	}
	if got := hdrs.Get("X-Yabanin-Region"); got != "JP" {
		t.Fatalf("X-Yabanin-Region = %q, want JP", got)
	}
	if got := hdrs.Get("Cf-Ray"); got != "84a1c-NRT" {
		t.Fatalf("Cf-Ray = %q, want 84a1c-NRT", got)
	}
}

func TestForwardJSONWrappers_Unchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion"}`))
	}))
	defer srv.Close()

	c, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "openai"})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}

	b, err := c.ForwardJSON(context.Background(), []byte(`{"messages":[]}`), "", "")
	if err != nil || len(b) == 0 {
		t.Fatalf("ForwardJSON: body=%q err=%v", b, err)
	}
	b, err = c.ForwardJSONWithTimeout(context.Background(), []byte(`{"messages":[]}`), "", "", 0)
	if err != nil || len(b) == 0 {
		t.Fatalf("ForwardJSONWithTimeout: body=%q err=%v", b, err)
	}
}
