package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSber_TokenExchangeThenChat(t *testing.T) {
	t.Parallel()
	var tokenCalls int32
	var chatAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Basic auth on token exchange")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-123",
			"expires_at":   time.Now().Add(30 * time.Minute).UnixMilli(),
		})
	})
	mux.HandleFunc("/api/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		chatAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Override base URL by pointing Path's baseURL arg at the test server.
	s := NewSberWithClient(srv.Client())
	req, err := s.PrepareRequest(context.Background(), srv.URL, sberChatPath, []byte(`{"model":"gigachat"}`), "secret", false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	if atomic.LoadInt32(&tokenCalls) != 1 {
		t.Fatalf("expected 1 token call, got %d", tokenCalls)
	}
	if chatAuth != "Bearer AT-123" {
		t.Fatalf("chat auth = %q", chatAuth)
	}
}

func TestSber_TokenCached_NoSecondExchange(t *testing.T) {
	t.Parallel()
	var tokenCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-CACHED",
			"expires_at":   time.Now().Add(30 * time.Minute).UnixMilli(),
		})
	})
	mux.HandleFunc("/api/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := NewSberWithClient(srv.Client())
	for i := 0; i < 3; i++ {
		req, err := s.PrepareRequest(context.Background(), srv.URL, sberChatPath, []byte(`{}`), "secret", false)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		c := srv.Client()
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("iter %d Do: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if atomic.LoadInt32(&tokenCalls) != 1 {
		t.Fatalf("expected 1 token exchange for 3 calls, got %d", tokenCalls)
	}
}

func TestSber_TokenRefreshOnExpiry(t *testing.T) {
	t.Parallel()
	var tokenCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		// Issue a token that is ALREADY past the refresh skew (expires "now"),
		// forcing the next PrepareRequest to refresh again.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-" + strings.Repeat("x", int(atomic.LoadInt32(&tokenCalls))),
			"expires_at":   time.Now().UnixMilli(),
		})
	})
	mux.HandleFunc("/api/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := NewSberWithClient(srv.Client())
	for i := 0; i < 2; i++ {
		req, err := s.PrepareRequest(context.Background(), srv.URL, sberChatPath, []byte(`{}`), "secret", false)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("iter %d Do: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if atomic.LoadInt32(&tokenCalls) != 2 {
		t.Fatalf("expected 2 token exchanges (one per near-expiry call), got %d", tokenCalls)
	}
}

func TestSber_HTTPClientProvided(t *testing.T) {
	s := NewSberWithClient(nil)
	if s.HTTPClient() == nil {
		t.Fatal("HTTPClient must not be nil")
	}
}
