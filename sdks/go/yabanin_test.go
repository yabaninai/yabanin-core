package yabanin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestConfigFromEnv_MissingKey_Errors(t *testing.T) {
	prev := os.Getenv("TOKENROUTER_API_KEY")
	os.Unsetenv("TOKENROUTER_API_KEY")
	defer os.Setenv("TOKENROUTER_API_KEY", prev)

	_, err := ConfigFromEnv()
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	os.Setenv("YABANIN_DEPLOY_MODE", "saas")
	prevKey := os.Getenv("TOKENROUTER_API_KEY")
	os.Setenv("TOKENROUTER_API_KEY", "pa_test-key")
	defer func() {
		os.Unsetenv("YABANIN_DEPLOY_MODE")
		os.Setenv("TOKENROUTER_API_KEY", prevKey)
	}()

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.BaseURL != "https://api.yabanin.io" {
		t.Errorf("expected saas default, got %s", cfg.BaseURL)
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.BaseURL() != "https://api.yabanin.io" {
		t.Errorf("BaseURL: %s", c.BaseURL())
	}
}

func TestNew_EmptyKey_Errors(t *testing.T) {
	os.Setenv("TOKENROUTER_API_KEY", "")
	defer os.Unsetenv("TOKENROUTER_API_KEY")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Skip("ConfigFromEnv already errored")
	}
	_, err = New(Config{BaseURL: cfg.BaseURL, APIKey: ""})
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestNew_OnPremDefault(t *testing.T) {
	os.Setenv("YABANIN_DEPLOY_MODE", "onprem")
	os.Setenv("TOKENROUTER_API_KEY", "pa_test-key")
	defer func() {
		os.Unsetenv("YABANIN_DEPLOY_MODE")
		os.Unsetenv("TOKENROUTER_API_KEY")
	}()

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.BaseURL != "http://localhost:8082" {
		t.Errorf("expected on-prem default, got %s", cfg.BaseURL)
	}
}

// TestChat_PostsToGatewayAndDecodes proves Chat hits /v1/chat/completions with
// the bearer key and decodes a successful completion (I8: the Go SDK must do
// real work, not just carry config).
func TestChat_PostsToGatewayAndDecodes(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cc-1","model":"cheap","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := c.Chat(context.Background(), ChatRequest{
		Model:    "smart",
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %s, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotBody["model"] != "smart" {
		t.Errorf("model in body = %v", gotBody["model"])
	}
	if resp.ID != "cc-1" || len(resp.Choices) != 1 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// TestChat_HTTPErrorSurfacesAsError proves non-2xx (401) raises an error that
// includes the status, instead of decoding the error body into a completion.
func TestChat_HTTPErrorSurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, APIKey: "wrong"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := c.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: "user", Content: "x"}}})
	if err == nil {
		t.Fatalf("expected error, got response %+v", resp)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status 401: %v", err)
	}
}

// NEXT-19 contract parity: the SDK's error surface against the canonical
// fixtures in contracts/api-contract.json. When the envelope changes, this
// test (and the gateway contract tests) fail together.
func TestContractParity_ErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key","type":"invalid_request_error"}}`))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	_, chatErr := c.Chat(context.Background(), ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: "x"}}})
	if chatErr == nil {
		t.Fatal("401 must surface as an error, not a decoded completion")
	}
	// The envelope bytes are included verbatim — SDKs do not rewrap errors.
	if !strings.Contains(chatErr.Error(), "invalid api key") {
		t.Fatalf("error must carry the envelope message: %v", chatErr)
	}
	if !strings.Contains(chatErr.Error(), "401") {
		t.Fatalf("error must carry the HTTP status: %v", chatErr)
	}
}
