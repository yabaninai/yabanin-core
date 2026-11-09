package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(server.URL, []string{server.URL})
	require.NoError(t, err)
	return c
}

// newTestClientWithAdapter pins local fixture servers explicitly while keeping
// tests focused on their provider behavior rather than egress configuration.
func newTestClientWithAdapter(opts Options) (*Client, error) {
	if len(opts.AllowedUpstreams) == 0 {
		parsed, err := url.Parse(opts.BaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			return NewClientWithAdapter(opts)
		}
		opts.AllowedUpstreams = []string{parsed.Scheme + "://" + parsed.Host}
	}
	return NewClientWithAdapter(opts)
}

func TestForwardJSON_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err) // handler goroutine: FailNow here is invalid
		assert.Contains(t, string(body), `"messages"`)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-123","object":"chat.completion","choices":[{"message":{"content":"hello"}}]}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)
	respBody, err := client.ForwardJSON(context.Background(), body, "gpt-4", "test-key")

	require.NoError(t, err)
	assert.Contains(t, string(respBody), `"chatcmpl-123"`)
}

func TestForwardJSON_TrailingSlashBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-456"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	respBody, err := client.ForwardJSON(context.Background(), []byte("{}"), "gpt-4", "test-key")

	require.NoError(t, err)
	assert.Contains(t, string(respBody), `"chatcmpl-456"`)
}

func TestForwardJSON_UpstreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"upstream down"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	respBody, err := client.ForwardJSON(context.Background(), []byte("{}"), "gpt-4", "test-key")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
	assert.Contains(t, err.Error(), "upstream down")
	assert.Nil(t, respBody)

	// W-PROV: the failure is typed — the gateway maps Status without parsing
	// error strings, and errors.As works through wrapping.
	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	assert.Equal(t, http.StatusBadGateway, uerr.Status)
	assert.Contains(t, uerr.Body, "upstream down")
	wrapped := fmt.Errorf("hop m1: %w", err)
	var werr *Error
	require.ErrorAs(t, wrapped, &werr)
	assert.Equal(t, http.StatusBadGateway, werr.Status)
}

// TestForwardJSON_TranslateResponseErrorTyped (W-PROV): a 200 whose body the
// adapter cannot convert into the OpenAI response contract must surface as a
// typed TranslateError — the raw provider body must never be handed to an
// OpenAI client.
func TestForwardJSON_TranslateResponseErrorTyped(t *testing.T) {
	for _, tc := range []struct {
		name         string
		providerName string
		respBody     string
	}{
		{"anthropic malformed", "anthropic", `not-json`},
		{"tgi malformed", "tgi", `not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.respBody))
			}))
			defer server.Close()

			client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: tc.providerName})
			require.NoError(t, err)
			respBody, ferr := client.ForwardJSON(context.Background(),
				[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`), "m", "k")

			require.Error(t, ferr)
			assert.Nil(t, respBody, "the raw provider-native body must not be returned to the caller")
			var terr *TranslateError
			require.ErrorAs(t, ferr, &terr)
			assert.NotEmpty(t, terr.Provider)
			require.Error(t, terr.Err)
		})
	}
}

// TestStream_UpstreamErrorTyped (W-PROV): the streaming path must return the
// typed error with the upstream status and body, not a formatted string.
func TestStream_UpstreamErrorTyped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	//nolint:bodyclose // error path: Stream returns a nil response on failure, asserted below
	resp, err := client.Stream(context.Background(), []byte(`{"model":"gpt-4","stream":true}`), "k")
	require.Error(t, err)
	require.Nil(t, resp)
	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	assert.Equal(t, http.StatusTooManyRequests, uerr.Status)
	assert.Contains(t, uerr.Body, "slow down")
	assert.Equal(t, "upstream error 429: "+uerr.Body, uerr.Error(), "legacy log/wire text must be preserved")
}

func TestForwardJSON_UpstreamReadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		http.Error(w, "", 0) // triggers connection close
	}))
	defer server.Close()

	client := newTestClient(t, server)
	respBody, err := client.ForwardJSON(context.Background(), []byte("{}"), "gpt-4", "test-key")

	if err == nil {
		assert.NotNil(t, respBody)
	} else {
		assert.Error(t, err)
	}
}

func TestForwardJSON_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {}
	}))
	defer server.Close()

	client := newTestClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	respBody, err := client.ForwardJSON(ctx, []byte("{}"), "gpt-4", "test-key")

	require.Error(t, err)
	// Either the explicit cancellation message or the generic failure wrapper
	// is acceptable — both indicate the request never completed.
	msg := err.Error()
	assert.True(t,
		strings.Contains(msg, "upstream request cancelled") ||
			strings.Contains(msg, "upstream request failed") ||
			strings.Contains(msg, "context canceled"),
		"unexpected error: %q", msg)
	assert.Nil(t, respBody)
}

func TestStream_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "text/event-stream", r.Header.Get("Accept"))
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"content\":\"hello\"}\n\n"))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	resp, err := client.Stream(context.Background(), []byte(`{"model":"gpt-4"}`), "test-key")

	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
}

func TestStream_UpstreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	resp, err := client.Stream(context.Background(), []byte(`{}`), "test-key")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	if resp != nil {
		defer resp.Body.Close()
	}
	assert.Nil(t, resp)
}

func TestStream_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {}
	}))
	defer server.Close()

	client := newTestClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err := client.Stream(ctx, []byte(`{}`), "test-key")

	require.Error(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	assert.Nil(t, resp)
}

func TestNewUpstreamClient(t *testing.T) {
	client, err := NewClient("http://localhost:8081", []string{"http://localhost:8081"})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8081", client.baseURL)
	assert.NotNil(t, client.client)
}

func TestNewClient_SSRFViolation_ReturnsError(t *testing.T) {
	c, err := NewClient("http://169.254.169.254", []string{"https://api.openai.com"})
	require.Error(t, err, "SSRF-allowlist violation must return an error, not panic (IMP-92)")
	assert.Nil(t, c)
}

func TestForwardJSON_NonexistentModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"model not found"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	respBody, err := client.ForwardJSON(context.Background(), []byte(`{"model":"nonexistent"}`), "nonexistent", "test-key")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "model not found")
	assert.Nil(t, respBody)
}

func TestStream_TrailingSlashBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: test\n\n"))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	resp, err := client.Stream(context.Background(), []byte(`{}`), "test-key")

	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyBytes), "test")
}

func TestForwardJSON_BodyContainsRequiredFields(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err) // handler goroutine: FailNow here is invalid
		err = json.Unmarshal(body, &receivedBody)
		assert.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"test-1"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	reqBody := map[string]any{
		"model":    "gpt-4",
		"messages": []any{map[string]any{"role": "user", "content": "hello"}},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	respBody, err := client.ForwardJSON(context.Background(), bodyBytes, "gpt-4", "test-key")

	require.NoError(t, err)
	assert.Contains(t, string(respBody), `"test-1"`)
	assert.Equal(t, "gpt-4", receivedBody["model"])
}

func TestForwardJSON_ContentTypeHeader(t *testing.T) {
	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	_, err := client.ForwardJSON(context.Background(), []byte(`{"model":"gpt-4"}`), "gpt-4", "test-key")

	require.NoError(t, err)
	assert.Equal(t, "application/json", contentType)
}

func TestStream_AcceptHeader(t *testing.T) {
	var accept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	resp, err := client.Stream(context.Background(), []byte(`{}`), "test-key")

	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, "text/event-stream", accept)
}

func TestForwardJSON_APIKeyUsed(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	_, err := client.ForwardJSON(context.Background(), []byte(`{}`), "gpt-4", "my-custom-key")

	require.NoError(t, err)
	assert.Equal(t, "Bearer my-custom-key", authHeader)
}

func TestStream_APIKeyUsed(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	resp, err := client.Stream(context.Background(), []byte(`{}`), "my-custom-key")

	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, "Bearer my-custom-key", authHeader)
}

func TestForwardJSON_BadURL(t *testing.T) {
	client := &Client{
		baseURL: "://invalid-url",
		adapter: provider.OpenAI{},
		client:  &http.Client{},
	}
	respBody, err := client.ForwardJSON(context.Background(), []byte(`{}`), "gpt-4", "test-key")

	require.Error(t, err)
	assert.Nil(t, respBody)
}

func TestStream_BadURL(t *testing.T) {
	client := &Client{
		baseURL: "://invalid-url",
		adapter: provider.OpenAI{},
		client:  &http.Client{},
	}
	resp, err := client.Stream(context.Background(), []byte(`{}`), "test-key")

	require.Error(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	assert.Nil(t, resp)
}

func TestForwardJSON_JSONParseableResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"delta":{"content":"partial"},"index":0}]}`))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	respBody, err := client.ForwardJSON(context.Background(), []byte(`{}`), "gpt-4", "test-key")

	require.NoError(t, err)
	var result map[string]any
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-abc", result["id"])
}

func TestStream_MultipleDataFrames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"content\":\"step1\"}\n\ndata: {\"content\":\"step2\"}\n\n"))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	resp, err := client.Stream(context.Background(), []byte(`{}`), "test-key")

	require.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyBytes), "step1")
	assert.Contains(t, string(bodyBytes), "step2")
}

// NEXT upstream capture: ForwardJSONCapturing must return the EXACT body
// sent upstream (post adapter translation + model override) — the evidence
// the explorer shows next to the client's original payload.
func TestForwardJSONCapturing_ReturnsSentBody(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"id":"1","model":"other-model","choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, []string{srv.URL})
	require.NoError(t, err)
	clientBody := []byte(`{"model":"client-model","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`)

	_, respBody, sent, err := c.ForwardJSONCapturing(context.Background(), clientBody, "other-model", "k", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// The upstream saw the overridden model…
	if string(received) != string(sent) {
		t.Fatalf("captured sent body != what upstream received:\nsent: %s\ngot:  %s", sent, received)
	}
	if !strings.Contains(string(sent), `"other-model"`) {
		t.Fatalf("sent body must carry the overridden model: %s", sent)
	}
	// …and the response round-trips alongside.
	if !strings.Contains(string(respBody), `"ok"`) {
		t.Fatalf("response body missing content: %s", respBody)
	}
}

func TestClientDo_OpenAIAuthAndPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/embeddings", r.URL.Path)
		assert.Equal(t, "Bearer k", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "openai"})
	require.NoError(t, err)
	resp, err := client.Do(context.Background(), "/v1/embeddings", []byte(`{"model":"m"}`), "k", false, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestClientDo_AnthropicHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "k", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		assert.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "anthropic"})
	require.NoError(t, err)
	resp, err := client.Do(context.Background(), "/v1/messages", []byte(`{"model":"m"}`), "k", false, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestClientDo_ExtraHeadersOverrideAndDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer other", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Content-Type"))
		assert.Equal(t, "1", r.Header.Get("X-Extra"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "openai"})
	require.NoError(t, err)
	extra := http.Header{}
	extra.Set("Authorization", "Bearer other")
	extra.Set("Content-Type", "")
	extra.Set("X-Extra", "1")
	resp, err := client.Do(context.Background(), "/v1/embeddings", []byte(`{}`), "k", false, extra)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func TestClientDo_Non200ReturnedAsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "openai"})
	require.NoError(t, err)
	resp, err := client.Do(context.Background(), "/v1/embeddings", []byte(`{}`), "k", false, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestClientDo_SSRFBlocked(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestClientWithAdapter(Options{
		BaseURL:          server.URL,
		ProviderName:     "openai",
		AllowedUpstreams: []string{server.URL},
	})
	require.NoError(t, err)
	client.baseURL = "https://evil.example"
	resp, err := client.Do(context.Background(), "/v1/embeddings", []byte(`{}`), "k", false, nil)
	if resp != nil && resp.Body != nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("close body: %v", cerr)
		}
	}
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.False(t, called)
}

func TestOverrideModelRaw_PreservesBigIntsAndOrder(t *testing.T) {
	in := []byte(`{"model":"old","n":12345678901234567890,"ok":true}`)
	got := OverrideModelRaw(in, "new-model")
	assert.Contains(t, string(got), "12345678901234567890")
	assert.NotContains(t, string(got), "1.2345678901234568e")
	require.JSONEq(t, `{"model":"new-model","n":12345678901234567890,"ok":true}`, string(got))

	bad := []byte(`not-json`)
	assert.Equal(t, string(bad), string(OverrideModelRaw(bad, "m")))
	assert.Contains(t, string(OverrideModel([]byte(`{"model":"old"}`), "kept")), `"kept"`)
}

func TestClientDo_TransportErrorsAndRequestID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "req-1", r.Header.Get("X-Request-ID"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "openai"})
	require.NoError(t, err)

	ctx := requestid.NewContext(context.Background(), "req-1")
	resp, err := client.Do(ctx, "/v1/embeddings", []byte(`{}`), "k", true, nil)
	require.NoError(t, err)
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("close body: %v", cerr)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err = client.Do(canceled, "/v1/embeddings", []byte(`{}`), "k", false, nil)
	if resp != nil && resp.Body != nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("close body: %v", cerr)
		}
	}
	require.ErrorContains(t, err, "upstream request cancelled")

	expired, cancelExpired := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelExpired()
	time.Sleep(time.Millisecond)
	resp, err = client.Do(expired, "/v1/embeddings", []byte(`{}`), "k", false, nil)
	if resp != nil && resp.Body != nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("close body: %v", cerr)
		}
	}
	require.ErrorContains(t, err, "upstream request timeout")

	down, err := newTestClientWithAdapter(Options{BaseURL: "http://127.0.0.1:1", ProviderName: "openai"})
	require.NoError(t, err)
	resp, err = down.Do(context.Background(), "/v1/embeddings", []byte(`{}`), "k", false, nil)
	if resp != nil && resp.Body != nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("close body: %v", cerr)
		}
	}
	require.ErrorContains(t, err, "upstream request failed")

	badURL, err := NewClientWithAdapter(Options{BaseURL: "http://[::1", AllowedUpstreams: []string{"http://[::1"}, ProviderName: "openai"})
	require.ErrorContains(t, err, "invalid provider URL")
	require.Nil(t, badURL)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	applyExtraHeaders(req, http.Header{"Content-Type": nil, "X-Keep": {"yes"}})
	assert.Empty(t, req.Header.Get("Content-Type"))
	assert.Equal(t, "yes", req.Header.Get("X-Keep"))
}

func TestTranslateError_ErrorAndUnwrap(t *testing.T) {
	var nilTranslateError *TranslateError
	assert.Equal(t, "upstream: translate response: <nil>", nilTranslateError.Error())

	underlying := errors.New("invalid provider response")
	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{name: "without provider", want: "upstream: translate response: invalid provider response"},
		{name: "with provider", provider: "anthropic", want: "upstream anthropic: translate response: invalid provider response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			translateErr := &TranslateError{Provider: tc.provider, Err: underlying}
			assert.Equal(t, tc.want, translateErr.Error())
			wrapped := fmt.Errorf("gateway response translation: %w", translateErr)
			require.ErrorIs(t, wrapped, underlying)
			assert.Same(t, underlying, translateErr.Unwrap())
		})
	}
}

func TestClientCheckRequestURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	client := newTestClient(t, server)
	validURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		target  *url.URL
		wantErr string
	}{
		{name: "valid", target: validURL},
		{name: "empty", target: &url.URL{}, wantErr: "invalid upstream URL"},
		{name: "unsupported scheme", target: &url.URL{Scheme: "ftp", Host: validURL.Host}, wantErr: "invalid upstream URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := client.checkRequestURL(tc.target)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestStream_TransportFailure(t *testing.T) {
	client, err := newTestClientWithAdapter(Options{BaseURL: "http://127.0.0.1:1", ProviderName: "openai"})
	require.NoError(t, err)

	resp, err := client.Stream(context.Background(), []byte(`{}`), "k")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorContains(t, err, "upstream stream failed")
}

func TestStream_DeadlineExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client := newTestClient(t, server)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	resp, err := client.Stream(ctx, []byte(`{}`), "k")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorContains(t, err, "upstream stream deadline exceeded")
}

func TestStream_TranslateRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "anthropic"})
	require.NoError(t, err)

	resp, err := client.Stream(context.Background(), []byte(`not-json`), "k")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorContains(t, err, "translate stream request")
}

// TestForwardJSON_TranslateRequestErrorIsTypedNotSent (N07-P01-T05): a
// translate-layer refusal is the typed proof the request never left this
// process — no dial, no bytes, no outcome ambiguity. Wrapping it at the
// seam keeps the exact adapter reason (I51) visible in Error() while making
// the fact machine-checkable for the retry classifier, the fallback chain
// and the gateway render.
func TestForwardJSON_TranslateRequestErrorIsTypedNotSent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "anthropic"})
	require.NoError(t, err)

	_, _, sent, ferr := client.ForwardJSONCapturing(context.Background(), []byte(`not-json`), "", "k", 0)
	require.Error(t, ferr)
	var ns *retry.RequestNotSentError
	require.ErrorAs(t, ferr, &ns, "translate refusal must be the typed not-sent proof")
	assert.Contains(t, ferr.Error(), "translate request", "the layer that refused must stay visible")
	assert.Nil(t, sent, "nothing was sent")
}

func TestStream_TranslateRequestErrorIsTypedNotSent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := newTestClientWithAdapter(Options{BaseURL: server.URL, ProviderName: "anthropic"})
	require.NoError(t, err)

	resp, serr := client.Stream(context.Background(), []byte(`not-json`), "k")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Nil(t, resp)
	var ns *retry.RequestNotSentError
	require.ErrorAs(t, serr, &ns)
	assert.Contains(t, serr.Error(), "translate stream request")
}
