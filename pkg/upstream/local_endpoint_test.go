package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/testutil/mockopenai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const localCompletionBody = `{"id":"cmpl-local-1","object":"chat.completion","model":"local-qwen","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":5,"total_tokens":16}}`

func TestLocalEndpoint_EndToEndChat_CloudFree(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	mi := resolver.ModelInfo{
		ModelName:       "local-qwen",
		DisplayName:     "Local Qwen",
		Tier:            "smart",
		UpstreamURL:     srv.URL,
		UpstreamTimeout: 2 * time.Second,
		Provider:        "llamacpp",
		Enabled:         true,
	}

	pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
	client, err := pool.Get(mi.UpstreamURL, mi.Provider)
	require.NoError(t, err)
	require.Equal(t, "llamacpp", client.Adapter().Name())

	chatBody := []byte(`{"model":"any-alias","messages":[{"role":"user","content":"ping"}],"max_tokens":16}`)
	_, respBody, _, ferr := client.ForwardJSONCapturing(context.Background(), chatBody, mi.ModelName, "", mi.UpstreamTimeout)
	require.NoError(t, ferr)

	reqs := mock.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
	assert.Equal(t, srv.Listener.Addr().String(), reqs[0].Host)
	assert.Equal(t, "application/json", reqs[0].Header.Get("Content-Type"))
	assert.Empty(t, reqs[0].Header.Get("Authorization"))

	var sent map[string]any
	require.NoError(t, json.Unmarshal([]byte(reqs[0].Body), &sent))
	assert.Equal(t, mi.ModelName, sent["model"])
	assert.Contains(t, sent, "messages")
	assert.NotContains(t, sent, "inputs")
	assert.NotContains(t, sent, "parameters")

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(respBody, &out))
	require.NotEmpty(t, out.Choices)
	assert.Equal(t, "pong", out.Choices[0].Message.Content)

	u := client.Adapter().ParseUsage(respBody)
	assert.Equal(t, provider.UsageSourceProvider, u.Source)
	assert.Equal(t, int64(11), u.PromptTokens)
	assert.Equal(t, int64(5), u.CompletionTokens)
	assert.Equal(t, int64(16), u.TotalTokens)

	ext := provider.ComputeCost(u, mi.Provider, mi.ModelName)
	assert.False(t, ext.PriceKnown)
	assert.Zero(t, ext.EstimatedCostUSD)
	assert.Equal(t, "llamacpp", ext.ProviderName)
}

func TestLocalEndpoint_EmptyProviderRowResolvesOpenAICompat(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	mi := resolver.ModelInfo{
		ModelName:       "local-qwen",
		UpstreamURL:     srv.URL,
		UpstreamTimeout: 2 * time.Second,
		Provider:        "",
	}

	pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
	client, err := pool.Get(mi.UpstreamURL, mi.Provider)
	require.NoError(t, err)
	assert.Equal(t, "openai", client.Adapter().Name())

	respBody, ferr := client.ForwardJSONWithTimeout(context.Background(),
		[]byte(`{"model":"local-qwen","messages":[{"role":"user","content":"ping"}]}`),
		mi.ModelName, "", mi.UpstreamTimeout)
	require.NoError(t, ferr)
	assert.Contains(t, string(respBody), "pong")

	reqs := mock.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
}

func TestLocalEndpoint_LocalAdapterNamesChat(t *testing.T) {
	for _, name := range []string{"llamacpp", "vllm", "ollama"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := mockopenai.New()
			mock.SetResponse(http.StatusOK, localCompletionBody)
			srv := httptest.NewServer(mock)
			t.Cleanup(srv.Close)

			pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
			client, err := pool.Get(srv.URL, name)
			require.NoError(t, err)
			assert.Equal(t, name, client.Adapter().Name())

			respBody, ferr := client.ForwardJSON(context.Background(),
				[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
			require.NoError(t, ferr)
			assert.Contains(t, string(respBody), "pong")

			reqs := mock.Requests()
			require.Len(t, reqs, 1)
			assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
		})
	}
}

func TestLocalEndpoint_OptionalBearerKey(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	client, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "llamacpp"})
	require.NoError(t, err)

	_, ferr := client.ForwardJSON(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`), "m", "k")
	require.NoError(t, ferr)

	reqs := mock.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "Bearer k", reqs[0].Header.Get("Authorization"))
}

// TestLocalEndpoint_UnknownCapabilityRefusedNotRouted pins the packet
// failure scenario "unknown capability" (contract §5 row 1, example 2): a
// typo'd local provider name is refused explicitly at the pool/factory
// boundary with the canonical `unknown provider %q` text — it must never
// silently fall back to a cloud adapter, no upstream may be contacted for
// the refused candidate (chat.go:772-778 turns this into a 502 config error
// and advances the failover chain), and the pool must stay usable so the
// next candidate resolves normally.
func TestLocalEndpoint_UnknownCapabilityRefusedNotRouted(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
	client, err := pool.Get(srv.URL, "llama-cpp")
	require.Error(t, err)
	require.Nil(t, client)
	assert.Contains(t, err.Error(), `unknown provider "llama-cpp"`,
		"refusal must name the misconfigured capability verbatim (diagnosable, not silent)")
	assert.Zero(t, mock.CallCount(),
		"refused candidate must not contact any upstream — no silent fallback to a cloud adapter")
	assert.Equal(t, 0, pool.Size(), "the failed key must not be cached")

	// The pool still serves the chain's next candidate: the correctly
	// spelled local name resolves and completes a chat.
	good, gerr := pool.Get(srv.URL, "llamacpp")
	require.NoError(t, gerr)
	respBody, ferr := good.ForwardJSON(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
	require.NoError(t, ferr)
	assert.Contains(t, string(respBody), "pong")
	assert.Equal(t, 1, mock.CallCount())
}

// TestLocalEndpoint_AllowlistedPrivateEndpointDials pins the D-4 fix
// (owner decision 2026-10-13): an exact allow-list entry is an explicit
// operator pin (pkg/ssrf trustExactPins), so a loopback/RFC1918 local
// provider behind allowed_upstreams is dialable with the guard on. The
// pins. The dial-time GuardDialedIP transport still pins the resolved IP
// against DNS rebinding (rebind_guard_test.go), and wildcard/default-mode
// lists keep refusing reserved ranges (pkg/ssrf tests).
func TestLocalEndpoint_AllowlistedPrivateEndpointDials(t *testing.T) {
	t.Parallel()

	t.Run("loopback explicitly listed dials end-to-end", func(t *testing.T) {
		t.Parallel()
		mock := mockopenai.New()
		mock.SetResponse(http.StatusOK, localCompletionBody)
		srv := httptest.NewServer(mock)
		t.Cleanup(srv.Close)

		client, cerr := newTestClientWithAdapter(Options{
			BaseURL:          srv.URL,
			ProviderName:     "llamacpp",
			AllowedUpstreams: []string{"http://" + srv.Listener.Addr().String()},
		})
		require.NoError(t, cerr, "an explicitly allow-listed host must pass construction")

		respBody, ferr := client.ForwardJSON(context.Background(),
			[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
		require.NoError(t, ferr, "an explicitly allow-listed loopback endpoint must be dialable when the guard is on")
		assert.Contains(t, string(respBody), "pong")
		assert.Equal(t, 1, mock.CallCount())
	})

	t.Run("RFC1918 explicitly listed passes the request-time guard", func(t *testing.T) {
		t.Parallel()
		client, cerr := newTestClientWithAdapter(Options{
			BaseURL:          "http://10.20.30.40:8081", // private-subnet local GPU box
			ProviderName:     "vllm",
			AllowedUpstreams: []string{"http://10.20.30.40:8081"},
		})
		require.NoError(t, cerr)
		require.NoError(t, client.checkSSRF(),
			"the exact allow-list pin admits the RFC1918 host at request time (D-4)")
	})
}

// TestLocalEndpoint_AllowlistedPrivateEndpointShouldDial is the acceptance
// regression for the D-4 fix: an explicitly allow-listed private endpoint
// must be dialable — that is the entire point of an allow-list entry (the
// dial-time GuardDialedIP transport still pins the resolved IP against DNS
// rebinding, covered by rebind_guard_test.go). The D-4 decision landed
// finding is removed together with the fix, as its registry entry required.
func TestLocalEndpoint_AllowlistedPrivateEndpointShouldDial(t *testing.T) {
	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	client, err := newTestClientWithAdapter(Options{
		BaseURL:          srv.URL,
		ProviderName:     "llamacpp",
		AllowedUpstreams: []string{"http://" + srv.Listener.Addr().String()},
	})
	require.NoError(t, err)
	respBody, ferr := client.ForwardJSON(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
	require.NoError(t, ferr, "an explicitly allow-listed loopback endpoint must be dialable when the guard is on")
	assert.Contains(t, string(respBody), "pong")
	assert.Equal(t, 1, mock.CallCount())
}

// TestLocalEndpoint_StalledUpstreamBoundedSingleAttempt pins the packet
// failure scenario "timeout" (contract §5 row 3, example 4): a local
// endpoint that accepts the connection but stalls before replying is
// bounded by the per-call deadline, surfaces as the typed timeout error
// (never a hang, never a success-shaped partial result), and the client
// layer performs exactly ONE attempt — retry policy belongs to the caller
// (chat.go retry.Do); the client must not multiply a stalled endpoint into
// a retry storm.
func TestLocalEndpoint_StalledUpstreamBoundedSingleAttempt(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body) // drain like a real inference server
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanup order matters: unblock the handler BEFORE Close waits on it.
	t.Cleanup(func() {
		close(release)
		srv.CloseClientConnections()
		srv.Close()
	})

	client, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "llamacpp"})
	require.NoError(t, err)

	start := time.Now()
	_, ferr := client.ForwardJSONWithTimeout(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "", 250*time.Millisecond)
	elapsed := time.Since(start)
	require.Error(t, ferr)
	require.EqualError(t, ferr, "upstream request timeout",
		"per-call deadline expiry must surface as the typed timeout error")
	assert.Less(t, elapsed, 2*time.Second, "the 250ms budget must actually bound the call")
	assert.Equal(t, int64(1), attempts.Load(), "client layer is single-shot: no retry storm against a stalled endpoint")
}

// TestLocalEndpoint_ResponseHeaderTimeoutBoundsStalledHeaders pins the
// deploy-level header budget (YABANIN_UPSTREAM_RESPONSE_HEADER_TIMEOUT,
// default 20s; contract example 4): a stalled endpoint is cut by the header
// timeout even when the overall call budget is much larger. On this
// toolchain the header-timeout transport error satisfies
// errors.Is(context.DeadlineExceeded), so forward() surfaces the same typed
// "upstream request timeout" as the overall budget — the budget identity is
// proven by TIMING: the call is cut at ~200ms while the overall budget is
// 10s, and no second attempt is made.
func TestLocalEndpoint_ResponseHeaderTimeoutBoundsStalledHeaders(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body) // drain like a real inference server
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanup order matters: unblock the handler BEFORE Close waits on it.
	t.Cleanup(func() {
		close(release)
		srv.CloseClientConnections()
		srv.Close()
	})

	client, err := newTestClientWithAdapter(Options{
		BaseURL:               srv.URL,
		ProviderName:          "llamacpp",
		ResponseHeaderTimeout: 200 * time.Millisecond,
	})
	require.NoError(t, err)

	start := time.Now()
	_, ferr := client.ForwardJSONWithTimeout(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "", 10*time.Second)
	elapsed := time.Since(start)
	require.Error(t, ferr)
	require.EqualError(t, ferr, "upstream request timeout")
	assert.Less(t, elapsed, 2*time.Second,
		"the 200ms header budget must cut the call even though the overall budget is 10s")
	assert.Equal(t, int64(1), attempts.Load())
}

// TestLocalEndpoint_CallerCancelPropagatesToEndpoint pins the cancellation
// contract (client.go Stream docs): when the caller's context is cancelled
// mid-flight, the client surfaces "upstream request cancelled" (never a
// partial success), performs no second attempt, and the endpoint actually
// observes the aborted request — no orphan generation keeps burning the
// local GPU after the client went away.
func TestLocalEndpoint_CallerCancelPropagatesToEndpoint(t *testing.T) {
	t.Parallel()

	handlerAborted := make(chan struct{}, 1)
	release := make(chan struct{})
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body) // drain like a real inference server
		select {
		case <-release:
		case <-r.Context().Done():
			select {
			case handlerAborted <- struct{}{}:
			default:
			}
		}
	}))
	// Cleanup order matters: unblock the handler BEFORE Close waits on it.
	t.Cleanup(func() {
		close(release)
		srv.CloseClientConnections()
		srv.Close()
	})

	client, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "llamacpp"})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, ferr := client.ForwardJSON(ctx,
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
	elapsed := time.Since(start)
	require.Error(t, ferr)
	require.EqualError(t, ferr, "upstream request cancelled")
	assert.Less(t, elapsed, 2*time.Second, "cancellation must bound the call, not wait for the endpoint")
	assert.Equal(t, int64(1), attempts.Load(), "cancelled call must not be retried")

	select {
	case <-handlerAborted:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not propagate to the endpoint request context")
	}
}

// TestLocalEndpoint_UnreachableEndpointDiagnosable pins the "local server
// is down" boundary: a pooled client for a dead loopback port constructs
// fine (client construction is offline) but the request fails fast with a
// diagnosable dial error — never a success-shaped result, single attempt
// (no internal retry storm), and the pool stays usable for the next
// candidate in the failover chain.
func TestLocalEndpoint_UnreachableEndpointDiagnosable(t *testing.T) {
	t.Parallel()

	dead := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // free the port: guaranteed-refused loopback listener

	pool := NewPool(Options{AllowedUpstreams: []string{deadURL}})
	client, err := pool.Get(deadURL, "llamacpp")
	require.NoError(t, err, "client construction must stay offline-capable; the dead endpoint fails at request time")

	start := time.Now()
	_, ferr := client.ForwardJSON(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
	elapsed := time.Since(start)
	require.Error(t, ferr)
	assert.Contains(t, ferr.Error(), "upstream request failed")
	assert.Contains(t, ferr.Error(), "connection refused", "error must name the dial failure so operators can diagnose it")
	assert.Less(t, elapsed, 5*time.Second, "connection-refused on loopback must fail fast")
}

// TestLocalEndpoint_StreamChatCapability pins the streaming half of the local
// capability walk (N08-P04-T02): every OpenAI-compatible local runtime adapter
// (vllm, ollama, llamacpp) streams chat over the SAME /v1/chat/completions
// path as non-streaming, advertises Accept: text/event-stream, ships the body
// verbatim (identity translation, no model-name remap — the registry name IS
// the served name: --served-model-name / Ollama tag / llama.cpp --alias), and
// passes the upstream SSE frames through untouched so the final usage-bearing
// chunk stays parseable for billing. Billing-side injection for these provider
// names is pinned separately by config.defaultStreamUsageProviders (RM-03)
// and the gateway stream_usage tests; adapter-level local usage parsing is
// pinned in pkg/provider/local_capabilities_test.go.
func TestLocalEndpoint_StreamChatCapability(t *testing.T) {
	t.Parallel()

	sseBody := `{"id":"c1","choices":[{"delta":{"content":"He"}}]}` + "\n\n" +
		`{"id":"c1","choices":[{"delta":{"content":"y"}}]}` + "\n\n" +
		`{"id":"c1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}` + "\n\n" +
		"data: [DONE]\n"

	for _, name := range []string{"vllm", "ollama", "llamacpp"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := mockopenai.New()
			mock.SetStreamMode(true)
			mock.SetResponse(http.StatusOK, sseBody)

			// Capture the wire request in a wrapper BEFORE the mock streams:
			// mockopenai drains the request body only after writing the SSE
			// response, so in stream mode its own Request.Body record comes
			// back empty (harness limitation, not adapter behaviour).
			var gotBody []byte
			var gotPath string
			var gotHeader http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				gotPath = r.URL.Path
				gotHeader = r.Header.Clone()
				mock.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			client, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: name})
			require.NoError(t, err)
			require.Equal(t, name, client.Adapter().Name())

			sentBody := []byte(`{"model":"qwen:7b","messages":[{"role":"user","content":"ping"}],"stream":true}`)
			resp, serr := client.Stream(context.Background(), sentBody, "")
			require.NoError(t, serr)
			raw, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, rerr)

			// SSE frames pass through untouched; [DONE] terminates the stream.
			assert.Contains(t, string(raw), `"delta":{"content":"He"}`)
			assert.Contains(t, string(raw), `"delta":{"content":"y"}`)
			assert.Contains(t, string(raw), `"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}`,
				"the usage-bearing final chunk must survive the passthrough so billing can parse it")
			assert.Contains(t, string(raw), "[DONE]")

			// Wire proof: same chat path as non-streaming, SSE advertised on
			// the outgoing hop, JSON body shipped verbatim.
			require.Len(t, mock.Requests(), 1, "exactly one upstream stream request")
			assert.Equal(t, "/v1/chat/completions", gotPath,
				"%s: streaming must use the same OpenAI-compatible chat endpoint", name)
			assert.Equal(t, "text/event-stream", gotHeader.Get("Accept"))
			assert.Equal(t, "application/json", gotHeader.Get("Content-Type"))
			assert.Equal(t, string(sentBody), string(gotBody),
				"%s: stream body must be the client payload verbatim (no schema or model rewrite at the adapter)", name)
		})
	}
}
