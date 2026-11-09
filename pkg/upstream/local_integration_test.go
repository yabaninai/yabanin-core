package upstream

// through the REAL consumer composition, not only the direct constructor
// bare-client dial/refusal/timeout (local_endpoint_test.go), retry
// classification (local_retry_classification_test.go) and the resolver link
// (pkg/resolver/local_scenario_test.go — row → ModelInfo, guard OFF there).
// The production gateway, however, builds its pool ONCE with the
// configured allow-list as pool defaults (buildGatewayEgress,
// gateway.go:388-403: Options{AllowedUpstreams: allowedUpstreamsForGateway(
// cfg.AllowedUpstreams, ...)}), and every model row then resolves into
// pool.Get(row.upstream_url, row.provider). These tests compose that exact
// boundary — resolver.ModelInfo row in, guarded pool out, chat on the wire —
// with the guard ON (D-4 posture: exact IP-literal pins dial; every
// non-pinned host stays behind the allow-list) and apply the packet's
// negative scenario (unknown capability, private endpoint SSRF, timeout)
// through that same guarded boundary.

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

// TestLocalIntegration_GuardedPoolAdminRowToChat_CloudFree is the packet
// acceptance criterion driven through the consumer composition: an
// admin-registered local row (resolver.ModelInfo — the resolution link is
// pinned in pkg/resolver/local_scenario_test.go) feeds a pool built with the
// deployment's allowed_upstreams (the buildGatewayEgress wiring), and the
// chat reaches ONLY the allow-listed loopback endpoint — no cloud egress, no
// credentials, provider-sourced usage, no invented cloud price.
//
// The guarded-mode proof is intrinsic: the same pool first REFUSES an
// unlisted host at Get ("not in the allowed list", nothing cached), so a
// green chat below cannot be the legacy guard-off mode passing by accident.
func TestLocalIntegration_GuardedPoolAdminRowToChat_CloudFree(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, localCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})

	// Guard is genuinely ON in this pool: an unlisted host is refused at the
	// pool boundary, nothing is dialed and the failed key is not cached.
	stranger, serr := pool.Get("http://203.0.113.7:9000", "llamacpp")
	require.Error(t, serr)
	require.Nil(t, stranger)
	assert.Contains(t, serr.Error(), "not in the allowed list")
	assert.Equal(t, 0, pool.Size(), "the refused key must not be cached")
	assert.Zero(t, mock.CallCount(), "the refused candidate must not contact any upstream")

	// The admin row resolves (resolver link pinned in
	// pkg/resolver/local_scenario_test.go) and drives the guarded pool.
	mi := resolver.ModelInfo{
		ModelName:       "local-qwen",
		DisplayName:     "Local Qwen",
		Tier:            "smart",
		UpstreamURL:     srv.URL,
		UpstreamTimeout: 2 * time.Second,
		Provider:        "llamacpp",
		Enabled:         true,
	}
	client, err := pool.Get(mi.UpstreamURL, mi.Provider)
	require.NoError(t, err)
	require.Equal(t, "llamacpp", client.Adapter().Name())

	_, respBody, _, ferr := client.ForwardJSONCapturing(context.Background(),
		[]byte(`{"model":"any-alias","messages":[{"role":"user","content":"ping"}],"max_tokens":16}`),
		mi.ModelName, "", mi.UpstreamTimeout)
	require.NoError(t, ferr)

	reqs := mock.Requests()
	require.Len(t, reqs, 1, "exactly one upstream request: no retries, no failover, no cloud egress")
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
	assert.Equal(t, srv.Listener.Addr().String(), reqs[0].Host,
		"zero cloud egress: the only contacted host is the allow-listed loopback endpoint")
	assert.Empty(t, reqs[0].Header.Get("Authorization"), "a keyless local row must not send credentials upstream")
	assert.Equal(t, "application/json", reqs[0].Header.Get("Content-Type"))

	var sent map[string]any
	require.NoError(t, json.Unmarshal([]byte(reqs[0].Body), &sent))
	assert.Equal(t, mi.ModelName, sent["model"], "the per-hop model override must apply to the resolved row")
	assert.Contains(t, sent, "messages", "OpenAI-compatible local endpoints receive the verbatim chat shape")
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
	assert.False(t, ext.PriceKnown, "a local model must not be priced with an invented cloud price")
	assert.Zero(t, ext.EstimatedCostUSD)
	assert.Equal(t, "llamacpp", ext.ProviderName)
}

// TestLocalIntegration_GuardedPool_LocalCapabilityNamesChat ties every
// local capability surface from the factory (llamacpp / vllm / ollama on
// their OpenAI-compat path, tgi via its /generate translation) into the
// guarded pool end-to-end: pool defaults carry the allow-list, Get binds the
// adapter, the chat completes against the loopback stand-in. A regression in
// any adapter's Path/PrepareRequest/TranslateResponse wiring must fail here
// at the composed boundary, not only in the adapter unit tests.
func TestLocalIntegration_GuardedPool_LocalCapabilityNamesChat(t *testing.T) {
	t.Run("openai-compat local adapters", func(t *testing.T) {
		t.Parallel()
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
				require.Equal(t, name, client.Adapter().Name())

				respBody, ferr := client.ForwardJSON(context.Background(),
					[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
				require.NoError(t, ferr)
				assert.Contains(t, string(respBody), "pong")

				reqs := mock.Requests()
				require.Len(t, reqs, 1)
				assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
			})
		}
	})

	t.Run("tgi translates to /generate and back", func(t *testing.T) {
		t.Parallel()

		mock := mockopenai.New()
		mock.SetResponse(http.StatusOK, `{"generated_text":"pong"}`)
		srv := httptest.NewServer(mock)
		t.Cleanup(srv.Close)

		pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
		client, err := pool.Get(srv.URL, "tgi")
		require.NoError(t, err)
		require.Equal(t, "tgi", client.Adapter().Name())

		respBody, ferr := client.ForwardJSON(context.Background(),
			[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}],"max_tokens":16,"temperature":0.5}`),
			"m", "")
		require.NoError(t, ferr)

		reqs := mock.Requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "/generate", reqs[0].Path,
			"TGI non-stream chat must land on the /generate endpoint")

		var sent map[string]any
		require.NoError(t, json.Unmarshal([]byte(reqs[0].Body), &sent))
		assert.Contains(t, sent, "inputs")
		params, ok := sent["parameters"].(map[string]any)
		require.True(t, ok, "TGI body must carry the parameters map")
		assert.InDelta(t, 16.0, params["max_new_tokens"], 0.0001)
		assert.NotContains(t, sent, "messages")

		var out struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		require.NoError(t, json.Unmarshal(respBody, &out))
		require.NotEmpty(t, out.Choices)
		assert.Equal(t, "pong", out.Choices[0].Message.Content,
			"TGI generated_text must be wrapped back into the OpenAI chat shape")
	})
}

// TestLocalIntegration_GuardedPool_UnknownCapabilityRefused applies the
// packet negative scenario "unknown capability" through the GUARDED pool
// boundary (the guard-off pool is covered): a typo'd capability
// is refused with the canonical text at Get, contacts nothing, caches
// nothing, and the same guarded pool stays viable for the failover chain's
// correctly spelled candidate.
func TestLocalIntegration_GuardedPool_UnknownCapabilityRefused(t *testing.T) {
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
		"refusal must name the misconfigured capability verbatim")
	assert.Zero(t, mock.CallCount(), "the refused candidate must not contact any upstream")
	assert.Equal(t, 0, pool.Size(), "the failed key must not be cached")

	good, gerr := pool.Get(srv.URL, "llamacpp")
	require.NoError(t, gerr)
	respBody, ferr := good.ForwardJSON(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
	require.NoError(t, ferr)
	assert.Contains(t, string(respBody), "pong")
	assert.Equal(t, 1, mock.CallCount(),
		"only the corrected candidate may reach the guarded endpoint")
}

// TestLocalIntegration_GuardedPool_PrivateEndpointNeedsExactPin pins the
// private-endpoint half of the packet negative scenario at the pool
// boundary under the D-4 posture: an allow-listed RFC1918 IP LITERAL is an
// explicit operator pin — it constructs through the guarded pool and passes
// the request-time validate layer — while a DIFFERENT reserved address that
// is not pinned is refused by the same pool at Get ("not in the allowed
// list"). Being reserved grants nothing and being reserved is no longer
// enough to refuse a pinned literal; only the explicit entry decides. Both
// assertions are offline: construction and checkSSRF dial nothing.
func TestLocalIntegration_GuardedPool_PrivateEndpointNeedsExactPin(t *testing.T) {
	t.Parallel()

	pool := NewPool(Options{AllowedUpstreams: []string{"http://10.20.30.40:8081"}})

	pinned, err := pool.Get("http://10.20.30.40:8081", "vllm")
	require.NoError(t, err, "an explicitly pinned RFC1918 endpoint must construct through the guarded pool (D-4)")
	require.NoError(t, pinned.checkSSRF(),
		"the exact pin must pass the request-time validate layer of the pool-built client")

	stranger, serr := pool.Get("http://192.168.1.50:8080", "vllm")
	require.Error(t, serr)
	require.Nil(t, stranger)
	assert.Contains(t, serr.Error(), "not in the allowed list",
		"a different reserved address is still behind the allow-list: nothing is dialed for it")
	assert.Equal(t, 1, pool.Size(), "only the pinned endpoint may be cached")
}

// TestLocalIntegration_GuardedPool_RowTimeoutBoundedSingleAttempt applies
// the packet negative scenario "timeout" through the guarded pool boundary:
// the row budget bounds a stalled pinned endpoint as the typed timeout, and
// the client layer stays single-shot behind the guard — no retry storm (the
// gateway's retry loop around it is pinned in
// local_retry_classification_test.go).
func TestLocalIntegration_GuardedPool_RowTimeoutBoundedSingleAttempt(t *testing.T) {
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

	pool := NewPool(Options{AllowedUpstreams: []string{srv.URL}})
	client, err := pool.Get(srv.URL, "llamacpp")
	require.NoError(t, err)

	mi := resolver.ModelInfo{ModelName: "local-qwen", UpstreamURL: srv.URL,
		UpstreamTimeout: 250 * time.Millisecond, Provider: "llamacpp", Enabled: true}

	start := time.Now()
	_, ferr := client.ForwardJSONWithTimeout(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`),
		mi.ModelName, "", mi.UpstreamTimeout)
	elapsed := time.Since(start)
	require.Error(t, ferr)
	require.EqualError(t, ferr, "upstream request timeout",
		"the row budget must surface as the typed timeout through the guarded pool, never a hang")
	assert.Less(t, elapsed, 2*time.Second, "the 250ms row budget must actually bound the guarded call")
	assert.Equal(t, int64(1), attempts.Load(), "the client layer stays single-shot behind the guard")
}
