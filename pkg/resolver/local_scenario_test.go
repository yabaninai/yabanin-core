package resolver

// refusal boundaries (row disappearance, registry outage, pool-level
// unknown-capability refusal); these scenarios close the remaining
// scenario-level gap on the WORKING path (contract §4 example 1): the
// admin-entered registry row must survive resolution intact — provider
// name, upstream_url and the upstream_timeout_ms → per-model budget
// mapping — and drive a chat that contacts ONLY the configured loopback
// endpoint (zero cloud egress), plus the example-2 sequence for a typo'd
// capability stored in the row (refusal at the pool, failover still viable).

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
	"github.com/reireirei/yabanin/pkg/testutil/mockopenai"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const scenarioCompletionBody = `{"id":"cmpl-local-scenario","object":"chat.completion","model":"local-qwen","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":5,"total_tokens":16}}`

// adminLocalRow returns models_registry column values (SELECT order of
// lookupDBChecked) for an admin-registered local row: name, display, tier,
// upstream_url, encrypted key (empty), provider, failover_models (NULL),
// enabled, upstream_timeout_ms, region.
func adminLocalRow(url, providerName string, timeoutMs int64) []any {
	return []any{"local-qwen", "Local Qwen", "smart", url, "", providerName, nil, true, timeoutMs, "GLOBAL"}
}

// TestLocalScenario_AdminRowToChat_CloudFree is the connected acceptance
// regression: admin configures a local OpenAI-compatible endpoint as a
// registry row, the row resolves through the resolver (and stays cached),
// and the resolved ModelInfo drives pool → chat with proofs on the wire.
// resolution link itself is under test — a row field that fails to survive
// resolution (URL, capability name, timeout mapping) must be caught here.
func TestLocalScenario_AdminRowToChat_CloudFree(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, scenarioCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	pool := &mockPool{rows: map[string][]any{
		"local-qwen": adminLocalRow(srv.URL, "llamacpp", 2000),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	ctx := context.Background()
	mi, err := r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, err)
	require.Equal(t, "local-qwen", mi.ModelName)
	require.Equal(t, "llamacpp", mi.Provider)
	require.Equal(t, srv.URL, mi.UpstreamURL, "the admin-configured local base_url must survive resolution verbatim")
	require.False(t, mi.Fallback)
	require.Equal(t, 2*time.Second, mi.UpstreamTimeout,
		"the row's upstream_timeout_ms must map to the per-model budget (2000ms → 2s)")

	// The local row is cached: a repeated resolve must not re-query.
	_, err = r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, err)
	assert.Equal(t, int64(1), pool.queries.Load(), "the resolved local row must be served from the resolver cache")

	client, gerr := upstream.NewPool(upstream.Options{}).Get(mi.UpstreamURL, mi.Provider)
	require.NoError(t, gerr)
	require.Equal(t, "llamacpp", client.Adapter().Name())

	_, respBody, sent, ferr := client.ForwardJSONCapturing(ctx,
		[]byte(`{"model":"any-alias","messages":[{"role":"user","content":"ping"}]}`),
		mi.ModelName, mi.UpstreamAPIKey, mi.UpstreamTimeout)
	require.NoError(t, ferr)

	reqs := mock.Requests()
	require.Len(t, reqs, 1, "exactly one upstream request: no retries, no failover, no cloud egress")
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/v1/chat/completions", reqs[0].Path)
	assert.Equal(t, srv.Listener.Addr().String(), reqs[0].Host,
		"zero cloud egress: the only contacted host is the admin-configured loopback endpoint")
	assert.Empty(t, reqs[0].Header.Get("Authorization"), "a keyless local row must not send credentials upstream")

	var sentBody map[string]any
	require.NoError(t, json.Unmarshal(sent, &sentBody))
	assert.Equal(t, mi.ModelName, sentBody["model"], "the per-hop model override must apply to the resolved row")
	assert.Contains(t, sentBody, "messages", "OpenAI-compatible local endpoints receive the verbatim chat shape")
	assert.NotContains(t, sentBody, "inputs")
	assert.NotContains(t, sentBody, "parameters")

	assert.Contains(t, string(respBody), "pong")

	u := client.Adapter().ParseUsage(respBody)
	assert.Equal(t, provider.UsageSourceProvider, u.Source)
	assert.Equal(t, int64(11), u.PromptTokens)
	assert.Equal(t, int64(16), u.TotalTokens)

	ext := provider.ComputeCost(u, mi.Provider, mi.ModelName)
	assert.False(t, ext.PriceKnown, "a local model must not be priced with an invented cloud price")
	assert.Zero(t, ext.EstimatedCostUSD)
}

// TestLocalScenario_RowTimeoutMsBoundsStalledChat pins the resolution link
// of the packet failure scenario "timeout": the registry row's
// upstream_timeout_ms must map to the ModelInfo budget that actually bounds
// scenario proves the budget COMES FROM THE ROW — a regression in the
// ms→duration mapping (or a dropped field) must fail here.
func TestLocalScenario_RowTimeoutMsBoundsStalledChat(t *testing.T) {
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

	pool := &mockPool{rows: map[string][]any{
		"local-qwen": adminLocalRow(srv.URL, "llamacpp", 250),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	mi, err := r.ResolveChecked(context.Background(), "local-qwen")
	require.NoError(t, err)
	require.Equal(t, 250*time.Millisecond, mi.UpstreamTimeout,
		"the row's upstream_timeout_ms must map to the per-model budget (250ms → 250ms)")

	client, gerr := upstream.NewPool(upstream.Options{}).Get(mi.UpstreamURL, mi.Provider)
	require.NoError(t, gerr)

	start := time.Now()
	_, ferr := client.ForwardJSONWithTimeout(context.Background(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`),
		mi.ModelName, "", mi.UpstreamTimeout)
	elapsed := time.Since(start)
	require.Error(t, ferr)
	require.EqualError(t, ferr, "upstream request timeout",
		"the registry row's budget must bound the chat as the typed timeout, never a hang")
	assert.Less(t, elapsed, 2*time.Second, "the 250ms row budget must actually bound the call")
	assert.Equal(t, int64(1), attempts.Load())
}

// TestLocalScenario_TypoProviderRowRefusedAtPoolNotRouted is the contract
// example-2 sequence at the resolver/pool boundary (decision D-1 pending,
// so the registry accepts the typo): a row stored with the misspelled
// capability "llama-cpp" resolves WITHOUT validation — the resolver must
// pass the stored name through unmodified, never silently normalizing it to
// a routable adapter (a silent fallback would send a local prompt to a
// cloud-shaped endpoint). The refusal then happens at the pool/factory
// boundary with the canonical error, contacts no upstream, and the
// corrected capability still resolves and chats on the same pool (the
// failover chain stays viable, chat.go advances the candidate).
func TestLocalScenario_TypoProviderRowRefusedAtPoolNotRouted(t *testing.T) {
	t.Parallel()

	mock := mockopenai.New()
	mock.SetResponse(http.StatusOK, scenarioCompletionBody)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	pool := &mockPool{rows: map[string][]any{
		"local-bad": adminLocalRow(srv.URL, "llama-cpp", 2000),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	ctx := context.Background()
	mi, err := r.ResolveChecked(ctx, "local-bad")
	require.NoError(t, err, "as-is boundary (D-1 pending): resolution does not validate the capability name")
	require.Equal(t, "llama-cpp", mi.Provider,
		"the stored capability must pass through unmodified — no silent normalization to a routable adapter")

	clients := upstream.NewPool(upstream.Options{})
	client, perr := clients.Get(mi.UpstreamURL, mi.Provider)
	require.Error(t, perr)
	require.Nil(t, client)
	assert.Contains(t, perr.Error(), `unknown provider "llama-cpp"`,
		"refusal must name the misconfigured capability verbatim")
	assert.Zero(t, mock.CallCount(), "the refused candidate must not contact any upstream")

	// Failover viability: the corrected capability resolves and chats.
	pool.rows["local-qwen"] = adminLocalRow(srv.URL, "llamacpp", 2000)
	good, gerr := r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, gerr)
	gclient, cerr := clients.Get(good.UpstreamURL, good.Provider)
	require.NoError(t, cerr)
	respBody, ferr := gclient.ForwardJSON(ctx,
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), good.ModelName, "")
	require.NoError(t, ferr)
	assert.Contains(t, string(respBody), "pong")
	assert.Equal(t, 1, mock.CallCount(), "only the corrected candidate may reach the endpoint")
}
