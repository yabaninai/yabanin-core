package cli

// prompt-cache scope exercised END-TO-END through the real chat boundary —
// not via direct helper calls:
//
//   - cache identity separation with a STORE-BACKED response cache: the
//     hinted and unhinted bodies of the SAME prompt resolve to distinct
//     cache keys (no cross-mode collision: the second mode still goes
//     upstream), while a hinted repeat HITS the entry its identity wrote;
//   - the stream path (D6): hinted bodies forward the markers through the
//     streaming translate, and the provider-reported cache tokens flow into
//     the stream drain's request.completed accounting event.
//
// Stand: in-process httptest mock-openai/anthropic upstream, DB-free
// resolver, fake policy store — the isolated synthetic stand of the card;
// no live model, no client data. Config and limits are recorded in

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
)

// r103StoreCache is a store-backed responseCache double: entries are keyed
// by the route identity + the NORMALIZED prompt (the same normalization the
// production exact-match path applies), so a lookup only hits when the
// effective (post-policy) content matches what a previous write stored.
type r103StoreCache struct {
	mu      sync.Mutex
	entries map[string]*cache.CacheHit

	lookups []string
	writes  []string
}

func newR103StoreCache() *r103StoreCache {
	return &r103StoreCache{entries: map[string]*cache.CacheHit{}}
}

func (c *r103StoreCache) key(ri cache.RouteIdentity, promptJSON []byte) string {
	norm, err := cache.NormalizeMessagesJSON(promptJSON)
	if err != nil {
		norm = promptJSON
	}
	return fmt.Sprintf("%s|%s|%s|%s", ri.OrgID, ri.Model, ri.GenParams, cache.ComputePromptHash(norm))
}

func (c *r103StoreCache) LookupWithResult(_ context.Context, ri cache.RouteIdentity, promptJSON []byte) (*cache.CacheHit, error) {
	k := c.key(ri, promptJSON)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups = append(c.lookups, k)
	if hit, ok := c.entries[k]; ok {
		cp := *hit
		return &cp, nil
	}
	return nil, nil //nolint:nilnil // documented miss contract, mirrors CacheService.LookupWithResult
}

func (c *r103StoreCache) Write(_ context.Context, ri cache.RouteIdentity, promptJSON, response json.RawMessage, _, _ int) error {
	k := c.key(ri, promptJSON)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, k)
	c.entries[k] = &cache.CacheHit{Data: append([]byte(nil), response...), SourceType: "exact", ModelUsed: ri.Model}
	return nil
}

// End-to-end identity separation over the real chat boundary: the same
// prompt posted by a hinted org and an unhinted org produces two distinct
// cache identities (the unhinted post MISSES even though the hinted post
// just wrote — no cross-mode collision, no cross-org leak), and a hinted
// repeat HITS the entry its own identity stored.
func TestR103_Integration_CacheIdentitySeparation_EndToEnd(t *testing.T) {
	const (
		orgHinted = "org-r103-int-hinted"
		orgPlain  = "org-r103-int-plain"
	)
	u := newR103IUpstream(t)
	gw, _ := r103TwoOrgGateway(t, u, orgHinted)
	store := newR103StoreCache()
	gw.cache = store

	first := r103PostGolden(t, gw, orgHinted)
	plain := r103PostGolden(t, gw, orgPlain)
	repeat := r103PostGolden(t, gw, orgHinted)

	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Equal(t, http.StatusOK, plain.Code, plain.Body.String())
	require.Equal(t, http.StatusOK, repeat.Code, repeat.Body.String())

	// Upstream order: hinted miss → plain miss → (no third call, cache hit).
	assert.NotNil(t, u.body("/v1/messages", 0), "hinted first post must go upstream")
	assert.NotNil(t, u.body("/v1/messages", 1), "unhinted post must go upstream — the hinted entry must NOT answer it")
	assert.Nil(t, u.body("/v1/messages", 2), "the hinted repeat must be served from the cache entry of its own identity")
	hintedUp := string(u.body("/v1/messages", 0))
	plainUp := string(u.body("/v1/messages", 1))
	assert.Contains(t, hintedUp, "cache_control")
	assert.NotContains(t, plainUp, "cache_control")
	assert.Equal(t, 1, strings.Count(hintedUp, "r103 golden question"), "one hinted forward")

	// Cache branch behavior on the wire.
	assert.Empty(t, first.Header().Get("X-Cache"), "first hinted post is a miss")
	assert.Empty(t, plain.Header().Get("X-Cache"), "the unhinted post misses against the hinted entry")
	assert.Equal(t, "EXACT", repeat.Header().Get("X-Cache"), "the hinted repeat hits its stored identity")
	assert.Contains(t, repeat.Body.String(), "ok", "the cached document answers the repeat")

	// Identity ledger: three lookups, two writes, hinted(1st)==hinted(3rd)
	// != plain(2nd).
	store.mu.Lock()
	defer store.mu.Unlock()
	require.Len(t, store.lookups, 3)
	require.Len(t, store.writes, 2)
	assert.Equal(t, store.lookups[0], store.lookups[2], "hinted repeats share one identity")
	assert.NotEqual(t, store.lookups[0], store.lookups[1], "hinted and unhinted bodies must never share an identity")
	assert.Equal(t, store.lookups[0], store.writes[0], "the write stored under the looked-up (mutated) identity")
	assert.Equal(t, store.lookups[1], store.writes[1], "the unhinted write stored under its own identity")
}

// The stream path (D6): a hinted streaming chat forwards the cache_control
// marker through the OpenAI→Anthropic streaming translate, and the
// provider-reported cache tokens (message_delta usage) flow into the stream
// drain's request.completed event — the header stays a JSON-path surface in
// the MINIMAL scope, but stream BILLING carries the cache fields.
func TestR103_Integration_Stream_BillingCacheTokensToCompleted(t *testing.T) {
	const orgHinted = "org-r103-int-stream"
	u := newR103StreamUpstream(t)
	gw, _ := r103TwoOrgGateway(t, u, orgHinted)
	gw.cache = newR103StoreCache()
	events := captureEvents(t)
	raw, err := os.ReadFile("testdata/r103_golden_request.json")
	require.NoError(t, err)
	var req map[string]any
	require.NoError(t, json.Unmarshal(raw, &req))
	req["stream"] = true
	body, err := json.Marshal(req)
	require.NoError(t, err)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", orgHinted)
	r.Header.Set("X-Session-Id", "sess-r103-stream")
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
	assert.Contains(t, rec.Body.String(), "data:", "SSE frames must reach the client")

	up := string(u.body("/v1/messages", 0))
	require.Contains(t, up, "cache_control", "the hint must survive the streaming translate:\n%s", up)
	require.Contains(t, up, "r103 golden question", "text survives the streaming forward:\n%s", up)

	var completed *struct {
		tokensIn, cacheRead, cacheWrite, tokensOut int64
		usageSource                                string
	}
	for _, ev := range events() {
		if ev.EventType != "request.completed" {
			continue
		}
		require.Nil(t, completed, "one completed event for the stream")
		completed = &struct {
			tokensIn, cacheRead, cacheWrite, tokensOut int64
			usageSource                                string
		}{ev.TokensIn, ev.CacheReadTokens, ev.CacheCreationTokens, ev.TokensOut, ev.UsageSource}
	}
	require.NotNil(t, completed, "the stream drain must publish request.completed")
	assert.Equal(t, int64(16), completed.tokensIn, "canonical stream TokensIn = input 10 + cache_read 4 + cache_write 2")
	assert.Equal(t, int64(4), completed.cacheRead, "stream billing carries cache_read_input_tokens")
	assert.Equal(t, int64(2), completed.cacheWrite, "stream billing carries cache_creation_input_tokens")
	assert.Equal(t, int64(7), completed.tokensOut)
	assert.Equal(t, "provider", completed.usageSource)
}

// newR103StreamUpstream answers anthropic SSE with cache-bearing usage.
func newR103StreamUpstream(t *testing.T) *r103iUpstream {
	t.Helper()
	u := &r103iUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.calls = append(u.calls, r103iCall{Path: r.URL.Path, Body: raw})
		u.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		sse := "event: message_start\n" +
			"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_r103s\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n" +
			"event: content_block_delta\n" +
			"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n" +
			"event: message_delta\n" +
			"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":10,\"output_tokens\":7,\"cache_creation_input_tokens\":2,\"cache_read_input_tokens\":4}}\n\n" +
			"event: message_stop\n" +
			"data: {\"type\":\"message_stop\"}\n\n"
		_, _ = io.WriteString(w, sse)
	}))
	t.Cleanup(u.srv.Close)
	return u
}
