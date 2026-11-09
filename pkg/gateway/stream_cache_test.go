package cli

// W-STCACHE regressions for the streaming semantic cache. The write path must
// store the synthetic chat.completion document accumulated from every delta
// chunk — never the first role-only frame, which served cache hits as empty
// answers — and the cache.stream_enabled kill-switch (default off) must gate
// the whole path.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
)

// streamCacheFrames is an OpenAI-compatible stream fixture: a role-only first
// delta, two content deltas, one tool call split across two fragments, and a
// final finish frame carrying usage.
var streamCacheFrames = []string{
	`{"id":"c1","object":"chat.completion.chunk","created":1700000000,"model":"m1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
	`{"id":"c1","choices":[{"index":0,"delta":{"content":"Hello "}}]}`,
	`{"id":"c1","choices":[{"index":0,"delta":{"content":"world"}}]}`,
	`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"shell","arguments":"{\"cm"}}]}}]}`,
	`{"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"d\":\"ls\"}"}}]}}]}`,
	`{"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":9,"total_tokens":16}}`,
}

func streamCacheUpstream(t *testing.T, frames ...string) *httptest.Server {
	t.Helper()
	if len(frames) == 0 {
		frames = streamCacheFrames
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: "+strings.Join(frames, "\n\ndata: ")+"\n\ndata: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func streamCachePost(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	gw.res = stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: gw.cfg.Provider, Enabled: true},
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	gw.serveStream(rec, r.Context(), rt06TestResolve(gw, "m1"), []byte(body), false,
		"sess", "org-a", "", "task", "req", testLogger(), routingDecision{From: "m1"}, "", 0, "", "", "", false)
	return rec
}

// TestStreamCache_WriteAccumulatesSyntheticCompletion proves both acceptance
// scenarios: after N streamed chunks, Write+Lookup yields (a) a document a
// non-stream client can consume with the FULL accumulated content, merged
// tool_calls, finish_reason and usage, and (b) an sseReplayFrames output that
// carries non-empty content.
func TestStreamCache_WriteAccumulatesSyntheticCompletion(t *testing.T) {
	srv := streamCacheUpstream(t)
	gw := streamTestGateway(srv.URL)
	gw.cfg.CacheStreamEnabled = true
	c := newRT05Cache()
	gw.cache = c

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":"stcache-on"}]}`
	rec := streamCachePost(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"Hello "`, "the live client stream passes through untouched")
	assert.Contains(t, rec.Body.String(), `"content":"world"`)

	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the streamed response must be written to the cache")
	wri := c.lastWrite()
	assert.Equal(t, "m1", wri.Model)
	assert.Equal(t, "org-a", wri.OrgID)

	hit, err := c.LookupWithResult(context.Background(), rt05WarmRI(gw, "org-a", "m1"), []byte(body)) // H1: pinned lookup identity
	require.NoError(t, err)
	require.NotNil(t, hit, "the accumulated document must be retrievable under the streaming identity")

	var doc struct {
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role      string `json:"role"`
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(hit.Data, &doc))
	require.Len(t, doc.Choices, 1)
	assert.Equal(t, "chat.completion", doc.Object)
	assert.Equal(t, "m1", doc.Model)
	assert.Equal(t, "assistant", doc.Choices[0].Message.Role)
	assert.Equal(t, "Hello world", doc.Choices[0].Message.Content,
		"(a) content must be the concatenation of every delta, not the first frame")
	require.Len(t, doc.Choices[0].Message.ToolCalls, 1)
	call := doc.Choices[0].Message.ToolCalls[0]
	assert.Equal(t, "call_1", call.ID)
	assert.Equal(t, "function", call.Type)
	assert.Equal(t, "shell", call.Function.Name)
	assert.JSONEq(t, `{"cmd":"ls"}`, call.Function.Arguments, "tool-call fragments must merge by index")
	require.NotNil(t, doc.Choices[0].FinishReason)
	assert.Equal(t, "tool_calls", *doc.Choices[0].FinishReason)
	require.NotNil(t, doc.Usage)
	assert.Equal(t, 16, doc.Usage.TotalTokens, "usage must carry over from the final frame")

	// (b) the SSE replay of the stored document carries the full content.
	frames, err := sseReplayFrames(hit.Data)
	require.NoError(t, err)
	assert.Contains(t, string(frames), "Hello world",
		"(b) sseReplayFrames must emit non-empty content for a stream-written entry")
	assert.True(t, strings.HasSuffix(string(frames), "data: [DONE]\n\n"))
}

func TestStreamCache_KillSwitchDefaultOff_NoWrite(t *testing.T) {
	srv := streamCacheUpstream(t)
	gw := streamTestGateway(srv.URL) // cache.stream_enabled defaults to false
	c := newRT05Cache()
	gw.cache = c

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":"stcache-off"}]}`
	rec := streamCachePost(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"Hello "`, "the kill-switch must not touch live streaming")

	assert.Equal(t, 0, c.writeCount(),
		"cache.stream_enabled=false must skip the stream cache write entirely")
	hit, err := c.LookupWithResult(context.Background(), cache.RouteIdentity{OrgID: "org-a", Model: "m1"}, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, hit, "no entry may exist while the kill-switch is off")
}

func TestStreamCache_RoleOnlyStream_NeverWritten(t *testing.T) {
	// The defect shape: a stream whose only parseable frame is the role-only
	// first delta must not land in the cache as an empty answer.
	srv := streamCacheUpstream(t, `{"id":"c1","model":"m1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`)
	gw := streamTestGateway(srv.URL)
	gw.cfg.CacheStreamEnabled = true
	c := newRT05Cache()
	gw.cache = c

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":"stcache-roleonly"}]}`
	rec := streamCachePost(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	assert.Equal(t, 0, c.writeCount(),
		"a role-only stream must not poison the cache with an empty-answer entry")
}

// TestStreamCache_CancelMidStreamNeverWritesPartialEntry (N03-P01-T05,
// review F1a): a stream cancelled mid-flight must never leave a partial
// document in the cache. The async writer only fires for fully drained
// streams (drainErr == nil); this test pins that guard on the wire: several
// content chunks are relayed, the client cancels, the delivered stream
// carries the interrupted-error tail — and the cache must stay empty both
// during and after the request. The positive control (a completed stream
// writes one entry) is TestStreamCache_WriteAccumulatesSyntheticCompletion,
// so the zero-write assertion here is not vacuous.
func TestStreamCache_CancelMidStreamNeverWritesPartialEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 400; i++ { // ~8s paced; the cancel ends it far earlier
			if _, err := fmt.Fprint(w, chunkFrame("c1", fmt.Sprintf("chunk-%d", i))); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.cfg.CacheStreamEnabled = true
	c := newRT05Cache()
	gw.cache = c
	gw.res = stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: gw.cfg.Provider, Enabled: true},
	}

	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":"stcache-cancel"}]}`
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(120*time.Millisecond, cancel)
	defer cancel()
	rec := httptest.NewRecorder()
	gw.serveStream(rec, ctx, rt06TestResolve(gw, "m1"), []byte(body), false,
		"sess", "org-a", "", "task", "req", testLogger(), routingDecision{From: "m1"},
		"", 0, "", "", "", false)

	// Non-vacuousness: chunks actually reached the client before the cancel.
	streamed := rec.Body.String()
	require.GreaterOrEqual(t, strings.Count(streamed, "data: {"), 1,
		"at least one content chunk must be relayed before the cancel, got:\n%s", streamed)
	require.Contains(t, streamed, `"content":"chunk-`)
	assertSingleTerminal(t, streamed, true)

	// The pin: no cache write may ever happen for an interrupted stream —
	// in particular no partial document. Never-guards past the serveStream
	// return so any late async flush would be caught too.
	require.Never(t, func() bool { return c.writeCount() > 0 },
		400*time.Millisecond, 20*time.Millisecond,
		"a mid-stream cancel must never write a (partial) cache entry")
	require.Empty(t, c.entries, "no cache entry may exist after a cancelled stream")

	hit, err := c.LookupWithResult(context.Background(), cache.RouteIdentity{OrgID: "org-a", Model: "m1"}, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, hit, "the cancelled stream must answer lookups as a miss")
}
