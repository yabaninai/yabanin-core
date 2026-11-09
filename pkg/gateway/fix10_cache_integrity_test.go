package cli

// FIX-10 (N03-P02-T09/T10) — cache completion integrity.
//
// Two defects proven red on the pre-fix source:
//
//  1. The write gate (shouldCache, used by the only cache-write site in
//     chat.go) admits undecodable/truncated bytes and semantically empty
//     completion documents (`{}`, `{"choices":[]}`) — json.Unmarshal
//     failures fell through to `return true`.
//  2. The read path already degrades non-decodable hits to a miss
//     (N03-P02-T08) and the streaming replay rejects empty choices, but the
//     nonstream probe decoded `{}`/`{"choices":[]}` successfully and SERVED
//     the empty document with X-Cache attribution — a semantically empty hit
//     was served instead of missed, and stream/nonstream disagreed.
//
// Green contract after the fix: undecodable and semantically empty bodies
// are never written; a semantically empty hit degrades to a miss on both
// client shapes; a valid completion (including tool-call responses) stays
// cacheable and a valid hit stays served; enforcement still precedes the
// integrity probe, so a denied corrupt entry never triggers an upstream
// refetch.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fix10TruncatedDoc = `{"id":"torn","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","cont`

// fix10DeniedTornDoc is truncated (undecodable) yet carries a deny-word in
// the surviving tail — enforcement must still see it before the integrity
// probe degrades the entry to a miss.
const fix10DeniedTornDoc = `{"id":"torn","choices":[{"index":0,"message":{"role":"assistant","content":"answer with leaked-ssn ins`

const fix10ToolCallDoc = `{"id":"tool-1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Oslo\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":6,"total_tokens":10}}`

// fix10Upstream is a minimal upstream double returning a fixed body.
type fix10Upstream struct {
	mu    sync.Mutex
	calls int
	srv   *httptest.Server
}

func newFix10Upstream(t *testing.T, body string) *fix10Upstream {
	t.Helper()
	u := &fix10Upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.mu.Lock()
		u.calls++
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fix10Upstream) totalCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// --- Write gate: shouldCache (the sole gate before gw.cache.Write) -----------

func TestFix10ShouldCache_RejectsUndecodableBytes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"truncated json", fix10TruncatedDoc},
		{"html error page", "<html><body>502 Bad Gateway</body></html>"},
		{"plain garbage", "not-json-at-all"},
		{"trailing comma", `{"id":"x","choices":[],}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, shouldCache([]byte(tc.body)),
				"undecodable bytes must never be written to the cache")
		})
	}
}

func TestFix10ShouldCache_RejectsSemanticallyEmptyCompletions(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty object", `{}`},
		{"json null", `null`},
		{"empty choices array", `{"id":"x","object":"chat.completion","choices":[]}`},
		{"null choices", `{"id":"x","choices":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, shouldCache([]byte(tc.body)),
				"a completion document without choices is semantically empty — the streaming replay already rejects it, the write gate must mirror that")
		})
	}
}

func TestFix10ShouldCache_KeepsValidCompletionsCacheable(t *testing.T) {
	validContent := `{"id":"ok","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

	assert.True(t, shouldCache([]byte(validContent)), "a normal completion stays cacheable")
	assert.True(t, shouldCache([]byte(fix10ToolCallDoc)),
		"a tool-call response stays cacheable (acceptance 1)")
	assert.False(t, shouldCache(nil), "empty body stays rejected")
	assert.False(t, shouldCache([]byte(`{"error":{"message":"upstream exploded"}}`)),
		"error envelopes stay rejected")
}

// --- Write gate end-to-end: the upstream body must not land in the cache -----

func TestFix10WriteGate_UndecodableAndEmptyUpstreamBodiesNotCached(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"truncated upstream body", fix10TruncatedDoc},
		{"semantically empty upstream body", `{"id":"e","object":"chat.completion","model":"m","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":0,"total_tokens":3}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := newFix10Upstream(t, tc.body)
			gw := streamTestGateway(u.srv.URL)
			c := &rt02Cache{}
			gw.cache = c

			rec := rt02Post(t, gw, `{"model":"m","messages":[{"role":"user","content":"fix10-write-gate"}]}`, nil)

			// The client still receives the upstream bytes verbatim — the
			// fix narrows the cache contract, not the passthrough.
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, tc.body, rec.Body.String(), "passthrough must be unchanged")
			assert.Equal(t, 1, u.totalCalls())
			assert.Equal(t, 0, c.writes,
				"the write gate must refuse an undecodable or semantically empty completion document")
		})
	}
}

// --- Read path: semantically empty / undecodable hits degrade to a miss ------

func TestFix10ReadProbe_SemanticallyEmptyHitDegradesToMiss_JSON(t *testing.T) {
	cases := []struct {
		name string
		hit  string
	}{
		{"empty object hit", `{}`},
		{"empty choices hit", `{"id":"x","object":"chat.completion","choices":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := newRT02Upstream(t)
			gw := rt02ChatGateway(t, u, nil)
			gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(tc.hit), SourceType: "exact", Similarity: 1.0}}

			rec := rt02Post(t, gw, `{"model":"m","messages":[{"role":"user","content":"fix10-empty-hit-json"}]}`, nil)

			assert.Equal(t, 1, u.totalCalls(),
				"a semantically empty hit must be a miss — refetch, never serve the empty document")
			assert.Empty(t, rec.Header().Get("X-Cache"),
				"a degraded hit must not carry cache attribution")
			assert.Contains(t, rec.Body.String(), `"content":"ok"`,
				"the client must receive a real completion, not the empty document")
		})
	}
}

func TestFix10ReadProbe_SemanticallyEmptyHitDegradesToMiss_StreamParity(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(`{"choices":[]}`), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw, `{"model":"m","stream":true,"messages":[{"role":"user","content":"fix10-empty-hit-sse"}]}`, nil)

	assert.Equal(t, 1, u.totalCalls())
	assert.Empty(t, rec.Header().Get("X-Cache"))
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"),
		"stream parity: the refetched stream replays normally")
}

func TestFix10ReadProbe_UndecodableHitStillDegradesToMiss(t *testing.T) {
	// Pins the existing N03-P02-T08 behavior: torn bytes never serve. The
	// FIX-10 write-gate tightening must not regress this read-side guard.
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(fix10TruncatedDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw, `{"model":"m","messages":[{"role":"user","content":"fix10-torn-hit"}]}`, nil)

	assert.Equal(t, 1, u.totalCalls(), "a torn hit must degrade to a miss and refetch")
	assert.Empty(t, rec.Header().Get("X-Cache"))
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
}

// Enforcement ordering invariant: the integrity probe sits AFTER post-upstream
// policy enforcement, so a corrupt entry whose governed verdict is a terminal
// deny answers the envelope WITHOUT an upstream refetch (acceptance 3).
func TestFix10ReadProbe_DeniedCorruptHitStaysDeniedWithoutRefetch(t *testing.T) {
	cases := []struct {
		name   string
		stream bool
	}{
		{name: "json"},
		{name: "stream", stream: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := newRT02Upstream(t)
			gw := rt02ChatGateway(t, u, nil)
			gw.cfg.CacheStreamEnabled = tc.stream
			_, rt := r011Runtime(t, &fakePolicyVersions{}, r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn")))
			gw.policyRuntime = rt
			gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(fix10DeniedTornDoc), SourceType: "exact", Similarity: 1.0}}

			body := `{"model":"m","messages":[{"role":"user","content":"fix10-deny-torn"}]}`
			if tc.stream {
				body = `{"model":"m","stream":true,"messages":[{"role":"user","content":"fix10-deny-torn"}]}`
			}
			rec := rt02Post(t, gw, body, nil)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "content_policy_violation")
			assert.Equal(t, 0, u.totalCalls(),
				"a denial must stay terminal — corruption must not convert enforcement into a refetch")
			assert.Empty(t, rec.Header().Get("X-Cache"))
		})
	}
}

// --- Valid hits keep serving (acceptance 1, end-to-end) ----------------------

func TestFix10ReadProbe_ValidHitStillServed_JSONAndReplay(t *testing.T) {
	validDoc := `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"from-cache"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

	t.Run("json", func(t *testing.T) {
		u := newRT02Upstream(t)
		gw := rt02ChatGateway(t, u, nil)
		gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(validDoc), SourceType: "exact", Similarity: 1.0}}

		rec := rt02Post(t, gw, `{"model":"m","messages":[{"role":"user","content":"fix10-valid-hit"}]}`, nil)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, 0, u.totalCalls(), "a valid hit is served, not refetched")
		assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
		assert.Contains(t, rec.Body.String(), "from-cache")
	})

	t.Run("stream replay", func(t *testing.T) {
		u := newRT02Upstream(t)
		gw := rt02ChatGateway(t, u, nil)
		gw.cfg.CacheStreamEnabled = true
		gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(validDoc), SourceType: "exact", Similarity: 1.0}}

		rec := rt02Post(t, gw, `{"model":"m","stream":true,"messages":[{"role":"user","content":"fix10-valid-hit"}]}`, nil)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, 0, u.totalCalls())
		assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"))
		assert.Contains(t, rec.Body.String(), "from-cache")
		assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	})
}

// --- Counterfactual consistency ----------------------------------------------

func TestFix10Counterfactual_SemanticallyEmptyDocumentNotPriced(t *testing.T) {
	assert.InDelta(t, 0.0,
		cachedUsageCounterfactual([]byte(`{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50}}`), "openai", "gpt-4o"), 1e-12,
		"a document the read path treats as a miss must not produce a priced counterfactual either")
	assert.InDelta(t, 0.0,
		cachedUsageCounterfactual([]byte(fix10TruncatedDoc), "openai", "gpt-4o"), 1e-12)

	priced := `{"id":"p","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2015,"completion_tokens":10,"total_tokens":2025}}`
	assert.Greater(t, cachedUsageCounterfactual([]byte(priced), "openai", "gpt-4o"), 0.0,
		"a valid cached document still prices its usage")
}
