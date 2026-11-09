package cli

// N03-P02-T02: a warm cache replay served to a streaming client must pass the
// CURRENT stream-stage policies (stream_prefix over the replayed content
// text, stream_final over the replay document) exactly like a live stream —
// policyPostUpstream only evaluates the post_upstream hook, so a deny
// attached to a stream stage and tightened after the response was cached
// would otherwise replay forbidden content. A replay has issued no bytes, so
// a stream_final deny stays terminal here (a live stream can only flag after
// issuance). The tenant boundary below the enforcement point stays the cache
// service's provenance verification (RT-05, pkg/cache/provenance_test.go): a
// foreign org's entry degrades to a miss.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n03p02StreamYAML builds an org chat policy whose steps govern only one
// streaming hook — the enforcement surface a warm replay must not bypass.
func n03p02StreamYAML(hook, stepsYAML string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: n03p02-stream\nmode: enforce\nhooks:\n  - " + hook + "\nsteps:\n" + stepsYAML
}

const n03p02StreamDoc = `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"reply with forbidden-token inside"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// TestN03P02_CacheHit_StreamFinalDeny_TerminalBeforeFrames: a warm exact hit
// whose document the current stream_final policy denies must answer the
// terminal envelope before any replay frame — no cached byte, no upstream
// refetch around the policy.
func TestN03P02_CacheHit_StreamFinalDeny_TerminalBeforeFrames(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	_, rt := r011Runtime(t, &fakePolicyVersions{}, n03p02StreamYAML("stream_final", r011DenyWordStep("forbidden-token")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(n03p02StreamDoc), SourceType: "exact", Similarity: 1.0}}
	events := captureEvents(t)

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"n03p02-final-deny"}]}`, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "content_policy_violation")
	assert.NotContains(t, rec.Body.String(), "forbidden-token", "denied cached content must never reach the client")
	assert.NotContains(t, rec.Body.String(), "data:", "denied content must not be framed as SSE")
	assert.Equal(t, 0, u.totalCalls(), "a denied cache hit must not silently refetch around the policy")

	failed := 0
	for _, ev := range events() {
		if ev.EventType != "request.failed" {
			continue
		}
		failed++
		assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
		assert.Contains(t, ev.Policy, `"verdict":"deny"`, "the decision record must ride the event")
	}
	assert.Equal(t, 1, failed, "exactly one request.failed event expected")
}

// TestN03P02_CacheHit_StreamPolicyTightenedAfterCaching_DenyApplies: the
// card's failure scenario on the stream surface — the entry was already warm
// before the stream policy existed; after the org attaches the deny (version
// bump), the SAME warm entry is denied on replay.
func TestN03P02_CacheHit_StreamPolicyTightenedAfterCaching_DenyApplies(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	store := newFakePolicyStore()
	versions := &fakePolicyVersions{}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(n03p02StreamDoc), SourceType: "exact", Similarity: 1.0}}

	body := `{"model":"m","stream":true,"messages":[{"role":"user","content":"n03p02-tighten"}]}`
	before := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusOK, before.Code, before.Body.String())
	assert.Contains(t, before.Body.String(), "forbidden-token",
		"with no policy attached the warm entry replays verbatim")

	store.add("org-a", adminstore.PolicyPipeline{
		ID: "n03p02-late", OrgID: "org-a", Name: "n03p02-stream", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: n03p02StreamYAML("stream_final", r011DenyWordStep("forbidden-token"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	versions.bump()

	after := rt02Post(t, gw, body, nil)
	require.Equal(t, http.StatusBadRequest, after.Code, after.Body.String())
	assert.Contains(t, after.Body.String(), "content_policy_violation")
	assert.NotContains(t, after.Body.String(), "forbidden-token",
		"an entry cached before the policy change must not replay past the new stream control")
	assert.Equal(t, 0, u.totalCalls())
}

// TestN03P02_CacheHit_StreamPrefixDeny_Terminal: a prefix-attached deny
// governs the replayed content the same way it aborts a live stream — the
// prefix stage alone (no post_upstream, no final hook) must stop the replay.
func TestN03P02_CacheHit_StreamPrefixDeny_Terminal(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	_, rt := r011Runtime(t, &fakePolicyVersions{}, n03p02StreamYAML("stream_prefix", r011DenyWordStep("forbidden-token")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(n03p02StreamDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"n03p02-prefix-deny"}]}`, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "content_policy_violation")
	assert.NotContains(t, rec.Body.String(), "forbidden-token")
	assert.NotContains(t, rec.Body.String(), "data:")
	assert.Equal(t, 0, u.totalCalls())
}

// TestN03P02_CacheHit_StreamPrefixRedact_SplicesReplayContent: a prefix
// mutator rewrites the replayed choices[0].message.content — the same text
// the live prefix gate ingests (delta.content) and mutates.
func TestN03P02_CacheHit_StreamPrefixRedact_SplicesReplayContent(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	_, rt := r011Runtime(t, &fakePolicyVersions{},
		n03p02StreamYAML("stream_prefix", r011RedactStep("badge", "cached-badge-[0-9]+")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011RedactableDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"n03p02-prefix-redact"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"), "a mask is not a miss — the hit is still served")
	assert.Contains(t, rec.Body.String(), "[REDACTED:badge:1]")
	assert.NotContains(t, rec.Body.String(), "cached-badge-777", "the raw secret must not reach the client")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	assert.Equal(t, 0, u.totalCalls())
}

// TestN03P02_CacheHit_StreamHooksNotAppliedToNonStreamReplay: parity — a live
// NON-streaming request never passes the stream hooks, so the same warm
// entry replays verbatim for a non-streaming client (post_upstream still
// governs it; a stream-only policy deliberately does not).
func TestN03P02_CacheHit_StreamHooksNotAppliedToNonStreamReplay(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{}, n03p02StreamYAML("stream_final", r011DenyWordStep("forbidden-token")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(n03p02StreamDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"n03p02-nonstream"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "forbidden-token")
	assert.Equal(t, 0, u.totalCalls())
}
