package cli

// of either) must pass the CURRENT post-upstream content policy exactly like
// a fresh upstream body — a deny answers the terminal content_policy_violation
// envelope, a mutator rewrites what the client sees — so an entry created
// before a policy change cannot replay past the live control. The tenant
// boundary below the enforcement point stays the cache service's provenance
// verification (RT-05): a foreign org's entry degrades to a miss.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r011PostUpstreamYAML builds an org chat policy whose steps govern only the
// post_upstream hook — the enforcement point a cache hit must not bypass.
func r011PostUpstreamYAML(stepsYAML string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: r011-post\nmode: enforce\nhooks:\n  - post_upstream\nsteps:\n" + stepsYAML
}

func r011DenyWordStep(word string) string {
	return "  - id: resp\n    detector: builtin/contains\n    params:\n      words: [\"" + word + "\"]\n      action: deny\n"
}

func r011RedactStep(category, pattern string) string {
	return "  - id: redact\n    mutator: builtin/redact\n    params:\n      patterns:\n        - category: " + category + "\n          pattern: \"" + pattern + "\"\n"
}

// r011Runtime wires an enforce-mode runtime whose store carries the given
// policy YAML for org-a (the org rt02Post authenticates).
func r011Runtime(t *testing.T, versions *fakePolicyVersions, yamls ...string) (*fakePolicyStore, *PolicyRuntime) {
	t.Helper()
	store := newFakePolicyStore()
	for i, y := range yamls {
		store.add("org-a", adminstore.PolicyPipeline{
			ID: "r011-" + string(rune('a'+i)), OrgID: "org-a", Name: "r011-post", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: y}, []adminstore.PolicyAttachment{chatAttachment(10)})
	}
	return store, newTestRuntime(t, store, versions, PolicyModeEnforce)
}

const r011CleanDoc = `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"from-cache"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

const r011DirtyDoc = `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"answer with leaked-ssn inside"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

const r011RedactableDoc = `{"id":"cached","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"id cached-badge-777 issued"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// TestR011_CacheHit_PostUpstreamDeny_TerminalEnvelope: a warm exact hit whose
// document the current post-upstream policy denies must answer the same
// terminal 400 envelope as the upstream denial path — no cached byte, no
// upstream refetch around the policy.
func TestR011_CacheHit_PostUpstreamDeny_TerminalEnvelope(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{}, r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}
	events := captureEvents(t)

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-cache-deny"}]}`, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "content_policy_violation")
	assert.NotContains(t, rec.Body.String(), "leaked-ssn", "denied cached content must never reach the client")
	assert.Equal(t, 0, u.totalCalls(), "a denied cache hit must not silently refetch around the policy")

	failed := 0
	for _, ev := range events() {
		if ev.EventType != "request.failed" {
			continue
		}
		failed++
		assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
		assert.Equal(t, "exact", ev.CacheHitType)
		assert.Contains(t, ev.Policy, `"verdict":"deny"`, "the decision record must ride the event")
	}
	assert.Equal(t, 1, failed, "exactly one request.failed event expected")
}

// TestR011_CacheHit_SemanticDeny_NeverServed: the semantic hit source is
// governed identically.
func TestR011_CacheHit_SemanticDeny_NeverServed(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{}, r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "semantic", Similarity: 0.93}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-semantic-deny"}]}`, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "leaked-ssn")
	assert.Equal(t, 0, u.totalCalls())
}

// TestR011_CacheHit_PolicyAddedAfterCaching_DenyApplies: the card's failure
// scenario — the entry was already warm before the policy existed. The first
// request serves it verbatim; after the org adds the deny policy (version
// bump), the SAME warm entry is denied.
func TestR011_CacheHit_PolicyAddedAfterCaching_DenyApplies(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	store := newFakePolicyStore()
	versions := &fakePolicyVersions{}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}

	before := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-before-policy"}]}`, nil)
	require.Equal(t, http.StatusOK, before.Code, before.Body.String())
	assert.Contains(t, before.Body.String(), "leaked-ssn",
		"with no policy attached the warm entry serves verbatim")

	store.add("org-a", adminstore.PolicyPipeline{
		ID: "r011-late", OrgID: "org-a", Name: "r011-post", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	versions.bump()

	after := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-after-policy"}]}`, nil)
	require.Equal(t, http.StatusBadRequest, after.Code, after.Body.String())
	assert.Contains(t, after.Body.String(), "content_policy_violation")
	assert.NotContains(t, after.Body.String(), "leaked-ssn",
		"an entry cached before the policy change must not replay past the new control")
	assert.Equal(t, 0, u.totalCalls())
}

// TestR011_CacheHit_RedactRewritesServedBody: a post-upstream mutator rewrites
// the cached document the same way it would rewrite a fresh upstream body.
func TestR011_CacheHit_RedactRewritesServedBody(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{},
		r011PostUpstreamYAML(r011RedactStep("badge", "cached-badge-[0-9]+")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011RedactableDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-cache-redact"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXACT", rec.Header().Get("X-Cache"), "a mask is not a miss — the hit is still served")
	assert.Contains(t, rec.Body.String(), "[REDACTED:badge:1]")
	assert.NotContains(t, rec.Body.String(), "cached-badge-777", "the raw secret must not reach the client")
	assert.Equal(t, 0, u.totalCalls())
}

// TestR011_CacheHit_SSEReplay_Redacted: the replay frames are converted from
// the policy-processed document — a stream client never sees the raw secret.
func TestR011_CacheHit_SSEReplay_Redacted(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	_, rt := r011Runtime(t, &fakePolicyVersions{},
		r011PostUpstreamYAML(r011RedactStep("badge", "cached-badge-[0-9]+")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011RedactableDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"r011-sse-redact"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "[REDACTED:badge:1]")
	assert.NotContains(t, rec.Body.String(), "cached-badge-777")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
	assert.Equal(t, 0, u.totalCalls())
}

// TestR011_CacheHit_SSEDeny_TerminalBeforeFrames: a denied cache hit answers
// the JSON envelope before any SSE frame is written — the client never
// receives a partial replay of denied content.
func TestR011_CacheHit_SSEDeny_TerminalBeforeFrames(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	_, rt := r011Runtime(t, &fakePolicyVersions{}, r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"r011-sse-deny"}]}`, nil)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "leaked-ssn")
	assert.NotContains(t, rec.Body.String(), "data:", "denied content must not be framed as SSE")
	assert.Equal(t, 0, u.totalCalls())
}

// TestR011_CacheHit_CleanDocServedAfterMaskPolicyAttach: the redact mutator
// must not corrupt a document without matches (mutation parity — no bytes in,
// no bytes changed).
func TestR011_CacheHit_CleanDocServedAfterMaskPolicyAttach(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	_, rt := r011Runtime(t, &fakePolicyVersions{},
		r011PostUpstreamYAML(r011RedactStep("badge", "cached-badge-[0-9]+")))
	gw.policyRuntime = rt
	gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011CleanDoc), SourceType: "exact", Similarity: 1.0}}

	rec := rt02Post(t, gw,
		`{"model":"m","messages":[{"role":"user","content":"r011-cache-clean"}]}`, nil)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "from-cache")
	assert.NotContains(t, rec.Body.String(), "[REDACTED")
	assert.Equal(t, 0, u.totalCalls())
}
