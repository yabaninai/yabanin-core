package cli

// to every warm-entry shape the packet names — exact, semantic, and the SSE
// replay of either — with observable client behavior, and an entry sealed
// before a policy change must be governed on the replay path exactly like on
// the real production handler; zero upstream calls prove the control is
// applied at the cache seam, not delegated to a refetch.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestR011_Regression_EffectivePolicyMatrix_ExactSemanticAndReplay walks the
// full fixture matrix the card names: warm source {exact, semantic} × client
// shape {json, sse replay} × post-upstream control {deny word, redact
// mutator}. Deny answers the terminal 400 envelope with no cached byte and no
// X-Cache attribution; a mutator rewrites exactly the matched secret while the
// hit stays attributed. No scenario may touch upstream.
func TestR011_Regression_EffectivePolicyMatrix_ExactSemanticAndReplay(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		similarity float32
		deny       bool // true = deny-word control, false = redact mutator
		stream     bool
		wantCode   int
	}{
		{name: "exact_json_deny", source: "exact", similarity: 1.0, deny: true, wantCode: http.StatusBadRequest},
		{name: "semantic_json_deny", source: "semantic", similarity: 0.93, deny: true, wantCode: http.StatusBadRequest},
		{name: "exact_replay_deny", source: "exact", similarity: 1.0, deny: true, stream: true, wantCode: http.StatusBadRequest},
		{name: "semantic_replay_deny", source: "semantic", similarity: 0.93, deny: true, stream: true, wantCode: http.StatusBadRequest},
		{name: "exact_json_redact", source: "exact", similarity: 1.0, wantCode: http.StatusOK},
		{name: "semantic_json_redact", source: "semantic", similarity: 0.93, wantCode: http.StatusOK},
		{name: "exact_replay_redact", source: "exact", similarity: 1.0, stream: true, wantCode: http.StatusOK},
		{name: "semantic_replay_redact", source: "semantic", similarity: 0.93, stream: true, wantCode: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := newRT02Upstream(t)
			gw := rt02ChatGateway(t, u, nil)
			gw.cfg.CacheStreamEnabled = tc.stream
			var yamls string
			if tc.deny {
				yamls = r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))
			} else {
				yamls = r011PostUpstreamYAML(r011RedactStep("badge", "cached-badge-[0-9]+"))
			}
			_, rt := r011Runtime(t, &fakePolicyVersions{}, yamls)
			gw.policyRuntime = rt
			doc := r011DirtyDoc
			if !tc.deny {
				doc = r011RedactableDoc
			}
			gw.cache = &rt02Cache{hit: &cache.CacheHit{Data: []byte(doc), SourceType: tc.source, Similarity: tc.similarity}}

			body := `{"model":"m","messages":[{"role":"user","content":"r011-regression-matrix"}]}`
			if tc.stream {
				body = `{"model":"m","stream":true,"messages":[{"role":"user","content":"r011-regression-matrix"}]}`
			}
			rec := rt02Post(t, gw, body, nil)

			require.Equal(t, tc.wantCode, rec.Code, rec.Body.String())
			assert.Equal(t, 0, u.totalCalls(),
				"the effective policy must govern the warm entry without a refetch around it")
			if tc.deny {
				assert.Contains(t, rec.Body.String(), "content_policy_violation")
				assert.NotContains(t, rec.Body.String(), "leaked-ssn",
					"denied cached content must never reach the client")
				assert.NotContains(t, rec.Body.String(), "from-cache")
				assert.Empty(t, rec.Header().Get("X-Cache"),
					"a denial is not a served hit — no cache attribution on the wire")
				if tc.stream {
					assert.NotContains(t, rec.Body.String(), "data:",
						"a denied replay must not be framed as SSE")
				}
				return
			}
			assert.Equal(t, strings.ToUpper(tc.source), rec.Header().Get("X-Cache"),
				"a mask is not a miss — the hit attribution survives")
			assert.Contains(t, rec.Body.String(), "[REDACTED:badge:1]")
			assert.NotContains(t, rec.Body.String(), "cached-badge-777",
				"the raw secret must not reach the client")
			if tc.stream {
				assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
				assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
			}
		})
	}
}

// TestR011_Regression_EntrySealedBeforePolicy_ReplayGoverned: the card's
// failure scenario on the replay path — the entry was warm before any policy
// existed and a streaming client replays it. While unregulated the replay
// serves verbatim; after the org attaches the deny policy (version bump) the
// SAME warm entry answers the terminal envelope with no SSE frame, and the
// request.failed event attributes the decision to the semantic cache hit.
func TestR011_Regression_EntrySealedBeforePolicy_ReplayGoverned(t *testing.T) {
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, nil)
	gw.cfg.CacheStreamEnabled = true
	store := newFakePolicyStore()
	versions := &fakePolicyVersions{}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw.policyRuntime = rt
	c := &rt02Cache{hit: &cache.CacheHit{Data: []byte(r011DirtyDoc), SourceType: "semantic", Similarity: 0.93}}
	gw.cache = c
	events := captureEvents(t)

	before := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"r011-reg-sealed-before"}]}`, nil)
	require.Equal(t, http.StatusOK, before.Code, before.Body.String())
	assert.Equal(t, "SEMANTIC", before.Header().Get("X-Cache"))
	assert.Contains(t, before.Body.String(), "leaked-ssn",
		"with no policy attached the warm replay serves verbatim")
	assert.True(t, strings.HasSuffix(before.Body.String(), "data: [DONE]\n\n"))

	store.add("org-a", adminstore.PolicyPipeline{
		ID: "r011-reg-late", OrgID: "org-a", Name: "r011-post", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: r011PostUpstreamYAML(r011DenyWordStep("leaked-ssn"))}, []adminstore.PolicyAttachment{chatAttachment(10)})
	versions.bump()

	after := rt02Post(t, gw,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"r011-reg-sealed-after"}]}`, nil)
	require.Equal(t, http.StatusBadRequest, after.Code, after.Body.String())
	assert.Contains(t, after.Body.String(), "content_policy_violation")
	assert.NotContains(t, after.Body.String(), "leaked-ssn",
		"an entry sealed before the policy change must not replay past the new control")
	assert.NotContains(t, after.Body.String(), "data:")
	assert.Equal(t, 0, u.totalCalls(), "no phase of the arc refetches around the policy")
	assert.Equal(t, 2, c.lookups, "each phase re-consults the cache — no sticky state")

	failed := 0
	for _, ev := range events() {
		if ev.EventType != "request.failed" {
			continue
		}
		failed++
		assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
		assert.Equal(t, "semantic", ev.CacheHitType,
			"the denial must stay attributed to the cache hit, not pose as an upstream failure")
		assert.Contains(t, ev.Policy, `"verdict":"deny"`)
	}
	assert.Equal(t, 1, failed, "exactly one request.failed event expected")
}
