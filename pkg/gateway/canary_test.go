package cli

// selection, the decision header/event carry the arm, the manual rollback
// never touches an already-routed request, and a failing canary upstream
// the stream starts, never).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
)

// canaryGateway builds the chat harness with the canary split wired: a
// classifier (rule tier, silent), a tier router whose pool deterministically
// selects the base model (canary sits in the pool at weight 0 — canary
// traffic arrives ONLY through the session-hash swap), and a switchable
// rollout loader.
type gatewayCanaryHarness struct {
	gw       *gateway
	upstream *rt02Upstream
	loader   *gatewayCanaryLoader
}

type gatewayCanaryLoader struct {
	loads    int
	rollouts []fallbackrouter.CanaryRollout
}

func (l *gatewayCanaryLoader) LoadCanaryRollouts(context.Context, string) ([]fallbackrouter.CanaryRollout, error) {
	l.loads++
	out := append([]fallbackrouter.CanaryRollout(nil), l.rollouts...)
	return out, nil
}

// gatewayCanaryVersions is the version-key probe double: the store bumps
// version after every mutation (canarystore:ver:<orgID>), the resolver
type gatewayCanaryVersions struct {
	version int64
}

func (v *gatewayCanaryVersions) GetCanaryVersion(context.Context, string) (int64, error) {
	return v.version, nil
}

func newGatewayCanaryHarness(t *testing.T, rollouts []fallbackrouter.CanaryRollout) (*gatewayCanaryHarness, *gatewayCanaryVersions) {
	t.Helper()
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.cfg.DecisionHeaderEnabled = true
	gw.cfg.DecisionEventEnabled = true
	gw.res = stubModelResolver{
		"base-model":   {ModelName: "base-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"canary-model": {ModelName: "canary-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, testLogger())
	loader := &gatewayCanaryLoader{rollouts: rollouts}
	versions := &gatewayCanaryVersions{version: 1}
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "base-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}, nil)
	gw.tierRouter.WithCanaryRollouts(fallbackrouter.NewCanaryRolloutCache(loader, versions, time.Minute, testLogger()))
	return &gatewayCanaryHarness{gw: gw, upstream: u, loader: loader}, versions
}

// gatewayCanarySession finds a session id whose arm at percent is want.
func gatewayCanarySession(t *testing.T, percent int, want bool) string {
	t.Helper()
	for i := 0; i < 100000; i++ {
		id := "gw-sess-" + time.Duration(i).String()
		if fallbackrouter.CanaryArm(id, percent) == want {
			return id
		}
	}
	t.Fatalf("no session found for want=%v percent=%d", want, percent)
	return ""
}

func gatewayCanaryPost(t *testing.T, h *gatewayCanaryHarness, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	return rt02Post(t, h.gw,
		`{"model":"base-model","messages":[{"role":"user","content":"Tell me about AI"}]}`,
		map[string]string{"X-Session-Id": sessionID})
}

func TestChatCompletions_CanaryArmDecisionHeaderAndModel(t *testing.T) {
	h, _ := newGatewayCanaryHarness(t, []fallbackrouter.CanaryRollout{{
		RolloutID: "roll-1", Name: "migration", Version: 2,
		BaseModel: "base-model", CanaryModel: "canary-model", Percent: 40,
	}})
	canarySession := gatewayCanarySession(t, 40, true)
	baseSession := gatewayCanarySession(t, 40, false)

	rec := gatewayCanaryPost(t, h, canarySession)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "canary-model", h.upstream.modelFor("/v1/chat/completions"),
		"the canary-arm session must be served by the canary model")

	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, decisionSourceTierRouter, dec.Source)
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, "roll-1", dec.RolloutID)
	assert.Equal(t, 2, dec.RolloutVersion)
	assert.Equal(t, 40, dec.CanaryPercent)
	assert.Equal(t, "canary-model", dec.To)

	rec = gatewayCanaryPost(t, h, baseSession)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "base-model", h.upstream.modelFor("/v1/chat/completions"),
		"the base-arm session keeps the base model")

	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "base", dec.Arm)
	assert.Equal(t, "roll-1", dec.RolloutID)
	assert.Equal(t, "base-model", dec.To)
}

func TestChatCompletions_CanaryFieldsOmittedWithoutRollout(t *testing.T) {
	// No rollout matches (empty org snapshot): the decision payload stays
	h, _ := newGatewayCanaryHarness(t, nil)
	rec := gatewayCanaryPost(t, h, "any-session")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	raw := rec.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, raw)
	assert.NotContains(t, raw, "arm", "no rollout → no arm field")
	assert.NotContains(t, raw, "rollout_id")
	assert.NotContains(t, raw, "canary_percent")
}

func TestChatCompletions_RollbackNeverTouchesRoutedRequest(t *testing.T) {
	// The manual rollback (D3): after the first request routed to canary,
	// flipping the snapshot off (store: enabled=false + version-key bump)
	// moves only NEW requests to base — the already-routed request
	// completed on canary (its model was pinned in the chatContext at
	// routing time, before any response byte).
	h, versions := newGatewayCanaryHarness(t, []fallbackrouter.CanaryRollout{{
		RolloutID: "roll-1", Name: "migration", Version: 1,
		BaseModel: "base-model", CanaryModel: "canary-model", Percent: 90,
	}})
	session := gatewayCanarySession(t, 90, true)

	rec := gatewayCanaryPost(t, h, session)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "canary-model", h.upstream.modelFor("/v1/chat/completions"),
		"pre-rollback request served by the canary model")

	// Rollback: the store flips enabled=false and bumps the version key;
	// the resolver drops its cache and the next snapshot carries nothing.
	h.loader.rollouts = nil
	versions.version = 2

	rec = gatewayCanaryPost(t, h, session)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "base-model", h.upstream.modelFor("/v1/chat/completions"),
		"post-rollback requests of the SAME session route base")
	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Empty(t, dec.Arm, "post-rollback decisions carry no arm")
}

func TestChatCompletions_SessionsWithoutIdentityNeverCanary(t *testing.T) {
	// No X-Session-Id: no bucketing identity, no rollout resolution — the
	// request is plain tier-routed base (zero-overhead path).
	h, _ := newGatewayCanaryHarness(t, []fallbackrouter.CanaryRollout{{
		RolloutID: "roll-1", Name: "migration", Version: 1,
		BaseModel: "base-model", CanaryModel: "canary-model", Percent: 99,
	}})
	rec := rt02Post(t, h.gw,
		`{"model":"base-model","messages":[{"role":"user","content":"Tell me about AI"}]}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "base-model", h.upstream.modelFor("/v1/chat/completions"))
	assert.Equal(t, 0, h.loader.loads, "a sessionless request must not resolve rollouts")
}

// TestChatCompletions_CanaryFailoverToBaseBeforeStream: a canary-arm request
// whose canary upstream fails 500 BEFORE any byte is streamed falls back to
// the base model inside the same response (the contract's "до stream start");
// the client still gets a 200 from base.
func TestChatCompletions_CanaryFailoverToBaseBeforeStream(t *testing.T) {
	var canaryCalls, baseCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var probe struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&probe)
		switch probe.Model {
		case "canary-model":
			atomic.AddInt32(&canaryCalls, 1)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":{"message":"canary upstream down"}}`))
		default:
			atomic.AddInt32(&baseCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"` + probe.Model + `","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		}
	}))
	t.Cleanup(srv.Close)

	gw := rt02ChatGateway(t, &rt02Upstream{srv: srv}, &rt02Access{})
	gw.cfg.DecisionHeaderEnabled = true
	gw.res = stubModelResolver{
		// The canary candidate carries the base model as its failover chain:
		// before the stream starts, executeFallback may move canary→base.
		"base-model":   {ModelName: "base-model", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
		"canary-model": {ModelName: "canary-model", Provider: "openai", UpstreamURL: srv.URL, Enabled: true, FailoverModels: []string{"base-model"}},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, testLogger())
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "base-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}, nil)
	gw.tierRouter.WithCanaryRollouts(fallbackrouter.NewCanaryRolloutCache(&gatewayCanaryLoader{
		rollouts: []fallbackrouter.CanaryRollout{{
			RolloutID: "roll-1", Name: "migration", Version: 1,
			BaseModel: "base-model", CanaryModel: "canary-model", Percent: 80,
		}},
	}, nil, time.Minute, testLogger()))

	session := gatewayCanarySession(t, 80, true)
	rec := rt02Post(t, gw,
		`{"model":"base-model","messages":[{"role":"user","content":"Tell me about AI"}]}`,
		map[string]string{"X-Session-Id": session})

	require.Equal(t, http.StatusOK, rec.Code, "the failover chain must complete the response on base: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
	assert.Equal(t, int32(1), atomic.LoadInt32(&canaryCalls), "the canary candidate was attempted first")
	assert.Equal(t, int32(1), atomic.LoadInt32(&baseCalls), "the base model served the response")

	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "canary", dec.Arm, "the decision still records the canary arm the session resolved to")
}

// TestChatCompletions_CanaryStickyAcrossRequests: the same session resolves
// to the same arm across 25 requests — the hash-sticky guarantee end to end.
func TestChatCompletions_CanaryStickyAcrossRequests(t *testing.T) {
	h, _ := newGatewayCanaryHarness(t, []fallbackrouter.CanaryRollout{{
		RolloutID: "roll-1", Name: "migration", Version: 1,
		BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30,
	}})
	session := gatewayCanarySession(t, 30, true)
	for i := 0; i < 25; i++ {
		rec := gatewayCanaryPost(t, h, session)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "canary-model", h.upstream.modelFor("/v1/chat/completions"),
			"request %d: the session must stay in the canary arm", i)
	}
}
