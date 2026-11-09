package cli

//
//   - concurrent activation during an in-flight request: the model and the
//     canary decision fields are pinned at routing time; a version activated
//     while the upstream is still answering changes only NEW requests;
//   - resolver error → fail-open to base: rollout infrastructure failing
//     never fails a request, and the decision stays inactive (no arm fields).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
)

// erroringCanaryLoader always fails the snapshot load.
type erroringCanaryLoader struct{ loads int }

func (l *erroringCanaryLoader) LoadCanaryRollouts(context.Context, string) ([]fallbackrouter.CanaryRollout, error) {
	l.loads++
	return nil, assert.AnError
}

// boundaryCanaryVersions is a settable version-key double.
type boundaryCanaryVersions struct{ version int64 }

func (v *boundaryCanaryVersions) GetCanaryVersion(context.Context, string) (int64, error) {
	return v.version, nil
}

func TestChatCompletions_Canary_ActivationDuringInflightRequest(t *testing.T) {
	// Reproduction of the packet negative "вес применяется несогласованно
	// между gateway" at its most adversarial: the NEW version activates
	// while THIS request is still being answered by the upstream. The
	// in-flight response must complete on the model pinned at routing time
	// with the v1 decision fields; only requests routed afterwards see v2.
	arrived := make(chan string, 1) // upstream received the call (routing is done)
	release := make(chan struct{})  // let the upstream answer
	var servedModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var probe struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&probe)
		servedModel = probe.Model
		select {
		case arrived <- probe.Model: // first arrival wins; later requests pass
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"` + probe.Model + `","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)

	gw := rt02ChatGateway(t, &rt02Upstream{srv: srv}, &rt02Access{})
	gw.cfg.DecisionHeaderEnabled = true
	gw.cfg.DecisionEventEnabled = true
	gw.res = stubModelResolver{
		"base-model":   {ModelName: "base-model", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
		"canary-model": {ModelName: "canary-model", Provider: "openai", UpstreamURL: srv.URL, Enabled: true},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, testLogger())
	loader := &gatewayCanaryLoader{rollouts: []fallbackrouter.CanaryRollout{{
		RolloutID: "roll-1", Name: "migration", Version: 1,
		BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30,
	}}}
	versions := &boundaryCanaryVersions{version: 1}
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "base-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}, nil)
	gw.tierRouter.WithCanaryRollouts(fallbackrouter.NewCanaryRolloutCache(loader, versions, time.Minute, testLogger()))

	// A session that is canary at BOTH percents (30 and 90): its arm is
	// stable, the assertable difference is the pinned version/percent.
	session := gatewayCanarySession(t, 30, true)
	// ...and one that is base at 30 but canary at 90: the activation must
	// move it on its NEXT request only.
	movingSession := ""
	for i := 0; i < 100000; i++ {
		id := "boundary-move-" + time.Duration(i).String()
		if !fallbackrouter.CanaryArm(id, 30) && fallbackrouter.CanaryArm(id, 90) {
			movingSession = id
			break
		}
	}
	require.NotEmpty(t, movingSession, "no session found between the two percents")

	type result struct {
		rec *httptest.ResponseRecorder
	}
	done := make(chan result, 1)
	go func() {
		done <- result{rec: gatewayCanaryPost(t, &gatewayCanaryHarness{gw: gw}, session)}
	}()

	// Wait until the upstream is answering THIS request — routing is over,
	// the decision and model are pinned in the chatContext.
	require.Equal(t, "canary-model", <-arrived, "the in-flight request must have routed to the canary model")

	// Mid-flight activation: version 2 at 90 percent lands in the store
	// (snapshot + version-key bump) while the response is still open.
	loader.rollouts = []fallbackrouter.CanaryRollout{{
		RolloutID: "roll-1", Name: "migration", Version: 2,
		BaseModel: "base-model", CanaryModel: "canary-model", Percent: 90,
	}}
	versions.version = 2
	close(release)

	res := <-done
	require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
	assert.Equal(t, "canary-model", servedModel, "the in-flight response must complete on the pinned model")
	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(res.rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, "roll-1", dec.RolloutID)
	assert.Equal(t, 1, dec.RolloutVersion, "the in-flight request keeps the version it was routed under")
	assert.Equal(t, 30, dec.CanaryPercent, "the in-flight request keeps the percent it was routed under")

	// NEW requests resolve the activated version: the between-percents
	// session moves to canary; the header carries v2.
	rec := gatewayCanaryPost(t, &gatewayCanaryHarness{gw: gw}, movingSession)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, 2, dec.RolloutVersion)
	assert.Equal(t, 90, dec.CanaryPercent)

	// The originally canary session stays canary (monotone ramp: 30 → 90).
	rec = gatewayCanaryPost(t, &gatewayCanaryHarness{gw: gw}, session)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, 2, dec.RolloutVersion)
}

func TestChatCompletions_Canary_ResolverErrorFailsOpenToBase(t *testing.T) {
	// The rollout resolver's FIRST load fails (canarystore down, nothing
	// cached): the request still routes on base — a 200, not a 5xx — and
	// the decision payload carries no canary fields (inactive), with no
	// infrastructure error leaked to the client.
	u := newRT02Upstream(t)
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.cfg.DecisionHeaderEnabled = true
	gw.res = stubModelResolver{
		"base-model":   {ModelName: "base-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"canary-model": {ModelName: "canary-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, testLogger())
	loader := &erroringCanaryLoader{}
	gw.tierRouter = fallbackrouter.NewTierRouter(rt02TierLoader{
		{Name: "base-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}, nil)
	gw.tierRouter.WithCanaryRollouts(fallbackrouter.NewCanaryRolloutCache(loader, nil, time.Minute, testLogger()))

	rec := gatewayCanaryPost(t, &gatewayCanaryHarness{gw: gw}, "any-session")
	require.Equal(t, http.StatusOK, rec.Code, "a resolver failure must fail open to base, not fail the request: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"content":"ok"`)
	assert.Equal(t, "base-model", u.modelFor("/v1/chat/completions"))
	assert.Equal(t, 1, loader.loads, "the failing resolver must have been consulted")

	raw := rec.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, raw)
	assert.NotContains(t, raw, "arm", "a fail-open request carries no canary fields")
	assert.NotContains(t, raw, "rollout_id")
	assert.NotContains(t, raw, "canary_percent")
}
