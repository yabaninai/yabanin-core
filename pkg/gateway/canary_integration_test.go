//go:build integration

package cli

// the canary rollout lifecycle through the PRODUCTION wiring shapes —
// adminstore.Store over a fully migrated Postgres, the Redis version-key
// cache both the store bumps and the gateway resolver reads, and the
// canarySnapshotLoader projection the production gateway uses
// (gateway.go wires exactly these three pieces).
//
//     resolvers converge on an activation within one resolve; a Redis-less
//     gateway converges after its TTL fallback;
//   - split accuracy over N sessions against the real snapshot, with
//     cross-gateway stickiness and monotone ramping;
//   - rollback atomicity: enabled=false + version bump flips both
//     gateways, history intact, re-enable restores instantly, and an
//     in-flight HTTP request completes on its pinned model;
//   - decision fields end-to-end: header arm/rollout_id/rollout_version/
//     canary_percent join-keyed to the real store row, plus the
//     canary_arm_total metric.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// canaryIntFixture is the production-shaped stand: migrated Postgres,
// Redis, the adminstore canary surface with the Redis version bumper
// wired (exactly what services/run does), and one org.
type canaryIntFixture struct {
	store *adminstore.Store
	pool  *pgxpool.Pool
	rdb   *redis.Client
	org   string
	log   *slog.Logger
}

func newCanaryIntFixture(t *testing.T) *canaryIntFixture {
	t.Helper()
	pool := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	log := slog.New(slog.DiscardHandler)
	store := adminstore.New(pool, log, nil)
	store.SetCanaryVersionBumper(adminstore.NewCanaryVersionCache(rdb, log))
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("can-int-a-%d", suffix), fmt.Sprintf("can-int-a-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", org.ID)
		_ = rdb.Del(context.Background(), adminstore.CanaryVersionKeyPrefix+org.ID).Err()
	})
	return &canaryIntFixture{store: store, pool: pool, rdb: rdb, org: org.ID, log: log}
}

// newGatewayResolver builds ONE gateway's rollout resolver over the real
// store + shared Redis version key (the production wiring of gateway.go).
func (fx *canaryIntFixture) newGatewayResolver(ttl time.Duration) *router.CanaryRolloutCache {
	return router.NewCanaryRolloutCache(
		canarySnapshotLoader(fx.store),
		adminstore.NewCanaryVersionCache(fx.rdb, fx.log),
		ttl, fx.log)
}

// rolloutVersionOf resolves through one gateway and returns the single
// (version, percent) pair it observes — failing the test on a mixed or
// missing snapshot.
func rolloutVersionOf(t *testing.T, c *router.CanaryRolloutCache, org, rolloutID string) (int, int) {
	t.Helper()
	got, err := c.Resolve(context.Background(), org)
	require.NoError(t, err)
	require.Len(t, got, 1, "exactly the one rollout must resolve")
	require.Equal(t, rolloutID, got[0].RolloutID)
	return got[0].Version, got[0].Percent
}

func TestCanaryIntegration_TwoGatewayActivationConvergence(t *testing.T) {
	fx := newCanaryIntFixture(t)
	ctx := context.Background()

	ga := fx.newGatewayResolver(time.Minute)
	gb := fx.newGatewayResolver(time.Minute)

	// A detached rollout (created, not attached) serves nothing on either
	// gateway; both cache the empty answer.
	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.org, "convergence", "base-model", "canary-model", 10, "admin@x.test")
	require.NoError(t, err)
	_, err = ga.Resolve(ctx, fx.org)
	require.NoError(t, err)
	empty, err := gb.Resolve(ctx, fx.org)
	require.NoError(t, err)
	assert.Empty(t, empty)

	// Attach + activate v1 (10%): the store bumps the Redis version key;
	// both gateways converge on their very next resolve — no restart, no
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.org, r.ID, true)
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 1)
	require.NoError(t, err)
	verA, pctA := rolloutVersionOf(t, ga, fx.org, r.ID)
	verB, pctB := rolloutVersionOf(t, gb, fx.org, r.ID)
	assert.Equal(t, 1, verA)
	assert.Equal(t, 10, pctA)
	assert.Equal(t, 1, verB)
	assert.Equal(t, 10, pctB)

	// Ramp: append v2 (25%) and activate — both gateways move to v2.
	_, err = fx.store.CreateCanaryRolloutVersion(ctx, fx.org, r.ID, "base-model", "canary-model", 25, "admin@x.test")
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 2)
	require.NoError(t, err)
	verA, pctA = rolloutVersionOf(t, ga, fx.org, r.ID)
	verB, pctB = rolloutVersionOf(t, gb, fx.org, r.ID)
	assert.Equal(t, 2, verA)
	assert.Equal(t, 25, pctA)
	assert.Equal(t, 2, verB)
	assert.Equal(t, 25, pctB)

	// A Redis-less gateway (version reader nil — outage or unwired Redis)
	// inside the TTL, fresh after it.
	gc := router.NewCanaryRolloutCache(canarySnapshotLoader(fx.store), nil, 120*time.Millisecond, fx.log)
	verC, _ := rolloutVersionOf(t, gc, fx.org, r.ID)
	assert.Equal(t, 2, verC, "the TTL-only gateway first loads the current snapshot")
	_, err = fx.store.CreateCanaryRolloutVersion(ctx, fx.org, r.ID, "base-model", "canary-model", 40, "admin@x.test")
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 3)
	require.NoError(t, err)
	verC, _ = rolloutVersionOf(t, gc, fx.org, r.ID)
	assert.Equal(t, 2, verC, "inside its TTL the Redis-less gateway stays stale (documented bound)")
	time.Sleep(180 * time.Millisecond)
	verC, pctC := rolloutVersionOf(t, gc, fx.org, r.ID)
	assert.Equal(t, 3, verC, "after the TTL the Redis-less gateway converges without any bump")
	assert.Equal(t, 40, pctC)
}

func TestCanaryIntegration_SplitAccuracyAndCrossGatewayStickiness(t *testing.T) {
	fx := newCanaryIntFixture(t)
	ctx := context.Background()

	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.org, "split", "base-model", "canary-model", 30, "admin@x.test")
	require.NoError(t, err)
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.org, r.ID, true)
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 1)
	require.NoError(t, err)

	// Two full gateways (own caches) over the same stand: base carries the
	// pool weight, canary sits at weight 0 — canary traffic arrives ONLY
	// through the session-hash swap.
	newRouter := func() *router.TierRouter {
		tr := router.NewTierRouter(rt02TierLoader{
			{Name: "base-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
			{Name: "canary-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
		}, nil)
		tr.WithCanaryRollouts(fx.newGatewayResolver(time.Minute))
		return tr
	}
	ga, gb := newRouter(), newRouter()

	const n = 2000
	canaryA := 0
	models := make(map[string]string, n)
	for i := 0; i < n; i++ {
		session := "int-split-" + time.Duration(i).String()
		sel, dec, err := ga.SelectModelForSession(ctx, classifier.ClassMedium, fx.org, "", session)
		require.NoError(t, err)
		require.True(t, dec.Active())
		models[session] = sel.Name
		if sel.Name == "canary-model" {
			canaryA++
		}
	}
	share := 100 * float64(canaryA) / float64(n)
	assert.InDelta(t, 30.0, share, 2.0,
		"measured canary share over %d sessions must stay within ±2pp of the configured 30%%", n)

	// Cross-gateway stickiness: the SAME sessions through gateway B land
	// on the SAME models (the hash is gateway-independent).
	for i := 0; i < n; i++ {
		session := "int-split-" + time.Duration(i).String()
		sel, _, err := gb.SelectModelForSession(ctx, classifier.ClassMedium, fx.org, "", session)
		require.NoError(t, err)
		if sel.Name != models[session] {
			t.Fatalf("session %q: gateway A routed %q but gateway B routed %q — stickiness broken",
				session, models[session], sel.Name)
		}
	}

	// Monotone ramp on real activation: 30% → 60% keeps every existing
	// canary session canary.
	_, err = fx.store.CreateCanaryRolloutVersion(ctx, fx.org, r.ID, "base-model", "canary-model", 60, "admin@x.test")
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 2)
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		session := "int-split-" + time.Duration(i).String()
		if models[session] != "canary-model" {
			continue
		}
		sel, dec, err := ga.SelectModelForSession(ctx, classifier.ClassMedium, fx.org, "", session)
		require.NoError(t, err)
		assert.Equal(t, "canary-model", sel.Name, "session %q left the canary arm on ramp-up", session)
		assert.Equal(t, 2, dec.Version)
		assert.Equal(t, 60, dec.Percent)
	}
}

// canaryIntPost drives the real chatCompletions handler against the
// production canary wiring over the Docker stand.
func canaryIntPost(t *testing.T, gw *gateway, orgID, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	return rt02Post(t, gw,
		`{"model":"base-model","messages":[{"role":"user","content":"Tell me about AI"}]}`,
		map[string]string{"X-Session-Id": sessionID, "X-Org-Id": orgID})
}

// newCanaryIntGateway wires a full chat gateway whose canary resolver runs
// over the REAL store + Redis version key (the production wiring), with a
// synthetic upstream and model registry.
func newCanaryIntGateway(t *testing.T, fx *canaryIntFixture, u *rt02Upstream) *gateway {
	t.Helper()
	gw := rt02ChatGateway(t, u, &rt02Access{})
	gw.cfg.DecisionHeaderEnabled = true
	gw.cfg.DecisionEventEnabled = true
	gw.res = stubModelResolver{
		"base-model":   {ModelName: "base-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
		"canary-model": {ModelName: "canary-model", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true},
	}
	gw.classifier = classifier.NewRegistryWithDBCacheSilent(
		classifier.NewRegistryWithCacheNoop(classifier.NewRegistry(classifier.NewRuleTier())), nil, testLogger())
	gw.tierRouter = router.NewTierRouter(rt02TierLoader{
		{Name: "base-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "medium", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}, nil)
	gw.tierRouter.WithCanaryRollouts(fx.newGatewayResolver(time.Minute))
	return gw
}

func TestCanaryIntegration_DecisionFieldsEndToEnd(t *testing.T) {
	fx := newCanaryIntFixture(t)
	ctx := context.Background()
	u := newRT02Upstream(t)
	gw := newCanaryIntGateway(t, fx, u)

	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.org, "dfe", "base-model", "canary-model", 25, "admin@x.test")
	require.NoError(t, err)
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.org, r.ID, true)
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 1)
	require.NoError(t, err)

	canarySession := gatewayCanarySession(t, 25, true)
	baseSession := gatewayCanarySession(t, 25, false)

	before := testutil.ToFloat64(metrics.CanaryArmTotal.WithLabelValues("canary", "dfe", "canary-model"))

	rec := canaryIntPost(t, gw, fx.org, canarySession)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "canary-model", u.modelFor("/v1/chat/completions"),
		"the canary-arm session must be served by the canary model over the real snapshot")

	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, decisionSourceTierRouter, dec.Source)
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, r.ID, dec.RolloutID, "rollout_id must be the real store row id (analytics join key)")
	assert.Equal(t, 1, dec.RolloutVersion)
	assert.Equal(t, 25, dec.CanaryPercent)
	assert.Equal(t, "canary-model", dec.To)

	rec = canaryIntPost(t, gw, fx.org, baseSession)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "base-model", u.modelFor("/v1/chat/completions"))
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "base", dec.Arm)
	assert.Equal(t, r.ID, dec.RolloutID)
	assert.Equal(t, "base-model", dec.To)

	after := testutil.ToFloat64(metrics.CanaryArmTotal.WithLabelValues("canary", "dfe", "canary-model"))
	assert.Greater(t, after, before, "the measured-share metric must count the canary decision")
}

func TestCanaryIntegration_RollbackAtomicityAndInflightPin(t *testing.T) {
	fx := newCanaryIntFixture(t)
	ctx := context.Background()

	// A bounded blocking upstream: the in-flight request parks between
	// routing and response completion.
	arrived := make(chan string, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	servedModel := ""
	modelServed := func(m string) {
		mu.Lock()
		servedModel = m
		mu.Unlock()
	}
	lastServedModel := func() string {
		mu.Lock()
		defer mu.Unlock()
		return servedModel
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var probe struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&probe)
		modelServed(probe.Model)
		select {
		case arrived <- probe.Model: // first arrival signals routing done
		default:
		}
		select {
		case <-release:
		case <-time.After(5 * time.Second): // bound: never wedge cleanup
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"` + probe.Model + `","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(srv.Close)

	gw := newCanaryIntGateway(t, fx, &rt02Upstream{srv: srv})

	r, _, err := fx.store.CreateCanaryRollout(ctx, fx.org, "rollback", "base-model", "canary-model", 90, "admin@x.test")
	require.NoError(t, err)
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.org, r.ID, true)
	require.NoError(t, err)
	_, err = fx.store.SetActiveCanaryRolloutVersion(ctx, fx.org, r.ID, 1)
	require.NoError(t, err)
	versionBefore, err := adminstore.NewCanaryVersionCache(fx.rdb, fx.log).GetCanaryVersion(ctx, fx.org)
	require.NoError(t, err)

	session := gatewayCanarySession(t, 90, true)
	type result struct{ rec *httptest.ResponseRecorder }
	done := make(chan result, 1)
	go func() {
		done <- result{rec: canaryIntPost(t, gw, fx.org, session)}
	}()
	require.Equal(t, "canary-model", <-arrived, "the in-flight request routed to canary")

	// Manual rollback (D3) while the response is still open: the store
	// flips enabled=false and bumps the version key in one breath.
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.org, r.ID, false)
	require.NoError(t, err)
	close(release)

	res := <-done
	require.Equal(t, http.StatusOK, res.rec.Code, res.rec.Body.String())
	assert.Equal(t, "canary-model", lastServedModel(), "the in-flight response completes on the pinned canary model")
	var dec routingDecision
	require.NoError(t, json.Unmarshal([]byte(res.rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "canary", dec.Arm, "the in-flight decision keeps its arm")
	assert.Equal(t, 1, dec.RolloutVersion)
	assert.Equal(t, 90, dec.CanaryPercent)

	// The rollback bumped the version key (invalidation contract).
	versionAfter, err := adminstore.NewCanaryVersionCache(fx.rdb, fx.log).GetCanaryVersion(ctx, fx.org)
	require.NoError(t, err)
	assert.Greater(t, versionAfter, versionBefore, "rollback must bump the gateway invalidation key")

	// NEW requests of the SAME session route base, decision inactive.
	rec := canaryIntPost(t, gw, fx.org, session)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "base-model", lastServedModel(), "post-rollback requests route base")
	raw := rec.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, raw)
	assert.NotContains(t, raw, "arm", "post-rollback decisions carry no arm fields")
	assert.NotContains(t, raw, "rollout_id")

	// History is intact and re-enable restores the rollout instantly.
	versions, err := fx.store.ListCanaryRolloutVersions(ctx, fx.org, r.ID)
	require.NoError(t, err)
	require.Len(t, versions, 1, "rollback never touches version history")
	_, err = fx.store.UpdateCanaryRollout(ctx, fx.org, r.ID, true)
	require.NoError(t, err)
	rec = canaryIntPost(t, gw, fx.org, session)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "canary-model", lastServedModel(), "re-enable restores the canary arm on the next request")
	require.NoError(t, json.Unmarshal([]byte(rec.Header().Get(decisionHeaderKey)), &dec))
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, 1, dec.RolloutVersion)
}
