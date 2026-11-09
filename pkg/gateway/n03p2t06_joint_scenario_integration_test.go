//go:build integration

package cli

// N03-P02-T06 acceptance: enforcement on exact semantic replay as one JOINT
// user scenario on the agreed environment — the same shape a tenant actually
// experiences, not per-leg fragments.
//
// Real plumbing: migrated Postgres + Redis containers, the real adminstore
// with the real Redis policy version bumper, the real PolicyRuntime, the
// production auth middleware (header mode + real key resolver), and a real
// cache service whose regime resolver is wired exactly like production
// (gw.cacheSvc.SetPolicyRegimeResolver(gw.policyCacheRegime), the
// wireCacheService parity the T01 stand predates). The scenario walks one
// continuous timeline: warm replays without any policy (json and SSE, each
// under its own prompt shape — normalization deliberately keeps the stream
// marker, so stream entries carry their own exact key), a per-org tighten,
// warm replay rejection with refetch + live denial, tenant isolation of both
// the tighten and the warm entries, warming UNDER a tightened regime, a
// second tighten, and the enforcement-off window (production-shaped: the
// nil runtime an off-mode deployment boots with) with its observability
// counter — then defense restored.
//
// Mock seams (explicit): the upstream model provider is a synthetic stand
// whose answer depends on the prompt ("benign" prompts get clean content,
// everything else gets marker content) — provider output was never the
// system under test. The rollback binding test uses a scripted regime
// resolver over the same real backends, because the real control plane can
// tighten (version + plan set both change) but cannot return to a previous
// exact fingerprint: the digest includes the store version, so a rolled-back
// plan set under a newer version is a NEW regime by construction. The
// scripted resolver exercises the binding contract itself.
//
// Live-stream scoping fact (observed, by design): post_upstream policies do
// not run on a fresh live stream (only stream_prefix/stream_final do), so
// after a tighten a degraded SSE entry becomes a miss whose fresh stream is
// relayed under the live stream control. The terminal denial story in this
// scenario therefore rides the JSON path; denial of an SSE replay that still
// hits (semantic-mode stands) is T01's coverage.
//
// The active OpenCode stand is never contacted; only disposable Docker
// stands are touched.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/upstream"
)

const (
	n03p2t06Model = "n03p2t06-model"
	// n03p2t06Leak is the marker token inside the upstream's marker answer
	// and the deny word of the first tighten (R1). The clean answer must not
	// contain it, so R1 lets the clean answer through.
	n03p2t06Leak = "n03t06leak-7717"
	// n03p2t06CleanWord is the deny word of the second tighten (R2): it only
	// matches the clean answer, never the marker answer.
	n03p2t06CleanWord = "clean"
)

// n03p2t06Upstream is the synthetic provider stand: marker prompts get a
// marker-bearing completion, benign prompts get a clean completion, and every
// call is counted so the suite can prove exactly when a request refetched.
// Stream requests get real SSE chunks (role frame, content frame, final
// frame with finish_reason and usage, DONE) — the stream cache write
// accumulates provider SSE chunks into a completion document, so a
// JSON-only stand would never produce a cacheable stream entry.
type n03p2t06Upstream struct {
	srv   *httptest.Server
	calls atomic.Int64
}

func newN03P2T06Upstream() *n03p2t06Upstream {
	u := &n03p2t06Upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		content := fmt.Sprintf("answer with %s inside", n03p2t06Leak)
		if strings.Contains(string(raw), "benign") {
			content = "a perfectly clean answer"
		}
		if strings.Contains(string(raw), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"id\":\"n03p2t06-up\",\"created\":1700000000,\"model\":%q,\"choices\":[{\"index\":0,\"finish_reason\":null,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n", n03p2t06Model)                                         //nolint:errcheck // test stand
			fmt.Fprintf(w, "data: {\"id\":\"n03p2t06-up\",\"created\":1700000000,\"model\":%q,\"choices\":[{\"index\":0,\"finish_reason\":null,\"delta\":{\"content\":%q}}]}\n\n", n03p2t06Model, content)                                                         //nolint:errcheck // test stand
			fmt.Fprintf(w, "data: {\"id\":\"n03p2t06-up\",\"created\":1700000000,\"model\":%q,\"choices\":[{\"index\":0,\"finish_reason\":\"stop\",\"delta\":{}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n", n03p2t06Model) //nolint:errcheck // test stand
			fmt.Fprint(w, "data: [DONE]\n\n")                                                                                                                                                                                                                      //nolint:errcheck // test stand
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"n03p2t06-up","object":"chat.completion","model":"%s","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, n03p2t06Model, content) //nolint:errcheck // test stand
	}))
	return u
}

// n03p2t06Embedding is a non-zero constant vector: the async pgvector write
// (which every cache write feeds regardless of the exact-only org mode)
// must be able to persist a valid vector, or the writer's "written"
// accounting never advances.
func n03p2t06Embedding() []float32 {
	vec := make([]float32, 384)
	for i := range vec {
		vec[i] = 0.5
	}
	return vec
}

// n03p2t06ITEnv owns the stand; unlike the T01 env it retains the gateway so
// the scenario can swap the policy runtime (the enforcement-off window) and
// wires the regime resolver with production parity.
type n03p2t06ITEnv struct {
	pg        *pgxpool.Pool
	rdb       *redis.Client
	store     *adminstore.Store
	versions  PolicyVersionReader
	cacheSvc  *cache.CacheService
	gw        *gateway
	enforceRT *PolicyRuntime
	log       *slog.Logger
	upstream  *n03p2t06Upstream
	server    *httptest.Server
	client    *http.Client
}

func n03p2t06ITSetup(t *testing.T) *n03p2t06ITEnv {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	pg := testdb.Postgres(t)
	rdb := testdb.Redis(t)

	store := adminstore.New(pg, logger, nil)
	store.SetPolicyVersionBumper(adminstore.NewPolicyVersionCache(rdb, logger))
	versions := adminstore.NewPolicyVersionCache(rdb, logger)

	cacheSvc := cache.NewCacheService(context.Background(), pg, rdb,
		&embeddings.StaticClient{Embedding: n03p2t06Embedding()}, logger, false)
	cacheSvc.SetOrgPolicyLoader(cache.NewDBPolicyLoader(pg, logger).Wrap())
	cacheSvc.SetEmbedCache(cache.NewEmbedCache(2048))
	cacheSvc.SetExperimentStore(cache.NewExperimentStore(pg))

	up := newN03P2T06Upstream()
	runtime, err := NewPolicyRuntime(store, versions, PolicyModeEnforce, nil, logger)
	require.NoError(t, err, "construct enforce policy runtime over the real store")
	gw := &gateway{
		gatewayCore: gatewayCore{cfg: config.Gateway{
			AuthMode:           "header",
			Provider:           up.srv.URL,
			FallbackModel:      n03p2t06Model,
			UnknownModelPolicy: "reject",
			CacheEnabled:       true,
			CacheStreamEnabled: true,
		}, rdb: rdb, log: logger},
		gatewayEgress:     gatewayEgress{pool: upstream.NewPool(upstream.Options{BaseURL: up.srv.URL})},
		gatewayRouting:    gatewayRouting{res: stubModelResolver{n03p2t06Model: {ModelName: n03p2t06Model, Provider: "openai", UpstreamURL: up.srv.URL, Enabled: true}}},
		gatewayCompliance: gatewayCompliance{policyRuntime: runtime},
	}
	gw.cache = cacheSvc
	gw.cacheSvc = cacheSvc
	// Production parity (wireCacheService, gateway.go): the cache regime
	// resolver reads the live runtime lazily, so the off-window swap below
	// flows through the same seam a real deployment uses.
	gw.cacheSvc.SetPolicyRegimeResolver(gw.policyCacheRegime)
	gw.auth = NewAuthMiddleware(gw.cfg, auth.NewResolver(pg, rdb, 300, nil))
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(up.srv.Close)

	client := server.Client()
	client.Timeout = 15 * time.Second
	return &n03p2t06ITEnv{pg: pg, rdb: rdb, store: store, versions: versions,
		cacheSvc: cacheSvc, gw: gw, enforceRT: runtime, log: logger,
		upstream: up, server: server, client: client}
}

// n03p2t06Org is one synthetic org on the exact-only cache mode: the card's
// subject is the exact replay path; the semantic layer's governance is T01's
// coverage.
type n03p2t06Org struct {
	id        string
	slug      string
	plaintext string
}

func n03p2t06NewOrg(t *testing.T, env *n03p2t06ITEnv, suffix string) n03p2t06Org {
	t.Helper()
	ctx := context.Background()
	slug := fmt.Sprintf("n03p2t06-%s-%d", suffix, time.Now().UnixNano())
	org, err := env.store.CreateOrganization(ctx, "N03P2T06 synthetic "+suffix, slug)
	require.NoError(t, err, "create synthetic org %s", suffix)
	team, err := env.store.CreateTeam(ctx, org.ID, "N03P2T06 team", slug+"-team", nil)
	require.NoError(t, err, "create synthetic team")
	_, err = env.pg.Exec(ctx, `UPDATE organizations SET cache_enabled = true, cache_mode = 'exact' WHERE id::text = $1`, org.ID)
	require.NoError(t, err, "set org cache mode to exact")
	key, err := auth.GeneratePersonalKey()
	require.NoError(t, err, "generate synthetic API key")
	apiKey, err := env.store.CreateAPIKey(ctx, auth.HashKey(key), "N03P2T06 integration", &org.ID, &team.ID)
	require.NoError(t, err, "create synthetic API key row")
	t.Cleanup(func() {
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM api_keys WHERE id::text = $1`, apiKey.ID)
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, org.ID)
	})
	return n03p2t06Org{id: org.ID, slug: slug, plaintext: key}
}

// n03p2t06AttachDeny runs the REAL control-plane mutation for one org
// (CreatePolicy + publish + attach + enable), whose wired bumper publishes
// the org's Redis version key. The bump is asserted so a later denial cannot
// be attributed to a TTL fallback.
func n03p2t06AttachDeny(t *testing.T, env *n03p2t06ITEnv, org n03p2t06Org, name, word string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version before attach")
	pipeline, version, err := env.store.CreatePolicy(ctx, org.id, name,
		r011PostUpstreamYAML(r011DenyWordStep(word)), "n03p2t06-test-sha", "n03p2t06-suite")
	require.NoError(t, err, "create deny policy %s", name)
	_, err = env.store.SetActivePolicyVersion(ctx, org.id, pipeline.ID, version.Version)
	require.NoError(t, err, "publish draft version as active")
	_, err = env.store.SetPolicyAttachments(ctx, org.id, pipeline.ID,
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	require.NoError(t, err, "attach deny policy to chat")
	_, err = env.store.UpdatePolicy(ctx, org.id, pipeline.ID, true)
	require.NoError(t, err, "enable deny policy")
	after, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version after attach")
	assert.Greater(t, after, before, "the real bumper must publish the version key on attach")
}

type n03p2t06Response struct {
	status int
	header http.Header
	body   string
}

func n03p2t06Post(t *testing.T, env *n03p2t06ITEnv, org n03p2t06Org, body string) n03p2t06Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, env.server.URL+"/v1/chat/completions", strings.NewReader(body))
	require.NoError(t, err, "build request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+org.plaintext)
	resp, err := env.client.Do(req)
	require.NoError(t, err, "POST through the live gateway")
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response body")
	return n03p2t06Response{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// n03p2t06WaitStreamWrite polls the writer pool until one more write landed:
// the detached stream write persists asynchronously after the response, and
// the Redis exact put precedes the worker's accounting, so a landed write
// guarantees the replayable entry is present.
func n03p2t06WaitStreamWrite(t *testing.T, env *n03p2t06ITEnv, baseline int64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, written := env.cacheSvc.WriterStats(); written > baseline {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("stream cache write did not land within 30s (baseline %d)", baseline)
}

func n03p2t06Chat(content string) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, n03p2t06Model, content)
}

func n03p2t06ChatStream(content string) string {
	return fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":%q}]}`, n03p2t06Model, content)
}

// TestN03P2T06_JointScenario_RegimeEnforcementOnExactReplay walks one
// continuous tenant timeline on real plumbing. Phases:
//
//  0. No policies: both orgs warm their own entry for the same question and
//     replay it verbatim from the real exact layer — json replays under the
//     json prompt shape, the SSE replay under the stream prompt shape.
//  1. Tighten org-a (deny the leak token, real attach + real bump): org-a's
//     json warm replay degrades to a miss, refetches upstream and is denied
//     by the live post-upstream control — twice, proving a denial is never
//     cached and cannot be replayed either. The warm SSE entry degrades too:
//     its replay is a miss served fresh under the live stream control.
//     org-b's warm entries are untouched (per-org regimes): still EXACT.
//  2. org-a warms a clean entry UNDER the tightened regime and replays it
//     EXACT — a tighten is a regime change, not a blanket flush. A second
//     tighten then degrades that entry too: replay misses, refetches, and
//     the fresh answer is denied by the new rule.
//  3. Enforcement-off window: swapping in the production off-shape (a nil
//     runtime, exactly what buildPolicyRuntime leaves for off-mode
//     deployments) gates the cache on every operation (counter +2 per
//     request: one lookup, one write) and the control no-ops, so the marker
//     answer is served fresh —
//     twice, proving nothing is cached while off. Restoring the enforce
//     runtime restores the denial: the off-phase answers never landed in any
//     cache layer.
//
// The audit trail mirrors the timeline: every denial is a request.failed
// with the deny verdict; every warm serve and off-window fresh serve is a
// request.completed.
func TestN03P2T06_JointScenario_RegimeEnforcementOnExactReplay(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t06NewOrg(t, env, "orga")
	orgB := n03p2t06NewOrg(t, env, "orgb")
	events := captureEvents(t)
	q1 := n03p2t06Chat("n03t06 replay marker please")
	q2 := n03p2t06Chat("a benign question")
	s1 := n03p2t06ChatStream("n03t06 replay marker please")

	// Phase 0 — no policies: warm and replay on both orgs, json and SSE.
	warm := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	assert.Empty(t, warm.header.Get("X-Cache"), "first request is a miss")
	assert.Contains(t, warm.body, n03p2t06Leak)
	require.Equal(t, int64(1), env.upstream.calls.Load())

	hit := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"), "the warm entry replays from the real exact layer")
	assert.Contains(t, hit.body, n03p2t06Leak)
	require.Equal(t, int64(1), env.upstream.calls.Load(), "a warm replay must not refetch")

	_, _, writeBase := env.cacheSvc.WriterStats()
	streamWarm := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, streamWarm.status, streamWarm.body)
	assert.Contains(t, streamWarm.body, n03p2t06Leak)
	require.Equal(t, int64(2), env.upstream.calls.Load(),
		"the stream prompt shape is its own cache key — the json entry does not serve it")
	n03p2t06WaitStreamWrite(t, env, writeBase)

	sse := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, sse.status, sse.body)
	assert.Equal(t, "EXACT", sse.header.Get("X-Cache"), "the SSE replay serves the stream-shaped warm entry")
	assert.Equal(t, "text/event-stream", sse.header.Get("Content-Type"))
	assert.Contains(t, sse.body, n03p2t06Leak)
	assert.True(t, strings.HasSuffix(sse.body, "data: [DONE]\n\n"), "replay must terminate with the DONE frame")
	require.Equal(t, int64(2), env.upstream.calls.Load(), "a warm SSE replay must not refetch")

	bWarm := n03p2t06Post(t, env, orgB, q1)
	require.Equal(t, http.StatusOK, bWarm.status, bWarm.body)
	require.Equal(t, int64(3), env.upstream.calls.Load(), "org-b warms its own entry, never org-a's")
	bHit := n03p2t06Post(t, env, orgB, q1)
	require.Equal(t, http.StatusOK, bHit.status, bHit.body)
	assert.Equal(t, "EXACT", bHit.header.Get("X-Cache"))
	require.Equal(t, int64(3), env.upstream.calls.Load())

	// Phase 1 — tighten org-a only (real attach, real version bump).
	n03p2t06AttachDeny(t, env, orgA, "n03p2t06-deny-leak", n03p2t06Leak)

	d1 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, d1.status, d1.body)
	assert.Contains(t, d1.body, "content_policy_violation")
	assert.NotContains(t, d1.body, n03p2t06Leak, "the warm entry must not replay past the tightened regime")
	assert.Empty(t, d1.header.Get("X-Cache"), "a denial is not a served hit")
	require.Equal(t, int64(4), env.upstream.calls.Load(),
		"the regime change degrades the warm entry to a miss: the fresh fetch is denied live")

	d2 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, d2.status, d2.body)
	assert.NotContains(t, d2.body, n03p2t06Leak)
	require.Equal(t, int64(5), env.upstream.calls.Load(), "a denial is never cached — every replay refetches")

	sse1 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, sse1.status, sse1.body)
	assert.Empty(t, sse1.header.Get("X-Cache"),
		"the warm SSE entry is bound to the old regime too — it must not replay past the tighten")
	assert.Equal(t, "text/event-stream", sse1.header.Get("Content-Type"),
		"the degraded replay is a fresh live stream relayed from the provider stand")
	require.Equal(t, int64(6), env.upstream.calls.Load())

	bHit2 := n03p2t06Post(t, env, orgB, q1)
	require.Equal(t, http.StatusOK, bHit2.status, bHit2.body)
	assert.Equal(t, "EXACT", bHit2.header.Get("X-Cache"),
		"org-a's tighten must not degrade org-b's warm entry — regimes are per-org")
	assert.Contains(t, bHit2.body, n03p2t06Leak)
	require.Equal(t, int64(6), env.upstream.calls.Load())

	// Phase 2 — warm UNDER the tightened regime, then tighten again.
	fresh := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, fresh.status, fresh.body)
	assert.Empty(t, fresh.header.Get("X-Cache"))
	assert.Contains(t, fresh.body, "perfectly clean")
	require.Equal(t, int64(7), env.upstream.calls.Load())

	warmedUnderR1 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, warmedUnderR1.status, warmedUnderR1.body)
	assert.Equal(t, "EXACT", warmedUnderR1.header.Get("X-Cache"),
		"an entry warmed under the tightened regime replays — a tighten is not a blanket flush")
	require.Equal(t, int64(7), env.upstream.calls.Load())

	n03p2t06AttachDeny(t, env, orgA, "n03p2t06-deny-clean", n03p2t06CleanWord)

	g1 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusBadRequest, g1.status, g1.body)
	assert.Contains(t, g1.body, "content_policy_violation")
	assert.NotContains(t, g1.body, "perfectly clean")
	assert.Empty(t, g1.header.Get("X-Cache"))
	require.Equal(t, int64(8), env.upstream.calls.Load(),
		"the second tighten degrades the R1 entry: the refetched clean answer is denied by the new rule")

	g2 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusBadRequest, g2.status, g2.body)
	assert.NotContains(t, g2.body, "perfectly clean")
	require.Equal(t, int64(9), env.upstream.calls.Load())

	// Phase 3 — the enforcement-off window. Production shape: an off-mode
	// deployment has NO runtime at all (buildPolicyRuntime early-returns,
	// gateway.go) and every hook short-circuits on the nil check, so the
	// faithful swap is nil — not a mode-off runtime object (that construct
	// never exists in production wiring and its post-upstream hook still
	// evaluates stored policies).
	offBefore := testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal)
	env.gw.policyRuntime = nil

	o1 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, o1.status, o1.body)
	assert.Empty(t, o1.header.Get("X-Cache"), "enforcement-off gates the lookup — no served hit")
	assert.Contains(t, o1.body, n03p2t06Leak,
		"mode off disables the control itself (fail-open by design), so the fresh answer serves unfiltered")
	require.Equal(t, int64(10), env.upstream.calls.Load())

	o2 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, o2.status, o2.body)
	assert.Empty(t, o2.header.Get("X-Cache"))
	require.Equal(t, int64(11), env.upstream.calls.Load(),
		"nothing is cached while enforcement is off — every replay refetches")
	offDelta := testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal) - offBefore
	assert.InDelta(t, float64(4), offDelta, 0.001,
		"two gated requests must tick the counter +2 each: one gated lookup, one gated write per request")
	env.gw.policyRuntime = env.enforceRT

	// Defense restored: the off-phase answers never landed anywhere.
	r1 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, r1.status, r1.body)
	assert.Contains(t, r1.body, "content_policy_violation")
	assert.NotContains(t, r1.body, n03p2t06Leak)
	require.Equal(t, int64(12), env.upstream.calls.Load(),
		"the enforcement window stored nothing: the restored control sees a miss and denies live")
	r2 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, r2.status, r2.body)
	require.Equal(t, int64(13), env.upstream.calls.Load())

	// Audit trail mirrors the timeline.
	evs := r011ITWaitEvents(t, events, 18)
	failedA, completedA, completedB, exactHitsB := 0, 0, 0, 0
	for _, ev := range evs {
		switch {
		case ev.OrgID == orgA.id && ev.EventType == "request.failed":
			failedA++
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`, "the decision record must ride the event")
		case ev.OrgID == orgA.id && ev.EventType == "request.completed":
			completedA++
		case ev.OrgID == orgB.id:
			completedB++
			assert.Equal(t, "request.completed", ev.EventType, "org-b is never denied — the tighten is org-a's")
			if ev.CacheHitType == "exact" {
				exactHitsB++
			}
		}
	}
	assert.Equal(t, 6, failedA, "all six org-a json denials (2 tighten-1 + 2 tighten-2 + 2 restored) must be observable")
	assert.Equal(t, 9, completedA, "org-a completes: 4 warm replays + tightened fresh serves + SSE miss serve + 2 off-window serves")
	assert.Equal(t, 3, completedB)
	assert.GreaterOrEqual(t, exactHitsB, 2, "org-b's warm hits must be attributed to the exact source")
}

// n03p2t06ScriptedRegime is a mutex-guarded scripted regime fingerprint: the
// only mock seam of the rollback test (the real control plane can tighten
// but cannot return to a previous exact fingerprint, because the digest
// includes the store version).
type n03p2t06ScriptedRegime struct {
	mu sync.Mutex
	fp string
}

func (s *n03p2t06ScriptedRegime) set(fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fp = fp
}

func (s *n03p2t06ScriptedRegime) resolve(context.Context, string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fp
}

// TestN03P2T06_FingerprintRollbackBindingOnExactReplay proves the binding
// contract on real backends with a scripted resolver: warm entries are bound
// to the fingerprint VALUE, not latched to a disable state. Forward (F1→F2)
// and backward (F2→F1) transitions behave identically — every flip degrades
// the other regime's entries to misses, each org refetches and re-warms
// independently, and no transition ever serves a foreign-regime entry.
func TestN03P2T06_FingerprintRollbackBindingOnExactReplay(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t06NewOrg(t, env, "orga")
	orgB := n03p2t06NewOrg(t, env, "orgb")
	events := captureEvents(t)
	q1 := n03p2t06Chat("n03t06 rollback replay please")

	const (
		f1 = "aaaa1111aaaa1111"
		f2 = "bbbb2222bbbb2222"
	)
	regime := &n03p2t06ScriptedRegime{fp: f1}
	env.cacheSvc.SetPolicyRegimeResolver(regime.resolve)

	// F1: both orgs warm and replay.
	warmA := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, warmA.status, warmA.body)
	hitA := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, hitA.status, hitA.body)
	assert.Equal(t, "EXACT", hitA.header.Get("X-Cache"), "warm replay under F1")
	require.Equal(t, int64(1), env.upstream.calls.Load())

	warmB := n03p2t06Post(t, env, orgB, q1)
	require.Equal(t, http.StatusOK, warmB.status, warmB.body)
	require.Equal(t, int64(2), env.upstream.calls.Load())
	hitB := n03p2t06Post(t, env, orgB, q1)
	assert.Equal(t, "EXACT", hitB.header.Get("X-Cache"))
	require.Equal(t, int64(2), env.upstream.calls.Load())

	// F1→F2: every F1 entry degrades to a miss; each org refetches and
	// re-warms under F2.
	regime.set(f2)
	missA := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, missA.status, missA.body)
	assert.Empty(t, missA.header.Get("X-Cache"), "the F1 entry must not serve under F2")
	require.Equal(t, int64(3), env.upstream.calls.Load(), "the flip forced a real refetch")
	rewarmA := n03p2t06Post(t, env, orgA, q1)
	assert.Equal(t, "EXACT", rewarmA.header.Get("X-Cache"), "re-warmed under F2")
	require.Equal(t, int64(3), env.upstream.calls.Load())

	missB := n03p2t06Post(t, env, orgB, q1)
	require.Equal(t, http.StatusOK, missB.status, missB.body)
	assert.Empty(t, missB.header.Get("X-Cache"), "org-b's F1 entry is bound to F1 too")
	require.Equal(t, int64(4), env.upstream.calls.Load())
	rewarmB := n03p2t06Post(t, env, orgB, q1)
	assert.Equal(t, "EXACT", rewarmB.header.Get("X-Cache"))
	require.Equal(t, int64(4), env.upstream.calls.Load())

	// F2→F1 (rollback): the binding is per fingerprint VALUE, not a
	// disable latch — the F2 entries degrade exactly like the F1 entries
	// did, and each org re-warms under F1 independently.
	regime.set(f1)
	backA := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, backA.status, backA.body)
	assert.Empty(t, backA.header.Get("X-Cache"), "the F2 entry must not serve under restored F1")
	require.Equal(t, int64(5), env.upstream.calls.Load(), "the rollback is a regime change, not a bypass")
	rewarmBackA := n03p2t06Post(t, env, orgA, q1)
	assert.Equal(t, "EXACT", rewarmBackA.header.Get("X-Cache"))
	require.Equal(t, int64(5), env.upstream.calls.Load())

	backB := n03p2t06Post(t, env, orgB, q1)
	require.Equal(t, http.StatusOK, backB.status, backB.body)
	assert.Empty(t, backB.header.Get("X-Cache"))
	require.Equal(t, int64(6), env.upstream.calls.Load())
	rewarmBackB := n03p2t06Post(t, env, orgB, q1)
	assert.Equal(t, "EXACT", rewarmBackB.header.Get("X-Cache"))
	require.Equal(t, int64(6), env.upstream.calls.Load())

	// No policies exist in this test, so every request completes.
	evs := r011ITWaitEvents(t, events, 12)
	for _, ev := range evs {
		assert.Equal(t, "request.completed", ev.EventType)
	}
}
