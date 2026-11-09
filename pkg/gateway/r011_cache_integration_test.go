//go:build integration

package cli

// through the REAL consumer entry point — a live chi-served gateway behind
// the production auth middleware (header mode + real key resolver over
// Postgres/Redis), a real adminstore with the real Redis policy version
// bumper, and a real cache service backed by pgvector + Redis with the
// production DBPolicyLoader parity wiring (SetOrgPolicyLoader + embed cache
// + experiment store). No harness fakes sit between the HTTP client and the
// enforcement decision, so the acceptance "a cache hit does not bypass the
// actual control and tenant boundary" is demonstrated on production-shaped
// plumbing: exact hits, semantic hits (real pgvector ANN lookup), and the
// SSE replay of both, including entries cached BEFORE the governing policy
// existed and entries warmed by a DIFFERENT organization.
//
// Upstream model output is synthetic; only disposable Docker stands
// (testdb.Postgres/testdb.Redis) are touched. The active OpenCode stand is
// never contacted.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/embeddings"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/upstream"
)

const (
	r011ITModel  = "r011-it-model"
	r011ITMarker = "r011-it-leaked-ssn-6809"
)

// r011ITOrg is one synthetic organization with a personal API key whose
// plaintext authenticates through the production auth middleware.
type r011ITOrg struct {
	id        string
	slug      string
	plaintext string
	keyID     string
}

// r011ITUpstream is the model provider stand: every call answers one
// deterministic completion document (marker-controlled) and counts calls so
// the suite can prove a warm hit never refetches and a miss really went out.
type r011ITUpstream struct {
	srv    *httptest.Server
	calls  atomic.Int64
	marker string
}

func newR011ITUpstream(marker string) *r011ITUpstream {
	u := &r011ITUpstream{marker: marker}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"r011it-up","object":"chat.completion","model":"%s","choices":[{"index":0,"message":{"role":"assistant","content":"answer with %s inside"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, r011ITModel, u.marker) //nolint:errcheck // test stand
	}))
	return u
}

// r011ITEnv owns every real dependency one gateway stand needs.
type r011ITEnv struct {
	pg       *pgxpool.Pool
	rdb      *redis.Client
	store    *adminstore.Store
	versions PolicyVersionReader
	cacheSvc *cache.CacheService
	upstream *r011ITUpstream
	server   *httptest.Server
	client   *http.Client
}

// r011ITEmbedding is a non-zero constant vector: every prompt embeds to the
// same unit vector, so any two prompts are similarity-1.0 semantic matches
// (real pgvector ANN search, deterministic verdict).
func r011ITEmbedding() []float32 {
	vec := make([]float32, 384)
	for i := range vec {
		vec[i] = 0.5
	}
	return vec
}

// r011ITSetup boots the full stand: migrated Postgres + Redis containers,
// adminstore with the real version bumper, a production-parity cache service
// (DBPolicyLoader + embed cache + experiment store over the same pool), and
// a live gateway behind the production auth middleware. Chat cache and
// stream replay are enabled like a deployment with the cache rollout on.
func r011ITSetup(t *testing.T, marker string) *r011ITEnv {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	pg := testdb.Postgres(t)
	rdb := testdb.Redis(t)

	store := adminstore.New(pg, logger, nil)
	store.SetPolicyVersionBumper(adminstore.NewPolicyVersionCache(rdb, logger))
	versions := adminstore.NewPolicyVersionCache(rdb, logger)

	cacheSvc := cache.NewCacheService(context.Background(), pg, rdb,
		&embeddings.StaticClient{Embedding: r011ITEmbedding()}, logger, false)
	cacheSvc.SetOrgPolicyLoader(cache.NewDBPolicyLoader(pg, logger).Wrap())
	cacheSvc.SetEmbedCache(cache.NewEmbedCache(2048))
	cacheSvc.SetExperimentStore(cache.NewExperimentStore(pg))

	up := newR011ITUpstream(marker)
	runtime, err := NewPolicyRuntime(store, versions, PolicyModeEnforce, nil, logger)
	require.NoError(t, err, "construct policy runtime over the real store")
	gw := &gateway{
		gatewayCore: gatewayCore{cfg: config.Gateway{
			AuthMode:           "header",
			Provider:           up.srv.URL,
			FallbackModel:      r011ITModel,
			UnknownModelPolicy: "reject",
			CacheEnabled:       true,
			CacheStreamEnabled: true,
		}, rdb: rdb, log: logger},
		gatewayEgress: gatewayEgress{pool: upstream.NewPool(upstream.Options{BaseURL: up.srv.URL})},
		gatewayRouting: gatewayRouting{res: stubModelResolver{
			r011ITModel: {ModelName: r011ITModel, Provider: "openai", UpstreamURL: up.srv.URL, Enabled: true},
		}},
		gatewayCompliance: gatewayCompliance{policyRuntime: runtime},
	}
	gw.cache = cacheSvc
	gw.cacheSvc = cacheSvc
	gw.auth = NewAuthMiddleware(gw.cfg, auth.NewResolver(pg, rdb, 300, nil))
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(up.srv.Close)

	client := server.Client()
	client.Timeout = 15 * time.Second
	return &r011ITEnv{pg: pg, rdb: rdb, store: store, versions: versions,
		cacheSvc: cacheSvc, upstream: up, server: server, client: client}
}

// r011ITNewOrg creates a synthetic org (semantic cache explicitly on, matching
// the migration defaults) and registers row cleanup.
func r011ITNewOrg(t *testing.T, env *r011ITEnv, suffix, cacheMode string) r011ITOrg {
	t.Helper()
	ctx := context.Background()
	slug := fmt.Sprintf("r011it-%s-%d", suffix, time.Now().UnixNano())
	org, err := env.store.CreateOrganization(ctx, "R011IT synthetic "+suffix, slug)
	require.NoError(t, err, "create synthetic org %s", suffix)
	team, err := env.store.CreateTeam(ctx, org.ID, "R011IT team", slug+"-team", nil)
	require.NoError(t, err, "create synthetic team")
	_, err = env.pg.Exec(ctx, `UPDATE organizations SET cache_enabled = true, cache_mode = $2 WHERE id::text = $1`,
		org.ID, cacheMode)
	require.NoError(t, err, "set org cache mode")
	key, err := auth.GeneratePersonalKey()
	require.NoError(t, err, "generate synthetic API key")
	apiKey, err := env.store.CreateAPIKey(ctx, auth.HashKey(key), "R011IT integration", &org.ID, &team.ID)
	require.NoError(t, err, "create synthetic API key row")
	t.Cleanup(func() {
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM api_keys WHERE id::text = $1`, apiKey.ID)
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, org.ID)
	})
	return r011ITOrg{id: org.ID, slug: slug, plaintext: key, keyID: apiKey.ID}
}

// r011ITAttachDeny runs the REAL control-plane mutation: CreatePolicy +
// SetPolicyAttachments on the adminstore, whose wired bumper publishes the
// Redis version key. The bump is asserted so a later denial cannot be
// attributed to a TTL fallback.
func r011ITAttachDeny(t *testing.T, env *r011ITEnv, org r011ITOrg, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version before attach")
	pipeline, version, err := env.store.CreatePolicy(ctx, org.id, "r011it-deny",
		r011PostUpstreamYAML(r011DenyWordStep(marker)), "r011it-test-sha", "r011it-suite")
	require.NoError(t, err, "create deny policy")
	_, err = env.store.SetActivePolicyVersion(ctx, org.id, pipeline.ID, version.Version)
	require.NoError(t, err, "publish draft version as active (the CLI apply promotes the draft)")
	_, err = env.store.SetPolicyAttachments(ctx, org.id, pipeline.ID,
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	require.NoError(t, err, "attach deny policy to chat")
	_, err = env.store.UpdatePolicy(ctx, org.id, pipeline.ID, true)
	require.NoError(t, err, "enable deny policy (the CLI apply flips the draft pipeline live)")
	after, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version after attach")
	assert.Greater(t, after, before, "the real bumper must publish the version key on attach")
}

// r011ITPost drives the consumer entry point exactly like a client: one
// authenticated HTTP call to the live server.
type r011ITResponse struct {
	status int
	header http.Header
	body   string
}

func r011ITPost(t *testing.T, env *r011ITEnv, org r011ITOrg, body string) r011ITResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/v1/chat/completions", strings.NewReader(body))
	require.NoError(t, err, "build request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+org.plaintext)
	resp, err := env.client.Do(req)
	require.NoError(t, err, "POST through the live gateway")
	defer resp.Body.Close() //nolint:errcheck // response fully read below
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response body")
	return r011ITResponse{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// r011ITWaitEvents polls the observer until want events arrived (event
// emission is synchronous with the response, the deadline only absorbs
// scheduler jitter).
func r011ITWaitEvents(t *testing.T, events func() []*eventpub.Event, want int) []*eventpub.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got []*eventpub.Event
	for time.Now().Before(deadline) {
		if got = events(); len(got) >= want {
			return got
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected %d events, saw %d", want, len(got))
	return nil
}

// r011ITWaitCacheWrite polls the writer pool until one more write landed
// (the pgvector semantic insert is asynchronous by design).
func r011ITWaitCacheWrite(t *testing.T, env *r011ITEnv, baseline int64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, written := env.cacheSvc.WriterStats(); written > baseline {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("cache writer did not persist a semantic entry within 30s (baseline %d)", baseline)
}

// TestR011_Integration_CacheHitEntryGovernedAfterPolicyChange is the card's
// failure scenario on real plumbing: org-a warms an exact entry and replays
// it verbatim (json + SSE) BEFORE any policy exists; the deny policy is then
// attached through the real store (real Redis bump) and the SAME warm entry
// is answered with the terminal envelope through the live gateway — json and
// stream alike — with zero upstream refetch. org-b proves both halves of the
// tenant boundary: org-a's warm entry is not served to org-b (provenance
// miss, fresh upstream call) and org-a's new policy does not govern org-b.
func TestR011_Integration_CacheHitEntryGovernedAfterPolicyChange(t *testing.T) {
	env := r011ITSetup(t, r011ITMarker)
	orgA := r011ITNewOrg(t, env, "orga", "semantic")
	orgB := r011ITNewOrg(t, env, "orgb", "semantic")
	events := captureEvents(t)
	chat := func(content string) string {
		return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, r011ITModel, content)
	}

	warm := r011ITPost(t, env, orgA, chat("r011it-p1"))
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	assert.Equal(t, int64(1), env.upstream.calls.Load(), "fresh request goes upstream once")
	assert.Empty(t, warm.header.Get("X-Cache"), "first request is a miss")

	exact := r011ITPost(t, env, orgA, chat("r011it-p1"))
	require.Equal(t, http.StatusOK, exact.status, exact.body)
	assert.Equal(t, "EXACT", exact.header.Get("X-Cache"), "second identical request must hit the real exact layer")
	assert.Contains(t, exact.body, r011ITMarker, "with no policy attached the warm entry serves verbatim")
	assert.Equal(t, int64(1), env.upstream.calls.Load(), "a warm hit must not refetch upstream")

	replay := r011ITPost(t, env, orgA, fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"r011it-p1"}]}`, r011ITModel))
	require.Equal(t, http.StatusOK, replay.status, replay.body)
	assert.Equal(t, "text/event-stream", replay.header.Get("Content-Type"))
	assert.Contains(t, replay.body, r011ITMarker, "the SSE replay serves the same warm entry verbatim")
	assert.True(t, strings.HasSuffix(replay.body, "data: [DONE]\n\n"), "replay must terminate with the DONE frame")
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	r011ITAttachDeny(t, env, orgA, r011ITMarker)

	denied := r011ITPost(t, env, orgA, chat("r011it-p1"))
	require.Equal(t, http.StatusBadRequest, denied.status, denied.body)
	assert.Contains(t, denied.body, "content_policy_violation")
	assert.NotContains(t, denied.body, r011ITMarker, "an entry cached before the policy change must not replay past the live control")
	assert.Empty(t, denied.header.Get("X-Cache"), "a denial is not a served hit")
	assert.Equal(t, int64(1), env.upstream.calls.Load(), "the policy verdict must answer before any upstream refetch")

	deniedStream := r011ITPost(t, env, orgA, fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"r011it-p1"}]}`, r011ITModel))
	require.Equal(t, http.StatusBadRequest, deniedStream.status, deniedStream.body)
	assert.Contains(t, deniedStream.body, "content_policy_violation")
	assert.NotContains(t, deniedStream.body, r011ITMarker)
	assert.NotContains(t, deniedStream.body, "data:", "denied content must not be framed as SSE")
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	foreign := r011ITPost(t, env, orgB, chat("r011it-p1"))
	require.Equal(t, http.StatusOK, foreign.status, foreign.body)
	assert.Equal(t, int64(2), env.upstream.calls.Load(), "org-b must not be served org-a's warm entry (provenance miss)")
	assert.Empty(t, foreign.header.Get("X-Cache"))
	assert.Contains(t, foreign.body, r011ITMarker, "org-a's deny policy must not govern org-b")

	evs := r011ITWaitEvents(t, events, 6)
	failedA := 0
	for _, ev := range evs {
		if ev.OrgID != orgA.id {
			continue
		}
		switch ev.EventType {
		case "request.failed":
			failedA++
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`, "the decision record must ride the event")
		case "request.completed":
			assert.NotEqual(t, http.StatusBadRequest, ev.StatusCode)
		}
	}
	assert.Equal(t, 2, failedA, "both warm-entry requests (json + stream) must fail with the policy verdict")
	for _, ev := range evs {
		if ev.OrgID == orgB.id {
			assert.Equal(t, "request.completed", ev.EventType, "org-b's fresh request must complete")
		}
	}
}

// TestR011_Integration_SemanticCacheHitGovernedAtEntry covers the semantic
// source on real pgvector: org-c warms an entry, a DIFFERENT prompt semantic-
// matches it (constant-embedding stand, real ANN lookup), the SSE replay of
// the semantic hit serves the same document, and after the deny policy is
// attached the semantic hit AND its replay AND the original exact prompt are
// all sealed at the same entry point.
func TestR011_Integration_SemanticCacheHitGovernedAtEntry(t *testing.T) {
	env := r011ITSetup(t, r011ITMarker)
	orgC := r011ITNewOrg(t, env, "orgc", "semantic")
	events := captureEvents(t)
	chat := func(content string) string {
		return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, r011ITModel, content)
	}

	_, _, baseline := env.cacheSvc.WriterStats()
	warm := r011ITPost(t, env, orgC, chat("r011it-alpha prompt one"))
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	assert.Equal(t, int64(1), env.upstream.calls.Load())
	r011ITWaitCacheWrite(t, env, baseline)

	semantic := r011ITPost(t, env, orgC, chat("r011it-beta prompt two"))
	require.Equal(t, http.StatusOK, semantic.status, semantic.body)
	assert.Equal(t, "SEMANTIC", semantic.header.Get("X-Cache"), "the real pgvector layer must answer the different prompt")
	assert.Contains(t, semantic.body, r011ITMarker, "with no policy attached the semantic hit serves verbatim")
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	semanticReplay := r011ITPost(t, env, orgC, fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"r011it-beta prompt two"}]}`, r011ITModel))
	require.Equal(t, http.StatusOK, semanticReplay.status, semanticReplay.body)
	assert.Equal(t, "text/event-stream", semanticReplay.header.Get("Content-Type"))
	assert.Contains(t, semanticReplay.body, r011ITMarker)
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	r011ITAttachDeny(t, env, orgC, r011ITMarker)

	denied := r011ITPost(t, env, orgC, chat("r011it-beta prompt two"))
	require.Equal(t, http.StatusBadRequest, denied.status, denied.body)
	assert.Contains(t, denied.body, "content_policy_violation")
	assert.NotContains(t, denied.body, r011ITMarker, "the semantic source is governed by the live control")
	assert.Empty(t, denied.header.Get("X-Cache"))
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	deniedReplay := r011ITPost(t, env, orgC, fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"r011it-beta prompt two"}]}`, r011ITModel))
	require.Equal(t, http.StatusBadRequest, deniedReplay.status, deniedReplay.body)
	assert.NotContains(t, deniedReplay.body, r011ITMarker)
	assert.NotContains(t, deniedReplay.body, "data:")

	deniedExact := r011ITPost(t, env, orgC, chat("r011it-alpha prompt one"))
	require.Equal(t, http.StatusBadRequest, deniedExact.status, deniedExact.body)
	assert.NotContains(t, deniedExact.body, r011ITMarker, "the original exact prompt is sealed too")

	// The served semantic hit re-sealed into the exact layer, so P_beta's
	// denials above answer from the exact source — the real seal-first
	// architecture. A NEVER-SERVED prompt misses exact and reaches the
	// pgvector semantic layer directly; the same live control must seal it.
	deniedSemantic := r011ITPost(t, env, orgC, chat("r011it-delta prompt three"))
	require.Equal(t, http.StatusBadRequest, deniedSemantic.status, deniedSemantic.body)
	assert.Contains(t, deniedSemantic.body, "content_policy_violation")
	assert.NotContains(t, deniedSemantic.body, r011ITMarker, "the semantic source is governed by the live control")
	assert.Empty(t, deniedSemantic.header.Get("X-Cache"))
	assert.Equal(t, int64(1), env.upstream.calls.Load(), "the semantic denial must not refetch upstream")

	evs := r011ITWaitEvents(t, events, 7)
	sources := map[string]int{}
	for _, ev := range evs {
		if ev.OrgID == orgC.id && ev.EventType == "request.failed" {
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`)
			sources[ev.CacheHitType]++
		}
	}
	assert.GreaterOrEqual(t, sources["semantic"], 1, "the semantic-hit denial must be observable on the event")
	assert.Equal(t, 4, sources["semantic"]+sources["exact"], "all four denied cache hits (semantic + its replay + exacts + the never-served semantic prompt) must be recorded")
}

// TestR011_Integration_TenantBoundaryForeignPolicyAndForeignEntry proves the
// tenant boundary through the real org-scoped keys and the real policy
// runtime: org-d's deny policy attached BEFORE org-e warms an entry does not
// govern org-e's hit, and org-e's warm entry is not served to org-d — org-d's
// request degrades to a real miss (one upstream call) whose FRESH document is
// then denied post-upstream, so the marker never reaches org-d either way.
func TestR011_Integration_TenantBoundaryForeignPolicyAndForeignEntry(t *testing.T) {
	env := r011ITSetup(t, r011ITMarker)
	orgD := r011ITNewOrg(t, env, "orgd", "semantic")
	orgE := r011ITNewOrg(t, env, "orge", "semantic")
	events := captureEvents(t)
	r011ITAttachDeny(t, env, orgD, r011ITMarker)
	chat := func(content string) string {
		return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, r011ITModel, content)
	}

	warm := r011ITPost(t, env, orgE, chat("r011it-gamma"))
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	hit := r011ITPost(t, env, orgE, chat("r011it-gamma"))
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"), "org-e's warm hit is real")
	assert.Contains(t, hit.body, r011ITMarker, "org-d's deny policy must not govern org-e's cache hit")
	assert.Equal(t, int64(1), env.upstream.calls.Load())

	orgDMiss := r011ITPost(t, env, orgD, chat("r011it-gamma"))
	require.Equal(t, http.StatusBadRequest, orgDMiss.status, orgDMiss.body)
	assert.Equal(t, int64(2), env.upstream.calls.Load(), "org-d must not be served org-e's warm entry — a real miss went upstream")
	assert.Contains(t, orgDMiss.body, "content_policy_violation", "org-d's fresh fetch is denied post-upstream")
	assert.NotContains(t, orgDMiss.body, r011ITMarker, "the marker must never reach org-d through either path")
	assert.Empty(t, orgDMiss.header.Get("X-Cache"))

	evs := r011ITWaitEvents(t, events, 3)
	for _, ev := range evs {
		if ev.OrgID == orgE.id {
			assert.Equal(t, "request.completed", ev.EventType, "org-e's warm hit must complete")
		}
		if ev.OrgID == orgD.id {
			assert.Equal(t, "request.failed", ev.EventType)
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`)
		}
	}
}
