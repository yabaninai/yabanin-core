//go:build integration

package cli

// N03-P02-T08 acceptance: interruption/retry/resume recovery without
// duplicates or losses, on the real plumbing (migrated Postgres + Redis
// containers, real adminstore + PolicyRuntime + production auth, real cache
// service wired for production parity, real async pgvector writer). The
// corpus is deliberately DISTINCT from the T07 boundary corpus (which pins
// static regime boundaries): here every scenario interrupts a live request —
// an upstream failure mid-request, torn cache bytes, a control-plane tighten
// landing between retry attempts, and an enforcement-off window spanning a
// retry.
//
// Axes:
//   A — retry after an interrupted upstream call: the resumed request
//       produces exactly one policy decision (over the winning body only)
//       and exactly one cache write; the replay is an exact hit.
//   B — torn/half-written cache entries (the interruption-between-write-
//       and-recheck shape): envelope-level corruption and a broken document
//       inside an intact envelope degrade to misses, the refetch rewrites
//       the good value over the same key (self-healing), and no duplicate
//       artifacts accumulate (pg upsert, single redis key).
//   C — a policy tighten landing between retry attempts: the in-flight
//       request does not bypass through warm cache; the value it rewrites
//       under the stale in-flight snapshot never serves after the tighten;
//       the next request is denied live.
//   D — enforcement off (nil runtime, the production off-shape) during a
//       retry: no cache reads and no writes, proven by the
//       cache_enforcement_off_skipped_total counter (exactly +2: one skipped
//       lookup, one skipped admission; the retry itself is transport-level
//       and adds no cache operations) and flat writer stats.
//
// Mock seams (explicit): only the upstream model provider (a scripted
// status/body stand) — provider behavior was never the system under test.
// Redis/Postgres are real containers; policy mutations go through the real
// adminstore and the real Redis version bumper. The tighten inside the
// upstream handler is ordered deterministically by a handshake channel, so
// the bump provably lands between attempt 1 and the retry.
//
// Out-of-scope observation (pinned, not a defect to fix here): the in-flight
// request's post-upstream re-governance uses the request-scoped pre-upstream
// regime snapshot (withRequestPolicyEntryOutcome), so a tighten landing
// mid-retry lets THAT one response serve under the stale snapshot — a
// bounded one-request window by design (T01 boundary). Axis C proves both
// halves of the contract around it: no warm-cache bypass for the in-flight
// request, live denial for the next one, and no bypass-shaped entry stored.

import (
	"context"
	"encoding/json"
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

const n03p2t08Answer = "n03t08 self-healed good answer"

// n03p2t08Step is one scripted upstream response. status 0 means 200; body
// is the completion document served for 200s.
type n03p2t08Step struct {
	status int
	body   string
}

// n03p2t08ScriptedUpstream serves the script call by call (the last step
// repeats once exhausted) and counts calls so the suite can prove exactly
// how many upstream attempts a request made. onCall runs synchronously
// inside the handler BEFORE the response is written — the seam axis C uses
// to land a real control-plane mutation between attempt 1 and the retry.
type n03p2t08ScriptedUpstream struct {
	srv    *httptest.Server
	calls  atomic.Int64
	onCall func(call int64)
	mu     sync.Mutex
	script []n03p2t08Step
}

func newN03P2T08ScriptedUpstream(script ...n03p2t08Step) *n03p2t08ScriptedUpstream {
	u := &n03p2t08ScriptedUpstream{script: script}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := u.calls.Add(1)
		if u.onCall != nil {
			u.onCall(call)
		}
		step := u.stepFor(call)
		w.Header().Set("Content-Type", "application/json")
		if step.status != 0 && step.status != http.StatusOK {
			w.WriteHeader(step.status)
			fmt.Fprintf(w, `{"error":{"message":"upstream unavailable","type":"server_error","code":%d}}`, step.status) //nolint:errcheck // test stand
			return
		}
		fmt.Fprint(w, step.body) //nolint:errcheck // test stand
	}))
	return u
}

func (u *n03p2t08ScriptedUpstream) stepFor(call int64) n03p2t08Step {
	u.mu.Lock()
	defer u.mu.Unlock()
	if int(call) <= len(u.script) {
		return u.script[call-1]
	}
	return u.script[len(u.script)-1]
}

func n03p2t08Completion(content string) string {
	return fmt.Sprintf(`{"id":"n03p2t08-up","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, n03p2t06Model, content)
}

// n03p2t08ITEnv owns the stand; it mirrors the T06 env with the scripted
// upstream the interruption axes need (the T06 stand always answers 200).
type n03p2t08ITEnv struct {
	pg        *pgxpool.Pool
	rdb       *redis.Client
	store     *adminstore.Store
	versions  PolicyVersionReader
	cacheSvc  *cache.CacheService
	gw        *gateway
	enforceRT *PolicyRuntime
	log       *slog.Logger
	upstream  *n03p2t08ScriptedUpstream
	server    *httptest.Server
	client    *http.Client
}

func n03p2t08ITSetup(t *testing.T, script ...n03p2t08Step) *n03p2t08ITEnv {
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

	up := newN03P2T08ScriptedUpstream(script...)
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
	// Production parity (wireCacheService, gateway.go).
	gw.cacheSvc.SetPolicyRegimeResolver(gw.policyCacheRegime)
	gw.auth = NewAuthMiddleware(gw.cfg, auth.NewResolver(pg, rdb, 300, nil))
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(up.srv.Close)

	client := server.Client()
	// 60s: the mid-retry test blocks a request inside the upstream handler
	// while the test lands a real control-plane mutation; that block is
	// part of the scenario, not a stall.
	client.Timeout = 60 * time.Second
	return &n03p2t08ITEnv{pg: pg, rdb: rdb, store: store, versions: versions,
		cacheSvc: cacheSvc, gw: gw, enforceRT: runtime, log: logger,
		upstream: up, server: server, client: client}
}

func n03p2t08NewOrg(t *testing.T, env *n03p2t08ITEnv, suffix string) n03p2t06Org {
	t.Helper()
	ctx := context.Background()
	slug := fmt.Sprintf("n03p2t08-%s-%d", suffix, time.Now().UnixNano())
	org, err := env.store.CreateOrganization(ctx, "N03P2T08 synthetic "+suffix, slug)
	require.NoError(t, err, "create synthetic org %s", suffix)
	team, err := env.store.CreateTeam(ctx, org.ID, "N03P2T08 team", slug+"-team", nil)
	require.NoError(t, err, "create synthetic team")
	_, err = env.pg.Exec(ctx, `UPDATE organizations SET cache_enabled = true, cache_mode = 'exact' WHERE id::text = $1`, org.ID)
	require.NoError(t, err, "set org cache mode to exact")
	key, err := auth.GeneratePersonalKey()
	require.NoError(t, err, "generate synthetic API key")
	apiKey, err := env.store.CreateAPIKey(ctx, auth.HashKey(key), "N03P2T08 integration", &org.ID, &team.ID)
	require.NoError(t, err, "create synthetic API key row")
	t.Cleanup(func() {
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM api_keys WHERE id::text = $1`, apiKey.ID)
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, org.ID)
	})
	return n03p2t06Org{id: org.ID, slug: slug, plaintext: key}
}

// n03p2t08Attach runs the REAL control-plane mutation (CreatePolicy +
// publish + attach + enable) whose wired bumper publishes the org's Redis
// version key; the bump is asserted so a later regime flip cannot be
// attributed to a TTL fallback.
func n03p2t08Attach(t *testing.T, env *n03p2t08ITEnv, org n03p2t06Org, name, stepsYAML string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version before attach")
	pipeline, version, err := env.store.CreatePolicy(ctx, org.id, name,
		r011PostUpstreamYAML(stepsYAML), "n03p2t08-test-sha", "n03p2t08-suite")
	require.NoError(t, err, "create policy %s", name)
	_, err = env.store.SetActivePolicyVersion(ctx, org.id, pipeline.ID, version.Version)
	require.NoError(t, err, "publish draft version as active")
	_, err = env.store.SetPolicyAttachments(ctx, org.id, pipeline.ID,
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	require.NoError(t, err, "attach policy to chat")
	_, err = env.store.UpdatePolicy(ctx, org.id, pipeline.ID, true)
	require.NoError(t, err, "enable policy")
	after, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version after attach")
	assert.Greater(t, after, before, "the real bumper must publish the version key on attach")
}

func n03p2t08AttachDeny(t *testing.T, env *n03p2t08ITEnv, org n03p2t06Org, name, word string) {
	t.Helper()
	n03p2t08Attach(t, env, org, name, r011DenyWordStep(word))
}

func n03p2t08AttachRedact(t *testing.T, env *n03p2t08ITEnv, org n03p2t06Org, name, category, pattern string) {
	t.Helper()
	n03p2t08Attach(t, env, org, name, r011RedactStep(category, pattern))
}

type n03p2t08Response struct {
	status int
	header http.Header
	body   string
}

// n03p2t08Do performs the request WITHOUT require calls: it is safe to run
// from non-test goroutines (a require there would FailNow via Goexit and
// silently drop the result).
func n03p2t08Do(env *n03p2t08ITEnv, org n03p2t06Org, body string) (n03p2t08Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, env.server.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return n03p2t08Response{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+org.plaintext)
	resp, err := env.client.Do(req)
	if err != nil {
		return n03p2t08Response{}, fmt.Errorf("POST /v1/chat/completions: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test stand
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return n03p2t08Response{}, fmt.Errorf("read response body: %w", err)
	}
	return n03p2t08Response{status: resp.StatusCode, header: resp.Header, body: string(raw)}, nil
}

func n03p2t08Post(t *testing.T, env *n03p2t08ITEnv, org n03p2t06Org, body string) n03p2t08Response {
	t.Helper()
	resp, err := n03p2t08Do(env, org, body)
	require.NoError(t, err)
	return resp
}

// n03p2t08WaitWrites polls the writer pool until `want` cumulative writes
// landed (the pgvector insert is asynchronous by design).
func n03p2t08WaitWrites(t *testing.T, env *n03p2t08ITEnv, want int64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, written := env.cacheSvc.WriterStats(); written >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _, written := env.cacheSvc.WriterStats()
	t.Fatalf("cache writer did not reach %d writes within 30s (at %d)", want, written)
}

func n03p2t08PgRows(t *testing.T, env *n03p2t08ITEnv, orgID string) int {
	t.Helper()
	var n int
	err := env.pg.QueryRow(context.Background(),
		`SELECT count(*) FROM cache_entries WHERE org_id::text = $1`, orgID).Scan(&n)
	require.NoError(t, err, "count cache_entries rows")
	return n
}

func n03p2t08RedisKeys(t *testing.T, env *n03p2t08ITEnv, orgID string) int {
	t.Helper()
	keys := 0
	iter := env.rdb.Scan(context.Background(), 0, cache.KeyPatternOrg(orgID), 500).Iterator()
	for iter.Next(context.Background()) {
		keys++
	}
	require.NoError(t, iter.Err(), "scan redis keys")
	return keys
}

// n03p2t08Envelope parses the sealed value (same JSON tags as the cache
// envelope) so a test can assert the outer envelope is intact while the
// completion document inside it is not decodable.
type n03p2t08Envelope struct {
	Route string          `json:"route"`
	Prov  json.RawMessage `json:"prov"`
	Data  json.RawMessage `json:"data"`
}

// --- axis A: retry after an interrupted upstream call -------------------------

// TestN03P2T08_Retry503_SingleDecision_SingleWrite_ExactReplay proves the
// no-duplicates/no-losses contract across a retry: the interrupted attempt
// (503) is retried, the winning body is governed exactly once (one allow
// decision, mask applied once), cached exactly once (one submit, one
// persist, one pg row), and the replay is an exact hit of that governed
// document with no further upstream calls or writes.
func TestN03P2T08_Retry503_SingleDecision_SingleWrite_ExactReplay(t *testing.T) {
	env := n03p2t08ITSetup(t,
		n03p2t08Step{status: http.StatusServiceUnavailable},
		n03p2t08Step{body: n03p2t08Completion("n03t08 answer cached-badge-4242 with details")},
	)
	org := n03p2t08NewOrg(t, env, "retry503")
	n03p2t08AttachRedact(t, env, org, "n03p2t08-mask-badge", "badge", "cached-badge-[0-9]+")
	events := captureEvents(t)
	q := n03p2t06Chat("n03t08 retry recovery question")
	q0, d0, w0 := env.cacheSvc.WriterStats()

	resp := n03p2t08Post(t, env, org, q)
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	assert.Contains(t, resp.body, "[REDACTED:badge:1]", "the winning body is governed before serving")
	assert.NotContains(t, resp.body, "cached-badge-4242", "the raw marker must not reach the client")
	require.Equal(t, int64(2), env.upstream.calls.Load(), "one interrupted attempt + one successful retry")

	n03p2t08WaitWrites(t, env, w0+1)
	q1, d1, w1 := env.cacheSvc.WriterStats()
	assert.Equal(t, q0+1, q1, "exactly one write submitted despite the retry")
	assert.Equal(t, d0, d1, "nothing dropped")
	assert.Equal(t, w0+1, w1, "exactly one write persisted")
	assert.Equal(t, 1, n03p2t08PgRows(t, env, org.id), "exactly one pgvector row for the recovered answer")

	evs := r011ITWaitEvents(t, events, 1)
	require.Len(t, evs, 1, "a retried request is one request: no per-attempt events")
	assert.Equal(t, "request.completed", evs[0].EventType)
	assert.Equal(t, 1, evs[0].RetryCount, "the completed event attributes the interrupted attempt")
	decisions := parseDecisions(t, evs[0].Policy)
	require.Len(t, decisions, 1, "policy decided exactly once — over the winning body, not per attempt")
	assert.Equal(t, "flag", decisions[0].Verdict, "the mask mutator flags its rewrite")

	hit := n03p2t08Post(t, env, org, q)
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"), "no losses: the recovered answer replays")
	assert.Equal(t, resp.body, hit.body, "the replay is the governed document, byte-stable")
	assert.Equal(t, int64(2), env.upstream.calls.Load(), "the replay never refetches")
	_, _, w2 := env.cacheSvc.WriterStats()
	assert.Equal(t, w1, w2, "the replay writes nothing")
}

// --- axis B: torn cache entries self-heal without duplicates ------------------

// TestN03P2T08_TornCacheEntry_SelfHeals_NoDuplicates walks the three
// half-written-entry shapes an interrupted write can leave behind: a broken
// completion document inside an intact envelope (provenance verifies, the
// document does not decode), a truncated sealed envelope, and a foreign-org
// seal over the key. Every shape degrades to a miss, the refetch rewrites
// the good value over the same key, and the org still owns exactly one pg
// row and one redis key — the store self-heals without duplicates.
func TestN03P2T08_TornCacheEntry_SelfHeals_NoDuplicates(t *testing.T) {
	env := n03p2t08ITSetup(t, n03p2t08Step{body: n03p2t08Completion(n03p2t08Answer)})
	org := n03p2t08NewOrg(t, env, "selfheal")
	q := n03p2t06Chat("n03t08 torn entry question")
	norm, err := cache.NormalizeMessagesJSON(json.RawMessage(q))
	require.NoError(t, err, "normalize prompt")
	hash := cache.ComputePromptHash(norm)
	store := cache.NewRedisStore(env.rdb, 24*time.Hour)
	ctx := context.Background()

	warm := n03p2t08Post(t, env, org, q)
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	hit := n03p2t08Post(t, env, org, q)
	require.Equal(t, "EXACT", hit.header.Get("X-Cache"), "the warm entry replays before corruption")
	goodRaw, err := store.Get(ctx, org.id, n03p2t06Model, hash)
	require.NoError(t, err, "read the sealed value the production writer stored")
	require.NotEmpty(t, goodRaw)

	cases := []struct {
		name    string
		corrupt func(t *testing.T, raw []byte) []byte
	}{
		{"envelope-intact-broken-document", func(t *testing.T, raw []byte) []byte {
			// Byte-level type-mismatch inside the data document: the
			// envelope stays valid JSON and provenance still verifies, but
			// the completion document no longer decodes (choices is a
			// string, not an array) — the half-written-body shape an
			// interrupted write leaves behind.
			broken := strings.Replace(string(raw), `"choices":[`,
				`"choices":"n03t08-torn","stale":[`, 1)
			require.NotEqual(t, string(raw), broken, "corruption must change the stored bytes")
			var env n03p2t08Envelope
			require.NoError(t, json.Unmarshal([]byte(broken), &env), "the torn value must remain a parseable envelope")
			require.NotEmpty(t, env.Prov, "provenance must survive the corruption")
			return []byte(broken)
		}},
		{"truncated-envelope", func(t *testing.T, raw []byte) []byte {
			return raw[:len(raw)/2]
		}},
		{"foreign-org-seal", func(t *testing.T, _ []byte) []byte {
			sealed, err := cache.SealEntry([]byte(n03p2t08Completion("foreign body must never serve")),
				cache.RouteIdentity{OrgID: "n03p2t08-foreign-org", Model: n03p2t06Model}.Resolved())
			require.NoError(t, err, "seal the foreign entry")
			return sealed
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			callsBefore := env.upstream.calls.Load()
			require.NoError(t, store.Put(ctx, org.id, n03p2t06Model, hash, tc.corrupt(t, goodRaw)),
				"plant the torn value at the exact key")

			resp := n03p2t08Post(t, env, org, q)
			require.Equal(t, http.StatusOK, resp.status, resp.body)
			assert.Contains(t, resp.body, n03p2t08Answer, "the client gets the good document, never torn bytes")
			assert.Empty(t, resp.header.Get("X-Cache"), "a torn entry must degrade to a miss")
			require.Equal(t, callsBefore+1, env.upstream.calls.Load(), "the torn entry forced a real refetch")

			healed, err := store.Get(ctx, org.id, n03p2t06Model, hash)
			require.NoError(t, err, "read the value after the refetch")
			prov, data, ok := cache.OpenEntry(healed)
			require.True(t, ok, "the refetch rewrote a verifiable entry over the torn value")
			assert.Equal(t, org.id, prov.OrgID, "the healed entry belongs to this org")
			assert.Contains(t, string(data), n03p2t08Answer, "the healed entry carries the good document")

			replay := n03p2t08Post(t, env, org, q)
			assert.Equal(t, "EXACT", replay.header.Get("X-Cache"), "the healed entry replays")
		})
	}

	// No duplicates: three refetches rewrote the same key — one pg row
	// (upsert), one redis key, and the surviving value is verifiable.
	n03p2t08WaitWrites(t, env, 4) // warm + three rewrites
	assert.Equal(t, 1, n03p2t08PgRows(t, env, org.id), "rewrites upsert, never duplicate")
	assert.Equal(t, 1, n03p2t08RedisKeys(t, env, org.id), "one key per prompt")
	final, err := store.Get(ctx, org.id, n03p2t06Model, hash)
	require.NoError(t, err)
	_, data, ok := cache.OpenEntry(final)
	require.True(t, ok)
	assert.Contains(t, string(data), n03p2t08Answer)
}

// --- axis C: tighten landing between retry attempts ---------------------------

// TestN03P2T08_TightenMidRetry_NoWarmBypass_NoBypassWrite lands a REAL
// control-plane tighten (attach + enable + version bump) synchronously
// between attempt 1 (503) and the retry of an in-flight request. The
// in-flight prompt is unique to the request, so its lookup deterministically
// misses and the handshake fires on its first upstream call; the tighten
// provably lands between the upstream attempts, not around the cache
// lookup. Contract: the in-flight request completes under its request-
// scoped pre-upstream snapshot (the bounded one-request window pinned by
// the T01 boundary), the value it rewrites is sealed under that stale
// snapshot and never serves after the tighten, the previously-warm prompt
// stops serving too, and the next request for either prompt is denied LIVE
// with the terminal content_policy_violation envelope.
func TestN03P2T08_TightenMidRetry_NoWarmBypass_NoBypassWrite(t *testing.T) {
	marker := "n03t08-midretry-secret-3131"
	env := n03p2t08ITSetup(t,
		n03p2t08Step{body: n03p2t08Completion("answer with " + marker + " inside")},
		n03p2t08Step{status: http.StatusServiceUnavailable},
		n03p2t08Step{body: n03p2t08Completion("answer with " + marker + " inside")},
		n03p2t08Step{body: n03p2t08Completion("answer with " + marker + " inside")},
	)
	org := n03p2t08NewOrg(t, env, "midretry")
	events := captureEvents(t)
	qWarm := n03p2t06Chat("n03t08 mid-retry warm prompt")
	qFlight := n03p2t06Chat("n03t08 mid-retry in-flight prompt")
	_, d0, w0 := env.cacheSvc.WriterStats()

	// Warm one prompt under the no-policy regime and prove the replay.
	warm := n03p2t08Post(t, env, org, qWarm)
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	hit := n03p2t08Post(t, env, org, qWarm)
	require.Equal(t, "EXACT", hit.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// In-flight request for a never-cached prompt: attempt 1 blocks inside
	// the upstream handler until the test lands the real tighten, then
	// answers 503; the retry (attempt 2) succeeds. The handshake makes the
	// ordering deterministic: the bump provably lands between the attempts.
	attempt1 := make(chan struct{})
	proceed := make(chan struct{})
	env.upstream.onCall = func(call int64) {
		if call == 2 {
			close(attempt1)
			<-proceed
		}
	}
	respCh := make(chan struct {
		n03p2t08Response
		err error
	}, 1)
	go func() {
		resp, err := n03p2t08Do(env, org, qFlight)
		respCh <- struct {
			n03p2t08Response
			err error
		}{resp, err}
	}()
	<-attempt1
	func() {
		defer close(proceed) // unblock the handler even if an attach step fails
		n03p2t08AttachDeny(t, env, org, "n03p2t08-tighten-midretry", marker)
	}()
	r := <-respCh
	require.NoError(t, r.err, "the in-flight retried request must complete")
	resp := r.n03p2t08Response
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	assert.Contains(t, resp.body, marker, "the in-flight retry completes with the fresh body")
	assert.Empty(t, resp.header.Get("X-Cache"),
		"the in-flight request was a miss that retried, never a cache hit")
	require.Equal(t, int64(3), env.upstream.calls.Load(), "one blocked attempt + one retry")
	n03p2t08WaitWrites(t, env, w0+2) // warm prompt + the in-flight rewrite

	// Both prompts are denied LIVE after the tighten: the rewritten value is
	// sealed under the stale in-flight snapshot, and the pre-tighten warm
	// entry no longer matches — no bypass-shaped entry serves.
	deniedFlight := n03p2t08Post(t, env, org, qFlight)
	require.Equal(t, http.StatusBadRequest, deniedFlight.status, deniedFlight.body)
	assert.Contains(t, deniedFlight.body, "content_policy_violation")
	assert.NotContains(t, deniedFlight.body, marker)
	deniedWarm := n03p2t08Post(t, env, org, qWarm)
	require.Equal(t, http.StatusBadRequest, deniedWarm.status, deniedWarm.body)
	assert.Contains(t, deniedWarm.body, "content_policy_violation")
	require.Equal(t, int64(5), env.upstream.calls.Load(),
		"both denials are live refetches (the tightened regime makes every prior entry a miss)")

	// Denials are never cached: no third write, and the artifacts stay at
	// one row / one key per prompt (the retry rewrite upserted over the
	// warm row it shares a prompt hash with — none here — and never
	// duplicated).
	_, d1, w1 := env.cacheSvc.WriterStats()
	assert.Equal(t, d0, d1, "nothing dropped")
	assert.Equal(t, w0+2, w1, "the denied refetches wrote nothing")
	assert.Equal(t, 2, n03p2t08PgRows(t, env, org.id))
	assert.Equal(t, 2, n03p2t08RedisKeys(t, env, org.id))

	// Events: three completed (warm fetch, warm replay, in-flight retry) and
	// two failed, each carrying the deny verdict; exactly one request
	// retried.
	evs := r011ITWaitEvents(t, events, 5)
	completed, failed, retryEvents := 0, 0, 0
	for _, ev := range evs {
		switch ev.EventType {
		case "request.completed":
			completed++
		case "request.failed":
			failed++
			assert.Contains(t, ev.Policy, `"verdict":"deny"`, "the denial decision rides the event")
		}
		if ev.RetryCount == 1 {
			retryEvents++
		}
	}
	assert.Equal(t, 3, completed, "warm fetch + warm replay + in-flight retry")
	assert.Equal(t, 2, failed, "exactly the two post-tighten denials")
	assert.Equal(t, 1, retryEvents, "exactly one request retried")
}

// --- axis D: enforcement off spanning a retry ---------------------------------

// TestN03P2T08_EnforcementOffDuringRetry_NoCacheOps runs a 503→200 retry
// while enforcement is off (the nil runtime an off-mode deployment boots
// with). Contract: no cache reads and no writes during the retry — proven
// by the cache_enforcement_off_skipped_total counter moving by EXACTLY +2
// (one skipped lookup, one skipped admission; the retry itself is
// transport-level and adds no cache operations) and flat writer stats — and
// no stale or partial artifact survives the window: after defense is
// restored the same prompt refetches, caches once, and replays exact.
func TestN03P2T08_EnforcementOffDuringRetry_NoCacheOps(t *testing.T) {
	env := n03p2t08ITSetup(t,
		n03p2t08Step{status: http.StatusServiceUnavailable},
		n03p2t08Step{body: n03p2t08Completion("n03t08 off-window answer")},
	)
	org := n03p2t08NewOrg(t, env, "offretry")
	events := captureEvents(t)
	q := n03p2t06Chat("n03t08 off-window retry question")
	q0, d0, w0 := env.cacheSvc.WriterStats()
	before := testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal)

	// Production off-shape: the nil runtime an off-mode deployment boots with.
	env.gw.policyRuntime = nil
	resp := n03p2t08Post(t, env, org, q)
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	assert.Contains(t, resp.body, "n03t08 off-window answer")
	require.Equal(t, int64(2), env.upstream.calls.Load(), "the retry still happens — enforcement is orthogonal")
	assert.InDelta(t, before+2, testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal), 0,
		"exactly one skipped lookup + one skipped admission; the retry adds no cache operations")
	q1, d1, w1 := env.cacheSvc.WriterStats()
	assert.Equal(t, q0, q1, "nothing queued while enforcement is off")
	assert.Equal(t, d0, d1, "nothing dropped")
	assert.Equal(t, w0, w1, "nothing persisted while enforcement is off")
	assert.Equal(t, 0, n03p2t08PgRows(t, env, org.id), "no pgvector rows while off")
	assert.Equal(t, 0, n03p2t08RedisKeys(t, env, org.id), "no redis keys while off")

	// Defense restored: the same prompt refetches (nothing was lost into a
	// half state), caches once, and replays exact.
	env.gw.policyRuntime = env.enforceRT
	fresh := n03p2t08Post(t, env, org, q)
	require.Equal(t, http.StatusOK, fresh.status, fresh.body)
	require.Equal(t, int64(3), env.upstream.calls.Load())
	n03p2t08WaitWrites(t, env, w1+1)
	replay := n03p2t08Post(t, env, org, q)
	require.Equal(t, http.StatusOK, replay.status, replay.body)
	assert.Equal(t, "EXACT", replay.header.Get("X-Cache"), "the recovered answer replays after the off window")
	assert.Equal(t, int64(3), env.upstream.calls.Load())

	evs := r011ITWaitEvents(t, events, 3)
	for _, ev := range evs {
		assert.Equal(t, "request.completed", ev.EventType, "no losses: every request in the window completes")
	}
}
