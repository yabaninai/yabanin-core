//go:build integration

package cli

// N03-P02-T09 acceptance: consumer compatibility of the exact semantic
// replay, walked through the REAL consumer entry point — a live chi-served
// gateway behind the production auth middleware, real adminstore, real cache
// service with production-parity regime wiring, and a real async pgvector
// writer. Every supported consumer shape (JSON chat completion, SSE stream)
// must receive exactly its own shape on replay, under the OLD configuration
// (cache stream caching off — the default kill-switch position) and the NEW
// one (on), and unsupported shapes must be explicitly refused rather than
// served as cache garbage.
//
// Axes:
//   A — new configuration (stream caching on): the JSON consumer replays
//       its completion document byte-stable, the SSE consumer replays a
//       valid framed event stream terminated by [DONE], and the two shapes
//       are separate cache entries — a JSON client asking the same prompt
//       text without "stream":true is served a JSON document, never the
//       stream-shaped bytes.
//   B — old configuration (stream caching off): the JSON consumer is
//       unaffected (warm replays continue), the stream consumer is
//       explicitly refused cache service on every attempt (empty X-Cache,
//       fresh live relay), and NO stream entry is written while the
//       kill-switch is off (it gates the write, not only the read).
//       Flipping to the new configuration mid-suite follows the production
//       seam (both gates read cfg per request): nothing stale resurrects —
//       the first stream request relays live and warms the entry, the next
//       replays EXACT.
//   C — residual (accepted, pinned): the gateway's coarse write-side probe
//       (shouldCache, see the unit pins) admits an upstream 200 with an
//       unparseable body, but the cache service's provenance seal fails
//       closed on it (an envelope cannot wrap non-JSON bytes) — nothing is
//       written to any layer, the consumer keeps getting the live relay it
//       already saw, and the first parseable refetch warms the key.
//   D — residual (accepted, pinned): a degenerate choices-less document
//       serves a JSON consumer with live parity (the JSON serve guard only
//       requires the document to decode), while the SSE replay twin
//       explicitly refuses the same document — a stream consumer can never
//       be handed a choices-less document. Planted at a stream prompt's
//       key, it degrades to a miss, the live relay warms a good entry over
//       it, and the next replay is EXACT.
//
// Mock seams (explicit): only the upstream model provider — a scripted
// stand that can answer JSON or SSE per request kind, and one planted
// sealed entry in the real Redis store (axis D). Redis/Postgres are real
// containers; the configuration flip is the cfg field both production
// gates read per request.

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

const n03p2t09Answer = "n03t09 compatible answer 5150"

// n03p2t09Step is one scripted upstream response. status 0 means 200; body
// is a completion document (JSON requests) or an SSE frame block (stream
// requests).
type n03p2t09Step struct {
	status int
	body   string
}

// n03p2t09ScriptedUpstream serves JSON requests from jsonScript and stream
// requests from streamScript (each last step repeats once exhausted) and
// counts total calls so the suite can prove exactly when a request
// refetched. The per-kind split mirrors the consumer contract under test:
// the upstream is allowed to answer differently per shape, and the cache
// must never mix the shapes.
type n03p2t09ScriptedUpstream struct {
	srv          *httptest.Server
	calls        atomic.Int64
	mu           sync.Mutex
	jsonScript   []n03p2t09Step
	streamScript []n03p2t09Step
	jsonCalls    int
	streamCalls  int
}

func newN03P2T09ScriptedUpstream(jsonScript, streamScript []n03p2t09Step) *n03p2t09ScriptedUpstream {
	u := &n03p2t09ScriptedUpstream{jsonScript: jsonScript, streamScript: streamScript}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		isStream := strings.Contains(string(raw), `"stream":true`)

		u.mu.Lock()
		var step n03p2t09Step
		if isStream {
			u.streamCalls++
			n := u.streamCalls
			if n > len(u.streamScript) {
				n = len(u.streamScript)
			}
			step = u.streamScript[n-1]
		} else {
			u.jsonCalls++
			n := u.jsonCalls
			if n > len(u.jsonScript) {
				n = len(u.jsonScript)
			}
			step = u.jsonScript[n-1]
		}
		u.mu.Unlock()

		if isStream {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		if step.status != 0 && step.status != http.StatusOK {
			w.WriteHeader(step.status)
			fmt.Fprintf(w, `{"error":{"message":"upstream unavailable","type":"server_error","code":%d}}`, step.status) //nolint:errcheck // test stand
			return
		}
		fmt.Fprint(w, step.body) //nolint:errcheck // test stand
	}))
	return u
}

func n03p2t09Completion(content string) string {
	return fmt.Sprintf(`{"id":"n03p2t09-up","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, n03p2t06Model, content)
}

// n03p2t09SSE is the provider stand's stream answer: role frame, content
// frame, final frame with finish_reason and usage, DONE — the shape the
// stream cache write accumulates into a replayable document.
func n03p2t09SSE(content string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "data: {\"id\":\"n03p2t09-up\",\"created\":1700000000,\"model\":%q,\"choices\":[{\"index\":0,\"finish_reason\":null,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n", n03p2t06Model)
	fmt.Fprintf(&b, "data: {\"id\":\"n03p2t09-up\",\"created\":1700000000,\"model\":%q,\"choices\":[{\"index\":0,\"finish_reason\":null,\"delta\":{\"content\":%q}}]}\n\n", n03p2t06Model, content)
	fmt.Fprintf(&b, "data: {\"id\":\"n03p2t09-up\",\"created\":1700000000,\"model\":%q,\"choices\":[{\"index\":0,\"finish_reason\":\"stop\",\"delta\":{}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n", n03p2t06Model)
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

// n03p2t09ITEnv owns the stand; it mirrors the T08 env with the stream-cache
// configuration switch and the per-kind scripted upstream.
type n03p2t09ITEnv struct {
	pg        *pgxpool.Pool
	rdb       *redis.Client
	store     *adminstore.Store
	versions  PolicyVersionReader
	cacheSvc  *cache.CacheService
	gw        *gateway
	enforceRT *PolicyRuntime
	log       *slog.Logger
	upstream  *n03p2t09ScriptedUpstream
	server    *httptest.Server
	client    *http.Client
}

func n03p2t09ITSetup(t *testing.T, streamCache bool, jsonScript, streamScript []n03p2t09Step) *n03p2t09ITEnv {
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

	up := newN03P2T09ScriptedUpstream(jsonScript, streamScript)
	runtime, err := NewPolicyRuntime(store, versions, PolicyModeEnforce, nil, logger)
	require.NoError(t, err, "construct enforce policy runtime over the real store")
	gw := &gateway{
		gatewayCore: gatewayCore{cfg: config.Gateway{
			AuthMode:           "header",
			Provider:           up.srv.URL,
			FallbackModel:      n03p2t06Model,
			UnknownModelPolicy: "reject",
			CacheEnabled:       true,
			CacheStreamEnabled: streamCache,
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
	client.Timeout = 30 * time.Second
	return &n03p2t09ITEnv{pg: pg, rdb: rdb, store: store, versions: versions,
		cacheSvc: cacheSvc, gw: gw, enforceRT: runtime, log: logger,
		upstream: up, server: server, client: client}
}

func n03p2t09NewOrg(t *testing.T, env *n03p2t09ITEnv, suffix string) n03p2t06Org {
	t.Helper()
	ctx := context.Background()
	slug := fmt.Sprintf("n03p2t09-%s-%d", suffix, time.Now().UnixNano())
	org, err := env.store.CreateOrganization(ctx, "N03P2T09 synthetic "+suffix, slug)
	require.NoError(t, err, "create synthetic org %s", suffix)
	team, err := env.store.CreateTeam(ctx, org.ID, "N03P2T09 team", slug+"-team", nil)
	require.NoError(t, err, "create synthetic team")
	_, err = env.pg.Exec(ctx, `UPDATE organizations SET cache_enabled = true, cache_mode = 'exact' WHERE id::text = $1`, org.ID)
	require.NoError(t, err, "set org cache mode to exact")
	key, err := auth.GeneratePersonalKey()
	require.NoError(t, err, "generate synthetic API key")
	apiKey, err := env.store.CreateAPIKey(ctx, auth.HashKey(key), "N03P2T09 integration", &org.ID, &team.ID)
	require.NoError(t, err, "create synthetic API key row")
	t.Cleanup(func() {
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM api_keys WHERE id::text = $1`, apiKey.ID)
		_, _ = env.pg.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, org.ID)
	})
	return n03p2t06Org{id: org.ID, slug: slug, plaintext: key}
}

func n03p2t09Post(t *testing.T, env *n03p2t09ITEnv, org n03p2t06Org, body string) n03p2t08Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, env.server.URL+"/v1/chat/completions", strings.NewReader(body))
	require.NoError(t, err, "build request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+org.plaintext)
	resp, err := env.client.Do(req)
	require.NoError(t, err, "POST through the live gateway")
	defer resp.Body.Close() //nolint:errcheck // test stand
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response body")
	return n03p2t08Response{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// n03p2t09WaitWrites polls the writer pool until `want` cumulative writes
// landed (the pgvector insert is asynchronous by design; the Redis exact put
// precedes the worker's accounting, so a landed write guarantees the
// replayable entry is present).
func n03p2t09WaitWrites(t *testing.T, env *n03p2t09ITEnv, want int64) {
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

func n03p2t09PgRows(t *testing.T, env *n03p2t09ITEnv, orgID string) int {
	t.Helper()
	var n int
	err := env.pg.QueryRow(context.Background(),
		`SELECT count(*) FROM cache_entries WHERE org_id::text = $1`, orgID).Scan(&n)
	require.NoError(t, err, "count cache_entries rows")
	return n
}

func n03p2t09RedisKeys(t *testing.T, env *n03p2t09ITEnv, orgID string) int {
	t.Helper()
	keys := 0
	iter := env.rdb.Scan(context.Background(), 0, cache.KeyPatternOrg(orgID), 500).Iterator()
	for iter.Next(context.Background()) {
		keys++
	}
	require.NoError(t, iter.Err(), "scan redis keys")
	return keys
}

// --- axis A: new configuration, both consumer shapes replay exactly -----------

// TestN03P2T09_NewConfig_BothConsumerShapesReplayExact proves that with
// stream caching ON both supported consumers get exactly their own shape
// from the cache: the JSON consumer replays its completion document
// byte-stable, the SSE consumer replays a valid framed stream terminated by
// [DONE], and the shapes never cross — the stream flag is part of the
// prompt shape, so a JSON client asking the same text is served a JSON
// document from its own entry, never the stream-shaped bytes.
func TestN03P2T09_NewConfig_BothConsumerShapesReplayExact(t *testing.T) {
	env := n03p2t09ITSetup(t, true,
		[]n03p2t09Step{{body: n03p2t09Completion(n03p2t09Answer)}},
		[]n03p2t09Step{{body: n03p2t09SSE(n03p2t09Answer)}},
	)
	org := n03p2t09NewOrg(t, env, "shapes")

	// JSON consumer: live miss, then a byte-stable exact replay.
	qJSON := n03p2t06Chat("n03t09 shape question json")
	live := n03p2t09Post(t, env, org, qJSON)
	require.Equal(t, http.StatusOK, live.status, live.body)
	assert.Empty(t, live.header.Get("X-Cache"), "first JSON request is a miss")
	assert.Contains(t, live.body, n03p2t09Answer)
	assert.Equal(t, "application/json", live.header.Get("Content-Type"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	hit := n03p2t09Post(t, env, org, qJSON)
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"), "the warm JSON entry replays")
	assert.Equal(t, live.body, hit.body, "the JSON replay is byte-stable with the live serve")
	assert.Equal(t, "application/json", hit.header.Get("Content-Type"))
	require.Equal(t, int64(1), env.upstream.calls.Load(), "a warm JSON replay must not refetch")

	// SSE consumer: live relay warms the stream-shaped entry, the replay is
	// a valid framed stream in its own shape.
	_, _, writeBase := env.cacheSvc.WriterStats()
	qStream := n03p2t06ChatStream("n03t09 shape question stream")
	sseLive := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sseLive.status, sseLive.body)
	assert.Empty(t, sseLive.header.Get("X-Cache"), "the stream prompt shape is its own cache key — the JSON entry does not serve it")
	assert.Equal(t, "text/event-stream", sseLive.header.Get("Content-Type"))
	assert.Contains(t, sseLive.body, n03p2t09Answer)
	assert.True(t, strings.HasSuffix(sseLive.body, "data: [DONE]\n\n"), "the live relay terminates with the DONE frame")
	require.Equal(t, int64(2), env.upstream.calls.Load())
	n03p2t09WaitWrites(t, env, writeBase+1)

	sseHit := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sseHit.status, sseHit.body)
	assert.Equal(t, "EXACT", sseHit.header.Get("X-Cache"), "the warm stream entry replays to the SSE consumer")
	assert.Equal(t, "text/event-stream", sseHit.header.Get("Content-Type"))
	assert.Contains(t, sseHit.body, n03p2t09Answer)
	assert.True(t, strings.HasSuffix(sseHit.body, "data: [DONE]\n\n"), "the replay terminates with the DONE frame")
	frames := parseSSEFrames(t, []byte(sseHit.body))
	assert.GreaterOrEqual(t, len(frames), 3, "role, content and final frames replay")
	assert.Equal(t, "[DONE]", frames[len(frames)-1])
	require.Equal(t, int64(2), env.upstream.calls.Load(), "a warm SSE replay must not refetch")

	// Shape isolation: the same prompt text WITHOUT the stream flag is a
	// different cache entry — the JSON consumer is served a JSON document,
	// never the stream-shaped bytes.
	crossShape := n03p2t09Post(t, env, org, n03p2t06Chat("n03t09 shape question stream"))
	require.Equal(t, http.StatusOK, crossShape.status, crossShape.body)
	assert.Empty(t, crossShape.header.Get("X-Cache"), "the stream-shaped entry must not serve the JSON consumer")
	assert.Equal(t, "application/json", crossShape.header.Get("Content-Type"))
	assert.Contains(t, crossShape.body, n03p2t09Answer)
	assert.NotContains(t, crossShape.body, "data: ", "no SSE framing may reach a JSON consumer")
	require.Equal(t, int64(3), env.upstream.calls.Load())
}

// --- axis B: old configuration refuses stream consumers, transition is clean --

// TestN03P2T09_OldConfig_StreamRefusedThenCleanTransition walks the old and
// new stream-cache configurations: with the kill-switch OFF (the old default)
// JSON consumers keep their exact replays while stream consumers are
// explicitly refused cache service (fresh live relay, empty X-Cache, stable
// across attempts) and NO stream entry is written — the switch gates the
// write, not only the read. Flipping to ON through the same cfg field the
// production gates read per request leaves nothing stale to resurrect: the
// first stream request relays live and warms the entry, the next replays
// EXACT.
func TestN03P2T09_OldConfig_StreamRefusedThenCleanTransition(t *testing.T) {
	env := n03p2t09ITSetup(t, false,
		[]n03p2t09Step{{body: n03p2t09Completion(n03p2t09Answer)}},
		[]n03p2t09Step{{body: n03p2t09SSE(n03p2t09Answer)}},
	)
	org := n03p2t09NewOrg(t, env, "oldcfg")

	// The supported JSON consumer is unaffected by the old configuration.
	qJSON := n03p2t06Chat("n03t09 old-config question json")
	live := n03p2t09Post(t, env, org, qJSON)
	require.Equal(t, http.StatusOK, live.status, live.body)
	assert.Empty(t, live.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())
	n03p2t09WaitWrites(t, env, 1)
	hit := n03p2t09Post(t, env, org, qJSON)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"), "the JSON consumer keeps exact replays under the old configuration")
	assert.Equal(t, live.body, hit.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// The stream consumer is refused cache service, stably.
	qStream := n03p2t06ChatStream("n03t09 old-config question stream")
	_, _, writesAfterJSON := env.cacheSvc.WriterStats()
	sse1 := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sse1.status, sse1.body)
	assert.Empty(t, sse1.header.Get("X-Cache"), "explicit refusal: no cache service for streams while the kill-switch is off")
	assert.Equal(t, "text/event-stream", sse1.header.Get("Content-Type"), "the refusal is a fresh live relay, not broken bytes")
	assert.Contains(t, sse1.body, n03p2t09Answer)
	assert.True(t, strings.HasSuffix(sse1.body, "data: [DONE]\n\n"))
	require.Equal(t, int64(2), env.upstream.calls.Load())
	sse2 := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sse2.status, sse2.body)
	assert.Empty(t, sse2.header.Get("X-Cache"), "the refusal is stable across attempts")
	require.Equal(t, int64(3), env.upstream.calls.Load(), "no cached stream answer exists to serve")

	// Nothing was written for the streams: the kill-switch gates the WRITE,
	// not only the read — no entry exists that a later flip could serve.
	n03p2t09WaitWrites(t, env, writesAfterJSON) // no delta
	assert.Equal(t, 1, n03p2t09PgRows(t, env, org.id), "only the JSON prompt has a pgvector row")
	assert.Equal(t, 1, n03p2t09RedisKeys(t, env, org.id), "only the JSON prompt has a cache key")

	// Transition to the new configuration through the production seam (the
	// cfg field both gates read per request). No pre-flip stream entry
	// exists, so nothing stale can resurrect: the first request relays live
	// and warms, the next replays EXACT.
	env.gw.cfg.CacheStreamEnabled = true
	sseWarm := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sseWarm.status, sseWarm.body)
	assert.Empty(t, sseWarm.header.Get("X-Cache"), "no stale pre-flip entry serves after the flip — the warm-up is a live relay")
	assert.Equal(t, "text/event-stream", sseWarm.header.Get("Content-Type"))
	require.Equal(t, int64(4), env.upstream.calls.Load())
	n03p2t09WaitWrites(t, env, writesAfterJSON+1)

	sseHit := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sseHit.status, sseHit.body)
	assert.Equal(t, "EXACT", sseHit.header.Get("X-Cache"), "after the flip the stream consumer gets exact replays")
	assert.Equal(t, "text/event-stream", sseHit.header.Get("Content-Type"))
	assert.True(t, strings.HasSuffix(sseHit.body, "data: [DONE]\n\n"))
	require.Equal(t, int64(4), env.upstream.calls.Load())
}

// --- axis C: residual — unparseable upstream entry degrades to a miss --------

// TestN03P2T09_Residual_UnparseableUpstream_NeverCached_ServesFresh pins the
// accepted write-side residual end-to-end: an upstream 200 with an
// unparseable body is admitted by the coarse shouldCache probe, but the
// cache service's provenance seal fails closed on it (an envelope cannot
// wrap non-JSON bytes) — the consumer keeps getting the live relay it
// already saw, nothing is written to any layer, and the first parseable
// refetch warms the key: no cache garbage can ever reach a consumer.
func TestN03P2T09_Residual_UnparseableUpstream_NeverCached_ServesFresh(t *testing.T) {
	garbage := "<html>bad gateway</html>"
	env := n03p2t09ITSetup(t, true,
		[]n03p2t09Step{{body: garbage}, {body: n03p2t09Completion(n03p2t09Answer)}},
		nil,
	)
	org := n03p2t09NewOrg(t, env, "selfheal")
	q := n03p2t06Chat("n03t09 unparseable upstream question")

	bad := n03p2t09Post(t, env, org, q)
	require.Equal(t, http.StatusOK, bad.status, bad.body)
	assert.Equal(t, garbage, bad.body, "the live serve passes the upstream's own body through verbatim")
	assert.Empty(t, bad.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// Residual pinned: the gateway probe admitted the body (shouldCache is
	// true for it), but the RT-05 seal fails closed — no queue job, no
	// persisted write, no cache artifact in any layer.
	queued, dropped, written := env.cacheSvc.WriterStats()
	assert.Equal(t, int64(0), queued, "an unsealable response is never enqueued")
	assert.Equal(t, int64(0), dropped)
	assert.Equal(t, int64(0), written)
	assert.Equal(t, 0, n03p2t09RedisKeys(t, env, org.id), "no cache key for the unparseable body")
	assert.Equal(t, 0, n03p2t09PgRows(t, env, org.id), "no pgvector row for the unparseable body")

	fresh := n03p2t09Post(t, env, org, q)
	require.Equal(t, http.StatusOK, fresh.status, fresh.body)
	assert.Empty(t, fresh.header.Get("X-Cache"), "nothing was cached, so the next consumer gets a fresh fetch")
	assert.Contains(t, fresh.body, n03p2t09Answer, "the consumer gets the parseable answer, never the garbage")
	require.Equal(t, int64(2), env.upstream.calls.Load())
	n03p2t09WaitWrites(t, env, 1)

	healed := n03p2t09Post(t, env, org, q)
	require.Equal(t, http.StatusOK, healed.status, healed.body)
	assert.Equal(t, "EXACT", healed.header.Get("X-Cache"), "the parseable answer replays")
	assert.Equal(t, fresh.body, healed.body, "the replay is byte-stable with the fresh serve")
	require.Equal(t, int64(2), env.upstream.calls.Load())

	assert.Equal(t, 1, n03p2t09PgRows(t, env, org.id), "exactly one pgvector row for the prompt")
	assert.Equal(t, 1, n03p2t09RedisKeys(t, env, org.id), "one key per prompt")
}

// --- axis D: residual — degenerate document: JSON parity, SSE twin refuses ----

// TestN03P2T09_Residual_EmptyChoices_JSONParity_SSETwinRefuses pins the
// accepted serve-guard asymmetry end-to-end. A degenerate choices-less
// document cached from a real upstream 200 serves the JSON consumer with
// live parity (the JSON serve guard only requires the document to decode —
// exactly what the upstream itself served live). The same document planted
// at a STREAM prompt's key is refused by the SSE replay twin: the stream
// consumer degrades to a live relay, the good stream entry is written over
// the planted value, and the next replay is EXACT — a stream consumer can
// never be handed a choices-less document.
func TestN03P2T09_Residual_EmptyChoices_JSONParity_SSETwinRefuses(t *testing.T) {
	env := n03p2t09ITSetup(t, true,
		[]n03p2t09Step{{body: `{}`}, {body: n03p2t09Completion(n03p2t09Answer)}},
		[]n03p2t09Step{{body: n03p2t09SSE(n03p2t09Answer)}},
	)
	org := n03p2t09NewOrg(t, env, "emptychoices")

	// JSON consumer: the degenerate document replays EXACT — live parity.
	qEmpty := n03p2t06Chat("n03t09 empty choices question")
	live := n03p2t09Post(t, env, org, qEmpty)
	require.Equal(t, http.StatusOK, live.status, live.body)
	assert.Equal(t, `{}`, live.body, "the upstream's degenerate body passes through live")
	assert.Empty(t, live.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())
	n03p2t09WaitWrites(t, env, 1)

	hit := n03p2t09Post(t, env, org, qEmpty)
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"),
		"residual pinned: the JSON serve guard accepts the degenerate document")
	assert.Equal(t, `{}`, hit.body, "the JSON replay serves exactly what the upstream served live")
	require.Equal(t, int64(1), env.upstream.calls.Load(), "the degenerate replay does not refetch")

	// Stream consumer: plant the same degenerate document, sealed under this
	// org's identity, at the stream prompt's cache key. The plant verifies,
	// so the refusal below is attributable to the twin's document check.
	qStream := n03p2t06ChatStream("n03t09 empty choices stream question")
	norm, err := cache.NormalizeMessagesJSON(json.RawMessage(qStream))
	require.NoError(t, err, "normalize stream prompt")
	hash := cache.ComputePromptHash(norm)
	store := cache.NewRedisStore(env.rdb, 24*time.Hour)
	sealed, err := cache.SealEntry([]byte(`{"choices":[]}`),
		cache.RouteIdentity{OrgID: org.id, Model: n03p2t06Model}.Resolved())
	require.NoError(t, err, "seal the degenerate document under the org's own identity")
	require.NoError(t, store.Put(context.Background(), org.id, n03p2t06Model, hash, sealed),
		"plant the degenerate document at the stream prompt's key")
	planted, err := store.Get(context.Background(), org.id, n03p2t06Model, hash)
	require.NoError(t, err, "read the planted value back")
	_, _, plantedOK := cache.OpenEntry(planted)
	require.True(t, plantedOK, "the plant must verify so the refusal is attributable to the twin")

	sse := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sse.status, sse.body)
	assert.Empty(t, sse.header.Get("X-Cache"),
		"the SSE twin must refuse the choices-less document — a stream consumer never sees one")
	assert.Equal(t, "text/event-stream", sse.header.Get("Content-Type"), "the refusal is a fresh live relay")
	assert.Contains(t, sse.body, n03p2t09Answer)
	assert.True(t, strings.HasSuffix(sse.body, "data: [DONE]\n\n"))
	require.Equal(t, int64(2), env.upstream.calls.Load(), "the refused entry forced a live stream relay")
	_, _, writeBase := env.cacheSvc.WriterStats()
	n03p2t09WaitWrites(t, env, writeBase+1)

	rewritten, err := store.Get(context.Background(), org.id, n03p2t06Model, hash)
	require.NoError(t, err, "read the value after the live relay")
	_, data, rewrittenOK := cache.OpenEntry(rewritten)
	require.True(t, rewrittenOK, "the live relay rewrote a verifiable entry over the planted value")
	assert.Contains(t, string(data), n03p2t09Answer, "the rewritten entry carries the good document")

	sseHit := n03p2t09Post(t, env, org, qStream)
	require.Equal(t, http.StatusOK, sseHit.status, sseHit.body)
	assert.Equal(t, "EXACT", sseHit.header.Get("X-Cache"), "the good stream entry replays")
	assert.Equal(t, "text/event-stream", sseHit.header.Get("Content-Type"))
	assert.True(t, strings.HasSuffix(sseHit.body, "data: [DONE]\n\n"))
	require.Equal(t, int64(2), env.upstream.calls.Load())
}
