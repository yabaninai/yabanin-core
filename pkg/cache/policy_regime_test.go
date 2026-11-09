package cache

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// N03-P02-T03: the tenant policy regime rides in the route identity's
// generation parameters slot. A regime change must degrade warm entries to
// misses (never serve), refills must land under the new regime, the binding
// must be org-scoped, and disarming must keep the plain RT-05 identity.
// N03-P02-T04: an armed resolver answering "" (enforcement off or
// unverifiable for the org) must gate the whole cache operation — no lookup
// at all, no write at all.

func TestComposeRegimeGenParams(t *testing.T) {
	assert.Empty(t, composeRegimeGenParams("", ""))
	assert.Equal(t, "high", composeRegimeGenParams("high", ""))
	assert.Equal(t, "polreg:r1", composeRegimeGenParams("", "r1"))
	assert.Equal(t, "high\x1fpolreg:r1", composeRegimeGenParams("high", "r1"))
}

func TestService_RegimeIdentity_DisarmedIsIdentity(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb) // no resolver armed

	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	assert.Equal(t, ri, cs.regimeIdentity(context.Background(), ri),
		"a nil resolver must leave the plain RT-05 identity unchanged")

	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "" })
	assert.Equal(t, ri, cs.regimeIdentity(context.Background(), ri),
		"an empty fingerprint must leave the identity unchanged")

	noOrg := RouteIdentity{Model: "m-1", GenParams: "high"}
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "r1" })
	assert.Equal(t, noOrg, cs.regimeIdentity(context.Background(), noOrg),
		"an org-less identity is refused while armed, so its identity comes back unchanged (uncomposed)")
}

func TestService_PolicyRegimeChange_IsMissThenRefill(t *testing.T) {
	rdb := redisContainer(t)
	ctx := context.Background()
	regime := "regime-1"
	cs := newRoutedTestService(rdb)
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return regime })

	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"regime"}]}`)
	respV1 := []byte(`{"id":"v1","choices":[{"message":{"content":"pre-tighten"}}]}`)
	respV2 := []byte(`{"id":"v2","choices":[{"message":{"content":"post-tighten"}}]}`)

	cold, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, cold, "cold lookup must miss")

	require.NoError(t, cs.Write(ctx, ri, body, respV1, 1, 2))
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respV1), string(hit.Data), "same regime serves the warm entry")

	// Tighten: the governing regime changes, the warm entry must not serve.
	regime = "regime-2"
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "a warm entry stored under the earlier policy regime must degrade to a miss")

	// Refill under the new regime serves again.
	require.NoError(t, cs.Write(ctx, ri, body, respV2, 1, 2))
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respV2), string(hit.Data))

	// The binding is symmetric: back under the old regime the refilled entry
	// is not served either — the identity carries exactly one regime.
	regime = "regime-1"
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "the refilled entry belongs to the new regime only")

	regime = "regime-2"
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respV2), string(hit.Data))
}

func TestService_PolicyRegimeChange_IsOrgScoped(t *testing.T) {
	rdb := redisContainer(t)
	ctx := context.Background()
	regimes := map[string]string{"org-1": "regime-1", "org-2": "regime-1"}
	cs := newRoutedTestService(rdb)
	cs.SetPolicyRegimeResolver(func(_ context.Context, org string) string { return regimes[org] })

	body := []byte(`{"messages":[{"role":"user","content":"scoped"}]}`)
	resp1 := []byte(`{"id":"o1","choices":[{"message":{"content":"org1"}}]}`)
	resp2 := []byte(`{"id":"o2","choices":[{"message":{"content":"org2"}}]}`)
	ri1 := RouteIdentity{OrgID: "org-1", Model: "m-1"}
	ri2 := RouteIdentity{OrgID: "org-2", Model: "m-1"}
	require.NoError(t, cs.Write(ctx, ri1, body, resp1, 1, 1))
	require.NoError(t, cs.Write(ctx, ri2, body, resp2, 1, 1))

	// Tighten org-1 only.
	regimes["org-1"] = "regime-2"

	hit1, err := cs.LookupWithResult(ctx, ri1, body)
	require.NoError(t, err)
	assert.Nil(t, hit1, "org-1's tightened regime must miss its warm entry")

	hit2, err := cs.LookupWithResult(ctx, ri2, body)
	require.NoError(t, err)
	require.NotNil(t, hit2, "org-2's unchanged regime must keep serving")
	assert.JSONEq(t, string(resp2), string(hit2.Data),
		"org-1's regime change must not touch org-2's entries")
}

func TestService_PolicyRegime_SealedInProvenance(t *testing.T) {
	rdb := redisContainer(t)
	ctx := context.Background()
	cs := newRoutedTestService(rdb)
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "regime-1" })

	ri := RouteIdentity{OrgID: "org-1", Model: "m-1"} // empty GenParams: bare tag form
	body := []byte(`{"messages":[{"role":"user","content":"seal"}]}`)
	resp := []byte(`{"id":"sealed","choices":[{"message":{"content":"ok"}}]}`)
	require.NoError(t, cs.Write(ctx, ri, body, resp, 1, 1))

	raw, err := rdb.Get(ctx, MakeKey(ri.OrgID, ri.Model,
		ComputePromptHash(normalizeForCache(body)))).Result()
	require.NoError(t, err, "the entry must sit at the regime-composed identity's key")
	prov, unsealed, ok := OpenEntry([]byte(raw))
	require.True(t, ok, "the stored bytes must be a sealed entry")
	assert.Equal(t, "polreg:regime-1", prov.GenParams,
		"the sealed provenance must carry the regime fingerprint")
	assert.JSONEq(t, string(resp), string(unsealed))
}

func TestService_PolicyRegime_DisarmKeepsPlainIdentity(t *testing.T) {
	rdb := redisContainer(t)
	ctx := context.Background()

	armed := newRoutedTestService(rdb)
	armed.SetPolicyRegimeResolver(func(context.Context, string) string { return "regime-1" })
	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"disarm"}]}`)
	require.NoError(t, armed.Write(ctx, ri, body, []byte(`{"id":"armed"}`), 1, 1))

	plain := newRoutedTestService(rdb) // same Redis, no resolver (e.g. a stand without the runtime)
	hit, err := plain.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit,
		"the armed entry is regime-bound; a disarmed service must not serve it")

	require.NoError(t, plain.Write(ctx, ri, body, []byte(`{"id":"plain"}`), 1, 1))
	hit, err = plain.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, `{"id":"plain"}`, string(hit.Data),
		"plain-written entries keep serving under the plain identity (RT-05 unchanged)")
}

// redisCmdCounter counts the Redis commands issued through one client, so a
// test can prove a code path touches the store exactly zero times
// (N03-P02-T04: enforcement-off must not read the cache — the gate is not
// "read and filter").
type redisCmdCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *redisCmdCounter) DialHook(next redis.DialHook) redis.DialHook { return next }

func (c *redisCmdCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.mu.Lock()
		c.counts[strings.ToLower(cmd.Name())]++
		c.mu.Unlock()
		return next(ctx, cmd)
	}
}

func (c *redisCmdCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		c.mu.Lock()
		for _, cmd := range cmds {
			c.counts[strings.ToLower(cmd.Name())]++
		}
		c.mu.Unlock()
		return next(ctx, cmds)
	}
}

func (c *redisCmdCounter) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.counts))
	for k, v := range c.counts {
		out[k] = v
	}
	return out
}

func TestRegimeResolve_GatesAndComposes(t *testing.T) {
	ctx := context.Background()
	cs := &CacheService{}
	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}

	// Disarmed: never gated, identity untouched, resolver not consulted.
	cs.SetPolicyRegimeResolver(nil)
	got, gated := cs.regimeResolve(ctx, ri)
	assert.False(t, gated)
	assert.Equal(t, ri, got)

	// Armed + fingerprint: not gated; GenParams composed once, input copy
	// carried into the returned identity.
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "r1" })
	got, gated = cs.regimeResolve(ctx, ri)
	assert.False(t, gated)
	assert.Equal(t, "high\x1fpolreg:r1", got.GenParams)

	// Armed + empty: the operation is gated; the identity comes back
	// unchanged (the caller must skip it entirely).
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "" })
	got, gated = cs.regimeResolve(ctx, ri)
	assert.True(t, gated, "an empty fingerprint while armed must gate the operation")
	assert.Equal(t, ri, got)

	// Org-less while armed: the operation cannot name a tenant regime to be
	// governed by, so it is refused explicitly — gated like an enforcement-off
	// answer, identity unchanged, resolver not consulted (the resolver
	// contract is per-org; see the service-level corpus for the no-read /
	// no-write pinning).
	calls := 0
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { calls++; return "r1" })
	noOrg := RouteIdentity{Model: "m-1", GenParams: "high"}
	got, gated = cs.regimeResolve(ctx, noOrg)
	assert.True(t, gated, "an org-less identity while armed must refuse the operation")
	assert.Equal(t, noOrg, got)
	assert.Zero(t, calls, "an org-less identity must not consult the resolver")
}

// TestService_EnforcementOff_NoLookupNoWrite pins the T04 acceptance: while
// enforcement is off for the org (armed resolver, empty fingerprint) the
// cache performs no lookup and no write — even when a matching plain entry
// sits at the exact key the ungated path would read. Toggling off→on→off
// leaves no bypass window on either side.
func TestService_EnforcementOff_NoLookupNoWrite(t *testing.T) {
	rdb := redisContainer(t)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	cs := newRoutedTestService(rdb)
	ctx := context.Background()

	org, model := "org-off", "m-1"
	body := []byte(`{"messages":[{"role":"user","content":"off-gate"}]}`)
	resp := []byte(`{"id":"poison","choices":[{"message":{"content":"forbidden?"}}]}`)
	hash := ComputePromptHash(normalizeForCache(body))

	// The poison entry: a plain (untagged) sealed entry at exactly the key
	// the ungated lookup would read — what a write performed while
	// enforcement was off would leave behind.
	plainRI := RouteIdentity{OrgID: org, Model: model}.Resolved()
	sealed, err := SealEntry(resp, plainRI)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, MakeKey(org, model, hash), sealed, time.Hour).Err())

	var mu sync.Mutex
	fingerprint := "" // start enforcement-off
	cs.SetPolicyRegimeResolver(func(_ context.Context, _ string) string {
		mu.Lock()
		defer mu.Unlock()
		return fingerprint
	})
	setFingerprint := func(fp string) {
		mu.Lock()
		fingerprint = fp
		mu.Unlock()
	}

	// Off: the plain entry sits at the exact key, but the lookup must not
	// even read it — enforcement-off is preserved without reads.
	before := counter.snapshot()
	hit, err := cs.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "enforcement-off must not serve cached content")
	after := counter.snapshot()
	assert.Zero(t, after["get"]-before["get"],
		"enforcement-off must not read the cache (no read-and-filter)")

	// Off: a write must not reach any layer or the writer queue.
	q0, d0, w0 := cs.WriterStats()
	before = counter.snapshot()
	require.NoError(t, cs.Write(ctx, RouteIdentity{OrgID: org, Model: model}, body, resp, 1, 1))
	after = counter.snapshot()
	assert.Zero(t, after["set"]-before["set"], "enforcement-off must not write to the cache")
	q1, d1, w1 := cs.WriterStats()
	assert.Equal(t, q0, q1, "the gated write must not queue a pgvector job")
	assert.Equal(t, d0, d1, "the gated write must not touch the writer queue")
	assert.Equal(t, w0, w1)

	// On: the same lookup still misses — the plain entry does not match the
	// regime-bound identity (T03) — but now the cache layers ARE consulted.
	// Same observable miss, real reads: the off-gate is the difference.
	setFingerprint("regime-1")
	before = counter.snapshot()
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "the plain entry must not serve under the regime-bound identity")
	after = counter.snapshot()
	assert.Positive(t, after["get"]-before["get"],
		"with enforcement on the cache is consulted (same miss, real read)")

	// A governed refill lands under the regime-bound identity and serves.
	governed := []byte(`{"id":"governed","choices":[{"message":{"content":"ok"}}]}`)
	require.NoError(t, cs.Write(ctx, RouteIdentity{OrgID: org, Model: model}, body, governed, 1, 1))
	_, dropped, _ := cs.WriterStats()
	assert.Positive(t, dropped, "the on-state write must reach the writer queue (contrast with the gated one)")
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: model}, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(governed), string(hit.Data))

	// Off again: the warm governed entry is not served and nothing is read;
	// a write attempt must not overwrite it. off→on→off leaves no window.
	setFingerprint("")
	before = counter.snapshot()
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "flipping enforcement off must silence lookups even with a warm entry")
	after = counter.snapshot()
	assert.Zero(t, after["get"]-before["get"])

	require.NoError(t, cs.Write(ctx, RouteIdentity{OrgID: org, Model: model}, body, resp, 1, 1))
	setFingerprint("regime-1")
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: model}, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(governed), string(hit.Data),
		"a write attempted while off must not overwrite the governed entry")
}

// TestService_EnforcementOff_DisarmedStaysPlainRT05 guards the new gate
// against over-firing: with NO resolver armed (a stand without a policy
// runtime) the plain RT-05 behavior is intentionally unchanged.
func TestService_EnforcementOff_DisarmedStaysPlainRT05(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb) // nil resolver
	ctx := context.Background()

	ri := RouteIdentity{OrgID: "org-plain", Model: "m-1"}
	body := []byte(`{"messages":[{"role":"user","content":"disarmed"}]}`)
	resp := []byte(`{"id":"plain","choices":[{"message":{"content":"ok"}}]}`)
	require.NoError(t, cs.Write(ctx, ri, body, resp, 1, 1))

	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "a disarmed binding must keep the plain RT-05 behavior")
	assert.JSONEq(t, string(resp), string(hit.Data))
}

// --- N03-P02-T05: warm cache after policy tightening -------------------------
//
// The acceptance is wire-level: an entry warmed (written AND served) under
// policy regime R_old must stop serving on EVERY layer once the regime
// tightens to R_new — the exact layer rejects on the sealed provenance, the
// semantic layer is still consulted (its ANN query runs) but rejects the
// same way — and a write raced by the tighten must land under the stale
// seal, staying unmatchable. Refills under R_new restore serving.

// pgAnnTracer counts semantic ANN SELECT statements that reach Postgres:
// wire-level evidence the pgvector layer was consulted (and rejected), not
// skipped.
type pgAnnTracer struct {
	mu  sync.Mutex
	ann int
}

func (t *pgAnnTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM cache_entries") && strings.Contains(data.SQL, "cosine_distance") {
		t.mu.Lock()
		t.ann++
		t.mu.Unlock()
	}
	return ctx
}

func (t *pgAnnTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (t *pgAnnTracer) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ann
}

// varyingEmbedder is a deterministic input-varying embedder without space
// versioning (like the production fake): distinct inputs land in mutually
// far vectors, so the nearest-1 ANN candidate is deterministic per prompt,
// and identical inputs reproduce the exact same vector (similarity 1.0).
type varyingEmbedder struct{}

func (varyingEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	sum := sha256.Sum256([]byte(text))
	v := make([]float32, 384)
	for i := range v {
		v[i] = float32(sum[i%len(sum)])/255.0 + 0.01
	}
	return v, nil
}

// newRegimeSemanticService builds a full cache service over real Redis and
// pgvector backends for the tighten tests: privacy enforced and semantic
// serving enabled for every org, a deterministic input-varying embedder, and
// a mutable regime fingerprint. The returned setter tightens/loosens the
// regime mid-test. The async writer is drained and stopped at cleanup,
// before the pool closes.
func newRegimeSemanticService(t *testing.T, tr *pgAnnTracer) (*CacheService, *pgxpool.Pool, *redis.Client, func(string)) {
	t.Helper()
	ctx := context.Background()
	rdb := redisContainer(t)
	pool := newSemanticPGPool(t, tr)
	cs := NewCacheService(ctx, pool, rdb, varyingEmbedder{}, slog.New(slog.DiscardHandler), false)
	cs.SetOrgPolicyLoader(func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	})
	var mu sync.Mutex
	fingerprint := "regime-warm"
	cs.SetPolicyRegimeResolver(func(_ context.Context, _ string) string {
		mu.Lock()
		defer mu.Unlock()
		return fingerprint
	})
	t.Cleanup(func() { cs.writer.StopWithTimeout(5 * time.Second) })
	return cs, pool, rdb, func(fp string) {
		mu.Lock()
		fingerprint = fp
		mu.Unlock()
	}
}

func mustGetRaw(t *testing.T, ctx context.Context, rdb *redis.Client, key string) []byte {
	t.Helper()
	raw, err := rdb.Get(ctx, key).Bytes()
	require.NoError(t, err)
	return raw
}

// mustPGResponse returns the sealed envelope stored in the org's newest
// cache_entries row (the async writer's landing zone).
func mustPGResponse(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) []byte {
	t.Helper()
	var raw []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT response FROM cache_entries WHERE org_id::text = $1 ORDER BY created_at DESC LIMIT 1`,
		orgID).Scan(&raw))
	return raw
}

// waitPGResponse polls the org's newest cache_entries row until its sealed
// envelope carries the wanted regime-composed provenance, returning the
// provenance and payload. The writer upserts per exact-slot key, so content
// transitions (refills) do not change the row count — this proves the async
// update landed where count-based waits cannot.
func waitPGResponse(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, wantGenParams string) (Provenance, []byte) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var raw []byte
		err := pool.QueryRow(ctx,
			`SELECT response FROM cache_entries WHERE org_id::text = $1 ORDER BY created_at DESC LIMIT 1`,
			orgID).Scan(&raw)
		if err == nil {
			if prov, data, ok := OpenEntry(raw); ok && prov.GenParams == wantGenParams {
				return prov, data
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			require.NoError(t, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("async writer did not persist the %q-sealed entry for org %s", wantGenParams, orgID)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestService_PolicyRegimeTighten_WarmExactEntry_RejectedOnEveryLayer pins
// the T05 acceptance for a warm EXACT entry: served under R_old, silent
// under R_new on both layers, with the in-flight write raced by the tighten
// landing under the stale seal, and refills restoring service on both layers.
func TestService_PolicyRegimeTighten_WarmExactEntry_RejectedOnEveryLayer(t *testing.T) {
	tr := &pgAnnTracer{}
	cs, pool, rdb, setFP := newRegimeSemanticService(t, tr)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	ctx := context.Background()

	org := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" // cache_entries.org_id is uuid
	model := "m-1"
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"tighten-exact"}]}`)
	respOld := []byte(`{"id":"old","choices":[{"message":{"content":"relaxed-policy answer"}}]}`)
	respNew := []byte(`{"id":"new","choices":[{"message":{"content":"tightened-policy answer"}}]}`)

	// Warm under R_old and prove the warm entry serves (positive control —
	// the entry is warm, not just stored).
	require.NoError(t, cs.Write(ctx, ri, body, respOld, 1, 1))
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the warm entry must serve before the tighten")
	assert.Equal(t, "exact", hit.SourceType)
	assert.JSONEq(t, string(respOld), string(hit.Data))

	// Wire-level: the exact entry sits sealed under the R_old-composed
	// provenance — the binding the tighten must break.
	prov, data, ok := OpenEntry(mustGetRaw(t, ctx, rdb, MakeKey(org, model, ComputePromptHash(normalizeForCache(body)))))
	require.True(t, ok)
	assert.Equal(t, "high\x1fpolreg:regime-warm", prov.GenParams)
	assert.JSONEq(t, string(respOld), string(data))

	// Tighten while the R_old write job is still in flight in the writer
	// queue, then let it land: a write raced by a tighten must persist under
	// the R_old seal (composition happens at Submit) and stay unmatchable.
	setFP("regime-tight")
	waitOrgCacheEntries(t, ctx, pool, org, 1)
	provPG, dataPG, ok := OpenEntry(mustPGResponse(t, ctx, pool, org))
	require.True(t, ok)
	assert.Equal(t, "high\x1fpolreg:regime-warm", provPG.GenParams,
		"the async write raced by the tighten must land under the R_old seal")
	assert.JSONEq(t, string(respOld), string(dataPG))

	// The tightened lookup must not serve the forbidden content on ANY layer,
	// and the rejection must be a decision, not a skip: the exact layer is
	// probed (GET runs) and the semantic layer is consulted (ANN query runs).
	beforeGet := counter.snapshot()["get"]
	beforeAnn := tr.count()
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "the tightened lookup must not serve the R_old content on any layer")
	assert.Greater(t, counter.snapshot()["get"], beforeGet,
		"the exact layer must still be probed under the tightened regime")
	assert.Greater(t, tr.count(), beforeAnn,
		"the semantic layer must still be consulted under the tightened regime and reject on provenance")

	// Refill under R_new restores exact serving for the same slot — and the
	// async refill REPLACES the stale R_old semantic row in place (upsert on
	// the exact-slot key), so the semantic layer heals too, not just Redis.
	require.NoError(t, cs.Write(ctx, ri, body, respNew, 1, 1))
	_, dataPG2 := waitPGResponse(t, ctx, pool, org, "high\x1fpolreg:regime-tight")
	assert.JSONEq(t, string(respNew), string(dataPG2),
		"the refill must replace the stale R_old row with the R_new-sealed response")

	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.Equal(t, "exact", hit.SourceType)
	assert.JSONEq(t, string(respNew), string(hit.Data))

	// Semantic serving is restored for the same slot: with the exact key gone
	// (expiry simulation) the refilled R_new row is the nearest candidate and
	// now matches the tightened identity.
	require.NoError(t, rdb.Del(ctx, MakeKey(org, model, ComputePromptHash(normalizeForCache(body)))).Err())
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the semantic layer must serve the refilled R_new entry")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.JSONEq(t, string(respNew), string(hit.Data))
}

// TestService_PolicyRegimeTighten_WarmSemanticOnlyEntry_Rejected pins the
// T05 acceptance for a SEMANTIC-only warm entry (exact key already expired):
// it serves under R_old and must stop serving once the regime tightens —
// with both layers still consulted (probe + ANN) — while refills under
// R_new restore semantic serving.
func TestService_PolicyRegimeTighten_WarmSemanticOnlyEntry_Rejected(t *testing.T) {
	tr := &pgAnnTracer{}
	cs, pool, rdb, setFP := newRegimeSemanticService(t, tr)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	ctx := context.Background()

	org := "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12"
	model := "m-1"
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"tighten-semantic"}]}`)
	respOld := []byte(`{"id":"old","choices":[{"message":{"content":"relaxed-policy answer"}}]}`)
	respNew := []byte(`{"id":"new","choices":[{"message":{"content":"tightened-policy answer"}}]}`)

	// Warm under R_old, then strip the exact key: a semantic-only warm entry.
	require.NoError(t, cs.Write(ctx, ri, body, respOld, 1, 1))
	waitOrgCacheEntries(t, ctx, pool, org, 1)
	key := MakeKey(org, model, ComputePromptHash(normalizeForCache(body)))
	require.NoError(t, rdb.Del(ctx, key).Err())

	// Positive control: the semantic-only warm entry serves under R_old.
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the semantic-only warm entry must serve before the tighten")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.JSONEq(t, string(respOld), string(hit.Data))
	// The semantic hit re-warms the exact key; strip it again for the tighten.
	require.NoError(t, rdb.Del(ctx, key).Err())

	// Tighten: the forbidden content must not be served, and the miss must
	// again be a decision — exact layer probed (GET), semantic layer
	// consulted (ANN) and rejected on the R_old provenance.
	setFP("regime-tight")
	beforeGet := counter.snapshot()["get"]
	beforeAnn := tr.count()
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "the tightened lookup must not serve the R_old content via the semantic layer")
	assert.Greater(t, counter.snapshot()["get"], beforeGet,
		"the exact layer must still be probed under the tightened regime")
	assert.Greater(t, tr.count(), beforeAnn,
		"the semantic layer must still be consulted under the tightened regime and reject on provenance")

	// Recovery: the refill replaces the stale R_old semantic row in place
	// (upsert on the exact-slot key) and semantic-only serving is restored
	// under R_new once the exact key is gone again.
	require.NoError(t, cs.Write(ctx, ri, body, respNew, 1, 1))
	_, dataPG2 := waitPGResponse(t, ctx, pool, org, "high\x1fpolreg:regime-tight")
	assert.JSONEq(t, string(respNew), string(dataPG2),
		"the refill must replace the stale R_old row with the R_new-sealed response")
	require.NoError(t, rdb.Del(ctx, key).Err())
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the semantic layer must serve the refilled R_new entry")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.JSONEq(t, string(respNew), string(hit.Data))
}

// TestService_CrossOrgExactKeyCollision_NeverServesForeignPayload pins the
// multi-tenant wire guarantees of the exact layer: keys are org-namespaced
// (one org's lookup cannot even name another org's key), and a foreign
// payload physically planted at an org's own key under another org's seal is
// rejected on provenance — ignored in place, never served, never deleted.
func TestService_CrossOrgExactKeyCollision_NeverServesForeignPayload(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb)
	ctx := context.Background()

	orgA, orgB, model := "org-a", "org-b", "m-1"
	body := []byte(`{"messages":[{"role":"user","content":"cross-org"}]}`)
	respA := []byte(`{"id":"a","choices":[{"message":{"content":"org-a answer"}}]}`)
	hash := ComputePromptHash(normalizeForCache(body))
	keyA, keyB := MakeKey(orgA, model, hash), MakeKey(orgB, model, hash)

	// Wire-level: the org id is part of the key material.
	require.NotEqual(t, keyA, keyB, "distinct orgs must not share a key slot")
	assert.Contains(t, keyA, orgA)
	assert.Contains(t, keyB, orgB)

	// orgA writes; orgB must not see the content.
	require.NoError(t, cs.Write(ctx, RouteIdentity{OrgID: orgA, Model: model}, body, respA, 1, 1))
	hit, err := cs.LookupWithResult(ctx, RouteIdentity{OrgID: orgB, Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "another org's entry must not be reachable")

	// Collision: plant orgA's sealed payload AT orgB's key — what a shared
	// backend without namespacing or a corrupted write could produce.
	rawA := mustGetRaw(t, ctx, rdb, keyA)
	provA, dataA, ok := OpenEntry(rawA)
	require.True(t, ok)
	assert.Equal(t, orgA, provA.OrgID, "the planted payload carries orgA's seal")
	assert.JSONEq(t, string(respA), string(dataA))
	require.NoError(t, rdb.Set(ctx, keyB, rawA, time.Hour).Err())

	// orgB's lookup must reject the foreign seal: no serve, no delete.
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: orgB, Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "a foreign-sealed payload at the org's own key must be rejected on provenance")
	planted := mustGetRaw(t, ctx, rdb, keyB)
	assert.Equal(t, rawA, planted, "the foreign payload must be ignored in place, not deleted — refill overwrites it")

	// orgB writes its own answer and is served.
	respB := []byte(`{"id":"b","choices":[{"message":{"content":"org-b answer"}}]}`)
	require.NoError(t, cs.Write(ctx, RouteIdentity{OrgID: orgB, Model: model}, body, respB, 1, 1))
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: orgB, Model: model}, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "orgB must recover with its own content")
	assert.JSONEq(t, string(respB), string(hit.Data))
}

// TestEnforcementOffSkip_CounterDistinguishesGatedOps pins the T05 metrics
// acceptance: every operation silenced at the regime gate increments
// cache_enforcement_off_skipped_total exactly once — before, a gated lookup
// was indistinguishable from an organic miss. Fingerprinted and disarmed
// operations must not touch the counter.
func TestEnforcementOffSkip_CounterDistinguishesGatedOps(t *testing.T) {
	ctx := context.Background()
	// Minimal service: the default org policy (no loader) is enforcement
	// enabled + semantic on, which is exactly what reaches the regime gate.
	cs := &CacheService{policy: NewPolicyCache(time.Minute), log: slog.New(slog.DiscardHandler)}
	ri := RouteIdentity{OrgID: "org-x", Model: "m-1"}
	body := []byte(`{"messages":[{"role":"user","content":"ctr"}]}`)

	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "" })
	before := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	_, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NoError(t, cs.Write(ctx, ri, body, []byte(`{"id":"gated"}`), 1, 1))
	_, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.InDelta(t, before+3, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"each gated operation must increment the enforcement-off skip counter exactly once")

	// Fingerprinted operations are not gated: no counter movement.
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "r1" })
	_, gated := cs.regimeResolve(ctx, ri)
	assert.False(t, gated)
	// Disarmed: never gated, never counted.
	cs.SetPolicyRegimeResolver(nil)
	_, gated = cs.regimeResolve(ctx, ri)
	assert.False(t, gated)
	assert.InDelta(t, before+3, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"non-gated and disarmed operations must not move the counter")
}
