package cache

// Independent invariant verification for the policy-regime enforcement seam
// (N03-P02-T10): permissions, resource limits, data integrity and negative
// scenarios, verified against the seam as delivered by T03–T09 rather than
// against any single corpus.
//
// The invariants pinned here close the verification gaps the independent
// review found in the existing coverage:
//
//  1. Resource: the resolver runs EXACTLY once per cache operation — one
//     consultation covers a full multi-layer lookup (exact miss → semantic
//     ANN hit) and one covers a write including its async pgvector landing
//     (the worker re-seals from the job's composed identity fields and never
//     re-resolves). No operation can pay two resolutions or observe two
//     different regimes inside one operation.
//  2. Resource: a refused (enforcement-off) operation pays no embedding
//     cost — the gate runs before the semantic section, so a silenced org
//     never triggers the expensive upstream embed call.
//  3. Negative: regime entries refuse across the full rollback lifecycle in
//     BOTH directions — a tighten applied across a disarm window rejects the
//     earlier regime's bytes, a later rollback to the earlier regime rejects
//     the tightened regime's bytes, and every entry stays byte-intact at its
//     own key so each regime remains recoverable without a rewrite.
//
// The permissions and data invariants verified by review (already pinned
// elsewhere, cited in the delivery record): every serve path re-verifies the
// sealed provenance against the composed identity (exact: OpenEntry+Matches;
// pg exact: same; semantic: same, after an org-scoped SQL ANN query), stale
// regime data is bounded by TTL on Redis and expires_at + the cleaner on pg,
// and the binding is wired exactly once at startup (production never disarms
// at runtime).

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingEmbedder wraps the deterministic varyingEmbedder and counts embed
// calls, so a test can pin the exact embedding cost of an operation.
type countingEmbedder struct {
	mu    sync.Mutex
	calls int
}

func (e *countingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	return varyingEmbedder{}.Embed(ctx, text)
}

func (e *countingEmbedder) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// TestService_RegimeResolver_ConsultedOncePerOperation pins the resource
// invariant on live backends: one resolver consultation per operation, no
// matter how many layers the operation touches. A full lookup path (exact
// miss → semantic ANN hit) resolves once; a write resolves once and its
// async pgvector landing re-seals from the queued identity without a second
// resolution. Governed operations never tick the skip counter.
func TestService_RegimeResolver_ConsultedOncePerOperation(t *testing.T) {
	tr := &pgAnnTracer{}
	cs, pool, rdb := newUpgradeableSemanticService(t, tr)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	ctx := context.Background()

	var mu sync.Mutex
	calls := 0
	cs.SetPolicyRegimeResolver(func(context.Context, string) string {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return "r-once"
	})
	resolutions := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	org := "d0eebc99-9c0b-4ef8-bb6d-6bb9bd380a14" // cache_entries.org_id is uuid
	model := "m-1"
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"once-per-op"}]}`)
	resp := []byte(`{"id":"once","choices":[{"message":{"content":"governed answer"}}]}`)
	key := MakeKey(org, model, ComputePromptHash(normalizeForCache(body)))

	// The write resolves once, and the async worker landing the pgvector row
	// resolves zero more times: the queued job carries the composed identity.
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	require.NoError(t, cs.Write(ctx, ri, body, resp, 1, 1))
	assert.Equal(t, 1, resolutions(), "a write consults the resolver exactly once")
	waitPGResponse(t, ctx, pool, org, "high\x1fpolreg:r-once")
	assert.Equal(t, 1, resolutions(),
		"the async write landing must re-seal from the job fields, not re-resolve")
	assert.InDelta(t, skips, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a governed write is not a refusal")

	// An exact-layer hit resolves once.
	before := resolutions()
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.Equal(t, "exact", hit.SourceType)
	assert.Equal(t, before+1, resolutions(), "an exact-layer hit resolves once")

	// The full multi-layer path (exact miss → semantic ANN hit) resolves
	// once too: the single resolution taken before the exact probe covers
	// every later layer, so one operation can never observe two regimes.
	require.NoError(t, rdb.Del(ctx, key).Err())
	beforeAnn := tr.count()
	before = resolutions()
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the semantic layer must serve the governed entry")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.Greater(t, tr.count(), beforeAnn, "the ANN query must have run")
	assert.Equal(t, before+1, resolutions(),
		"the exact-miss → pg-ANN → semantic-hit path resolves exactly once")
	assert.InDelta(t, skips, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a governed lookup is not a refusal, whatever the layer that served it")
}

// TestService_EnforcementOff_OperationNeverEmbeds pins the resource bound for
// refused operations on a semantic-enabled org: while the armed resolver
// answers the enforcement-off fingerprint, a lookup is refused before the
// semantic section, so the org pays no embedding call, no layer round-trip
// and no write; the governed contrast proves the harness itself does embed
// once the org is governed again.
func TestService_EnforcementOff_OperationNeverEmbeds(t *testing.T) {
	tr := &pgAnnTracer{}
	ctx := context.Background()
	rdb := redisContainer(t)
	pool := newSemanticPGPool(t, tr)
	emb := &countingEmbedder{}
	cs := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	cs.SetOrgPolicyLoader(func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	})
	t.Cleanup(func() { cs.writer.StopWithTimeout(5 * time.Second) })
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)

	fp := "" // enforcement off / unverifiable for every org
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return fp })

	org := "e0eebc99-9c0b-4ef8-bb6d-6bb9bd380a15" // cache_entries.org_id is uuid
	model := "m-1"
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"off-never-embeds"}]}`)
	resp := []byte(`{"id":"off","choices":[{"message":{"content":"must never be stored"}}]}`)

	// Lookup under enforcement off: a clean miss with zero embedding cost,
	// zero cache reads, one skip counted.
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	beforeGet := counter.snapshot()["get"]
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "an enforcement-off lookup must refuse")
	assert.Zero(t, counter.snapshot()["get"]-beforeGet, "the refusal must not read any cache layer")
	assert.Equal(t, 0, emb.count(), "a refused lookup must never pay the embedding call")
	assert.InDelta(t, skips+1, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0)

	// Write under enforcement off: stores nothing anywhere (no exact put, no
	// writer queue job — hence no writer-side embedding either), and the
	// refusal is its own counted skip.
	q0, d0, w0 := cs.WriterStats()
	require.NoError(t, cs.Write(ctx, ri, body, resp, 1, 1))
	assert.Equal(t, 0, emb.count(), "a refused write must never reach the embedder")
	assert.InDelta(t, skips+2, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"the refused write counts as its own skip")
	q1, d1, w1 := cs.WriterStats()
	assert.Equal(t, q0, q1, "the refused write must not queue a pgvector job")
	assert.Equal(t, d0, d1)
	assert.Equal(t, w0, w1)
	require.Error(t, rdb.Get(ctx, MakeKey(org, model, ComputePromptHash(normalizeForCache(body)))).Err(),
		"the refused write must not store an exact entry")

	// Governed contrast: the same org, same prompt, same harness — the
	// resolver answers a valid fingerprint and the lookup pays exactly one
	// embedding call on its way to the (empty) semantic layer.
	fp = "r-embed"
	beforeGet = counter.snapshot()["get"]
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "no warm entry exists for the org yet")
	assert.Positive(t, counter.snapshot()["get"]-beforeGet, "the governed lookup probes the exact layer")
	assert.Equal(t, 1, emb.count(), "the governed semantic lookup embeds exactly once")
	assert.InDelta(t, skips+2, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a governed miss is not a refusal — no additional skip")
}

// TestService_RegimeTighten_AcrossRollbackWindow pins the negative scenario
// for a policy tighten applied across a disarm window: an entry sealed under
// the earlier regime never serves after the tightened regime is armed — in
// either direction. Both entries stay byte-intact at their own keys through
// the whole lifecycle, so each regime remains exactly recoverable without a
// rewrite, and every cross-regime refusal is a governed miss (no skip
// counted), while the disarmed window behaves as plain RT-05.
func TestService_RegimeTighten_AcrossRollbackWindow(t *testing.T) {
	rdb := redisContainer(t)
	cs := newRoutedTestService(rdb)
	ctx := context.Background()

	org, model := "org-window", "m-1"
	bodyA := []byte(`{"messages":[{"role":"user","content":"window-a"}]}`)
	bodyB := []byte(`{"messages":[{"role":"user","content":"window-b"}]}`)
	respA := []byte(`{"id":"a","choices":[{"message":{"content":"regime-a answer"}}]}`)
	respB := []byte(`{"id":"b","choices":[{"message":{"content":"regime-b answer"}}]}`)
	keyA := MakeKey(org, model, ComputePromptHash(normalizeForCache(bodyA)))
	keyB := MakeKey(org, model, ComputePromptHash(normalizeForCache(bodyB)))
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}

	setRegime := func(fp string) {
		if fp == "" {
			cs.SetPolicyRegimeResolver(nil) // the disarm window: plain RT-05
			return
		}
		answer := fp
		cs.SetPolicyRegimeResolver(func(context.Context, string) string { return answer })
	}

	// Regime A armed: entry A warms and serves under its regime seal.
	setRegime("reg-a")
	require.NoError(t, cs.Write(ctx, ri, bodyA, respA, 1, 1))
	hit, err := cs.LookupWithResult(ctx, ri, bodyA)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respA), string(hit.Data))
	rawA := mustGetRaw(t, ctx, rdb, keyA)
	provA, _, ok := OpenEntry(rawA)
	require.True(t, ok)
	assert.Equal(t, "high\x1fpolreg:reg-a", provA.GenParams)

	// Disarm window: plain RT-05 — entry A's regime seal no longer matches
	// the plain identity, so it misses; nothing is refused (no resolver).
	setRegime("")
	hit, err = cs.LookupWithResult(ctx, ri, bodyA)
	require.NoError(t, err)
	assert.Nil(t, hit, "the disarmed window must not serve a regime-sealed entry")
	assert.Equal(t, rawA, mustGetRaw(t, ctx, rdb, keyA), "the disarm window leaves entry A intact")

	// Tighten across the window (regime B armed): entry A must not serve the
	// tightened org, and must stay intact for a possible rollback.
	setRegime("reg-b")
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	hit, err = cs.LookupWithResult(ctx, ri, bodyA)
	require.NoError(t, err)
	assert.Nil(t, hit, "the tightened regime must not serve the earlier regime's entry")
	assert.InDelta(t, skips, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a cross-regime miss is a governed miss, not a refusal")
	assert.Equal(t, rawA, mustGetRaw(t, ctx, rdb, keyA), "the tightened lookup leaves entry A intact")

	// Entry B warms under the tightened regime at its own key.
	require.NoError(t, cs.Write(ctx, ri, bodyB, respB, 1, 1))
	hit, err = cs.LookupWithResult(ctx, ri, bodyB)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respB), string(hit.Data))
	rawB := mustGetRaw(t, ctx, rdb, keyB)
	provB, _, ok := OpenEntry(rawB)
	require.True(t, ok)
	assert.Equal(t, "high\x1fpolreg:reg-b", provB.GenParams)
	assert.Equal(t, rawA, mustGetRaw(t, ctx, rdb, keyA),
		"entry B's write must not clobber entry A's slot")

	// Rollback to the earlier regime: entry B (tightened bytes) must not
	// serve the rolled-back org; entry A recovers byte-identical.
	setRegime("reg-a")
	hit, err = cs.LookupWithResult(ctx, ri, bodyB)
	require.NoError(t, err)
	assert.Nil(t, hit, "the rolled-back regime must not serve the tightened regime's entry")
	assert.Equal(t, rawB, mustGetRaw(t, ctx, rdb, keyB), "the rollback lookup leaves entry B intact")
	hit, err = cs.LookupWithResult(ctx, ri, bodyA)
	require.NoError(t, err)
	require.NotNil(t, hit, "the earlier regime's entry must recover after the rollback")
	assert.JSONEq(t, string(respA), string(hit.Data))
	assert.Equal(t, rawA, mustGetRaw(t, ctx, rdb, keyA),
		"the full regime cycle must not rewrite entry A")

	// And the tightened entry is still there for a re-tighten.
	setRegime("reg-b")
	hit, err = cs.LookupWithResult(ctx, ri, bodyB)
	require.NoError(t, err)
	require.NotNil(t, hit, "the tightened regime's entry must recover on re-tighten")
	assert.JSONEq(t, string(respB), string(hit.Data))
}

// TestService_CrossRegimeRows_NeverMix pins the data invariant that stale
// regime rows in pg are inert, never mixed: the semantic ANN query is
// org-scoped in SQL and every served row is re-verified against the composed
// identity, so a row sealed under a foreign regime (or a foreign org) can be
// returned only to be rejected — never served, never mutated.
func TestService_CrossRegimeRows_NeverMix(t *testing.T) {
	tr := &pgAnnTracer{}
	cs, pool, _ := newUpgradeableSemanticService(t, tr)
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "reg-mix" })
	ctx := context.Background()

	orgA := "f0eebc99-9c0b-4ef8-bb6d-6bb9bd380a16" // cache_entries.org_id is uuid
	orgB := "f0eebc99-9c0b-4ef8-bb6d-6bb9bd380a17"
	model := "m-1"
	// The SAME prompt text for both orgs: org B's semantic query is a
	// perfect-ANN match for org A's row — only the org scoping and the seal
	// can keep the rows apart.
	body := []byte(`{"messages":[{"role":"user","content":"same-prompt-two-orgs"}]}`)
	respA := []byte(`{"id":"mix-a","choices":[{"message":{"content":"org-a answer"}}]}`)
	respB := []byte(`{"id":"mix-b","choices":[{"message":{"content":"org-b answer"}}]}`)
	riA := RouteIdentity{OrgID: orgA, Model: model, GenParams: "high"}
	riB := RouteIdentity{OrgID: orgB, Model: model, GenParams: "high"}

	require.NoError(t, cs.Write(ctx, riA, body, respA, 1, 1))
	waitOrgCacheEntries(t, ctx, pool, orgA, 1)

	// Strip org B's exact slot (it has none) — the semantic layer must not
	// hand org A's row to org B: miss, not a foreign replay.
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	beforeAnn := tr.count()
	hit, err := cs.LookupWithResult(ctx, riB, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "org B must not be served org A's semantic row for the same prompt")
	assert.Greater(t, tr.count(), beforeAnn, "the ANN query ran (org-scoped) and returned nothing servable")
	assert.InDelta(t, skips, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a governed cross-org miss is not a refusal")

	// Org B's own write lands under the same regime seal and serves — the
	// rows coexist without mixing.
	require.NoError(t, cs.Write(ctx, riB, body, respB, 1, 1))
	_, dataB := waitPGResponse(t, ctx, pool, orgB, "high\x1fpolreg:reg-mix")
	assert.JSONEq(t, string(respB), string(dataB))
	hit, err = cs.LookupWithResult(ctx, riB, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respB), string(hit.Data))
}
