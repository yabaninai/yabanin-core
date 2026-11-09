package cache

// Configuration-consumer compatibility corpus for the policy-regime seam
// (N03-P02-T09): the cache must behave correctly for every supported
// consumer under BOTH the old configuration (binding disarmed — a stand
// without a policy runtime, plain RT-05 identities) and the new one
// (binding armed — regime-bound identities), and the two configurations
// must never replay each other's entries.
//
// Pinned here:
//   - the upgrade path: a warm cache built while disarmed stops serving on
//     every layer once the binding is armed — the legacy seal is rejected on
//     provenance, the layers are still consulted, and a governed refill
//     restores serving (acceptance: warm cache must not hand out the
//     pre-governance answer);
//   - the rollback path: disarming must not serve armed entries, must keep
//     them intact in place, must keep serving plain entries to old
//     consumers, and re-arming must restore service with no rewrite;
//   - the legacy Lookup wrapper surface: served under the old configuration,
//     governed under the new one, and explicitly refused (a clean miss, not
//     an error) for unsupported shapes while armed.
//
// The negative scenarios live inside each path: a legacy warm entry, an
// armed warm entry under rollback, and an org-less lookup must never bypass
// the configuration actually in force.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpgradeableSemanticService mirrors newRegimeSemanticService but starts
// with the binding DISARMED (the old configuration): the test walks the
// upgrade to the armed state itself. Real Redis and pgvector backends, the
// deterministic varyingEmbedder, semantic serving enabled for every org.
func newUpgradeableSemanticService(t *testing.T, tr *pgAnnTracer) (*CacheService, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	ctx := context.Background()
	rdb := redisContainer(t)
	pool := newSemanticPGPool(t, tr)
	cs := NewCacheService(ctx, pool, rdb, varyingEmbedder{}, slog.New(slog.DiscardHandler), false)
	cs.SetOrgPolicyLoader(func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	})
	t.Cleanup(func() { cs.writer.StopWithTimeout(5 * time.Second) })
	return cs, pool, rdb
}

// TestService_ConfigUpgrade_LegacyWarmCache_NeverServesArmed pins the
// upgrade compatibility path on live backends: entries warmed while the
// binding was disarmed (plain RT-05 seal) must stop serving on BOTH layers
// once the binding is armed — the armed lookup composes the regime identity,
// the legacy seal no longer matches, and the pre-governance answer must not
// replay. The layers stay consulted (probe + ANN) and the legacy entry is
// ignored in place, never deleted; a governed refill re-seals and restores
// serving on both layers.
func TestService_ConfigUpgrade_LegacyWarmCache_NeverServesArmed(t *testing.T) {
	tr := &pgAnnTracer{}
	cs, pool, rdb := newUpgradeableSemanticService(t, tr)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	ctx := context.Background()

	org := "c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13" // cache_entries.org_id is uuid
	model := "m-1"
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}
	body := []byte(`{"messages":[{"role":"user","content":"upgrade"}]}`)
	respOld := []byte(`{"id":"legacy","choices":[{"message":{"content":"pre-governance answer"}}]}`)
	respNew := []byte(`{"id":"governed","choices":[{"message":{"content":"governed answer"}}]}`)
	key := MakeKey(org, model, ComputePromptHash(normalizeForCache(body)))

	// Old configuration (disarmed): the legacy warm cache serves — positive
	// control that the entry is genuinely warm before the upgrade.
	require.NoError(t, cs.Write(ctx, ri, body, respOld, 1, 1))
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the old configuration must serve its own warm entry")
	assert.Equal(t, "exact", hit.SourceType)
	assert.JSONEq(t, string(respOld), string(hit.Data))

	// The legacy seal carries the plain identity — no regime tag anywhere.
	legacyRaw := mustGetRaw(t, ctx, rdb, key)
	prov, data, ok := OpenEntry(legacyRaw)
	require.True(t, ok)
	assert.Equal(t, "high", prov.GenParams, "the old configuration seals the plain RT-05 identity")
	assert.JSONEq(t, string(respOld), string(data))

	// Old configuration semantic replay: strip the exact key, the semantic
	// layer serves the same legacy answer.
	waitOrgCacheEntries(t, ctx, pool, org, 1)
	require.NoError(t, rdb.Del(ctx, key).Err())
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the old configuration must serve via the semantic layer too")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.JSONEq(t, string(respOld), string(hit.Data))

	// --- upgrade: arm the binding (the new configuration takes effect) ---
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "regime-now" })

	// The legacy exact entry must not serve: the armed lookup composes
	// "high\x1fpolreg:regime-now" and the plain seal no longer matches. The
	// miss is a decision, not a refusal — the exact layer is probed and no
	// enforcement-off skip is counted.
	legacyWarm := mustGetRaw(t, ctx, rdb, key) // the semantic hit above re-warmed the exact key
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	beforeGet := counter.snapshot()["get"]
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit,
		"after the upgrade the warm legacy entry must not serve the pre-governance answer")
	assert.Greater(t, counter.snapshot()["get"], beforeGet,
		"the armed lookup must still probe the exact layer")
	assert.InDelta(t, skips, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a provenance mismatch under a valid regime is a governed miss, not an enforcement-off refusal")
	assert.Equal(t, legacyWarm, mustGetRaw(t, ctx, rdb, key),
		"the legacy entry must be ignored in place, not deleted or rewritten")

	// The legacy semantic row must not serve either: the layer is consulted
	// (the ANN query runs) and rejects the plain seal against the armed
	// identity.
	require.NoError(t, rdb.Del(ctx, key).Err())
	beforeAnn := tr.count()
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit,
		"after the upgrade the legacy semantic row must not serve the pre-governance answer")
	assert.Greater(t, tr.count(), beforeAnn,
		"the armed lookup must still consult the semantic layer and reject the legacy seal there")

	// Refill under the armed regime re-seals the slot and restores serving.
	require.NoError(t, cs.Write(ctx, ri, body, respNew, 1, 1))
	_, dataPG := waitPGResponse(t, ctx, pool, org, "high\x1fpolreg:regime-now")
	assert.JSONEq(t, string(respNew), string(dataPG),
		"the governed refill must land under the regime-composed seal")
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.Equal(t, "exact", hit.SourceType)
	assert.JSONEq(t, string(respNew), string(hit.Data))

	// Semantic serving is restored for the same slot under the armed regime.
	require.NoError(t, rdb.Del(ctx, key).Err())
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the semantic layer must serve the governed refill")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.JSONEq(t, string(respNew), string(hit.Data),
		"the pre-governance answer must never come back under the armed regime")
}

// TestService_ConfigRollback_Lifecycle pins the rollback compatibility path
// on a live Redis: disarming the binding (the stand falls back to the old
// configuration) must stop serving armed entries, keep them byte-intact in
// place, and keep the old-configuration behavior for plain entries; re-arming
// must restore service from the surviving entry with no rewrite anywhere.
func TestService_ConfigRollback_Lifecycle(t *testing.T) {
	rdb := redisContainer(t)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	cs := newRoutedTestService(rdb)
	ctx := context.Background()

	model := "m-1"
	body := []byte(`{"messages":[{"role":"user","content":"rollback"}]}`)
	respA := []byte(`{"id":"armed","choices":[{"message":{"content":"governed answer"}}]}`)
	respPlain := []byte(`{"id":"plain","choices":[{"message":{"content":"legacy answer"}}]}`)

	// Armed phase: the governed entry warms and serves.
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "regime-a" })
	riGov := RouteIdentity{OrgID: "org-gov", Model: model, GenParams: "high"}
	require.NoError(t, cs.Write(ctx, riGov, body, respA, 1, 1))
	hit, err := cs.LookupWithResult(ctx, riGov, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the armed configuration must serve its own warm entry")
	assert.JSONEq(t, string(respA), string(hit.Data))
	armedRaw := mustGetRaw(t, ctx, rdb, MakeKey("org-gov", model, ComputePromptHash(normalizeForCache(body))))
	prov, _, ok := OpenEntry(armedRaw)
	require.True(t, ok)
	assert.Equal(t, "high\x1fpolreg:regime-a", prov.GenParams)

	// Rollback: the binding is disarmed (the old configuration returns).
	cs.SetPolicyRegimeResolver(nil)

	// The armed entry must not serve the legacy configuration: its seal
	// carries the regime identity the disarmed lookup does not compose. The
	// miss is a plain RT-05 provenance mismatch — the entry stays in place.
	hit, err = cs.LookupWithResult(ctx, riGov, body)
	require.NoError(t, err)
	assert.Nil(t, hit,
		"a rollback must not serve entries sealed under the armed identity")
	assert.Equal(t, armedRaw,
		mustGetRaw(t, ctx, rdb, MakeKey("org-gov", model, ComputePromptHash(normalizeForCache(body)))),
		"the rollback lookup must leave the armed entry intact in place")

	// Old-configuration consumers keep working: a plain entry written while
	// disarmed serves under the plain identity (RT-05 unchanged).
	riPlain := RouteIdentity{OrgID: "org-plain", Model: model}
	require.NoError(t, cs.Write(ctx, riPlain, body, respPlain, 1, 1))
	hit, err = cs.LookupWithResult(ctx, riPlain, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "the old configuration must keep serving its own entries")
	assert.JSONEq(t, string(respPlain), string(hit.Data))

	// Re-arm (the new configuration returns): the surviving governed entry
	// serves again, byte-identical — the rollback window consumed nothing.
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return "regime-a" })
	hit, err = cs.LookupWithResult(ctx, riGov, body)
	require.NoError(t, err)
	require.NotNil(t, hit, "re-arming must restore service from the surviving entry")
	assert.JSONEq(t, string(respA), string(hit.Data))
	assert.Equal(t, armedRaw,
		mustGetRaw(t, ctx, rdb, MakeKey("org-gov", model, ComputePromptHash(normalizeForCache(body)))),
		"the full disarm/re-arm cycle must not rewrite the governed entry")
}

// TestLegacyLookup_ConsumerMatrix walks the legacy Lookup wrapper (the
// compatibility consumer surface that builds RouteIdentity itself) across
// both configurations and the unsupported shapes. Supported consumers get
// plain behavior under the old configuration and governed behavior under the
// new one; unsupported shapes while armed get the explicit refusal as a clean
// miss — no error, no layer touch, one skip counted.
func TestLegacyLookup_ConsumerMatrix(t *testing.T) {
	model := "m-1"

	cases := []struct {
		name      string
		org       string // what the legacy consumer passes as orgID
		armed     bool
		fp        string // resolver answer when armed
		wantHit   bool
		wantCalls int // resolver consultations during the lookup alone
		wantSkips int // enforcement-off skip counter delta
	}{
		{
			name: "old configuration serves the plain entry",
			org:  "org-leg", wantHit: true, wantCalls: 0, wantSkips: 0,
		},
		{
			name: "new configuration serves the governed entry",
			org:  "org-leg", armed: true, fp: "r1", wantHit: true, wantCalls: 1, wantSkips: 0,
		},
		{
			name: "new configuration refuses when enforcement is off",
			org:  "org-leg", armed: true, fp: "", wantHit: false, wantCalls: 1, wantSkips: 1,
		},
		{
			name: "new configuration refuses an org-less consumer without consulting the resolver",
			org:  "", armed: true, fp: "r1", wantHit: false, wantCalls: 0, wantSkips: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rdb := redisContainer(t)
			counter := &redisCmdCounter{counts: map[string]int{}}
			rdb.AddHook(counter)
			cs := newRoutedTestService(rdb)
			ctx := context.Background()
			calls := 0
			if tc.armed {
				cs.SetPolicyRegimeResolver(func(context.Context, string) string {
					calls++
					return tc.fp
				})
			}

			body := []byte(`{"messages":[{"role":"user","content":"legacy-` + tc.name + `"}]}`)
			resp := []byte(`{"id":"m","choices":[{"message":{"content":"matrix answer"}}]}`)

			// The legacy consumer writes through the plain RouteIdentity
			// (empty GenParams — the bare tag form when armed) and reads
			// through the Lookup wrapper.
			writeErr := cs.Write(ctx, RouteIdentity{OrgID: tc.org, Model: model}, body, resp, 1, 1)
			require.NoError(t, writeErr)

			beforeGet := counter.snapshot()["get"]
			skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
			callsBefore := calls // the write above already consulted the resolver when armed
			data, err := cs.Lookup(ctx, tc.org, model, body)
			require.NoError(t, err, "a refusal is a clean miss on the legacy surface, never an error")
			afterGet := counter.snapshot()["get"]

			if tc.wantHit {
				require.NotNil(t, data)
				assert.JSONEq(t, string(resp), string(data))
			} else {
				assert.Nil(t, data)
			}
			assert.Equal(t, tc.wantCalls, calls-callsBefore, "resolver consultations for the legacy lookup")
			assert.InDelta(t, skips+float64(tc.wantSkips), testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
				"the skip counter must tick exactly for refused operations")

			// A refused lookup must not have touched the cache at all; the
			// governed and plain lookups must have probed the exact layer.
			if tc.wantHit {
				assert.Positive(t, afterGet-beforeGet)
			} else if tc.armed {
				assert.Zero(t, afterGet-beforeGet,
					"a refused legacy lookup must not read the cache")
			}
		})
	}
}
