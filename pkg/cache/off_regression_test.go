package cache

// negative proof that the checks DISTINGUISH the broken behavior (cache_mode
// off включил semantic; isolated fixes конфликтуют) from the fixed one.
//
// Unlike the nil-backend unit gate (TestCacheService_OffPolicy_NoLookupNoWrite,
// where pass == "backends untouched"), these fixtures run the full service on
// real backends (disposable pgvector PG + Redis containers, the repo
// testdb/redisContainer harness) with positive controls, so a vacuous check
// cannot pass:
//   - TestRegression_CacheModeOff_NoReadNoWrite_RealRedis resolves the policy
//     from real organizations rows through DBPolicyLoader SQL: a semantic org
//     caches (gate open), an off org neither reads a planted, perfectly
//     matching entry nor writes anything on either backend, and an exact org
//     keeps exact caching (no overcorrection);
//   - TestRegression_CacheModeOff_BrokenVariantsAreDistinguishable pins the
//     discriminating power itself: both broken policy variants — the
//     historical defect (off → enabled+semantic) and the isolated partial fix
//     (off → enabled, semantic gated only) — observably cache (redis key,
//     pgvector row, exact hit served), while the fixed policy never does.
//     If either broken variant stopped being distinguishable, the F6 gate
//     would be blind to exactly the regression it exists to catch.
// The end-to-end stand proofs (flip + fresh view, recovery) remain on the
// integration suite; this file makes the acceptance repeatable in seconds.
// Each phase gets a fresh CacheService on the shared backends so WriterStats
// are attributable to that phase's org (integration-fixture shape).

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOffRegressionBackends starts the shared disposable stand (PG + Redis).
func newOffRegressionBackends(t *testing.T) (*pgxpool.Pool, *redis.Client) {
	t.Helper()
	return testdb.Postgres(t), redisContainer(t)
}

// newOffRegressionService builds a fully wired CacheService on the shared
// backends. pgExactEnabled stays false: the redis exact layer is the read
// path under test.
func newOffRegressionService(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client) *CacheService {
	t.Helper()
	return NewCacheService(ctx, pool, rdb,
		&embeddings.StaticClient{Embedding: makeTestEmbedding(384, 0.1)},
		slog.New(slog.DiscardHandler), false)
}

// plantExactEntry stores a response in the redis exact layer under ri's
// provenance — the same bytes Write would store — simulating entries that
// already exist when an org's mode flips to off.
func plantExactEntry(t *testing.T, ctx context.Context, cs *CacheService, ri RouteIdentity, prompt, response json.RawMessage) {
	t.Helper()
	normalized := normalizeForCache(prompt)
	sealed, err := SealEntry(response, ri)
	require.NoError(t, err)
	require.NoError(t, cs.exact.Put(ctx, ri.OrgID, ri.Model, ComputePromptHash(normalized), sealed))
}

func countOrgRedisKeys(t *testing.T, ctx context.Context, rdb *redis.Client, orgID string) int {
	t.Helper()
	n := 0
	iter := rdb.Scan(ctx, 0, KeyPatternOrg(orgID), 500).Iterator()
	for iter.Next(ctx) {
		n++
	}
	require.NoError(t, iter.Err())
	return n
}

// waitOrgCacheEntries polls until the org has exactly want pgvector rows (the
// async writer persisted its job) — integration-suite deadline convention.
func waitOrgCacheEntries(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var rows int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM cache_entries WHERE org_id::text = $1`, orgID).Scan(&rows))
		if rows == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("async cache writer did not persist: org %s has %d cache_entries rows, want %d", orgID, rows, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func offOrgPGRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) int {
	t.Helper()
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM cache_entries WHERE org_id::text = $1`, orgID).Scan(&rows))
	return rows
}

// TestRegression_CacheModeOff_NoReadNoWrite_RealRedis: the F6 acceptance
// fixture on real backends, with the policy resolved from real organizations
// rows through the DBPolicyLoader SQL path. Semantic and exact orgs are
// positive controls (the gate opens, entries persist and are served), so the
// off-org zero-read/zero-write assertions cannot pass vacuously.
func TestRegression_CacheModeOff_NoReadNoWrite_RealRedis(t *testing.T) {
	ctx := context.Background()
	pool, rdb := newOffRegressionBackends(t)
	loader := NewDBPolicyLoader(pool, slog.New(slog.DiscardHandler)).Wrap()

	prompt := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"r016-04 regression prompt"}]}`)
	response := json.RawMessage(`{"id":"regression-response","choices":[{"message":{"content":"cached"}}]}`)

	// Real organizations rows: the policy flows through the production SQL
	// path, exactly as the gateway stand loads it.
	orgSemantic := seedCacheOrg(t, pool, "cache-regression-semantic", true, "semantic")
	orgOff := seedCacheOrg(t, pool, "cache-regression-off", true, "off")
	orgExact := seedCacheOrg(t, pool, "cache-regression-exact", true, "exact")
	riSemantic := RouteIdentity{OrgID: orgSemantic, Model: "smart"}.Resolved()
	riOff := RouteIdentity{OrgID: orgOff, Model: "smart"}.Resolved()
	riExact := RouteIdentity{OrgID: orgExact, Model: "smart"}.Resolved()

	// Positive control: the semantic-mode org caches through the real path.
	csS := newOffRegressionService(t, ctx, pool, rdb)
	csS.SetOrgPolicyLoader(loader)
	require.NoError(t, csS.Write(ctx, riSemantic, prompt, response, 5, 3))
	require.Equal(t, 1, countOrgRedisKeys(t, ctx, rdb, orgSemantic), "semantic org Write must reach the exact backend")
	waitOrgCacheEntries(t, ctx, pool, orgSemantic, 1)
	hit, err := csS.LookupWithResult(ctx, riSemantic, prompt)
	require.NoError(t, err)
	require.NotNil(t, hit, "semantic-mode org must be served from cache")
	assert.Equal(t, "exact", hit.SourceType)

	// The off org: a perfectly matching entry already exists (as it would
	// from the semantic era), planted at the store level.
	csOff := newOffRegressionService(t, ctx, pool, rdb)
	csOff.SetOrgPolicyLoader(loader)
	plantExactEntry(t, ctx, csOff, riOff, prompt, response)
	offKeys := countOrgRedisKeys(t, ctx, rdb, orgOff)
	require.Equal(t, 1, offKeys, "scenario setup: the off org has one existing entry")

	// No read: the policy gate denies the lookup although the stored
	// provenance matches the route exactly.
	got, err := csOff.LookupWithResult(ctx, riOff, prompt)
	require.NoError(t, err, "cache_mode=off is a miss, not an error")
	assert.Nil(t, got, "cache_mode=off must never serve an existing entry (no read)")

	// No write: nothing queued, nothing persisted, no new artifacts on
	// either backend.
	require.NoError(t, csOff.Write(ctx, riOff, prompt, response, 5, 3),
		"the policy gate returns success without writing")
	queued, dropped, written := csOff.WriterStats()
	assert.Equal(t, int64(0), queued+dropped+written, "off-org Write must not reach the writer pool")
	assert.Equal(t, offKeys, countOrgRedisKeys(t, ctx, rdb, orgOff), "cache_mode=off must not write redis keys")
	assert.Equal(t, 0, offOrgPGRows(t, ctx, pool, orgOff), "cache_mode=off must not write pgvector entries")

	// Positive control: exact-mode caching is not overcorrected away.
	csE := newOffRegressionService(t, ctx, pool, rdb)
	csE.SetOrgPolicyLoader(loader)
	require.NoError(t, csE.Write(ctx, riExact, prompt, response, 5, 3))
	require.Equal(t, 1, countOrgRedisKeys(t, ctx, rdb, orgExact), "exact org Write must reach the exact backend")
	hit, err = csE.LookupWithResult(ctx, riExact, prompt)
	require.NoError(t, err)
	require.NotNil(t, hit, "cache_mode=exact keeps exact caching")
	assert.Equal(t, "exact", hit.SourceType)
}

// TestRegression_CacheModeOff_BrokenVariantsAreDistinguishable: the negative
// proof as a permanent fixture. Both broken policy states must remain
// observably different from the fixed one:
//   - variant A (historical defect, pre-acd33e26): off fell into the default
//     branch → enabled + semantic — the org's prompts were cached;
//   - variant B (isolated partial fix): only the semantic axis gated
//     (enabled, Semantic=false) — lookups degrade but the write path still
//     persists prompts to both backends and the exact layer still serves
//     them, so the isolated fix conflicts with the governance contract.
//
// The regression assertions (no redis key, no pgvector row, no hit) fire on
// both variants; this test proves they are load-bearing by showing the
// broken states DO cache.
func TestRegression_CacheModeOff_BrokenVariantsAreDistinguishable(t *testing.T) {
	ctx := context.Background()
	pool, rdb := newOffRegressionBackends(t)

	prompt := json.RawMessage(`{"model":"gpt-4o","messages":[{"role":"user","content":"r016-04 broken-variant prompt"}]}`)
	response := json.RawMessage(`{"id":"broken-variant-response"}`)

	// Fixed policy: exactly what cachePolicyFor produces for cache_mode=off.
	fixed := OrgPolicy{Mode: PrivacyDisabled, Semantic: false}
	// Variant A: the historical defect — off treated as the semantic default.
	variantA := OrgPolicy{Mode: PrivacyEnabled, Semantic: true, CacheMetrics: true, TTL: 24 * time.Hour}
	// Variant B: the isolated partial fix — semantic gated, write path left open.
	variantB := OrgPolicy{Mode: PrivacyEnabled, Semantic: false, CacheMetrics: true, TTL: 24 * time.Hour}

	variants := []struct {
		name   string
		orgID  string
		policy OrgPolicy
		broken bool
	}{}
	for _, v := range []struct {
		name   string
		policy OrgPolicy
		broken bool
	}{
		{"historical defect (off → semantic default)", variantA, true},
		{"isolated partial fix (only semantic gated)", variantB, true},
		{"fixed policy (fully disabled)", fixed, false},
	} {
		slug := "cache-regression-variant-" + v.name[:9]
		orgID := seedCacheOrg(t, pool, slug, true, "off")
		variants = append(variants, struct {
			name   string
			orgID  string
			policy OrgPolicy
			broken bool
		}{v.name, orgID, v.policy, v.broken})
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			cs := newOffRegressionService(t, ctx, pool, rdb)
			policies := map[string]OrgPolicy{v.orgID: v.policy}
			cs.SetOrgPolicyLoader(func(_ context.Context, orgID string) (*OrgPolicy, error) {
				pol := policies[orgID]
				return &pol, nil
			})

			ri := RouteIdentity{OrgID: v.orgID, Model: "smart"}.Resolved()

			require.NoError(t, cs.Write(ctx, ri, prompt, response, 5, 3))
			keys := countOrgRedisKeys(t, ctx, rdb, v.orgID)

			if v.broken {
				assert.Equal(t, 1, keys, "the broken policy must observably cache (otherwise the F6 gate is vacuous)")
				waitOrgCacheEntries(t, ctx, pool, v.orgID, 1)
				hit, err := cs.LookupWithResult(ctx, ri, prompt)
				require.NoError(t, err)
				require.NotNil(t, hit, "the broken policy must serve entries — the F6 gate must catch it")
				assert.Equal(t, "exact", hit.SourceType)
				return
			}

			assert.Equal(t, 0, keys, "the fixed policy must not write redis keys")
			queued, dropped, written := cs.WriterStats()
			assert.Equal(t, int64(0), queued+dropped+written, "the fixed policy must not enqueue pgvector jobs")
			plantExactEntry(t, ctx, cs, ri, prompt, response)
			got, err := cs.LookupWithResult(ctx, ri, prompt)
			require.NoError(t, err)
			assert.Nil(t, got, "the fixed policy must not serve an existing entry even with a matching stored provenance")
		})
	}
}
