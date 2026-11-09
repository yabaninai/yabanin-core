package cache

// valid cache_mode enum is off | exact | semantic (cache_handlers), and the
// that said NO got semantic caching of its prompts (governance defect).
// Covered here:
//   - unit: the full mapping matrix (off, exact, semantic, "", unknown,
//     disabled flag × modes) — 'off' must disable the cache ENTIRELY
//     (lookup AND write), the other modes must not regress;
//   - service: with the mapped 'off' policy, Lookup is a miss (nil) and
//     Write writes nothing — the policy short-circuit runs before any
//     backend is touched;
//   - live (disposable PG): real organizations rows with cache_mode
//     off/semantic/exact/NULL load through the SQL path as mapped.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachePolicyFor_ModeMatrix(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	t.Run("off disables the cache entirely (F-6)", func(t *testing.T) {
		for _, mode := range []string{"off", "OFF", "Off"} {
			pol := cachePolicyFor(true, mode, log)
			assert.Equal(t, PrivacyDisabled, pol.Mode, "cache_mode=%q: an org that said NO must not cache", mode)
			assert.False(t, pol.Semantic, "cache_mode=%q: no semantic lookups either", mode)
		}
	})

	t.Run("exact enables non-semantic caching", func(t *testing.T) {
		pol := cachePolicyFor(true, "exact", log)
		assert.Equal(t, PrivacyEnabled, pol.Mode)
		assert.False(t, pol.Semantic)
	})

	t.Run("semantic and empty default to semantic caching", func(t *testing.T) {
		for _, mode := range []string{"semantic", "SEMANTIC", ""} {
			pol := cachePolicyFor(true, mode, log)
			assert.Equal(t, PrivacyEnabled, pol.Mode, "mode=%q", mode)
			assert.True(t, pol.Semantic, "mode=%q", mode)
		}
	})

	t.Run("unknown mode keeps the documented semantic default (warn)", func(t *testing.T) {
		pol := cachePolicyFor(true, "hybrid", log)
		assert.Equal(t, PrivacyEnabled, pol.Mode)
		assert.True(t, pol.Semantic)
	})

	t.Run("cache_enabled=false disables regardless of mode", func(t *testing.T) {
		for _, mode := range []string{"off", "exact", "semantic", "", "hybrid"} {
			pol := cachePolicyFor(false, mode, log)
			assert.Equal(t, PrivacyDisabled, pol.Mode, "mode=%q", mode)
		}
	})

	t.Run("defaults carry metrics and the 24h TTL", func(t *testing.T) {
		pol := cachePolicyFor(true, "off", log)
		assert.True(t, pol.CacheMetrics)
		assert.Equal(t, 24*time.Hour, pol.TTL)
	})
}

// TestCacheService_OffPolicy_NoLookupNoWrite: the mapped 'off' policy makes
// the service skip the cache entirely — Lookup never answers a hit and Write
// never writes. The backends are nil here on purpose: any touch would panic,
// so the passing assertions ARE the policy short-circuit.
func TestCacheService_OffPolicy_NoLookupNoWrite(t *testing.T) {
	loader := newDBPolicyMappingLoader()
	for _, tc := range []struct {
		name string
		mode string
	}{
		{"cache_mode=off", "off"},
		{"cache_enabled=false", "disabled-flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := &CacheService{policy: NewPolicyCache(time.Second), log: slog.New(slog.DiscardHandler)}
			cs.SetOrgPolicyLoader(loader(tc.mode))

			ctx := context.Background()
			ri := RouteIdentity{OrgID: "org-off", Model: "gpt-test"}.Resolved()

			hit, err := cs.LookupWithResult(ctx, ri, []byte(`{"prompt":"hi"}`))
			require.NoError(t, err)
			assert.Nil(t, hit, "a privacy-disabled org is a miss, never a hit")
			assert.NoError(t, cs.Write(ctx, ri, []byte(`{"prompt":"hi"}`), []byte(`"resp"`), 1, 1),
				"a privacy-disabled org must not write")
		})
	}
}

// newDBPolicyMappingLoader builds an OrgPolicyLoader wired through the real
// DBPolicyLoader mapping (not a hand-written OrgPolicy) so the service test
// exercises the exact production translation of the org settings row.
func newDBPolicyMappingLoader() func(mode string) func(ctx context.Context, orgID string) (*OrgPolicy, error) {
	log := slog.New(slog.DiscardHandler)
	return func(mode string) func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		return func(_ context.Context, _ string) (*OrgPolicy, error) {
			if mode == "disabled-flag" {
				return cachePolicyFor(false, "semantic", log), nil
			}
			return cachePolicyFor(true, mode, log), nil
		}
	}
}

// TestDBPolicyLoader_Live: the real SQL path — organizations rows with
// cache_mode off/semantic/exact load exactly as the unit matrix maps them.
// (cache_mode is NOT NULL in the schema; the loader's COALESCE stays as
// defense for exotic states.) Skips in -short mode and without Docker
// (repo convention).
func TestDBPolicyLoader_Live(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	l := NewDBPolicyLoader(pool, slog.New(slog.DiscardHandler))

	semID := seedCacheOrg(t, pool, "cache-semantic-org", true, "semantic")
	exactID := seedCacheOrg(t, pool, "cache-exact-org", true, "exact")
	offID := seedCacheOrg(t, pool, "cache-off-org", true, "off")
	disabledID := seedCacheOrg(t, pool, "cache-disabled-org", false, "semantic")

	t.Run("cache_mode=off loads fully disabled", func(t *testing.T) {
		pol, err := l.LoadOrgPolicy(ctx, offID)
		require.NoError(t, err)
		assert.Equal(t, PrivacyDisabled, pol.Mode, "an org that said NO must not cache (F-6)")
		assert.False(t, pol.Semantic)
	})

	t.Run("cache_mode=semantic/exact keep their semantics", func(t *testing.T) {
		pol, err := l.LoadOrgPolicy(ctx, semID)
		require.NoError(t, err)
		assert.Equal(t, PrivacyEnabled, pol.Mode)
		assert.True(t, pol.Semantic)

		pol, err = l.LoadOrgPolicy(ctx, exactID)
		require.NoError(t, err)
		assert.Equal(t, PrivacyEnabled, pol.Mode)
		assert.False(t, pol.Semantic)
	})

	t.Run("cache_enabled=false wins over any mode", func(t *testing.T) {
		pol, err := l.LoadOrgPolicy(ctx, disabledID)
		require.NoError(t, err)
		assert.Equal(t, PrivacyDisabled, pol.Mode)
	})
}

// seedCacheOrg inserts one organizations row with the given cache settings
// and registers its cleanup (fixtures own their context: the cleanup runs
// after the test's ctx may be gone — repo idiom, services/loggerd parity).
func seedCacheOrg(t *testing.T, pool *pgxpool.Pool, name string, cacheEnabled bool, cacheMode string) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, cache_enabled, cache_mode) VALUES ($1, $2, $3, $4) RETURNING id::text`,
		name, name, cacheEnabled, cacheMode).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", orgID)
	})
	return orgID
}
