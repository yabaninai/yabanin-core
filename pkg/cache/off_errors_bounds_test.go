package cache

// Error and boundary tests for the
// cache_mode=off governance contract. The main scenario (off neither reads
// nor writes) is covered by db_policy_loader_test.go and the integration
// stand; this file pins the failure arcs around it:
//   - policy source failure: a loader error must fail CLOSED at the service
//     level — a miss, never an error leaked to the caller, never a hit, and
//     never a write (partial/unknown states are not success);
//   - interrupted request: a cancelled caller must fail closed immediately
//     without serving or writing, even when the org's real policy would be
//     permissive, and the shared load must stay usable for a retry;
//   - invalid input: the organizations schema itself rejects unknown and
//     NULL cache_mode values, and a missing org produces a diagnosable
//     wrapped error (which is exactly what the service fail-closes on).

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCacheService_PolicySourceFailure_FailsClosed: when the policy loader
// errors (DB down, SQL defect, exhaustion), the service must degrade the
// whole cache for that org to a miss: LookupWithResult answers (nil, nil) —
// the documented miss contract, not an error — and Write returns nil without
// queueing anything. A loader outage must never fail open into caching.
func TestCacheService_PolicySourceFailure_FailsClosed(t *testing.T) {
	cs := &CacheService{policy: NewPolicyCache(time.Second), log: slog.New(slog.DiscardHandler)}
	cs.SetOrgPolicyLoader(func(context.Context, string) (*OrgPolicy, error) {
		return nil, errors.New("db down")
	})

	ctx := context.Background()
	ri := RouteIdentity{OrgID: "org-loader-error", Model: "gpt-test"}.Resolved()

	hit, err := cs.LookupWithResult(ctx, ri, []byte(`{"prompt":"hi"}`))
	require.NoError(t, err, "a loader outage is a miss, not a caller-visible error")
	assert.Nil(t, hit, "fail-closed policy must not serve anything")

	require.NoError(t, cs.Write(ctx, ri, []byte(`{"prompt":"hi"}`), []byte(`"resp"`), 1, 1),
		"fail-closed policy must silently skip the write, not error the request path")

	// Retry after the failure: identical no-op outcome, not a half state.
	hit, err = cs.LookupWithResult(ctx, ri, []byte(`{"prompt":"hi"}`))
	require.NoError(t, err)
	assert.Nil(t, hit, "retried lookup under a failing source stays a miss")
	require.NoError(t, cs.Write(ctx, ri, []byte(`{"prompt":"hi"}`), []byte(`"resp"`), 1, 1))
}

// TestCacheService_CancelledPolicyLoad_FailsClosed: a cancelled caller must
// get the fail-closed answer immediately — before the (still blocked) shared
// load finishes — regardless of what that load would return. Cancellation is
// therefore never a bypass: an org whose real policy allows caching still
// gets neither a served entry nor a write from the interrupted request, and
// once the load lands, the true policy governs later callers.
func TestCacheService_CancelledPolicyLoad_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		// policy the blocked loader returns once released
		releasedMode PrivacyMode
		releasedSem  bool
	}{
		{"org that said NO stays a no-op after retry", PrivacyDisabled, false},
		{"permissive org gets no read and no write from the interrupted call", PrivacyEnabled, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := make(chan struct{})
			loader := func(context.Context, string) (*OrgPolicy, error) {
				<-gate
				return &OrgPolicy{Mode: tc.releasedMode, Semantic: tc.releasedSem, TTL: time.Hour}, nil
			}

			cs := &CacheService{policy: NewPolicyCache(time.Hour), log: slog.New(slog.DiscardHandler)}
			cs.SetOrgPolicyLoader(loader)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			ri := RouteIdentity{OrgID: "org-cancel-" + tc.releasedMode.String(), Model: "gpt-test"}.Resolved()

			hit, err := cs.LookupWithResult(ctx, ri, []byte(`{"prompt":"hi"}`))
			require.NoError(t, err, "cancellation is a miss, not an error")
			assert.Nil(t, hit, "interrupted lookup must not serve entries even if the policy would allow it")

			require.NoError(t, cs.Write(ctx, ri, []byte(`{"prompt":"hi"}`), []byte(`"resp"`), 1, 1),
				"interrupted write must be a silent no-op, not an error and not a queued job")

			// Release the shared load and give it time to publish; the
			// cancelled calls above must have consumed nothing.
			close(gate)
			require.Eventually(t, func() bool {
				return cs.policy.Get(context.Background(), ri.OrgID, nil).Mode == tc.releasedMode
			}, 2*time.Second, 5*time.Millisecond, "the shared load must land for later callers")

			// Retry after the interruption, with a live context: the real
			// policy now governs. Asserted at the policy level (the full
			// permissive serve path needs real backends and is proven on the
			// integration stand; here the contract under test is the gate).
			pol := cs.policy.Get(context.Background(), ri.OrgID, nil)
			assert.Equal(t, tc.releasedMode, pol.Mode)
			assert.Equal(t, tc.releasedSem, pol.Semantic)
		})
	}
}

// TestDBPolicyLoader_InputBoundaries_Live: invalid cache settings cannot
// reach cachePolicyFor through SQL — the organizations schema is the input
// boundary (admin API validates on top). A missing org yields the diagnosable
// wrapped error the service fail-closes on. Skips without Docker (repo
// convention, pkg/testdb).
func TestDBPolicyLoader_InputBoundaries_Live(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	l := NewDBPolicyLoader(pool, slog.New(slog.DiscardHandler))

	t.Run("unknown cache_mode is rejected by the schema check", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO organizations (name, slug, cache_enabled, cache_mode) VALUES ($1, $2, true, $3)`,
			"cache-bad-mode", "cache-bad-mode", "hybrid")
		require.Error(t, err, "cache_mode='hybrid' must not be storable")

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "expected a pg error")
		assert.Equal(t, "23514", pgErr.Code, "check_violation")
		assert.Equal(t, "organizations_cache_mode_check", pgErr.ConstraintName,
			"the diagnosable cause is the enum check constraint")
	})

	t.Run("NULL cache_mode is rejected by NOT NULL", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO organizations (name, slug, cache_enabled, cache_mode) VALUES ($1, $2, true, NULL)`,
			"cache-null-mode", "cache-null-mode")
		require.Error(t, err, "cache_mode is NOT NULL; the loader's COALESCE stays defense-in-depth")

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "23502", pgErr.Code, "not_null_violation")
		assert.Equal(t, "cache_mode", pgErr.ColumnName)
	})

	t.Run("missing org loads a diagnosable wrapped error", func(t *testing.T) {
		_, err := l.LoadOrgPolicy(ctx, "00000000-0000-0000-0000-0000000000ff")
		require.Error(t, err)
		require.ErrorIs(t, err, pgx.ErrNoRows)
		assert.ErrorContains(t, err, "load org cache policy",
			"the wrapped cause is what PolicyCache turns into a fail-closed disabled policy")
	})
}

// guard: the fail-closed mapping must also survive a pool that is closed
// after construction — an org whose policy source dies mid-flight is a miss,
// never a hit and never an error surfaced to the cache caller.
func TestDBPolicyLoader_ClosedPool_WrapsError(t *testing.T) {
	pool := testdb.Postgres(t)
	dead, err := pgxpool.New(context.Background(), pool.Config().ConnString())
	require.NoError(t, err)
	dead.Close()

	l := NewDBPolicyLoader(dead, slog.New(slog.DiscardHandler))
	_, err = l.LoadOrgPolicy(context.Background(), "org-any")
	require.Error(t, err)
	assert.ErrorContains(t, err, "load org cache policy")
}
