package adminstore

// org_onboarding under the application RLS posture (SET ROLE yabanin_app):
// the store must pin app.current_org inside its own transaction — a bare
// app-role session used to 500 on the upsert (RLS WITH CHECK) and silently
// answer "not onboarded" forever on the read, so the welcome flow could
// never be dismissed (regression seen live on the quickstart stand).

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newOnboardingFixture(t *testing.T) (store *Store, pool *pgxpool.Pool, orgID string) {
	t.Helper()
	pool = openAdminTestPool(t)
	store = New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("onb-%d", suffix), fmt.Sprintf("onb-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", org.ID)
	})
	return store, pool, org.ID
}

// TestOrgOnboarding_AppRoleRoundTrip_Integration: with NO externally bound
// app.current_org (the exact posture the admin plane runs in when a route
// handler calls the store directly), upsert then read back must succeed and
// report the marked state.
func TestOrgOnboarding_AppRoleRoundTrip_Integration(t *testing.T) {
	store, pool, orgID := newOnboardingFixture(t)
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(context.Background(), "RESET ROLE")
		_, _ = conn.Exec(context.Background(), "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	}()
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")

	rls := newForTest(rlsConnAdapter{conn.Conn()}, slog.New(slog.DiscardHandler), nil)

	require.NoError(t, rls.UpsertOrgOnboarding(ctx, orgID, false, true),
		"the store pins app.current_org in its own tx; a bare app-role session must not 500")
	got, err := rls.GetOrgOnboarding(ctx, orgID)
	require.NoError(t, err)
	assert.True(t, got.Skipped, "the read must see the row the upsert wrote (RLS GUC), not silently report zero state")
	assert.False(t, got.Completed)

	// completed and skipped are mutually exclusive terminal states
	// (org_onboarding_state_check): marking completed after skipped must be
	// rejected by the database, not silently merged.
	err = rls.UpsertOrgOnboarding(ctx, orgID, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org_onboarding_state_check")

	// The completed path on a fresh org works under the same posture.
	org2, err := store.CreateOrganization(ctx, "onb2-"+orgID[len(orgID)-8:], "onb2-"+orgID[len(orgID)-8:])
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", org2.ID)
	})
	require.NoError(t, rls.UpsertOrgOnboarding(ctx, org2.ID, true, false))
	got2, err := rls.GetOrgOnboarding(ctx, org2.ID)
	require.NoError(t, err)
	assert.True(t, got2.Completed)
	assert.False(t, got2.Skipped)

	// Unknown org is ErrNotFound, not an RLS error.
	err = rls.UpsertOrgOnboarding(ctx, "00000000-0000-0000-0000-000000000000", true, false)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestOrgOnboarding_ZeroStateForMissingRow_Integration: a fresh org answers
// the zero state (not an error) — the dashboard treats "never answered" as
// false/false.
func TestOrgOnboarding_ZeroStateForMissingRow_Integration(t *testing.T) {
	store, _, orgID := newOnboardingFixture(t)
	got, err := store.GetOrgOnboarding(context.Background(), orgID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, got.Completed)
	assert.False(t, got.Skipped)
}
