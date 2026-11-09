package adminstore

// methods moved out of services/admin/handlers/region_handlers.go — the
// org_home_region upsert (insert and conflict-update branches) and the
// get that the handler answers with its "sg" default when the row is

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLContractRegion(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	org := fx.Token + "-region-org" // org_home_region.org_id is plain text, no FK
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM org_home_region WHERE org_id LIKE $1`, fx.Token+"-region-org%"); err != nil {
			t.Errorf("region cleanup: %v", err)
		}
	})

	// Insert branch round-trips region and pin flag.
	contract(t, "UpsertOrgHomeRegion[insert]", func(ctx context.Context) error {
		return store.UpsertOrgHomeRegion(ctx, org, "eu", true)
	})
	contract(t, "GetOrgHomeRegion[inserted]", func(ctx context.Context) error {
		region, pinned, err := store.GetOrgHomeRegion(ctx, org)
		if err != nil {
			return err
		}
		if region != "eu" || !pinned {
			t.Errorf("GetOrgHomeRegion: expected (eu, true), got (%q, %v)", region, pinned)
		}
		return nil
	})

	// Conflict-update branch overwrites both columns.
	contract(t, "UpsertOrgHomeRegion[conflict]", func(ctx context.Context) error {
		return store.UpsertOrgHomeRegion(ctx, org, "in", false)
	})
	contract(t, "GetOrgHomeRegion[updated]", func(ctx context.Context) error {
		region, pinned, err := store.GetOrgHomeRegion(ctx, org)
		if err != nil {
			return err
		}
		if region != "in" || pinned {
			t.Errorf("GetOrgHomeRegion: expected (in, false), got (%q, %v)", region, pinned)
		}
		return nil
	})

	// The read is org-scoped: another org has no assignment yet.
	contract(t, "GetOrgHomeRegion[unknown-org]", func(ctx context.Context) error {
		region, pinned, err := store.GetOrgHomeRegion(ctx, fx.Token+"-no-such-region-org")
		switch {
		case err == nil:
			t.Errorf("GetOrgHomeRegion: expected ErrNoRows for a missing org")
		case region != "" || pinned:
			t.Errorf("GetOrgHomeRegion: expected zero values beside the error, got (%q, %v)", region, pinned)
		default:
			require.ErrorIs(t, err, pgx.ErrNoRows)
		}
		return nil
	})

	// The seeded fixture orgs must stay untouched by the token-scoped rows.
	var fixtureRegions int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM org_home_region WHERE org_id = $1`, fx.OrgA).Scan(&fixtureRegions))
	assert.Equal(t, 0, fixtureRegions, "fixture org must not gain a region row")
}
