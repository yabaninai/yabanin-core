package consumer

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-LOGG fix-guards: the retention worker is beta (not wired), but a future
// activation must not panic on partial policies. Each family checks its own
// window pointer — the old `CacheEntriesDays != nil || LineageDays != nil`
// condition dereferenced a nil CacheEntriesDays for lineage-only policies.

type wloggPolicySource struct {
	teams     []adminstore.TeamRetentionAssignment
	effective map[string]*adminstore.OrgRetention
}

func (f wloggPolicySource) ListEnabledTeamRetentionAssignments(context.Context) ([]adminstore.TeamRetentionAssignment, error) {
	return f.teams, nil
}

func (f wloggPolicySource) EffectiveOrgRetention(_ context.Context, orgID string) (*adminstore.OrgRetention, error) {
	if eff, ok := f.effective[orgID]; ok {
		return eff, nil
	}
	return nil, adminstore.ErrNoRetention
}

// wloggRetentionDB answers every select with zero rows and records which
// family selects ran.
type wloggRetentionDB struct {
	queries []string
}

func (f *wloggRetentionDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("DELETE 0"), nil
}

func (f *wloggRetentionDB) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	f.queries = append(f.queries, query)
	return &fakeRows{}, nil
}

func intPtr(n int) *int { return &n }

func destPtr(dest string) *string { return &dest }

// A lineage-only org policy must skip the cache family — before the fix
// this exact shape dereferenced the nil CacheEntriesDays and panicked.
func TestRetention_LineageOnlyPolicyDoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		db := &wloggRetentionDB{}
		w := NewRetentionWorker(db, wloggPolicySource{
			// A team assignment registers the org even when it carries no
			// request_logs window of its own.
			teams: []adminstore.TeamRetentionAssignment{
				{TeamRetentionPolicy: adminstore.TeamRetentionPolicy{TeamID: "team-l"}, OrgID: "aaaa0000-0000-4000-8000-000000000001"},
			},
			effective: map[string]*adminstore.OrgRetention{
				"aaaa0000-0000-4000-8000-000000000001": {LineageDays: intPtr(30), Destination: destPtr("file://" + t.TempDir())},
			},
		}, silentLogger())

		stats, err := w.runOnce(context.Background())
		require.NoError(t, err)
		assert.Zero(t, stats.CacheEntriesExported, "cache family skipped: no window")

		var lineageSelected, cacheSelected bool
		for _, q := range db.queries {
			switch {
			case strings.Contains(q, "FROM request_lineage"):
				lineageSelected = true
			case strings.Contains(q, "FROM cache_entries"):
				cacheSelected = true
			}
		}
		assert.True(t, lineageSelected, "the lineage family runs on its own window")
		assert.False(t, cacheSelected, "the cache family never runs without its window")
	})
}

// A cache-only policy must skip the lineage family.
func TestRetention_CacheOnlyPolicyDoesNotTouchLineage(t *testing.T) {
	require.NotPanics(t, func() {
		db := &wloggRetentionDB{}
		w := NewRetentionWorker(db, wloggPolicySource{
			teams: []adminstore.TeamRetentionAssignment{
				{TeamRetentionPolicy: adminstore.TeamRetentionPolicy{TeamID: "team-c"}, OrgID: "aaaa0000-0000-4000-8000-000000000002"},
			},
			effective: map[string]*adminstore.OrgRetention{
				"aaaa0000-0000-4000-8000-000000000002": {CacheEntriesDays: intPtr(14), Destination: destPtr("file://" + t.TempDir())},
			},
		}, silentLogger())

		stats, err := w.runOnce(context.Background())
		require.NoError(t, err)
		assert.Zero(t, stats.LineageExported)

		var lineageSelected, cacheSelected bool
		for _, q := range db.queries {
			switch {
			case strings.Contains(q, "FROM request_lineage"):
				lineageSelected = true
			case strings.Contains(q, "FROM cache_entries"):
				cacheSelected = true
			}
		}
		assert.True(t, cacheSelected)
		assert.False(t, lineageSelected, "lineage never runs without its window")
	})
}

// A team assignment without a request_logs window plus an org policy with no
// windows at all is a full no-op pass — never a panic.
func TestRetention_NoWindowsNoOp(t *testing.T) {
	require.NotPanics(t, func() {
		db := &wloggRetentionDB{}
		w := NewRetentionWorker(db, wloggPolicySource{
			teams: []adminstore.TeamRetentionAssignment{
				{TeamRetentionPolicy: adminstore.TeamRetentionPolicy{TeamID: "team-1"}, OrgID: "aaaa0000-0000-4000-8000-000000000003"},
			},
			effective: map[string]*adminstore.OrgRetention{
				"aaaa0000-0000-4000-8000-000000000003": {Destination: destPtr("file://" + t.TempDir())},
			},
		}, silentLogger())

		stats, err := w.runOnce(context.Background())
		require.NoError(t, err)
		assert.Equal(t, RetentionStats{}, stats, "nothing is exported or deleted")
		assert.Empty(t, db.queries, "no family query runs without a window")
	})
}
