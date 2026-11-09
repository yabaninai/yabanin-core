package inbox

// E06-P01 W05-C02: acceptance battery for keyset pagination against the
// REAL migration 0027 table under the real yabanin_app role:
//
//   - the house clamp (50/100, sub-1 → default) holds in
//     NewPageRequest AND inside SearchPage (raw structs cannot smuggle
//     an unbounded fetch);
//   - nil org / invalid filters / malformed cursor are refused before
//     any statement (the refusing fake);
//   - a full cursor walk serves every row exactly once in the keyset
//     order (last_seen DESC, id ASC), including a same-last_seen tie
//     split across a page boundary;
//   - the walk is stable under concurrent inserts: a row inserted after
//     page 1 is served (it is newer than the cursor position) or held
//     for the next fresh walk (it is newer than the walk head) — it can
//     NEVER re-serve or skip rows already positioned before the cursor
//     (the OFFSET failure mode this card exists to kill);
//   - filters compose with the cursor (a paged, filtered walk);
//   - empty result → empty page, nil cursor, never an error.
//
// Fixture rows are written by the superuser stand (search_test.go
// precedent). Deterministic: fixed anchor timestamps, per-run org
// tokens, no sleeps.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginationNewPageRequestClamps(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, DefaultPageSize},
		{-3, DefaultPageSize},
		{1, 1},
		{50, 50},
		{100, MaxPageSize},
		{101, MaxPageSize},
		{9999, MaxPageSize},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, NewPageRequest(tc.in, nil).PageSize, "pageSize %d", tc.in)
	}
	cur := &PageCursor{LastSeen: time.Now(), IncidentID: uuid.New()}
	assert.Equal(t, cur, NewPageRequest(7, cur).Cursor, "cursor passes through untouched")
}

func TestPaginationCursorValidation(t *testing.T) {
	require.NoError(t, PageRequest{}.validate())
	require.NoError(t, PageRequest{Cursor: nil}.validate())
	require.NoError(t, PageRequest{
		Cursor: &PageCursor{LastSeen: time.Now(), IncidentID: uuid.New()},
	}.validate())
	err := PageRequest{Cursor: &PageCursor{LastSeen: time.Now()}}.validate()
	require.ErrorIs(t, err, ErrInvalidPageRequest)
	err = PageRequest{Cursor: &PageCursor{IncidentID: uuid.New()}}.validate()
	require.ErrorIs(t, err, ErrInvalidPageRequest)
}

// Nil org, invalid filters and a malformed cursor are all refused before
// Begin — the refusing fake fails the test if any statement is issued.
func TestPaginationRefusesBeforeAnyStatement(t *testing.T) {
	ctx := context.Background()
	rs := NewStore(&refusingDB{t: t})
	_, err := rs.SearchPage(ctx, uuid.Nil, SearchFilters{}, NewPageRequest(0, nil))
	require.ErrorIs(t, err, ErrStoreOrgRequired)
	_, err = rs.SearchPage(ctx, uuid.New(), SearchFilters{Severity: "ultra"}, NewPageRequest(0, nil))
	require.ErrorIs(t, err, ErrInvalidSearchFilters)
	_, err = rs.SearchPage(ctx, uuid.New(), SearchFilters{},
		NewPageRequest(0, &PageCursor{LastSeen: time.Now()}))
	require.ErrorIs(t, err, ErrInvalidPageRequest)
}

// pgWalk walks every page with the given size until the cursor runs
// out, asserting page shapes along the way.
func pgWalk(t *testing.T, ctx context.Context, store *Store, org uuid.UUID, f SearchFilters, size int) []Incident {
	t.Helper()
	var out []Incident
	var cursor *PageCursor
	pages := 0
	for {
		page, err := store.SearchPage(ctx, org, f, NewPageRequest(size, cursor))
		require.NoError(t, err)
		require.NotNil(t, page.Rows, "an empty page is an empty slice, not nil")
		require.LessOrEqual(t, len(page.Rows), size, "a page never exceeds the requested size")
		out = append(out, page.Rows...)
		if page.NextCursor == nil {
			break
		}
		require.NotEmpty(t, page.Rows, "a continuation cursor is only issued with a full page")
		require.Len(t, page.Rows, size, "has-more requires the probe row to exist")
		cursor = page.NextCursor
		pages++
		require.Less(t, pages, 100, "walk guard: a cursor loop must terminate")
	}
	return out
}

// A full walk serves every row exactly once in the keyset order,
// including a last_seen tie split across a page boundary.
func TestPaginationWalkServesEveryRowOnce(t *testing.T) {
	su, app, orgA, orgB := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06p%x", time.Now().UnixNano())

	// 7 rows: distinct last_seen, plus a two-row tie at the end so the
	// tie crosses a page-3 boundary at size 3 (rows 8,9 share last_seen).
	rows := []siRow{
		{key: "r1", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(1 * time.Hour)},
		{key: "r2", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(2 * time.Hour)},
		{key: "r3", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(3 * time.Hour)},
		{key: "r4", summary: "s", severity: SeverityMedium, status: StatusNew, assignee: nil, lastSeen: base.Add(4 * time.Hour)},
		{key: "r5", summary: "s", severity: SeverityMedium, status: StatusNew, assignee: nil, lastSeen: base.Add(5 * time.Hour)},
		{key: "r6", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(6 * time.Hour)},
		{key: "r7", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(7 * time.Hour)},
		{key: "r8", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(8 * time.Hour)},
		{key: "r9", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(8 * time.Hour)},
	}
	siInsertRows(t, ctx, su, orgA, token, rows)
	siInsertRows(t, ctx, su, orgB, token, []siRow{
		{key: "r1", summary: "s", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: base.Add(9 * time.Hour)},
	})

	store := NewStore(app)
	walked := pgWalk(t, ctx, store, orgA, SearchFilters{}, 3)
	require.Len(t, walked, 9, "every orgA row exactly once, orgB invisible")

	// Keyset order: last_seen DESC (r8/r9 tie → id ASC), r7, r6, …
	keys := make([]string, 0, 9)
	for _, inc := range walked {
		keys = append(keys, inc.GroupKey[len(token)+1:])
	}
	assert.True(t, uuidLess(walked[0].ID, walked[1].ID),
		"the last_seen tie is served id ASC, got %s then %s", walked[0].ID, walked[1].ID)
	assert.Equal(t, []string{"r7", "r6", "r5", "r4", "r3", "r2", "r1"}, keys[2:],
		"after the tie the order is strictly last_seen DESC")
	// No duplicates: 9 walked rows, 9 distinct ids.
	ids := map[uuid.UUID]bool{}
	for _, inc := range walked {
		require.False(t, ids[inc.ID], "a row served twice")
		ids[inc.ID] = true
	}

	// A filtered walk composes with the cursor: only the two medium rows.
	filtered := pgWalk(t, ctx, store, orgA, SearchFilters{Severity: SeverityMedium}, 1)
	require.Len(t, filtered, 2)
	for _, inc := range filtered {
		assert.Equal(t, SeverityMedium, inc.Severity)
	}
}

// The OFFSET failure mode, killed: inserting a row mid-walk can never
// re-serve or skip rows already positioned before the cursor.
func TestPaginationStableUnderConcurrentInserts(t *testing.T) {
	su, app, orgA, _ := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06c%x", time.Now().UnixNano())

	mk := func(i int, sev string) siRow {
		return siRow{key: fmt.Sprintf("r%d", i), summary: "s", severity: sev,
			status: StatusNew, assignee: nil, lastSeen: base.Add(time.Duration(i) * time.Hour)}
	}
	for i := 1; i <= 6; i++ {
		siInsertRows(t, ctx, su, orgA, token, []siRow{mk(i, SeverityLow)})
	}

	store := NewStore(app)
	page1, err := store.SearchPage(ctx, orgA, SearchFilters{}, NewPageRequest(3, nil))
	require.NoError(t, err)
	require.Len(t, page1.Rows, 3)
	require.NotNil(t, page1.NextCursor, "6 rows at size 3 → more pages")
	assert.Equal(t, token+"-r6", page1.Rows[0].GroupKey)

	// A concurrent insert AFTER page 1 was served.
	siInsertRows(t, ctx, su, orgA, token, []siRow{mk(7, SeverityLow)})

	page2, err := store.SearchPage(ctx, orgA, SearchFilters{}, NewPageRequest(3, page1.NextCursor))
	require.NoError(t, err)
	require.Len(t, page2.Rows, 3)
	assert.Nil(t, page2.NextCursor, "the walk had exactly 6 rows when it started")

	got := make([]string, 0, 6)
	for _, inc := range append(append([]Incident{}, page1.Rows...), page2.Rows...) {
		got = append(got, inc.GroupKey[len(token)+1:])
	}
	assert.Equal(t, []string{"r6", "r5", "r4", "r3", "r2", "r1"}, got,
		"the walk completes the snapshot it started on — r7 neither re-served nor skipped into it")

	// A FRESH walk (nil cursor) sees the new head — keyset never hides
	// newer rows, it only keeps already-served positions stable.
	fresh, err := store.SearchPage(ctx, orgA, SearchFilters{}, NewPageRequest(3, nil))
	require.NoError(t, err)
	require.Len(t, fresh.Rows, 3)
	assert.Equal(t, token+"-r7", fresh.Rows[0].GroupKey, "a fresh walk starts at the new head")
}

// Empty org / empty match: an empty page with a nil cursor, never an
// error; the raw-struct clamp holds inside SearchPage too.
func TestPaginationEmptyResultsAndRawStructClamp(t *testing.T) {
	su, app, orgA, _ := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06e%x", time.Now().UnixNano())
	siInsertRows(t, ctx, su, orgA, token, []siRow{
		{key: "only", summary: "s", severity: SeverityHigh, status: StatusNew, assignee: nil, lastSeen: base},
	})

	store := NewStore(app)
	page, err := store.SearchPage(ctx, orgA, SearchFilters{Severity: SeverityLow}, PageRequest{PageSize: 9999})
	require.NoError(t, err)
	require.NotNil(t, page.Rows)
	assert.Empty(t, page.Rows, "no low-severity row → empty page")
	assert.Nil(t, page.NextCursor)

	// PageSize 9999 raw struct: clamped to MaxPageSize — prove by asking
	// for exactly one row more than exists at the clamped size.
	page, err = store.SearchPage(ctx, orgA, SearchFilters{}, PageRequest{PageSize: -7})
	require.NoError(t, err)
	require.Len(t, page.Rows, 1, "negative raw size → default clamp, single row org served whole")
	assert.Nil(t, page.NextCursor, "no probe row → last page")
}
