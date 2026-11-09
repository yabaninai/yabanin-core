package inbox

// E06-P01 W05-C01: acceptance battery for scoped search against the REAL
// migration 0027 table under the real yabanin_app role (same stand shape
// as store_test.go):
//
//   - validation is fail-loud and BEFORE any statement (dictionary,
//     bounds, inverted window) — proved with the refusing fake;
//   - nil-org refusal stays before Begin (the standing store law);
//   - every filter arm matches exactly and ANDs with the others; the
//     result stays org-scoped (cross-org rows invisible) and in the
//     keyset order last_seen DESC, id ASC (tie broken by id, the 0027
//     index order);
//   - the summary query is a LITERAL substring: % and _ in the query
//     match themselves, and a classic injection string matches nothing
//     (no error, no widening);
//   - the explicit org predicate holds even for a superuser store (the
//     second lock proven independently of RLS);
//   - empty match → empty slice, never an error.
//
// Fixture rows are written by the superuser stand (the same precedent as
// the operator-state setup in store_test.go) so severity/status/assignee/
// window/summary are controlled per row. Deterministic: fixed anchor
// timestamps, per-run org tokens, no sleeps.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// siRow describes one fixture row with controlled search dimensions.
type siRow struct {
	key      string // group_key (unique per run via token)
	summary  string
	severity string
	status   string
	assignee *uuid.UUID
	lastSeen time.Time
}

// siInsertRows writes controlled incident rows for one org via the
// superuser stand (fixture precedent: store_test.go operator-state arm).
func siInsertRows(t *testing.T, ctx context.Context, su *pgxpool.Pool, org uuid.UUID, token string, rows []siRow) []uuid.UUID {
	t.Helper()
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		var id uuid.UUID
		require.NoError(t, su.QueryRow(ctx, `
			INSERT INTO security_inbox
			  (org_id, group_key, summary, severity, confidence, status, assignee,
			   first_seen, last_seen, first_event_id, last_event_id)
			VALUES ($1, $2, $3, $4, 0.9, $5, $6, $7, $7, $8, $8)
			RETURNING id`,
			org, token+"-"+r.key, r.summary, r.severity, r.status, r.assignee,
			r.lastSeen, token+"-"+r.key+"-evt").Scan(&id))
		ids = append(ids, id)
	}
	return ids
}

func siTimePtr(t time.Time) *time.Time { return &t }

// Validation is a store-level law: dictionary violations, oversized
// input and an inverted window are refused before any statement.
func TestSearchFiltersValidateFailLoud(t *testing.T) {
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		f    SearchFilters
		want error
	}{
		{"zero filters is valid", SearchFilters{}, nil},
		{"full valid set", SearchFilters{
			Severity: SeverityHigh, Status: StatusNew,
			Assignee: uuid.New(), AssigneeSet: true,
			From: siTimePtr(base), To: siTimePtr(base.Add(time.Hour)),
			GroupKey: "gk", SummaryQuery: "needle",
		}, nil},
		{"severity outside dictionary", SearchFilters{Severity: "ultra"}, ErrInvalidSearchFilters},
		{"status outside dictionary", SearchFilters{Status: "closed"}, ErrInvalidSearchFilters},
		{"group key over the model bound", SearchFilters{GroupKey: string(make([]byte, MaxGroupKeyLen+1))}, ErrInvalidSearchFilters},
		{"summary query over the bound", SearchFilters{SummaryQuery: string(make([]byte, MaxSummaryQueryLen+1))}, ErrInvalidSearchFilters},
		{"inverted window", SearchFilters{From: siTimePtr(base.Add(time.Hour)), To: siTimePtr(base)}, ErrInvalidSearchFilters},
		{"half window is fine", SearchFilters{From: siTimePtr(base)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.f.validate()
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// Nil org AND invalid filters are both refused before Begin — the
// refusing fake fails the test if any statement is issued.
func TestSearchRefusesBeforeAnyStatement(t *testing.T) {
	ctx := context.Background()
	rs := NewStore(&refusingDB{t: t})
	_, err := rs.Search(ctx, uuid.Nil, SearchFilters{})
	require.ErrorIs(t, err, ErrStoreOrgRequired)
	_, err = rs.Search(ctx, uuid.New(), SearchFilters{Severity: "ultra"})
	require.ErrorIs(t, err, ErrInvalidSearchFilters)
	_, err = rs.Search(ctx, uuid.New(), SearchFilters{From: siTimePtr(time.Now()), To: siTimePtr(time.Now().Add(-time.Hour))})
	require.ErrorIs(t, err, ErrInvalidSearchFilters)
}

// The full battery: every filter arm matches exactly, arms AND together,
// results stay org-scoped, and the order is the keyset order.
func TestSearchScopesToOrgAndMatchesExactly(t *testing.T) {
	su, app, orgA, orgB := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06s%x", time.Now().UnixNano())
	member1, member2 := uuid.New(), uuid.New()

	rowsA := []siRow{
		{key: "gk1", summary: "API key leaked in repo", severity: SeverityHigh, status: StatusNew, assignee: &member1, lastSeen: base.Add(1 * time.Hour)},
		{key: "gk2", summary: "Suspicious login 100% sure", severity: SeverityMedium, status: StatusAcknowledged, assignee: nil, lastSeen: base.Add(2 * time.Hour)},
		{key: "gk3", summary: "Unusual 100_underscore pattern", severity: SeverityLow, status: StatusResolved, assignee: &member2, lastSeen: base.Add(3 * time.Hour)},
		{key: "gk4", summary: "tool deny", severity: SeverityHigh, status: StatusNew, assignee: nil, lastSeen: base.Add(4 * time.Hour)},
	}
	ids := siInsertRows(t, ctx, su, orgA, token, rowsA)
	// A foreign-org row with dimensions that WOULD match several arms if
	// the org scoping ever broke.
	siInsertRows(t, ctx, su, orgB, token, []siRow{
		{key: "gk1", summary: "API key leaked in repo", severity: SeverityHigh, status: StatusNew, assignee: &member1, lastSeen: base.Add(5 * time.Hour)},
	})

	store := NewStore(app)
	keys := func(incs []Incident) []string {
		out := []string{}
		for _, inc := range incs {
			out = append(out, inc.GroupKey)
		}
		return out
	}
	tokenPrefix := token + "-"

	stripped := func(ks []string) []string {
		out := make([]string, len(ks))
		for i, k := range ks {
			out[i] = k[len(tokenPrefix):]
		}
		return out
	}

	t.Run("zero filters = the org list in keyset order", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk4", "gk3", "gk2", "gk1"}, stripped(keys(incs)), "last_seen DESC, no foreign-org row")
	})

	t.Run("severity exact", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{Severity: SeverityHigh})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk4", "gk1"}, stripped(keys(incs)))
	})

	t.Run("status exact", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{Status: StatusNew})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk4", "gk1"}, stripped(keys(incs)))
	})

	t.Run("assignee member exact", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{Assignee: member1, AssigneeSet: true})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk1"}, stripped(keys(incs)))
	})

	t.Run("assignee tri-state nil = unassigned only", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{AssigneeSet: true})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk4", "gk2"}, stripped(keys(incs)))
	})

	t.Run("closed window on last_seen", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{
			From: siTimePtr(base.Add(90 * time.Minute)), To: siTimePtr(base.Add(3*time.Hour + 30*time.Minute)),
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk3", "gk2"}, stripped(keys(incs)), "inclusive bounds on both sides")
	})

	t.Run("group key exact", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{GroupKey: token + "-gk2"})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk2"}, stripped(keys(incs)), "same key in another org does not leak")
	})

	t.Run("summary literal substring, case-insensitive", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{SummaryQuery: "api key"})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk1"}, stripped(keys(incs)), "ILIKE case fold, substring only")
	})

	t.Run("summary % in the query is literal", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{SummaryQuery: "100%"})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk2"}, stripped(keys(incs)),
			"escaped % must not act as a suffix wildcard (gk3 '100_underscore' must NOT match)")
	})

	t.Run("summary _ in the query is literal", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{SummaryQuery: "100_u"})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk3"}, stripped(keys(incs)),
			"escaped _ must not act as a single-char wildcard (gk2 '100% sure' must NOT match)")
	})

	t.Run("bare wildcard query matches only literal holders", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{SummaryQuery: "%"})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk2"}, stripped(keys(incs)), "only the row whose summary literally contains %")
	})

	t.Run("injection string is a literal that matches nothing", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{SummaryQuery: `' OR '1'='1 --`})
		require.NoError(t, err)
		assert.Empty(t, incs, "no row contains that literal; the query must not widen into SQL")
	})

	t.Run("filters AND together", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{
			Severity: SeverityHigh, Status: StatusNew, AssigneeSet: true,
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"gk4"}, stripped(keys(incs)), "high+new+unassigned narrows to one row")
	})

	t.Run("empty match is an empty slice, never an error", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{Severity: SeverityHigh, Status: StatusResolved})
		require.NoError(t, err)
		require.NotNil(t, incs)
		assert.Empty(t, incs)
	})

	t.Run("ids resolve to the fixture rows", func(t *testing.T) {
		incs, err := store.Search(ctx, orgA, SearchFilters{GroupKey: token + "-gk1"})
		require.NoError(t, err)
		require.Len(t, incs, 1)
		assert.Equal(t, ids[0], incs[0].ID)
		require.NoError(t, incs[0].Validate())
		assert.Equal(t, "API key leaked in repo", incs[0].Summary)
	})

	t.Run("last_seen DESC tie is broken by id ASC", func(t *testing.T) {
		tie := base.Add(6 * time.Hour)
		tieToken := token + "tie"
		siInsertRows(t, ctx, su, orgA, tieToken, []siRow{
			{key: "t1", summary: "tie one", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: tie},
			{key: "t2", summary: "tie two", severity: SeverityLow, status: StatusNew, assignee: nil, lastSeen: tie},
		})
		all, err := store.Search(ctx, orgA, SearchFilters{From: siTimePtr(tie)})
		require.NoError(t, err)
		require.Len(t, all, 2, "both tie rows surface")
		assert.True(t, uuidLess(all[0].ID, all[1].ID), "equal last_seen → id ASC, got %s then %s", all[0].ID, all[1].ID)
	})
}

// uuidLess is a byte-wise uuid comparison (the SQL id ASC tiebreak).
func uuidLess(a, b uuid.UUID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// The explicit org predicate is the second lock: it holds even when the
// store runs on a superuser session where RLS would not constrain
// anything. The bypass-RLS arm dials a DEDICATED superuser connection,
// never the shared su pool: on PG14+ any set_config of a custom GUC —
// even transaction-local — leaves an ” session placeholder for that
// connection's life (reader.go:99), and the shared su pool must stay
// GUC-less (the standing W05 probe, store_test.go:274). The placeholder
// dies with this connection when the test closes it.
func TestSearchOrgPredicateHoldsWithoutRLS(t *testing.T) {
	su, _, orgA, orgB := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06su%x", time.Now().UnixNano())
	siInsertRows(t, ctx, su, orgA, token, []siRow{
		{key: "a1", summary: "in A", severity: SeverityHigh, status: StatusNew, assignee: nil, lastSeen: base},
	})
	siInsertRows(t, ctx, su, orgB, token, []siRow{
		{key: "b1", summary: "in B", severity: SeverityHigh, status: StatusNew, assignee: nil, lastSeen: base},
	})

	conn, err := pgx.ConnectConfig(ctx, su.Config().ConnConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	store := NewStore(conn) // dedicated superuser session: RLS-exempt
	incs, err := store.Search(ctx, orgA, SearchFilters{Severity: SeverityHigh})
	require.NoError(t, err)
	require.Len(t, incs, 1)
	assert.Equal(t, orgA, incs[0].OrgID)
	incs, err = store.Search(ctx, orgB, SearchFilters{Severity: SeverityHigh})
	require.NoError(t, err)
	require.Len(t, incs, 1)
	assert.Equal(t, orgB, incs[0].OrgID)
}
