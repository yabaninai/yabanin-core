package adminstore

// Exact-row export identity against a real PostgreSQL (disposable
// testcontainers stand). The client-supplied request id is a correlation
// field only (migration 0028): two legitimate invocations may share it, bill
// independently and log as two physical request_logs rows. The export must
// therefore emit each physical row exactly once, load each detail by the
// immutable row key, and never attach another invocation's correlation-keyed
// child facts to a row they cannot be attributed to.
//
// Covered shapes:
//
//   - two rows sharing org + request_id + created_at (distinct invocations,
//     distinct usage) both export with their own tokens;
//   - NULL-correlation rows (legacy/missing X-Request-ID) export
//     independently instead of collapsing into one;
//   - 201 rows sharing created_at AND request_id page across the 200-row
//     boundary with zero losses and zero duplicates — ordering there is
//     only the immutable rl.id tie-break;
//   - tool_calls/tool_call_invocations keyed by a shared correlation attach
//     to NONE of its rows (not attributable), while the same children under
//     a unique correlation attach unchanged.

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

// newExportIdentityOrg creates an isolated organization for the identity
// tests and cleans its rows (request_logs plus the correlation-keyed child
// tables, which carry no FK) on teardown.
func newExportIdentityOrg(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(context.Background(),
		"INSERT INTO organizations (name, slug) VALUES ('Export identity', $1) RETURNING id::text",
		fmt.Sprintf("export-identity-%d", time.Now().UnixNano())).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM tool_call_invocations WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM tool_calls WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM request_logs WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})
	return orgID
}

// insertExportIdentityRow seeds one request_logs row and returns its
// immutable id. requestID nil = NULL correlation (legacy row).
func insertExportIdentityRow(t *testing.T, pool *pgxpool.Pool, orgID string, requestID *string, tokensIn int64, createdAt time.Time) int64 {
	t.Helper()
	var id int64
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
		   duration_ms, tokens_in, tokens_out, request_id, created_at)
		 VALUES ($1, 'sg', 'm', 'm', 200, 10, $2, 3, $3, $4) RETURNING id`,
		orgID, tokensIn, requestID, createdAt).Scan(&id))
	return id
}

// exportOrgDetails streams the org's export into detail records.
func exportOrgDetails(t *testing.T, store *Store, orgID string, access RequestPayloadAccess, maxRows int) ([]*RequestDetail, int, error) {
	t.Helper()
	var got []*RequestDetail
	total, err := store.StreamRequestExport(context.Background(),
		RequestListFilters{OrgID: orgID}, access, maxRows,
		func(d *RequestDetail) error { got = append(got, d); return nil })
	return got, total, err
}

// TestExportSharedCorrelation_DistinctRowsExported is the store-level mirror
// of the frozen owner control: two paid invocations from one org sharing the
// client request id, the same created_at, distinct minted invocation usage.
// Both physical rows must export, each carrying its own tokens, and the list
// must surface both row keys.
func TestExportSharedCorrelation_DistinctRowsExported(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newExportIdentityOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)
	shared := "same-correlation"
	id1 := insertExportIdentityRow(t, pool, orgID, &shared, 7, stamp)
	id2 := insertExportIdentityRow(t, pool, orgID, &shared, 19, stamp)
	require.NotEqual(t, id1, id2, "two physical rows must exist")

	store := New(pool, slog.Default(), nil)

	rows, total, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID})
	require.NoError(t, err)
	require.Equal(t, 2, total, "the list counts both physical rows")
	require.Len(t, rows, 2)
	assert.ElementsMatch(t, []int64{id1, id2}, []int64{rows[0].RowKey, rows[1].RowKey},
		"the list selects the actual row keys")

	details, total, err := exportOrgDetails(t, store, orgID, RequestPayloadAccess{OrgWideMetadata: true}, 10)
	require.NoError(t, err)
	require.Equal(t, 2, total, "the export total counts both physical rows")
	require.Len(t, details, 2)
	tokens := []int64{details[0].TokensIn, details[1].TokensIn}
	assert.ElementsMatch(t, []int64{7, 19}, tokens, "each exported record carries its own row's usage")
	for _, d := range details {
		assert.Equal(t, shared, d.RequestID, "the external correlation id is preserved on every row")
	}
}

// TestExportNullCorrelation_RowsIndependent pins the legacy/NULL shape: rows
// without a correlation (COALESCE ”) must not collapse into a single
// emission — each physical row exports on its own row key.
func TestExportNullCorrelation_RowsIndependent(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newExportIdentityOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)
	insertExportIdentityRow(t, pool, orgID, nil, 3, stamp)
	insertExportIdentityRow(t, pool, orgID, nil, 4, stamp)

	details, total, err := exportOrgDetails(t, New(pool, slog.Default(), nil), orgID, RequestPayloadAccess{OrgWideMetadata: true}, 10)
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, details, 2)
	assert.ElementsMatch(t, []int64{3, 4}, []int64{details[0].TokensIn, details[1].TokensIn})
	for _, d := range details {
		assert.Empty(t, d.RequestID, "the NULL correlation stays empty, never fabricated")
	}
}

// TestExportIdenticalKeysPageBoundary_RowKeyTiebreak walks 201 rows whose
// created_at AND request_id are ALL identical: nothing in the visible key
// space distinguishes them, so paging stability across the 200/201 boundary
// rests entirely on the immutable rl.id tie-break. Every row must export
// exactly once — zero losses, zero duplicates.
func TestExportIdenticalKeysPageBoundary_RowKeyTiebreak(t *testing.T) {
	pool := openAdminTestPool(t)
	orgID := newExportIdentityOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)
	shared := "tie-correlation"
	const n = 201
	for i := 0; i < n; i++ {
		insertExportIdentityRow(t, pool, orgID, &shared, int64(i), stamp)
	}

	details, total, err := exportOrgDetails(t, New(pool, slog.Default(), nil), orgID, RequestPayloadAccess{OrgWideMetadata: true}, 300)
	require.NoError(t, err)
	require.Equal(t, n, total)
	require.Len(t, details, n)
	seen := map[int64]int{}
	for _, d := range details {
		seen[d.TokensIn]++
		assert.Equal(t, shared, d.RequestID)
	}
	require.Len(t, seen, n, "every physical row is distinct; none lost, none doubled")
	for tok, c := range seen {
		assert.Equal(t, 1, c, "row with tokens_in=%d exported %d times", tok, c)
	}
}

// TestExportSharedCorrelation_NoCrossAttachedChildren pins the child-facts
// rule under exact-row identity: tool_calls/tool_call_invocations are keyed
// by (org_id, request_id) — a correlation two invocations may share — so
// under a shared correlation the children are attributable to NEITHER row
// and attach to none of them, while the same children under a unique
// correlation attach unchanged.
func TestExportSharedCorrelation_NoCrossAttachedChildren(t *testing.T) {
	pool := openAdminTestPool(t)
	ctx := context.Background()
	orgID := newExportIdentityOrg(t, pool)
	stamp := time.Now().UTC().Add(-time.Hour)

	shared := "shared-children"
	insertExportIdentityRow(t, pool, orgID, &shared, 7, stamp)
	insertExportIdentityRow(t, pool, orgID, &shared, 19, stamp)
	_, err := pool.Exec(ctx,
		"INSERT INTO tool_calls (org_id, request_id, tool_name) VALUES ($1, $2, 'search'), ($1, $2, 'fetch')", orgID, shared)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO tool_call_invocations (org_id, request_id, seq, call_id, tool_name, arguments) VALUES ($1, $2, 1, 'c1', 'search', '{}'), ($1, $2, 2, 'c2', 'fetch', '{}')", orgID, shared)
	require.NoError(t, err)

	uniq := "unique-children"
	insertExportIdentityRow(t, pool, orgID, &uniq, 5, stamp)
	_, err = pool.Exec(ctx,
		"INSERT INTO tool_calls (org_id, request_id, tool_name) VALUES ($1, $2, 'weather')", orgID, uniq)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO tool_call_invocations (org_id, request_id, seq, call_id, tool_name, arguments) VALUES ($1, $2, 1, 'c9', 'weather', '{}')", orgID, uniq)
	require.NoError(t, err)

	// Grant access so payload-gated children are eligible at all.
	details, total, err := exportOrgDetails(t, New(pool, slog.Default(), nil), orgID,
		RequestPayloadAccess{Grant: true, OrgWideMetadata: true}, 10)
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Len(t, details, 3)

	byToken := map[int64]*RequestDetail{}
	for _, d := range details {
		byToken[d.TokensIn] = d
	}
	for _, tok := range []int64{7, 19} {
		d := byToken[tok]
		require.NotNil(t, d, "shared-correlation row with tokens %d must export", tok)
		assert.Empty(t, d.ToolCalls, "ambiguous children attach to no shared-correlation row")
		assert.Empty(t, d.ToolCallInvocations, "ambiguous invocations attach to no shared-correlation row")
	}
	d := byToken[5]
	require.NotNil(t, d, "unique-correlation row must export")
	require.Len(t, d.ToolCalls, 1)
	assert.Equal(t, "weather", d.ToolCalls[0].ToolName, "unambiguous children still attach")
	require.Len(t, d.ToolCallInvocations, 1)
	assert.Equal(t, "weather", d.ToolCallInvocations[0].ToolName)
}
