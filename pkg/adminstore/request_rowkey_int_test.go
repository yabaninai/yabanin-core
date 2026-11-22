//go:build integration

package adminstore

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real-Postgres coverage for the 0028 row identity: a correlation legitimately
// spans several physical request_logs rows; the list must expose each row's
// own key (exactly, beyond 2^53) and the correlation-scoped row-key read must
// answer with the selected row's facts — and only within the caller's org and
// the requested correlation.

// seedRowKeyCorrelation inserts one request_logs row and returns its
// id::text (the exact bigint, unrounded) for use as a row_key oracle.
func seedRowKeyCorrelation(t *testing.T, db *pgxpool.Pool, orgID, req, model string, tokensIn, tokensOut int64, explicitID int64) string {
	t.Helper()
	var idText string
	err := db.QueryRow(context.Background(),
		`INSERT INTO request_logs (id, org_id, home_region, model_requested, model_used, status_code,
		   duration_ms, tokens_in, tokens_out, request_id, cost_in_usd, created_at)
		 VALUES (COALESCE(NULLIF($1::bigint, 0), nextval(pg_get_serial_sequence('request_logs', 'id'))), $2, 'sg', $3, $3, 200, 10, $4, $5, $6, 0.001, $7) RETURNING id::text`,
		explicitID, orgID, model, tokensIn, tokensOut, req, time.Now().UTC()).Scan(&idText)
	require.NoError(t, err)
	require.NotEmpty(t, idText)
	return idText
}

func TestIntegration_RequestRowKeyIdentity(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()

	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Rowkey', 'rowkey') RETURNING id::text").Scan(&orgID))
	var otherOrg string
	require.NoError(t, pool.QueryRow(ctx,
		fmt.Sprintf("INSERT INTO organizations (name, slug) VALUES ('Other', 'other-%d') RETURNING id::text", time.Now().UnixNano())).Scan(&otherOrg))

	// Correlation req-x spans three physical rows, including one whose
	// bigint id exceeds 2^53 (0 = let Postgres assign).
	key1 := seedRowKeyCorrelation(t, pool, orgID, "req-x", "gpt-4o-mini", 100, 50, 0)
	key2 := seedRowKeyCorrelation(t, pool, orgID, "req-x", "gpt-4o", 200, 60, 0)
	bigKeyText := seedRowKeyCorrelation(t, pool, orgID, "req-x", "gpt-4o", 300, 70, 9007199254740993)
	keyOther := seedRowKeyCorrelation(t, pool, orgID, "req-y", "claude-3", 400, 80, 0)
	keyForeign := seedRowKeyCorrelation(t, pool, otherOrg, "req-x", "evil", 900, 90, 0) // same correlation, other org

	require.Equal(t, "9007199254740993", bigKeyText, "the explicit beyond-2^53 id must come back exact")

	// LIST: every physical row appears with its own row_key — including the
	// beyond-2^53 value, which must survive as an exact int64.
	rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: orgID})
	require.NoError(t, err)
	require.Equal(t, 4, total)
	byKey := map[int64]RequestListRow{}
	for _, r := range rows {
		byKey[r.RowKey] = r
	}
	require.Len(t, byKey, 4, "each physical row is its own list entry")
	assert.Equal(t, int64(9007199254740993), byKey[9007199254740993].RowKey,
		"the beyond-2^53 key must survive the read exactly (2^53 rounding would give 9007199254740992)")
	assert.Equal(t, "gpt-4o-mini", byKey[mustKey(t, key1)].ModelUsed)
	assert.Equal(t, "gpt-4o", byKey[mustKey(t, key2)].ModelUsed)

	// DETAIL, correlation-scoped row-key selection: the selected row's own
	// facts. Members with requests:read can see org-wide metadata.
	_, err = store.GetRequestDetailRowInCorrelation(ctx, orgID, "req-x", mustKey(t, key1))
	assert.ErrorIs(t, err, ErrNotFound, "a caller with no scope gets the fail-closed miss even for a physically present row")

	metaCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{OrgWideMetadata: true})
	d1, err := store.GetRequestDetailRowInCorrelation(metaCtx, orgID, "req-x", mustKey(t, key1))
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o-mini", d1.ModelUsed)
	assert.Equal(t, int64(100), d1.TokensIn)
	assert.Equal(t, int64(50), d1.TokensOut)

	d2, err := store.GetRequestDetailRowInCorrelation(metaCtx, orgID, "req-x", mustKey(t, key2))
	require.NoError(t, err)
	assert.Equal(t, int64(200), d2.TokensIn, "the sibling's facts, not the other row's")

	dBig, err := store.GetRequestDetailRowInCorrelation(metaCtx, orgID, "req-x", 9007199254740993)
	require.NoError(t, err)
	assert.Equal(t, int64(300), dBig.TokensIn, "the beyond-2^53 row answers under its exact key")

	// The selection is fenced by correlation AND org — and the fence holds
	// for a caller who legitimately sees this org's metadata.
	_, err = store.GetRequestDetailRowInCorrelation(metaCtx, orgID, "req-x", mustKey(t, keyOther))
	assert.ErrorIs(t, err, ErrNotFound, "a key belonging to another correlation is a miss")
	_, err = store.GetRequestDetailRowInCorrelation(metaCtx, orgID, "req-x", mustKey(t, keyForeign))
	assert.ErrorIs(t, err, ErrNotFound, "a foreign org's row must never answer this org's read")
	_, err = store.GetRequestDetailRowInCorrelation(metaCtx, otherOrg, "req-x", mustKey(t, key2))
	assert.ErrorIs(t, err, ErrNotFound, "this org's row must never answer the foreign org's read")
}

// mustKey parses a seeded id::text back to the exact int64.
func mustKey(t *testing.T, idText string) int64 {
	t.Helper()
	k, err := strconv.ParseInt(idText, 10, 64)
	require.NoError(t, err)
	return k
}
