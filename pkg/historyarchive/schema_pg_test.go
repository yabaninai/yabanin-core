package historyarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/migrate"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// These tests validate the manifest against a REAL fully migrated Postgres
// (testdb applies the production migrations/*.up.sql set in filename order —
// the same set a clean install applies). They are the integration teeth of
// the contract: the unit tests compare manifest bytes to migration bytes,
// these prove the migrated database and a representative manifest-ordered
// archive projection agree with both, at contract scope (Core ships no
// live batch writer/reader today). Requires Docker outside -short mode.

// canonicalType rebuilds the SQL type token information_schema reports for
// one column (lowercase data_type, plus precision/scale for numeric) so it
// is byte-comparable with the manifest's DBType tokens.
func canonicalType(dataType string, precision, scale *int32) string {
	t := strings.ToLower(dataType)
	if t == "numeric" && precision != nil && scale != nil {
		return fmt.Sprintf("%s(%d,%d)", t, *precision, *scale)
	}
	return t
}

// TestRequestLogsLiveSchemaMatchesManifest: the fully migrated database's
// request_logs columns (names, types, ordinal order) must equal the
// cumulative manifest exactly — 0001 columns in CREATE order plus the
// sanctioned additive migrations. A drift between migration bytes, manifest
// and the actually migrated schema cannot pass here.
func TestRequestLogsLiveSchemaMatchesManifest(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `
		SELECT column_name, data_type, numeric_precision, numeric_scale
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'request_logs'
		ORDER BY ordinal_position`)
	require.NoError(t, err)
	defer rows.Close()

	var live []HistoryColumn
	for rows.Next() {
		var name, dataType string
		var precision, scale *int32
		require.NoError(t, rows.Scan(&name, &dataType, &precision, &scale))
		live = append(live, HistoryColumn{Name: name, DBType: canonicalType(dataType, precision, scale), Kind: KindMetadata})
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, live, "no request_logs columns in the migrated stand")

	require.Len(t, live, len(HistoryColumns),
		"fully migrated request_logs column count drifted from the manifest — extend the sanctioned registry (and the generation) in the same change")
	for i, lc := range live {
		require.Equal(t, HistoryColumns[i].Name, lc.Name,
			"live request_logs column %d drifted (live %q vs manifest %q)", i, lc.Name, HistoryColumns[i].Name)
		require.Equal(t, HistoryColumns[i].DBType, lc.DBType,
			"live request_logs column %q type drifted (live %q vs manifest %q)", lc.Name, lc.DBType, HistoryColumns[i].DBType)
	}
}

// archiveFixture seeds two request_logs rows on the fully migrated stand:
// one carrying the 0028 invocation identity, one legacy row with NULL
// invocation_id — the exact population a hot→cold transfer must carry
// through without losing or fabricating invocation linkage.
const (
	invSeedID      = int64(992801)
	legacySeedID   = int64(992802)
	invSeedUUID    = "28ad0000-0000-4000-8000-0000000000a1"
	seedOrg        = "28ad0000-0000-4000-8000-0000000000b1"
	seedSession    = "28ad0000-0000-4000-8000-0000000000c1"
	seedModel      = "test-model-invocation"
	seedTimestamp  = "2026-11-21 12:00:00+00"
	seedResponseJb = `{"ok":true,"source":"pg-contract"}`
)

func seedArchiveRows(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The fixture is idempotent: re-running replaces the seeded rows only.
	_, err := pool.Exec(ctx, `
		INSERT INTO public.request_logs
			(id, session_id, org_id, model_requested, model_used, status_code,
			 duration_ms, home_region, request_id, response, cost_in_usd,
			 created_at, updated_at, invocation_id)
		VALUES
			($1, $3, $4, $5, $5, 200, 7, 'eu', 'req-inv-1', $6::jsonb, 1.25, $7, $7, $2::uuid),
			($8, $3, $4, $5, $5, 200, 9, 'eu', 'req-legacy-1', $6::jsonb, 2.50, $7, $7, NULL)
		ON CONFLICT (id) DO UPDATE SET
			invocation_id = EXCLUDED.invocation_id,
			response = EXCLUDED.response,
			cost_in_usd = EXCLUDED.cost_in_usd`,
		invSeedID, invSeedUUID, seedSession, seedOrg, seedModel, seedResponseJb, seedTimestamp, legacySeedID)
	require.NoError(t, err, "seed archive fixture rows")
}

// projectionSelect builds the manifest-ordered text-cast projection the
// archive transfer uses: every column explicitly quoted, cast to text (the
// canonical wire form), in manifest order. cols may be a generation's
// column list (an old-generation reader projects the same way).
func projectionSelect(cols []HistoryColumn) (string, []string) {
	parts := make([]string, len(cols))
	names := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = fmt.Sprintf(`"%s"::text`, c.Name)
		names[i] = c.Name
	}
	return "SELECT " + strings.Join(parts, ", ") + " FROM public.request_logs WHERE id = ANY($1) ORDER BY id", names
}

// projectRows runs the projection and returns one []any of (string | nil)
// per row in projection order.
func projectRows(t *testing.T, pool *pgxpool.Pool, cols []HistoryColumn, ids []int64) [][]any {
	t.Helper()
	query, _ := projectionSelect(cols)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, query, ids)
	require.NoError(t, err, "projection query must resolve against the fully migrated schema")
	defer rows.Close()
	var out [][]any
	for rows.Next() {
		vals, err := rows.Values()
		require.NoError(t, err)
		require.Len(t, vals, len(cols))
		for _, v := range vals {
			_, isString := v.(string)
			require.True(t, isString || v == nil,
				"text-cast projection must yield string or NULL, got %T", v)
		}
		out = append(out, vals)
	}
	require.NoError(t, rows.Err())
	return out
}

// rowDigest fingerprints one projected row over the projection's column
// names and values — the per-record digest an archive batch carries.
func rowDigest(names []string, vals []any) string {
	h := sha256.New()
	for i, v := range vals {
		text := "\x00NULL"
		if v != nil {
			text = v.(string)
		}
		_, _ = fmt.Fprintf(h, "%s=%s\x1e", names[i], text)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Both ends enforce the request log's tenant and session foreign keys.
func seedArchiveParents(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	_, err := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'Archive test','archive-test')", seedOrg)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", seedOrg)
		require.NoError(t, err)
	})
	_, err = pool.Exec(ctx, "INSERT INTO sessions (id,org_id,home_region) VALUES ($1,$2,'eu')", seedSession, seedOrg)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), "DELETE FROM sessions WHERE id=$1", seedSession)
		require.NoError(t, err)
	})
}

func archiveTarget(t *testing.T, source *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	name := "archive_" + uuid.NewString()
	identifier := pgx.Identifier{name}.Sanitize()
	_, err := source.Exec(t.Context(), "CREATE DATABASE "+identifier)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := source.Exec(ctx, "DROP DATABASE "+identifier)
		require.NoError(t, err)
	})
	dsn, err := url.Parse(source.Config().ConnString())
	require.NoError(t, err)
	dsn.Path = "/" + name
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	_, err = migrate.Run(ctx, dsn.String(), "eu")
	require.NoError(t, err)
	target, err := pgxpool.New(ctx, dsn.String())
	require.NoError(t, err)
	t.Cleanup(target.Close)
	return target
}

// TestArchiveProjectionRoundTripPreservesInvocation is the representative
// archive transfer: project the seeded rows through the current manifest
// (invocation-bearing + legacy NULL), restore the projected records into a
// FRESH clean-install database (new database, full migration replay), then
// re-project and require byte-identical per-record digests — invocation
// linkage survives clean-install backup/restore verbatim, and the
// pre-invocation generation's projection still reads both sides
// identically (old-archive compatibility).
func TestArchiveProjectionRoundTripPreservesInvocation(t *testing.T) {
	source := testdb.Postgres(t)
	seedArchiveParents(t, source)
	seedArchiveRows(t, source)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := source.Exec(ctx, "DELETE FROM public.request_logs WHERE id IN ($1, $2)", invSeedID, legacySeedID)
		require.NoError(t, err, "cleanup seeded rows")
	})

	ids := []int64{invSeedID, legacySeedID}
	current := CurrentGeneration().Columns
	srcRows := projectRows(t, source, current, ids)
	require.Len(t, srcRows, 2, "both seeded rows must project")
	// The projection is manifest-ordered: invocation_id is the LAST field.
	invocationIdx := len(current) - 1
	require.Equal(t, current[invocationIdx].Name, "invocation_id")
	require.Equal(t, invSeedUUID, srcRows[0][invocationIdx], "invocation row must carry its identity")
	require.Nil(t, srcRows[1][invocationIdx], "legacy row must keep NULL invocation_id")

	target := archiveTarget(t, source)
	seedArchiveParents(t, target)
	t.Cleanup(func() {
		_, err := target.Exec(context.Background(), "DELETE FROM request_logs WHERE id IN ($1,$2)", invSeedID, legacySeedID)
		require.NoError(t, err)
	})

	// Restore: insert the projected records through the exact manifest
	// column list — the logical archive restore path.
	_, names := projectionSelect(current)
	quoted := make([]string, len(names))
	placeholders := make([]string, len(names))
	for i, n := range names {
		quoted[i] = `"` + n + `"`
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	insertSQL := fmt.Sprintf("INSERT INTO public.request_logs (%s) VALUES (%s)",
		strings.Join(quoted, ", "), strings.Join(placeholders, ", "))
	for _, vals := range srcRows {
		ictx, icancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := target.Exec(ictx, insertSQL, vals...)
		icancel()
		require.NoError(t, err, "restore projected record into the clean-install target")
	}

	// Re-project the restored records: per-record digests must be
	// byte-identical — nothing (invocation linkage included) was lost,
	// reordered or rewritten through backup/restore.
	dstRows := projectRows(t, target, current, ids)
	require.Equal(t, srcRows, dstRows, "every projected field must survive the transfer")
	for i := range srcRows {
		require.Equal(t, rowDigest(names, srcRows[i]), rowDigest(names, dstRows[i]),
			"record %d digest changed across clean-install restore", ids[i])
	}

	// Historical generation resolution at contract scope: the
	// pre-invocation generation's projection reads source and restored
	// target identically. Core ships no live batch reader today — this
	// validates the projection contract a generation-1 historical artifact
	// demands, not a live compatibility claim.
	v1 := Generations()[0]
	_, v1Names := projectionSelect(v1.Columns)
	srcV1 := projectRows(t, source, v1.Columns, ids)
	dstV1 := projectRows(t, target, v1.Columns, ids)
	require.Len(t, srcV1, 2)
	for i := range srcV1 {
		require.Equal(t, rowDigest(v1Names, srcV1[i]), rowDigest(v1Names, dstV1[i]),
			"generation-1 digest changed across clean-install restore", ids[i])
	}
}
