package consumer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NEXT-21 live acceptance (disposable PG, same stand contract as AF-16):
// the retention worker exports expired rows to cold storage BEFORE deleting
// them, honours per-team policies (enabled only, redaction, destinations),
// refuses to delete without a usable destination, archives the lineage chain
// verbatim (the table is append-only, PB1.2), and gates destructive passes
// by cadence.

func seedN21RequestLog(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID, teamID, requestID, age string) {
	t.Helper()
	_, err := pool.Exec(ctx, fmt.Sprintf(`
		INSERT INTO request_logs
			(org_id, team_id, request_id, model_requested, model_used, status_code, duration_ms,
			 created_at, updated_at, response)
		VALUES ($1::uuid, $2::uuid, $3, 'model-x', 'model-x', 200, 5,
			now() - %s, now() - %s, '{"secret":"do-not-leak"}'::jsonb)`, age, age),
		orgID, teamID, requestID)
	require.NoError(t, err, "seed request_logs retention fixture")
}

func countN21(ctx context.Context, t *testing.T, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

func TestRetentionLive_ExportBeforeDeletePerTeamPolicies(t *testing.T) {
	// Same stand contract as AF-16: disposable PG with the credit tables
	// guaranteed (store.CreateOrganization writes the org wallet lazily).
	ctx, pool := newSettlementLiveEnv(t)
	store := adminstore.New(pool, silentLogger(), nil)

	org, err := store.CreateOrganization(ctx, "NEXT-21 retention org",
		fmt.Sprintf("n21-ret-%d", time.Now().UnixNano()))
	require.NoError(t, err)
	orgID := org.ID
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM request_logs WHERE org_id = $1::uuid
			 DELETE FROM cache_entries WHERE org_id = $1::uuid`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM request_lineage WHERE org_id = $1::uuid`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1::uuid`, orgID)
	})

	teamA, err := store.CreateTeam(ctx, orgID, "Ret A",
		fmt.Sprintf("n21-ret-a-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)
	teamB, err := store.CreateTeam(ctx, orgID, "Ret B",
		fmt.Sprintf("n21-ret-b-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)

	coldDir := t.TempDir()
	one := 1
	require.NoError(t, store.UpsertTeamRetentionPolicy(ctx, &adminstore.TeamRetentionPolicy{
		TeamID:              teamA.ID,
		RequestLogsDays:     &one,
		CacheEntriesDays:    &one,
		LineageDays:         &one,
		BackupSnapshotsDays: nil,
		RedactContent:       true,
		ColdDestination:     "file://" + coldDir,
		Enabled:             true,
	}))
	// Team B stores a policy with a destination the worker cannot write:
	// its expired rows must SURVIVE (export-before-delete contract).
	require.NoError(t, store.UpsertTeamRetentionPolicy(ctx, &adminstore.TeamRetentionPolicy{
		TeamID:          teamB.ID,
		RequestLogsDays: &one,
		RedactContent:   true,
		ColdDestination: "s3://bucket-n21",
		Enabled:         true,
	}))

	seedN21RequestLog(ctx, t, pool, orgID, teamA.ID, "n21-old-1", "interval '2 days'")
	seedN21RequestLog(ctx, t, pool, orgID, teamA.ID, "n21-old-2", "interval '2 days'")
	seedN21RequestLog(ctx, t, pool, orgID, teamA.ID, "n21-fresh", "interval '0 seconds'")
	seedN21RequestLog(ctx, t, pool, orgID, teamB.ID, "n21-b-old", "interval '2 days'")

	_, err = pool.Exec(ctx, `
		INSERT INTO cache_entries (org_id, model_tier, prompt_hash, embedding, response, created_at, expires_at)
		VALUES ($1::uuid, 'smart', 'n21old', array_fill(0.1, ARRAY[384])::vector,
		        '{"cached":"secret"}'::jsonb, now() - interval '2 days', now() + interval '1 day'),
		       ($1::uuid, 'smart', 'n21fresh', array_fill(0.2, ARRAY[384])::vector,
		        '{"cached":"fresh"}'::jsonb, now(), now() + interval '1 day')`, orgID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO request_lineage
			(request_id, org_id, ts, model_used, inference_region, model_origin_country,
			 log_storage_region, provider_entity_jurisdiction, attestation_hash,
			 raw_attestation, record_hash, prev_hash)
		VALUES
			('n21-req-1', $1, now() - interval '2 days', 'model-x', 'us', 'US', 'us', 'US', 'att1', '{}', 'h1', NULL),
			('n21-req-2', $1, now() - interval '2 days' + interval '1 second', 'model-x', 'us', 'US', 'us', 'US', 'att2', '{}', 'h2', 'h1'),
			('n21-req-3', $1, now(), 'model-x', 'us', 'US', 'us', 'US', 'att3', '{}', 'h3', 'h2')`, orgID)
	require.NoError(t, err)

	w := NewRetentionWorker(pool, StorePolicySource{Store: store}, silentLogger()).
		WithConfig(RetentionConfig{
			Interval:       time.Hour,
			CleanupEvery:   time.Hour,
			BatchSize:      2,
			BatchesPerTick: 10,
		})

	stats, err := w.tick(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, stats.RequestLogsExported, "team A's two expired rows exported+deleted")
	assert.Equal(t, 1, stats.CacheEntriesExported)
	assert.Equal(t, 2, stats.LineageExported, "expired chain prefix h1,h2 archived")
	assert.Equal(t, 1, stats.SkippedUnsupported, "team B's s3:// destination skips cleanup")

	// Hot storage: expired exported rows are gone; everything else stays.
	assert.Equal(t, int64(1), countN21(ctx, t, pool, `SELECT count(*) FROM request_logs WHERE team_id = $1::uuid AND request_id LIKE 'n21-%'`, teamA.ID),
		"only the fresh team A row remains")
	assert.Equal(t, int64(1), countN21(ctx, t, pool, `SELECT count(*) FROM request_logs WHERE team_id = $1::uuid`, teamB.ID),
		"team B's expired row survives: no usable destination, no delete")
	assert.Equal(t, int64(1), countN21(ctx, t, pool, `SELECT count(*) FROM cache_entries WHERE org_id = $1::uuid AND prompt_hash = 'n21fresh'`, orgID),
		"fresh cache entry survives")
	assert.Equal(t, int64(0), countN21(ctx, t, pool, `SELECT count(*) FROM cache_entries WHERE org_id = $1::uuid AND prompt_hash = 'n21old'`, orgID))
	assert.Equal(t, int64(3), countN21(ctx, t, pool, `SELECT count(*) FROM request_lineage WHERE org_id = $1`, orgID),
		"request_lineage is append-only (PB1.2): the worker archives, never deletes")

	var prevHash string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT prev_hash FROM request_lineage WHERE record_hash = 'h3'`).Scan(&prevHash))
	assert.Equal(t, "h2", prevHash,
		"hot chain untouched — hashes were never rewritten, the archive copies them verbatim")

	// Cold storage: request_logs archive redacts the content payload.
	rlFiles, err := filepath.Glob(filepath.Join(coldDir, "request_logs", teamA.ID, "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, rlFiles, 1)
	rlData, err := os.ReadFile(rlFiles[0])
	require.NoError(t, err)
	assert.NotContains(t, string(rlData), "do-not-leak", "redacted exports carry no content payloads")
	var exportedRows []map[string]any
	for _, line := range splitJSONL(string(rlData)) {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		exportedRows = append(exportedRows, m)
	}
	require.Len(t, exportedRows, 2)
	for _, m := range exportedRows {
		assert.Nil(t, m["response"], "redacted content exports as explicit null")
		assert.Contains(t, m, "prompt_hash")
		assert.Contains(t, m, "cost_in_usd")
	}
	ids := map[string]bool{exportedRows[0]["request_id"].(string): true, exportedRows[1]["request_id"].(string): true}
	assert.True(t, ids["n21-old-1"] && ids["n21-old-2"], "archive covers exactly the deleted ids")

	// Cache archive: response redacted, embedding never exported.
	cacheFiles, err := filepath.Glob(filepath.Join(coldDir, "cache_entries", orgID, "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, cacheFiles, 1)
	cacheData, err := os.ReadFile(cacheFiles[0])
	require.NoError(t, err)
	assert.NotContains(t, string(cacheData), "cached")

	// Lineage archive: hash chain verbatim + manifest integrity.
	linFiles, err := filepath.Glob(filepath.Join(coldDir, "request_lineage", orgID, "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, linFiles, 1)
	linData, err := os.ReadFile(linFiles[0])
	require.NoError(t, err)
	var linRows []map[string]any
	for _, line := range splitJSONL(string(linData)) {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		linRows = append(linRows, m)
	}
	require.Len(t, linRows, 2)
	assert.Equal(t, "h1", linRows[0]["record_hash"])
	assert.Nil(t, linRows[0]["prev_hash"])
	assert.Equal(t, "h1", linRows[1]["prev_hash"],
		"the archive chain links exactly like the ledger rows it replaced")
	assert.Equal(t, "h2", linRows[1]["record_hash"])

	var mf exportManifest
	mfBytes, err := os.ReadFile(linFiles[0] + ".manifest.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(mfBytes, &mf))
	sum := sha256.Sum256(linData)
	assert.Equal(t, hex.EncodeToString(sum[:]), mf.Sha256)
	assert.Equal(t, 2, mf.Rows)
	assert.False(t, mf.Redacted, "lineage rows are never redacted — chain verbatim")

	// Cadence gate: an immediate second tick is a no-op.
	stats, err = w.tick(ctx)
	require.NoError(t, err)
	assert.Zero(t, stats.RequestLogsExported+stats.CacheEntriesExported+stats.LineageExported)
	assert.Zero(t, stats.SkippedUnsupported)
}

func splitJSONL(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
