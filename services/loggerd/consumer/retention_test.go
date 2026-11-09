package consumer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NEXT-21 unit contract: worker bounds, destination resolution, archive
// integrity and the SQL shapes that carry the export-before-delete and
// lineage-prefix guarantees. Behavior over real data is pinned by
// retention_live_test.go (disposable PG).

func TestDefaultRetentionConfig_RetentionDefaults(t *testing.T) {
	cfg := DefaultRetentionConfig()
	assert.Equal(t, time.Hour, cfg.Interval)
	assert.Equal(t, time.Hour, cfg.CleanupEvery)
	assert.Equal(t, 500, cfg.BatchSize)
	assert.Equal(t, 40, cfg.BatchesPerTick)

	filled := RetentionConfig{}.withDefaults()
	assert.Equal(t, cfg, filled, "zero-value config falls back to production defaults")
}

func TestColdStorageFromURI(t *testing.T) {
	_, err := coldStorageFromURI("")
	require.ErrorIs(t, err, ErrNoColdDestination,
		"empty destination = no store; caller must skip cleanup")

	store, err := coldStorageFromURI("file:///var/cold/yabanin")
	require.NoError(t, err)
	fs, ok := store.(*FSStore)
	require.True(t, ok)
	assert.Equal(t, "/var/cold/yabanin", fs.root)

	_, err = coldStorageFromURI("file://relative/path")
	require.Error(t, err, "file paths must be absolute")

	_, err = coldStorageFromURI("s3://bucket/prefix")
	require.ErrorIs(t, err, ErrUnsupportedColdDestination,
		"s3 is reserved until a native writer lands; the worker must skip, never guess")

	_, err = coldStorageFromURI("http://bucket")
	require.Error(t, err)
}

func TestFSStore_WriteRoundTripAndTraversalGuard(t *testing.T) {
	root := t.TempDir()
	store, err := NewFSStore(root)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.Write(ctx, "request_logs/team-1/a.jsonl", []byte("hello")))
	got, err := os.ReadFile(filepath.Join(root, "request_logs", "team-1", "a.jsonl")) //nolint:gosec // G304: path is fixed under the t.TempDir root
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	require.NoError(t, store.Write(ctx, "../../escape.jsonl", []byte("nope")),
		"keys are anchored under the root")
	_, err = os.Stat(filepath.Join(root, "..", "escape.jsonl"))
	assert.True(t, os.IsNotExist(err), "traversal key must not escape the root")
	anchored, statErr := os.Stat(filepath.Join(root, "escape.jsonl"))
	require.NoError(t, statErr, "the anchored form is written INSIDE the root")
	assert.NotNil(t, anchored)

	_, err = NewFSStore("relative/root")
	assert.Error(t, err, "cold storage root must be absolute")
}

func TestWriteArchive_JSONLAndManifestSha(t *testing.T) {
	root := t.TempDir()
	store, err := NewFSStore(root)
	require.NoError(t, err)

	rows := []requestLogExport{
		{ID: 1, ModelUsed: "m1", Response: nil},
		{ID: 2, ModelUsed: "m2", Response: json.RawMessage(`{"k":1}`)},
	}
	require.NoError(t, writeArchive(context.Background(), store, "request_logs", "team-1", 30, true, rows))

	matches, err := filepath.Glob(filepath.Join(root, "request_logs", "team-1", "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, matches, 1)

	data, err := os.ReadFile(matches[0])
	require.NoError(t, err)
	sum := sha256.Sum256(data)

	var mf exportManifest
	manifestBytes, err := os.ReadFile(matches[0] + ".manifest.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(manifestBytes, &mf))

	assert.Equal(t, 2, mf.Rows)
	assert.Equal(t, hex.EncodeToString(sum[:]), mf.Sha256, "manifest sha covers the exact JSONL bytes")
	assert.True(t, mf.Redacted)
	assert.Equal(t, 30, mf.CutoffDays)
	assert.Equal(t, "request_logs", mf.Table)
	assert.Equal(t, "team-1", mf.Scope)
	assert.False(t, mf.ExportedAt.IsZero())

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	assert.Len(t, lines, 2, "one JSON object per line")
	var first map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	assert.Nil(t, first["response"], "redacted content exports as explicit null")
}

// The delete statements must stay id-scoped: retention removes exactly what
// was exported, never a time window. A future edit that turns these into a
// bare time-based DELETE breaks the export-before-delete contract.
// request_lineage has NO delete at all: the table is append-only (PB1.2
// tamper-evidence trigger), the worker only archives.
func TestRetentionQueries_DeleteIsIDScopedAndBounded(t *testing.T) {
	assert.Equal(t, "DELETE FROM request_logs WHERE id = ANY($1)", retentionRequestLogsDelete)
	assert.Equal(t, "DELETE FROM cache_entries WHERE id = ANY($1)", retentionCacheDelete)

	assert.Equal(t, "ORDER BY created_at, id", beforeLastLine(retentionRequestLogsSelect))
	assert.Equal(t, "LIMIT $3", lastLine(retentionRequestLogsSelect))
	assert.NotContains(t, retentionRequestLogsSelect, "DELETE",
		"select and delete must stay separate statements")

	// Org-scoped families: the team policy resolves through the effective
	// MIN window, the SQL keys on org_id.
	assert.Contains(t, retentionCacheSelect, "FROM cache_entries")
	assert.Contains(t, retentionCacheSelect, "WHERE org_id = $1")
	assert.Equal(t, "ORDER BY created_at, id", beforeLastLine(retentionCacheSelect))

	// Lineage: verbatim hash-chain columns, oldest-first archive order —
	// and no delete path anywhere in this file's lineage SQL.
	assert.Contains(t, retentionLineageSelect, "FROM request_lineage")
	assert.Contains(t, retentionLineageSelect, "WHERE org_id = $1")
	assert.Equal(t, "ORDER BY ts, id", beforeLastLine(retentionLineageSelect))
	for _, chainCol := range []string{"record_hash", "prev_hash", "raw_attestation", "attestation_hash"} {
		assert.Contains(t, retentionLineageSelect, chainCol,
			"archives must carry the hash chain verbatim")
	}
	assert.NotContains(t, retentionLineageSelect, "response",
		"lineage has no content payloads — nothing to redact, nothing to drop")
}

func lastLine(q string) string {
	lines := splitLines(q)
	return lines[len(lines)-1]
}

func beforeLastLine(q string) string {
	lines := splitLines(q)
	return lines[len(lines)-2]
}

func splitLines(q string) []string {
	parts := strings.Split(q, "\n")
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}

// Compile-time seam check.
var _ ColdStorage = (*FSStore)(nil)
