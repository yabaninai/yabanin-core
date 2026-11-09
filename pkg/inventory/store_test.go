package inventory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	pool := testdb.Postgres(t) // applies the full production migration set incl. 0022
	s := NewStore(pool)
	require.NoError(t, s.EnsureSchema(context.Background()), "EnsureSchema must be a no-op over migration 0022")
	return s
}

func imp(t time.Time, org, key string, kind AssetKind, payload string) Asset {
	return Asset{
		OrgID: org, AssetKey: key, Kind: kind,
		Payload: json.RawMessage(payload), Source: SourceMCPRegistry,
		Confidence: ConfidenceHigh, FirstSeen: t, LastSeen: t,
	}
}

func TestStoreUpsertClassification(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	c, err := s.UpsertAssets(ctx, []Asset{imp(at, "org-cls", "mcp_server:fs", KindMCPServer, `{"name":"fs","v":1}`)})
	require.NoError(t, err)
	require.Equal(t, ImportCounts{Created: 1}, c, "first import of a row is created")

	// Identical re-import: unchanged, nothing touched.
	c, err = s.UpsertAssets(ctx, []Asset{imp(at, "org-cls", "mcp_server:fs", KindMCPServer, `{"name":"fs","v":1}`)})
	require.NoError(t, err)
	require.Equal(t, ImportCounts{Unchanged: 1}, c, "identical re-import is unchanged")

	// Later timestamp, same payload: last_seen moves → updated.
	later := at.Add(time.Hour)
	c, err = s.UpsertAssets(ctx, []Asset{imp(later, "org-cls", "mcp_server:fs", KindMCPServer, `{"name":"fs","v":1}`)})
	require.NoError(t, err)
	require.Equal(t, ImportCounts{Updated: 1}, c, "last_seen movement is updated")

	// Payload change: updated.
	c, err = s.UpsertAssets(ctx, []Asset{imp(later, "org-cls", "mcp_server:fs", KindMCPServer, `{"name":"fs","v":2}`)})
	require.NoError(t, err)
	require.Equal(t, ImportCounts{Updated: 1}, c, "payload change is updated")

	row, found, err := s.GetAsset(ctx, "org-cls", KindMCPServer, "mcp_server:fs")
	require.NoError(t, err)
	require.True(t, found)
	require.False(t, row.Tombstone)
	require.True(t, row.FirstSeen.Equal(at), "first_seen is monotonic (earliest kept)")
	require.True(t, row.LastSeen.Equal(later), "last_seen is monotonic (latest kept)")
	require.JSONEq(t, `{"name":"fs","v":2}`, string(row.Payload))
}

func TestStoreEmptyBatchIsNoOpSuccess(t *testing.T) {
	s := newTestStore(t)
	c, err := s.UpsertAssets(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, ImportCounts{}, c, "empty upstream: no-op success")
}

func TestStoreBatchIsAtomicOnInvalidRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	bad := imp(at, "org-atomic", "mcp_server:x", KindMCPServer, `{"name":"x"}`)
	bad.Confidence = "certain"
	_, err := s.UpsertAssets(ctx, []Asset{
		imp(at, "org-atomic", "mcp_server:ok", KindMCPServer, `{"name":"ok"}`),
		bad,
	})
	require.Error(t, err, "validation is all-or-nothing per batch")
	_, found, err := s.GetAsset(ctx, "org-atomic", KindMCPServer, "mcp_server:ok")
	require.NoError(t, err)
	require.False(t, found, "no partial batch may land")
}

func TestStoreTombstoneAndResurrect(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	_, err := s.UpsertAssets(ctx, []Asset{
		imp(at, "org-ts", "mcp_tool:fs/read_file", KindTool, `{"name":"read_file"}`),
		imp(at, "org-ts", "mcp_tool:fs/write_file", KindTool, `{"name":"write_file"}`),
	})
	require.NoError(t, err)

	gone := time.Date(2026, 11, 7, 13, 0, 0, 0, time.UTC)
	n, err := s.TombstoneAssets(ctx, "org-ts", KindTool, gone, []string{"mcp_tool:fs/read_file", "mcp_tool:fs/absent"})
	require.NoError(t, err)
	require.Equal(t, 1, n, "only the present live row flips; absent keys are no-ops")

	// Idempotent: re-tombstoning flips nothing.
	n, err = s.TombstoneAssets(ctx, "org-ts", KindTool, gone, []string{"mcp_tool:fs/read_file"})
	require.NoError(t, err)
	require.Equal(t, 0, n)

	live, _, err := s.ListAssets(ctx, "org-ts", ListParams{})
	require.NoError(t, err)
	require.Len(t, live, 1, "default listing excludes tombstones")
	require.Equal(t, "mcp_tool:fs/write_file", live[0].AssetKey)

	all, _, err := s.ListAssets(ctx, "org-ts", ListParams{IncludeTombstoned: true})
	require.NoError(t, err)
	require.Len(t, all, 2)
	var tsRow Row
	for _, r := range all {
		if r.AssetKey == "mcp_tool:fs/read_file" {
			tsRow = r
		}
	}
	require.True(t, tsRow.Tombstone)
	require.True(t, tsRow.TombstonedAt.Equal(gone))

	// Resurrect by re-import: counts as updated, tombstone cleared.
	c, err := s.UpsertAssets(ctx, []Asset{imp(at.Add(2*time.Hour), "org-ts", "mcp_tool:fs/read_file", KindTool, `{"name":"read_file"}`)})
	require.NoError(t, err)
	require.Equal(t, ImportCounts{Updated: 1}, c, "resurrection of a tombstoned row is updated")
	row, found, err := s.GetAsset(ctx, "org-ts", KindTool, "mcp_tool:fs/read_file")
	require.NoError(t, err)
	require.True(t, found)
	require.False(t, row.Tombstone, "re-import resurrects (tombstone cleared)")
}

func TestStoreCrossOrgIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	_, err := s.UpsertAssets(ctx, []Asset{
		imp(at, "org-a", "mcp_server:fs", KindMCPServer, `{"name":"fs"}`),
		imp(at, "org-b", "mcp_server:fs", KindMCPServer, `{"name":"fs-b"}`),
	})
	require.NoError(t, err)

	rows, _, err := s.ListAssets(ctx, "org-a", ListParams{})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "org-a", rows[0].OrgID)

	row, found, err := s.GetAsset(ctx, "org-a", KindMCPServer, "mcp_server:fs")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "org-a", row.OrgID)
	require.JSONEq(t, `{"name":"fs"}`, string(row.Payload), "same key in another org is a different row")

	_, found, err = s.GetAsset(ctx, "org-c", KindMCPServer, "mcp_server:fs")
	require.NoError(t, err)
	require.False(t, found, "foreign org read is not-found, never a leak")
}

func TestStoreListCursorAndFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	var batch []Asset
	for i := 0; i < 7; i++ {
		batch = append(batch, imp(at, "org-cursor", "mcp_tool:s/t"+string(rune('a'+i)), KindTool, `{"n":1}`))
	}
	for i := 0; i < 3; i++ {
		batch = append(batch, imp(at, "org-cursor", "mcp_server:srv"+string(rune('a'+i)), KindMCPServer, `{"n":1}`))
	}
	_, err := s.UpsertAssets(ctx, batch)
	require.NoError(t, err)

	// Empty registry lists empty without error (200 [] semantics).
	empty, next, err := s.ListAssets(ctx, "org-empty", ListParams{})
	require.NoError(t, err)
	require.Empty(t, empty)
	require.Empty(t, next)

	// Full walk in pages of 4: deterministic (kind, asset_key) order, no dupes.
	var walk []string
	next = ""
	pages := 0
	for {
		page, cursor, err := s.ListAssets(ctx, "org-cursor", ListParams{After: next, Limit: 4})
		require.NoError(t, err)
		for _, r := range page {
			walk = append(walk, string(r.Kind)+"|"+r.AssetKey)
		}
		pages++
		if cursor == "" {
			break
		}
		next = cursor
	}
	require.Equal(t, 3, pages, "10 rows at limit 4 = 3 pages")
	require.Len(t, walk, 10)
	require.IsNonDecreasing(t, walk, "(kind, asset_key) order across pages")

	// Kind filter.
	onlyServers, _, err := s.ListAssets(ctx, "org-cursor", ListParams{Kind: KindMCPServer})
	require.NoError(t, err)
	require.Len(t, onlyServers, 3)
	for _, r := range onlyServers {
		require.Equal(t, KindMCPServer, r.Kind)
	}

	// Unknown kind is rejected, malformed cursor is rejected.
	_, _, err = s.ListAssets(ctx, "org-cursor", ListParams{Kind: AssetKind("vendor")})
	require.Error(t, err)
	_, _, err = s.ListAssets(ctx, "org-cursor", ListParams{After: "noseparator"})
	require.Error(t, err)
	_, _, err = s.ListAssets(ctx, "", ListParams{})
	require.Error(t, err, "org_id is required")
}
