package inventory

// E02-P01 W02-C02: incremental import runner tests. The incrementality
// contract: a server whose config_version and allowed_tools did not move
// since the last imported snapshot skips the tool listing entirely (no
// upstream call, no tool rows disturbed); any config movement refreshes
// the full allow-listed tool surface. Runs against the real store over
// the migration stand.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingTools wraps a ToolSource and counts ListTools calls per server.
type countingTools struct {
	inner ToolSource
	calls map[string]int
}

func newCountingTools(inner ToolSource) *countingTools {
	return &countingTools{inner: inner, calls: map[string]int{}}
}

func (c *countingTools) ListTools(ctx context.Context, orgID, server string) ([]mcpagg.ToolDescriptor, error) {
	c.calls[server]++
	return c.inner.ListTools(ctx, orgID, server)
}

func newRunner(t *testing.T, src *fixtureSource) (*ImportRunner, *countingTools, *Store) {
	t.Helper()
	s := newTestStore(t)
	ct := newCountingTools(src)
	r, err := NewImportRunner(s, src, ct)
	require.NoError(t, err)
	return r, ct, s
}

func TestImportRunner_FirstPassImportsEverything(t *testing.T) {
	src := &fixtureSource{
		servers: []*mcpagg.Server{testServer("fs", true, nil, 3)},
		tools:   map[string][]mcpagg.ToolDescriptor{"fs": {{Name: "read_file"}}},
	}
	r, ct, s := newRunner(t, src)
	ctx := context.Background()

	report, err := r.Run(ctx, "org-run1")
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 2}, report.Counts)
	assert.Equal(t, 1, ct.calls["fs"])
	require.Len(t, report.Servers, 1)
	assert.False(t, report.Servers[0].Skipped)
	assert.Equal(t, 1, report.Servers[0].ToolsImported)

	rows, _, err := s.ListAssets(ctx, "org-run1", ListParams{})
	require.NoError(t, err)
	require.Len(t, rows, 2)
}

func TestImportRunner_UnchangedConfigSkipsToolListing(t *testing.T) {
	src := &fixtureSource{
		servers: []*mcpagg.Server{testServer("fs", true, nil, 3)},
		tools:   map[string][]mcpagg.ToolDescriptor{"fs": {{Name: "read_file"}}},
	}
	r, ct, _ := newRunner(t, src)
	ctx := context.Background()

	_, err := r.Run(ctx, "org-run2")
	require.NoError(t, err)
	require.Equal(t, 1, ct.calls["fs"])

	// Second pass: identical config_version + allowed_tools → skip.
	report, err := r.Run(ctx, "org-run2")
	require.NoError(t, err)
	assert.Equal(t, 1, ct.calls["fs"], "no second upstream call for an unchanged server")
	require.Len(t, report.Servers, 1)
	assert.True(t, report.Servers[0].Skipped, "the report marks the server as skipped")
	assert.Zero(t, report.Servers[0].ToolsImported)
	// The server row still refreshes: a new observation time moves
	// last_seen, which classifies as updated (not unchanged).
	assert.Equal(t, ImportCounts{Updated: 1}, report.Counts, "only the server row refreshes")
}

func TestImportRunner_ConfigVersionBumpRefreshesTools(t *testing.T) {
	srv := testServer("fs", true, nil, 3)
	src := &fixtureSource{
		servers: []*mcpagg.Server{srv},
		tools:   map[string][]mcpagg.ToolDescriptor{"fs": {{Name: "read_file"}}},
	}
	r, ct, _ := newRunner(t, src)
	ctx := context.Background()

	_, err := r.Run(ctx, "org-run3")
	require.NoError(t, err)
	require.Equal(t, 1, ct.calls["fs"])

	srv.ConfigVersion = 4 // operator bumped the server config
	report, err := r.Run(ctx, "org-run3")
	require.NoError(t, err)
	assert.Equal(t, 2, ct.calls["fs"], "config movement re-lists the tool surface")
	require.Len(t, report.Servers, 1)
	assert.False(t, report.Servers[0].Skipped)
	assert.Equal(t, 1, report.Servers[0].ToolsImported)
}

func TestImportRunner_AllowedToolsChangeRefreshesTools(t *testing.T) {
	srv := testServer("fs", true, nil, 3)
	src := &fixtureSource{
		servers: []*mcpagg.Server{srv},
		tools: map[string][]mcpagg.ToolDescriptor{
			"fs": {{Name: "read_file"}, {Name: "write_file"}},
		},
	}
	r, ct, s := newRunner(t, src)
	ctx := context.Background()

	// First pass with the full allow-list (all tools).
	report, err := r.Run(ctx, "org-run4")
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Created: 3}, report.Counts)

	// Same config_version but the allow-list narrows — the tool surface
	// must refresh (this is exactly the allowed_tools delta dimension).
	srv.AllowedTools = []string{"read_file"}
	src.tools["fs"] = []mcpagg.ToolDescriptor{{Name: "read_file"}, {Name: "write_file"}}
	report, err = r.Run(ctx, "org-run4")
	require.NoError(t, err)
	assert.Equal(t, 2, ct.calls["fs"], "allowed_tools delta re-lists despite equal config_version")
	require.Len(t, report.Servers, 1)
	assert.False(t, report.Servers[0].Skipped)

	// The narrowed surface is observable: listing kind=tool shows the
	// write_file row still present (tombstones are a separate concern),
	// and the server payload carries the new allow-list.
	row, found, err := s.GetAsset(ctx, "org-run4", KindMCPServer, MCPServerKey("fs"))
	require.NoError(t, err)
	require.True(t, found)
	var sp MCPServerPayload
	require.NoError(t, json.Unmarshal(row.Payload, &sp))
	assert.Equal(t, []string{"read_file"}, sp.AllowedTools)
}

func TestImportRunner_ToolMissKeepsServerIdentityAndRecovers(t *testing.T) {
	srv := testServer("fs", true, nil, 3)
	src := &fixtureSource{
		servers: []*mcpagg.Server{srv},
		tools:   map[string][]mcpagg.ToolDescriptor{"fs": {{Name: "read_file"}}},
		errs:    map[string]error{"fs": errBoom},
	}
	r, _, s := newRunner(t, src)
	ctx := context.Background()

	report, err := r.Run(ctx, "org-run5")
	require.NoError(t, err, "a tool miss is a report entry, not an import failure")
	require.Len(t, report.Servers, 1)
	assert.Contains(t, report.Servers[0].Error, "boom")
	assert.Equal(t, ImportCounts{Created: 1}, report.Counts, "only the server row landed")

	// Upstream recovers on the next pass (config unchanged, but there is
	// no imported tool snapshot to skip against — the miss is retried).
	src.errs = nil
	report, err = r.Run(ctx, "org-run5")
	require.NoError(t, err)
	require.Len(t, report.Servers, 1)
	assert.Empty(t, report.Servers[0].Error)
	assert.Equal(t, 1, report.Servers[0].ToolsImported)

	rows, _, err := s.ListAssets(ctx, "org-run5", ListParams{Kind: KindTool})
	require.NoError(t, err)
	require.Len(t, rows, 1, "the recovered pass imported the tool")
}

func TestImportRunner_NewServerJoinsExistingOrg(t *testing.T) {
	src := &fixtureSource{
		servers: []*mcpagg.Server{testServer("fs", true, nil, 1)},
		tools:   map[string][]mcpagg.ToolDescriptor{"fs": {{Name: "read_file"}}},
	}
	r, _, _ := newRunner(t, src)
	ctx := context.Background()
	_, err := r.Run(ctx, "org-run6")
	require.NoError(t, err)

	// A second server registers later: only it triggers work; fs is
	// skipped against its unchanged snapshot.
	src.servers = append(src.servers, testServer("db", true, nil, 1))
	src.tools["db"] = []mcpagg.ToolDescriptor{{Name: "query"}}
	report, err := r.Run(ctx, "org-run6")
	require.NoError(t, err)
	require.Len(t, report.Servers, 2)
	assert.True(t, report.Servers[0].Skipped, "fs unchanged → skipped")
	assert.False(t, report.Servers[1].Skipped, "db is new → imported")
	assert.Equal(t, ImportCounts{Created: 2, Updated: 1}, report.Counts, "db server + db tool created; fs server row refreshed")
}

func TestImportRunner_EmptyOrgIsNoOpSuccess(t *testing.T) {
	src := &fixtureSource{}
	r, ct, _ := newRunner(t, src)
	report, err := r.Run(context.Background(), "org-run7")
	require.NoError(t, err)
	assert.Empty(t, report.Servers)
	assert.Empty(t, ct.calls)
	assert.Equal(t, ImportCounts{}, report.Counts)
}

func TestNewImportRunner_NilSeams(t *testing.T) {
	s := newTestStore(t)
	src := &fixtureSource{}
	_, err := NewImportRunner(nil, src, src)
	require.ErrorIs(t, err, ErrNilStore)
	_, err = NewImportRunner(s, nil, src)
	require.ErrorIs(t, err, ErrNilSource)
	_, err = NewImportRunner(s, src, nil)
	require.ErrorIs(t, err, ErrNilSource)
}

func TestServerConfigMoved(t *testing.T) {
	snap := serverSnapshot{ConfigVersion: 3, AllowedTools: []string{"a"}}
	assert.True(t, serverConfigMoved(nil, snap), "no prior snapshot → refresh")
	assert.False(t, serverConfigMoved(&Row{Payload: []byte(`{"config_version":3,"allowed_tools":["a"],"tools_synced":true}`)}, snap))
	assert.True(t, serverConfigMoved(&Row{Payload: []byte(`{"config_version":3,"allowed_tools":["a"]}`)}, snap), "unsynced snapshot (tool miss last pass) → retry")
	assert.True(t, serverConfigMoved(&Row{Payload: []byte(`{"config_version":4,"allowed_tools":["a"],"tools_synced":true}`)}, snap), "version bump → refresh")
	assert.True(t, serverConfigMoved(&Row{Payload: []byte(`{"config_version":3,"allowed_tools":["a","b"],"tools_synced":true}`)}, snap), "allow-list delta → refresh")
	assert.True(t, serverConfigMoved(&Row{Payload: []byte(`not json`)}, snap), "unreadable prior state → refresh")
}

// errBoom is the fixture upstream failure.
var errBoom = &staticError{"boom: upstream unreachable"}

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }
