package inventory

// E02-P01 W02-C01: MCP registry import tests. Builders are exercised
// purely (key formats, allow-list intersection, drop rules); the driver
// runs against the real store over the migration stand (atomic upsert,
// per-server miss reporting, empty upstream rule).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureSource answers from fixed tables.
type fixtureSource struct {
	servers []*mcpagg.Server
	tools   map[string][]mcpagg.ToolDescriptor
	errs    map[string]error // per-server listing failure
}

func (f *fixtureSource) List(context.Context, string) ([]*mcpagg.Server, error) {
	return f.servers, nil
}

func (f *fixtureSource) ListTools(_ context.Context, _, server string) ([]mcpagg.ToolDescriptor, error) {
	if err, ok := f.errs[server]; ok {
		return nil, err
	}
	return f.tools[server], nil
}

func impAt() Timestamps {
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	return Timestamps{FirstSeen: at, LastSeen: at}
}

func testServer(name string, enabled bool, allowed []string, v int64) *mcpagg.Server {
	return &mcpagg.Server{ID: "srv-" + name, OrgID: "org-mcpimp", Name: name,
		URL: "https://upstream.example.com/" + name, Transport: "http",
		AllowedTools: allowed, Enabled: enabled, CredentialMode: "auto", ConfigVersion: v}
}

func TestMCPKeysAreDeterministic(t *testing.T) {
	assert.Equal(t, "mcp_server:fs", MCPServerKey("fs"))
	assert.Equal(t, "mcp_tool:fs/read_file", MCPToolKey("fs", "read_file"))
}

func TestBuildMCPImportAssets_ServerRowAndToolRows(t *testing.T) {
	at := impAt()
	srv := testServer("fs", true, nil, 7)
	assets, dropped, err := BuildMCPImportAssets(at, "org-mcpimp", srv,
		[]mcpagg.ToolDescriptor{
			{Name: "read_file", Description: "Read a file", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "write_file"},
		}, nil, true)
	require.NoError(t, err)

	require.Empty(t, dropped)
	require.Len(t, assets, 3)

	assert.Equal(t, KindMCPServer, assets[0].Kind)
	assert.Equal(t, "mcp_server:fs", assets[0].AssetKey)
	var sp MCPServerPayload
	require.NoError(t, json.Unmarshal(assets[0].Payload, &sp))
	assert.Equal(t, "fs", sp.Name)
	assert.True(t, sp.Enabled)
	assert.EqualValues(t, 7, sp.ConfigVersion)
	require.NoError(t, assets[0].Validate(), "server asset must satisfy the write model")

	assert.Equal(t, KindTool, assets[1].Kind)
	assert.Equal(t, "mcp_tool:fs/read_file", assets[1].AssetKey)
	var tp MCPToolPayload
	require.NoError(t, json.Unmarshal(assets[1].Payload, &tp))
	assert.Equal(t, "fs", tp.Server)
	assert.Equal(t, "Read a file", tp.Description)
	require.NoError(t, assets[1].Validate())
}

func TestBuildMCPImportAssets_AllowListFiltersTools(t *testing.T) {
	at := impAt()
	srv := testServer("fs", true, []string{"read_file"}, 2) // configured surface
	assets, dropped, err := BuildMCPImportAssets(at, "org-mcpimp", srv,
		[]mcpagg.ToolDescriptor{{Name: "read_file"}, {Name: "rm_rf"}}, srv.AllowedTools, true)
	require.NoError(t, err)

	require.Empty(t, dropped, "rm_rf is filtered by the allow-list, not dropped as invalid")
	require.Len(t, assets, 2, "server row + only the allow-listed tool")
	assert.Equal(t, "mcp_tool:fs/read_file", assets[1].AssetKey)
}

func TestBuildMCPImportAssets_InvalidToolNameIsDroppedNotFatal(t *testing.T) {
	at := impAt()
	srv := testServer("fs", true, nil, 1)
	assets, dropped, err := BuildMCPImportAssets(at, "org-mcpimp", srv,
		[]mcpagg.ToolDescriptor{{Name: "bad name\nwith newline"}, {Name: "ok_tool"}}, nil, true)
	require.NoError(t, err)

	assert.Equal(t, []string{"bad name\nwith newline"}, dropped, "the invalid descriptor is reported")
	assert.Len(t, assets, 2, "server row + the valid tool still import")
}

func TestBuildMCPImportAssets_EmptyUpstreamImportsServerIdentity(t *testing.T) {
	at := impAt()
	srv := testServer("lonely", false, nil, 1)
	assets, dropped, err := BuildMCPImportAssets(at, "org-mcpimp", srv, nil, nil, true)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	require.Len(t, assets, 1, "no tools advertised → the server identity still lands")
	var sp MCPServerPayload
	require.NoError(t, json.Unmarshal(assets[0].Payload, &sp))
	assert.False(t, sp.Enabled, "disabled state is observable in the payload")
}

func TestImportMCPRegistry_UpsertsAndReports(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	src := &fixtureSource{
		servers: []*mcpagg.Server{
			testServer("fs", true, nil, 3),
			testServer("db", true, nil, 1),
		},
		tools: map[string][]mcpagg.ToolDescriptor{
			"fs": {{Name: "read_file"}, {Name: "write_file"}},
		},
		errs: map[string]error{"db": errors.New("upstream unreachable")},
	}

	report, err := ImportMCPRegistry(ctx, s, "org-mcpimp", src, src, impAt())
	require.NoError(t, err)

	// fs: 1 server + 2 tools created; db: server row created, tools missed.
	require.Len(t, report.Servers, 2)
	fsRes, dbRes := report.Servers[0], report.Servers[1]
	assert.Equal(t, "fs", fsRes.Name)
	assert.Equal(t, 2, fsRes.ToolsImported)
	assert.Empty(t, fsRes.Error)
	assert.Equal(t, "db", dbRes.Name)
	assert.Contains(t, dbRes.Error, "unreachable")
	assert.Equal(t, ImportCounts{Created: 4}, report.Counts)

	rows, _, err := s.ListAssets(ctx, "org-mcpimp", ListParams{})
	require.NoError(t, err)
	require.Len(t, rows, 4)
	keys := []string{rows[0].AssetKey, rows[1].AssetKey, rows[2].AssetKey, rows[3].AssetKey}
	assert.ElementsMatch(t, []string{"mcp_server:db", "mcp_server:fs", "mcp_tool:fs/read_file", "mcp_tool:fs/write_file"}, keys)

	// Idempotent second pass: everything unchanged.
	report2, err := ImportMCPRegistry(ctx, s, "org-mcpimp", src, src, impAt())
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Unchanged: 4}, report2.Counts, "a pass with no changes refreshes nothing")
}

func TestImportMCPRegistry_EmptyUpstreamIsSuccessWithEmptyReport(t *testing.T) {
	s := newTestStore(t)
	src := &fixtureSource{} // no servers at all
	report, err := ImportMCPRegistry(context.Background(), s, "org-mcpimp2", src, src, impAt())
	require.NoError(t, err, "empty upstream is a successful no-op, never an error")
	assert.Empty(t, report.Servers)
	assert.Equal(t, ImportCounts{}, report.Counts)
}

func TestImportMCPRegistry_NilSeams(t *testing.T) {
	s := newTestStore(t)
	src := &fixtureSource{}
	_, err := ImportMCPRegistry(context.Background(), nil, "org-mcpimp2", src, src, impAt())
	require.ErrorIs(t, err, ErrNilStore)
	_, err = ImportMCPRegistry(context.Background(), s, "org-mcpimp2", nil, src, impAt())
	require.ErrorIs(t, err, ErrNilSource)
	_, err = ImportMCPRegistry(context.Background(), s, "org-mcpimp2", src, nil, impAt())
	require.ErrorIs(t, err, ErrNilSource)
}
