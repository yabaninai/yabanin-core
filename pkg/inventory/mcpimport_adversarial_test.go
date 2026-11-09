package inventory

// E02-P01 W02-C03: adversarial battery for the MCP import path. The
// upstream (a hostile or broken MCP server / registry seam) must never be
// able to (a) fail the org's import, (b) smuggle an invalid asset into
// the registry, or (c) conflate two distinct identities into one key.
// Every hostile descriptor is either imported validly or reported — never
// silently discarded.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostileServer builds a server with an arbitrary (rule-breaking) name —
// only reachable through a broken ServerSource, which is exactly the
// posture under test.
func hostileServer(name string) *mcpagg.Server {
	s := testServer(name, true, nil, 1)
	return s
}

func TestAdversarial_InvalidServerNamesAreRejectedNotImported(t *testing.T) {
	at := impAt()
	for _, name := range []string{
		"",                       // empty
		"Bad Name",               // whitespace
		"a/b",                    // slash — would conflate tool keys
		"mcp_server:fs",          // colon injection into the key prefix
		strings.Repeat("x", 257), // oversize
		"ctrl\nname",             // control character
	} {
		assets, dropped, err := BuildMCPImportAssets(at, "org-adv", hostileServer(name),
			[]mcpagg.ToolDescriptor{{Name: "t"}}, nil, true)
		require.Error(t, err, "server name %q must be rejected", name)
		assert.Nil(t, assets, "no rows may land for a rejected server")
		assert.Nil(t, dropped)
	}
}

func TestAdversarial_SlashServerNameCannotConflateToolIdentities(t *testing.T) {
	at := impAt()
	// server "a" + tool "b/c" produces mcp_tool:a/b/c; a server literally
	// named "a/b" would produce a colliding tool namespace — it must be
	// rejected so the key grammar stays injective.
	_, _, err := BuildMCPImportAssets(at, "org-adv", hostileServer("a/b"),
		[]mcpagg.ToolDescriptor{{Name: "c"}}, nil, true)
	require.Error(t, err)

	assets, dropped, err := BuildMCPImportAssets(at, "org-adv", testServer("a", true, nil, 1),
		[]mcpagg.ToolDescriptor{{Name: "b/c"}}, nil, true)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	assert.Equal(t, "mcp_tool:a/b/c", assets[1].AssetKey)
	assert.Empty(t, dropped, "a slash in a TOOL name is legal: server names cannot contain one, so the split at the first '/' is unambiguous")
}

func TestAdversarial_DuplicateToolNamesDedupedNotBatchFailed(t *testing.T) {
	// The same tool advertised twice would address one conflict key twice
	// inside a single upsert statement ("cannot affect row a second
	// time") and abort the WHOLE org import. The builder must dedupe.
	at := impAt()
	assets, dropped, err := BuildMCPImportAssets(at, "org-adv", testServer("fs", true, nil, 1),
		[]mcpagg.ToolDescriptor{
			{Name: "read_file", Description: "first"},
			{Name: "list_dir"},
			{Name: "read_file", Description: "second"}, // duplicate
			{Name: "read_file"},                        // duplicate
		}, nil, true)
	require.NoError(t, err)
	require.Len(t, assets, 3, "server row + each distinct tool exactly once")
	assert.Equal(t, []string{"read_file", "read_file"}, dropped, "duplicates are reported, never silent")
	require.NoError(t, assets[1].Validate())

	// First occurrence wins (deterministic).
	var tp MCPToolPayload
	require.NoError(t, json.Unmarshal(assets[1].Payload, &tp))
	assert.Equal(t, "first", tp.Description)
}

func TestAdversarial_CorruptInputSchemaIsDroppedNotFatal(t *testing.T) {
	at := impAt()
	assets, dropped, err := BuildMCPImportAssets(at, "org-adv", testServer("fs", true, nil, 1),
		[]mcpagg.ToolDescriptor{
			{Name: "good_tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "bad_schema", InputSchema: json.RawMessage(`{not json`)},
		}, nil, true)
	require.NoError(t, err, "one corrupt descriptor must not fail the batch")
	require.Len(t, assets, 2)
	assert.Equal(t, []string{"bad_schema"}, dropped)
	require.NoError(t, assets[1].Validate(), "the surviving tool payload is a valid JSON object")
}

func TestAdversarial_ToolNameBoundaries(t *testing.T) {
	at := impAt()
	max := strings.Repeat("t", 256)  // validKeyPart limit
	over := strings.Repeat("t", 257) // one past
	assets, dropped, err := BuildMCPImportAssets(at, "org-adv", testServer("fs", true, nil, 1),
		[]mcpagg.ToolDescriptor{{Name: max}, {Name: over}, {Name: ""}, {Name: "sp ace"}, {Name: "tab\tname"}},
		nil, true)
	require.NoError(t, err)
	require.Len(t, assets, 2, "server + only the 256-byte name")
	assert.Equal(t, []string{over, "", "sp ace", "tab\tname"}, dropped)
}

func TestAdversarial_HostileStringsInPayloadsAreJSONSafe(t *testing.T) {
	at := impAt()
	hostile := "quote\" backslash\\ newline\n control\x00 utf8-инъекция </script>"
	assets, _, err := BuildMCPImportAssets(at, "org-adv", testServer("fs", true, nil, 1),
		[]mcpagg.ToolDescriptor{{Name: "t", Description: hostile}}, nil, true)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	require.NoError(t, assets[1].Validate(), "payload stays valid JSON whatever the description contains")
	var tp MCPToolPayload
	require.NoError(t, json.Unmarshal(assets[1].Payload, &tp))
	assert.Equal(t, hostile, tp.Description, "round-trips byte-identical — no %q-style corruption")
}

func TestAdversarial_HostilePassImportSucceedsAndReportsEverything(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	src := &fixtureSource{
		servers: []*mcpagg.Server{
			testServer("good", true, nil, 1),
			hostileServer("a/b"), // whole server rejected
			hostileServer("Bad"), // whole server rejected
			testServer("mixed", true, nil, 1),
		},
		tools: map[string][]mcpagg.ToolDescriptor{
			"good":  {{Name: "ok"}},
			"mixed": {{Name: "fine"}, {Name: "dup"}, {Name: "dup"}, {Name: "bad name"}},
		},
	}

	report, err := ImportMCPRegistry(ctx, s, "org-adv2", src, src, impAt())
	require.NoError(t, err, "a hostile upstream must never fail the org import")
	require.Len(t, report.Servers, 4)

	// good: clean import.
	assert.Equal(t, "good", report.Servers[0].Name)
	assert.Equal(t, 1, report.Servers[0].ToolsImported)
	assert.Empty(t, report.Servers[0].Error)

	// rejected servers: reported errors, no rows.
	assert.NotEmpty(t, report.Servers[1].Error)
	assert.NotEmpty(t, report.Servers[2].Error)

	// mixed: valid tools land (fine + first dup occurrence), the second
	// duplicate and the invalid name are reported.
	assert.Equal(t, 2, report.Servers[3].ToolsImported)
	assert.Equal(t, 2, report.Servers[3].DroppedTools)
	assert.Empty(t, report.Servers[3].Error)

	// Exactly the valid identities landed: good + ok, mixed + fine/dup.
	rows, _, err := s.ListAssets(ctx, "org-adv2", ListParams{})
	require.NoError(t, err)
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, r.AssetKey)
	}
	assert.ElementsMatch(t, []string{
		"mcp_server:good", "mcp_tool:good/ok",
		"mcp_server:mixed", "mcp_tool:mixed/fine", "mcp_tool:mixed/dup",
	}, keys)
}

func TestAdversarial_RunnerSurvivesHostileSource(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	src := &fixtureSource{
		servers: []*mcpagg.Server{hostileServer("a/b"), testServer("good", true, nil, 1)},
		tools:   map[string][]mcpagg.ToolDescriptor{"good": {{Name: "ok"}}},
	}
	ct := newCountingTools(src)
	r, err := NewImportRunner(s, src, ct)
	require.NoError(t, err)

	report, err := r.Run(ctx, "org-adv3")
	require.NoError(t, err, "the runner reports hostile servers, it does not fail")
	require.Len(t, report.Servers, 2)
	assert.NotEmpty(t, report.Servers[0].Error, "the hostile server is reported")
	assert.Equal(t, 1, report.Servers[1].ToolsImported)
	assert.Equal(t, ImportCounts{Created: 2}, report.Counts)

	// A hostile server never lands a row, so it is retried every pass —
	// it must not poison the well server's incrementality.
	_, err = r.Run(ctx, "org-adv3")
	require.NoError(t, err)
	assert.Equal(t, 1, ct.calls["good"], "the well-behaved server is still skipped after its synced pass")
}
