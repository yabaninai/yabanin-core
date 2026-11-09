package toolpolicy

// The cross-org boundary of the
// RUNTIME policy path end-to-end — RLS (0002 org_isolation) + the
// tx-pinned store + the engine cache. An org's engine must load ONLY its
// own rows: a foreign org's deny row must be invisible (its calls stay
// allowed) across cache refills, and the bound org's own deny must fire —
// a cross-org leak or a wrong deny would both read as policy outcomes, so
// both directions are pinned.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestToolPolicies_RLS_EngineLoadsOnlyOwnOrgRows_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	appStore := NewStore(testdb.PostgresApp(t, "test"))
	ctx := context.Background()

	var orgA, orgB string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ('r035-eng-a', 'r035-eng-a') RETURNING id::text`).Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ('r035-eng-b', 'r035-eng-b') RETURNING id::text`).Scan(&orgB))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tool_policies WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})

	// orgB: deny github/search. orgA: an unrelated allow row on the same
	// coordinates — if either org ever loaded the other's rows, the verdicts
	// below would flip.
	_, err := appStore.Create(ctx, CreateParams{OrgID: orgB, Name: "b-deny-search", Subject: "*",
		Server: "github", Tool: "search", Action: "deny", Enabled: true})
	require.NoError(t, err)
	_, err = appStore.Create(ctx, CreateParams{OrgID: orgA, Name: "a-allow-search", Subject: "*",
		Server: "github", Tool: "search", Action: "allow", Enabled: true})
	require.NoError(t, err)

	engine := NewEngine(appStore, 0)

	assertAllowed := func(org string) {
		t.Helper()
		rep := engine.GuardArgs(ctx, org, "ag-1", "github", "search", json.RawMessage(`{"q":"x"}`))
		assert.False(t, rep.Denied, "%s must not see a foreign deny: %+v", org, rep)
		assert.False(t, rep.Degraded, "%s loader must stay healthy: %+v", org, rep)
	}

	// Fresh loads: each org sees exactly its own row.
	assertAllowed(orgA)
	if rep := engine.GuardArgs(ctx, orgB, "ag-1", "github", "search", json.RawMessage(`{}`)); !rep.Denied {
		t.Fatalf("orgB's own deny must fire: %+v", rep)
	}

	// Cache refills (admin CRUD invalidation parity) must not cross the
	// tenant boundary: evict both, reload, re-assert both directions.
	engine.Invalidate(orgA)
	engine.Invalidate(orgB)
	assertAllowed(orgA)
	if rep := engine.GuardArgs(ctx, orgB, "ag-1", "github", "search", json.RawMessage(`{}`)); !rep.Denied {
		t.Fatalf("orgB's deny must survive a refill: %+v", rep)
	}

	// The loader view itself (the engine's only data source) is org-scoped
	// under RLS: no row of the foreign org is ever returned.
	rowsA, err := appStore.ListEnabled(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, rowsA, 1)
	assert.Equal(t, "a-allow-search", rowsA[0].Name)
	rowsB, err := appStore.ListEnabled(ctx, orgB)
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	assert.Equal(t, "b-deny-search", rowsB[0].Name)
}
