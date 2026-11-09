package toolpolicy

// the admin CRUD (Store.Create through the tx-pinned app.current_org GUC)
// must land under the tool_policies org_isolation RLS and drive the engine
// verdicts of EXACTLY their own org, both directions, across cache
// refills. This is the mutation anchor for the G4 mechanism: neutering the
// withOrgTx org pin must break the writes (the RLS WITH CHECK arm rejects
// an insert under a foreign/empty org) and with them this whole scenario
// The boundary matrix
// stays in rls_boundary_int_test.go / rls_int_test.go.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestToolPolicies_Regression_CRUDToEnginePerOrg_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	appStore := NewStore(testdb.PostgresApp(t, "test"))
	ctx := context.Background()

	var orgA, orgB string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ('r035-reg-a', 'r035-reg-a') RETURNING id::text`).Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ('r035-reg-b', 'r035-reg-b') RETURNING id::text`).Scan(&orgB))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tool_policies WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})

	// Admin CRUD writes THROUGH the pinned tx (the RLS WITH CHECK arm must
	// accept an org-pinned insert): orgA gets the per-tool allow pair plus
	// a per-argument guard row; orgB denies the same delete coordinates
	// orgA allows.
	allowRow, err := appStore.Create(ctx, CreateParams{OrgID: orgA, Name: "a-allow-github",
		Subject: "*", Server: "github", Tool: "*", Action: "allow", Enabled: true})
	require.NoError(t, err, "org-pinned insert must pass the RLS WITH CHECK arm")
	require.Equal(t, orgA, allowRow.OrgID)
	_, err = appStore.Create(ctx, CreateParams{OrgID: orgA, Name: "a-guard-create",
		Subject: "*", Server: "github", Tool: "create_issue", Action: "allow",
		Rules:   json.RawMessage(`{"args":{"schema":{"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false},"deny_regex":["BEGIN (RSA )?PRIVATE KEY"]}}`),
		Enabled: true})
	require.NoError(t, err)
	_, err = appStore.Create(ctx, CreateParams{OrgID: orgB, Name: "b-deny-delete",
		Subject: "*", Server: "github", Tool: "delete_issue", Action: "deny", Enabled: true})
	require.NoError(t, err)

	engine := NewEngine(appStore, 0)

	// orgA: the working path passes, the guard-rule inputs deny (per-tool
	// AND per-argument permissions, end-to-end through RLS).
	rep := engine.GuardArgs(ctx, orgA, "ag-1", "github", "create_issue", json.RawMessage(`{"title":"t"}`))
	assert.False(t, rep.Denied, "valid args must pass: %+v", rep)
	rep = engine.GuardArgs(ctx, orgA, "ag-1", "github", "create_issue",
		json.RawMessage(`{"body":"BEGIN RSA PRIVATE KEY ..."}`))
	assert.True(t, rep.Denied, "secret-bearing args must deny: %+v", rep)
	rep = engine.GuardArgs(ctx, orgA, "ag-1", "github", "delete_issue", json.RawMessage(`{}`))
	assert.False(t, rep.Denied, "orgA allows delete_issue: %+v", rep)

	// orgB: its own deny fires; orgA's rows never leak into the verdict.
	rep = engine.GuardArgs(ctx, orgB, "ag-1", "github", "delete_issue", json.RawMessage(`{}`))
	assert.True(t, rep.Denied, "orgB's own deny must fire: %+v", rep)
	rep = engine.GuardArgs(ctx, orgB, "ag-1", "github", "create_issue", json.RawMessage(`{"title":"t"}`))
	assert.False(t, rep.Denied, "orgA's guard row must not restrict orgB: %+v", rep)

	// Cache refills (admin CRUD invalidation parity) reload through RLS —
	// the verdicts persist.
	engine.Invalidate(orgA)
	engine.Invalidate(orgB)
	rep = engine.GuardArgs(ctx, orgA, "ag-1", "github", "delete_issue", json.RawMessage(`{}`))
	assert.False(t, rep.Denied, "orgA allow must survive a refill: %+v", rep)
	rep = engine.GuardArgs(ctx, orgB, "ag-1", "github", "delete_issue", json.RawMessage(`{}`))
	assert.True(t, rep.Denied, "orgB deny must survive a refill: %+v", rep)

	// The store view is org-scoped under RLS: exactly the org's own rows.
	rowsA, err := appStore.ListEnabled(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, rowsA, 2)
	assert.Equal(t, "a-allow-github", rowsA[0].Name, "stable name order")
	rowsB, err := appStore.ListEnabled(ctx, orgB)
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	assert.Equal(t, "b-deny-delete", rowsB[0].Name)
}
