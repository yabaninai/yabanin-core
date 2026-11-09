package mcpagg

// disposable, fully migrated Postgres (testdb.Postgres, no build tag — the
// harness posture of pkg/adminstore sqlcontract_int_test.go). Every exported
// store method (servers and per-agent grants) runs against the production
// SQL with present/disabled/missing combinations and every partial-update
// placeholder shape, failing on any *pgconn.PgError (rejected
// columns/types/placeholders). Business errors (ErrNotFound, duplicate
// names) are asserted where they pin the semantics.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlc03fMCPContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError); other errors are business answers and only logged.
func sqlc03fMCPContract(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Errorf("%s: Postgres rejected the SQL: %s (code %s, where %s, detail %q)",
			name, pgErr.Message, pgErr.Code, pgErr.Where, pgErr.Detail)
		return
	}
	t.Logf("%s: non-SQL error tolerated by the contract: %v", name, err)
}

type sqlc03fMCPFixture struct {
	Token          string
	OrgA, OrgB     string
	AgentA, AgentB string // agent_keys ids
	Missing        string // a name that never exists
}

func sqlc03fMCPSeed(t *testing.T, pool *pgxpool.Pool) *sqlc03fMCPFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("sc03f%x", time.Now().UnixNano())
	fx := &sqlc03fMCPFixture{
		Token:   token,
		Missing: token + "-missing",
	}
	orgID := func(name string) string {
		var id string
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, name).Scan(&id))
		return id
	}
	fx.OrgA = orgID(token + "-org-a")
	fx.OrgB = orgID(token + "-org-b")
	agent := func(name string) string {
		var id string
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			fx.OrgA, name, name+"-hash").Scan(&id))
		return id
	}
	fx.AgentA = agent(token + "-agent-a")
	fx.AgentB = agent(token + "-agent-b")

	// alpha enabled with a tool allow-list; beta registered but disabled.
	_, err := pool.Exec(ctx, `
		INSERT INTO mcp_servers (org_id, name, display_name, url, transport, allowed_tools, enabled)
		VALUES ($1::uuid, $2, 'Contract MCP A', 'https://mcp.example.com', 'http-sse', '["search"]'::jsonb, true),
		       ($1::uuid, $3, 'Contract MCP B', 'https://mcp.example.com/b', 'http-sse', '[]'::jsonb, false)`,
		fx.OrgA, token+"-alpha", token+"-beta")
	require.NoError(t, err)
	// Grants: agentA→alpha enabled; agentB→alpha disabled.
	_, err = pool.Exec(ctx, `
		INSERT INTO mcp_server_grants (org_id, agent_id, server_name, allowed_tools, enabled)
		VALUES ($1::uuid, $2::uuid, $4, '[]'::jsonb, true),
		       ($1::uuid, $3::uuid, $4, '["search"]'::jsonb, false)`,
		fx.OrgA, fx.AgentA, fx.AgentB, token+"-alpha")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("mcpagg contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM mcp_server_grants WHERE org_id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
		cleanup(`DELETE FROM mcp_servers WHERE org_id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
		cleanup(`DELETE FROM agent_keys WHERE key_hash LIKE $1`, token+"%")
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{fx.OrgA, fx.OrgB})
	})
	return fx
}

func TestSQLContractMCPAgg(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := sqlc03fMCPSeed(t, pool)
	ctx := context.Background()
	store := NewStore(pool)

	// --- Servers.
	sqlc03fMCPContract(t, "Create[gamma]", func(ctx context.Context) error {
		srv, err := store.Create(ctx, CreateParams{
			OrgID: fx.OrgA, Name: fx.Token + "-gamma", URL: "https://mcp.example.com/g",
			AllowedTools: nil, Enabled: true,
		})
		if err != nil {
			return err
		}
		assert.Equal(t, TransportHTTP, srv.Transport, "the default transport lands in the CHECK-constrained column")
		return nil
	})
	_, err := store.Create(ctx, CreateParams{OrgID: fx.OrgA, Name: fx.Token + "-gamma", URL: "https://mcp.example.com"})
	require.ErrorContains(t, err, "already exists", "Create[duplicate] is a typed conflict")

	sqlc03fMCPContract(t, "GetEnabled[alpha]", func(ctx context.Context) error {
		srv, err := store.GetEnabled(ctx, fx.OrgA, fx.Token+"-alpha")
		if err != nil {
			return err
		}
		if assert.NotNil(t, srv) {
			assert.Equal(t, []string{"search"}, srv.AllowedTools)
		}
		return nil
	})
	_, err = store.GetEnabled(ctx, fx.OrgA, fx.Token+"-beta")
	require.ErrorIs(t, err, ErrNotFound, "GetEnabled[disabled] must not reveal the row")
	_, err = store.GetEnabled(ctx, fx.OrgA, fx.Missing)
	require.ErrorIs(t, err, ErrNotFound, "GetEnabled[missing]")

	sqlc03fMCPContract(t, "Get[alpha]", func(ctx context.Context) error {
		_, err := store.Get(ctx, fx.OrgA, fx.Token+"-alpha")
		return err
	})
	sqlc03fMCPContract(t, "Get[beta,disabled]", func(ctx context.Context) error {
		srv, err := store.Get(ctx, fx.OrgA, fx.Token+"-beta")
		if err != nil {
			return err
		}
		assert.False(t, srv.Enabled)
		return nil
	})
	_, err = store.Get(ctx, fx.OrgA, fx.Missing)
	require.ErrorIs(t, err, ErrNotFound, "Get[missing]")

	sqlc03fMCPContract(t, "List[orgA]", func(ctx context.Context) error {
		servers, err := store.List(ctx, fx.OrgA)
		if err != nil {
			return err
		}
		assert.GreaterOrEqual(t, len(servers), 3, "alpha, beta and the created gamma")
		return nil
	})
	sqlc03fMCPContract(t, "List[orgB,empty]", func(ctx context.Context) error {
		servers, err := store.List(ctx, fx.OrgB)
		if err != nil {
			return err
		}
		assert.Empty(t, servers)
		return nil
	})

	// Update — every partial combination re-shapes the placeholder list.
	newURL := "https://mcp.example.com/g2"
	newTools := []string{"search", "fetch"}
	enabled := false
	display := "Gamma MCP"
	transport := TransportHTTP
	for _, tc := range []struct {
		name string
		p    UpdateParams
	}{
		{"url", UpdateParams{URL: &newURL}},
		{"tools", UpdateParams{AllowedTools: &newTools}},
		{"enabled", UpdateParams{Enabled: &enabled}},
		{"display-name", UpdateParams{DisplayName: &display}},
		{"transport", UpdateParams{Transport: &transport}},
		{"all", UpdateParams{DisplayName: &display, URL: &newURL, Transport: &transport, AllowedTools: &newTools, Enabled: &enabled}},
		{"none", UpdateParams{}},
	} {
		sqlc03fMCPContract(t, "Update[gamma,"+tc.name+"]", func(ctx context.Context) error {
			srv, err := store.Update(ctx, fx.OrgA, fx.Token+"-gamma", tc.p)
			if err != nil {
				return err
			}
			assert.Equal(t, fx.Token+"-gamma", srv.Name)
			return nil
		})
	}
	_, err = store.Update(ctx, fx.OrgA, fx.Missing, UpdateParams{})
	require.ErrorIs(t, err, ErrNotFound, "Update[missing]")

	sqlc03fMCPContract(t, "Delete[gamma]", func(ctx context.Context) error {
		return store.Delete(ctx, fx.OrgA, fx.Token+"-gamma")
	})
	err = store.Delete(ctx, fx.OrgA, fx.Token+"-gamma")
	require.ErrorIs(t, err, ErrNotFound, "Delete[already removed]")

	// --- Grants.
	sqlc03fMCPContract(t, "CreateGrant[agentB,beta]", func(ctx context.Context) error {
		grant, err := store.CreateGrant(ctx, GrantCreateParams{
			OrgID: fx.OrgA, AgentID: fx.AgentB, ServerName: fx.Token + "-beta", AllowedTools: nil, Enabled: true})
		if err != nil {
			return err
		}
		assert.Equal(t, fx.Token+"-beta", grant.ServerName)
		return nil
	})
	_, err = store.CreateGrant(ctx, GrantCreateParams{OrgID: fx.OrgA, AgentID: fx.AgentA, ServerName: fx.Token + "-alpha"})
	require.ErrorContains(t, err, "already exists", "CreateGrant[duplicate] is a typed conflict")

	sqlc03fMCPContract(t, "GetEnabledGrant[agentA,alpha]", func(ctx context.Context) error {
		grant, err := store.GetEnabledGrant(ctx, fx.OrgA, fx.AgentA, fx.Token+"-alpha")
		if err != nil {
			return err
		}
		assert.True(t, grant.Enabled)
		return nil
	})
	_, err = store.GetEnabledGrant(ctx, fx.OrgA, fx.AgentB, fx.Token+"-alpha")
	require.ErrorIs(t, err, ErrNotFound, "GetEnabledGrant[disabled grant] must read as no access")
	_, err = store.GetEnabledGrant(ctx, fx.OrgA, fx.AgentA, fx.Missing)
	require.ErrorIs(t, err, ErrNotFound, "GetEnabledGrant[missing]")

	sqlc03fMCPContract(t, "GetGrant[disabled]", func(ctx context.Context) error {
		grant, err := store.GetGrant(ctx, fx.OrgA, fx.AgentB, fx.Token+"-alpha")
		if err != nil {
			return err
		}
		assert.False(t, grant.Enabled)
		return nil
	})
	_, err = store.GetGrant(ctx, fx.OrgA, fx.AgentA, fx.Missing)
	require.ErrorIs(t, err, ErrNotFound, "GetGrant[missing]")

	// List checks run before the UpdateGrant loop below disables the
	// agentA grant — ListGrantsForAgent serves enabled rows only.
	sqlc03fMCPContract(t, "ListGrantsForAgent[agentA]", func(ctx context.Context) error {
		grants, err := store.ListGrantsForAgent(ctx, fx.OrgA, fx.AgentA)
		if err != nil {
			return err
		}
		assert.Len(t, grants, 1, "only the enabled grant is served to the agent")
		return nil
	})
	sqlc03fMCPContract(t, "ListGrantsForAgent[orgB,empty]", func(ctx context.Context) error {
		grants, err := store.ListGrantsForAgent(ctx, fx.OrgB, fx.AgentA)
		if err != nil {
			return err
		}
		assert.Empty(t, grants)
		return nil
	})
	sqlc03fMCPContract(t, "ListGrantsForServer[alpha]", func(ctx context.Context) error {
		grants, err := store.ListGrantsForServer(ctx, fx.OrgA, fx.Token+"-alpha")
		if err != nil {
			return err
		}
		assert.Len(t, grants, 2, "both grants regardless of enabled state")
		return nil
	})
	sqlc03fMCPContract(t, "ListGrantsForServer[beta]", func(ctx context.Context) error {
		grants, err := store.ListGrantsForServer(ctx, fx.OrgA, fx.Token+"-beta")
		if err != nil {
			return err
		}
		assert.Len(t, grants, 1, "the created beta grant is listed for admins")
		return nil
	})
	sqlc03fMCPContract(t, "ListGrantsForServer[no-grants,empty]", func(ctx context.Context) error {
		grants, err := store.ListGrantsForServer(ctx, fx.OrgA, fx.Missing)
		if err != nil {
			return err
		}
		assert.Empty(t, grants)
		return nil
	})

	grantTools := []string{"fetch"}
	grantEnabled := false
	for _, tc := range []struct {
		name string
		p    GrantUpdateParams
	}{
		{"tools", GrantUpdateParams{AllowedTools: &grantTools}},
		{"enabled", GrantUpdateParams{Enabled: &grantEnabled}},
		{"all", GrantUpdateParams{AllowedTools: &grantTools, Enabled: &grantEnabled}},
		{"none", GrantUpdateParams{}},
	} {
		sqlc03fMCPContract(t, "UpdateGrant[agentA,alpha,"+tc.name+"]", func(ctx context.Context) error {
			grant, err := store.UpdateGrant(ctx, fx.OrgA, fx.AgentA, fx.Token+"-alpha", tc.p)
			if err != nil {
				return err
			}
			assert.Equal(t, fx.Token+"-alpha", grant.ServerName)
			return nil
		})
	}
	_, err = store.UpdateGrant(ctx, fx.OrgA, fx.AgentA, fx.Missing, GrantUpdateParams{})
	require.ErrorIs(t, err, ErrNotFound, "UpdateGrant[missing]")

	sqlc03fMCPContract(t, "DeleteGrant[agentB,beta]", func(ctx context.Context) error {
		return store.DeleteGrant(ctx, fx.OrgA, fx.AgentB, fx.Token+"-beta")
	})
	err = store.DeleteGrant(ctx, fx.OrgA, fx.AgentB, fx.Token+"-beta")
	require.ErrorIs(t, err, ErrNotFound, "DeleteGrant[already removed]")
}
