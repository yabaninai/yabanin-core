package mcpagg

// AUTH-02 integration: DelegationChainAllowance against the REAL SQL — the
// recursive agent_keys walk joined to mcp_server_grants — over a disposable
// migrated Postgres (testdb.Postgres, same harness posture as
// sqlcontract_int_test.go). Pins the fail-closed semantics the mock layer
// cannot prove: chain intersection per server, missing/disabled ancestor
// grants, revoked ancestors, foreign-org parent links, and the
// unknown-key ErrNotFound.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type auth02ChainFixture struct {
	prefix                     string
	orgA, orgB                 string
	rootA, childA, grandchildA string // active chain
	rootRevoked, childRev      string // revoked-ancestor chain
	rootForeign                string // orgB key whose parent lives in orgA
	alpha, beta, gamma         string // server names
}

func auth02ChainSeed(t *testing.T, pool *pgxpool.Pool) *auth02ChainFixture {
	t.Helper()
	ctx := context.Background()
	prefix := "auth02-chain" // mcp_servers_name_check: lowercase [a-z0-9_-]; disposable DB, no collisions
	fx := &auth02ChainFixture{prefix: prefix}

	orgID := func(name string) string {
		var id string
		require.NoError(t, pool.QueryRow(ctx,
			`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, name).Scan(&id))
		return id
	}
	fx.orgA = orgID(prefix + "-org-a")
	fx.orgB = orgID(prefix + "-org-b")

	agent := func(orgID, name string, parent *string, active bool) string {
		var id string
		if parent != nil {
			require.NoError(t, pool.QueryRow(ctx, `
				INSERT INTO agent_keys (org_id, name, key_hash, parent_id, active)
				VALUES ($1::uuid, $2, $3, $4::uuid, $5::boolean) RETURNING id::text`,
				orgID, name, name+"-hash", parent, active).Scan(&id))
			return id
		}
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO agent_keys (org_id, name, key_hash, active)
			VALUES ($1::uuid, $2, $3, $4::boolean) RETURNING id::text`,
			orgID, name, name+"-hash", active).Scan(&id))
		return id
	}
	fx.rootA = agent(fx.orgA, prefix+"-root", nil, true)
	fx.childA = agent(fx.orgA, prefix+"-child", &fx.rootA, true)
	fx.grandchildA = agent(fx.orgA, prefix+"-grand", &fx.childA, true)
	// The revoked chain: root is inactive, its child is active. The active
	// child's walk must NOT reach a root (the inactive root is excluded) →
	// fail closed even though its grant survives.
	fx.rootRevoked = agent(fx.orgA, prefix+"-root-rev", nil, false)
	fx.childRev = agent(fx.orgA, prefix+"-child-rev", &fx.rootRevoked, true)
	// A foreign-org parent link (only reachable through corrupt/direct SQL
	// data): an orgB key pointing at an orgA parent. The walk must treat the
	// missing orgB parent as a broken chain.
	fx.rootForeign = agent(fx.orgB, prefix+"-foreign", &fx.rootA, true)

	fx.alpha = prefix + "-alpha"
	fx.beta = prefix + "-beta"
	fx.gamma = prefix + "-gamma"
	_, err := pool.Exec(ctx, `
		INSERT INTO mcp_servers (org_id, name, url, transport, allowed_tools, enabled)
		VALUES ($1::uuid, $2, 'https://mcp.example.com/a', 'http-sse', '["search","delete"]'::jsonb, true),
		       ($1::uuid, $3, 'https://mcp.example.com/b', 'http-sse', '[]'::jsonb, true),
		       ($1::uuid, $4, 'https://mcp.example.com/c', 'http-sse', '[]'::jsonb, true)`,
		fx.orgA, fx.alpha, fx.beta, fx.gamma)
	require.NoError(t, err)

	// Grants (enabled unless stated):
	//   alpha: root ["search"] restricted, child unrestricted,
	//          grandchild ["search","delete"] → chain ∩ = ["search"];
	//   beta:  root + child unrestricted, grandchild MISSING;
	//   gamma: root + child enabled, grandchild DISABLED;
	//   alpha for childRev (under the revoked root): enabled, unrestricted.
	_, err = pool.Exec(ctx, `
		INSERT INTO mcp_server_grants (org_id, agent_id, server_name, allowed_tools, enabled)
		VALUES ($1::uuid, $2::uuid,  $6, '["search"]'::jsonb, true),        -- rootA→alpha
		       ($1::uuid, $3::uuid,  $6, '[]'::jsonb, true),                -- childA→alpha (all)
		       ($1::uuid, $4::uuid,  $6, '["search","delete"]'::jsonb, true), -- grandchildA→alpha
		       ($1::uuid, $2::uuid,  $7, '[]'::jsonb, true),           -- rootA→beta (all)
		       ($1::uuid, $3::uuid,  $7, '[]'::jsonb, true),           -- childA→beta (all)
		       ($1::uuid, $2::uuid,  $8, '[]'::jsonb, true),           -- rootA→gamma (all)
		       ($1::uuid, $3::uuid,  $8, '[]'::jsonb, true),           -- childA→gamma (all)
		       ($1::uuid, $4::uuid,  $8, '[]'::jsonb, false),          -- grandchildA→gamma DISABLED
		       ($1::uuid, $5::uuid,  $6, '[]'::jsonb, true)            -- childRev→alpha (all)
		`,
		fx.orgA, fx.rootA, fx.childA, fx.grandchildA, fx.childRev,
		fx.alpha, fx.beta, fx.gamma)
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("auth02 chain cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM mcp_server_grants WHERE org_id::text = ANY($1)`, []string{fx.orgA, fx.orgB})
		cleanup(`DELETE FROM mcp_servers WHERE org_id::text = ANY($1)`, []string{fx.orgA, fx.orgB})
		cleanup(`DELETE FROM agent_keys WHERE key_hash LIKE $1`, prefix+"%")
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{fx.orgA, fx.orgB})
	})
	return fx
}

func TestAuth02ChainAllowance_RealSQL(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := auth02ChainSeed(t, pool)
	store := NewStore(pool)
	ctx := context.Background()

	t.Run("root alone: own grants only", func(t *testing.T) {
		a, err := store.DelegationChainAllowance(ctx, fx.orgA, fx.rootA)
		require.NoError(t, err)
		assert.Equal(t, []string{"search"}, a[fx.alpha])
		assert.Nil(t, a[fx.beta], "unrestricted grant stays unrestricted (nil)")
		_, ok := a[fx.gamma]
		assert.True(t, ok, "root's own gamma grant gives chain access")
	})

	t.Run("child: unrestricted grant inherits the parent restriction", func(t *testing.T) {
		a, err := store.DelegationChainAllowance(ctx, fx.orgA, fx.childA)
		require.NoError(t, err)
		assert.Equal(t, []string{"search"}, a[fx.alpha],
			"child's unrestricted alpha grant must be narrowed by the parent's search-only scope")
		assert.Nil(t, a[fx.beta])
		_, ok := a[fx.gamma]
		assert.True(t, ok)
	})

	t.Run("grandchild: three-member intersection", func(t *testing.T) {
		a, err := store.DelegationChainAllowance(ctx, fx.orgA, fx.grandchildA)
		require.NoError(t, err)
		assert.Equal(t, []string{"search"}, a[fx.alpha],
			"alpha = [search] ∩ (all) ∩ [search,delete] = [search]")
		_, ok := a[fx.beta]
		assert.False(t, ok, "grandchild has NO beta grant → server hidden")
		_, ok = a[fx.gamma]
		assert.False(t, ok, "grandchild's gamma grant is disabled → server hidden")
	})

	t.Run("revoked ancestor retracts the delegation", func(t *testing.T) {
		a, err := store.DelegationChainAllowance(ctx, fx.orgA, fx.childRev)
		require.NoError(t, err)
		assert.Empty(t, a,
			"the walk must not reach a root through an inactive ancestor: everything denied")
	})

	t.Run("foreign-org parent link is a broken chain", func(t *testing.T) {
		a, err := store.DelegationChainAllowance(ctx, fx.orgB, fx.rootForeign)
		require.NoError(t, err)
		assert.Empty(t, a, "an orgB key must never inherit through an orgA parent")
	})

	t.Run("unknown key is ErrNotFound", func(t *testing.T) {
		_, err := store.DelegationChainAllowance(ctx, fx.orgA, "00000000-0000-0000-0000-000000000000")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("org mismatch is ErrNotFound", func(t *testing.T) {
		_, err := store.DelegationChainAllowance(ctx, fx.orgB, fx.rootA)
		assert.ErrorIs(t, err, ErrNotFound, "the key exists but belongs to another org")
	})
}
