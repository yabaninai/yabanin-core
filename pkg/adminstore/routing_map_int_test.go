package adminstore

// sqlcontract style): production SQL against the disposable migrated stand,
// PgError / rows-iteration failures fail the test; business answers are
// asserted. The warning engine's rules live in routing_map_test.go — this
// file proves the SQL resolves the real columns and that org scoping keeps
// another org's rules out of the map.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type routingMapFixture struct {
	Token            string
	OrgA, OrgB       string
	DisabledModel    string
	LiveModel        string
	CycleModel       string
	AliasDisabled    string
	RuleATarget      string
	RuleBOtherTarget string
}

// seedRoutingMapFixture seeds: an enabled model whose chain points at a
// disabled and a nonexistent model, a self-looping model, aliases pointing
// at a disabled and a nonexistent model, and one enabled rule per org
// (org A's targeting the disabled model).
func seedRoutingMapFixture(t *testing.T, pool *pgxpool.Pool) *routingMapFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("rm47a%x", time.Now().UnixNano())
	fx := &routingMapFixture{
		Token:         token,
		LiveModel:     token + "-m-live",
		DisabledModel: token + "-m-off",
		CycleModel:    token + "-m-cycle",
	}

	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&fx.OrgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&fx.OrgB))

	models := []struct {
		name     string
		enabled  bool
		failover []string
	}{
		{fx.LiveModel, true, []string{fx.DisabledModel, token + "-m-ghost"}},
		{fx.DisabledModel, false, []string{}},
		{fx.CycleModel, true, []string{fx.CycleModel}},
	}
	for _, m := range models {
		_, err := pool.Exec(ctx, `
			INSERT INTO models_registry (model_name, display_name, tier, provider, failover_models, tier_pool, enabled)
			VALUES ($1, $1, 'smart', 'openai-compat', $2, '{}'::text[], $3)`,
			m.name, m.failover, m.enabled)
		require.NoError(t, err, "seed model %s", m.name)
	}

	// Aliases: target_model carries a FK to models_registry, so an alias to
	// a nonexistent model cannot exist in real data (the missing-alias
	// warning stays as defense-in-depth in the pure engine, unit tested);
	// an alias to a DISABLED model is legal and must warn.
	fx.AliasDisabled = token + "-alias-off"
	_, err := pool.Exec(ctx, `INSERT INTO model_aliases (alias, target_model) VALUES ($1, $2)`,
		fx.AliasDisabled, fx.DisabledModel)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO routing_rules (org_id, match_expr, target_model, priority, enabled)
		VALUES ($1::uuid, $2, $3, 10, true)`,
		fx.OrgA, `model == "`+fx.LiveModel+`"`, fx.DisabledModel)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO routing_rules (org_id, match_expr, target_model, priority, enabled)
		VALUES ($1::uuid, $2, $3, 10, true)`,
		fx.OrgB, `model == "x"`, fx.LiveModel)
	require.NoError(t, err)
	fx.RuleATarget = fx.DisabledModel
	fx.RuleBOtherTarget = fx.LiveModel

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("routing map fixture cleanup: %v", err)
			}
		}
		orgs := []string{fx.OrgA, fx.OrgB}
		cleanup(`DELETE FROM routing_rules WHERE org_id::text = ANY($1)`, orgs)
		cleanup(`DELETE FROM model_aliases WHERE alias LIKE $1`, token+"%")
		cleanup(`DELETE FROM models_registry WHERE model_name LIKE $1`, token+"%")
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, orgs)
	})

	return fx
}

func TestStore_GetRoutingMap_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedRoutingMapFixture(t, pool)

	mapping, err := store.GetRoutingMap(context.Background(), fx.OrgA)
	require.NoError(t, err)

	// Models: every registry entry is present with its provider and
	// failover/tier fields resolved from real columns.
	byName := map[string]RoutingMapModel{}
	for _, m := range mapping.Models {
		byName[m.ModelName] = m
	}
	live, ok := byName[fx.LiveModel]
	require.True(t, ok, "live model must be in the map")
	assert.True(t, live.Enabled)
	assert.Equal(t, "openai-compat", live.Provider)
	assert.Equal(t, []string{fx.DisabledModel, fx.Token + "-m-ghost"}, live.FailoverModels)
	assert.NotNil(t, live.TierPool)

	// Aliases: the global section carries the seeded target.
	aliasTargets := map[string]string{}
	for _, a := range mapping.Aliases {
		aliasTargets[a.Alias] = a.TargetModel
	}
	assert.Equal(t, fx.DisabledModel, aliasTargets[fx.AliasDisabled])

	// Rules: org A sees only its own rule — org B's must not leak.
	require.Len(t, mapping.Rules, 1, "org A must see exactly its own rule")
	assert.Equal(t, fx.RuleATarget, mapping.Rules[0].TargetModel)
	assert.True(t, mapping.Rules[0].Enabled)

	// Warnings: the chain to the disabled and the nonexistent model, the
	// self-cycle, the alias to the disabled model, and the enabled rule on
	// the disabled model.
	codes := map[string]int{}
	for _, w := range mapping.Warnings {
		codes[w.Code]++
	}
	assert.GreaterOrEqual(t, codes[WarnChainTargetDisabled], 1, "chain to the disabled model must warn")
	assert.GreaterOrEqual(t, codes[WarnChainTargetMissing], 1, "chain to the nonexistent model must warn")
	assert.GreaterOrEqual(t, codes[WarnChainCycle], 1, "self-loop must be flagged")
	assert.GreaterOrEqual(t, codes[WarnAliasTargetDisabled], 1)
	assert.GreaterOrEqual(t, codes[WarnRuleTargetDisabled], 1, "org A rule targets a disabled model")

	// The org B map carries org B's rule only — the scoping is in the SQL,
	// not a post-filter, and this is the cross-tenant leak detector.
	other, err := store.GetRoutingMap(context.Background(), fx.OrgB)
	require.NoError(t, err)
	require.Len(t, other.Rules, 1)
	assert.Equal(t, fx.RuleBOtherTarget, other.Rules[0].TargetModel)
}

func TestStore_GetRoutingMap_Integration_OrgWithoutRules(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	token := fmt.Sprintf("rm47e%x", time.Now().UnixNano())

	var orgID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org", token+"-org").Scan(&orgID))
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id::text = $1`, orgID); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	// An org without rules gets a well-formed map: the org-scoped sections
	// are empty-but-present ([] in JSON, never null). Models/aliases are
	// global registry sections, so only rules/warnings presence is asserted
	// here beyond the identity.
	mapping, err := store.GetRoutingMap(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, orgID, mapping.OrgID)
	assert.NotNil(t, mapping.Rules)
	assert.NotNil(t, mapping.Warnings)
	assert.Empty(t, mapping.Rules, "org without rules must see an empty rules list")
}
