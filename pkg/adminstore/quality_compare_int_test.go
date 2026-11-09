package adminstore

// by-model and by-task queries aggregate `should_upgrade` (boolean) into an
// upgrade rate — Postgres cannot cast boolean straight to float8, so the
// original `AVG(e.should_upgrade::float8)` made every query fail. These tests
// pin the repaired SQL: real verdict rows → real rates, real recommendation
// decisions at the qualityMinVerdicts boundary, and the org filter.

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

type imp02Verdict struct {
	taskClass     string // "" → NULL (the "(untagged)" bucket)
	shouldUpgrade bool
}

func imp02OrgID(n int) string {
	return fmt.Sprintf("999%d0444-4444-4444-8444-0000000000%02d", n, n)
}

func imp02SeedVerdicts(t *testing.T, pool *pgxpool.Pool, org, cheapModel, premiumModel string, verdicts []imp02Verdict) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, 'IMP02 Int Org', $2)
		ON CONFLICT (id) DO NOTHING`,
		org, "imp02-int-org-"+org[len(org)-2:])
	require.NoError(t, err)
	for i, v := range verdicts {
		reqID := fmt.Sprintf("imp02-%s-%04d", org[len(org)-2:], i)
		var taskID interface{}
		if v.taskClass != "" {
			taskID = v.taskClass
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, request_id, task_id, home_region)
			VALUES ($1::uuid, $2, $2, 200, 5, $3, $4, 'sg')`,
			org, cheapModel, reqID, taskID)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `
			INSERT INTO evalgate_results (
				org_id, request_id, prompt, cheap_model, premium_model,
				cheap_quality, premium_quality, should_upgrade, reason
			) VALUES ($1, $2, 'imp02 probe', $3, $4, 0.5, 0.8, $5, 'imp02')`,
			org, reqID, cheapModel, premiumModel, v.shouldUpgrade)
		require.NoError(t, err)
	}
}

func imp02Cleanup(t *testing.T, pool *pgxpool.Pool, orgs ...string) {
	t.Helper()
	ctx := context.Background()
	for _, org := range orgs {
		_, err := pool.Exec(ctx, `DELETE FROM evalgate_results WHERE org_id = $1`, org)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1::uuid`, org)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1::uuid`, org)
		require.NoError(t, err)
	}
}

func imp02VerdictSlice(n, upgrades int, taskClass string) []imp02Verdict {
	vs := make([]imp02Verdict, n)
	for i := range vs {
		vs[i] = imp02Verdict{taskClass: taskClass, shouldUpgrade: i < upgrades}
	}
	return vs
}

// TestStore_GetQualityScores_Integration: 70% upgrade verdicts on a real PG →
// upgrade_rate 0.7, the recommendation fires, the by-task split keeps the
// per-class rates and the org filter excludes the other org's verdicts.
func TestStore_GetQualityScores_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	orgA, orgB := imp02OrgID(1), imp02OrgID(2)
	// Org A: 20 judged samples on one (cheap, premium) pair, 14 say upgrade.
	// First 12 rows carry task class "imp02-code" (all upgrade), the rest are
	// untagged (2 of 8 upgrade) → deterministic by-task rates.
	verdictsA := make([]imp02Verdict, 0, 20)
	for i := 0; i < 12; i++ {
		verdictsA = append(verdictsA, imp02Verdict{taskClass: "imp02-code", shouldUpgrade: true})
	}
	verdictsA = append(verdictsA, imp02Verdict{shouldUpgrade: true}, imp02Verdict{shouldUpgrade: true})
	verdictsA = append(verdictsA, imp02VerdictSlice(6, 0, "")...)
	imp02SeedVerdicts(t, pool, orgA, "imp02-cheap-a", "imp02-premium-a", verdictsA)
	// Org B: same sample size, only 20% upgrade — must never leak into A.
	imp02SeedVerdicts(t, pool, orgB, "imp02-cheap-b", "imp02-premium-b",
		imp02VerdictSlice(20, 4, ""))
	t.Cleanup(func() { imp02Cleanup(t, pool, orgA, orgB) })

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	rep, err := store.GetQualityScores(ctx, orgA, from, to)
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Equal(t, orgA, rep.OrgID)
	assert.Equal(t, "has_data", rep.Verdict)
	assert.Equal(t, 20, rep.TotalVerdicts, "org B verdicts must not leak in")

	// By-model: the repaired upgrade aggregation over real boolean rows.
	require.Len(t, rep.ByModel, 1)
	m := rep.ByModel[0]
	assert.Equal(t, "imp02-cheap-a", m.PrimaryModel)
	assert.Equal(t, "imp02-premium-a", m.ShadowModel)
	assert.Equal(t, 20, m.Verdicts)
	assert.InDelta(t, 0.5, m.CheapQuality, 1e-9)
	assert.InDelta(t, 0.8, m.PremiumQuality, 1e-9)
	assert.InDelta(t, 0.7, m.UpgradeRate, 1e-9, "14 of 20 verdicts say upgrade")

	// By-task: same window, class split with the "(untagged)" bucket.
	require.Len(t, rep.ByTaskClass, 2)
	byTask := map[string]QualityTaskClassScore{}
	for _, g := range rep.ByTaskClass {
		byTask[g.TaskClass] = g
	}
	code, ok := byTask["imp02-code"]
	require.True(t, ok, "task class rows: %+v", rep.ByTaskClass)
	assert.Equal(t, "imp02-cheap-a", code.PrimaryModel)
	assert.Equal(t, 12, code.Verdicts)
	assert.InDelta(t, 1.0, code.UpgradeRate, 1e-9)
	assert.InDelta(t, 0.5, code.CheapQuality, 1e-9)
	untagged, ok := byTask[UntaggedBucket]
	require.True(t, ok)
	assert.Equal(t, 8, untagged.Verdicts)
	assert.InDelta(t, 0.25, untagged.UpgradeRate, 1e-9, "2 of 8 untagged verdicts say upgrade")

	// Recommendation: 20 verdicts (== qualityMinVerdicts) at 70% (>= 0.60) →
	// a human-only draft model-swap from cheap-a to premium-a.
	require.NotNil(t, rep.Recommendation)
	assert.True(t, rep.Recommendation.HasRecommendation)
	assert.Equal(t, "imp02-cheap-a", rep.Recommendation.PrimaryModel)
	assert.Equal(t, "imp02-premium-a", rep.Recommendation.TargetModel)
	assert.Equal(t, 20, rep.Recommendation.Verdicts)
	assert.InDelta(t, 0.7, rep.Recommendation.UpgradeRate, 1e-9)
	assert.Contains(t, rep.Recommendation.MatchExpr, "model_requested")
	assert.Contains(t, rep.Recommendation.Justification, "70%")

	// Org B scope: only its own pair, at its own 20% rate.
	repB, err := store.GetQualityScores(ctx, orgB, from, to)
	require.NoError(t, err)
	require.Len(t, repB.ByModel, 1)
	assert.Equal(t, "imp02-cheap-b", repB.ByModel[0].PrimaryModel)
	assert.Equal(t, 20, repB.TotalVerdicts)
	assert.InDelta(t, 0.2, repB.ByModel[0].UpgradeRate, 1e-9)
	assert.Nil(t, repB.Recommendation, "20% is below the 0.60 upgrade bar")
}

// TestStore_GetQualityScores_VerdictThreshold_Integration pins the
// qualityMinVerdicts boundary on real PG: exactly 20 verdicts at the 0.60
// upgrade bar still fire (>= semantics), one verdict short does not.
func TestStore_GetQualityScores_VerdictThreshold_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	orgC, orgD := imp02OrgID(3), imp02OrgID(4)
	imp02SeedVerdicts(t, pool, orgC, "imp02-cheap-c", "imp02-premium-c",
		imp02VerdictSlice(19, 14, "")) // 0.74 rate (>= bar) but only 19 verdicts
	imp02SeedVerdicts(t, pool, orgD, "imp02-cheap-d", "imp02-premium-d",
		imp02VerdictSlice(20, 12, "")) // exactly 20 verdicts at the 0.60 bar
	t.Cleanup(func() { imp02Cleanup(t, pool, orgC, orgD) })

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	repC, err := store.GetQualityScores(ctx, orgC, from, to)
	require.NoError(t, err)
	require.Len(t, repC.ByModel, 1)
	assert.InDelta(t, 14.0/19.0, repC.ByModel[0].UpgradeRate, 1e-9)
	assert.Nil(t, repC.Recommendation, "19 verdicts is below qualityMinVerdicts")

	repD, err := store.GetQualityScores(ctx, orgD, from, to)
	require.NoError(t, err)
	require.Len(t, repD.ByModel, 1)
	assert.InDelta(t, 0.6, repD.ByModel[0].UpgradeRate, 1e-9)
	require.NotNil(t, repD.Recommendation, "the >=20 verdicts / >=0.60 rate boundary fires")
	assert.Equal(t, 20, repD.Recommendation.Verdicts)
	assert.InDelta(t, 0.6, repD.Recommendation.UpgradeRate, 1e-9)
}
