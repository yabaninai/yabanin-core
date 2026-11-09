package adminstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// qualityMockDB routes the two quality queries (by-model vs by-task) to the
// right fixture rows based on a marker in the SQL, and captures the args so the
// window/org filter can be asserted.
func qualityMockDB(byModel, byTask [][]interface{}, wantByModel, wantByTask *bool) *mockDB {
	return &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "premium_model"):
				*wantByModel = true
				return &mockPGXRows{data: byModel}, nil
			case strings.Contains(sql, "task_class"):
				*wantByTask = true
				return &mockPGXRows{data: byTask}, nil
			}
			return nil, errors.New("unexpected query")
		},
	}
}

func TestGetQualityScores_Success_WithRecommendation(t *testing.T) {
	// by-model: 200 judged samples, 70% say upgrade → recommendation fires.
	byModel := [][]interface{}{
		{"glm-5.3", "qwen-local", int64(200), 0.55, 0.85, 0.70},
		{"glm-5.3-flash", "grok-4.6", int64(40), 0.7, 0.72, 0.30},
	}
	byTask := [][]interface{}{
		{"coding", "glm-5.3", int64(150), 0.5, 0.75},
		{UntaggedBucket, "glm-5.3", int64(50), 0.6, 0.6},
	}
	sawModel, sawTask := false, false
	db := qualityMockDB(byModel, byTask, &sawModel, &sawTask)
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(30 * 24 * time.Hour)

	rep, err := s.GetQualityScores(context.Background(), "org-1", from, to)
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.True(t, sawModel && sawTask, "both by-model and by-task queries must run")
	assert.Equal(t, "org-1", rep.OrgID)
	assert.Equal(t, "has_data", rep.Verdict)
	assert.Equal(t, 240, rep.TotalVerdicts) // 200 + 40
	require.Len(t, rep.ByModel, 2)
	assert.Equal(t, "glm-5.3", rep.ByModel[0].PrimaryModel)
	assert.Equal(t, "qwen-local", rep.ByModel[0].ShadowModel)
	assert.InDelta(t, 0.55, rep.ByModel[0].CheapQuality, 1e-9)
	assert.InDelta(t, 0.85, rep.ByModel[0].PremiumQuality, 1e-9)
	assert.InDelta(t, 0.70, rep.ByModel[0].UpgradeRate, 1e-9)
	require.Len(t, rep.ByTaskClass, 2)
	assert.Equal(t, "coding", rep.ByTaskClass[0].TaskClass)
	assert.Equal(t, UntaggedBucket, rep.ByTaskClass[1].TaskClass)

	// Recommendation: the top pair (200 samples, 70% upgrade) clears both
	// thresholds (>=20 verdicts, >=0.60 upgrade) → a draft model-swap.
	require.NotNil(t, rep.Recommendation)
	assert.True(t, rep.Recommendation.HasRecommendation)
	assert.Equal(t, "glm-5.3", rep.Recommendation.PrimaryModel)
	assert.Equal(t, "qwen-local", rep.Recommendation.ShadowModel)
	assert.Contains(t, rep.Recommendation.MatchExpr, `model_requested`)
	assert.Equal(t, "qwen-local", rep.Recommendation.TargetModel)
	assert.Contains(t, rep.Recommendation.Justification, "200")
	assert.Contains(t, rep.Recommendation.Justification, "70%")
	assert.NotEmpty(t, rep.SampleScopeNote)
}

func TestGetQualityScores_NoRecommendation_LowUpgradeRate(t *testing.T) {
	// 200 samples but only 30% upgrade → below the 0.60 bar, no recommendation.
	byModel := [][]interface{}{
		{"glm-5.3", "qwen-local", int64(200), 0.8, 0.82, 0.30},
	}
	sawModel, sawTask := false, false
	db := qualityMockDB(byModel, nil, &sawModel, &sawTask)
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	rep, err := s.GetQualityScores(context.Background(), "", from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Equal(t, "has_data", rep.Verdict)
	assert.Nil(t, rep.Recommendation)
}

func TestGetQualityScores_NoRecommendation_FewVerdicts(t *testing.T) {
	// High upgrade rate but only 5 judged samples → below the 20-sample bar.
	byModel := [][]interface{}{
		{"glm-5.3", "qwen-local", int64(5), 0.2, 0.9, 0.95},
	}
	sawModel, sawTask := false, false
	db := qualityMockDB(byModel, nil, &sawModel, &sawTask)
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	rep, err := s.GetQualityScores(context.Background(), "org-1", from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Nil(t, rep.Recommendation)
}

func TestGetQualityScores_Empty(t *testing.T) {
	sawModel, sawTask := false, false
	db := qualityMockDB(nil, nil, &sawModel, &sawTask)
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	rep, err := s.GetQualityScores(context.Background(), "org-1", from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Equal(t, "insufficient_data", rep.Verdict)
	assert.Equal(t, 0, rep.TotalVerdicts)
	assert.Empty(t, rep.ByModel)
	assert.Empty(t, rep.ByTaskClass)
	assert.Nil(t, rep.Recommendation)
}

func TestGetQualityScores_OrgFilterApplied(t *testing.T) {
	var sawOrgFilter string
	db := &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			sawOrgFilter = sql
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetQualityScores(context.Background(), "org-9", from, from.Add(24*time.Hour))
	require.NoError(t, err)
	// The org filter must cast request_logs.org_id (uuid) to text and match the
	// provided org id (the join needs a consistent type).
	assert.Contains(t, sawOrgFilter, "rl.org_id::text = $3")
}

func TestGetQualityScores_QueryError(t *testing.T) {
	db := &mockDB{
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetQualityScores(context.Background(), "org-1", from, from.Add(24*time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quality by-model query")
}

func TestGetQualityScores_ByTaskScanError(t *testing.T) {
	// by-model returns cleanly; the by-task query's rows signal a scan error
	// (e.g. a column type change) → the whole call surfaces a wrapped error
	// rather than a partial report.
	db := &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if strings.Contains(sql, "premium_model") {
				return &mockPGXRows{data: [][]interface{}{{"glm-5.3", "qwen-local", int64(200), 0.5, 0.8, 0.7}}}, nil
			}
			return &mockPGXRows{data: [][]interface{}{{"bad", "glm-5.3", int64(1), 0.5, 0.7}}, err: errors.New("column type mismatch")}, nil
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetQualityScores(context.Background(), "org-1", from, from.Add(24*time.Hour))
	require.Error(t, err)
	// The by-task row error surfaces via rows.Err() after the loop (the mock's
	// Scan is lenient, so the signal rides on Err()).
	assert.Contains(t, err.Error(), "quality by-task")
}

func TestGetQualityScores_NilDB(t *testing.T) {
	s := &Store{}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetQualityScores(context.Background(), "org-1", from, from.Add(24*time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database not available")
}
