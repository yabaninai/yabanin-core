package adminstore

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ADL-08: the task-tag dimension (cost + latency per model × task class).

// D-01 regression: on every issued shadow query the highest $n placeholder in
// the SQL must equal len(args) — the org-filter placeholder is numbered from
// the args slice only after the org argument was appended. Before the fix the
// org filter re-used $2 (the window bound) while three arguments were passed,
// so every org-scoped request died in Postgres (500).
func TestShadowComparison_PlaceholderContract(t *testing.T) {
	type query struct {
		sql  string
		args []interface{}
	}
	var queries []query
	mockDB := &mockDB{
		queryFn: func(_ context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			queries = append(queries, query{sql: sql, args: args})
			return &mockPGXRows{data: [][]interface{}{}}, nil
		},
	}
	s := newForTest(mockDB, newTestLogger(), nil)

	placeholder := regexp.MustCompile(`\$(\d+)`)
	for _, orgID := range []string{"", "org-1"} {
		queries = nil
		_, err := s.GetShadowComparison(context.Background(), orgID, 30)
		require.NoError(t, err)
		require.Len(t, queries, 2, "by-model and by-task queries must both run")
		for i, q := range queries {
			maxN := 0
			for _, m := range placeholder.FindAllStringSubmatch(q.sql, -1) {
				n, err := strconv.Atoi(m[1])
				require.NoError(t, err)
				maxN = max(maxN, n)
			}
			assert.Equal(t, len(q.args), maxN,
				"org=%q query #%d: max placeholder $%d must equal len(args)=%d\nSQL: %s",
				orgID, i, maxN, len(q.args), q.sql)
			if orgID != "" {
				// The org filter must reference exactly the last placeholder.
				assert.Contains(t, q.sql, fmt.Sprintf("p.org_id::text = $%d", len(q.args)),
					"org=%q query #%d: org filter must use the last placeholder\nSQL: %s", orgID, i, q.sql)
			}
		}
	}
}

func TestShadowComparison_ByTaskClass(t *testing.T) {
	ctx := context.Background()
	// The mock returns by_model rows for the first query and by_task rows for
	// the second (distinguished by which SQL is issued).
	mockDB := &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if containsSQL(sql, "GROUP BY 1, p.model_used") {
				// by_task: task_class, primary, shadow, overlap, p_avg, s_avg, p_ms, s_ms
				return &mockPGXRows{data: [][]interface{}{
					{"stand-opencode/feature-42", "glm-5.3-flash", "glm-5.3", int64(30), 0.0010, 0.0040, int64(120), int64(900)},
					{"(untagged)", "glm-5.3-flash", "glm-5.3", int64(5), 0.0005, 0.0020, int64(80), int64(600)},
				}}, nil
			}
			// by_model: primary, shadow, overlap, p_avg, s_avg
			return &mockPGXRows{data: [][]interface{}{
				{"glm-5.3-flash", "glm-5.3", int64(35), 0.0010, 0.0040},
			}}, nil
		},
	}
	s := newForTest(mockDB, newTestLogger(), nil)

	rep, err := s.GetShadowComparison(ctx, "org-1", 30)
	require.NoError(t, err)
	require.NotNil(t, rep)

	// Headline (by_model) is intact.
	require.Len(t, rep.ByModel, 1)
	assert.Equal(t, "glm-5.3-flash", rep.PrimaryModel)

	// ADL-08: the by-task breakdown is present and carries cost + latency.
	require.Len(t, rep.ByTaskClass, 2, "by_task_class must be populated")
	first := rep.ByTaskClass[0]
	assert.Equal(t, "stand-opencode/feature-42", first.TaskClass)
	assert.Equal(t, "glm-5.3-flash", first.PrimaryModel)
	assert.Equal(t, "glm-5.3", first.ShadowModel)
	assert.Equal(t, 30, first.Overlap)
	assert.InDelta(t, 0.0010, first.PrimaryAvgUSD, 1e-9)
	assert.InDelta(t, 0.0040, first.ShadowAvgUSD, 1e-9)
	assert.Equal(t, int64(120), first.PrimaryAvgMs)
	assert.Equal(t, int64(900), first.ShadowAvgMs)
	// The shadow model is ~4x pricier → a "pricier" verdict.
	assert.Equal(t, "pricier", first.Verdict)

	// NULL task_id is grouped as "(untagged)"; low overlap (5 < 20) →
	// insufficient_data even though it is pricier in absolute terms.
	second := rep.ByTaskClass[1]
	assert.Equal(t, "(untagged)", second.TaskClass)
	assert.Equal(t, "insufficient_data", second.Verdict)
}

func TestShadowComparison_NoShadowTraffic(t *testing.T) {
	ctx := context.Background()
	// Empty by_model AND empty by_task: a zero-overlap report (insufficient_data).
	mockDB := &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{}}, nil
		},
	}
	s := newForTest(mockDB, newTestLogger(), nil)
	rep, err := s.GetShadowComparison(ctx, "", 30)
	require.NoError(t, err)
	assert.Equal(t, "insufficient_data", rep.Verdict)
	assert.Empty(t, rep.ByModel)
	assert.Empty(t, rep.ByTaskClass)
	assert.NotNil(t, rep.ByTaskClass, "by_task_class must be a concrete (empty) slice, not nil")
}
