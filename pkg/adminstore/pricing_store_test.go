package adminstore

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdatePricing_ArgIdxIncremented(t *testing.T) {
	// Verify that UpdatePricing generates correct $N placeholders.
	// Regression: argIdx was never incremented, causing all UPDATE columns
	// to use $1 and the WHERE clause to filter by the field value, not ID.

	tests := []struct {
		name      string
		params    UpdatePricingParams
		expectSQL string // expected query prefix to verify placeholder correctness
	}{
		{
			name: "single field update",
			params: UpdatePricingParams{
				ID:        123,
				InputPerM: ptr64(0.5),
			},
			expectSQL: `UPDATE models_pricing SET input_per_m = $1 WHERE id = $2`,
		},
		{
			name: "two fields update",
			params: UpdatePricingParams{
				ID:         456,
				InputPerM:  ptr64(0.1),
				OutputPerM: ptr64(0.2),
			},
			expectSQL: `UPDATE models_pricing SET input_per_m = $1, output_per_m = $2 WHERE id = $3`,
		},
		{
			name: "all fields update",
			params: UpdatePricingParams{
				ID:             789,
				InputPerM:      ptr64(0.1),
				OutputPerM:     ptr64(0.2),
				CacheWritePerM: ptr64(0.01),
				CacheReadPerM:  ptr64(0.005),
			},
			expectSQL: `UPDATE models_pricing SET input_per_m = $1, output_per_m = $2, cache_write_per_m = $3, cache_read_per_m = $4 WHERE id = $5`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedSQL string
			var capturedArgs []interface{}

			mock := &mockDB{
				queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
					capturedSQL = sql
					capturedArgs = args
					return &mockPGXRow{data: [][]interface{}{{
						int64(1), "test", "gpt-4", 0.5, 1.0, 0.01, 0.005, "manual", nil, nil, time.Now(), nil,
					}}}
				},
			}

			store := newForTest(mock, newTestLogger(), nil)

			_, err := store.UpdatePricing(context.Background(), tt.params)
			require.NoError(t, err)

			assert.Contains(t, capturedSQL, tt.expectSQL, "SQL placeholder mismatch — argIdx not incremented")

			// Verify args count matches $N placeholders in final WHERE clause
			// The query ends with: ... WHERE id = $N RETURNING ...
			// Count all $1-$N placeholders across the full query
			placeholderCount := 0
			for _, ch := range capturedSQL {
				if ch == '$' {
					placeholderCount++
				}
			}
			assert.Len(t, capturedArgs, placeholderCount, "args count must match $N placeholders in SQL")
		})
	}
}

func TestListPricing_ArgIdxIncremented(t *testing.T) {
	tests := []struct {
		name      string
		opts      ListPricingOptions
		expectSQL string
	}{
		{
			name:      "provider filter only",
			opts:      ListPricingOptions{Provider: "openai"},
			expectSQL: `SELECT id, provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref, updated_by, effective_from, effective_to FROM models_pricing WHERE 1=1 AND provider = $1`,
		},
		{
			name:      "provider + model filter",
			opts:      ListPricingOptions{Provider: "openai", Model: "gpt-4"},
			expectSQL: `SELECT id, provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref, updated_by, effective_from, effective_to FROM models_pricing WHERE 1=1 AND provider = $1 AND model = $2`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedSQL string
			var capturedArgs []interface{}

			rows := &mockPGXRows{
				data: [][]interface{}{},
			}

			mock := &mockDB{
				queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
					capturedSQL = sql
					capturedArgs = args
					return rows, nil
				},
			}

			store := newForTest(mock, newTestLogger(), nil)

			_, err := store.ListPricing(context.Background(), tt.opts)
			require.NoError(t, err)

			assert.Contains(t, capturedSQL, tt.expectSQL, "SQL placeholder mismatch — argIdx not incremented")

			// Count $N placeholders in expected SQL and verify args match
			expectedCount := 0
			for _, ch := range tt.expectSQL {
				if ch == '$' {
					expectedCount++
				}
			}
			assert.Len(t, capturedArgs, expectedCount, "args count mismatch with placeholders")
		})
	}
}

func TestUpdatePricing_NoFields(t *testing.T) {
	mock := &mockDB{}
	store := newForTest(mock, newTestLogger(), nil)

	_, err := store.UpdatePricing(context.Background(), UpdatePricingParams{ID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no fields to update")
}

func ptr64(f float64) *float64 { return &f }
