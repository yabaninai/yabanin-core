package consumer

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: the savings sub-queries filter cache_hit_type / tier_used /
// classifier columns on IS NOT NULL. Ordinary (uncached, unclassified)
// requests carried empty strings in those event fields, and binding them
// verbatim made EVERY row look like a classified cache hit — cache-hit
// counts and savings percentages were computed over the whole table.
// Positions follow the INSERT column list: 12=cache_hit_type,
// 16=classifier_class, 18=classifier_source, 19=tier_used.

func TestHandleRequestComplete_EmptyCategoricalFieldsStoredAsNULL(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_nullable_cat",
			"org_id":          testOrgUUID,
			"model_requested": "glm-5.3-flash",
			"model_used":      "glm-5.3-flash",
			"status_code":     float64(200),
			"duration_ms":     float64(100),
			// Absent categorical fields — the omitempty publisher drops
			// them for ordinary uncached requests.
		},
	}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))

	assert.Nil(t, values[12], "absent cache_hit_type must bind NULL, not ''")
	assert.Nil(t, values[16], "absent classifier_class must bind NULL, not ''")
	assert.Nil(t, values[18], "absent classifier_source must bind NULL, not ''")
	assert.Nil(t, values[19], "absent tier_used must bind NULL, not ''")
}

func TestHandleRequestComplete_PresentCategoricalFieldsPreserved(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":        "request.completed",
			"source":            "gateway",
			"session_id":        "ses_nullable_cat_hit",
			"org_id":            testOrgUUID,
			"model_requested":   "glm-5.3-flash",
			"model_used":        "glm-5.3-flash",
			"status_code":       float64(200),
			"duration_ms":       float64(0),
			"cache_hit_type":    "exact",
			"tier_used":         "glm-5.3-flash",
			"classifier_class":  "easy",
			"classifier_source": "classifier",
		},
	}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))

	assert.Equal(t, "exact", values[12])
	assert.Equal(t, "easy", values[16])
	assert.Equal(t, "classifier", values[18])
	assert.Equal(t, "glm-5.3-flash", values[19])
}

func TestNullableString(t *testing.T) {
	assert.Nil(t, nullableString(map[string]interface{}{"k": ""}, "k"))
	assert.Nil(t, nullableString(map[string]interface{}{}, "k"))
	assert.Nil(t, nullableString(map[string]interface{}{"k": 42}, "k"))
	assert.Equal(t, "exact", nullableString(map[string]interface{}{"k": "exact"}, "k"))
}
