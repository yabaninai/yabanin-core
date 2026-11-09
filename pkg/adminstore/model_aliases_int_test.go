package adminstore

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestStore_ModelAliasCRUD_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	const model = "qa-alias-target"
	_, err := pool.Exec(ctx, `DELETE FROM model_aliases WHERE target_model = $1 OR alias = $2`, model, "claude-sonnet-4-6")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM models_registry WHERE model_name = $1`, model)
	require.NoError(t, err)
	_, err = store.CreateModel(ctx, model, "QA alias target", "smart", nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM model_aliases WHERE target_model = $1`, model)
		_, _ = pool.Exec(context.Background(), `DELETE FROM models_registry WHERE model_name = $1`, model)
	})

	created, err := store.CreateModelAlias(ctx, "claude-sonnet-4-6", model)
	require.NoError(t, err)
	assert.Equal(t, model, created.TargetModel)

	rows, err := store.ListModelAliases(ctx)
	require.NoError(t, err)
	found := false
	for _, row := range rows {
		if row.Alias == "claude-sonnet-4-6" {
			found = true
		}
	}
	assert.True(t, found)

	require.NoError(t, store.DeleteModelAlias(ctx, "claude-sonnet-4-6"))
	require.Error(t, store.DeleteModelAlias(ctx, "claude-sonnet-4-6"))
}
