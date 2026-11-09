package adminstore

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestOrderBy_UnsetSortKeepsDefault(t *testing.T) {
	f := NewPageFilter(1, 50)
	assert.Equal(t, " ORDER BY created_at DESC, id ASC",
		f.OrderBy(APIKeySortColumns, "created_at", true))
	assert.Equal(t, " ORDER BY priority DESC, id ASC",
		f.OrderBy(RoutingRuleSortColumns, "priority", true))
	// Models default is created_at ascending.
	assert.Equal(t, " ORDER BY created_at ASC, id ASC",
		f.OrderBy(ModelSortColumns, "created_at", false))

	f.Sort = &Sort{Column: "created_at", Set: false}
	assert.Equal(t, " ORDER BY created_at DESC, id ASC",
		f.OrderBy(APIKeySortColumns, "created_at", true), "Unset Sort must not change the order")
}

func TestOrderBy_ExplicitColumnAndDirection(t *testing.T) {
	f := NewPageFilter(1, 50)
	f.Sort = &Sort{Column: "name", Set: true}
	assert.Equal(t, " ORDER BY name ASC, id ASC", f.OrderBy(APIKeySortColumns, "created_at", true))
	f.Sort = &Sort{Column: "name", Set: true, Desc: true}
	assert.Equal(t, " ORDER BY name DESC, id ASC", f.OrderBy(APIKeySortColumns, "created_at", true))
}

func TestOrderBy_UnknownColumnFallsBackToDefault(t *testing.T) {
	// The HTTP layer rejects unknown columns with 400 invalid_sort; the
	// store-side fallback is defense in depth for direct store callers.
	f := NewPageFilter(1, 50)
	f.Sort = &Sort{Column: "key_hash; DROP TABLE api_keys", Set: true, Desc: true}
	assert.Equal(t, " ORDER BY created_at DESC, id ASC",
		f.OrderBy(APIKeySortColumns, "created_at", true))
}

func TestOrderBy_NilSortKeepsDefault(t *testing.T) {
	f := NewPageFilter(1, 50)
	f.Sort = nil
	assert.Equal(t, " ORDER BY created_at DESC, id ASC",
		f.OrderBy(AdminUserSortColumns, "created_at", true))
}

func TestSortColumns_AllowlistsExcludeSecrets(t *testing.T) {
	for _, banned := range []struct {
		cols SortColumns
		col  string
	}{
		{APIKeySortColumns, "key_hash"},
		{AdminUserSortColumns, "password_hash"},
	} {
		_, ok := banned.cols[banned.col]
		assert.False(t, ok, "secret column %s must not be sortable", banned.col)
	}
}

// TestStore_ListAPIKeys_SortSmoke exercises the OrderBy path against a real
// database through the public store API (both directions plus the unknown
// column fallback).
func TestStore_ListAPIKeys_SortSmoke(t *testing.T) {
	pool := testdb.Postgres(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	// Slug must be unique across repeat runs (-count>1) on the shared stand.
	org, err := store.CreateOrganization(ctx,
		"sort smoke org", fmt.Sprintf("sort-smoke-org-%d", time.Now().UnixNano()))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM api_keys WHERE org_id = $1", org.ID)
		_ = store.DeleteOrganization(context.Background(), org.ID)
	})
	team, err := store.GetDefaultTeam(ctx, org.ID)
	require.NoError(t, err)
	keyNames := []string{"srt-alpha", "srt-beta", "srt-gamma"}
	for _, n := range keyNames {
		_, err := store.CreateAPIKey(ctx, "smoke-hash-"+org.ID+"-"+n, n, &org.ID, &team.ID)
		require.NoError(t, err)
	}

	f := NewPageFilter(1, 50)
	f.Sort = &Sort{Column: "name", Set: true}
	keys, _, err := store.ListAPIKeys(ctx, &org.ID, f)
	require.NoError(t, err)
	got := make([]string, 0, len(keys))
	for _, k := range keys {
		got = append(got, k.Name)
	}
	assert.Equal(t, keyNames, got, "name asc")

	f.Sort = &Sort{Column: "name", Set: true, Desc: true}
	keys, _, err = store.ListAPIKeys(ctx, &org.ID, f)
	require.NoError(t, err)
	got = got[:0]
	for _, k := range keys {
		got = append(got, k.Name)
	}
	assert.Equal(t, []string{"srt-gamma", "srt-beta", "srt-alpha"}, got, "name desc")

	// Unknown column must fall back to the default (created_at DESC).
	f.Sort = &Sort{Column: "bogus", Set: true, Desc: true}
	keys, _, err = store.ListAPIKeys(ctx, &org.ID, f)
	require.NoError(t, err)
	createdAt := make([]time.Time, 0, len(keys))
	for _, k := range keys {
		createdAt = append(createdAt, k.CreatedAt)
	}
	require.Len(t, createdAt, len(keyNames))
	for i := 1; i < len(createdAt); i++ {
		assert.True(t, createdAt[i-1].After(createdAt[i]) || createdAt[i-1].Equal(createdAt[i]),
			"fallback order must stay created_at DESC")
	}
}
