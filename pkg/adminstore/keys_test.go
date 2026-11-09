package adminstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type destRecorder struct {
	kinds []string
}

func (d *destRecorder) Scan(dest ...any) error {
	for _, v := range dest {
		d.kinds = append(d.kinds, fmt.Sprintf("%T", v))
	}
	return nil
}

func TestScanAPIKey_UsesAddressOfNullableOrgAndTeam(t *testing.T) {
	var rec destRecorder
	var k APIKey
	require.NoError(t, scanAPIKey(&rec, &k))
	require.Equal(t, []string{
		"*string", "*string", "**string", "**string", "*string", "*bool", "*time.Time",
		"*[]uint8", "*bool", "*bool", "*bool", "**time.Time", "**time.Time", "*int",
	}, rec.kinds)
}

func TestListAPIKeys_Success(t *testing.T) {
	created := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	expires := created.Add(30 * 24 * time.Hour)
	used := created.Add(time.Hour)
	store := newForTest(&mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(1)}}}
		},
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{
				{"key-1", "hash", "org-1", "team-1", "opencode", true, created, nil, false, false, false, expires, nil, 5},
				{"key-2", "hash2", "org-1", "team-1", "used", true, created, nil, false, false, false, nil, used, 9},
			}}, nil
		},
	}, newTestLogger(), nil)

	orgID := "org-1"
	keys, total, err := store.ListAPIKeys(t.Context(), &orgID, PageFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, keys, 2)
	require.Equal(t, "opencode", keys[0].Name)
	require.NotNil(t, keys[0].OrgID)
	require.Equal(t, "org-1", *keys[0].OrgID)
	require.NotNil(t, keys[0].TeamID)
	require.Equal(t, "team-1", *keys[0].TeamID)
	require.NotNil(t, keys[0].ExpiresAt)
	require.True(t, keys[0].ExpiresAt.Equal(expires))
	require.Nil(t, keys[0].LastUsedAt)
	require.Nil(t, keys[1].ExpiresAt)
	require.NotNil(t, keys[1].LastUsedAt)
	require.True(t, keys[1].LastUsedAt.Equal(used))
	require.Equal(t, 5, keys[0].Priority)
	require.Equal(t, 9, keys[1].Priority)
}

func TestListAPIKeys_NilDB(t *testing.T) {
	store := newForTest(nil, newTestLogger(), nil)
	keys, total, err := store.ListAPIKeys(t.Context(), nil, PageFilter{})
	require.Error(t, err)
	require.Nil(t, keys)
	require.Zero(t, total)
}
