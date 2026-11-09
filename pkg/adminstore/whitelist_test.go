package adminstore

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetKeyWhitelistEntry_NoRowsIsNotError is a regression test for the
// fail-closed bug where a missing whitelist row (the normal "no restriction"
// case) was reported as an error. The store is backed by pgx, so a missing row
// surfaces as pgx.ErrNoRows — checking database/sql.ErrNoRows (as the buggy
// code did) would not match, and the gateway would deny every request for a key
// without an explicit whitelist entry. The correct behavior: (nil, false, nil).
func TestGetKeyWhitelistEntry_NoRowsIsNotError(t *testing.T) {
	mock := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			// Simulate pgx reporting "no rows" — the value a real pgx pool
			// returns when the SELECT matches nothing.
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}
	store := newForTest(mock, newTestLogger(), nil)

	entry, found, err := store.GetKeyWhitelistEntry(context.Background(), "key-1", "gpt-4o")
	require.NoError(t, err, "a missing whitelist row must not be an error (pgx.ErrNoRows case)")
	assert.False(t, found)
	assert.Nil(t, entry)
}

// TestGetTeamWhitelistEntry_NoRowsIsNotError is the team-scope analogue of the
// above regression.
func TestGetTeamWhitelistEntry_NoRowsIsNotError(t *testing.T) {
	mock := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
	}
	store := newForTest(mock, newTestLogger(), nil)

	entry, found, err := store.GetTeamWhitelistEntry(context.Background(), "team-1", "gpt-4o")
	require.NoError(t, err, "a missing team whitelist row must not be an error (pgx.ErrNoRows case)")
	assert.False(t, found)
	assert.Nil(t, entry)
}

// TestGetKeyWhitelistEntry_FoundReturnsEntry ensures the happy path still works:
// a present row is returned with found=true.
func TestGetKeyWhitelistEntry_FoundReturnsEntry(t *testing.T) {
	mock := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{
				{"id-1", "key-1", "gpt-4o", true, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			}}
		},
	}
	store := newForTest(mock, newTestLogger(), nil)

	entry, found, err := store.GetKeyWhitelistEntry(context.Background(), "key-1", "gpt-4o")
	require.NoError(t, err)
	assert.True(t, found)
	require.NotNil(t, entry)
	assert.True(t, entry.Allowed)
	assert.Equal(t, "gpt-4o", entry.ModelName)
}
