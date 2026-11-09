package whitelist

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errStoreUnavailable = errors.New("store unavailable")

func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// --- Tests with in-memory store, no Redis. ---

func TestLoader_Check_NoWhitelist_DefaultAllow(t *testing.T) {
	store := newInMemoryStore()
	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "team-1", "gpt-4")
	require.NoError(t, err)
	assert.True(t, allowed, "should default allow when no whitelist entry exists")
}

func TestLoader_Check_EmptyKey_DefaultAllow(t *testing.T) {
	store := newInMemoryStore()
	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "", "team-1", "gpt-4")
	require.NoError(t, err)
	assert.True(t, allowed, "should default allow when API key ID is empty (fail-open)")
}

func TestLoader_Check_KeyWhitelistDeny(t *testing.T) {
	store := newInMemoryStore()
	store.SetKeyWhitelist("key-1", "gpt-4", false) // explicitly deny

	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "", "gpt-4")
	require.NoError(t, err)
	assert.False(t, allowed, "should deny when key-scope entry has allowed=false")
}

func TestLoader_Check_KeyWhitelistAllow(t *testing.T) {
	store := newInMemoryStore()
	store.SetKeyWhitelist("key-1", "gpt-4", true) // explicitly allow

	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "", "gpt-4")
	require.NoError(t, err)
	assert.True(t, allowed, "should allow when key-scope entry has allowed=true")
}

func TestLoader_Check_TeamFallback(t *testing.T) {
	store := newInMemoryStore()
	// No key-level entry for gpt-5 → should fall back to team-level.
	store.SetTeamWhitelist("team-1", "gpt-5", false)

	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "team-1", "gpt-5")
	require.NoError(t, err)
	assert.False(t, allowed, "should deny via team-scope fallback when key-scope has no entry")
}

func TestLoader_Check_KeyDenyOverridesTeamAllow(t *testing.T) {
	store := newInMemoryStore()
	// Key explicitly denies gpt-4 → team allow should NOT override.
	store.SetKeyWhitelist("key-1", "gpt-4", false)
	store.SetTeamWhitelist("team-1", "gpt-4", true)

	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "team-1", "gpt-4")
	require.NoError(t, err)
	assert.False(t, allowed, "key-scope deny should take precedence over team-scope allow")
}

func TestLoader_Check_TeamAllowWhenKeyNoEntry(t *testing.T) {
	store := newInMemoryStore()
	// Key has no entry for claude-3 → team allow should apply.
	store.SetTeamWhitelist("team-1", "claude-3", true)

	loader := NewLoader(store, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "team-1", "claude-3")
	require.NoError(t, err)
	assert.True(t, allowed, "should allow via team-scope when key-scope has no entry")
}

func TestLoader_Check_DifferentModels(t *testing.T) {
	store := newInMemoryStore()
	store.SetKeyWhitelist("key-1", "gpt-4", false) // deny gpt-4 only

	loader := NewLoader(store, nil, 0, newTestLogger())

	// Denied model
	allowed, err := loader.Check(context.Background(), "key-1", "", "gpt-4")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Different model not in whitelist → default allow
	allowed, err = loader.Check(context.Background(), "key-1", "", "claude-3")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestLoader_Check_EmptyTeamID_NoTeamFallback(t *testing.T) {
	store := newInMemoryStore()
	// Only team whitelist exists; key has no entry for model.
	store.SetTeamWhitelist("team-1", "gpt-4", false)

	loader := NewLoader(store, nil, 0, newTestLogger())

	// Call with empty teamID → no team fallback → default allow
	allowed, err := loader.Check(context.Background(), "key-1", "", "gpt-4")
	require.NoError(t, err)
	assert.True(t, allowed, "should default allow when teamID is empty and key-scope has no entry")
}

// erroringStore is a Store double that always fails, used to verify the loader
// propagates datastore errors so the gateway can fail-closed (503) instead of
// silently admitting a possibly-restricted model.
type erroringStore struct{}

func (erroringStore) GetKeyWhitelistEntry(context.Context, string, string) (*adminstore.WhitelistEntry, bool, error) {
	return nil, false, errStoreUnavailable
}

func (erroringStore) GetTeamWhitelistEntry(context.Context, string, string) (*adminstore.WhitelistEntry, bool, error) {
	return nil, false, errStoreUnavailable
}

// TestLoader_Check_StoreErrorPropagates confirms a datastore error surfaces from
// Check (I2.2): the gateway relies on this to deny with 503 rather than fail open.
func TestLoader_Check_StoreErrorPropagates(t *testing.T) {
	loader := NewLoader(erroringStore{}, nil, 0, newTestLogger())

	allowed, err := loader.Check(context.Background(), "key-1", "team-1", "gpt-4")
	require.Error(t, err)
	assert.False(t, allowed, "must not allow when the store is unavailable")
}
