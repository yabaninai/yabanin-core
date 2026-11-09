// Package whitelist provides Redis-cached model-whitelist enforcement for the gateway.
package whitelist

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// Store provides whitelist data access for the Loader.
type Store interface {
	GetKeyWhitelistEntry(ctx context.Context, apiKeyID, modelName string) (*adminstore.WhitelistEntry, bool, error)
	GetTeamWhitelistEntry(ctx context.Context, teamID, modelName string) (*adminstore.WhitelistEntry, bool, error)
}

// Loader checks whether a model is allowed for an API key or its team.
type Loader struct {
	store Store
	rdb   *redis.Client
	ttl   time.Duration
	log   *slog.Logger
}

// NewLoader creates a new whitelist loader with optional Redis caching.
func NewLoader(store Store, rdb *redis.Client, ttl time.Duration, log *slog.Logger) *Loader {
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &Loader{store: store, rdb: rdb, ttl: ttl, log: log.With("component", "whitelist")}
}

// Check returns true if the model is allowed for (apiKeyID, teamID).
//
// Resolution algorithm:
//  1. If apiKeyID is empty → default ALLOW (fail-open, cannot check without identity).
//  2. Key-scope entry found? Return its Allowed value immediately.
//  3. Team-scope entry found? Return its Allowed value.
//  4. No entry in either scope → default ALLOW (whitelist = explicit allow/deny, not deny-by-default).
func (l *Loader) Check(ctx context.Context, apiKeyID, teamID, modelName string) (bool, error) {
	if apiKeyID == "" {
		l.log.Warn("whitelist check: no API key ID, defaulting to allow")
		return true, nil
	}

	// 1. Key-scope
	keyAllowed, found, err := l.checkScope(ctx, "key", apiKeyID, modelName)
	if err != nil {
		return false, err
	}
	if found {
		return keyAllowed, nil
	}

	// 2. Team-scope (if team exists)
	if teamID != "" {
		teamAllowed, found, err := l.checkScope(ctx, "team", teamID, modelName)
		if err != nil {
			return false, err
		}
		if found {
			return teamAllowed, nil
		}
	}

	// 3. Default allow — no entry means the model is not restricted for this scope.
	return true, nil
}

func (l *Loader) checkScope(ctx context.Context, scope, id, model string) (allowed, found bool, err error) {
	cacheKey := fmt.Sprintf("wl:%s:%s:%s", scope, id, model)

	// Try Redis cache first.
	if l.rdb != nil {
		v, err := l.rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			return v == "1", true, nil
		}
		if err != redis.Nil {
			l.log.Warn("whitelist cache read error, falling back to DB", "error", err)
		}
	}

	// Query database.
	var entry *adminstore.WhitelistEntry
	if scope == "key" {
		entry, found, err = l.store.GetKeyWhitelistEntry(ctx, id, model)
	} else {
		entry, found, err = l.store.GetTeamWhitelistEntry(ctx, id, model)
	}
	if err != nil {
		return false, false, err
	}
	if !found {
		return false, false, nil
	}

	// Cache the result.
	if l.rdb != nil {
		val := "0"
		if entry.Allowed {
			val = "1"
		}
		_ = l.rdb.Set(ctx, cacheKey, val, l.ttl).Err()
	}

	return entry.Allowed, true, nil
}

// Invalidate clears all cached whitelist entries for a given scope and target ID.
func (l *Loader) Invalidate(ctx context.Context, scope, id string) error {
	if l.rdb == nil {
		return nil
	}
	pattern := fmt.Sprintf("wl:%s:%s:*", scope, id)
	iter := l.rdb.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		_ = l.rdb.Del(ctx, iter.Val()).Err()
	}
	return iter.Err()
}

// --- In-memory fallback Store for testing when DB is not available. ---

type inMemoryStore struct {
	mu      sync.RWMutex
	keyMap  map[string]map[string]bool // apiKeyID -> modelName -> allowed
	teamMap map[string]map[string]bool // teamID -> modelName -> allowed
}

func newInMemoryStore() *inMemoryStore {
	return &inMemoryStore{
		keyMap:  make(map[string]map[string]bool),
		teamMap: make(map[string]map[string]bool),
	}
}

func (s *inMemoryStore) GetKeyWhitelistEntry(_ context.Context, apiKeyID, modelName string) (*adminstore.WhitelistEntry, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	models, ok := s.keyMap[apiKeyID]
	if !ok {
		return nil, false, nil
	}
	allowed, ok := models[modelName]
	if !ok {
		return nil, false, nil
	}
	return &adminstore.WhitelistEntry{ModelName: modelName, Allowed: allowed}, true, nil
}

func (s *inMemoryStore) GetTeamWhitelistEntry(_ context.Context, teamID, modelName string) (*adminstore.WhitelistEntry, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	models, ok := s.teamMap[teamID]
	if !ok {
		return nil, false, nil
	}
	allowed, ok := models[modelName]
	if !ok {
		return nil, false, nil
	}
	return &adminstore.WhitelistEntry{ModelName: modelName, Allowed: allowed}, true, nil
}

// SetKeyWhitelist sets a whitelist entry for an API key (test helper).
func (s *inMemoryStore) SetKeyWhitelist(apiKeyID, modelName string, allowed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyMap[apiKeyID] == nil {
		s.keyMap[apiKeyID] = make(map[string]bool)
	}
	s.keyMap[apiKeyID][modelName] = allowed
}

// SetTeamWhitelist sets a whitelist entry for a team (test helper).
func (s *inMemoryStore) SetTeamWhitelist(teamID, modelName string, allowed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.teamMap[teamID] == nil {
		s.teamMap[teamID] = make(map[string]bool)
	}
	s.teamMap[teamID][modelName] = allowed
}
