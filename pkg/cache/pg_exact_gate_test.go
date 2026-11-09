package cache

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingStore is a mock BackendStore that counts GetExact calls and
// always reports no exact entry.
type countingStore struct {
	getExactCalls int
}

func (c *countingStore) GetExact(ctx context.Context, orgID, modelTier, promptHash, modelVer string) (*Entry, error) {
	c.getExactCalls++
	//nolint:nilnil // mirrors Store.GetExact contract in store.go: nil entry + nil error = "not found"; callers check entry != nil
	return nil, nil
}

func (c *countingStore) PurgeExpired(ctx context.Context) (int, error) {
	return 0, nil
}

func (c *countingStore) PurgeExpiredWithLock(ctx context.Context) (int, bool, error) {
	return 0, false, nil
}

// failingEmbedder always fails, short-circuiting LookupWithResult before the
// semantic lookup (so the test never touches Postgres).
type failingEmbedder struct{}

func (failingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	return nil, errors.New("no embedder in unit test")
}

// newGateTestService builds a CacheService with: in-memory policy (enabled +
// semantic), a Redis client bound to a dead port (instant miss), and the mock
// backend store.
func newGateTestService(store BackendStore, pgExactEnabled bool) *CacheService {
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond})
	return &CacheService{
		exact:          NewRedisStore(rdb, 24*time.Hour),
		store:          store,
		policy:         pc,
		embedder:       failingEmbedder{},
		log:            slog.Default(),
		pgExactEnabled: pgExactEnabled,
	}
}

func TestLookupWithResult_PGExactDisabled_SkipsStore(t *testing.T) {
	store := &countingStore{}
	cs := newGateTestService(store, false)

	_, err := cs.LookupWithResult(context.Background(), RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, []byte(`{"m":"hi"}`))
	require.NoError(t, err)
	assert.Equal(t, 0, store.getExactCalls, "pg-exact lookup must be skipped when disabled")
}

func TestLookupWithResult_PGExactEnabled_CallsStore(t *testing.T) {
	store := &countingStore{}
	cs := newGateTestService(store, true)

	_, err := cs.LookupWithResult(context.Background(), RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, []byte(`{"m":"hi"}`))
	require.NoError(t, err)
	assert.Equal(t, 1, store.getExactCalls, "pg-exact lookup must run when enabled")
}
