package eventpublisher

// N02-P06 T03/T06: the shared org original-retention resolver — ONE
// semantic, two call sites (RedisPublisher.Publish pre-XADD strip and the
// loggerd durable-history/DLQ gate). These tests pin the fail-closed
// resolution rules at the shared definition; the consumer-side delivery
// behavior is pinned in services/loggerd/consumer/original_retention_test.go.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
)

// retResolverStubStore is a configurable OriginalRetentionStore fake.
type retResolverStubStore struct {
	calls int
	// err, when set, fails every lookup.
	err error
	// effective answers every lookup; nilOverride models a NULL
	// retain_original_text override (inherit the platform default).
	effective   bool
	nilOverride bool
	found       bool
	lastOrgID   string
}

func (s *retResolverStubStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	s.calls++
	s.lastOrgID = orgID
	if s.err != nil {
		return nil, s.err
	}
	if !s.found {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	setting := &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: s.effective}
	if s.nilOverride {
		setting.Inherited = true
		setting.Effective = adminstore.OriginalRetentionPlatformDefault
	}
	return setting, nil
}

// TestOriginalRetentionResolver_Matrix pins the fail-closed resolution
// rules of the shared per-process toggle source.
func TestOriginalRetentionResolver_Matrix(t *testing.T) {
	ctx := context.Background()

	t.Run("nil resolver and nil store fail closed", func(t *testing.T) {
		var nilRes *OriginalRetentionResolver
		assert.False(t, nilRes.Enabled(ctx, "org-1"))
		assert.False(t, NewOriginalRetentionResolver(nil).Enabled(ctx, "org-1"))
	})

	t.Run("empty org fails closed", func(t *testing.T) {
		store := &retResolverStubStore{found: true, effective: true}
		r := NewOriginalRetentionResolver(store)
		assert.False(t, r.Enabled(ctx, ""))
		assert.Equal(t, 0, store.calls, "no lookup for an empty org")
	})

	t.Run("explicit opt-in, explicit off and inherited default", func(t *testing.T) {
		store := &retResolverStubStore{found: true, effective: true}
		r := NewOriginalRetentionResolver(store)
		assert.True(t, r.Enabled(ctx, "org-on"))

		store.effective, store.nilOverride = false, false
		assert.False(t, r.Enabled(ctx, "org-off"))

		store.nilOverride = true
		assert.False(t, r.Enabled(ctx, "org-inherit"), "NULL override inherits the platform default false")
	})

	t.Run("lookup error fails closed and is not cached", func(t *testing.T) {
		store := &retResolverStubStore{err: errors.New("db down")}
		r := NewOriginalRetentionResolver(store)
		assert.False(t, r.Enabled(ctx, "org-1"))
		assert.False(t, r.Enabled(ctx, "org-1"))
		assert.Equal(t, 2, store.calls, "an error must never be cached as the resolved value")
	})

	t.Run("resolved value serves the TTL window once", func(t *testing.T) {
		store := &retResolverStubStore{found: true, effective: true}
		r := NewOriginalRetentionResolver(store)
		now := time.Unix(1700000000, 0)
		r.now = func() time.Time { return now }
		r.ttl = time.Minute

		assert.True(t, r.Enabled(ctx, "org-1"))
		assert.True(t, r.Enabled(ctx, "org-1"))
		assert.Equal(t, 1, store.calls, "one resolution per org per TTL window")

		// TTL expiry re-reads and picks up the flipped value.
		now = now.Add(2 * r.ttl)
		store.effective = false
		assert.False(t, r.Enabled(ctx, "org-1"))
		assert.Equal(t, 2, store.calls)
	})

	t.Run("org churn stays bounded", func(t *testing.T) {
		store := &retResolverStubStore{found: true, effective: true}
		r := NewOriginalRetentionResolver(store)
		for i := 0; i < MaxOriginalRetentionOrgs+10; i++ {
			r.Enabled(ctx, fmt.Sprintf("org-%d", i))
		}
		r.mu.Lock()
		size := len(r.cache)
		r.mu.Unlock()
		assert.LessOrEqual(t, size, MaxOriginalRetentionOrgs, "the resolver map stays bounded")
	})
}
