package router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRT01_Affinity_SameSessionIDTwoOrgs_Isolated_Memory(t *testing.T) {
	sa := NewSessionAffinity(0, 0, 0)
	sa.Record(context.Background(), "org-a", "sess-1", "model-a", 1000)
	sa.Record(context.Background(), "org-b", "sess-1", "model-b", 1000)

	assert.Equal(t, "model-a", sa.Preferred(context.Background(), "org-a", "sess-1"),
		"org A must not see org B's sticky model for the same session ID")
	assert.Equal(t, "model-b", sa.Preferred(context.Background(), "org-b", "sess-1"))
	assert.Empty(t, sa.Preferred(context.Background(), "org-c", "sess-1"), "unknown org must have no affinity")
	assert.Empty(t, sa.Preferred(context.Background(), "", "sess-1"), "empty org must never read an entry")
}

func TestRT01_Affinity_SameSessionIDTwoOrgs_Isolated_Redis(t *testing.T) {
	fake := newFakeAffinityRedis()
	sa := NewRedisSessionAffinity(fake, 0, 0, nil)
	sa.Record(context.Background(), "org-a", "sess-1", "model-a", 1000)
	sa.Record(context.Background(), "org-b", "sess-1", "model-b", 1000)

	assert.Equal(t, "model-a", sa.Preferred(context.Background(), "org-a", "sess-1"),
		"org A must not see org B's sticky model for the same session ID")
	assert.Equal(t, "model-b", sa.Preferred(context.Background(), "org-b", "sess-1"))
}

func TestRT01_Affinity_LegacyUnscopedEntryIgnored_Redis(t *testing.T) {
	fake := newFakeAffinityRedis()
	// A pre-RT-01 unscoped entry must never be read: its model has no org
	// binding, so honoring it could leak another org's routing.
	fake.m["yb:affinity:sess-1"] = "legacy-model"

	sa := NewRedisSessionAffinity(fake, 0, 0, nil)
	assert.Empty(t, sa.Preferred(context.Background(), "org-a", "sess-1"),
		"legacy unscoped affinity entries must be ignored")

	// A new org-scoped write lands on the v2 layout and is then read back.
	sa.Record(context.Background(), "org-a", "sess-1", "model-a", 1000)
	require.Contains(t, fake.m, "yb:affinity:v2:org-a:sess-1")
	assert.Equal(t, "model-a", sa.Preferred(context.Background(), "org-a", "sess-1"))
}
