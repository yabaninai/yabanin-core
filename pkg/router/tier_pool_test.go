package router

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// mockModelLoader returns a fixed set of models.
type mockModelLoader struct {
	models []ModelInfo
}

func (m *mockModelLoader) ListModels(_ context.Context) ([]ModelInfo, error) {
	return m.models, nil
}

// mockRedisClient is a simple in-memory counter for weighted round-robin.
type mockRedisClient struct {
	counters map[string]int64
}

func newMockRedis() *mockRedisClient {
	return &mockRedisClient{counters: make(map[string]int64)}
}

func (m *mockRedisClient) Incr(_ context.Context, key string) *redis.IntCmd {
	m.counters[key]++
	return redis.NewIntResult(m.counters[key], nil)
}

func (m *mockRedisClient) Expire(_ context.Context, _ string, _ time.Duration) *redis.BoolCmd {
	return redis.NewBoolResult(true, nil)
}

func TestTierRouter_SelectEasy_ReturnsCheapModel(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "gemma-7b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "gpt-4o", Tier: "turbo", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}
	rdb := newMockRedis()

	router := NewTierRouter(loader, rdb)

	selected, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "gemma-7b", selected.Name)
}

func TestTierRouter_SelectHard_ReturnsPremiumModel(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "gpt-4o", Tier: "turbo", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}
	rdb := newMockRedis()

	router := NewTierRouter(loader, rdb)

	selected, err := router.SelectModel(context.Background(), classifier.ClassHard, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o", selected.Name)
}

func TestTierRouter_LoadBalancing_DistributesByWeight(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "cheap-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 3, Enabled: true},
		{Name: "cheap-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	rdb := newMockRedis()

	router := NewTierRouter(loader, rdb)

	// Send 40 requests and count distribution.
	counts := make(map[string]int)
	for i := 0; i < 40; i++ {
		sel, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
		require.NoError(t, err)
		counts[sel.Name]++
	}

	// cheap-a should have roughly 3x more selections than cheap-b.
	assert.Greater(t, counts["cheap-a"], counts["cheap-b"])
	total := counts["cheap-a"] + counts["cheap-b"]
	assert.Equal(t, 40, total)
}

func TestTierRouter_EmptyPool_FallbacksToMedium(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "gpt-4o", Tier: "turbo", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}
	rdb := newMockRedis()

	router := NewTierRouter(loader, rdb)

	// No models for easy → should fallback to hard (first in fallback chain).
	selected, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o", selected.Name)
}

func TestTierRouter_DisabledModelsSkipped(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "disabled-model", TierPool: []string{"easy"}, Weight: 1, Enabled: false},
	}}
	rdb := newMockRedis()

	router := NewTierRouter(loader, rdb)

	_, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no models available")
}

func TestTierRouter_NoRedis_FallbacksToSimpleSelection(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	router := NewTierRouter(loader, nil) // no Redis

	sel, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "model-a", sel.Name)
}

func TestTierRouter_NoRedis_NeverSelectsZeroWeightModel(t *testing.T) {
	// The no-Redis fallback must walk the same cumulative-weight
	// distribution as the Redis path: a weight-0 member (a canary candidate
	// parked in the pool for the session-hash swap) is never directly
	// selectable — a direct pick would serve canary traffic outside the
	// rollout's percent split and its rollback governance.
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"easy"}, Weight: 0, Enabled: true},
	}}
	router := NewTierRouter(loader, nil) // no Redis

	for i := 0; i < 400; i++ {
		sel, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
		require.NoError(t, err)
		require.NotEqual(t, "canary-model", sel.Name,
			"selection %d: a weight-0 canary candidate must never be picked directly", i)
	}
}

func TestTierRouter_CacheRefresh_AfterTTL(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-old", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	router := NewTierRouter(loader, newMockRedis())

	// First selection loads the cache.
	sel1, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "model-old", sel1.Name)

	// Replace models in loader (simulating a DB update).
	loader.models = []ModelInfo{
		{Name: "model-new", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}

	// Force TTL expiry by setting loaded to the past.
	router.mu.Lock()
	router.loaded = time.Now().Add(-2 * time.Minute)
	router.mu.Unlock()

	// Should pick up the new model.
	sel2, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "model-new", sel2.Name)
}

func TestTierRouter_MultiTierPool(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		// This model serves BOTH easy and medium tiers.
		{Name: "versatile", TierPool: []string{"easy", "medium"}, Weight: 1, Enabled: true},
	}}
	rdb := newMockRedis()

	router := NewTierRouter(loader, rdb)

	selEasy, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "versatile", selEasy.Name)

	selMed, err := router.SelectModel(context.Background(), classifier.ClassMedium, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "versatile", selMed.Name)
}

func TestTierRouter_SelectWithAffinity_PreferredInPool_IsChosen(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "cheap-a", TierPool: []string{"easy"}, Weight: 3, Enabled: true},
		{Name: "cheap-b", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	router := NewTierRouter(loader, newMockRedis())

	selected, err := router.SelectModelWithAffinity(context.Background(), classifier.ClassEasy, "org-1", "cheap-b")
	require.NoError(t, err)
	assert.Equal(t, "cheap-b", selected.Name)
}

func TestTierRouter_SelectWithAffinity_PreferredNotInPool_FallsBackNoPanic(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "cheap-a", TierPool: []string{"easy"}, Weight: 3, Enabled: true},
		{Name: "cheap-b", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	router := NewTierRouter(loader, newMockRedis())

	// Preferred model absent from the pool (e.g. filtered by sovereignty or
	// simply not loaded) → normal weighted selection, no panic.
	selected, err := router.SelectModelWithAffinity(context.Background(), classifier.ClassEasy, "org-1", "gpt-5.2-not-in-pool")
	require.NoError(t, err)
	assert.Contains(t, []string{"cheap-a", "cheap-b"}, selected.Name)
}

func TestTierRouter_SelectWithAffinity_EmptyPreferred_BehavesLikeSelectModel(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "solo", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	router := NewTierRouter(loader, newMockRedis())

	// Empty preferred = legacy behavior.
	selected, err := router.SelectModelWithAffinity(context.Background(), classifier.ClassEasy, "org-1", "")
	require.NoError(t, err)
	assert.Equal(t, "solo", selected.Name)

	// SelectModel delegates with empty preferred.
	legacy, err := router.SelectModel(context.Background(), classifier.ClassEasy, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "solo", legacy.Name)
}
