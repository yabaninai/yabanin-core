package router

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAffinityRedis is an in-memory affinityRedis double.
type fakeAffinityRedis struct {
	m          map[string]string
	setErr     error
	getErr     error
	pexpireErr error
	setCalls   int
}

func newFakeAffinityRedis() *fakeAffinityRedis {
	return &fakeAffinityRedis{m: make(map[string]string)}
}

func (f *fakeAffinityRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	if f.getErr != nil {
		cmd.SetErr(f.getErr)
		return cmd
	}
	v, ok := f.m[key]
	if !ok {
		cmd.SetErr(redis.Nil)
		return cmd
	}
	cmd.SetVal(v)
	return cmd
}

func (f *fakeAffinityRedis) Set(ctx context.Context, key string, value interface{}, _ time.Duration) *redis.StatusCmd {
	f.setCalls++
	cmd := redis.NewStatusCmd(ctx)
	if f.setErr != nil {
		cmd.SetErr(f.setErr)
		return cmd
	}
	f.m[key] = value.(string)
	cmd.SetVal("OK")
	return cmd
}

func (f *fakeAffinityRedis) PExpire(ctx context.Context, key string, _ time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx)
	if f.pexpireErr != nil {
		cmd.SetErr(f.pexpireErr)
		return cmd
	}
	_, ok := f.m[key]
	cmd.SetVal(ok)
	return cmd
}

func TestRedisAffinity_RecordAndPreferred(t *testing.T) {
	fake := newFakeAffinityRedis()
	a := NewRedisSessionAffinity(fake, time.Minute, 512, nil)

	a.Record(context.Background(), "org-1", "s1", "model-a", 1000) // above threshold → sets the model
	assert.Equal(t, "model-a", a.Preferred(context.Background(), "org-1", "s1"))
	assert.Equal(t, 1, fake.setCalls)
}

func TestRedisAffinity_BelowThresholdRefreshesOnly(t *testing.T) {
	fake := newFakeAffinityRedis()
	a := NewRedisSessionAffinity(fake, time.Minute, 512, nil)

	a.Record(context.Background(), "org-1", "s1", "model-a", 1000)
	a.Record(context.Background(), "org-1", "s1", "model-b", 10) // below threshold → must NOT overwrite model
	assert.Equal(t, "model-a", a.Preferred(context.Background(), "org-1", "s1"), "below-threshold record keeps the existing model")
	assert.Equal(t, 1, fake.setCalls, "below-threshold record does not SET")
}

func TestRedisAffinity_AbsentPreferredIsEmpty(t *testing.T) {
	fake := newFakeAffinityRedis()
	a := NewRedisSessionAffinity(fake, time.Minute, 512, nil)
	assert.Empty(t, a.Preferred(context.Background(), "org-1", "never-seen"))
}

func TestRedisAffinity_EmptySessionIgnored(t *testing.T) {
	fake := newFakeAffinityRedis()
	a := NewRedisSessionAffinity(fake, time.Minute, 512, nil)
	a.Record(context.Background(), "org-1", "", "model", 1000)
	assert.Empty(t, a.Preferred(context.Background(), "org-1", ""))
	assert.Equal(t, 0, fake.setCalls, "empty session must not write")
}

func TestRedisAffinity_RedisErrorDegradesGracefully(t *testing.T) {
	fake := newFakeAffinityRedis()
	fake.getErr = assert.AnError
	fake.setErr = assert.AnError
	a := NewRedisSessionAffinity(fake, time.Minute, 512, nil)

	// A Redis failure must not panic and Preferred degrades to "".
	assert.NotPanics(t, func() { a.Record(context.Background(), "org-1", "s1", "model-a", 1000) })
	assert.Empty(t, a.Preferred(context.Background(), "org-1", "s1"))
}

func TestRedisAffinity_DefaultsApplied(t *testing.T) {
	fake := newFakeAffinityRedis()
	a := NewRedisSessionAffinity(fake, 0, 0, nil)
	require.NotNil(t, a)
	// minTokens default 512: a 100-token record is below threshold (no SET).
	a.Record(context.Background(), "org-1", "s1", "model", 100)
	assert.Equal(t, 0, fake.setCalls)
}
