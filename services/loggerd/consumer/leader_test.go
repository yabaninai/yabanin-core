package consumer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// fakeLeaderRedis simulates a single-key Redis lock with owner fencing,
// mirroring the renew/release Lua semantics.
type fakeLeaderRedis struct {
	mu      sync.Mutex
	holder  string // "" = unlocked
	setErr  error
	evalErr error
}

func (f *fakeLeaderRedis) SetNX(ctx context.Context, _ string, value any, _ time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx)
	if f.setErr != nil {
		cmd.SetErr(f.setErr)
		return cmd
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holder == "" {
		f.holder = value.(string)
		cmd.SetVal(true)
	} else {
		cmd.SetVal(false)
	}
	return cmd
}

func (f *fakeLeaderRedis) Eval(ctx context.Context, script string, _ []string, args ...interface{}) *redis.Cmd {
	cmd := redis.NewCmd(ctx)
	if f.evalErr != nil {
		cmd.SetErr(f.evalErr)
		return cmd
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	isRenew := len(args) == 2 // (id, ttlMs)
	id := args[0].(string)
	if strings.Contains(script, "pexpire") { // renewScript
		if isRenew && f.holder == id {
			cmd.SetVal(int64(1))
		} else {
			cmd.SetVal(int64(0))
		}
		return cmd
	}
	// releaseScript
	if f.holder == id {
		f.holder = ""
		cmd.SetVal(int64(1))
	} else {
		cmd.SetVal(int64(0))
	}
	return cmd
}

func TestLeader_TryAcquireExclusive(t *testing.T) {
	fake := &fakeLeaderRedis{}
	l1 := NewLeader(fake, "k", "replica-1", time.Second, nil)
	l2 := NewLeader(fake, "k", "replica-2", time.Second, nil)

	ok1, err := l1.TryAcquire(context.Background())
	require.NoError(t, err)
	assert.True(t, ok1, "first replica acquires")
	assert.True(t, l1.IsHeld())

	ok2, err := l2.TryAcquire(context.Background())
	require.NoError(t, err)
	assert.False(t, ok2, "second replica is blocked while the first holds the lock")
	assert.False(t, l2.IsHeld())
}

func TestLeader_RenewFenced(t *testing.T) {
	fake := &fakeLeaderRedis{}
	l1 := NewLeader(fake, "k", "replica-1", time.Second, nil)
	l2 := NewLeader(fake, "k", "replica-2", time.Second, nil)
	_, _ = l1.TryAcquire(context.Background())

	// The owner can renew.
	still, err := l1.Renew(context.Background())
	require.NoError(t, err)
	assert.True(t, still)

	// A non-owner cannot renew (fencing).
	still, err = l2.Renew(context.Background())
	require.NoError(t, err)
	assert.False(t, still, "a non-holder's renew must be rejected")
}

func TestLeader_ReleaseFenced(t *testing.T) {
	fake := &fakeLeaderRedis{}
	l1 := NewLeader(fake, "k", "replica-1", time.Second, nil)
	l2 := NewLeader(fake, "k", "replica-2", time.Second, nil)
	_, _ = l1.TryAcquire(context.Background())

	// A non-owner cannot release the owner's lock (fencing).
	require.NoError(t, l2.Release(context.Background()))
	// l1 still holds it, so l2's acquire fails.
	stillHeld, err := l2.TryAcquire(context.Background())
	require.NoError(t, err)
	assert.False(t, stillHeld, "lock is still held by l1 after l2's fenced release")
	assert.False(t, l2.IsHeld())

	// The owner can release; then the other can acquire.
	require.NoError(t, l1.Release(context.Background()))
	ok2, err := l2.TryAcquire(context.Background())
	require.NoError(t, err)
	assert.True(t, ok2, "after the owner releases, another replica can acquire")
}

func TestLeader_RenewErrorKeepsHeldState(t *testing.T) {
	fake := &fakeLeaderRedis{}
	l := NewLeader(fake, "k", "r1", time.Second, nil)
	_, _ = l.TryAcquire(context.Background())
	fake.evalErr = assert.AnError
	still, err := l.Renew(context.Background())
	require.Error(t, err)
	assert.True(t, still, "on a transient error the prior held state is reported")
}

func TestLeader_LeadRunsWorkloadAndReleasesOnShutdown(t *testing.T) {
	fake := &fakeLeaderRedis{}
	l := NewLeader(fake, "k", "r1", 60*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{})
	leadDone := make(chan error, 1)
	go func() {
		leadDone <- l.Lead(ctx, func(fnCtx context.Context) error {
			close(ran)
			<-fnCtx.Done() // block until the leader context is cancelled
			return nil
		})
	}()

	<-ran // Lead promoted this replica and started the workload
	assert.True(t, l.IsHeld(), "leader holds the lock while running the workload")

	cancel() // trigger shutdown
	require.NoError(t, <-leadDone, "Lead returns cleanly on shutdown")
	assert.False(t, l.IsHeld(), "leader released on shutdown")
}

func TestLeader_LeadStandbyThenTakeover(t *testing.T) {
	fake := &fakeLeaderRedis{}
	// Pre-hold the lock as another replica so our Leader starts in standby.
	other := NewLeader(fake, "k", "other", time.Second, nil)
	_, _ = other.TryAcquire(context.Background())

	l := NewLeader(fake, "k", "r1", 60*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ran := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- l.Lead(ctx, func(fnCtx context.Context) error {
			ran <- struct{}{}
			<-fnCtx.Done()
			return nil
		})
	}()

	// Stand by until "other" releases (simulating the other leader dying).
	// While "other" holds the lock our replica's TryAcquire fails, so it never
	// becomes held — a deterministic (non-timing) assertion.
	time.Sleep(30 * time.Millisecond)
	assert.False(t, l.IsHeld(), "standby replica does not hold while another leads")
	require.NoError(t, other.Release(context.Background()))

	// Our replica should take over and start the workload.
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for takeover")
	}
}

func TestLeader_Lead_WorkloadError_IncrementsMetric(t *testing.T) {
	// leader_fn_failed_total — instead of silently discarded.
	before := testutil.ToFloat64(metrics.LeaderFnFailedTotal)

	fake := &fakeLeaderRedis{}
	l := NewLeader(fake, "k", "r1", 60*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{})
	var once sync.Once
	leadDone := make(chan error, 1)
	go func() {
		leadDone <- l.Lead(ctx, func(fnCtx context.Context) error {
			once.Do(func() { close(ran) })
			return errors.New("workload crashed")
		})
	}()

	<-ran // Lead promoted this replica and started the workload

	// The fn fails immediately and Lead re-elects in a loop; the counter must
	// grow within the election interval.
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.LeaderFnFailedTotal) > before
	}, 2*time.Second, 5*time.Millisecond,
		"leader_fn_failed_total must increment when the workload fails")

	cancel() // stop the re-election loop
	require.NoError(t, <-leadDone, "Lead returns cleanly on shutdown")
}
