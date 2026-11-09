package historyops

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fence regression suite (HIST-05, audit ledger 2026-11-02): a worker
// whose lease expired and whose job was taken over by another worker must
// stop at the batch loop's reload WITHOUT executing the batch, checkpointing,
// or touching the new owner's lease/error state — the store's hold() guard
// alone cannot prevent the stale worker from using the NEW owner's worker id
// in its release/finalize calls, because a reloaded job carries the new
// owner's identity.

// takeoverStore wraps the memory store: the Nth engine reload (JobByID)
// simulates the full takeover timeline a slow reload races against — lease
// expiry, recovery requeue, worker B's claim — and then returns the (now
// B-owned) job, so the engine observes a completed takeover at its fence.
type takeoverStore struct {
	JobStore
	t        *testing.T
	clock    *fakeClock
	jobID    string
	atReload int
	cancelOn bool // also request a cancel as part of the takeover

	mu      sync.Mutex
	reloads int
	fired   bool
}

func (s *takeoverStore) JobByID(ctx context.Context, orgID, jobID string) (*Job, error) {
	s.mu.Lock()
	s.reloads++
	fire := s.reloads == s.atReload && !s.fired
	s.mu.Unlock()
	if fire {
		s.clock.Advance(31 * time.Second)
		recovered, err := s.RecoverExpiredLeases(ctx)
		require.NoError(s.t, err)
		require.Equal(s.t, 1, recovered, "takeover hook: the expired lease is requeued")
		claimed, err := s.ClaimNext(ctx, "worker-b", 30*time.Second)
		require.NoError(s.t, err)
		require.NotNil(s.t, claimed)
		require.Equal(s.t, s.jobID, claimed.ID, "takeover hook: worker B claims the same job")
		if s.cancelOn {
			require.NoError(s.t, s.RequestCancel(ctx, orgID, jobID, s.clock.Now()))
		}
		s.mu.Lock()
		s.fired = true
		s.mu.Unlock()
	}
	// Qualified selector: JobByID is this override itself — the embedded
	// shorthand would recurse.
	return s.JobStore.JobByID(ctx, orgID, jobID)
}

// armTakeover swaps the harness store for a takeover store firing on the
// engine's atReload-th reload (reload 1 = before batch 0, reload 2 = before
// batch 1).
func armTakeover(t *testing.T, h *testHarness, atReload int, cancelOn bool) *takeoverStore {
	t.Helper()
	ts := &takeoverStore{JobStore: h.store, t: t, clock: h.clock, atReload: atReload, cancelOn: cancelOn}
	h.engine.store = ts
	return ts
}

// TestStaleWorkerFencedBeforeBatchEffect: worker A's reload observes worker
// B's completed takeover; A must stop without executing batch 1 and without
// writing checkpoint, lease or error state over B's claim.
func TestStaleWorkerFencedBeforeBatchEffect(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}, {"r2"}}, "r1", "r2")
	ctx := context.Background()
	t0 := h.clock.Now()
	ts := armTakeover(t, h, 2, false)

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-fence")
	ts.jobID = job.ID
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored := mustJob(t, ctx, h, job.ID)
	require.Equal(t, JobProcessing, stored.Status,
		"the stale worker leaves the job with its new owner")
	require.Equal(t, "worker-b", stored.WorkerID)
	require.True(t, stored.LeaseUntil.Equal(t0.Add(61*time.Second)),
		"worker B's claim lease (t0+31s claim, 30s TTL) is untouched: got %s", stored.LeaseUntil)
	require.Equal(t, 2, stored.Attempts, "A's claim + B's claim, no further mutations")
	require.Empty(t, stored.LastError, "no release-for-retry noise written over B's claim")

	_, applied, exec := h.runner.snapshot()
	assert.Equal(t, 1, exec[0], "batch 0 executed once while the lease was held")
	assert.Zero(t, exec[1],
		"the fenced stale worker must NOT execute batch 1 after the takeover")
	assert.Equal(t, 1, applied["r1"])
	assert.Zero(t, applied["r2"], "batch 1's row stays hot for worker B")

	assert.Equal(t, 1, h.journal.Count(ActionStarted))
	assert.Zero(t, h.journal.Count(ActionCompleted), "the job is not terminal — B owns it")
	assert.Zero(t, h.journal.Count(ActionCanceled))
	assert.Zero(t, h.journal.Count(ActionDenied))
}

// TestStaleWorkerRefusalCannotFailNewOwner: the sharpest variant — the stale
// worker's batch would fail with a refusal. The failure path must never
// finalize the job using the new owner's worker id (which the store guard
// would ACCEPT, failing a job B is actively processing).
func TestStaleWorkerRefusalCannotFailNewOwner(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}, {"r2"}}, "r1", "r2")
	ctx := context.Background()
	t0 := h.clock.Now()
	ts := armTakeover(t, h, 2, false)
	h.runner.batchErr = map[int]error{1: Refuse(RefusalActiveGrant, "grant became active")}

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-fence-refusal")
	ts.jobID = job.ID
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored := mustJob(t, ctx, h, job.ID)
	require.Equal(t, JobProcessing, stored.Status,
		"a stale worker's refusal must not fail the job its new owner is processing")
	require.Equal(t, "worker-b", stored.WorkerID)
	require.Nil(t, stored.Refusal, "no refusal recorded over worker B's claim")
	require.True(t, stored.LeaseUntil.After(t0.Add(45*time.Second)),
		"worker B's live lease survives the stale worker's error path")

	_, _, exec := h.runner.snapshot()
	assert.Zero(t, exec[1], "the fenced stale worker never reached the failing batch")
	assert.Zero(t, h.journal.Count(ActionDenied),
		"the stale worker's refusal is not journalled as the job's denial")
}

// TestStaleWorkerCancelFencedAfterTakeover: cancel requested during the
// takeover window — the fence runs BEFORE the cancel check, so the stale
// worker stops silently and leaves the cancel for the new owner to observe
// (finalizing a cancel over B's claim would be a stale-identity mutation of
// a live lease).
func TestStaleWorkerCancelFencedAfterTakeover(t *testing.T) {
	h := newTestHarness(t, [][]string{{"r1"}, {"r2"}}, "r1", "r2")
	ctx := context.Background()
	ts := armTakeover(t, h, 2, true)

	job := h.enqueue(t, OpArchiveRemoveHot, "cleanup-fence-cancel")
	ts.jobID = job.ID
	claimed, err := h.engine.ExecuteNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, claimed)

	stored := mustJob(t, ctx, h, job.ID)
	require.Equal(t, JobProcessing, stored.Status,
		"the cancel belongs to the new owner's loop, not the fenced stale worker")
	require.Equal(t, "worker-b", stored.WorkerID)
	require.False(t, stored.CancelRequested.IsZero(),
		"the cancel request stays pending for worker B's next reload")
	_, _, exec := h.runner.snapshot()
	assert.Zero(t, exec[1])
	assert.Zero(t, h.journal.Count(ActionCanceled))
}
