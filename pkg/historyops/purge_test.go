package historyops

// Unit tests for the purge enqueue gate (confirmation binding, single-use
// digest idempotency, rights) and the pure plan-assembly ordering. The
// database-backed behavior lives in purge_int_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// newPurgeEnqueueHarness is a DB-free engine harness for enqueue-gate tests:
// the default (zero) stamp keeps the digest computation deterministic.
func newPurgeEnqueueHarness(t *testing.T) (*Engine, *MemoryJournaler) {
	t.Helper()
	clock := newFakeClock()
	clock.Advance(8 * 24 * time.Hour) // past previewPeriod, so selections validate closed
	journal := &MemoryJournaler{}
	engine := NewEngine(NewMemoryJobStore(clock.Now), journal, EngineConfig{
		LeaseTTL: time.Minute, MaxAttempts: 3, Interval: time.Second, Now: clock.Now,
	})
	return engine, journal
}

// purgeDigestFor computes the digest an enqueue must echo, under the same
// default stamp the harness engine uses.
func purgeDigestFor(t *testing.T, sel Selection) string {
	t.Helper()
	digest, err := SelectionDigest(OpPurge, sel, SchemaStamp{FamiliesSchemaVersion: FamiliesSchemaVersion})
	require.NoError(t, err)
	return digest
}

func TestEnqueuePurgeConfirmationGate(t *testing.T) {
	engine, journal := newPurgeEnqueueHarness(t)
	ctx := context.Background()
	sel := previewSelection(testOrg, FamilyRequestLogs)
	digest := purgeDigestFor(t, sel)

	purgeReq := func(confirmation, idemKey string) EnqueueRequest {
		return EnqueueRequest{
			OrgID: testOrg, Op: OpPurge, Selection: sel,
			PresentedDigest: digest, Confirmation: confirmation, IdempotencyKey: idemKey,
			Actor: JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
		}
	}

	// Missing confirmation: refused, zero jobs, journalled denial.
	_, err := engine.Enqueue(ctx, purgeReq("", "caller-key-1"))
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "missing confirmation must refuse typed, got %v", err)
	assert.Equal(t, RefusalPurgeConfirmationMissing, refusal.Code)
	assert.Equal(t, 1, journal.Count(ActionDenied))
	assert.Zero(t, journal.Count(ActionStarted))

	// Wrong confirmation (stale digest from another scope/schema): refused.
	_, err = engine.Enqueue(ctx, purgeReq("deadbeef", "caller-key-2"))
	refusal, ok = RefusalOf(err)
	require.True(t, ok, "wrong confirmation must refuse typed, got %v", err)
	assert.Equal(t, RefusalDigestMismatch, refusal.Code)
	assert.Equal(t, 2, journal.Count(ActionDenied))

	// Correct echo: one job, and the idempotency key IS the digest — the
	// caller-supplied key is ignored (single use without a token store).
	job, err := engine.Enqueue(ctx, purgeReq(digest, "caller-key-3"))
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, digest, job.IdempotencyKey,
		"the confirmed digest is the single-use key, not the caller's key")
	assert.Equal(t, digest, job.SelectionDigest)
	assert.Equal(t, 1, journal.Count(ActionStarted))

	// Replay: same scope + same echo returns the SAME job — a second purge
	// of one confirmed scope is impossible; even a replay that forgot the
	// confirmation replays the stored decision.
	replayed, err := engine.Enqueue(ctx, purgeReq("", "caller-key-4"))
	require.NoError(t, err)
	assert.Equal(t, job.ID, replayed.ID)
	assert.Equal(t, 1, journal.Count(ActionStarted), "replay journals nothing new")
}

func TestEnqueuePurgeRightsGate(t *testing.T) {
	engine, journal := newPurgeEnqueueHarness(t)
	ctx := context.Background()
	sel := previewSelection(testOrg, FamilyRequestLogs)
	digest := purgeDigestFor(t, sel)

	viewer := Caller{
		UserID: "u-viewer",
		Role:   adminstore.RoleReader,
		Perms:  map[adminstore.Permission]bool{adminstore.PermRequestsRead: true},
	}
	_, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: testOrg, Op: OpPurge, Selection: sel, PresentedDigest: digest,
		Confirmation: digest, IdempotencyKey: "k-viewer",
		Actor: JobActor{Author: "u-viewer"}, Caller: viewer,
	})
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "viewer purge must refuse typed, got %v", err)
	assert.Equal(t, RefusalInsufficientRights, refusal.Code)
	assert.Equal(t, 1, journal.Count(ActionDenied))
}

func TestAssemblePurgeBatchesOrdering(t *testing.T) {
	work := &purgeSelection{
		plannedReqIDs:  map[string]bool{"req-1": true, "req-2": true},
		attachedTools:  map[string][]int64{"req-1": {11}},
		attachedInvocs: map[string][]int64{"req-2": {21, 22}},
		requestRows: []purgeRequestRow{
			{ID: 1, RequestID: "req-1"},
			{ID: 2, RequestID: "req-2"},
		},
		toolIDs:       []int64{31},
		invocationIDs: []int64{32},
		cacheIDs:      []string{"6f1e9c76-9f9e-4a1e-b0a2-6f3e1e9b7d01"},
		sessionIDs:    []string{"6f1e9c76-9f9e-4a1e-b0a2-6f3e1e9b7d02"},
	}

	batches := assemblePurgeBatches(work, 1)
	require.NotEmpty(t, batches)

	// Batch 0 = the first request WITH its attached tool row (same logical
	// unit); batch 1 = the second request with its two invocations.
	assert.Equal(t, []string{
		encodePlanID(FamilyRequestLogs, "1"),
		encodePlanID(FamilyToolCalls, "11"),
	}, batches[0])
	assert.Equal(t, []string{
		encodePlanID(FamilyRequestLogs, "2"),
		encodePlanID(FamilyToolCallInvocations, "21"),
		encodePlanID(FamilyToolCallInvocations, "22"),
	}, batches[1])

	// Standalone tool rows form their own batches; sessions are strictly
	// LAST so this job's own request batches have committed before any
	// session delete runs.
	flat := make([]Family, 0, 8)
	for _, b := range batches {
		for _, pid := range b {
			f, _, err := decodePlanID(pid)
			require.NoError(t, err)
			flat = append(flat, f)
		}
	}
	last := flat[len(flat)-1]
	assert.Equal(t, FamilySessions, last, "sessions batch runs last")
	for i, f := range flat {
		if f == FamilySessions {
			assert.Equal(t, len(flat)-1, i, "no family may follow a session id")
		}
	}

	// Chunking: three cache ids with batch size 2 → 2+1.
	chunkWork := &purgeSelection{
		plannedReqIDs: map[string]bool{},
		attachedTools: map[string][]int64{}, attachedInvocs: map[string][]int64{},
		cacheIDs: []string{"a", "b", "c"},
	}
	chunks := assemblePurgeBatches(chunkWork, 2)
	require.Len(t, chunks, 2)
	assert.Len(t, chunks[0], 2)
	assert.Len(t, chunks[1], 1)
}

func TestExecutePurgeBatchRejectsCorruptedPlanBeforeDB(t *testing.T) {
	runner := NewPurgeRunner(nil, PurgeConfig{}) // nil pool: any DB touch panics
	sel := previewSelection(testOrg, FamilyRequestLogs)
	job := &Job{OrgID: testOrg, Op: OpPurge, Selection: sel, Checkpoint: Checkpoint{Planned: true}}

	// Malformed plan id → invalid request before any database access.
	_, err := runner.ExecuteBatch(t.Context(), job, 0, []string{"not-a-plan-id"})
	require.ErrorIs(t, err, ErrInvalidRequest)

	// Family outside the selection → invalid request before any DB access
	// (corrupted checkpoints must never widen the delete scope).
	_, err = runner.ExecuteBatch(t.Context(), job, 0, []string{
		encodePlanID(FamilyCacheEntries, "6f1e9c76-9f9e-4a1e-b0a2-6f3e1e9b7d03"),
	})
	require.ErrorIs(t, err, ErrInvalidRequest, "family outside selection")
}
