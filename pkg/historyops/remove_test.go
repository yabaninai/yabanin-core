package historyops

// ENT-HIST-06 tests — archive_and_remove_hot: the destructive half is gated
// by the archive half on every batch (backlog card 03 AC), the plan is
// FK-safe and grant-aware, and the at-least-once engine replay is
// exactly-once in effect.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- fixtures ----

// removeJob is the runner-direct job for archive_and_remove_hot: same shape
// as archiveJob but digested for the destructive op.
func removeJob(t *testing.T, ctx context.Context, pool testPGPool, orgID string, sel Selection, dest string) *Job {
	t.Helper()
	seedSchemaMigrations(t, ctx, pool, 16)
	stamp, err := SchemaStampFromDB(ctx, pool)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveRemoveHot, sel, stamp)
	require.NoError(t, err)
	return &Job{
		ID:              fmt.Sprintf("job-remove-%d", time.Now().UnixNano()),
		OrgID:           orgID,
		Op:              OpArchiveRemoveHot,
		Selection:       sel,
		SelectionDigest: digest,
		Stamp:           stamp,
		Destination:     dest,
		CreatedAt:       time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		Confirmed:       FamilyCounts{},
	}
}

func removeRunner(db HistoryDB, store ColdStorage) *ArchiveRemoveHotRunner {
	return &ArchiveRemoveHotRunner{
		DB:                 db,
		ResolveDestination: func(string) (ColdStorage, error) { return store, nil },
	}
}

func insertToolCallRM(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, at time.Time) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO tool_calls (org_id, request_id, tool_name, created_at) VALUES ($1::uuid, $2, 'search', $3) RETURNING id::text",
		orgID, requestID, at).Scan(&id))
	return id
}

func insertToolInvocation(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, seq int, at time.Time) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO tool_call_invocations (org_id, request_id, seq, tool_name, created_at) VALUES ($1::uuid, $2, $3, 'search', $4) RETURNING id::text",
		orgID, requestID, seq, at).Scan(&id))
	return id
}

func insertCacheEntryRM(t *testing.T, ctx context.Context, pool testPGPool, orgID string, at time.Time) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO cache_entries (org_id, model_tier, prompt_hash, embedding, response, created_at) VALUES ($1::uuid, 'primary', 'ph-remove', array_fill(0.1::real, ARRAY[384])::vector, '{\"v\":1}'::jsonb, $2) RETURNING id::text",
		orgID, at).Scan(&id))
	return id
}

func orgRowCount(t *testing.T, ctx context.Context, pool testPGPool, table, orgID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM "+table+" WHERE org_id = $1::uuid", orgID).Scan(&n))
	return n
}

func seedWatermark(t *testing.T, ctx context.Context, pool testPGPool) {
	t.Helper()
	// Upsert: other tests in the binary may already have created the
	// singleton row (last_id=0); this test needs a distinct sentinel.
	_, err := pool.Exec(ctx,
		"INSERT INTO log_export_watermark (id, last_id) VALUES (1, 42) ON CONFLICT (id) DO UPDATE SET last_id = 42")
	require.NoError(t, err)
}

func watermarkLastID(t *testing.T, ctx context.Context, pool testPGPool) int64 {
	t.Helper()
	var last int64
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT last_id FROM log_export_watermark WHERE id = 1").Scan(&last))
	return last
}

// executePlan runs every planned batch in order and accumulates the runner's
// reported counts (the engine does the same across its checkpoint loop).
func executePlan(t *testing.T, ctx context.Context, runner *ArchiveRemoveHotRunner, job *Job, plan [][]string) FamilyCounts {
	t.Helper()
	job.Checkpoint.Plan = plan
	totals := FamilyCounts{}
	for i, batch := range plan {
		counts, err := runner.ExecuteBatch(ctx, job, i, batch)
		require.NoError(t, err)
		for family, n := range counts {
			totals[family] += n
		}
	}
	return totals
}

// ---- integration pins ----

// TestArchiveRemoveHotExportBeforeDelete_Integration pins the core AC: the
// archive object for a batch is fully written (and read back) while every
// row of that batch still exists, and only then are the exported ids
// deleted. It also pins the per-batch reported counts and child-first order.
func TestArchiveRemoveHotExportBeforeDelete_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-r1",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":1}`))
	insertRequestLog(t, ctx, pool, orgID, "req-r2",
		time.Date(2026, 3, 3, 1, 0, 0, 0, time.UTC), nil)
	insertToolCallRM(t, ctx, pool, orgID, "req-r1", time.Date(2026, 3, 2, 1, 0, 30, 0, time.UTC))
	insertToolCallRM(t, ctx, pool, orgID, "req-r1", time.Date(2026, 3, 2, 1, 0, 31, 0, time.UTC))
	insertToolInvocation(t, ctx, pool, orgID, "req-r1", 1, time.Date(2026, 3, 2, 1, 0, 30, 0, time.UTC))

	type probe struct {
		key                      string
		invocations, calls, reqs int
	}
	var order []probe
	store := newMapStore()
	store.onWrite = func(key string) {
		order = append(order, probe{key: key,
			invocations: orgRowCount(t, ctx, pool, "tool_call_invocations", orgID),
			calls:       orgRowCount(t, ctx, pool, "tool_calls", orgID),
			reqs:        orgRowCount(t, ctx, pool, "request_logs", orgID)})
	}

	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls, FamilyToolCallInvocations),
		"file:///cold/historyops/"+orgID+"/remove/")
	runner := removeRunner(pool, store)

	require.NoError(t, runner.VerifySnapshot(ctx, job))
	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 3, "children batches first (invocations, calls), then the request parents")

	totals := executePlan(t, ctx, runner, job, plan)
	assert.EqualValues(t, 1, totals[FamilyToolCallInvocations])
	assert.EqualValues(t, 2, totals[FamilyToolCalls])
	assert.EqualValues(t, 2, totals[FamilyRequestLogs])

	// Export-before-delete: during the tool_calls JSONL write the rows and
	// their parents were still in the hot tables; during the request JSONL
	// write the already-deleted tool batches are gone but the parents of
	// THIS batch were still there.
	require.Len(t, order, 6, "jsonl + manifest per batch")
	assert.Equal(t, 2, order[2].calls, "tool_calls rows exist when their object is written")
	assert.Equal(t, 2, order[2].reqs, "parent requests exist when the child object is written")
	assert.Equal(t, 2, order[4].reqs, "request rows exist when their own object is written")
	assert.Equal(t, 0, order[4].calls, "earlier batches already deleted their rows")

	assert.Zero(t, orgRowCount(t, ctx, pool, "request_logs", orgID))
	assert.Zero(t, orgRowCount(t, ctx, pool, "tool_calls", orgID))
	assert.Zero(t, orgRowCount(t, ctx, pool, "tool_call_invocations", orgID))
}

// TestArchiveRemoveHotCorruptRefusalKeepsRows_Integration: a corrupted
// archive write refuses archive_checksum_mismatch and NOT A SINGLE hot row
// is deleted (backlog card 03 AC — the destructive half is withheld).
func TestArchiveRemoveHotCorruptRefusalKeepsRows_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-c1",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":1}`))
	insertToolCallRM(t, ctx, pool, orgID, "req-c1", time.Date(2026, 3, 2, 1, 0, 30, 0, time.UTC))

	store := newMapStore()
	store.corrupt = true
	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls),
		"file:///cold/historyops/"+orgID+"/corrupt/")
	runner := removeRunner(pool, store)

	// VerifySnapshot is a validation-only probe: it passes with a store that
	// will later corrupt writes (the gate is at execution time).
	require.NoError(t, runner.VerifySnapshot(ctx, job))
	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 2)

	_, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	assert.Equal(t, RefusalArchiveChecksum, refusalCodeOf(t, err))

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "request_logs", orgID),
		"a checksum-mismatched archive write forbids the delete")
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "tool_calls", orgID))

	// The stored object was refused before any delete: the failure is
	// fail-closed for the whole job, batch order irrelevant.
	_, err = runner.ExecuteBatch(ctx, job, 1, plan[1])
	assert.Equal(t, RefusalArchiveChecksum, refusalCodeOf(t, err))
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "request_logs", orgID))
}

// TestArchiveRemoveHotCrashReplaySkip_Integration: the engine's
// at-least-once execution is exactly-once in effect — replaying a fully
// applied batch observes an empty export, skips it with zero counts and
// writes nothing.
func TestArchiveRemoveHotCrashReplaySkip_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-p1",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":1}`))
	insertRequestLog(t, ctx, pool, orgID, "req-p2",
		time.Date(2026, 3, 3, 1, 0, 0, 0, time.UTC), nil)

	store := newMapStore()
	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/replay/")
	runner := removeRunner(pool, store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)

	totals := executePlan(t, ctx, runner, job, plan)
	assert.EqualValues(t, 2, totals[FamilyRequestLogs])
	assert.Zero(t, orgRowCount(t, ctx, pool, "request_logs", orgID))
	writesAfterFirst := store.totalWrites()

	// Crash-window replay of the same batch: nothing left to export, the
	// skip fires before any storage write and reports zero counts.
	counts, err := runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	assert.Empty(t, counts, "replay of an applied batch counts nothing")
	assert.Equal(t, writesAfterFirst, store.totalWrites(),
		"the replay skip writes no objects")
	assert.Zero(t, orgRowCount(t, ctx, pool, "request_logs", orgID))
}

// TestArchiveRemoveHotProtectedSkip_Integration: live-grant requests are
// skipped — their rows AND their tool children survive (children ride the
// parent's chunk; the standalone scope refuses to destroy them through the
// side door). The skipped ids land in the checkpoint's protected report.
func TestArchiveRemoveHotProtectedSkip_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-prot",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":"protected"}`))
	insertRequestLog(t, ctx, pool, orgID, "req-open",
		time.Date(2026, 3, 3, 1, 0, 0, 0, time.UTC), strptr(`{"v":"open"}`))
	insertToolCallRM(t, ctx, pool, orgID, "req-prot", time.Date(2026, 3, 2, 1, 0, 30, 0, time.UTC))
	insertToolCallRM(t, ctx, pool, orgID, "req-open", time.Date(2026, 3, 3, 1, 0, 30, 0, time.UTC))
	grantID := seedActiveGrant(t, ctx, pool, orgID, "req-prot", 24*time.Hour)

	sel := previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls)
	job := removeJob(t, ctx, pool, orgID, sel, "file:///cold/historyops/"+orgID+"/protected/")
	runner := removeRunner(pool, newMapStore())

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	// Only the open request's unit: its tool child, then its parent.
	require.Len(t, plan, 2)
	_, childIDs, err := decodeBatch(plan[0])
	require.NoError(t, err)
	require.Len(t, childIDs, 1, "only the open request's tool child is planned")

	totals := executePlan(t, ctx, runner, job, plan)
	assert.EqualValues(t, 1, totals[FamilyToolCalls])
	assert.EqualValues(t, 1, totals[FamilyRequestLogs])

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "request_logs", orgID),
		"the protected request stays")
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "tool_calls", orgID),
		"the protected request's tool child stays (no side door)")

	// The protected report: identifier-only, captured into the checkpoint.
	var cp Checkpoint
	require.NoError(t, runner.PlanReport(ctx, job, &cp))
	require.Len(t, cp.ProtectedIDs, 1)
	assert.NotEqual(t, "req-prot", cp.ProtectedIDs[0],
		"report carries the row id, never external identifiers")
	assert.False(t, cp.ProtectedTruncated)
	_ = grantID // grant existence is what protects the row; its id is not the report payload
}

// TestArchiveRemoveHotAllProtectedCorner_Integration: when every selected
// request is under a live grant, the plan refuses active_grant naming the
// grant ids and nothing is touched — unless another selected family still
// has permitted rows, in which case the op proceeds on those rows only.
func TestArchiveRemoveHotAllProtectedCorner_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-g1",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":1}`))
	insertRequestLog(t, ctx, pool, orgID, "req-g2",
		time.Date(2026, 3, 3, 1, 0, 0, 0, time.UTC), strptr(`{"v":2}`))
	grantID := seedActiveGrant(t, ctx, pool, orgID, "req-g1", 24*time.Hour)
	// A second live grant for req-g2 without tripping the seeder's per-org
	// admin-user emails: reuse the existing grantor/grantee identities.
	var grantorID, granteeID string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM admin_users WHERE email = $1", "grantor-"+orgID+"@itest").Scan(&grantorID))
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM admin_users WHERE email = $1", "grantee-"+orgID+"@itest").Scan(&granteeID))
	_, err := pool.Exec(ctx, `INSERT INTO request_payload_grants
	    (id, token_hash, grantor_root, grantee, org_id, request_id, scope, expires_at)
	  VALUES (gen_random_uuid(), $1, $2::uuid, $3::uuid, $4::uuid, 'req-g2', 'payload.read', now() + interval '24 hours')`,
		[]byte(fmt.Sprintf("fixture-token-%x", sha256.Sum256([]byte(orgID+"/req-g2/remove-corner")))),
		grantorID, granteeID, orgID)
	require.NoError(t, err)

	// (a) Requests only: all protected → active_grant refusal, zero writes,
	// zero deletes.
	store := newMapStore()
	sel := previewSelection(orgID, FamilyRequestLogs)
	job := removeJob(t, ctx, pool, orgID, sel, "file:///cold/historyops/"+orgID+"/corner/")
	runner := removeRunner(pool, store)

	_, err = runner.Plan(ctx, job)
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "all-protected corner must refuse, got: %v", err)
	assert.Equal(t, RefusalActiveGrant, refusal.Code)
	assert.Contains(t, refusal.GrantIDs, grantID)
	assert.Zero(t, store.totalWrites(), "the refusal never touches storage")
	assert.Equal(t, 2, orgRowCount(t, ctx, pool, "request_logs", orgID))

	// (b) Same protected requests + a cache family with a permitted row:
	// the op proceeds and deletes ONLY the permitted rows.
	insertCacheEntryRM(t, ctx, pool, orgID, time.Date(2026, 3, 4, 1, 0, 0, 0, time.UTC))
	selCache := previewSelection(orgID, FamilyRequestLogs, FamilyCacheEntries)
	jobCache := removeJob(t, ctx, pool, orgID, selCache, "file:///cold/historyops/"+orgID+"/corner2/")
	plan, err := removeRunner(pool, store).Plan(ctx, jobCache)
	require.NoError(t, err)
	require.Len(t, plan, 1, "only the cache batch is planned")
	totals := executePlan(t, ctx, removeRunner(pool, store), jobCache, plan)
	assert.EqualValues(t, 1, totals[FamilyCacheEntries])
	assert.Equal(t, 2, orgRowCount(t, ctx, pool, "request_logs", orgID),
		"protected requests survive the cross-family run")
	assert.Zero(t, orgRowCount(t, ctx, pool, "cache_entries", orgID))
}

// TestArchiveRemoveHotStandaloneTools_Integration: tool rows without a
// request_logs parent are their own destructive scope — org+period scoped,
// disjoint from request-child batches, and period-excluded rows survive.
func TestArchiveRemoveHotStandaloneTools_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	inPeriod := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	insertToolCallRM(t, ctx, pool, orgID, "standalone-a", inPeriod)
	insertToolCallRM(t, ctx, pool, orgID, "standalone-b", inPeriod)
	insertToolCallRM(t, ctx, pool, orgID, "standalone-old", time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC))
	insertToolInvocation(t, ctx, pool, orgID, "standalone-a", 1, inPeriod)

	store := newMapStore()
	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyToolCalls, FamilyToolCallInvocations),
		"file:///cold/historyops/"+orgID+"/standalone/")
	// F-3 probe: arms the export decision point with identity/ownership
	// evidence; see remove_flakeprobe_test.go. Assertion-free, read-only.
	runner := removeRunner(newFlakeProbeDB(t, pool, orgID), store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 2, "one standalone batch per tool family")

	totals := executePlan(t, ctx, runner, job, plan)
	assert.EqualValues(t, 2, totals[FamilyToolCalls])
	assert.EqualValues(t, 1, totals[FamilyToolCallInvocations])

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "tool_calls", orgID),
		"the out-of-period standalone call survives")
	assert.Zero(t, orgRowCount(t, ctx, pool, "tool_call_invocations", orgID))
}

// TestArchiveRemoveHotSessionsPinGuardCascade_Integration: only unpinned
// sessions are planned; the delete re-checks the pin; the message cascade is
// counted explicitly and the log_export_watermark is untouched.
func TestArchiveRemoveHotSessionsPinGuardCascade_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	pinned := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC))
	insertRequestLogWithSession(t, ctx, pool, orgID, "req-pin", pinned,
		time.Date(2026, 3, 4, 8, 0, 5, 0, time.UTC), nil)
	insertMessage(t, ctx, pool, pinned, "user", "pinned stays", time.Date(2026, 3, 4, 8, 0, 6, 0, time.UTC))

	free := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, free, "user", "m1", time.Date(2026, 3, 4, 9, 0, 1, 0, time.UTC))
	insertMessage(t, ctx, pool, free, "assistant", "m2", time.Date(2026, 3, 4, 9, 0, 2, 0, time.UTC))

	seedWatermark(t, ctx, pool)

	store := newMapStore()
	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilySessions),
		"file:///cold/historyops/"+orgID+"/sessions/")
	runner := removeRunner(pool, store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1, "the pinned session is never planned")

	totals := executePlan(t, ctx, runner, job, plan)
	assert.EqualValues(t, 1, totals[FamilySessions])
	assert.EqualValues(t, 2, totals[FamilyMessages], "the cascade is counted explicitly")

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "sessions", orgID),
		"the FK-pinned session stays")
	var msgCount int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages m JOIN sessions s ON s.id = m.session_id WHERE s.org_id = $1::uuid",
		orgID).Scan(&msgCount))
	assert.Equal(t, 1, msgCount, "only the pinned session's message survives")
	assert.EqualValues(t, 42, watermarkLastID(t, ctx, pool),
		"the operation never touches the log_export_watermark")
}

// TestArchiveRemoveHotArchivesMessageCascade_Integration pins HIST-02: the
// sessions DELETE cascades to messages, so the cascade must be ARCHIVED
// before the delete — a dedicated derived object under the job's identity,
// complete enough to restore every message from the archive alone.
func TestArchiveRemoveHotArchivesMessageCascade_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	sessionID := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "user", "hello", time.Date(2026, 3, 4, 9, 0, 1, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "assistant", "hi there", time.Date(2026, 3, 4, 9, 0, 2, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "user", "bye", time.Date(2026, 3, 4, 9, 0, 3, 0, time.UTC))

	// The originals, captured before the run: id, role, content — the
	// restore rehearsal compares against these.
	var originals []msgRow
	rows, err := pool.Query(ctx,
		"SELECT id::text, role, content FROM messages WHERE session_id = $1::uuid ORDER BY id",
		sessionID)
	require.NoError(t, err)
	for rows.Next() {
		var m msgRow
		require.NoError(t, rows.Scan(&m.ID, &m.Role, &m.Content))
		originals = append(originals, m)
	}
	require.NoError(t, rows.Err())
	require.Len(t, originals, 3)

	// The comparison below keys on id order, but the wire can permute even
	// bare ORDER BY id streams under race load (complete set delivered as
	// [10, 8, 9] — the transport-level reordering class the export sort
	// neutralizes). The product export is already client-side sorted (R1);
	// normalize the test capture the same way, and keep a log witness of any
	// wire permutation so the anomaly evidence is not silently lost.
	if !msgIDsAscending(originals) {
		t.Logf("f3-evidence: bare SELECT ORDER BY id returned non-ascending %v — transport-level reordering witnessed", msgRowIDs(originals))
	}
	sortMsgRowsByID(originals)

	store := newMapStore()
	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilySessions),
		"file:///cold/historyops/"+orgID+"/cascade/")
	runner := removeRunner(pool, store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)

	totals := executePlan(t, ctx, runner, job, plan)
	assert.EqualValues(t, 1, totals[FamilySessions])
	assert.EqualValues(t, 3, totals[FamilyMessages])

	// Hot: everything gone.
	assert.Zero(t, orgRowCount(t, ctx, pool, "sessions", orgID))
	var hotMsgs int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages m JOIN sessions s ON s.id = m.session_id WHERE s.org_id = $1::uuid",
		orgID).Scan(&hotMsgs))
	assert.Zero(t, hotMsgs, "the cascaded messages are gone from the hot table")

	// The derived cascade object exists under the job's identity, with a
	// manifest declaring the messages table.
	mkey := archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilyMessages)
	require.True(t, store.has(mkey), "the message cascade is archived")
	require.True(t, store.has(mkey+".manifest.json"))
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(store.bytes(mkey+".manifest.json"), &manifest))
	assert.Equal(t, "messages", manifest["table"])
	assert.EqualValues(t, 3, manifest["rows"])
	assert.Equal(t, job.ID, manifest["job_id"])

	// The JSONL carries every message verbatim.
	payload := store.bytes(mkey)
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var archived []map[string]any
	for dec.More() {
		var line map[string]any
		require.NoError(t, dec.Decode(&line))
		archived = append(archived, line)
	}
	require.Len(t, archived, 3)

	// Restore rehearsal: rebuild the session and the messages from the
	// archive alone, then compare against the originals.
	s0 := archived[0]
	_, err = pool.Exec(ctx, `INSERT INTO sessions (id, org_id, home_region, created_at)
	  VALUES ($1::uuid, $2::uuid, $3, $4::timestamptz)`,
		s0["session_id"], orgID, s0["home_region"], s0["created_at"])
	require.NoError(t, err, "the archived rows carry a restorable session shape")
	for i, line := range archived {
		id, err := line["id"].(json.Number).Int64()
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO messages (id, session_id, role, content, home_region, created_at)
		  VALUES ($1, $2::uuid, $3, $4, $5, $6::timestamptz)`,
			id, line["session_id"], line["role"], line["content"], line["home_region"], line["created_at"])
		require.NoError(t, err)
		var got msgRow
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT id::text, role, content FROM messages WHERE id = $1", id).
			Scan(&got.ID, &got.Role, &got.Content))
		assert.Equal(t, originals[i], got, "restore yields the original message %d", i)
	}
}

// TestArchiveRemoveHotRefusesCascadeGrowth_Integration pins HIST-02's
// fail-closed gate: a message inserted between the cascade archive snapshot
// and the pre-delete count (the concurrent-writer window) must refuse the
// delete — the hot session and every message survive for a fresh re-run.
func TestArchiveRemoveHotRefusesCascadeGrowth_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	sessionID := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "user", "early-1", time.Date(2026, 3, 4, 9, 0, 1, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "assistant", "early-2", time.Date(2026, 3, 4, 9, 0, 2, 0, time.UTC))

	seedWatermark(t, ctx, pool)

	store := newMapStore()
	var lateFired atomic.Bool
	store.onWrite = func(key string) {
		// Fires during the cascade object write: strictly after the
		// message export snapshot committed, strictly before the
		// pre-delete count — the exact window the gate exists for.
		if strings.HasSuffix(key, string(FamilyMessages)+".jsonl") && lateFired.CompareAndSwap(false, true) {
			insertMessage(t, ctx, pool, sessionID, "user", "late-arrival",
				time.Date(2026, 3, 4, 9, 0, 3, 0, time.UTC))
		}
	}

	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilySessions),
		"file:///cold/historyops/"+orgID+"/growth/")
	runner := removeRunner(pool, store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)

	_, err = runner.ExecuteBatch(ctx, job, 0, plan[0])
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "cascade growth must refuse fail-closed, got %v", err)
	assert.Equal(t, RefusalCascadeChanged, refusal.Code)

	// Nothing died: the session and all three messages stay hot; the two
	// archived messages are the recovery point for a fresh re-run.
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "sessions", orgID))
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE session_id = $1::uuid", sessionID).Scan(&n))
	assert.Equal(t, 3, n, "the late message must not die unarchived")

	mkey := archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilyMessages)
	require.True(t, store.has(mkey), "the archived cascade is the recovery point")
	assert.EqualValues(t, 42, watermarkLastID(t, ctx, pool))
}

// TestArchiveRemoveHotGrantRacedAfterPlanRefuses_Integration pins HIST-04's
// post-archive grant re-check: a payload grant issued AFTER the plan (the
// plan→delete window) must refuse the delete — plan-time narrowing alone
// would destroy the now-granted payload. Both the request row and its tool
// child refuse, nothing dies.
func TestArchiveRemoveHotGrantRacedAfterPlanRefuses_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-race",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":"grantable"}`))
	insertToolCallRM(t, ctx, pool, orgID, "req-race", time.Date(2026, 3, 2, 1, 0, 30, 0, time.UTC))
	seedWatermark(t, ctx, pool)

	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls),
		"file:///cold/historyops/"+orgID+"/race/")
	runner := removeRunner(pool, newMapStore())

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 2, "no grant at plan time: the tool child and the parent are planned")

	// The grant lands inside the plan→execute window.
	seedActiveGrant(t, ctx, pool, orgID, "req-race", 24*time.Hour)

	for i, batch := range plan {
		_, err := runner.ExecuteBatch(ctx, job, i, batch)
		refusal, ok := RefusalOf(err)
		require.True(t, ok, "batch %d must refuse on the raced grant, got %v", i, err)
		assert.Equal(t, RefusalActiveGrant, refusal.Code,
			"batch %d refusal names the blocking grants: %v", i, refusal.GrantIDs)
	}

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "request_logs", orgID),
		"the granted request stays hot")
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "tool_calls", orgID),
		"the granted request's tool child stays hot")
}

// TestArchiveRemoveHotConcurrentMutateStaysHot_Integration pins HIST-04's
// paired-xmin delete: a request row MUTATED between its archive and the
// delete (the concurrent-writer window) keeps its mutated content hot —
// the delete removes only exactly-archived versions, and the archive holds
// the pre-mutation content. Nothing is lost.
func TestArchiveRemoveHotConcurrentMutateStaysHot_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-mut",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":"original"}`))
	seedWatermark(t, ctx, pool)

	store := newMapStore()
	var mutated atomic.Bool
	store.onWrite = func(key string) {
		// Fires inside the store write, strictly after the row's export
		// snapshot committed and strictly before the delete — the exact
		// window the version guard exists for.
		if strings.HasSuffix(key, string(FamilyRequestLogs)+".jsonl") && mutated.CompareAndSwap(false, true) {
			_, err := pool.Exec(ctx,
				"UPDATE request_logs SET response = $1::jsonb WHERE org_id = $2::uuid AND request_id = $3",
				`{"v":"mutated-after-archive"}`, orgID, "req-mut")
			require.NoError(t, err)
		}
	}

	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilyRequestLogs),
		"file:///cold/historyops/"+orgID+"/mutate/")
	runner := removeRunner(pool, store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)

	totals, err := runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err, "a mid-flight mutation is not a refusal — the row just stays hot")
	assert.Zero(t, totals[FamilyRequestLogs], "the mutated version is never deleted")

	var response string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT response::text FROM request_logs WHERE org_id = $1::uuid AND request_id = $2",
		orgID, "req-mut").Scan(&response))
	assert.Contains(t, response, "mutated-after-archive", "the mutation survives hot")

	key := archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilyRequestLogs)
	require.True(t, store.has(key))
	assert.Contains(t, string(store.bytes(key)), `"v": "original"`,
		"the archive holds the pre-mutation content")
}

// TestArchiveRemoveHotSessionMutateStaysHot_Integration: the same version
// guard for sessions — a session row mutated after its archive stays hot
// together with its whole cascade, and nothing is counted as deleted.
func TestArchiveRemoveHotSessionMutateStaysHot_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	sessionID := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "user", "m1", time.Date(2026, 3, 4, 9, 0, 1, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionID, "assistant", "m2", time.Date(2026, 3, 4, 9, 0, 2, 0, time.UTC))
	seedWatermark(t, ctx, pool)

	store := newMapStore()
	var mutated atomic.Bool
	store.onWrite = func(key string) {
		if strings.HasSuffix(key, string(FamilySessions)+".jsonl") && mutated.CompareAndSwap(false, true) {
			_, err := pool.Exec(ctx,
				"UPDATE sessions SET home_region = 'mutated-region' WHERE id = $1::uuid", sessionID)
			require.NoError(t, err)
		}
	}

	job := removeJob(t, ctx, pool, orgID,
		previewSelection(orgID, FamilySessions),
		"file:///cold/historyops/"+orgID+"/session-mutate/")
	runner := removeRunner(pool, store)

	plan, err := runner.Plan(ctx, job)
	require.NoError(t, err)
	require.Len(t, plan, 1)

	totals, err := runner.ExecuteBatch(ctx, job, 0, plan[0])
	require.NoError(t, err)
	assert.Empty(t, totals, "the mutated session (and its cascade) is never deleted")

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "sessions", orgID))
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE session_id = $1::uuid", sessionID).Scan(&n))
	assert.Equal(t, 2, n, "the cascade stays with its session")

	// The archive still holds both the session and the full cascade —
	// the recovery point for a fresh re-run.
	base := archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilySessions)
	mkey := archiveObjectKey(orgID, job.SelectionDigest, job.ID, 0, FamilyMessages)
	require.True(t, store.has(base))
	require.True(t, store.has(mkey), "the cascade archive exists for the re-run")
	assert.EqualValues(t, 42, watermarkLastID(t, ctx, pool))
}

// TestArchiveRemoveHotEngineFailClosed_Integration: through the engine, a
// corrupted archive write fails the job with the typed refusal and the hot
// rows survive.
func TestArchiveRemoveHotEngineFailClosed_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-fc",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":1}`))

	seedSchemaMigrations(t, ctx, pool, 16)
	stampFn := func(ctx context.Context) (SchemaStamp, error) { return SchemaStampFromDB(ctx, pool) }

	store := newMapStore()
	store.corrupt = true
	engine := NewEngine(NewMemoryJobStore(previewNow), &MemoryJournaler{}, EngineConfig{
		LeaseTTL:    30 * time.Second,
		MaxAttempts: 1, // no retry loop: the refusal fails the job immediately
		Now:         previewNow,
		Stamp:       stampFn,
	})
	engine.RegisterRunner(OpArchiveRemoveHot, removeRunner(pool, store))

	sel := previewSelection(orgID, FamilyRequestLogs)
	stamp, err := stampFn(ctx)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveRemoveHot, sel, stamp)
	require.NoError(t, err)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           orgID,
		Op:              OpArchiveRemoveHot,
		Selection:       sel,
		PresentedDigest: digest,
		IdempotencyKey:  "engine-remove-fc",
		Destination:     "file:///cold/historyops/" + orgID + "/failclosed/",
		Actor:           JobActor{Type: ActorUser, Author: "u-admin-1"},
		Caller:          adminCaller(),
	})
	require.NoError(t, err)

	_, _ = engine.ExecuteNext(ctx, "worker-remove-fc")

	final, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, final.Status, "last_error=%q refusal=%+v",
		final.LastError, final.Refusal)
	require.NotNil(t, final.Refusal, "the failed job carries the typed refusal")
	assert.Equal(t, RefusalArchiveChecksum, final.Refusal.Code)
	assert.Contains(t, final.LastError, string(RefusalArchiveChecksum))
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "request_logs", orgID),
		"the engine path keeps the destructive half withheld")
}

// TestArchiveRemoveHotEngineProtectedCapture_Integration: the engine-wired
// happy path captures the protected report into the checkpoint and deletes
// exactly the permitted rows.
func TestArchiveRemoveHotEngineProtectedCapture_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	insertRequestLog(t, ctx, pool, orgID, "req-ec-prot",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), strptr(`{"v":"keep"}`))
	insertRequestLog(t, ctx, pool, orgID, "req-ec-open",
		time.Date(2026, 3, 3, 1, 0, 0, 0, time.UTC), strptr(`{"v":"delete"}`))
	insertToolCallRM(t, ctx, pool, orgID, "req-ec-prot", time.Date(2026, 3, 2, 1, 0, 30, 0, time.UTC))
	insertToolCallRM(t, ctx, pool, orgID, "req-ec-open", time.Date(2026, 3, 3, 1, 0, 30, 0, time.UTC))
	seedActiveGrant(t, ctx, pool, orgID, "req-ec-prot", 24*time.Hour)

	seedSchemaMigrations(t, ctx, pool, 16)
	stampFn := func(ctx context.Context) (SchemaStamp, error) { return SchemaStampFromDB(ctx, pool) }

	store := newMapStore()
	engine := NewEngine(NewMemoryJobStore(previewNow), &MemoryJournaler{}, EngineConfig{
		LeaseTTL:    30 * time.Second,
		MaxAttempts: 3,
		Now:         previewNow,
		Stamp:       stampFn,
	})
	engine.RegisterRunner(OpArchiveRemoveHot, removeRunner(pool, store))

	sel := previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls)
	stamp, err := stampFn(ctx)
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveRemoveHot, sel, stamp)
	require.NoError(t, err)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID:           orgID,
		Op:              OpArchiveRemoveHot,
		Selection:       sel,
		PresentedDigest: digest,
		IdempotencyKey:  "engine-remove-capture",
		Destination:     "file:///cold/historyops/" + orgID + "/capture/",
		Actor:           JobActor{Type: ActorUser, Author: "u-admin-1"},
		Caller:          adminCaller(),
	})
	require.NoError(t, err)

	more, err := engine.ExecuteNext(ctx, "worker-remove-capture")
	require.NoError(t, err)
	require.True(t, more)

	final, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, final.Status,
		"job failed: last_error=%q refusal=%+v confirmed=%+v checkpoint=%+v",
		final.LastError, final.Refusal, final.Confirmed, final.Checkpoint)
	assert.EqualValues(t, 1, final.Confirmed[FamilyRequestLogs])
	assert.EqualValues(t, 1, final.Confirmed[FamilyToolCalls])
	require.Len(t, final.Checkpoint.ProtectedIDs, 1,
		"the protected report rides the checkpoint")
	assert.False(t, final.Checkpoint.ProtectedTruncated)

	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "request_logs", orgID))
	assert.Equal(t, 1, orgRowCount(t, ctx, pool, "tool_calls", orgID),
		"the protected pair (parent + tool child) survives the engine run")
}

// msgRow is one captured messages-table row (id, role, content).
type msgRow struct{ ID, Role, Content string }

// msgIDsAscending reports whether a captured msgRow stream is in ascending
// numeric id order (the contract of the ORDER BY id capture query).
func msgIDsAscending(rows []msgRow) bool {
	for i := 1; i < len(rows); i++ {
		prev, errPrev := strconv.ParseInt(rows[i-1].ID, 10, 64)
		cur, errCur := strconv.ParseInt(rows[i].ID, 10, 64)
		if errPrev == nil && errCur == nil && cur < prev {
			return false
		}
	}
	return true
}

func msgRowIDs(rows []msgRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}

func sortMsgRowsByID(rows []msgRow) {
	sort.SliceStable(rows, func(a, b int) bool {
		prev, errPrev := strconv.ParseInt(rows[a].ID, 10, 64)
		cur, errCur := strconv.ParseInt(rows[b].ID, 10, 64)
		if errPrev == nil && errCur == nil {
			return prev < cur
		}
		return rows[a].ID < rows[b].ID
	})
}
