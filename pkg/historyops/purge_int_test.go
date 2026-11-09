package historyops

// ENT-HIST-07 integration coverage on a real PostgreSQL stand (skipped under
// -short): the purge engine operation end to end — family-ordered deletes
// (tool invocations → tool calls → request_logs → cache → messages →
// sessions), grant protection parity with the preview, the blocked_by_fk
// fail-closed refusal for pinned sessions, empty-scope no-op, single-use
// digest idempotency, and the counts+digest audit chain ride.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver for the audit verifier
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// purgeSeedAt is inside previewPeriod (2026-03-01..05), closed relative to
// previewNow.
var purgeSeedAt = time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)

// newPurgeHarness wires a purge engine against the real stand: runner,
// org-admin rights (purge needs none beyond org-admin) and the grant guard.
func newPurgeHarness(t *testing.T, pool testPGPool, batchSize int) (*Engine, *MemoryJournaler) {
	t.Helper()
	seedSchemaMigrations(t, context.Background(), pool, 16)
	clock := newFakeClock()
	clock.Advance(8 * 24 * time.Hour) // 2026-03-10T11:30Z: previewPeriod closed
	journal := &MemoryJournaler{}
	engine := NewEngine(NewMemoryJobStore(clock.Now), journal, EngineConfig{
		LeaseTTL:    time.Minute,
		MaxAttempts: 3,
		Now:         clock.Now,
		Stamp: func(ctx context.Context) (SchemaStamp, error) {
			return SchemaStampFromDB(ctx, pool)
		},
	})
	engine.RegisterRunner(OpPurge, NewPurgeRunner(pool, PurgeConfig{BatchSize: batchSize}))
	engine.SetBatchGuard(NewPurgeGrantGuard(pool))
	return engine, journal
}

func purgeJobKey(tag string) string {
	return fmt.Sprintf("purge-%s-%d", tag, time.Now().UnixNano())
}

// purgeGrantSeq keeps seed emails unique when an org gets several grants
// (seedActiveGrant assumes one grant per org; purge tests cover multi-grant
// scopes).
var purgeGrantSeq atomic.Uint64

// seedPurgeGrant seeds one live payload grant with per-grant unique admin
// users and returns the grant id.
func seedPurgeGrant(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, ttl time.Duration) string {
	t.Helper()
	seq := purgeGrantSeq.Add(1)
	var grantorID, granteeID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash) VALUES ($1, 'x') RETURNING id::text`,
		fmt.Sprintf("grantor-%s-%d@itest", orgID, seq)).Scan(&grantorID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash) VALUES ($1, 'x') RETURNING id::text`,
		fmt.Sprintf("grantee-%s-%d@itest", orgID, seq)).Scan(&granteeID))
	var grantID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO request_payload_grants
	    (id, token_hash, grantor_root, grantee, org_id, request_id, scope, expires_at)
	  VALUES (gen_random_uuid(), $1, $2::uuid, $3::uuid, $4::uuid, $5, 'payload.read', $6)
	  RETURNING id::text`,
		[]byte(fmt.Sprintf("fixture-token-%x", sha256.Sum256(
			[]byte(fmt.Sprintf("%s/%s/%d", orgID, requestID, time.Now().UnixNano()))))),
		grantorID, granteeID, orgID, requestID,
		time.Now().Add(ttl)).Scan(&grantID))
	return grantID
}

func countScope(t *testing.T, ctx context.Context, pool testPGPool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

func requestRowID(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM request_logs WHERE org_id = $1::uuid AND request_id = $2`,
		orgID, requestID).Scan(&id))
	return id
}

// insertLineage seeds one append-only request_lineage row (PB1.2 tamper
// evidence) — purge must never touch it.
func insertLineage(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO request_lineage
	    (request_id, org_id, ts, model_used, inference_region, model_origin_country,
	     log_storage_region, provider_entity_jurisdiction, attestation_hash, raw_attestation)
	  VALUES ($1, $2::text, $3, 'glm-5', 'sg', 'SG', 'sg', 'US', 'itest-hash', '{}'::jsonb)`,
		requestID, orgID, at)
	require.NoError(t, err)
}

// runPurgeToCompletion enqueues with the digest echo (the single-use
// confirmation) and drives one worker pass over the whole plan.
func runPurgeToCompletion(t *testing.T, ctx context.Context, engine *Engine,
	orgID string, sel Selection, digest, tag string) *Job {
	t.Helper()
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpPurge, Selection: sel,
		PresentedDigest: digest, Confirmation: digest, IdempotencyKey: purgeJobKey(tag),
		Actor: JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err, tag)
	claimed, err := engine.ExecuteNext(ctx, "worker-purge-"+tag)
	require.NoError(t, err, tag)
	require.True(t, claimed, tag)
	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, stored.Status, stored.LastError)
	return stored
}

func TestPurgeDeletesAcrossFamilies_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	foreign := seedPreviewOrg(t, ctx, pool)

	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"purge me"}`)
	// Three in-scope requests; the first carries a tool call + invocation,
	// the second an invocation (attached rows ride their request's batch).
	for i := 1; i <= 3; i++ {
		insertRequestLog(t, ctx, pool, orgID, fmt.Sprintf("req-purge-%d", i), purgeSeedAt, envelope)
	}
	insertToolCall(t, ctx, pool, orgID, "req-purge-1", purgeSeedAt)
	insertToolCallInvocation(t, ctx, pool, orgID, "req-purge-1", `{"cmd":"ls"}`, purgeSeedAt)
	insertToolCallInvocation(t, ctx, pool, orgID, "req-purge-2", `{"cmd":"cat"}`, purgeSeedAt)
	// Standalone tool row: in-scope timestamp, request id with no planned
	// parent row — its own batch, same logical unit rules do not apply.
	insertToolCall(t, ctx, pool, orgID, "req-orphan-parent", purgeSeedAt)
	cacheID := insertCacheEntry(t, ctx, pool, orgID, "ph-purge-1", *envelope, "", purgeSeedAt)
	// One in-scope session with two messages (messages ride the sessions
	// batch; CASCADE alone is not the count source — deletes are explicit).
	sessionID := insertSession(t, ctx, pool, orgID, purgeSeedAt)
	insertMessage(t, ctx, pool, sessionID, "user", "hello", purgeSeedAt)
	insertMessage(t, ctx, pool, sessionID, "assistant", "hi", purgeSeedAt)
	// Append-only lineage rows and the export watermark must survive purge.
	// request_lineage.request_id is GLOBALLY unique, so the ids carry the
	// run-unique org prefix (the stand is shared across -count runs).
	lineageReq1 := "lineage-" + orgID + "-1"
	lineageReq2 := "lineage-" + orgID + "-2"
	insertLineage(t, ctx, pool, orgID, lineageReq1, purgeSeedAt)
	insertLineage(t, ctx, pool, orgID, lineageReq2, purgeSeedAt)
	lineageBefore := countScope(t, ctx, pool, `SELECT COUNT(*) FROM request_lineage WHERE org_id::text = $1`, orgID)
	watermarkBefore := countScope(t, ctx, pool, `SELECT COUNT(*) FROM log_export_watermark`)
	// Foreign-org twin: purge is strictly org-scoped.
	insertRequestLog(t, ctx, pool, foreign, "req-purge-1", purgeSeedAt, envelope)

	previewer := newIntPreviewer(t, pool)
	// FamilyMessages is a dependent family (sessions cascade) — previews
	// scope it under sessions, never as a standalone selection family.
	sel := previewSelection(orgID, FamilySessions, FamilyRequestLogs,
		FamilyToolCalls, FamilyToolCallInvocations, FamilyCacheEntries)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)

	engine, journal := newPurgeHarness(t, pool, 2)
	stored := runPurgeToCompletion(t, ctx, engine, orgID, sel, report.SelectionDigest, "families")

	// Physical-effect counts: replaying the same plan deletes nothing.
	assert.EqualValues(t, 3, stored.Confirmed[FamilyRequestLogs])
	assert.EqualValues(t, 2, stored.Confirmed[FamilyToolCalls])
	assert.EqualValues(t, 2, stored.Confirmed[FamilyToolCallInvocations])
	assert.EqualValues(t, 1, stored.Confirmed[FamilyCacheEntries])
	assert.EqualValues(t, 2, stored.Confirmed[FamilyMessages])
	assert.EqualValues(t, 1, stored.Confirmed[FamilySessions])

	// Every seeded row is physically gone.
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid`, orgID), "requests")
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM tool_calls WHERE org_id = $1::uuid`, orgID), "tool_calls (attached + standalone)")
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM tool_call_invocations WHERE org_id = $1::uuid`, orgID), "invocations")
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM cache_entries WHERE id::text = $1`, cacheID), "cache entry")
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM sessions WHERE id::text = $1`, sessionID), "session")
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM messages WHERE session_id::text = $1`, sessionID), "messages")

	// Untouchables: lineage, watermark, foreign org.
	assert.Equal(t, lineageBefore, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_lineage WHERE org_id::text = $1`, orgID), "request_lineage is append-only")
	assert.Equal(t, watermarkBefore, countScope(t, ctx, pool, `SELECT COUNT(*) FROM log_export_watermark`),
		"the export watermark is never touched by purge")
	assert.EqualValues(t, 1, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid`, foreign), "foreign-org twin survives")

	// Sessions were planned strictly last: no family id follows a session id.
	sessionBatches := 0
	for _, batch := range stored.Checkpoint.Plan {
		if len(batch) == 0 {
			continue
		}
		firstFamily, _, err := decodePlanID(batch[0])
		require.NoError(t, err)
		if firstFamily == FamilySessions {
			sessionBatches++
		}
	}
	assert.Equal(t, 1, sessionBatches, "one trailing sessions batch")

	// Journal: one start, one entry per batch, one completion.
	assert.Equal(t, 1, journal.Count(JournalAction(OpPurge, ActionStarted)))
	assert.Equal(t, 1, journal.Count(JournalAction(OpPurge, ActionCompleted)))

	// Post-purge preview: same scope, nothing left, and the digest is
	// unchanged — it binds scope+stamp, not data volume.
	after, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	assert.True(t, after.NoOp, "after purge the same selection finds nothing")
	for _, f := range sel.Families {
		fam := after.Families[f]
		assert.Zero(t, fam.Found, "family %s", f)
	}
	assert.Equal(t, report.SelectionDigest, after.SelectionDigest,
		"purge digest is scope+stamp only; it must not shift with the data")
}

func TestPurgeGrantProtection_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"protected?"}`)
	for i := 1; i <= 3; i++ {
		insertRequestLog(t, ctx, pool, orgID, fmt.Sprintf("req-grant-%d", i), purgeSeedAt, envelope)
	}
	grantID := seedPurgeGrant(t, ctx, pool, orgID, "req-grant-1", time.Hour)

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilyRequestLogs)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	// The preview states every refusal honestly: the standing "previews
	// carry no confirmation" gate plus the live-grant protection.
	require.NotEmpty(t, report.Refusals)
	var grantRefused bool
	for _, r := range report.Refusals {
		if r.Code == RefusalActiveGrant {
			grantRefused = true
		}
	}
	require.True(t, grantRefused, "refusals = %v", report.Refusals)
	assert.EqualValues(t, 1, report.Families[FamilyRequestLogs].Protected)
	assert.EqualValues(t, 2, report.Families[FamilyRequestLogs].Permitted)

	engine, _ := newPurgeHarness(t, pool, 0)
	stored := runPurgeToCompletion(t, ctx, engine, orgID, sel, report.SelectionDigest, "grant-protect")

	assert.EqualValues(t, 2, stored.Confirmed[FamilyRequestLogs], "only the unprotected rows purge")
	assert.EqualValues(t, 1, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid AND request_id = 'req-grant-1'`, orgID),
		"the granted request survives purge")
	assert.EqualValues(t, 1, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_payload_grants WHERE id::text = $1`, grantID),
		"the grant itself is never deleted")

	// All-protected scope: nothing is permitted, so the job refuses instead
	// of executing an empty plan.
	orgAll := seedPreviewOrg(t, ctx, pool)
	for i := 1; i <= 2; i++ {
		insertRequestLog(t, ctx, pool, orgAll, fmt.Sprintf("req-all-%d", i), purgeSeedAt, envelope)
	}
	seedPurgeGrant(t, ctx, pool, orgAll, "req-all-1", time.Hour)
	seedPurgeGrant(t, ctx, pool, orgAll, "req-all-2", time.Hour)

	selAll := previewSelection(orgAll, FamilyRequestLogs)
	reportAll, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: selAll, Caller: adminCaller()})
	require.NoError(t, err)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgAll, Op: OpPurge, Selection: selAll,
		PresentedDigest: reportAll.SelectionDigest, Confirmation: reportAll.SelectionDigest,
		IdempotencyKey: purgeJobKey("all-protected"),
		Actor:          JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-purge-all-protected")
	require.NoError(t, err)
	require.True(t, claimed)
	storedAll, err := engine.Status(ctx, orgAll, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, storedAll.Status)
	require.NotNil(t, storedAll.Refusal)
	assert.Equal(t, RefusalActiveGrant, storedAll.Refusal.Code)
	assert.NotEmpty(t, storedAll.Refusal.GrantIDs, "the refusal names the blocking grants")
	assert.Zero(t, storedAll.Confirmed.Total())
	assert.EqualValues(t, 2, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid`, orgAll),
		"an all-protected purge touches zero rows")
}

func TestPurgeGrantGuardDirect_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, orgID, "req-guard-1", purgeSeedAt, nil)
	grantID := seedPurgeGrant(t, ctx, pool, orgID, "req-guard-1", time.Hour)

	guard := NewPurgeGrantGuard(pool)
	requestID := encodePlanID(FamilyRequestLogs,
		fmt.Sprintf("%d", requestRowID(t, ctx, pool, orgID, "req-guard-1")))
	purgeJob := &Job{OrgID: orgID, Op: OpPurge, Selection: previewSelection(orgID, FamilyRequestLogs)}

	// A batch covering the granted request is refused with the grant id.
	err := guard.BatchAllowed(ctx, purgeJob, []string{requestID})
	refusal, ok := RefusalOf(err)
	require.True(t, ok, "live grant must refuse typed, got %v", err)
	assert.Equal(t, RefusalActiveGrant, refusal.Code)
	assert.Contains(t, refusal.GrantIDs, grantID)

	// Non-purge operations are not grant-guarded (redact rewrites content,
	// it does not destroy rows).
	require.NoError(t, guard.BatchAllowed(ctx, &Job{OrgID: orgID, Op: OpRedactContent}, []string{requestID}),
		"the guard is op-gated to purge")

	// A batch with no request ids cannot collide with a grant.
	sessionID := insertSession(t, ctx, pool, orgID, purgeSeedAt)
	require.NoError(t, guard.BatchAllowed(ctx, purgeJob, []string{
		encodePlanID(FamilySessions, sessionID),
	}), "session-only batches need no grant check")

	// Revoked grants no longer protect.
	_, err = pool.Exec(ctx, `UPDATE request_payload_grants SET revoked_at = now()
	  WHERE id::text = $1`, grantID)
	require.NoError(t, err)
	assert.NoError(t, guard.BatchAllowed(ctx, purgeJob, []string{requestID}),
		"revoked grants stop protecting after revocation")
}

func TestPurgeBlockedByFKRefusal_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"pin"}`)
	// In-scope request (would purge) + in-scope session, but the session is
	// pinned by an out-of-scope request_logs row (created_at after To).
	insertRequestLog(t, ctx, pool, orgID, "req-in-scope", purgeSeedAt, envelope)
	sessionID := insertSession(t, ctx, pool, orgID, purgeSeedAt)
	insertMessage(t, ctx, pool, sessionID, "user", "pinned", purgeSeedAt)
	insertRequestLogWithSession(t, ctx, pool, orgID, "req-pinner", sessionID,
		time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC), envelope)

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilySessions, FamilyRequestLogs)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err, "the previewer cannot see physical FK pins; the runner must")

	engine, _ := newPurgeHarness(t, pool, 0)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpPurge, Selection: sel,
		PresentedDigest: report.SelectionDigest, Confirmation: report.SelectionDigest,
		IdempotencyKey: purgeJobKey("blocked-fk"),
		Actor:          JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-purge-blocked-fk")
	require.NoError(t, err)
	require.True(t, claimed)
	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, stored.Status, "a pinned session fails the job, never a partial purge")
	require.NotNil(t, stored.Refusal)
	assert.Equal(t, RefusalBlockedByFK, stored.Refusal.Code)

	// Fail-closed: zero rows deleted anywhere.
	assert.EqualValues(t, 2, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid`, orgID), "both requests survive")
	assert.EqualValues(t, 1, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM sessions WHERE id::text = $1`, sessionID), "the pinned session survives")
	assert.EqualValues(t, 1, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM messages WHERE session_id::text = $1`, sessionID))
	assert.Zero(t, stored.Confirmed.Total())
}

func TestPurgeNoOpAndSingleUse_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	previewer := newIntPreviewer(t, pool)

	// Empty scope: a valid closed period with no rows at all — the job
	// completes as a no-op (AC: purge of nothing is a completed purge of
	// nothing, not an error).
	emptySel, err := NewSelection(orgID, "", Period{
		From: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 2, 5, 0, 0, 0, 0, time.UTC),
	}, []Family{FamilyRequestLogs}, SelectionFilters{}, previewNow())
	require.NoError(t, err)
	engine, journal := newPurgeHarness(t, pool, 0)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: emptySel, Caller: adminCaller()})
	require.NoError(t, err)
	stored := runPurgeToCompletion(t, ctx, engine, orgID, emptySel, report.SelectionDigest, "noop")
	assert.Zero(t, stored.Confirmed.Total(), "empty selection = zero physical effects")
	assert.Equal(t, 1, journal.Count(JournalAction(OpPurge, ActionCompleted)))
	assert.Zero(t, journal.Count(JournalAction(OpPurge, ActionBatch)), "no batches for an empty plan")

	// Single use: the second enqueue of the SAME confirmed scope replays the
	// stored job instead of purging again.
	org2 := seedPreviewOrg(t, ctx, pool)
	insertRequestLog(t, ctx, pool, org2, "req-once-1", purgeSeedAt,
		strptr(`{"v":1,"kind":"model_response","status":"complete","content":"once"}`))
	sel2 := previewSelection(org2, FamilyRequestLogs)
	report2, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel2, Caller: adminCaller()})
	require.NoError(t, err)

	first := runPurgeToCompletion(t, ctx, engine, org2, sel2, report2.SelectionDigest, "once-1")
	assert.EqualValues(t, 1, first.Confirmed[FamilyRequestLogs])

	startedBeforeReplay := journal.Count(JournalAction(OpPurge, ActionStarted))
	replay, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: org2, Op: OpPurge, Selection: sel2,
		PresentedDigest: report2.SelectionDigest, Confirmation: report2.SelectionDigest,
		IdempotencyKey: purgeJobKey("once-2-should-be-ignored"),
		Actor:          JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	require.NoError(t, err, "a replay returns the stored decision, not an error")
	assert.Equal(t, first.ID, replay.ID, "the confirmed digest is single-use: replay, never re-execute")
	assert.Equal(t, startedBeforeReplay, journal.Count(JournalAction(OpPurge, ActionStarted)),
		"the replay journals nothing new")
	assert.Zero(t, countScope(t, ctx, pool,
		`SELECT COUNT(*) FROM request_logs WHERE org_id = $1::uuid`, org2))
}

func TestPurgeAuditChain_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `TRUNCATE admin_audit_outbox; TRUNCATE admin_audit_logs;`)
	require.NoError(t, err)

	orgID := seedPreviewOrg(t, ctx, pool)
	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"audited purge"}`)
	for i := 1; i <= 2; i++ {
		insertRequestLog(t, ctx, pool, orgID, fmt.Sprintf("req-paudit-%d", i), purgeSeedAt, envelope)
	}
	insertToolCall(t, ctx, pool, orgID, "req-paudit-1", purgeSeedAt)

	store := adminstore.New(pool, slog.Default(), nil)
	journaler := NewAuditJournaler(store.InsertAuditLogEntry)
	seedSchemaMigrations(t, ctx, pool, 16)
	clock := newFakeClock()
	clock.Advance(8 * 24 * time.Hour)
	engine := NewEngine(NewMemoryJobStore(clock.Now), journaler, EngineConfig{
		Now:   clock.Now,
		Stamp: func(ctx context.Context) (SchemaStamp, error) { return SchemaStampFromDB(ctx, pool) },
	})
	engine.RegisterRunner(OpPurge, NewPurgeRunner(pool, PurgeConfig{BatchSize: 1}))

	sel := previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls)
	previewer := newIntPreviewer(t, pool)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpPurge, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpPurge, Selection: sel,
		PresentedDigest: report.SelectionDigest, Confirmation: report.SelectionDigest,
		IdempotencyKey: purgeJobKey("audit"),
		Actor:          JobActor{Type: ActorService, Author: "purge-svc", PolicyVersion: "purge-v1"},
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-purge-audit")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, stored.Status, stored.LastError)

	// The purge journal rides the shared hash chain — intact.
	sqlDB, err := sql.Open("pgx", pool.Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	broken, err := auditlog.NewVerifier(sqlDB).Verify(ctx)
	require.NoError(t, err)
	require.Zero(t, broken, "the audit chain must stay intact across purge entries")

	rows, err := pool.Query(ctx, `SELECT action, resource, details FROM admin_audit_logs
	     WHERE action LIKE 'history_op.purge.%' ORDER BY seq ASC`)
	require.NoError(t, err)
	defer rows.Close()
	type auditRow struct{ Action, Resource, Details string }
	var got []auditRow
	for rows.Next() {
		var r auditRow
		require.NoError(t, rows.Scan(&r.Action, &r.Resource, &r.Details))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())

	counts := map[string]int{}
	for _, r := range got {
		counts[r.Action]++
		assert.Equal(t, "historyops_job:"+job.ID, r.Resource)
		// Destroyed payloads never reach the journal — identifier keys only.
		for _, forbidden := range []string{"content", "payload", "response"} {
			assert.NotContains(t, r.Details, `"`+forbidden+`"`, r.Action)
		}
	}
	assert.Equal(t, 1, counts[JournalAction(OpPurge, ActionStarted)])
	assert.Equal(t, 1, counts[JournalAction(OpPurge, ActionCompleted)])

	// Terminal entry: the confirmed counts and the executed digest.
	var rowsByFamily map[string]int64
	var digests []string
	for _, r := range got {
		if !strings.HasSuffix(r.Action, ActionCompleted) {
			continue
		}
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &details))
		raw, err := json.Marshal(details["rows_by_family"])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &rowsByFamily))
		if d, ok := details["digest"].(string); ok {
			digests = append(digests, d)
		}
	}
	require.Contains(t, rowsByFamily, string(FamilyRequestLogs))
	assert.EqualValues(t, 2, rowsByFamily[string(FamilyRequestLogs)])
	assert.Contains(t, rowsByFamily, string(FamilyToolCalls))
	assert.EqualValues(t, 1, rowsByFamily[string(FamilyToolCalls)])
	require.Len(t, digests, 1)
	assert.Equal(t, report.SelectionDigest, digests[0],
		"the terminal entry names the digest the purge ran under")
}
