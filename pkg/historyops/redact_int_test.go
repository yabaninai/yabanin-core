package historyops

// ENT-HIST-04 integration coverage on a real PostgreSQL stand (skipped under
// -short): the redact_content engine operation end to end — content columns
// nulled, metadata invariants kept (counts-invariant pin), digest-gated
// snapshots, idempotent reruns, cross-org isolation, tool_calls zero-effect,
// and the audit-chain ride.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver for the audit verifier
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// redactCaller passes AuthorizeEnqueue(OpRedactContent): org-admin plus the
// two explicit payload grants the rights model requires for content rewrites.
func redactCaller() Caller {
	c := adminCaller()
	c.Perms[adminstore.PermRequestsPayloads] = true
	c.Perms[adminstore.PermRequestsReadOriginals] = true
	return c
}

// newRedactHarness wires a real-pool redact engine. The clock advances past
// previewNow so previewPeriod is closed for engine-side validation too.
func newRedactHarness(t *testing.T, pool testPGPool, batchSize int) (*Engine, *MemoryJournaler) {
	t.Helper()
	seedSchemaMigrations(t, context.Background(), pool, 16)
	clock := newFakeClock()
	clock.Advance(8 * 24 * time.Hour) // 2026-03-10T11:30Z
	journal := &MemoryJournaler{}
	engine := NewEngine(NewMemoryJobStore(clock.Now), journal, EngineConfig{
		LeaseTTL:    time.Minute,
		MaxAttempts: 3,
		Now:         clock.Now,
		Stamp: func(ctx context.Context) (SchemaStamp, error) {
			return SchemaStampFromDB(ctx, pool)
		},
	})
	engine.RegisterRunner(OpRedactContent, NewRedactRunner(pool, RedactConfig{BatchSize: batchSize}))
	return engine, journal
}

func redactJobKey(tag string) string {
	return fmt.Sprintf("redact-%s-%d", tag, time.Now().UnixNano())
}

// insertRedactableRequestLog seeds one request_logs row with every content
// column populated (empty pointers/text stay SQL NULL).
func insertRedactableRequestLog(t *testing.T, ctx context.Context, pool testPGPool,
	orgID, requestID string, at time.Time, response, upstreamReq, upstreamResp *string, errMsg, promptHash string) {
	t.Helper()
	var respArg, upReqArg, upRespArg any
	if response != nil {
		respArg = *response
	}
	if upstreamReq != nil {
		upReqArg = *upstreamReq
	}
	if upstreamResp != nil {
		upRespArg = *upstreamResp
	}
	_, err := pool.Exec(ctx, `INSERT INTO request_logs
	    (org_id, home_region, model_requested, model_used, status_code, duration_ms,
	     tokens_in, tokens_out, request_id, error, response, upstream_request,
	     upstream_response, prompt_hash, created_at)
	  VALUES ($1::uuid, 'sg', 'glm-5', 'glm-5', 200, 42, 11, 7, $2,
	          NULLIF($3, ''), $4::jsonb, $5::jsonb, $6::jsonb, NULLIF($7, ''), $8)`,
		orgID, requestID, errMsg, respArg, upReqArg, upRespArg, promptHash, at)
	require.NoError(t, err)
}

// insertCacheEntry seeds one cache_entries row (embedding: 384-dim zero
// vector; empty sseChunks stays SQL NULL) and returns its id.
func insertCacheEntry(t *testing.T, ctx context.Context, pool testPGPool,
	orgID, promptHash, response, sseChunks string, at time.Time) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO cache_entries
	    (org_id, model_tier, prompt_hash, embedding, response, sse_chunks, created_at)
	  VALUES ($1::uuid, 'smart', $2,
	          ('[' || array_to_string(array_fill(0::float8, ARRAY[384]), ',') || ']')::vector,
	          $3::jsonb, NULLIF($4, '')::jsonb, $5)
	  RETURNING id::text`, orgID, promptHash, response, sseChunks, at).Scan(&id))
	return id
}

func insertToolCallInvocation(t *testing.T, ctx context.Context, pool testPGPool,
	orgID, requestID, arguments string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO tool_call_invocations
	    (request_id, org_id, seq, tool_name, arguments, created_at)
	  VALUES ($1, $2::uuid, 0, 'bash', $3, $4)`, requestID, orgID, arguments, at)
	require.NoError(t, err)
}

func insertToolCall(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO tool_calls
	    (request_id, org_id, model_used, tool_name, created_at)
	  VALUES ($1, $2::uuid, 'glm-5', 'bash', $3)`, requestID, orgID, at)
	require.NoError(t, err)
}

// redactRequestLogState is the full metadata+content snapshot of one row, for
// before/after comparisons.
type redactRequestLogState struct {
	Response         []byte
	UpstreamRequest  []byte
	UpstreamResponse []byte
	Error            *string
	PromptHash       *string
	TokensIn         int64
	TokensOut        int64
	StatusCode       int
	ModelUsed        string
	RequestID        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func fetchRequestLogState(t *testing.T, ctx context.Context, pool testPGPool, orgID, requestID string) redactRequestLogState {
	t.Helper()
	var s redactRequestLogState
	require.NoError(t, pool.QueryRow(ctx, `SELECT response, upstream_request, upstream_response,
	       error, prompt_hash, tokens_in, tokens_out, status_code, model_used,
	       request_id, created_at, updated_at
	     FROM request_logs WHERE org_id = $1::uuid AND request_id = $2`,
		orgID, requestID).Scan(&s.Response, &s.UpstreamRequest, &s.UpstreamResponse,
		&s.Error, &s.PromptHash, &s.TokensIn, &s.TokensOut, &s.StatusCode, &s.ModelUsed,
		&s.RequestID, &s.CreatedAt, &s.UpdatedAt))
	return s
}

// requireCountsInvariant pins the backlog-05 invariant: a completed redact
// changes no scope counts. The digest is data-independent, so the same
// selection must preview identically before and after (bytes/views aside).
func requireCountsInvariant(t *testing.T, before, after *PreviewReport) {
	t.Helper()
	require.Equal(t, before.SelectionDigest, after.SelectionDigest,
		"the digest is scope+stamp only: a completed redact must not invalidate it")
	require.Len(t, after.Families, len(before.Families))
	for family, b := range before.Families {
		a := after.Families[family]
		assert.Equal(t, b.Found, a.Found, family+": row counts are redact-invariant")
		assert.Equal(t, b.Permitted, a.Permitted, family)
		assert.Equal(t, b.Protected, a.Protected, family)
		assert.Equal(t, b.BlockedByFK, a.BlockedByFK, family)
	}
	require.Len(t, after.Cascades, len(before.Cascades))
	for i, b := range before.Cascades {
		assert.Equal(t, b.Rows, after.Cascades[i].Rows,
			"cascade row counts are redact-invariant (messages survive)")
	}
}

func TestRedactContentRequestLogs_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	foreignOrg := seedPreviewOrg(t, ctx, pool)

	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"answer text"}`)
	legacy := strptr(`{"prompt":"raw legacy snapshot"}`)
	upReq := strptr(`{"model":"glm-5","messages":[{"role":"user","content":"secret prompt"}]}`)
	upResp := strptr(`{"id":"cmpl-1","choices":[{"text":"raw provider output"}]}`)
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-redact-1",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), envelope, upReq, upResp, "", "ph-alpha-1")
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-redact-2",
		time.Date(2026, 3, 2, 2, 0, 0, 0, time.UTC), legacy, upReq, upResp, "boom: provider timeout", "ph-alpha-2")
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-redact-3",
		time.Date(2026, 3, 2, 3, 0, 0, 0, time.UTC), nil, nil, nil, "provider 500", "ph-alpha-3")
	// Foreign org twin of row 1: must never be touched.
	insertRedactableRequestLog(t, ctx, pool, foreignOrg, "req-redact-1",
		time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC), envelope, upReq, upResp, "", "ph-alpha-1")

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilyRequestLogs)
	before, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	fpBefore := before.Families[FamilyRequestLogs]
	require.EqualValues(t, 3, fpBefore.Found)
	require.Positive(t, fpBefore.ContentBytesEst)
	require.NotNil(t, fpBefore.ResponseViews)
	assert.EqualValues(t, 1, fpBefore.ResponseViews.Envelope)
	assert.EqualValues(t, 1, fpBefore.ResponseViews.Legacy)
	assert.EqualValues(t, 1, fpBefore.ResponseViews.Absent)

	engine, journal := newRedactHarness(t, pool, 2) // 3 rows -> 2 batches
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpRedactContent, Selection: sel,
		PresentedDigest: before.SelectionDigest, IdempotencyKey: redactJobKey("reqlogs"),
		Actor: JobActor{Author: "u-admin-1"}, Caller: redactCaller(),
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-redact-1")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, stored.Status)
	require.Nil(t, stored.Refusal, stored.LastError)
	assert.EqualValues(t, 3, stored.Confirmed[FamilyRequestLogs],
		"every planned row is rewritten exactly once")
	assert.Equal(t, 2, stored.BatchesTotal())
	assert.Equal(t, 2, journal.Count(ActionBatch), "one journal entry per applied batch")
	assert.Equal(t, 1, journal.Count(ActionCompleted))

	// Content is gone; every metadata signal survives; the updated_at
	// trigger fired (the rewrite is visible, the content is not).
	s1 := fetchRequestLogState(t, ctx, pool, orgID, "req-redact-1")
	assert.Nil(t, s1.Response, "response content is destroyed")
	assert.Nil(t, s1.UpstreamRequest)
	assert.Nil(t, s1.UpstreamResponse)
	assert.Nil(t, s1.Error, "error text is content too")
	require.NotNil(t, s1.PromptHash)
	assert.Equal(t, "ph-alpha-1", *s1.PromptHash, "prompt_hash survives the rewrite")
	assert.EqualValues(t, 11, s1.TokensIn, "token accounting survives (counts-invariant)")
	assert.EqualValues(t, 7, s1.TokensOut)
	assert.Equal(t, 200, s1.StatusCode)
	assert.Equal(t, "glm-5", s1.ModelUsed)
	assert.True(t, s1.UpdatedAt.After(s1.CreatedAt), "the updated_at trigger marks the rewrite")

	s2 := fetchRequestLogState(t, ctx, pool, orgID, "req-redact-2")
	assert.Nil(t, s2.Response)
	assert.Nil(t, s2.Error, "error text is content: it is nulled too")
	require.NotNil(t, s2.PromptHash)
	assert.Equal(t, "ph-alpha-2", *s2.PromptHash)

	foreign := fetchRequestLogState(t, ctx, pool, foreignOrg, "req-redact-1")
	assert.NotNil(t, foreign.Response, "cross-org rows are never touched")
	assert.Equal(t, "ph-alpha-1", *foreign.PromptHash)

	after, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	requireCountsInvariant(t, before, after)
	fpAfter := after.Families[FamilyRequestLogs]
	assert.Zero(t, fpAfter.ContentBytesEst, "all content bytes are gone")
	require.NotNil(t, fpAfter.ResponseViews)
	assert.EqualValues(t, 3, fpAfter.ResponseViews.Absent, "every response view is now absent")
	assert.Zero(t, fpAfter.ResponseViews.Envelope)
	assert.Zero(t, fpAfter.ResponseViews.Legacy)
}

func TestRedactContentAllFamilies_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	foreignOrg := seedPreviewOrg(t, ctx, pool)

	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"by request"}`)
	upReq := strptr(`{"model":"glm-5","messages":[{"role":"user","content":"prompt bytes"}]}`)
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-all-1",
		time.Date(2026, 3, 3, 1, 0, 0, 0, time.UTC), envelope, upReq, upReq, "", "ph-all-1")
	insertToolCall(t, ctx, pool, orgID, "req-all-1", time.Date(2026, 3, 3, 1, 1, 0, 0, time.UTC))
	insertToolCallInvocation(t, ctx, pool, orgID, "req-all-1", `{"cmd":"cat /etc/secret"}`,
		time.Date(2026, 3, 3, 1, 2, 0, 0, time.UTC))
	insertCacheEntry(t, ctx, pool, orgID, "cache-ph-1", `{"answer":"cached secret"}`,
		`[{"delta":"streamed secret"}]`, time.Date(2026, 3, 3, 1, 3, 0, 0, time.UTC))
	sessionA := insertSession(t, ctx, pool, orgID, time.Date(2026, 3, 3, 2, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionA, "user", "secret user question", time.Date(2026, 3, 3, 2, 1, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, sessionA, "assistant", "secret assistant answer", time.Date(2026, 3, 3, 2, 2, 0, 0, time.UTC))
	// The session is FK-pinned by request_logs: still redactable (content
	// only), and the preview must report the same blocker before and after.
	insertRequestLogWithSession(t, ctx, pool, orgID, "req-pins-session", sessionA,
		time.Date(2026, 3, 3, 2, 3, 0, 0, time.UTC), envelope)
	// Foreign-org session+message: untouched.
	foreignSession := insertSession(t, ctx, pool, foreignOrg, time.Date(2026, 3, 3, 2, 0, 0, 0, time.UTC))
	insertMessage(t, ctx, pool, foreignSession, "user", "foreign secret", time.Date(2026, 3, 3, 2, 1, 0, 0, time.UTC))

	sel := previewSelection(orgID, FamilyRequestLogs, FamilyToolCalls, FamilyToolCallInvocations,
		FamilyCacheEntries, FamilySessions)
	previewer := newIntPreviewer(t, pool)
	before, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	require.EqualValues(t, 1, before.Families[FamilySessions].BlockedByFK)
	require.Len(t, before.Cascades, 1)
	cascadeBefore := before.Cascades[0]
	assert.EqualValues(t, 2, cascadeBefore.Rows)
	assert.Positive(t, cascadeBefore.ContentBytesEst)

	engine, _ := newRedactHarness(t, pool, 0)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpRedactContent, Selection: sel,
		PresentedDigest: before.SelectionDigest, IdempotencyKey: redactJobKey("allfam"),
		Actor: JobActor{Author: "u-admin-1"}, Caller: redactCaller(),
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-redact-2")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, stored.Status, stored.LastError)
	assert.EqualValues(t, 2, stored.Confirmed[FamilyRequestLogs],
		"both in-scope rows rewrite: the content row and the FK-pinning row")
	assert.EqualValues(t, 1, stored.Confirmed[FamilyToolCallInvocations])
	assert.EqualValues(t, 1, stored.Confirmed[FamilyCacheEntries])
	assert.EqualValues(t, 2, stored.Confirmed[FamilyMessages],
		"session batches report the messages they redacted")
	assert.NotContains(t, stored.Confirmed, FamilyToolCalls,
		"tool_calls has no content surface: zero planned ids, zero reported effects")
	for _, batch := range stored.Checkpoint.Plan {
		for _, pid := range batch {
			assert.NotContains(t, pid, string(FamilyToolCalls)+"/",
				"the plan never carries tool_calls ids")
		}
	}

	// Database truth per family.
	invArguments := sql.NullString{}
	require.NoError(t, pool.QueryRow(ctx, `SELECT arguments FROM tool_call_invocations
	     WHERE org_id = $1::uuid AND request_id = 'req-all-1'`, orgID).Scan(&invArguments))
	assert.False(t, invArguments.Valid, "tool arguments are destroyed")

	var cacheResp, cacheSSE []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT response, sse_chunks FROM cache_entries
	     WHERE org_id = $1::uuid AND prompt_hash = 'cache-ph-1'`, orgID).Scan(&cacheResp, &cacheSSE))
	require.NotNil(t, cacheResp, "response is NOT NULL: the absent marker replaces it")
	assert.Equal(t, "null", string(cacheResp), "the jsonb null absent marker")
	assert.Nil(t, cacheSSE, "sse chunks are destroyed")

	var msgContent string
	require.NoError(t, pool.QueryRow(ctx, `SELECT content FROM messages
	     WHERE session_id = $1::uuid AND role = 'user'`, sessionA).Scan(&msgContent))
	assert.Empty(t, msgContent, "message content is emptied, the row survives")
	var msgCount int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM messages WHERE session_id = $1::uuid`,
		sessionA).Scan(&msgCount))
	assert.EqualValues(t, 2, msgCount, "message rows survive")

	foreignMsg := ""
	require.NoError(t, pool.QueryRow(ctx, `SELECT content FROM messages
	     WHERE session_id = $1::uuid AND role = 'user'`, foreignSession).Scan(&foreignMsg))
	assert.Equal(t, "foreign secret", foreignMsg, "cross-org messages are never touched")

	after, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	requireCountsInvariant(t, before, after)
	assert.Less(t, after.Families[FamilyToolCallInvocations].ContentBytesEst,
		before.Families[FamilyToolCallInvocations].ContentBytesEst, "argument bytes destroyed")
	assert.Less(t, after.Families[FamilyCacheEntries].ContentBytesEst,
		before.Families[FamilyCacheEntries].ContentBytesEst, "cache content bytes destroyed")
	assert.Less(t, after.Cascades[0].ContentBytesEst, cascadeBefore.ContentBytesEst,
		"message bytes destroyed")
	assert.EqualValues(t, 0, after.Families[FamilyToolCallInvocations].ContentBytesEst)
}

func TestRedactContentIdempotentRerun_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)

	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"s"}`)
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-rerun-1",
		time.Date(2026, 3, 2, 5, 0, 0, 0, time.UTC), envelope, nil, nil, "e1", "ph-rerun-1")
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-rerun-2",
		time.Date(2026, 3, 2, 5, 1, 0, 0, time.UTC), envelope, nil, nil, "e2", "ph-rerun-2")

	previewer := newIntPreviewer(t, pool)
	sel := previewSelection(orgID, FamilyRequestLogs)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)

	engine, _ := newRedactHarness(t, pool, 0)

	run := func(tag string) *Job {
		job, err := engine.Enqueue(ctx, EnqueueRequest{
			OrgID: orgID, Op: OpRedactContent, Selection: sel,
			PresentedDigest: report.SelectionDigest, IdempotencyKey: redactJobKey(tag),
			Actor: JobActor{Author: "u-admin-1"}, Caller: redactCaller(),
		})
		require.NoError(t, err)
		claimed, err := engine.ExecuteNext(ctx, "worker-redact-"+tag)
		require.NoError(t, err)
		require.True(t, claimed)
		stored, err := engine.Status(ctx, orgID, job.ID)
		require.NoError(t, err)
		require.Equal(t, JobCompleted, stored.Status, stored.LastError)
		return stored
	}

	first := run("first")
	assert.EqualValues(t, 2, first.Confirmed[FamilyRequestLogs], "the first run rewrites both rows")

	// The digest survives the data change (scope+stamp only), so the exact
	// same selection can be enqueued again — and must rewrite nothing.
	second := run("second")
	assert.EqualValues(t, 0, second.Confirmed.Total(),
		"the guarded UPDATEs rewrite nothing on a rerun")

	s := fetchRequestLogState(t, ctx, pool, orgID, "req-rerun-1")
	assert.Nil(t, s.Response)
	assert.Equal(t, "ph-rerun-1", *s.PromptHash)
}

func TestRedactContentSnapshotDrift_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	orgID := seedPreviewOrg(t, ctx, pool)
	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"drift target"}`)
	insertRedactableRequestLog(t, ctx, pool, orgID, "req-drift-1",
		time.Date(2026, 3, 2, 6, 0, 0, 0, time.UTC), envelope, nil, nil, "", "ph-drift-1")

	runner := NewRedactRunner(pool, RedactConfig{})
	sel := previewSelection(orgID, FamilyRequestLogs)

	// Runner-level: a correct digest verifies; a wrong digest refuses
	// digest_mismatch fail-closed before any write.
	// The raw-SQL testdb stand carries no schema_migrations (it is a
	// deploy-layer artifact, not in migrations/*.up.sql), so seed the
	// fixture head before the first stamp read: without this the test
	// silently depended on another suite having created the table earlier
	// in the binary (42P01 under -shuffle order or a standalone -run).
	seedSchemaMigrations(t, ctx, pool, 16)
	stamp, err := SchemaStampFromDB(ctx, pool)
	require.NoError(t, err)
	goodDigest, err := SelectionDigest(OpRedactContent, sel, stamp)
	require.NoError(t, err)
	require.NoError(t, runner.VerifySnapshot(ctx, &Job{Selection: sel, SelectionDigest: goodDigest}))
	err = runner.VerifySnapshot(ctx, &Job{Selection: sel, SelectionDigest: "deadbeef"})
	refusal, ok := RefusalOf(err)
	require.True(t, ok)
	assert.Equal(t, RefusalDigestMismatch, refusal.Code)

	// Engine-level: schema drift between enqueue and execute (a migration
	// landing mid-flight) refuses the whole job with zero rows touched.
	previewer := newIntPreviewer(t, pool)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	engine, _ := newRedactHarness(t, pool, 0)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpRedactContent, Selection: sel,
		PresentedDigest: report.SelectionDigest, IdempotencyKey: redactJobKey("drift"),
		Actor: JobActor{Author: "u-admin-1"}, Caller: redactCaller(),
	})
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES (17, false)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 17`) })

	claimed, err := engine.ExecuteNext(ctx, "worker-redact-drift")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobFailed, stored.Status, "schema drift must fail the job, not retry it")
	require.NotNil(t, stored.Refusal)
	assert.Equal(t, RefusalDigestMismatch, stored.Refusal.Code)
	s := fetchRequestLogState(t, ctx, pool, orgID, "req-drift-1")
	assert.NotNil(t, s.Response, "a refused job touches zero rows")
}

func TestRedactContentAuditChain_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `TRUNCATE admin_audit_outbox; TRUNCATE admin_audit_logs;`)
	require.NoError(t, err)

	orgID := seedPreviewOrg(t, ctx, pool)
	envelope := strptr(`{"v":1,"kind":"model_response","status":"complete","content":"audited"}`)
	for i := 1; i <= 3; i++ {
		insertRedactableRequestLog(t, ctx, pool, orgID, fmt.Sprintf("req-audit-%d", i),
			time.Date(2026, 3, 2, 7, i, 0, 0, time.UTC), envelope, nil, nil, "", fmt.Sprintf("ph-audit-%d", i))
	}

	store := adminstore.New(pool, slog.Default(), nil)
	journaler := NewAuditJournaler(store.InsertAuditLogEntry)
	seedSchemaMigrations(t, ctx, pool, 16)
	clock := newFakeClock()
	clock.Advance(8 * 24 * time.Hour)
	engine := NewEngine(NewMemoryJobStore(clock.Now), journaler, EngineConfig{
		Now:   clock.Now,
		Stamp: func(ctx context.Context) (SchemaStamp, error) { return SchemaStampFromDB(ctx, pool) },
	})
	engine.RegisterRunner(OpRedactContent, NewRedactRunner(pool, RedactConfig{BatchSize: 1})) // 3 batches

	sel := previewSelection(orgID, FamilyRequestLogs)
	previewer := newIntPreviewer(t, pool)
	report, err := previewer.Report(ctx, PreviewRequest{Op: OpRedactContent, Selection: sel, Caller: adminCaller()})
	require.NoError(t, err)
	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: orgID, Op: OpRedactContent, Selection: sel,
		PresentedDigest: report.SelectionDigest, IdempotencyKey: redactJobKey("audit"),
		Actor: JobActor{Type: ActorService, Author: "redact-svc", PolicyVersion: "redact-v1"},
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-redact-audit")
	require.NoError(t, err)
	require.True(t, claimed)

	stored, err := engine.Status(ctx, orgID, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, stored.Status, stored.LastError)

	// The redact journal rides the shared hash chain — intact.
	sqlDB, err := sql.Open("pgx", pool.Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	broken, err := auditlog.NewVerifier(sqlDB).Verify(ctx)
	require.NoError(t, err)
	require.Zero(t, broken, "the audit chain must stay intact across redact entries")

	rows, err := pool.Query(ctx, `SELECT action, resource, details FROM admin_audit_logs
	     WHERE action LIKE 'history_op.redact_content.%' ORDER BY seq ASC`)
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
		// Identifier/flag keys only — redacted bytes never reach the journal.
		for _, forbidden := range []string{"content", "payload", "response", "prompt_hash"} {
			assert.NotContains(t, r.Details, `"`+forbidden+`"`, r.Action)
		}
	}
	assert.Equal(t, 1, counts[JournalAction(OpRedactContent, ActionStarted)])
	assert.Equal(t, 3, counts[JournalAction(OpRedactContent, ActionBatch)])
	assert.Equal(t, 1, counts[JournalAction(OpRedactContent, ActionCompleted)])

	var rowsByFamily map[string]int64
	for _, r := range got {
		if strings.HasSuffix(r.Action, ActionCompleted) {
			var details map[string]any
			require.NoError(t, json.Unmarshal([]byte(r.Details), &details))
			raw, err := json.Marshal(details["rows_by_family"])
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &rowsByFamily))
		}
	}
	require.Contains(t, rowsByFamily, string(FamilyRequestLogs))
	assert.EqualValues(t, 3, rowsByFamily[string(FamilyRequestLogs)],
		"per-family counts ride the terminal journal entry")
}
