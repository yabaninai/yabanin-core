package historyops

// Integration against a real PostgreSQL (disposable testcontainers stand):
// engine journal entries land in the shared admin audit table through the
// AF-10 seam, the hash chain stays intact across started/batch/completed/
// denied entries, and details carry identifiers and flags only — never
// payload content and never grant tokens.

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // register the pgx database/sql driver for the production verifier
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestJournalRidesAdminAuditChain(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `TRUNCATE admin_audit_outbox; TRUNCATE admin_audit_logs;`)
	require.NoError(t, err)

	store := adminstore.New(pool, slog.Default(), nil)
	journaler := NewAuditJournaler(store.InsertAuditLogEntry)

	// Engine harness identical to the unit tests, but the journal rides the
	// durable admin audit seam.
	clock := newFakeClock()
	stamp := SchemaStamp{MigrationHead: 16, FamiliesSchemaVersion: FamiliesSchemaVersion}
	engine := NewEngine(NewMemoryJobStore(clock.Now), journaler, EngineConfig{
		Now:   clock.Now,
		Stamp: func(context.Context) (SchemaStamp, error) { return stamp, nil },
	})
	runner := newScriptedRunner([][]string{{"r1", "r2"}, {"r3"}}, "r1", "r2", "r3")
	engine.RegisterRunner(OpArchiveRemoveHot, runner)

	sel, err := NewSelection(testOrg, "", closedPeriod(), []Family{FamilyRequestLogs},
		SelectionFilters{Model: "glm-5"}, clock.Now())
	require.NoError(t, err)
	digest, err := SelectionDigest(OpArchiveRemoveHot, sel, stamp)
	require.NoError(t, err)

	// One denied enqueue (digest mismatch), then one full run.
	_, err = engine.Enqueue(ctx, EnqueueRequest{
		OrgID: testOrg, Op: OpArchiveRemoveHot, Selection: sel,
		PresentedDigest: "stale", IdempotencyKey: "int-deny",
		Destination: testDestination,
		Actor:       JobActor{Author: "u-admin-1"}, Caller: adminCaller(),
	})
	refusal, ok := RefusalOf(err)
	require.True(t, ok)
	require.Equal(t, RefusalDigestMismatch, refusal.Code)

	job, err := engine.Enqueue(ctx, EnqueueRequest{
		OrgID: testOrg, Op: OpArchiveRemoveHot, Selection: sel,
		PresentedDigest: digest, IdempotencyKey: "int-run",
		Destination: testDestination,
		Actor:       JobActor{Type: ActorService, Author: "retention-svc", PolicyVersion: "ret-v3"},
	})
	require.NoError(t, err)
	claimed, err := engine.ExecuteNext(ctx, "worker-int")
	require.NoError(t, err)
	require.True(t, claimed)

	// The whole journal — the new entries included — still verifies.
	sqlDB, err := sql.Open("pgx", pool.Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	broken, err := auditlog.NewVerifier(sqlDB).Verify(ctx)
	require.NoError(t, err)
	require.Zero(t, broken, "audit chain must stay intact across engine entries")

	rows, err := pool.Query(ctx,
		`SELECT action, resource, details, admin_id, reason
		 FROM admin_audit_logs ORDER BY seq ASC`)
	require.NoError(t, err)
	defer rows.Close()

	type auditRow struct {
		Action   string
		Resource string
		Details  string
		AdminID  string
		Reason   string
	}
	var got []auditRow
	for rows.Next() {
		var r auditRow
		require.NoError(t, rows.Scan(&r.Action, &r.Resource, &r.Details, &r.AdminID, &r.Reason))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, got)

	actions := make(map[string]int, len(got))
	for _, r := range got {
		actions[r.Action]++
		if r.Action == JournalAction(OpArchiveRemoveHot, ActionDenied) {
			assert.Equal(t, "historyops_job:", r.Resource,
				"enqueue denials reference no job (it was never created)")
			continue
		}
		assert.Equal(t, "historyops_job:"+job.ID, r.Resource,
			"job entries reference the job id")
		// Details must be valid JSON with identifier/flag keys only.
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &details), r.Details)
		for key := range details {
			assert.NotContains(t, []string{"content", "payload", "response", "token", "grant_token"},
				key, "journal details must never carry content-ish keys")
		}
	}

	assert.Equal(t, 1, actions[JournalAction(OpArchiveRemoveHot, ActionStarted)])
	assert.Equal(t, 2, actions[JournalAction(OpArchiveRemoveHot, ActionBatch)])
	assert.Equal(t, 1, actions[JournalAction(OpArchiveRemoveHot, ActionCompleted)])
	assert.Equal(t, 1, actions[JournalAction(OpArchiveRemoveHot, ActionDenied)],
		"the denied enqueue is journalled against the submitted scope")
	assert.Zero(t, actions[JournalAction(OpArchiveRemoveHot, ActionCanceled)])

	// Service actor stamping rides into the durable journal (A-R7).
	for _, r := range got {
		if r.Action == JournalAction(OpArchiveRemoveHot, ActionStarted) {
			assert.Equal(t, "retention-svc", r.AdminID)
			var details map[string]any
			require.NoError(t, json.Unmarshal([]byte(r.Details), &details))
			assert.Equal(t, "ret-v3", details["policy_version"])
			assert.Equal(t, "service", details["actor_type"])
			assert.Contains(t, r.Reason, "actor:service")
		}
	}

	// The completed job's confirmed counts stay consistent with journal rows.
	stored, err := engine.Status(ctx, testOrg, job.ID)
	require.NoError(t, err)
	require.Equal(t, JobCompleted, stored.Status)
	assert.EqualValues(t, 3, stored.Confirmed.Total())
}
