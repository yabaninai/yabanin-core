package secevents

// E06-P01 W01-C01 (Trigger ②): the WRITER half of the 0026 posture, landed
// in the same change as the RLS migration and the first production reader
// (pkg/inbox). Three pins:
//   - SQL shape (always on, no DB): the writer GUC-pin law — durablePinSQL
//     (transaction-local set_config), durableNeedsPinSQL (bypass roles skip
//     the pin: for them it is inert residue) and the exactly-once INSERT.
//   - mirror pin (always on, no DB): migration 0026 up/down are the W04 §5.1
//     decision DDL verbatim (formatting-insensitive), so the tenant
//     boundary can never drift from the decided one.
//   - battery (Docker, real stand): the sink under the REAL 0026 policy on
//     public.secevents_documents with the real yabanin_app role — insert,
//     exactly-once redelivery, cross-org write rejection from the policy's
//     WITH CHECK arm, pin locality under the app posture, and NO GUC
//     residue on bypass sessions (the regression that killed the
//     same-statement CTE form: on PG14+ any set_config of a custom GUC
//     leaves the session placeholder as '', breaking NULL-vs-empty
//     distinctions like the W05 S3 probe).

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestDurableWriterPinLawSQLShapes(t *testing.T) {
	assert.Contains(t, durablePinSQL, "set_config('app.current_org', $1, true)",
		"transaction-local pin (is_local=true, the withOrgTx semantics)")
	assert.Contains(t, durableNeedsPinSQL, "rolsuper OR rolbypassrls",
		"bypass sessions skip the pin: for them it is inert residue")
	assert.Contains(t, durableInsertSQL, "ON CONFLICT (org_id, event_id) DO NOTHING",
		"the exactly-once decision stays inside the statement")
	assert.NotContains(t, durableInsertSQL, "WITH org_pin",
		"the same-statement CTE pin is rejected: its set_config leaves the GUC session placeholder as '' on PG14+ pooled connections")
}

// The pin law, behaviorally: a bypass (superuser) session writes WITHOUT any
// set_config — the connection keeps a pristine, truly-unset GUC (NULL, not
// ”). This is the regression arm for the W05 S3 probe failure that killed
// the CTE form.
func TestDurableWriterLeavesNoGUCResidueOnBypassSessions(t *testing.T) {
	ctx := context.Background()
	conn, err := testdb.Postgres(t).Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	sink := NewDurableSink(conn)
	e := validEvent()
	e.OrgID = fmt.Sprintf("e06res%x", time.Now().UnixNano())
	e.EventID = e.OrgID + "-evt"
	require.NoError(t, e.Validate())
	st, err := sink.RecordContext(context.Background(), e)
	require.NoError(t, err)
	require.Equal(t, DurableInserted, st)

	var guc *string
	require.NoError(t, conn.QueryRow(context.Background(),
		`SELECT current_setting('app.current_org', true)`).Scan(&guc))
	assert.Nil(t, guc, "a bypass write must leave the GUC truly unset — not even the '' placeholder")
}

// w04DecisionRlsUp/Down are the E06-P04 W04-readpath-decision.md §5.1 DDL,
// verbatim — the source the migration files must mirror.
const w04DecisionRlsUp = `ALTER TABLE public.secevents_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secevents_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON public.secevents_documents
  USING (org_id = NULLIF(current_setting('app.current_org', true), ''))
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), ''))`

const w04DecisionRlsDown = `DROP POLICY org_isolation ON public.secevents_documents;
ALTER TABLE public.secevents_documents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.secevents_documents DISABLE ROW LEVEL SECURITY`

func TestMigration0026MirrorsW04DecisionRLS(t *testing.T) {
	root := os.DirFS("../../migrations") // same resolution as the 0021 mirror pin
	up, err := fs.ReadFile(root, "0026_secevents_documents_rls.up.sql")
	require.NoError(t, err, "migrations/0026_secevents_documents_rls.up.sql must exist")
	assert.Equal(t, normalizeDDL(w04DecisionRlsUp), normalizeDDL(string(up)),
		"migration 0026 up must be the W04 §5.1 decision DDL verbatim (formatting-insensitive)")
	down, err := fs.ReadFile(root, "0026_secevents_documents_rls.down.sql")
	require.NoError(t, err, "migrations/0026_secevents_documents_rls.down.sql must exist")
	assert.Equal(t, normalizeDDL(w04DecisionRlsDown), normalizeDDL(string(down)),
		"migration 0026 down must be the W04 §5.1 reverse DDL verbatim")
}

func TestDurableSinkAppPostureUnderRLS(t *testing.T) {
	su := testdb.Postgres(t)
	app := testdb.PostgresApp(t, "test")
	token := fmt.Sprintf("e06w%x", time.Now().UnixNano())
	orgA, orgB := token+"a", token+"b"
	ctx := context.Background()

	sinkApp := NewDurableSink(app)
	// No EnsureSchema here on purpose: the app role MUST NOT hold CREATE on
	// the public schema (bootstrap grants DML only), and CREATE TABLE IF NOT
	// EXISTS still requires it. The table exists via the stand's migrations
	// (0021); the app posture is DML-only.

	// THE key pin: the app role writes successfully under the REAL 0026
	// policy (FORCE RLS + org_isolation) because RecordContext pins the org
	// in the same transaction as the INSERT — the WITH CHECK sees the
	// binding at insert time.
	e := validEvent()
	e.OrgID = orgA
	e.EventID = token + "-evt1"
	require.NoError(t, e.Validate())
	st, err := sinkApp.RecordContext(ctx, e)
	require.NoError(t, err, "app-role write must pass the WITH CHECK via the same-statement pin")
	require.Equal(t, DurableInserted, st)

	// Exactly-once under the RLS posture: a redelivery is a no-op, never an
	// error and never a second row.
	st, err = sinkApp.RecordContext(ctx, e)
	require.NoError(t, err)
	require.Equal(t, DurableAlreadyPresent, st)
	var docs int
	require.NoError(t, su.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents WHERE org_id=$1 AND event_id=$2`,
		orgA, e.EventID).Scan(&docs))
	assert.Equal(t, 1, docs, "insert + redelivery under RLS posture = exactly one durable document")

	t.Run("cross-org write is policy-rejected, never silent", func(t *testing.T) {
		// A session pinned to orgA attempts a raw insert of orgB's row: the
		// org_isolation WITH CHECK arm must reject it (the REAL policy, not
		// the C02 fixture copy).
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgA)
		require.NoError(t, err)
		foreign := validEvent()
		foreign.OrgID = orgB
		foreign.EventID = token + "-evt-b"
		require.NoError(t, foreign.Validate())
		_, err = tx.Exec(ctx,
			`INSERT INTO secevents_documents
			   (org_id, event_id, schema_version, event_type, occurred_at, document)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			foreign.OrgID, foreign.EventID, int(foreign.SchemaVersion), foreign.EventType, foreign.OccurredAt, mustEncode(t, foreign))
		require.Error(t, err, "a session pinned to orgA must not write orgB rows")
		assert.Contains(t, err.Error(), "row-level security",
			"the rejection must come from the org_isolation WITH CHECK arm")
	})

	t.Run("writer pin is transaction-local on the pooled connection", func(t *testing.T) {
		// The pin's set_config is transaction-local inside the record's
		// transaction: after the commit the same connection must see the
		// deny-all default again (the '' placeholder residue of PG14+ is
		// fail-closed under the NULLIF policy — it matches nothing).
		conn, err := app.Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
		sinkConn := NewDurableSink(conn)
		e2 := validEvent()
		e2.OrgID = orgA
		e2.EventID = token + "-evt2"
		require.NoError(t, e2.Validate())
		st, err := sinkConn.RecordContext(ctx, e2)
		require.NoError(t, err)
		require.Equal(t, DurableInserted, st)

		var seen int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents`).Scan(&seen))
		assert.Zero(t, seen,
			"set_config(..., true) inside the insert statement must not survive the statement's implicit transaction")
	})
}
