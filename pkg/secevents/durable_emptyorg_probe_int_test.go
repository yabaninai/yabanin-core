package secevents

// E01-P04 W05-C01 adversarial probe — the S3 soft spot (W04 decision record
// §10.5 / §9 sabotage S3), attacked head-on instead of assumed:
//
//	W04's claim under test: «the empty-string arm stays GREEN only because
//	the write law forbids '' rows — an honestly disclosed defense-in-depth,
//	not a load-bearing wall» — i.e. org_id='' rows are creatable ONLY
//	outside the three-layer write law (Decode, Ingest validation, sink
//	guard), and the interim predicate covers operational reads.
//
// This file injects exactly such an out-of-law row (raw superuser SQL — the
// A4/DB-operator posture, outside the write law by construction) and measures
// what EVERY defensive layer does against it:
//
//	L1 interim predicate  `WHERE org_id = $1`   — today's operational rule;
//	L2 decided RLS policy WITH NULLIF          — the migration-0022 shape;
//	L2' the same policy WITHOUT NULLIF         — the S3 sabotage shape,
//	                                             applied here as a MODELED
//	                                             alternative on its own
//	                                             fixture schema (not a
//	                                             scratch tree edit);
//	L3 the writer GUC pin + WITH CHECK         — set_config('',''...)
//	                                             writer must not be able
//	                                             to create '' rows either.
//
// Verdict this probe pins (W05-C02 records it): W04's claim VERIFIED — no
// single layer alone survives both an out-of-law '' row AND an org-less
// reader, but every pairing of (session-derived non-empty org) OR (policy
// with NULLIF) OR (writer pin) independently closes the hole. The sharpened
// obligation for the wiring card: the read-boundary derivation law must
// REFUSE an empty org parameter — the predicate layer alone does not.
//
// REAL vs MODELED (W02 doctrine): the PostgreSQL behavior, app-role posture,
// RLS evaluation and write-law layers are REAL; the policies are MODELED
// copies (fixture-applied, as in durable_read_isolation_int_test.go —
// production landing is the wiring card's migration 0022). Docker-backed
// legs skip under -short like every testdb stand.
//
// Mandatory variants for this arm: allowed = own-org reads through each
// layer; empty/unavailable = GUC unset and '' (the matrix core);
// rights-denial + cross-org = no binding (incl. '') reaches foreign or
// outlaw rows through the policy; replay/delay = N/A — the policy is
// stateless per statement and the outlaw row's persistence is a write-path
// concern; rollback = N/A — no migration is in scope here and the 0021
// here, the fixture schema is dropped on cleanup, and the migration
// down-side transcript belongs to the wiring card (W04-C03 owns the 0021
// exercise).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// w05PolicyNoNullifSQL is the S3 sabotage shape as a MODELED alternative
// policy: identical to the decided DDL minus the NULLIF wrapper. It is
// applied to its OWN fixture schema (never by editing the decided w04PolicySQL
// or any product file).
const w05PolicyNoNullifSQL = `
ALTER TABLE secevents_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE secevents_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON secevents_documents
  USING (org_id = current_setting('app.current_org', true))
  WITH CHECK (org_id = current_setting('app.current_org', true));
`

// w05EmptyOrgFixture provisions one fixture-schema stand with the given
// policy (decided WITH-NULLIF or modeled WITHOUT-NULLIF), one REAL in-law
// row (DurableSink, superuser/migration posture — bypasses RLS by design)
// and one OUT-OF-LAW row (raw superuser INSERT with org_id=”): the ” row
// the three-layer write law forbids, created precisely the way §10.5 says
// it could exist — outside that law. The out-of-law document keeps both org
// homes consistent (document org_id = ” too): org-homes agreement
// (TestDurableReadIsolation_OrgHomesAgree) does NOT catch out-of-law rows,
// and this fixture pins that honestly.
func w05EmptyOrgFixture(t *testing.T, fixtureName, policySQL string) (pool *pgxpool.Pool, org string, ownID, outlawID string) {
	t.Helper()
	pool = testdb.PostgresOwnedSchema(t, fixtureName)
	ctx := context.Background()

	sink := NewDurableSink(pool)
	require.NoError(t, sink.EnsureSchema(ctx))
	_, err := pool.Exec(ctx, policySQL)
	require.NoError(t, err, "fixture must apply the policy variant verbatim")
	// Deploy-layer grants parity (w04ReadFixture): table + policy + grants
	// together model the production posture.
	var fixtureSchema string
	require.NoError(t, pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&fixtureSchema))
	_, err = pool.Exec(ctx, `GRANT USAGE ON SCHEMA `+pgx.Identifier{fixtureSchema}.Sanitize()+` TO yabanin_app`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `GRANT SELECT, INSERT ON secevents_documents TO yabanin_app`)
	require.NoError(t, err)

	token := fmt.Sprintf("w05eo%x", time.Now().UnixNano())
	org = token + "-org-a"
	ownID = token + "-own"
	outlawID = token + "-outlaw"

	// In-law row through the REAL write path.
	e := validEvent()
	e.OrgID = org
	e.EventID = ownID
	require.NoError(t, e.Validate())
	status, err := sink.RecordContext(ctx, e)
	require.NoError(t, err)
	require.Equal(t, DurableInserted, status)

	// Out-of-law row: raw SQL, org_id='' in BOTH org homes (Encode does not
	// validate, so the document carries the empty org naturally). This is
	// the adversarial premise, not a fixture bug: §10.5's "rows creatable
	// outside the write law" materialized.
	outlaw := validEvent()
	outlaw.OrgID = ""
	outlaw.EventID = outlawID
	_, err = pool.Exec(ctx, `
		INSERT INTO secevents_documents
		  (org_id, event_id, schema_version, event_type, occurred_at, document)
		VALUES ('', $1, $2, $3, $4, $5)`,
		outlaw.EventID, int(outlaw.SchemaVersion), outlaw.EventType, outlaw.OccurredAt, mustEncode(t, outlaw))
	require.NoError(t, err, "premise: a superuser can create the '' row the write law forbids")

	var outlaws int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents WHERE org_id = ''`).Scan(&outlaws))
	require.Equal(t, 1, outlaws, "the out-of-law row must exist for the probe to mean anything")
	return pool, org, ownID, outlawID
}

// TestW05EmptyOrgWriteLawRepins pins all THREE write-law layers against the
// org side of the null-key attack (the existing TestDurableSinkRejectsUnkeyedEvent
// pins the event_id side). REAL layers, no DB needed for the first two.
func TestW05EmptyOrgWriteLawRepins(t *testing.T) {
	e := validEvent()
	e.OrgID = "" // the attack: strip the org

	t.Run("layer 1: Decode/Validate rejects the empty org", func(t *testing.T) {
		err := e.Validate()
		require.ErrorIs(t, err, ErrInvalidEvent, "schema.go: org_id is required (dedup keys are org-scoped)")
	})

	t.Run("layer 2: Ingest rejects the empty org before any sink call", func(t *testing.T) {
		ing := NewIngester(SinkFunc(func(Event) error {
			t.Fatal("the sink must never see an org-less event")
			return nil
		}))
		_, err := ing.Ingest(e, anchorOcc)
		require.ErrorIs(t, err, ErrInvalidEvent)
		assert.False(t, ing.Recorded(e), "a rejected event is never marked seen")
	})

	t.Run("layer 3: DurableSink guard rejects the empty org", func(t *testing.T) {
		pool, sink, _ := aud01Sink(t)
		status, err := sink.RecordContext(context.Background(), e)
		require.Error(t, err, "the sink guard must reject org_id='' before SQL runs")
		assert.Equal(t, DurableAlreadyPresent, status, "guard-refusal keeps the sentinel status shape")
		var n int
		require.NoError(t, pool.QueryRow(context.Background(),
			`SELECT count(*) FROM secevents_documents WHERE org_id = ''`).Scan(&n))
		assert.Zero(t, n, "no '' row may appear through the guarded sink")
	})
}

// TestW05EmptyOrgVsLayers runs the S3 matrix on BOTH policy variants. Each
// subtest names the layer under measurement and the adversary position.
func TestW05EmptyOrgVsLayers(t *testing.T) {
	ctx := context.Background()

	t.Run("decided policy WITH NULLIF", func(t *testing.T) {
		pool, org, ownID, outlawID := w05EmptyOrgFixture(t, "w05nullif", w04PolicySQL) //nolint:contextcheck // fixture bootstrap chain takes testing.TB, not ctx

		t.Run("L1 interim predicate: real-org reader never sees the outlaw row", func(t *testing.T) {
			var n int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM secevents_documents WHERE org_id = $1`, org).Scan(&n))
			assert.Equal(t, 1, n, "own row visible (allowed variant)")
			var id string
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT event_id FROM secevents_documents WHERE org_id = $1`, org).Scan(&id))
			assert.Equal(t, ownID, id, "the visible row is exactly the own in-law row")
			var outlaw int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM secevents_documents WHERE org_id = $1 AND event_id = $2`, org, outlawID).Scan(&outlaw))
			assert.Zero(t, outlaw, "the outlaw row is invisible to a non-empty-org reader")
		})

		t.Run("L1 sharp edge: an EMPTY org parameter makes the predicate return the outlaw row", func(t *testing.T) {
			// This is the honest adversarial finding: the predicate layer
			// does NOT defend an org-less reader — the derivation law
			// (refuse empty org at the read boundary) is load-bearing.
			var ids []string
			rows, err := pool.Query(ctx,
				`SELECT event_id FROM secevents_documents WHERE org_id = $1`, "")
			require.NoError(t, err)
			defer rows.Close()
			for rows.Next() {
				var id string
				require.NoError(t, rows.Scan(&id))
				ids = append(ids, id)
			}
			require.NoError(t, rows.Err())
			assert.Equal(t, []string{outlawID}, ids,
				"org-less reader + predicate-only layer = out-of-law rows visible: the wiring card MUST refuse empty org at the read boundary")
		})

		t.Run("L2 policy: unbound session sees nothing incl. the outlaw row", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			var seen int
			require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
			assert.Zero(t, seen, "deny-all default holds even with an outlaw row present")
		})

		t.Run("L2 policy: empty GUC sees nothing (NULLIF is the wall here)", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
			require.NoError(t, err)
			var seen int
			require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
			assert.Zero(t, seen, "empty binding must not match the '' row: NULLIF('','') is NULL")
		})

		t.Run("L2 policy: bound org sees own row, never the outlaw row", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", org)
			require.NoError(t, err)
			var id string
			err = conn.QueryRow(ctx,
				`SELECT event_id FROM secevents_documents WHERE event_id = $1`, outlawID).Scan(&id)
			require.ErrorIs(t, err, pgx.ErrNoRows, "the outlaw row stays invisible to the bound org")
			var seen int
			require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
			assert.Equal(t, 1, seen, "exactly the own row")
		})

		t.Run("L3 writer pin: empty-org GUC writer cannot create an outlaw row", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			tx, err := conn.Begin(ctx)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, "SELECT set_config('app.current_org', '', true)")
			require.NoError(t, err)
			outlaw := validEvent()
			outlaw.OrgID = ""
			outlaw.EventID = "w05-pin-attempt"
			_, err = tx.Exec(ctx, `
				INSERT INTO secevents_documents
				  (org_id, event_id, schema_version, event_type, occurred_at, document)
				VALUES ($1, $2, $3, $4, $5, $6)`,
				outlaw.OrgID, outlaw.EventID, int(outlaw.SchemaVersion), outlaw.EventType, outlaw.OccurredAt, mustEncode(t, outlaw))
			require.Error(t, err, "WITH CHECK with NULLIF must reject the '' write even from a ''-bound writer")
			require.Contains(t, err.Error(), "row-level security")
			require.NoError(t, tx.Rollback(ctx))
		})
	})

	t.Run("modeled alternative policy WITHOUT NULLIF (S3 shape)", func(t *testing.T) {
		pool, org, ownID, _ := w05EmptyOrgFixture(t, "w05nonullif", w05PolicyNoNullifSQL) //nolint:contextcheck // fixture bootstrap chain takes testing.TB, not ctx

		t.Run("L2' unbound session still sees nothing (structural NULL compare)", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			var seen int
			require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
			assert.Zero(t, seen, "without NULLIF the unset GUC still yields NULL: no match — this arm alone cannot distinguish the variants")
		})

		t.Run("L2' empty GUC SEES the outlaw row: NULLIF is load-bearing once out-of-law rows exist", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
			require.NoError(t, err)
			var seen int
			require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
			assert.Equal(t, 1, seen,
				"WITHOUT NULLIF an empty binding matches the '' row: the W04 S3 disclosure, now demonstrated with a live row")
		})

		t.Run("L2' bound org still sees only its own row", func(t *testing.T) {
			conn := w04AppRoleConn(t, ctx, pool)
			_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", org)
			require.NoError(t, err)
			var id string
			require.NoError(t, conn.QueryRow(ctx,
				`SELECT event_id FROM secevents_documents`).Scan(&id))
			assert.Equal(t, ownID, id, "the bound-org behavior is identical in both variants: exactly the own row")
		})
	})
}
