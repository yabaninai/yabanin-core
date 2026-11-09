package secevents

// E01-P04 W04-C02 contract pins (durable read-path isolation). The decision
// record (artifacts/enterprise-beta/E01-P04/W04-readpath-decision.md) chose:
// RLS org_isolation per the house admin-surface pattern, landing with the
// first reader as migration 0022 + writer GUC pinning, with explicit
// predicates in reader SQL as defense-in-depth. Until that card lands there
// is NO production reader (W03 catalog XF-1) — so this file pins the DECIDED
// posture, not shipped product code:
//
//   - REAL arms: a fixture-schema stand carries a MODELED copy of the decided
//     policy DDL (verbatim from the decision record §5) plus the deploy-layer
//     app-role grants; the assertions run under the REAL application posture
//     (SET ROLE yabanin_app, NOBYPASSRLS — the toolpolicy rls_int_test.go
//     parity) against real PostgreSQL RLS semantics. MODELED part: the policy
//     itself (fixture-applied, not a product migration yet).
//   - MODELED arms: the interim predicate law (contract §1.5) exercised as
//     reader SQL that mirrors what any operational read must do today — no
//     product reader exists to test through.
//   - REAL org-consistency pin: the two org homes (column org_id and the
//     document body org_id) cannot diverge — the read path scopes by column.
//   - REAL extreme-skew pin: ±24 h producer timestamps stay verbatim (the
//     e01p03v pin extended beyond ±90 s/+5 min to a day each way).
//
// Deterministic: per-run org/event tokens, no sleeps. Docker-backed legs skip
// under -short like every testdb stand (one container per test binary; the
// fixture schema is dropped on cleanup, so the shared stand is never left
// with a policy or grants residue).

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

// w04PolicySQL is the decided tenant boundary, verbatim from the W04-C01
// decision record §5 (TEXT-org adaptation of the 0002 house shape). The
// fixture applies it to its own schema; production lands it as migration
// 0022 with the first reader.
const w04PolicySQL = `
ALTER TABLE secevents_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE secevents_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON secevents_documents
  USING (org_id = NULLIF(current_setting('app.current_org', true), ''))
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), ''));
`

// w04ReadFixture provisions a fixture-schema stand: the durable table via
// EnsureSchema (the SPI/test-stand home of the 0021 shape), the decided
// policy, and the deploy-layer grants the bootstrap gives yabanin_app on
// migrated tables (the fixture models table + policy + grants together —
// that triple IS the production posture being pinned). Seeding goes through
// the REAL write path (DurableSink) as the container superuser — the
// migration posture, which bypasses RLS by design.
func w04ReadFixture(t *testing.T) (pool *pgxpool.Pool, orgA, orgB string, idsA, idsB []string) {
	t.Helper()
	pool = testdb.PostgresOwnedSchema(t, "w04rls")
	ctx := context.Background()

	sink := NewDurableSink(pool)
	require.NoError(t, sink.EnsureSchema(ctx))
	_, err := pool.Exec(ctx, w04PolicySQL)
	require.NoError(t, err, "fixture must apply the decided policy DDL verbatim")
	// The deploy layer grants the app role DML on tenant tables (bootstrap
	// parity); the fixture schema's table starts owner-only, and a new
	// schema grants USAGE to no one — name lookup under the app role needs
	// explicit USAGE (the fixture models table + policy + grants together;
	// that triple IS the production posture being pinned). The pool's
	// search_path is pinned to the fixture schema, so the unqualified name
	// resolves to the fixture table.
	var fixtureSchema string
	require.NoError(t, pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&fixtureSchema))
	_, err = pool.Exec(ctx, `GRANT USAGE ON SCHEMA `+pgx.Identifier{fixtureSchema}.Sanitize()+` TO yabanin_app`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `GRANT SELECT, INSERT ON secevents_documents TO yabanin_app`)
	require.NoError(t, err)

	token := fmt.Sprintf("w04%x", time.Now().UnixNano())
	orgA, orgB = token+"-org-a", token+"-org-b"
	// idsA = [shared, a1, a2]; idsB = [shared, b1]. The SHARED id is
	// deliberate: identity is org-scoped (PK (org_id, event_id), contract
	// §1.1) — the same event_id under two orgs is two distinct rows, and a
	// foreign org replaying an id cannot collide with or shadow the own
	// org's row. The read arms pin that at the boundary.
	shared := token + "-shared"
	for _, id := range append([]string{shared}, token+"-a1", token+"-a2") {
		e := validEvent()
		e.OrgID = orgA
		e.EventID = id
		require.NoError(t, e.Validate()) // producer-side normalization
		status, err := sink.RecordContext(ctx, e)
		require.NoError(t, err)
		require.Equal(t, DurableInserted, status)
		idsA = append(idsA, e.EventID)
	}
	for _, id := range []string{shared, token + "-b1"} {
		e := validEvent()
		e.OrgID = orgB
		e.EventID = id
		require.NoError(t, e.Validate())
		_, err := sink.RecordContext(ctx, e)
		require.NoError(t, err)
		idsB = append(idsB, e.EventID)
	}
	return pool, orgA, orgB, idsA, idsB
}

// w04AppRoleConn downgrades one pooled connection to the application
// posture (the toolpolicy rlsAppRoleConn parity) and returns it with a
// cleanup that resets the session. The app.current_org GUC stays UNBOUND —
// callers bind their own. RLS assertions are void unless the session is
// downgraded, so the posture is asserted, not assumed.
func w04AppRoleConn(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *pgxpool.Conn {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "RESET ROLE")
		_, _ = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	})
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	return conn
}

// REAL arms (real PostgreSQL RLS, real app posture; the policy DDL itself is
// the MODELED part — fixture-applied copy of the decided migration 0022):
// the deny-all default, org binding, cross-org read/write rejection, and
// transaction-local GUC semantics of the decided boundary.
func TestDurableReadIsolation_RLSPolicyAppPosture(t *testing.T) {
	pool, orgA, orgB, idsA, idsB := w04ReadFixture(t)
	ctx := context.Background()

	t.Run("unbound session sees nothing (deny-all default)", func(t *testing.T) {
		conn := w04AppRoleConn(t, ctx, pool)
		var seen int
		require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
		assert.Zero(t, seen, "a session without org context must see no rows at all — never everything")
	})

	t.Run("empty-string GUC sees nothing (NULLIF fail-closed)", func(t *testing.T) {
		conn := w04AppRoleConn(t, ctx, pool)
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
		require.NoError(t, err)
		var seen int
		require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
		assert.Zero(t, seen, "an empty org binding must behave like no binding (fail closed), not like a wildcard")
	})

	t.Run("bound session sees exactly its own org", func(t *testing.T) {
		conn := w04AppRoleConn(t, ctx, pool)
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgA)
		require.NoError(t, err)

		var seen int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents WHERE org_id = $1`, orgA).Scan(&seen))
		assert.Equal(t, len(idsA), seen, "the bound org sees its own rows")

		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents WHERE org_id = $1`, orgB).Scan(&seen))
		assert.Zero(t, seen, "the bound org must not see the foreign org's rows")

		// Cross-org by exact primary key: the sharpest confused-deputy
		// probe — ask for a FOREIGN-ONLY event id under the OWN org
		// session. (idsB[0] is the shared id and resolves to A's OWN row
		// below; idsB[1:] are exclusive to org B.)
		for _, id := range idsB[1:] {
			var doc *string
			err := conn.QueryRow(ctx,
				`SELECT document::text FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
				orgA, id).Scan(&doc)
			require.ErrorIs(t, err, pgx.ErrNoRows, "foreign event under own org session: not found, no document leak")
			assert.Nil(t, doc)
		}
		// And the own ids ARE resolvable under the own org binding.
		for _, id := range idsA {
			var doc string
			require.NoError(t, conn.QueryRow(ctx,
				`SELECT document::text FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
				orgA, id).Scan(&doc), "own event under own org session must resolve")
			assert.NotEmpty(t, doc)
		}
	})

	t.Run("org-scoped identity: the same event_id coexists per org", func(t *testing.T) {
		// Bind orgB on a fresh app session: the shared id resolves to B's
		// OWN row (not A's), and B's counts are exactly its two rows.
		conn := w04AppRoleConn(t, ctx, pool)
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgB)
		require.NoError(t, err)

		var doc string
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT document::text FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
			orgB, idsB[0]).Scan(&doc), "the shared id must resolve under its owning org")
		var docOrg string
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT document->>'org_id' FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
			orgB, idsB[0]).Scan(&docOrg))
		assert.Equal(t, orgB, docOrg, "the shared-id row under orgB's binding is orgB's row — no shadowing")

		var seenB int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents WHERE org_id = $1`, orgB).Scan(&seenB))
		assert.Equal(t, len(idsB), seenB, "orgB sees exactly its own rows")
	})

	t.Run("cross-org write is rejected, never silent", func(t *testing.T) {
		conn := w04AppRoleConn(t, ctx, pool)
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgA)
		require.NoError(t, err)

		e := validEvent()
		e.OrgID = orgB
		e.EventID = idsB[0] + "-inject-attempt"
		require.NoError(t, e.Validate())
		_, err = conn.Exec(ctx,
			`INSERT INTO secevents_documents
			   (org_id, event_id, schema_version, event_type, occurred_at, document)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			e.OrgID, e.EventID, int(e.SchemaVersion), e.EventType, e.OccurredAt, mustEncode(t, e))
		require.Error(t, err, "the org_isolation WITH CHECK arm must reject a cross-org write")
		// The rejection must be the POLICY, not an incidental failure shape:
		// distinguish "violates row-level security" from any other error.
		require.Contains(t, err.Error(), "row-level security",
			"cross-org write rejection must come from the org_isolation policy's WITH CHECK arm")

		// Rejected means not-written: check under the superuser posture
		// (migration posture, bypasses RLS by design).
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents WHERE event_id = $1`, e.EventID).Scan(&n))
		assert.Zero(t, n, "a rejected cross-org write must leave no row behind")
	})

	t.Run("transaction-local GUC does not leak to the next transaction", func(t *testing.T) {
		conn := w04AppRoleConn(t, ctx, pool)
		// tx 1: bind orgA transaction-locally (the withOrgTx semantics the
		// writer/reader must use) and see rows.
		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgA)
		require.NoError(t, err)
		var seen int
		require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&seen))
		assert.Equal(t, len(idsA), seen, "inside the bound transaction the own rows are visible")
		require.NoError(t, tx.Commit(ctx))

		// Same pooled connection, next transaction, no binding: the GUC
		// must NOT have survived the commit (deputy elevation pin).
		var after int
		require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM secevents_documents`).Scan(&after))
		assert.Zero(t, after, "a transaction-local org binding must not leak into the next transaction on the same connection")
	})
}

// MODELED arms: the interim predicate law (contract §1.5) as reader SQL.
// No production reader exists (XF-1); this SQL mirrors what ANY operational
// read of the table must do until migration 0022 lands, and stays the
// defense-in-depth layer after. Runs on the superuser fixture pool — the
// operational posture today.
func TestDurableReadIsolation_PredicateLawInterim(t *testing.T) {
	pool, orgA, orgB, idsA, idsB := w04ReadFixture(t)
	ctx := context.Background()

	// A list reader scoped by predicate: foreign org → empty, nil error
	// (absence is never an error-leak and never everything).
	rows, err := pool.Query(ctx,
		`SELECT event_id FROM secevents_documents WHERE org_id = $1 ORDER BY event_id`, orgA)
	require.NoError(t, err)
	defer rows.Close()
	var gotA []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		gotA = append(gotA, id)
	}
	require.NoError(t, rows.Err())
	require.ElementsMatch(t, idsA, gotA, "own org list: exactly the own events")

	// Foreign org's B-ONLY ids under orgA's predicate: none — listing
	// cannot observe orgB rows (idsB[0] is the shared id and is A's OWN row
	// under orgA; idsB[1:] are exclusive to org B).
	rowsB, err := pool.Query(ctx,
		`SELECT event_id FROM secevents_documents WHERE org_id = $1 AND event_id = ANY($2)`, orgA, idsB[1:])
	require.NoError(t, err)
	defer rowsB.Close()
	var leaked []string
	for rowsB.Next() {
		var id string
		require.NoError(t, rowsB.Scan(&id))
		leaked = append(leaked, id)
	}
	require.NoError(t, rowsB.Err())
	assert.Empty(t, leaked, "a predicate reader must never return foreign org events")

	// Unknown org: empty result, nil error — not-found and error are
	// distinct; absence must not error-leak.
	rowsU, err := pool.Query(ctx,
		`SELECT event_id FROM secevents_documents WHERE org_id = $1 ORDER BY event_id`, "org-never-existed")
	require.NoError(t, err)
	defer rowsU.Close()
	var unknown []string
	for rowsU.Next() {
		var id string
		require.NoError(t, rowsU.Scan(&id))
		unknown = append(unknown, id)
	}
	require.NoError(t, rowsU.Err())
	assert.Empty(t, unknown, "unknown org: zero rows, nil error — never everything")

	// Positive control on the same law: orgB's own list returns exactly its
	// rows, shared id included — the predicate isolates, it does not erase.
	rowsOwnB, err := pool.Query(ctx,
		`SELECT event_id FROM secevents_documents WHERE org_id = $1 ORDER BY event_id`, orgB)
	require.NoError(t, err)
	defer rowsOwnB.Close()
	var gotB []string
	for rowsOwnB.Next() {
		var id string
		require.NoError(t, rowsOwnB.Scan(&id))
		gotB = append(gotB, id)
	}
	require.NoError(t, rowsOwnB.Err())
	require.ElementsMatch(t, idsB, gotB, "foreign org's OWN list still works: exactly its events, shared id included")

	// Get-by-key for a foreign (org, id) pair: not-found via ErrNoRows, no
	// document content returned. (idsB[1] is exclusive to org B.)
	var doc *string
	err = pool.QueryRow(ctx,
		`SELECT document::text FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
		orgA, idsB[1]).Scan(&doc)
	require.ErrorIs(t, err, pgx.ErrNoRows, "foreign (org, event) key: not-found, not the foreign document")
	assert.Nil(t, doc)
}

// REAL org-consistency pin: the two org homes — the org_id column (what the
// read path scopes by, in either posture) and the document body's org_id
// (what document consumers see) — must agree on every row. A divergence
// would split the org truth between SQL and JSON consumers; it is
// contractually impossible (write law) and pinned here.
func TestDurableReadIsolation_OrgHomesAgree(t *testing.T) {
	pool, orgA, orgB, _, _ := w04ReadFixture(t)
	ctx := context.Background()

	var mismatched int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM secevents_documents
		WHERE document->>'org_id' IS DISTINCT FROM org_id`).Scan(&mismatched))
	assert.Zero(t, mismatched, "column org_id and document org_id must agree on every row")

	for _, org := range []string{orgA, orgB} {
		var docOrg string
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT document->>'org_id' FROM secevents_documents WHERE org_id = $1 LIMIT 1`, org).Scan(&docOrg))
		assert.Equal(t, org, docOrg, "stored document carries its org verbatim")
	}
}

// REAL extreme-skew pin (extends TestDurableSinkSkewVerbatimAndUnknownCost
// from ±90 s / +5 min to a full day each way): producer timestamps stay
// verbatim in both homes — never rebased to delivery time, never clamped to
// plausible ranges — and the org home stays consistent under extreme skew.
func TestDurableSinkExtremeSkewVerbatim(t *testing.T) {
	pool, sink, token := aud01Sink(t)
	ctx := context.Background()
	ing := NewIngester(sink)

	cases := []struct {
		name string
		skew time.Duration
	}{
		{"a full day in the past", -24 * time.Hour},
		{"a full day in the future", 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			e.EventID = fmt.Sprintf("%s-skew%+d", token, tc.skew/time.Hour)
			e.OccurredAt = anchorOcc.Add(tc.skew)
			require.NoError(t, e.Validate()) // producer-side normalization

			_, err := ing.Ingest(e, anchorOcc) // delivered at the anchored now
			require.NoError(t, err)

			var storedAt time.Time
			var docOccurredAt, docOrg string
			err = pool.QueryRow(ctx, `
				SELECT occurred_at, document->>'occurred_at', document->>'org_id'
				FROM secevents_documents WHERE org_id=$1 AND event_id=$2`,
				e.OrgID, e.EventID).Scan(&storedAt, &docOccurredAt, &docOrg)
			require.NoError(t, err)
			assert.True(t, storedAt.Equal(anchorOcc.Add(tc.skew)),
				"extreme skew must stay verbatim: got %v want %v", storedAt, anchorOcc.Add(tc.skew))
			assert.Equal(t, anchorOcc.Add(tc.skew).Format(time.RFC3339), docOccurredAt,
				"document carries the skewed producer timestamp verbatim")
			assert.Equal(t, e.OrgID, docOrg, "org home stays consistent under extreme skew")
		})
	}
}
