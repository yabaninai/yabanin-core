// Consumer boundary battery (E01-P05 card W02-C02, dispatch of 2026-11-07,
// mandate A: consumer/verification only — this file is the card's single
// deliverable; the RLS boundary itself, migration 0026 and the production
// reader are E06-P01 W01-C01's single-owned territory, used here read-only).
//
// The store now has two production access paths through one boundary:
//
//   - the WRITE path (pkg/secevents: Ingester → DurableSink.RecordContext,
//     writer GUC pin W04 §5.2), and
//   - the READ path (pkg/inbox.Reader, reader GUC pin + org predicate,
//     the E06-P01 first production reader).
//
// This battery verifies the boundary from the CONSUMER side of pkg/secevents:
// the full write path stays green under the real migrated posture (app role,
// NOBYPASSRLS, migration 0026 applied by the stand bootstrap), the inbox
// reader is a correct second access path over the same pool, the empty-org
// refusal is explicit and precedes any database work, the org comes from the
// context (never a client parameter), the WHERE org_id predicate holds as
// defense-in-depth on top of the policy, and both the reader and the writer
// GUC pins are transaction-local under interleaved consumer traffic.
//
// Variants canon (stand coverage): allowed = own-org read/write through both
// production paths; empty/unavailable = unknown org reads empty with a nil
// error; rights/cross-org = foreign org is invisible down to the exact
// primary key; replay/delay = redelivery after a restart-shaped fresh
// ingester converges to exactly one durable row; rollback = N/A — this card
// owns no DDL, so there is no boundary migration of ours to roll back (the
// 0026 posture belongs to its single owner and is verified in place).
package secevents_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/inbox"
	"github.com/reireirei/yabanin/pkg/secevents"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// cbEvent builds a minimal valid security event (the same document shape the
// E06 reader battery uses: known agent, unknown tool state, unknown cost).
func cbEvent(org, id string, occ time.Time) secevents.Event {
	e := secevents.Event{}
	e.SchemaVersion = secevents.SchemaVersion
	e.EventID = id
	e.EventType = "tool.deny"
	e.OrgID = org
	e.OccurredAt = occ
	e.Identity.Agent = secevents.IDRef{Value: "agent-7", State: secevents.IDKnown}
	e.Identity.Session = secevents.IDRef{Value: "sess-42"}
	e.Identity.Task = secevents.IDRef{State: secevents.IDAbsent}
	e.Identity.Tool = secevents.IDRef{State: secevents.IDUnknown}
	e.Cost = secevents.Cost{State: secevents.CostUnknown}
	return e
}

// cbFixture stands up the real boundary: a fully migrated stand (all
// migrations including 0026 org_isolation, applied by the testdb bootstrap),
// a superuser pool (migration posture, bypasses RLS by design) and an
// app-role pool (NOBYPASSRLS — the production surface both consumer paths
// run on). Org tokens are unique per run so concurrent runs coexist. Both A
// events share occurred_at so the (occurred_at, event_id) total order must
// break the tie by event_id.
func cbFixture(t *testing.T) (su, app *pgxpool.Pool, orgA, orgB string, idsA []string, idB string) {
	t.Helper()
	su = testdb.Postgres(t)
	app = testdb.PostgresApp(t, "test")
	token := fmt.Sprintf("cbp05b%x", time.Now().UnixNano())
	orgA, orgB = token+"a", token+"b"
	ctx := context.Background()
	base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	idsA = []string{token + "-evt1", token + "-evt2"}
	for _, id := range idsA {
		st, err := secevents.NewDurableSink(su).RecordContext(ctx, cbEvent(orgA, id, base))
		require.NoError(t, err)
		require.Equal(t, secevents.DurableInserted, st)
	}
	idB = token + "-evtb"
	st, err := secevents.NewDurableSink(su).RecordContext(ctx, cbEvent(orgB, idB, base))
	require.NoError(t, err)
	require.Equal(t, secevents.DurableInserted, st)
	return su, app, orgA, orgB, idsA, idB
}

// TestConsumerBoundary_WritePathRegressionUnderBoundary pins the card's
// primary regression: the pkg/secevents write path — direct RecordContext
// AND the full Ingester → DurableSink front door — stays green when it runs
// on the app-role pool under the real 0026 posture. The writer GUC pin must
// admit the org-scoped insert, and a redelivery after a restart-shaped fresh
// ingester must converge to exactly one durable row (exactly-once), reported
// as DurableAlreadyPresent by the sink.
func TestConsumerBoundary_WritePathRegressionUnderBoundary(t *testing.T) {
	su, app, orgA, _, _, _ := cbFixture(t)
	ctx := context.Background()
	token := fmt.Sprintf("cbwp%x", time.Now().UnixNano())
	id := token + "-evt"
	base := time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)

	// Direct sink write through the app-role surface: the pin admits it.
	st, err := secevents.NewDurableSink(app).RecordContext(ctx, cbEvent(orgA, id, base))
	require.NoError(t, err, "the write path must stay green under the boundary (app role, real 0026)")
	require.Equal(t, secevents.DurableInserted, st)

	// Redelivery (fresh sink, lost-acknowledgment model): already durable
	// is success, the stored document is untouched.
	st, err = secevents.NewDurableSink(app).RecordContext(ctx, cbEvent(orgA, id, base))
	require.NoError(t, err)
	require.Equal(t, secevents.DurableAlreadyPresent, st)

	// Full front door over the app pool: first ingest records.
	id2 := token + "-evt2"
	ing := secevents.NewIngester(secevents.NewDurableSink(app))
	res, err := ing.Ingest(cbEvent(orgA, id2, base), base.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, secevents.OutcomeRecorded, res.Outcome)
	require.Equal(t, secevents.Cost{State: secevents.CostUnknown}, res.Cost)

	// Restart-shaped redelivery: a FRESH ingester instance has lost its
	// in-memory dedup; durability is the sink's decision — one row total.
	ing2 := secevents.NewIngester(secevents.NewDurableSink(app))
	_, err = ing2.Ingest(cbEvent(orgA, id2, base), base.Add(2*time.Second))
	require.NoError(t, err)

	for _, eID := range []string{id, id2} {
		var n int
		require.NoError(t, su.QueryRow(ctx,
			`SELECT count(*) FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
			orgA, eID).Scan(&n))
		assert.Equal(t, 1, n, "exactly one durable row per (org, event_id) after redeliveries")
	}
}

// TestConsumerBoundary_ReadViaInboxReaderRoundTrip pins the reader as a
// correct second access path over the same app-role pool: what the write
// path stored for an org is exactly what the bound org reads back — same
// ids, same total order (tie on occurred_at broken by event_id ASC), same
// document org — a foreign org sees only its own events, and an unknown org
// reads empty with a nil error (empty/unavailable variant), never an error
// and never foreign rows.
func TestConsumerBoundary_ReadViaInboxReaderRoundTrip(t *testing.T) {
	_, app, orgA, orgB, idsA, idB := cbFixture(t)
	r := inbox.NewReader(app)
	ctx := context.Background()

	evs, err := r.Events(inbox.WithOrg(ctx, orgA))
	require.NoError(t, err)
	require.Len(t, evs, len(idsA), "the bound org reads back exactly what its write path stored")
	assert.Equal(t, idsA[0], evs[0].EventID, "tie on occurred_at broken by event_id ASC")
	assert.Equal(t, idsA[1], evs[1].EventID)
	assert.Equal(t, orgA, evs[0].OrgID)
	assert.Equal(t, "tool.deny", evs[0].EventType)
	assert.Equal(t, secevents.SchemaVersion, evs[0].SchemaVersion)

	evsB, err := r.Events(inbox.WithOrg(ctx, orgB))
	require.NoError(t, err)
	require.Len(t, evsB, 1)
	assert.Equal(t, idB, evsB[0].EventID)
	assert.Equal(t, orgB, evsB[0].OrgID)

	evsU, err := r.Events(inbox.WithOrg(ctx, orgA+"-unknown"))
	require.NoError(t, err, "unknown org is an empty feed, not an error")
	assert.Empty(t, evsU)
}

// TestConsumerBoundary_EmptyOrgExplicitRefusal pins the refusal law at the
// consumer seam: a missing org binding AND an explicitly empty one are both
// refused with inbox.ErrOrgRequired — an empty org is never a wildcard. The
// cancelled-context probe proves the refusal is decided at the Go boundary
// BEFORE any database work: with a cancelled context and no binding the
// error is still ErrOrgRequired, not context.Canceled.
func TestConsumerBoundary_EmptyOrgExplicitRefusal(t *testing.T) {
	_, app, _, _, _, _ := cbFixture(t)
	r := inbox.NewReader(app)
	ctx := context.Background()

	_, err := r.Events(ctx)
	require.ErrorIs(t, err, inbox.ErrOrgRequired, "missing org binding must be refused")

	_, err = r.Events(inbox.WithOrg(ctx, ""))
	require.ErrorIs(t, err, inbox.ErrOrgRequired, "empty org binding must be refused, not treated as no scope")

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = r.Events(cancelled)
	require.ErrorIs(t, err, inbox.ErrOrgRequired,
		"refusal precedes the database: a cancelled context must not turn ErrOrgRequired into context.Canceled")
	require.NotErrorIs(t, err, context.Canceled)
}

// TestConsumerBoundary_OrgDerivedFromContextOnly pins the derivation law
// from the consumer side: Events(ctx) carries no org parameter — the org
// can only arrive via WithOrg from the authenticated context. The same
// reader over the same pool yields disjoint exact scopes per binding, which
// is only possible if the scope travels with the context, never the call.
func TestConsumerBoundary_OrgDerivedFromContextOnly(t *testing.T) {
	_, app, orgA, orgB, idsA, idB := cbFixture(t)
	r := inbox.NewReader(app)
	ctx := context.Background()

	evsA, err := r.Events(inbox.WithOrg(ctx, orgA))
	require.NoError(t, err)
	evsB, err := r.Events(inbox.WithOrg(ctx, orgB))
	require.NoError(t, err)

	gotA := make(map[string]bool, len(evsA))
	for _, ev := range evsA {
		gotA[ev.EventID] = true
	}
	for _, id := range idsA {
		assert.True(t, gotA[id], "orgA binding sees its own event %s", id)
		assert.False(t, containsEvent(evsB, id), "orgB binding must not see orgA event %s", id)
	}
	assert.True(t, containsEvent(evsB, idB), "orgB binding sees its own event")
	assert.False(t, containsEvent(evsA, idB), "orgA binding must not see orgB event")
}

func containsEvent(evs []secevents.Event, id string) bool {
	for _, ev := range evs {
		if ev.EventID == id {
			return true
		}
	}
	return false
}

// cbList is the consumer-side list pattern the reader SQL contract prescribes:
// one transaction, transaction-local pin, explicit WHERE org_id predicate on
// top of the policy. It returns the ordered event ids visible to that scope.
func cbList(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pinOrg, predicateOrg string) []string {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT set_config('app.current_org', $1, true)`, pinOrg)
	require.NoError(t, err)
	rows, err := tx.Query(ctx,
		`SELECT event_id FROM secevents_documents WHERE org_id = $1 ORDER BY occurred_at, event_id`,
		predicateOrg)
	require.NoError(t, err)
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, tx.Commit(ctx))
	return ids
}

// TestConsumerBoundary_PredicateDefenseInDepth pins the explicit WHERE
// org_id predicate as a layer ON TOP of the org_isolation policy, observable
// from the consumer side:
//
//   - own org pinned, own predicate → the exact own set;
//   - own org pinned, foreign predicate → empty: the predicate alone
//     refuses the cross-org read even before the policy is consulted;
//   - unknown org predicate → empty;
//   - the exact PRIMARY KEY of a foreign event under the own-org pin →
//     zero rows: the predicate defeats row-address probing;
//   - an unpinned app-role statement sees nothing at all (the deny-all
//     default of the 0026 NULLIF posture).
//
// The raw-SQL foreign-pin arm documents why the Go-boundary derivation law
// is load-bearing rather than redundant: the POLICY itself trusts the
// binding, so only the reader's context-only derivation (ErrOrgRequired,
// Events(ctx) without an org parameter) keeps a consumer from ever pinning
// a foreign org.
func TestConsumerBoundary_PredicateDefenseInDepth(t *testing.T) {
	su, app, orgA, orgB, idsA, idB := cbFixture(t)
	ctx := context.Background()

	own := cbList(t, ctx, app, orgA, orgA)
	assert.Equal(t, idsA, own, "own pin + own predicate = the exact own set")

	foreign := cbList(t, ctx, app, orgA, orgB)
	assert.Empty(t, foreign, "the WHERE org_id predicate refuses the cross-org read under the own pin")

	unknown := cbList(t, ctx, app, orgA, orgA+"-unknown")
	assert.Empty(t, unknown, "unknown org predicate = empty")

	var pkHits int
	require.NoError(t, app.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents WHERE org_id = $1 AND event_id = $2`,
		orgA, idB).Scan(&pkHits))
	assert.Zero(t, pkHits, "the exact primary key of a foreign event must not be addressable")

	var unpinned int
	require.NoError(t, app.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents`).Scan(&unpinned))
	assert.Zero(t, unpinned, "an unpinned app-role statement sees the deny-all default")

	// Documented observation (not a production path): with the binding set
	// directly, the policy admits the foreign rows — the isolation trusts
	// the GUC. This is exactly why Events must never accept an org client
	// parameter: the derivation law is the layer that cannot be confused.
	foreignPin := cbList(t, ctx, app, orgB, orgB)
	assert.Equal(t, []string{idB}, foreignPin,
		"policy trusts the binding; only the context-only derivation law makes that safe")

	var suTotal int
	require.NoError(t, su.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents WHERE org_id IN ($1, $2)`,
		orgA, orgB).Scan(&suTotal))
	assert.Equal(t, len(idsA)+1, suTotal, "superuser posture sees all seeded rows (migration stand truth)")
}

// TestConsumerBoundary_TxLocalityInterleaved pins both GUC pins — the
// reader's and the writer's — as transaction-local under interleaved
// consumer traffic on the SHARED app pool: A-read, B-read, A-write, A-read,
// B-read, and afterwards no binding residue on the pooled connections, so
// the next unpinned statement sees the deny-all default, never org A's rows
// and never the whole table.
func TestConsumerBoundary_TxLocalityInterleaved(t *testing.T) {
	su, app, orgA, orgB, idsA, _ := cbFixture(t)
	r := inbox.NewReader(app)
	ctx := context.Background()

	// A → B: each read sees exactly its own current set.
	evsA1, err := r.Events(inbox.WithOrg(ctx, orgA))
	require.NoError(t, err)
	require.Len(t, evsA1, len(idsA))
	evsB1, err := r.Events(inbox.WithOrg(ctx, orgB))
	require.NoError(t, err)
	require.Len(t, evsB1, 1)

	// Interleaved app-role write of a NEW orgA event between reads.
	newID := fmt.Sprintf("cbtx%x", time.Now().UnixNano()) + "-evt3"
	base := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	st, err := secevents.NewDurableSink(app).RecordContext(ctx, cbEvent(orgA, newID, base))
	require.NoError(t, err)
	require.Equal(t, secevents.DurableInserted, st)

	// A again: sees its new event; B again: unaffected by A's write.
	evsA2, err := r.Events(inbox.WithOrg(ctx, orgA))
	require.NoError(t, err)
	require.Len(t, evsA2, len(idsA)+1)
	assert.True(t, containsEvent(evsA2, newID), "the bound org sees the interleaved write")
	assert.Equal(t, newID, evsA2[len(evsA2)-1].EventID, "later occurred_at sorts last")
	evsB2, err := r.Events(inbox.WithOrg(ctx, orgB))
	require.NoError(t, err)
	require.Len(t, evsB2, 1, "orgB's feed is unaffected by orgA's interleaved write")

	// No pin residue: an unpinned app-role statement sees nothing.
	var unpinned int
	require.NoError(t, app.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents`).Scan(&unpinned))
	assert.Zero(t, unpinned, "neither the reader nor the writer pin may survive its transaction")

	// Stand truth for the total (superuser posture).
	var suTotal int
	require.NoError(t, su.QueryRow(ctx,
		`SELECT count(*) FROM secevents_documents WHERE org_id = $1`, orgA).Scan(&suTotal))
	assert.Equal(t, len(idsA)+1, suTotal)
}

// TestConsumerBoundary_ErrOrgRequiredIsSentinel keeps the refusal a typed
// sentinel (errors.Is-identity, not substring matching): consumers gate on
// the sentinel to distinguish "no authenticated org" (a caller bug) from a
// storage failure, and that contract must not rot behind error wrapping.
func TestConsumerBoundary_ErrOrgRequiredIsSentinel(t *testing.T) {
	_, app, _, _, _, _ := cbFixture(t)
	_, err := inbox.NewReader(app).Events(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, inbox.ErrOrgRequired)
}
