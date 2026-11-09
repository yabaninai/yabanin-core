package inbox

// E06-P01 W01-C01 (Trigger ②): acceptance tests for the first production
// reader of secevents_documents — landing in the same change as migration
// 0026 (RLS org_isolation) and the writer GUC pin (pkg/secevents, a
// same-transaction set_config — the CTE pin form was rejected in
// E01-P04 W04-readpath-decision.md §5.2).
//
// Two layers:
//   - unit (always on, no Docker): the derivation law — a missing or EMPTY
//     org binding is refused with ErrOrgRequired BEFORE any statement is
//     issued (the fail-if-called DB proves the no-query half), and the SQL
//     contracts (tx-local pin, explicit predicate, total order);
//   - battery (Docker, real stand): the reader against the REAL migration
//     0026 policy on public.secevents_documents under the real yabanin_app
//     role — exactly-own-org reads, cross-org invisibility, tx-locality of
//     the pin, and the org-homes agreement guard (the W04-C02 REAL pin,
//     now enforced by the production reader).
//
// Deterministic: fixed anchor timestamps, per-run org tokens so concurrent
// suites coexist on the shared stand, no sleeps.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/secevents"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// refusingDB fails the test if ANY of its methods is called: the refusal
// arms must be decided at the Go boundary, before a statement is issued.
type refusingDB struct {
	t     *testing.T
	calls atomic.Int32
}

func (d *refusingDB) touch(what string) {
	d.calls.Add(1)
	d.t.Fatalf("%s must not be called before the org is validated", what)
}

func (d *refusingDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	d.touch("Exec")
	var zero pgconn.CommandTag
	return zero, nil // unreachable after Fatalf
}

func (d *refusingDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	d.touch("Query")
	panic("unreachable: touch fails the test")
}

func (d *refusingDB) Begin(context.Context) (pgx.Tx, error) {
	d.touch("Begin")
	panic("unreachable: touch fails the test")
}

func TestReaderRefusesMissingOrgContext(t *testing.T) {
	db := &refusingDB{t: t}
	_, err := NewReader(db).Events(context.Background())
	require.ErrorIs(t, err, ErrOrgRequired)
	assert.Zero(t, db.calls.Load(), "no statement may be issued for an unbound org")
}

// The W05-C02 sharpened law: an empty org is not a valid "no scope" and
// must be refused exactly like a missing one — the policy layer alone does
// not enforce this (an empty GUC must not degrade into a wildcard read).
func TestReaderRefusesEmptyOrgContext(t *testing.T) {
	db := &refusingDB{t: t}
	_, err := NewReader(db).Events(WithOrg(context.Background(), ""))
	require.ErrorIs(t, err, ErrOrgRequired)
	assert.Zero(t, db.calls.Load(), "no statement may be issued for an empty org")
}

func TestReaderSQLContracts(t *testing.T) {
	assert.Contains(t, readerPinSQL, "set_config('app.current_org', $1, true)",
		"the pin must be transaction-local (is_local=true, the withOrgTx semantics)")
	assert.Contains(t, readerSelectSQL, "WHERE org_id = $1",
		"explicit org predicate: defense-in-depth on top of the org_isolation policy")
	assert.Contains(t, readerSelectSQL, "ORDER BY occurred_at, event_id",
		"deterministic total order under timestamp ties")
}

// riEvent builds a valid event (the schema_test.go validEvent shape) for an
// arbitrary org/id/time, settable through the exported surface only.
func riEvent(org, id string, occ time.Time) secevents.Event {
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

// riFixture seeds the REAL public table (migration 0021 schema, migration
// 0026 policy, applied by the stand bootstrap) with two events for orgA and
// one for orgB, written through the superuser sink (migration posture,
// bypasses RLS by design). Org tokens are unique per run, so concurrent
// runs coexist and the exactly-own-org assertions never see foreign rows.
func riFixture(t *testing.T) (app *pgxpool.Pool, orgA, orgB string, idsA []string, idB string) {
	t.Helper()
	su := testdb.Postgres(t)
	app = testdb.PostgresApp(t, "test")
	token := fmt.Sprintf("rie06%x", time.Now().UnixNano())
	orgA, orgB = token+"a", token+"b"
	sink := secevents.NewDurableSink(su)
	require.NoError(t, sink.EnsureSchema(context.Background()))
	// Anchor time; both A events share it so the (occurred_at, event_id)
	// total order must break the tie deterministically.
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	idsA = []string{token + "-evt1", token + "-evt2"}
	for _, id := range idsA {
		st, err := sink.RecordContext(ctx, riEvent(orgA, id, base))
		require.NoError(t, err)
		require.Equal(t, secevents.DurableInserted, st)
	}
	idB = token + "-evtb"
	st, err := sink.RecordContext(ctx, riEvent(orgB, idB, base))
	require.NoError(t, err)
	require.Equal(t, secevents.DurableInserted, st)
	return app, orgA, orgB, idsA, idB
}

func TestReaderEvents_BoundOrgSeesExactlyOwnEvents(t *testing.T) {
	app, orgA, orgB, idsA, idB := riFixture(t)
	r := NewReader(app)
	ctx := context.Background()

	evs, err := r.Events(WithOrg(ctx, orgA))
	require.NoError(t, err)
	require.Len(t, evs, len(idsA), "the bound org sees exactly its own events")
	assert.Equal(t, idsA[0], evs[0].EventID, "tie on occurred_at broken by event_id ASC")
	assert.Equal(t, idsA[1], evs[1].EventID)
	assert.Equal(t, orgA, evs[0].OrgID)
	assert.Equal(t, "tool.deny", evs[0].EventType)
	assert.Equal(t, secevents.SchemaVersion, evs[0].SchemaVersion)

	// Cross-org invisibility: orgB sees exactly its one event and none of
	// orgA's — the policy and the predicate agree.
	evsB, err := r.Events(WithOrg(ctx, orgB))
	require.NoError(t, err)
	require.Len(t, evsB, 1)
	assert.Equal(t, idB, evsB[0].EventID)
	assert.Equal(t, orgB, evsB[0].OrgID)
}

// The pin rides a committed transaction with is_local=true: nothing may
// survive Events() on the pooled app-role connections — the next unpinned
// statement sees the deny-all default, never orgA's rows and never the
// whole table.
func TestReaderEvents_TxLocalityOfPin(t *testing.T) {
	app, orgA, _, _, _ := riFixture(t)
	_, err := NewReader(app).Events(WithOrg(context.Background(), orgA))
	require.NoError(t, err)
	var seen int
	require.NoError(t, app.QueryRow(context.Background(),
		`SELECT count(*) FROM secevents_documents`).Scan(&seen))
	assert.Zero(t, seen, "the org pin must not leak past Events() onto pooled connections")
}

// Org-homes agreement (W04-C02 REAL pin, enforced by the production
// reader): a superuser row whose column org differs from the document's
// org is refused — the whole feed, never a partial serve, never a skip.
func TestReaderEvents_OrgHomesMismatchRefused(t *testing.T) {
	su := testdb.Postgres(t)
	app := testdb.PostgresApp(t, "test")
	token := fmt.Sprintf("riorg%x", time.Now().UnixNano())
	orgA, orgB := token+"a", token+"b"
	ctx := context.Background()

	e := riEvent(orgB, token+"-evt1", time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC))
	doc, err := e.Encode()
	require.NoError(t, err)
	_, err = su.Exec(ctx,
		`INSERT INTO secevents_documents
		   (org_id, event_id, schema_version, event_type, occurred_at, document)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		orgA, e.EventID, int(e.SchemaVersion), e.EventType, e.OccurredAt, doc)
	require.NoError(t, err)

	evs, err := NewReader(app).Events(WithOrg(ctx, orgA))
	require.Error(t, err, "a row whose homes disagree must fail the whole feed")
	assert.Nil(t, evs)
	assert.Contains(t, err.Error(), "org mismatch")
}
