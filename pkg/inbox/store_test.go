package inbox

// E06-P01 W01-C02: acceptance battery for the incident store and the
// reader→store projection against the REAL migration 0027 table
// (house-RLS org_isolation with the ::uuid GUC cast) on a real stand,
// under the real yabanin_app role — mirroring the W01-C01 battery shape
// for the inbox's own table:
//
//   - the full Trigger ② path: durable events → org-bound reader →
//     projection → incidents (one row per finding class, folded counts);
//   - fold invariants: out-of-order delivery, operator state preserved
//     across folds, replay merges (never a second incident);
//   - the RLS battery: cross-org write refused, unbound session sees
//     nothing, cross-org reads invisible, nil-org refused before any
//     statement;
//   - empty org: an inbox with no events is an empty list, not an error.
//
// Deterministic: fixed anchor timestamps, per-run org rows so concurrent
// suites coexist on the shared stand, no sleeps.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/secevents"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// QueryRow completes the reader battery's refusing fake for the InboxDB
// surface: the store's refusal arms must not issue any statement.
func (d *refusingDB) QueryRow(context.Context, string, ...any) pgx.Row {
	d.touch("QueryRow")
	panic("unreachable: touch fails the test")
}

// siEvent extends the reader battery's event builder with the fields the
// projection folds (summary, evidence).
func siEvent(org, id, summary string, occ time.Time, ev ...secevents.EvidenceRef) secevents.Event {
	e := riEvent(org, id, occ)
	e.Summary = summary
	e.Evidence = ev
	return e
}

func validDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// siFixture creates two real organizations and returns superuser and app
// pools. Org rows are per-run (unique slug), so concurrent suites never
// share an org.
func siFixture(t *testing.T) (su, app *pgxpool.Pool, orgA, orgB uuid.UUID) {
	t.Helper()
	su = testdb.Postgres(t)
	app = testdb.PostgresApp(t, "test")
	token := fmt.Sprintf("sie06%x", time.Now().UnixNano())
	ctx := context.Background()
	orgA = siInsertOrg(t, ctx, su, token+"-a")
	orgB = siInsertOrg(t, ctx, su, token+"-b")
	return su, app, orgA, orgB
}

func siInsertOrg(t *testing.T, ctx context.Context, su *pgxpool.Pool, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, su.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id`,
		"Inbox Org "+slug, slug).Scan(&id))
	return id
}

// The full Trigger ② path: events durably recorded (superuser sink, the
// only legal write path), read through the org-bound production reader
// under the app role, folded into exactly one incident per finding class.
func TestStoreProjectReaderFoldsIncidents(t *testing.T) {
	su, app, orgA, orgB := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06f%x", time.Now().UnixNano())

	sink := secevents.NewDurableSink(su)
	idsA := []string{token + "-evt1", token + "-evt2"}
	for _, id := range idsA {
		st, err := sink.RecordContext(ctx, siEvent(orgA.String(), id, "tool deny", base,
			secevents.EvidenceRef{Kind: secevents.EvidencePayloadDigest, Digest: validDigest(id)}))
		require.NoError(t, err)
		require.Equal(t, secevents.DurableInserted, st)
	}
	_, err := sink.RecordContext(ctx, siEvent(orgB.String(), token+"-evtb", "other org", base))
	require.NoError(t, err)

	store := NewStore(app)
	reader := NewReader(app)
	require.NoError(t, ProjectReader(WithOrg(ctx, orgA.String()), store, orgA, reader))

	incs, err := store.List(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, incs, 1, "two events of one finding class fold into ONE incident")
	inc := incs[0]
	assert.Equal(t, orgA, inc.OrgID)
	wantKey, err := GroupKey(siEvent(orgA.String(), "x", "", base))
	require.NoError(t, err)
	assert.Equal(t, wantKey, inc.GroupKey)
	assert.Equal(t, int64(2), inc.EventCount)
	assert.Equal(t, StatusNew, inc.Status)
	assert.Nil(t, inc.Assignee)
	assert.Equal(t, idsA[0], inc.FirstEventID, "reader order: tie on occurred_at broken by event_id ASC")
	assert.Equal(t, idsA[1], inc.LastEventID)
	assert.True(t, inc.FirstSeen.Equal(base) && inc.LastSeen.Equal(base))
	assert.Equal(t, "tool deny", inc.Summary, "summary tracks the greatest-occurred_at event")
	require.Len(t, inc.Evidence, 1)
	assert.Equal(t, validDigest(idsA[1]), inc.Evidence[0].Digest, "evidence tracks the greatest-occurred_at event")
	require.NoError(t, inc.Validate())

	// Detail read inside the org scope; the same incident id is invisible
	// under the other org's scope (predicate + policy agree).
	got, ok, err := store.Get(ctx, orgA, inc.ID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, inc.ID, got.ID)
	_, ok, err = store.Get(ctx, orgB, inc.ID)
	require.NoError(t, err)
	assert.False(t, ok, "an incident id from another org must not resolve")

	// The other org folds to its own single-incident inbox.
	require.NoError(t, ProjectReader(WithOrg(ctx, orgB.String()), store, orgB, reader))
	incsB, err := store.List(ctx, orgB)
	require.NoError(t, err)
	require.Len(t, incsB, 1)
	assert.Equal(t, int64(1), incsB[0].EventCount)
}

// Fold invariants: out-of-order delivery (late arrival of an earlier
// event), operator state surviving folds, and a replayed delivery merging
// into the same row — never a second incident.
func TestStoreUpsertFoldInvariants(t *testing.T) {
	su, app, orgA, _ := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06i%x", time.Now().UnixNano())
	store := NewStore(app)

	late := siEvent(orgA.String(), token+"-late", "late", base.Add(2*time.Hour))
	early := siEvent(orgA.String(), token+"-early", "early", base.Add(1*time.Hour))
	require.NoError(t, Project(ctx, store, orgA, []secevents.Event{late, early}),
		"out-of-order delivery must fold without error")

	incs, err := store.List(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, incs, 1)
	inc := incs[0]
	assert.Equal(t, int64(2), inc.EventCount)
	assert.Equal(t, token+"-early", inc.FirstEventID, "first_seen takes the LEAST regardless of fold order")
	assert.Equal(t, token+"-late", inc.LastEventID, "last_seen takes the GREATEST regardless of fold order")
	assert.Equal(t, "late", inc.Summary, "content fields track the greatest-occurred_at event")
	require.True(t, inc.FirstSeen.Before(inc.LastSeen))

	// Operator state: acknowledged + assigned (superuser stand-in for the
	// W04 write path). A later fold must not reset it.
	member := uuid.New()
	_, err = su.Exec(ctx,
		`UPDATE security_inbox SET status = $1, assignee = $2 WHERE org_id = $3`,
		StatusAcknowledged, member, orgA)
	require.NoError(t, err)

	newest := siEvent(orgA.String(), token+"-newest", "newest", base.Add(3*time.Hour))
	require.NoError(t, Project(ctx, store, orgA, []secevents.Event{newest}))

	incs, err = store.List(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, incs, 1, "a fold never creates a second incident")
	assert.Equal(t, int64(3), incs[0].EventCount)
	assert.Equal(t, StatusAcknowledged, incs[0].Status, "operator state survives projection folds")
	require.NotNil(t, incs[0].Assignee)
	assert.Equal(t, member, *incs[0].Assignee)
	assert.Equal(t, token+"-early", incs[0].FirstEventID, "the group's origin survives every fold")

	// Replay: re-delivering an already-folded event merges (counts
	// advance, still one row) — the durable layer guarantees the reader
	// never re-serves it; the projection contract is "same incident, no
	// duplicates" either way.
	require.NoError(t, Project(ctx, store, orgA, []secevents.Event{early}))
	incs, err = store.List(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, incs, 1, "replayed delivery merges into the same incident")
	assert.Equal(t, int64(4), incs[0].EventCount)
	assert.Equal(t, token+"-newest", incs[0].LastEventID, "a replayed older event never regresses last_seen")
}

// The RLS battery for the inbox's own table (house pattern with the
// ::uuid GUC cast): cross-org writes are policy-rejected, an unbound
// session sees nothing, cross-org reads come back empty, and the nil-org
// refusal is decided before any statement is issued.
func TestStoreRLSBatteryForInboxTable(t *testing.T) {
	su, app, orgA, orgB := siFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("sie06r%x", time.Now().UnixNano())
	store := NewStore(app)
	require.NoError(t, Project(ctx, store, orgA,
		[]secevents.Event{siEvent(orgA.String(), token+"-evt1", "s", base)}))

	t.Run("cross-org write is policy-rejected, never silent", func(t *testing.T) {
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `SELECT set_config('app.current_org', $1, true)`, orgA.String())
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `
			INSERT INTO security_inbox
			  (org_id, group_key, severity, confidence, first_seen, last_seen,
			   first_event_id, last_event_id)
			VALUES ($1, 'forged-key', 'high', 0.5, $2, $2, 'forged-evt', 'forged-evt')`,
			orgB, base)
		require.Error(t, err, "a row for another org must fail the WITH CHECK, not insert silently")
		assert.Contains(t, err.Error(), "row-level security")
	})

	t.Run("unbound session sees nothing (fail-closed)", func(t *testing.T) {
		var seen int
		require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM security_inbox`).Scan(&seen))
		assert.Zero(t, seen, "no pin → NULLIF('')::uuid → NULL → policy matches nothing")
	})

	t.Run("cross-org read is empty, not an error", func(t *testing.T) {
		incs, err := store.List(ctx, orgB)
		require.NoError(t, err)
		assert.Empty(t, incs, "orgB's inbox does not contain orgA incidents")
	})

	t.Run("nil org refused before any statement", func(t *testing.T) {
		refuse := &refusingDB{t: t}
		rs := NewStore(refuse)
		_, err := rs.Upsert(ctx, uuid.Nil, IncidentDraft{GroupKey: "k", Severity: SeverityLow, OccurredAt: base, EventID: "e"})
		require.ErrorIs(t, err, ErrStoreOrgRequired)
		_, err = rs.List(ctx, uuid.Nil)
		require.ErrorIs(t, err, ErrStoreOrgRequired)
		_, _, err = rs.Get(ctx, uuid.Nil, uuid.New())
		require.ErrorIs(t, err, ErrStoreOrgRequired)
		require.ErrorIs(t, Project(ctx, rs, uuid.Nil, nil), ErrStoreOrgRequired)
	})

	t.Run("invalid draft refused before any statement", func(t *testing.T) {
		rs := NewStore(&refusingDB{t: t})
		_, err := rs.Upsert(ctx, uuid.New(), IncidentDraft{
			GroupKey: "k", Severity: "ultra", Confidence: 1, OccurredAt: base, EventID: "e",
		})
		assert.ErrorIs(t, err, ErrInvalidIncident)
	})

	t.Run("the pin does not leak past store calls", func(t *testing.T) {
		incs, err := store.List(ctx, orgA)
		require.NoError(t, err)
		require.Len(t, incs, 1)
		var seen int
		require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM security_inbox`).Scan(&seen))
		assert.Zero(t, seen, "the next unpinned statement on the pool must see the deny-all default")
	})

	// Superuser stands keep GUC-less connections (the writer law's bypass
	// probe): a superuser fold leaves no session residue.
	var residue *string
	require.NoError(t, su.QueryRow(ctx, `SELECT current_setting('app.current_org', true)`).Scan(&residue))
	assert.Nil(t, residue, "superuser store operations must not leave a GUC session value")
}

// An org with no events has an empty inbox — an empty list, never an
// error (the W01-C03 "200 []" contract decided here).
func TestStoreEmptyOrgInboxIsEmpty(t *testing.T) {
	_, app, _, orgB := siFixture(t)
	incs, err := NewStore(app).List(context.Background(), orgB)
	require.NoError(t, err, "an org without events is not an error")
	require.NotNil(t, incs, "the empty inbox is an empty slice, not nil")
	assert.Empty(t, incs)
}

// The projection's org-homes law: an event whose TEXT org key is not the
// target org's uuid string is refused whole, before any store statement
// (proved by the fail-if-called DB).
func TestStoreProjectRefusesForeignOrgEvents(t *testing.T) {
	_, _, _, orgB := siFixture(t)
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	foreign := siEvent(uuid.New().String(), "foreign-evt", "s", base)
	err := Project(context.Background(), NewStore(&refusingDB{t: t}), orgB, []secevents.Event{foreign})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "homes law")
}
