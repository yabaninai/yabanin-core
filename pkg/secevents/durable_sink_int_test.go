package secevents

// AUD-EVENT-01 acceptance tests (owner audit 2026-11-02): the durable sink
// contract — persist-then-error and retry paths must neither lose nor
// duplicate an event, and two concurrent ingesters plus a process restart
// must converge to EXACTLY ONE durable JSON document per (org, event_id).
//
// Baseline evidence: with an append-only sink the in-memory Ingester dedup
// loses the redelivery race across instances/restarts (2 durable copies;
// artifacts/imp/audit-event/RED-baseline-evidence.log). These tests pin the
// fix: the exactly-once decision lives in the database (INSERT ... ON
// CONFLICT DO NOTHING), not in any single process.
//
// Deterministic: fixed anchors (anchorOcc), per-run org/event tokens so
// runs coexist on a shared stand, no sleeps, real PG via the testdb stand
// (Docker required; skips under -short like every Docker-backed helper).

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// aud01Sink provisions a DurableSink over the stand with its schema in
// place, scoped by a per-run token so concurrent suites never collide.
func aud01Sink(t *testing.T) (*pgxpool.Pool, *DurableSink, string) {
	t.Helper()
	pool := testdb.Postgres(t)
	sink := NewDurableSink(pool)
	require.NoError(t, sink.EnsureSchema(context.Background()))
	token := fmt.Sprintf("aud01%x", time.Now().UnixNano())
	return pool, sink, token
}

// aud01Docs returns the durable documents stored for one (org, event_id).
func aud01Docs(t *testing.T, pool *pgxpool.Pool, org, eventID string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT document::text FROM secevents_documents WHERE org_id=$1 AND event_id=$2 ORDER BY recorded_at`,
		org, eventID)
	require.NoError(t, err)
	defer rows.Close()
	var docs []string
	for rows.Next() {
		var d string
		require.NoError(t, rows.Scan(&d))
		docs = append(docs, d)
	}
	require.NoError(t, rows.Err())
	return docs
}

// The lost-ack retry path: a successful record followed by the very same
// record again (the client never learned the first write succeeded) must
// converge to exactly one durable document, reported as already-present —
// never as a second row and never as an error.
func TestDurableSinkLostAckRetryConvergesExactlyOnce(t *testing.T) {
	pool, sink, token := aud01Sink(t)
	ctx := context.Background()

	e := validEvent()
	e.EventID = token + "-evt"

	status, err := sink.RecordContext(ctx, e)
	require.NoError(t, err)
	require.Equal(t, DurableInserted, status)

	// Persist-then-error: the write committed, the caller saw an error
	// (connection lost), the delivery loop retries the identical event.
	status, err = sink.RecordContext(ctx, e)
	require.NoError(t, err, "an already-durable redelivery is success, not a stall")
	require.Equal(t, DurableAlreadyPresent, status)

	docs := aud01Docs(t, pool, e.OrgID, e.EventID)
	require.Len(t, docs, 1, "exactly one durable JSON document")
	require.JSONEq(t, string(mustEncode(t, e)), docs[0], "document is the canonical wire form")
}

// The restart path: the ingester instance that recorded the event dies
// (its in-memory dedup state is lost) and a fresh instance receives the
// redelivery. The durable store must keep exactly one document.
func TestDurableSinkRestartRedeliveryKeepsOneDocument(t *testing.T) {
	pool, sink, token := aud01Sink(t)

	ingA := NewIngester(sink) // process A
	e := validEvent()
	e.EventID = token + "-evt"
	// Normalize exactly like a producer must: Ingest normalizes its own
	// copy, so the local event and the stored document must agree.
	require.NoError(t, e.Validate())

	_, err := ingA.Ingest(e, anchorOcc)
	require.NoError(t, err)

	ingB := NewIngester(sink) // process B: restarted instance, empty dedup state
	res, err := ingB.Ingest(e, anchorOcc.Add(500*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, OutcomeRecorded, res.Outcome, "B's local view is fresh; the store carries the invariant")

	docs := aud01Docs(t, pool, e.OrgID, e.EventID)
	require.Len(t, docs, 1, "restart redelivery must not duplicate the durable document")
	require.JSONEq(t, string(mustEncode(t, e)), docs[0])
}

// The full acceptance race (AUD-EVENT-01 AC verbatim): two concurrent
// ingester instances deliver the same redelivered event set at the same
// time, then a fresh (restarted) third instance replays the whole set.
// Exactly N documents must survive, each byte-faithful to its event.
func TestDurableSinkDualInstancesAndRestartConverge(t *testing.T) {
	pool, sink, token := aud01Sink(t)

	const n = 6
	events := make([]Event, n)
	for i := range events {
		events[i] = validEvent()
		events[i].EventID = fmt.Sprintf("%s-evt-%02d", token, i)
		// Producer-side normalization (see the restart test).
		require.NoError(t, events[i].Validate())
	}

	// Two concurrent ingester instances (two processes) race on the same
	// deliveries, each event delivered to both at once.
	instances := []*Ingester{NewIngester(sink), NewIngester(sink)}
	var wg sync.WaitGroup
	errs := make([]error, 2*n)
	for k, ing := range instances {
		for i, e := range events {
			wg.Add(1)
			go func(k, i int, e Event) {
				defer wg.Done()
				_, err := ing.Ingest(e, anchorOcc)
				errs[k*n+i] = err
			}(k, i, e)
		}
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}

	// A restarted third instance replays the whole set (DLQ replay
	// posture): every delivery again lands, none may duplicate.
	ingC := NewIngester(sink)
	for i, e := range events {
		_, err := ingC.Ingest(e, anchorOcc.Add(time.Duration(i)*time.Millisecond))
		require.NoError(t, err)
	}

	for _, e := range events {
		docs := aud01Docs(t, pool, e.OrgID, e.EventID)
		require.Len(t, docs, 1, "event %s: exactly one durable document after dual-instance delivery + restart replay", e.EventID)
		require.JSONEq(t, string(mustEncode(t, e)), docs[0])
	}
}

// A storage failure must not record the event as seen: the retry then
// records exactly once. Pinned on the Ingester side with a fail-once sink
// wrapper; the durable side is covered by the lost-ack test above.
func TestDurableSinkStorageFailureStaysUnseenUntilRetry(t *testing.T) {
	pool, sink, token := aud01Sink(t)

	boom := errors.New("storage unavailable")
	var failOnce int32 = 1
	flap := SinkFunc(func(e Event) error {
		if swap := failOnce; swap == 1 {
			failOnce = 0
			return boom
		}
		return sink.Record(e)
	})

	ing := NewIngester(flap)
	e := validEvent()
	e.EventID = token + "-evt"
	require.NoError(t, e.Validate()) // producer-side normalization (see the restart test)

	_, err := ing.Ingest(e, anchorOcc)
	require.ErrorIs(t, err, boom, "the storage failure surfaces")
	require.False(t, ing.Recorded(e), "a failed record must not mark the event seen")

	// Delivery loop retries into the recovered storage.
	res, err := ing.Ingest(e, anchorOcc.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, OutcomeRecorded, res.Outcome)
	require.True(t, ing.Recorded(e))

	docs := aud01Docs(t, pool, e.OrgID, e.EventID)
	require.Len(t, docs, 1, "retry after failure records exactly once")
}

// Direct-sink guard: the store is keyed by (org_id, event_id); a caller
// bypassing Ingest must not be able to write null-key rows.
func TestDurableSinkRejectsUnkeyedEvent(t *testing.T) {
	_, sink, _ := aud01Sink(t)
	e := validEvent()
	e.EventID = ""
	_, err := sink.RecordContext(context.Background(), e)
	require.Error(t, err)
}

// E01-P03 acceptance invariant (E01.md:63) at the DURABLE layer: a
// redelivery delivered with a skewed clock (late AND
// future-dated producer timestamps) must leave the stored producer time
// verbatim — never rebased to delivery time, never clamped — and an
// unknown cost must survive into the durable document as {unknown, 0},
// distinguishable from a known zero. recorded_at is delivery bookkeeping
// only; skew semantics live with the producer timestamp.
func TestDurableSinkSkewVerbatimAndUnknownCost(t *testing.T) {
	pool, sink, token := aud01Sink(t)

	late := validEvent()
	late.EventID = token + "-late"
	require.NoError(t, late.Validate()) // producer-side normalization

	ingA := NewIngester(sink)
	_, err := ingA.Ingest(late, anchorOcc)
	require.NoError(t, err)

	// Fresh instance redelivers 90s LATE (delivery clock behind producer).
	ingB := NewIngester(sink)
	res, err := ingB.Ingest(late, anchorOcc.Add(90*time.Second))
	require.NoError(t, err)
	require.Equal(t, OutcomeRecorded, res.Outcome)

	var storedLate time.Time
	var docOccurredAt string
	err = pool.QueryRow(context.Background(),
		`SELECT occurred_at, document->>'occurred_at' FROM secevents_documents WHERE org_id=$1 AND event_id=$2`,
		late.OrgID, late.EventID).Scan(&storedLate, &docOccurredAt)
	require.NoError(t, err)
	require.True(t, storedLate.Equal(anchorOcc),
		"late delivery must not rebase the producer timestamp: got %v want %v", storedLate, anchorOcc)
	require.Equal(t, anchorOcc.Format(time.RFC3339), docOccurredAt,
		"document carries the producer timestamp verbatim")

	// Future-dated producer time delivered now: stored verbatim, no clamp
	// to the receiver's clock.
	future := validEvent()
	future.EventID = token + "-future"
	future.OccurredAt = anchorOcc.Add(5 * time.Minute)
	require.NoError(t, future.Validate())
	_, err = ingB.Ingest(future, anchorOcc)
	require.NoError(t, err)
	var storedFuture time.Time
	err = pool.QueryRow(context.Background(),
		`SELECT occurred_at FROM secevents_documents WHERE org_id=$1 AND event_id=$2`,
		future.OrgID, future.EventID).Scan(&storedFuture)
	require.NoError(t, err)
	require.True(t, storedFuture.Equal(anchorOcc.Add(5*time.Minute)),
		"future-dated producer time must not be clamped: got %v", storedFuture)

	// Unknown cost stays unknown in the durable document — the state
	// string is the distinguisher from a known zero; it must not be coerced
	// into success/zero by any layer of the durable path. Wire contract:
	// micro_usd is omitempty, so an unknown/0 cost carries NO micro_usd key
	// (absent or literal 0 both satisfy "never a known nonzero").
	var costState string
	var costMicroRaw *string
	err = pool.QueryRow(context.Background(),
		`SELECT document->'cost'->>'state', document->'cost'->>'micro_usd'
		 FROM secevents_documents WHERE org_id=$1 AND event_id=$2`,
		late.OrgID, late.EventID).Scan(&costState, &costMicroRaw)
	require.NoError(t, err)
	require.Equal(t, "unknown", costState, "unknown cost must stay unknown in the durable document")
	if costMicroRaw != nil {
		require.Equal(t, "0", *costMicroRaw, "unknown cost must never carry a non-zero micro_usd")
	}
}

// The production home of the store DDL is migration 0021; EnsureSchema
// carries the same shape for SPI/test stands. This always-on pin (no DB
// needed) fails loudly if the two homes drift — including when a later
// migration ALTERs the table without updating durableSchemaSQL to the full
// current shape.
func TestMigration0021MirrorsDurableSchema(t *testing.T) {
	root := os.DirFS("../../migrations") // canonical root set; same resolution as pkg/migrate's sync test
	up, err := fs.ReadFile(root, "0021_secevents_documents.up.sql")
	require.NoError(t, err, "migrations/0021_secevents_documents.up.sql must exist next to the durable DDL home")
	require.Equal(t, normalizeDDL(durableSchemaSQL), normalizeDDL(string(up)),
		"migration 0021 and durableSchemaSQL must define the identical table (mirror contract, durable.go wiring note)")
}

// normalizeDDL strips comments/blank lines and whitespace so two "same
// shape" DDL texts compare equal regardless of formatting; IF NOT EXISTS
// (the intentional EnsureSchema-only difference) is normalized away.
func normalizeDDL(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		b.WriteString(t)
		b.WriteByte(' ')
	}
	out := strings.ReplaceAll(b.String(), "CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ")
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(out), ";"))
}
