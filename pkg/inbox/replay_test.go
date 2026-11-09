package inbox

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// E06-P01 W02-C02 — package acceptance: replay never duplicates incidents.
//
// The guards are layered exactly as the dispatch demands:
//   - durable layer: same (org_id, event_id) again → ON CONFLICT DO NOTHING
//     (DurableAlreadyPresent) — the duplicate never becomes a document;
//   - projection: every event that DOES arrive folds by group_key —
//     counts++ / last_seen forward, never a second row (unique index +
//     ON CONFLICT);
//   - delayed delivery: an event that arrives late (earlier occurred_at
//     than what is already folded) collapses into the SAME incident with
//     LEAST/GREATEST bounds, whatever the delivery order.
//
// The determinism precedent is secevents.derivedEventID (adapter.go): a
// finding redelivered derives the SAME event id, so the durable anchor does
// not even see it twice. Fold-order independence below pins the same law on
// the inbox side.
//
// Deterministic: fixed anchor timestamps, per-run org rows (siFixture), no
// sleeps; the concurrent arm joins its goroutines, it does not race them
// against the clock.

// mustListOne lists the org's incidents and requires exactly one row.
func mustListOne(t *testing.T, store *Store, org uuid.UUID) Incident {
	t.Helper()
	incs, err := store.List(context.Background(), org)
	require.NoError(t, err)
	require.Len(t, incs, 1)
	return incs[0]
}

func TestReplaySameEventDoesNotDuplicate(t *testing.T) {
	su, app, org, _ := siFixture(t)
	ctx := WithOrg(context.Background(), org.String())
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	token := fmt.Sprintf("replay1%x", time.Now().UnixNano())

	sink := secevents.NewDurableSink(su)
	first, err := sink.RecordContext(ctx, siEvent(org.String(), token+"-evt1", "tool deny", base))
	require.NoError(t, err)
	require.Equal(t, secevents.DurableInserted, first, "first delivery inserts")

	// Redelivery of the SAME event id: the durable anchor refuses it
	// (ON CONFLICT DO NOTHING) — the projection never sees it again.
	second, err := sink.RecordContext(ctx, siEvent(org.String(), token+"-evt1", "tool deny", base))
	require.NoError(t, err)
	require.Equal(t, secevents.DurableAlreadyPresent, second, "redelivery is a no-op at the durable layer")

	store := NewStore(app)
	require.NoError(t, ProjectReader(ctx, store, org, NewReader(app)))
	inc := mustListOne(t, store, org)
	assert.Equal(t, int64(1), inc.EventCount, "exactly one fold of one delivered event")
	assert.Equal(t, token+"-evt1", inc.LastEventID)

	// The card's acceptance: a replayed finding NEVER becomes a second
	// incident. Re-fold after the duplicate delivery attempts: the reader
	// still returns exactly one document (the durable anchor refused the
	// twin at INSERT), so the fold merges into the SAME row.
	//
	// event_count advances once per fold pass — the documented W01-C02
	// upsert semantics ("a replayed or late event advances counts and
	// last_seen and nothing else"): counts measure fold observations, a
	// rebuild re-derives them by folding a wiped table. The invariant that
	// matters to operators — ONE incident per finding — holds on every
	// pass, pinned here.
	require.NoError(t, ProjectReader(ctx, store, org, NewReader(app)))
	inc = mustListOne(t, store, org)
	assert.Equal(t, int64(2), inc.EventCount, "documented re-count per pass; row identity is the invariant")
	assert.Equal(t, token+"-evt1", inc.LastEventID, "no new event arrived — bounds do not move")
}

func TestReplayNewEventOfSameFindingFolds(t *testing.T) {
	su, app, org, _ := siFixture(t)
	ctx := WithOrg(context.Background(), org.String())
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	later := base.Add(3 * time.Minute)
	token := fmt.Sprintf("replay2%x", time.Now().UnixNano())

	sink := secevents.NewDurableSink(su)
	for i, id := range []string{token + "-evt1", token + "-evt2"} {
		occ := base
		if i == 1 {
			occ = later
		}
		st, err := sink.RecordContext(ctx, siEvent(org.String(), id, fmt.Sprintf("tool deny %d", i), occ))
		require.NoError(t, err)
		require.Equal(t, secevents.DurableInserted, st)
	}

	store := NewStore(app)
	require.NoError(t, ProjectReader(ctx, store, org, NewReader(app)))
	inc := mustListOne(t, store, org)
	assert.Equal(t, int64(2), inc.EventCount, "two events of one finding fold into one counted incident")
	assert.Equal(t, token+"-evt1", inc.FirstEventID)
	assert.Equal(t, token+"-evt2", inc.LastEventID)
	assert.True(t, inc.FirstSeen.Equal(base))
	assert.True(t, inc.LastSeen.Equal(later))
}

func TestReplayDelayedOutOfOrderDeliveryFoldsIdentically(t *testing.T) {
	// The same finding delivered in DIFFERENT orders must reach the SAME
	// incident state. Two orgs carry the two orders; the end states are
	// compared field by field.
	su, app, orgA, orgB := siFixture(t)
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	later := base.Add(10 * time.Minute)
	token := fmt.Sprintf("replay3%x", time.Now().UnixNano())
	type delivery struct {
		id  string
		occ time.Time
	}

	fold := func(org uuid.UUID, order []delivery) {
		t.Helper()
		ctx := WithOrg(context.Background(), org.String())
		sink := secevents.NewDurableSink(su)
		for _, ev := range order {
			_, err := sink.RecordContext(ctx, siEvent(org.String(), ev.id, "tool deny "+ev.id, ev.occ))
			require.NoError(t, err)
		}
		require.NoError(t, ProjectReader(ctx, NewStore(app), org, NewReader(app)))
	}

	fold(orgA, []delivery{{token + "-early", base}, {token + "-late", later}})
	fold(orgB, []delivery{{token + "-late", later}, {token + "-early", base}})

	incA := mustListOne(t, NewStore(app), orgA)
	incB := mustListOne(t, NewStore(app), orgB)
	assert.Equal(t, incA.GroupKey, incB.GroupKey, "delivery order must not change the finding identity")
	assert.Equal(t, incA.FirstEventID, incB.FirstEventID)
	assert.Equal(t, incA.LastEventID, incB.LastEventID)
	assert.Equal(t, incA.FirstSeen, incB.FirstSeen)
	assert.Equal(t, incA.LastSeen, incB.LastSeen)
	assert.Equal(t, incA.EventCount, incB.EventCount)
	assert.Equal(t, token+"-early", incA.FirstEventID, "LEAST bounds survive late arrival")
	assert.Equal(t, token+"-late", incA.LastEventID)
}

func TestReplayConcurrentUpsertsKeepOneRow(t *testing.T) {
	// Concurrent projection upserts of the same finding: the unique index
	// (org_id, group_key) + ON CONFLICT DO UPDATE serialize the writers —
	// exactly one row survives and every winning upsert is counted once.
	_, app, org, _ := siFixture(t)
	ctx := WithOrg(context.Background(), org.String())
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	store := NewStore(app)

	const writers = 8
	key, err := GroupKey(siEvent(org.String(), "x", "", base))
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			draft := IncidentDraft{
				GroupKey:   key,
				Summary:    fmt.Sprintf("concurrent fold %d", i),
				Severity:   provisionalSeverity,
				Confidence: provisionalConfidence,
				OccurredAt: base.Add(time.Duration(i) * time.Minute),
				EventID:    fmt.Sprintf("evt-conc-%d", i),
			}
			if _, err := store.Upsert(ctx, org, draft); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "concurrent upsert must not fail")
	}

	inc := mustListOne(t, store, org)
	assert.Equal(t, int64(writers), inc.EventCount, "every serialized upsert counts exactly once")
	require.NoError(t, inc.Validate())
	assert.False(t, inc.FirstSeen.After(inc.LastSeen), "LEAST/GREATEST bounds hold under concurrency")
}
