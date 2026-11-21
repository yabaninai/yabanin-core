//go:build integration

package accounting

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAccountingRedisEventRedeliveryIdempotent: EVENT REDELIVERY semantics
// at the Redis boundary (no second HTTP call, no gateway involvement after
// the original completion). The ORIGINAL committed event's exact field map
// is XADDed under FRESH entry IDs twice. Proof obligations:
//
//  1. the original invocation succeeded for the client (status and body)
//     and its accounting fully materialized (billed row, wallet debit,
//     wallet intent present — the non-vacuity anchor);
//  2. the replayed entry IDs are distinct from each other and from the
//     original entry's ID (XRANGE/XADD evidence);
//  3. the consumer actually claimed each replay: a committed event_inbox
//     row per fresh entry id with the stand's stream as source and the
//     observed consumer group as consumer — fresh ids are never
//     inbox-deduped, so this is durable processing evidence, unlike a
//     delivery cursor which only proves the group saw an entry;
//  4. nothing is parked or lost: the consumer group's pending list is
//     empty and no retry/dead-letter/parking stream carries a copy;
//  5. idempotence: still exactly ONE billed request_logs row, ONE signed
//     wallet usage debit (-32 micro-USD), the EXACT per-kind settlement
//     intent set the original produced (not a possibly-vacuous "unchanged
//     total"), one admission still 'reconciled'/'event_delivered', and an
//     UNCHANGED provider ledger (1/1/1 — no re-dispatch).
func TestAccountingRedisEventRedeliveryIdempotent(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "replay-pre")

	rid := s.reqPrefix + "tgt-replay"
	before := s.fixture.Snapshot()

	// Original committed invocation: the client must have succeeded.
	status, body, err := s.chat(t, rid, 30*time.Second)
	if err != nil || status != httpOK {
		t.Fatalf("replay: original client invocation failed (status=%d err=%v body=%s)", status, err, body)
	}
	if !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("replay: original client body %q does not contain the assistant content", body)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		t.Fatalf("replay: original ledger delta = %d/%d/%d, want 1/1/1", delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Wait until the original event is fully consumed (billed + charged).
	pollUntil(t, 3*time.Minute, "original event consumed", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row yet")
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows == 0 {
			return fmt.Errorf("no wallet usage row yet")
		}
		return nil
	})
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "replay original")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "replay original")
	// Non-vacuity anchor: the wallet intent kind the consumer always plans
	// for a positive quote must exist exactly once. Any additional scoped
	// kinds the event's attribution produces are captured and must survive
	// the replays unchanged.
	wantKinds := s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "replay original")
	t.Logf("replay: original settlement intent set: %v", wantKinds)

	rdb := s.redisClient(t)

	// Locate the original committed event entries for the target.
	entries := s.findStreamEntries(t, rdb, rid)
	if len(entries) == 0 {
		t.Fatalf("replay: no event entries found in %s for %s (consumer may have trimmed the stream — pre-condition unmet)", s.eventStream, rid)
	}
	originalIDs := make([]string, 0, len(entries))
	for _, e := range entries {
		originalIDs = append(originalIDs, e.ID)
	}
	t.Logf("replay: original event entries for %s: %v", rid, originalIDs)

	// Replay each original entry twice under fresh Redis-minted IDs.
	var replayIDs []string
	for _, e := range entries {
		id1 := s.replayEntryUnderFreshID(t, rdb, e)
		id2 := s.replayEntryUnderFreshID(t, rdb, e)
		for _, orig := range originalIDs {
			if id1 == orig || id2 == orig || id1 == id2 {
				t.Fatalf("replay: fresh IDs not distinct (orig=%s id1=%s id2=%s)", orig, id1, id2)
			}
		}
		replayIDs = append(replayIDs, id1, id2)
	}
	t.Logf("replay: replayed under fresh entry IDs: %v", replayIDs)

	// Processing proof per replay: a committed event_inbox claim row for
	// every fresh entry id (correct stream source and consumer group),
	// then a fully drained group and no parked copies anywhere.
	s.requireInboxClaimsCommitted(t, rdb, replayIDs)
	time.Sleep(5 * time.Second) // let any duplicate processing finish loudly if broken
	s.requireGroupDrained(t, rdb)
	s.assertNoRetryCarrier(t, rdb, rid)

	// Idempotence: the exact intent set the original produced, still.
	s.requireSettlementIntents(t, rid, s.oracleDB.orgID, "replay after", wantKinds)
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "replay after")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "replay after")
	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "replay after")
	if adms := s.oracleAdmissions(t, rid, s.oracleDB.orgID); len(adms) > 1 {
		t.Fatalf("replay: admissions = %d (%s), want the single original", len(adms), fmtAdmissions(adms))
	} else if len(adms) == 1 {
		a := adms[0]
		requireAdmissionVocabulary(t, a)
		if a.State != "reconciled" || a.ResolveReason.String != reasonEventLive {
			t.Fatalf("replay: admission changed to %s (want reconciled/%s)", fmtAdmissions(adms), reasonEventLive)
		}
	}

	// Provider ledger unchanged: redelivery is a pure consumer-side event.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("replay: provider ledger arr/disp/recv = %d/%d/%d, want 1/1/1 (unchanged)", arr, disp, recv)
	}

	s.controlRequest(t, "replay-post")
}
