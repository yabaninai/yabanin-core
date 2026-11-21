//go:build integration

package accounting

import (
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestAccountingFactsRecoveryWithoutLiveEvent: FACTS-RECOVERY semantics.
// Simply stopping loggerd while Redis retains the published event proves
// NOTHING about facts recovery (the restart just consumes the queued live
// event). This case removes the target's queued notification from the
// isolated per-run event stream BEFORE the consumer restart — after
// proving no live retry carrier (retry/dead-letter/parking stream or
// pending group entry) holds a copy — so the ONLY durable evidence is
// request_terminal_facts. Required outcome: materialization +
// reconciliation with resolve_reason SPECIFICALLY 'recovered_from_facts',
// exactly one signed wallet debit, the exact per-kind intent set with the
// wallet kind present, unchanged provider ledger. THEN the original live
// event is replayed (late delivery of a lost-then-found event): each
// replay is proven claimed via its committed event_inbox row, the group is
// drained, no copy is parked, and no duplicate row, charge, or intent
// appears.
//
// Admission-ACK loss vs lost event: the "DB commit acknowledged but the
// gateway sees an error" variant (facts/admission commit succeeded, the
// publish itself errored back to the gateway) is covered by the separate
// admission-ack case in admission_ack_test.go, which injects it
// black-box via a gateway-only loopback DB relay with a DB advisory-lock
// barrier — no product fault hooks. That case merges as an independent
// leaf; the XDEL-after-publish construction here covers the complementary
// boundary: facts committed, live event gone.
func TestAccountingFactsRecoveryWithoutLiveEvent(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "facts-pre")

	rid := s.reqPrefix + "tgt-facts"
	rdb := s.redisClient(t)

	// Consumer DOWN before the target: the notification queues in Redis.
	s.stopLoggerd()
	defer func() {
		if s.loggerdCmd == nil {
			s.restartLoggerd()
		}
	}()

	s.serveWhileConsumerDown(t, rid)
	s.requireTerminalFactsWhileConsumerDown(t, rid)
	entries := s.removeUndeliveredFactsNotification(t, rdb, rid)
	s.ageAdmissionPastGrace(t, rid, s.oracleDB.orgID)
	s.restartLoggerd()
	s.waitForRecoveredBilling(t, rid, 6*time.Minute)
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "facts recovery")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "facts recovery")
	wantKinds := s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "facts recovery")
	s.requireReconciledFromFacts(t, rid)
	s.replayAfterFactsRecovery(t, rdb, rid, entries, wantKinds)
	s.controlRequest(t, "facts-post")
}

func (s *stand) removeUndeliveredFactsNotification(t *testing.T, rdb *redis.Client, rid string) []streamEntry {
	t.Helper()
	// The queued notification exists; capture its exact field map, then
	// REMOVE it so no live copy survives.
	entries := s.findStreamEntries(t, rdb, rid)
	if len(entries) == 0 {
		t.Fatalf("facts: expected queued event entries for %s in %s while consumer is down", rid, s.eventStream)
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	s.deleteStreamEntriesFor(t, rdb, rid, ids)
	// No live retry carrier anywhere in Redis.
	s.assertNoRetryCarrier(t, rdb, rid)
	// And nothing pending-unacked in the main stream's group that a restart
	// would redeliver as "live".
	cursor, ok := s.groupDeliveryCursor(t, rdb)
	if !ok {
		t.Fatal("facts: missing consumer group after the healthy control")
	}
	for _, id := range ids {
		if !entryIDAfter(id, cursor) {
			t.Fatalf("facts: stream entry %s for %s reached delivery cursor %s before deletion", id, rid, cursor)
		}
	}
	return entries
}

func (s *stand) waitForRecoveredBilling(t *testing.T, rid string, timeout time.Duration) {
	t.Helper()
	// The wallet debit lands on the settlement worker's tick (AF-06: the
	// sweep only writes settlement_jobs intents; the worker debits
	// credit_transactions asynchronously), so the poll must cover both
	// boundaries before the immediate exactly-once assertions below —
	// the same shape as the settlement-fault, client-retry and
	// event-redelivery cases.
	pollUntil(t, timeout, "request log and wallet debit materialize after restart", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row yet")
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows == 0 {
			return fmt.Errorf("no wallet usage row yet")
		}
		return nil
	})
}

func (s *stand) requireReconciledFromFacts(t *testing.T, rid string) {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("facts: admissions table absent — reconciliation reason unverifiable")
	}
	pollUntil(t, 6*time.Minute, "admission reconciles via recovered_from_facts", func() error {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		if len(rows) != 1 {
			return fmt.Errorf("admissions = %d (%s), want 1", len(rows), fmtAdmissions(rows))
		}
		a := rows[0]
		requireAdmissionVocabulary(t, a)
		switch a.State {
		case "reconciled":
			if a.ResolveReason.String != reasonRecovered {
				return abortf("reconciled reason %q, want SPECIFICALLY %q (no live event existed — this is facts recovery)", a.ResolveReason.String, reasonRecovered)
			}
			return nil
		case "admitted":
			return fmt.Errorf("still admitted after facts-present sweep: %s", fmtAdmissions(rows))
		case "voided":
			return abortf("voided but facts exist: %s", fmtAdmissions(rows))
		case "unresolved":
			return fmt.Errorf("unresolved despite facts present (facts-present path must materialize regardless of grace): %s", fmtAdmissions(rows))
		}
		return nil
	})

	// Provider ledger unchanged by recovery.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("facts: provider ledger after recovery = %d/%d/%d, want 1/1/1", arr, disp, recv)
	}

}

func (s *stand) replayAfterFactsRecovery(t *testing.T, rdb *redis.Client, rid string, entries []streamEntry, wantKinds map[string]int) {
	t.Helper()
	// LATE LIVE REPLAY: the original event finally arrives
	// (lost-then-found). Each replay must be claimed (committed
	// event_inbox row per fresh entry id) and the consumer must treat it
	// as a duplicate of the recovered state: no second row, charge, or
	// intent; the admission stays as recovered; nothing parked or pending.
	var replayIDs []string
	for _, e := range entries {
		fresh := s.replayEntryUnderFreshID(t, rdb, e)
		replayIDs = append(replayIDs, fresh)
		t.Logf("facts: late live replay under fresh entry id %s", fresh)
	}
	s.requireInboxClaimsCommitted(t, rdb, replayIDs)
	time.Sleep(5 * time.Second) // let any duplicate processing fail loudly if broken
	s.requireGroupDrained(t, rdb)
	s.assertNoRetryCarrier(t, rdb, rid)

	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "after late live replay")
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "after late live replay")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "after late live replay")
	s.requireSettlementIntents(t, rid, s.oracleDB.orgID, "after late live replay", wantKinds)
	if rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID); len(rows) != 1 || rows[0].State != "reconciled" || rows[0].ResolveReason.String != reasonRecovered {
		t.Fatalf("facts: admission changed after late live replay: %s (want reconciled/%s)", fmtAdmissions(rows), reasonRecovered)
	}
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("facts: provider ledger after late live replay = %d/%d/%d, want 1/1/1", arr, disp, recv)
	}

}
