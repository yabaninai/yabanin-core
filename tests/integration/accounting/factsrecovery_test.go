//go:build integration

package accounting

import (
	"fmt"
	"strings"
	"testing"
	"time"
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

	before := s.fixture.Snapshot()
	status, body, err := s.chat(t, rid, 60*time.Second)
	if err != nil || status != httpOK || !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("facts: target invocation status=%d body=%q err=%v — serving must not depend on the consumer", status, body, err)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		t.Fatalf("facts: ledger delta = %d/%d/%d, want 1/1/1", delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Durable terminal facts committed before publish (0028 design).
	if !s.oracleTableExists(t, "request_terminal_facts") {
		t.Fatalf("PRODUCT DEFECT (baseline): request_terminal_facts absent — no durable pre-publish terminal evidence to recover from")
	}
	if s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID) == 0 {
		t.Fatalf("facts: no terminal facts row for served %s while consumer down", rid)
	}

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
	if cursor, ok := s.groupDeliveryCursor(t, rdb); ok {
		for _, e := range entries {
			if entryIDAfter(cursor, e.ID) {
				t.Fatalf("facts: entry %s for %s was already delivered (cursor %s) — restart would redeliver it; precondition violated", e.ID, rid, cursor)
			}
		}
	}
	t.Logf("facts: live notification removed; only request_terminal_facts remains as evidence")

	// Deterministic sweep visit: age ONLY the target's still-open admission.
	s.ageAdmissionPastGrace(t, rid, s.oracleDB.orgID)

	// Consumer up: recovery must proceed FROM FACTS, not from a live event
	// (there is none), and must say so.
	s.restartLoggerd()

	pollUntil(t, 6*time.Minute, "recovery materializes from facts", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row yet")
		}
		return nil
	})
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "facts recovery")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "facts recovery")
	// Non-vacuity anchor: the recovered state carries the wallet intent
	// kind exactly once; the full recovered set must survive the late live
	// replay below unchanged.
	wantKinds := s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "facts recovery")
	t.Logf("facts: recovered settlement intent set: %v", wantKinds)

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

	s.controlRequest(t, "facts-post")
}
