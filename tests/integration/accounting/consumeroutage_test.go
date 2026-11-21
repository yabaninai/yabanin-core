//go:build integration

package accounting

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAccountingConsumerOutageDrainsOnRestart: a fully served request
// whose accounting consumer is DOWN at completion time must not lose
// accounting: 0028 commits usage/attribution/exact cost to
// request_terminal_facts BEFORE the completion event is published, so
// restarting loggerd must materialize the billed row and exactly one
// signed wallet debit — with zero extra provider calls (ledger stays
// 1/1/1). "Reconciled with terminal facts must still have exactly one
// wallet debit if configured" (consumer contract review).
//
// Scope note (distinct from facts recovery): here the published event is
// NOT deleted — it remains queued in the stream, and the restart may
// consume it live. What this case proves is the pre-publish durable commit
// (facts exist while the consumer is down) and that the queued event
// drains into exactly one charge. See
// TestAccountingFactsRecoveryWithoutLiveEvent for the no-live-event path.
func TestAccountingConsumerOutageDrainsOnRestart(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "outage-pre")

	rid := s.reqPrefix + "tgt-outage"

	// Consumer down BEFORE the target request (ack path dead end to end).
	s.stopLoggerd()
	defer func() {
		if s.loggerdCmd == nil {
			s.restartLoggerd()
		}
	}()

	before := s.fixture.Snapshot()
	status, body, err := s.chat(t, rid, 60*time.Second)
	if err != nil {
		t.Fatalf("consumer outage: client error: %v", err)
	}
	if status != httpOK || !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("consumer outage: status=%d body=%q, want 200 with the assistant content (serving must not depend on the consumer)", status, body)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		t.Fatalf("consumer outage: ledger delta = %d/%d/%d, want 1/1/1", delta.arrivals, delta.dispatches, delta.receipts)
	}

	// The durable terminal facts row must already exist while the consumer
	// is down — this is the pre-publish commit that makes recovery possible.
	if !s.oracleTableExists(t, "request_terminal_facts") {
		t.Fatalf("PRODUCT DEFECT (baseline): request_terminal_facts absent — terminal usage/cost is not durably committed before the completion event, so a lost consumer ack loses accounting")
	}
	if s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID) == 0 {
		t.Fatalf("consumer outage: no request_terminal_facts row for served %s while consumer is down — pre-publish durable commit violated", rid)
	}
	t.Logf("consumer outage: terminal facts durably present for %s with consumer down", rid)

	// Restart the consumer; accounting must materialize from facts/events.
	s.restartLoggerd()

	pollUntil(t, 3*time.Minute, "billed row materializes after consumer restart", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row yet")
		}
		return nil
	})
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "consumer outage")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "consumer outage")
	s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "consumer outage")

	// No re-dispatch ever happened.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("consumer outage: ledger after recovery arr/disp/recv = %d/%d/%d, want 1/1/1 (zero extra provider calls)", arr, disp, recv)
	}

	// Admission reconciles with the live-delivery reason (the queued event
	// drained) or, if the event was lost in flight and recovery swept from
	// facts, the recovery reason — both are single-charge terminal
	// resolutions for this construction.
	if s.oracleTableExists(t, "request_admissions") {
		pollUntil(t, 6*time.Minute, "consumer outage admission reconciles", func() error {
			rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
			if len(rows) != 1 {
				return fmt.Errorf("admissions = %d (%s), want 1", len(rows), fmtAdmissions(rows))
			}
			a := rows[0]
			requireAdmissionVocabulary(t, a)
			switch a.State {
			case "reconciled":
				if a.ResolveReason.String != reasonEventLive && a.ResolveReason.String != reasonRecovered {
					return abortf("reconciled reason %q, want %q or %q", a.ResolveReason.String, reasonEventLive, reasonRecovered)
				}
				return nil
			case "admitted":
				return fmt.Errorf("still admitted after consumer restart: %s", fmtAdmissions(rows))
			case "voided":
				return abortf("voided but the request completed and facts exist: %s", fmtAdmissions(rows))
			case "unresolved":
				return abortf("unresolved despite terminal facts present (facts-present path must materialize regardless of grace): %s", fmtAdmissions(rows))
			}
			return nil
		})
	}

	s.controlRequest(t, "outage-post")
}
