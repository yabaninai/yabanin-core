//go:build integration

package accountingext

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestExtLostAckRecoveredFromFacts: a fully served request whose accounting
// consumer is DOWN at completion time must not lose accounting: 0028 commits
// usage/attribution/exact cost to request_terminal_facts BEFORE the
// completion event is published, so restarting loggerd must materialize the
// billed row and exactly one signed wallet debit — with zero extra provider
// calls (ledger stays 1/1/1). "Reconciled with terminal facts must still
// have exactly one wallet debit if configured" (consumer contract review).
func TestExtLostAckRecoveredFromFacts(t *testing.T) {
	s := startExtStand(t)
	s.waitGatewayHealthy(t)

	s.assertWalletConfigured(t, s.orgIDA, "pre-control")
	s.controlRequest(t, "lostack-pre", s.apiKeyA, modelA, s.orgIDA, false)

	rid := "target-lostack-" + s.runID

	// Consumer down BEFORE the target request (ack path dead end to end).
	s.stopLoggerd(t)

	before := s.fixture.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := s.chat(ctx, rid, false)
	if res.Err != nil {
		t.Fatalf("lost-ack: client error: %v", res.Err)
	}
	if res.StatusCode != http.StatusOK || res.Content != "Hi" {
		t.Fatalf("lost-ack: status=%d content=%q, want 200/%q (serving must not depend on the consumer)", res.StatusCode, res.Content, "Hi")
	}
	dArr, dDisp, dRecv := s.fixture.Since(before)
	if dArr != 1 || dDisp != 1 || dRecv != 1 {
		t.Fatalf("lost-ack: ledger delta = %d/%d/%d, want 1/1/1", dArr, dDisp, dRecv)
	}

	// The durable terminal facts row must already exist while the consumer
	// is down — this is the pre-publish commit that makes recovery possible.
	if !s.oracleTableExists(t, "request_terminal_facts") {
		t.Fatalf("PRODUCT DEFECT (baseline): request_terminal_facts absent — terminal usage/cost is not durably committed before the completion event, so a lost consumer ack loses accounting")
	}
	if !s.oracleTerminalFactsPresent(t, s.orgIDA, rid) {
		t.Fatalf("lost-ack: no request_terminal_facts row for served %s while consumer is down — pre-publish durable commit violated", rid)
	}
	t.Logf("lost-ack: terminal facts durably present for %s with consumer down", rid)

	// Restart the consumer; accounting must materialize from facts/events.
	s.startLoggerd(t)

	eventually(t, 3*time.Minute, pollEvery, "billed row materializes after consumer restart", func() error {
		rows := s.oracleRequestLogRows(t, s.orgIDA, rid)
		if len(rows) == 0 {
			return errf("no request_logs row yet")
		}
		return nil
	})
	s.requireBilledRow(t, s.orgIDA, rid, "lost-ack")
	s.requireWalletChargedExactlyOnce(t, s.orgIDA, rid, extCostMicroUSD, "lost-ack")

	// No re-dispatch ever happened.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("lost-ack: ledger after recovery arr/disp/recv = %d/%d/%d, want 1/1/1 (zero extra provider calls)", arr, disp, recv)
	}

	// Admission reconciles with the live-delivery reason (or, if the event
	// was lost in flight and recovery swept from facts, the recovery reason —
	// both are single-charge terminal resolutions).
	if s.oracleTableExists(t, "request_admissions") {
		eventually(t, 6*time.Minute, pollEvery, "lost-ack admission reconciles", func() error {
			rows := s.oracleAdmissions(t, s.orgIDA, rid)
			if len(rows) != 1 {
				return errf("admissions = %d (%s), want 1", len(rows), fmtAdmissions(rows))
			}
			a := rows[0]
			requireAdmissionVocabulary(t, a)
			switch a.State {
			case "reconciled":
				if a.ResolveReas.String != reasonEventLive && a.ResolveReas.String != reasonRecovered {
					return fatalf("reconciled reason %q, want %q or %q", a.ResolveReas.String, reasonEventLive, reasonRecovered)
				}
				return nil
			case "admitted":
				return errf("still admitted after consumer restart: %s", fmtAdmissions(rows))
			case "voided":
				return fatalf("voided but the request completed and facts exist: %s", fmtAdmissions(rows))
			case "unresolved":
				return fatalf("unresolved despite terminal facts present (facts-present path must materialize regardless of grace): %s", fmtAdmissions(rows))
			}
			return nil
		})
	}

	s.controlRequest(t, "lostack-post", s.apiKeyA, modelA, s.orgIDA, false)
}
