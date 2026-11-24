//go:build integration

package accounting

import (
	"fmt"
	"math"
	"strconv"
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
	// The restart guard must live in test scope: registered here it fires
	// only at test end, and only if a phase failed before the explicit
	// restart — never between phases while the outage oracle is asserting.
	s.stopLoggerd()
	defer func() {
		if s.loggerdCmd == nil {
			s.restartLoggerd()
		}
	}()

	s.serveWhileConsumerDown(t, rid)
	invocationID := s.requireTerminalFactsWhileConsumerDown(t, rid)
	s.requireAccountingMaterializedAfterRestart(t, rid)
	s.requireOutageAdmissionSettled(t, rid)
	s.requireRecoveredChargeIdentity(t, rid, invocationID, "consumer outage")

	s.controlRequest(t, "outage-post")
}

// serveWhileConsumerDown serves the target request against the already
// stopped consumer and proves serving independence: the client still
// gets the assistant content, and the provider ledger records exactly
// one arrival/dispatch/receipt. The caller stops the consumer and owns
// the deferred restart guard.
func (s *stand) serveWhileConsumerDown(t *testing.T, rid string) {
	t.Helper()

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
}

// requireTerminalFactsWhileConsumerDown proves the pre-publish durable
// commit while the consumer is verifiably still down: usage/attribution/
// exact cost land in exactly one request_terminal_facts row for the
// admitted invocation BEFORE the completion event is consumed.
func (s *stand) requireTerminalFactsWhileConsumerDown(t *testing.T, rid string) string {
	t.Helper()
	if s.loggerdCmd != nil {
		t.Fatalf("consumer outage: loggerd is running while the durable facts are asserted — the outage oracle requires the consumer down end to end")
	}
	if !s.oracleTableExists(t, "request_terminal_facts") {
		t.Fatalf("PRODUCT DEFECT (baseline): request_terminal_facts absent — terminal usage/cost is not durably committed before the completion event, so a lost consumer ack loses accounting")
	}
	if n := s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID); n != 1 {
		t.Fatalf("consumer outage: %d request_terminal_facts rows for served %s while consumer is down, want exactly 1 — pre-publish durable commit violated", n, rid)
	}
	invocationID := s.requireTerminalFactsMatchFixture(t, rid)
	t.Logf("consumer outage: terminal facts durably present for %s with consumer down", rid)
	return invocationID
}

// requireTerminalFactsMatchFixture asserts the single terminal-facts row
// carries the fixture usage, identity attribution and expected cost: the
// durable projection the reconciler recovers from must be the one the
// served invocation actually produced.
func (s *stand) requireTerminalFactsMatchFixture(t *testing.T, rid string) string {
	t.Helper()
	fact := func(field string) string {
		v, ok := s.oracleQueryRowString(t,
			`SELECT event->>$3 FROM request_terminal_facts WHERE client_request_id = $1 AND org_id = $2`,
			rid, s.oracleDB.orgID, field)
		if !ok {
			t.Fatalf("consumer outage: terminal facts row for %s has no %q field", rid, field)
		}
		return v
	}

	// The fact belongs to the single admitted invocation of this request.
	admissions := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(admissions) != 1 {
		t.Fatalf("consumer outage: %d admission row(s) for %s while consumer down, want the single admitted invocation", len(admissions), rid)
	}
	invocationID := admissions[0].InvocationID
	if keyed, ok := s.oracleQueryRowString(t,
		`SELECT invocation_id::text FROM request_terminal_facts WHERE client_request_id = $1 AND org_id = $2`,
		rid, s.oracleDB.orgID); !ok || keyed != invocationID {
		t.Fatalf("consumer outage: terminal facts row keyed to invocation %q, want the admitted invocation %s", keyed, invocationID)
	}

	for _, tc := range []struct{ field, want, what string }{
		{"invocation_id", invocationID, "admitted invocation"},
		{"org_id", s.oracleDB.orgID, "org attribution"},
		{"request_id", rid, "client correlation id"},
		{"status_code", strconv.Itoa(httpOK), "served status"},
		{"tokens_in", strconv.Itoa(fixturePromptTokens), "fixture input tokens"},
		{"tokens_out", strconv.Itoa(fixtureCompletionTokens), "fixture completion tokens"},
	} {
		if got := fact(tc.field); got != tc.want {
			t.Fatalf("consumer outage: terminal facts %s = %q, want %q (%s)", tc.field, got, tc.want, tc.what)
		}
	}
	s.requireTerminalFactCost(t, "estimated_cost_usd", fact("estimated_cost_usd"))
	s.requireTerminalFactCost(t, "resale_cost_usd", fact("resale_cost_usd"))
	return invocationID
}

// requireTerminalFactCost asserts a terminal-facts cost field carries
// the independently computed fixture cost under the operator-installed
// zero-markup rates (fixtureMicroUSDCost micro-USD).
func (s *stand) requireTerminalFactCost(t *testing.T, field, raw string) {
	t.Helper()
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || int64(math.Round(v*1e6)) != int64(fixtureMicroUSDCost) {
		t.Fatalf("consumer outage: terminal facts %s = %q, want the fixture-expected %d micro-USD (zero-markup resale at the installed rates)", field, raw, fixtureMicroUSDCost)
	}
}

// requireAccountingMaterializedAfterRestart restarts the consumer and
// waits for accounting to materialize from facts/events: the billed row,
// exactly one signed wallet debit, the wallet intent — and zero extra
// provider calls (ledger stays 1/1/1).
func (s *stand) requireAccountingMaterializedAfterRestart(t *testing.T, rid string) {
	t.Helper()
	s.restartLoggerd()

	s.waitForRecoveredBilling(t, rid, 3*time.Minute)
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "consumer outage")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "consumer outage")
	s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "consumer outage")

	// No re-dispatch ever happened.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("consumer outage: ledger after recovery arr/disp/recv = %d/%d/%d, want 1/1/1 (zero extra provider calls)", arr, disp, recv)
	}
}

// requireOutageAdmissionSettled waits for the single admission to reach a
// terminal single-charge resolution: reconciled with the live-delivery
// reason (the queued event drained) or the recovery reason (the event was
// lost in flight and recovery swept from facts).
func (s *stand) requireOutageAdmissionSettled(t *testing.T, rid string) {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — consumer outage admission resolution unverifiable")
	}
	pollUntil(t, 6*time.Minute, "consumer outage admission reconciles", func() error {
		return checkOutageAdmission(t, s.oracleAdmissions(t, rid, s.oracleDB.orgID))
	})
}

// checkOutageAdmission validates one admission row for the served
// request: never still admitted, voided or unresolved; reconciled must
// carry the live-delivery or recovered reason.
func checkOutageAdmission(t *testing.T, rows []admissionRow) error {
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
}
