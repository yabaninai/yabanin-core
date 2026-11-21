//go:build integration

package accounting

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAccountingCrashClientRetrySingleCharge: crash + CLIENT RETRY
// semantics. A crashed streamed invocation followed by a SECOND, distinct
// HTTP invocation under the SAME client correlation id must bill EXACTLY
// ONCE for the completed work: two legitimate invocations (distinct minted
// UUIDs per 0028) share the correlation id and bill independently — only
// the completed one charges — with exactly one signed wallet debit of -32
// micro-USD, exactly one billed request_logs row, and the crashed
// invocation's row (if any) never claiming success/usage. The completed
// admission reaches 'reconciled' ('event_delivered'); the crashed one —
// identified by the server UUID captured at the pre-kill barrier and
// deterministically expired past grace by that UUID, never its same-rid
// sibling — must reach EXACTLY 'unresolved' ('grace_elapsed_no_terminal_
// facts', resolved_at set). Monetary totals are asserted only after the
// consumer's actual completion (polled materialization), and the exact
// per-kind settlement intent set of the billed invocation must survive
// the unresolved transition unchanged.
//
// NOTE: this is NOT an event-redelivery case (no Redis replay happens
// here); see TestAccountingRedisEventRedeliveryIdempotent and
// TestAccountingFactsRecoveryWithoutLiveEvent for those.
func TestAccountingCrashClientRetrySingleCharge(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	// Streamed healthy control proves the SSE path is billed + charged.
	s.controlRequestOpts(t, "redelivery-pre", s.oracleDB.orgID, chatOptions{stream: true})

	rid := s.reqPrefix + "tgt-redelivery"
	before := s.fixture.Snapshot()
	disconnected := s.fixture.Hold(rid)

	type chatResult struct {
		status int
		body   string
		err    error
	}
	clientDone := make(chan chatResult, 1)
	go func() {
		status, body, err := s.chatFull(t, rid, 90*time.Second, chatOptions{stream: true})
		clientDone <- chatResult{status: status, body: body, err: err}
	}()

	if !s.fixture.WaitForDispatch(rid, 20*time.Second) {
		t.Fatalf("target: first invocation never dispatched")
	}
	// Capture the FIRST invocation's server-minted UUID at the pre-kill
	// barrier: exactly one admission exists at this moment, and it is the
	// row that must later expire to 'unresolved' — never the same-rid
	// second invocation, so the grace expiry below is keyed to this UUID.
	firstInvocation := ""
	if s.oracleTableExists(t, "request_admissions") {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		if len(rows) != 1 {
			t.Fatalf("durable start: admissions at barrier = %d (%s), want exactly 1 for the in-flight first invocation", len(rows), fmtAdmissions(rows))
		}
		requireAdmissionVocabulary(t, rows[0])
		if rows[0].State != "admitted" {
			t.Fatalf("durable start: barrier admission state %q, want 'admitted'", rows[0].State)
		}
		firstInvocation = rows[0].InvocationID
	}

	// Crash invocation 1 mid-flight (after dispatch, before finalize).
	s.killGatewaySIGKILL()
	s.fixture.releaseAfterDisconnect(disconnected)
	select {
	case r := <-clientDone:
		if r.err == nil && r.status == httpOK {
			t.Fatalf("harness: first invocation reported success (%d) although the gateway died mid-flight", r.status)
		}
		t.Logf("target: first invocation observed the crash (status=%d err=%v)", r.status, r.err)
	case <-time.After(10 * time.Second):
		t.Fatalf("harness: first invocation did not terminate after the gateway was killed")
	}
	s.restartGateway()

	// Invocation 2: same client correlation id, streamed, served to
	// completion. Distinct body so no prompt-derived cache can suppress
	// the second paid call.
	status, body, err := s.chatFull(t, rid, 60*time.Second, chatOptions{
		stream:  true,
		content: "client retry after crash, distinct body " + s.runID,
	})
	if err != nil {
		t.Fatalf("client retry: invocation 2 error: %v", err)
	}
	if status != httpOK || !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("client retry: invocation 2 status=%d body=%q, want 200 with the assistant content", status, body)
	}

	// Both invocations reached the provider; only the live one got its
	// receipt delivered back (the crashed gateway never read the bytes).
	arr, disp, recv := s.fixture.Counts(rid)
	if arr != 2 || disp != 2 || recv != 1 {
		t.Fatalf("client retry: ledger arr/disp/recv = %d/%d/%d, want 2/2/1 (two dispatches, one delivered receipt)", arr, disp, recv)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 2 || delta.dispatches != 2 || delta.receipts != 1 {
		t.Fatalf("client retry: ledger delta = %d/%d/%d, want 2/2/1", delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Monetary totals only AFTER the consumer actually completed: wait for
	// the second invocation's accounting to materialize before asserting
	// anything about rows, debits or intents.
	pollUntil(t, 3*time.Minute, "retry accounting materializes", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row yet")
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows == 0 {
			return fmt.Errorf("no wallet usage row yet")
		}
		return nil
	})

	// Exactly one billed row across both invocations; crashed row silent.
	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "client retry")
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "client retry")
	s.requireCrashedRowSilent(t, rid, s.oracleDB.orgID, "client retry")

	// Exactly one wallet debit, signed -32 micro-USD.
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "client retry")
	// Exact per-kind settlement intent set for the billed invocation,
	// anchored on the always-planned wallet kind. The crashed invocation
	// produced no terminal event, so it must add nothing; the final state
	// below re-asserts this set unchanged.
	kinds := s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "client retry")

	// Admissions: exactly two minted invocations under the correlation id,
	// each in its correct terminal state — the FIRST (captured at the
	// barrier, crashed) 'unresolved' with the exact no-facts reason after
	// its own grace expiry, the SECOND (completed) 'reconciled' via live
	// delivery. The default 15-minute grace never elapses inside a test
	// run on its own, so the crashed invocation's row is expired
	// deterministically — by invocation UUID, never the same-rid sibling.
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — client-retry single-charge cannot be verified by invocation identity")
	}
	s.ageAdmissionByInvocationPastGrace(t, firstInvocation, s.oracleDB.orgID)
	pollUntil(t, 6*time.Minute, "client retry admissions settle per invocation", func() error {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		if len(rows) != 2 {
			return fmt.Errorf("admissions = %d (%s), want exactly 2 minted invocations", len(rows), fmtAdmissions(rows))
		}
		var first, second *admissionRow
		for i := range rows {
			switch rows[i].InvocationID {
			case firstInvocation:
				first = &rows[i]
			default:
				second = &rows[i]
			}
		}
		if first == nil || second == nil {
			return abortf("admission UUIDs (%s vs captured %s) do not resolve to two distinct invocations: %s",
				fmtAdmissions(rows), firstInvocation, fmtAdmissions(rows))
		}
		for _, a := range []admissionRow{*first, *second} {
			requireAdmissionVocabulary(t, a)
			if a.State == "voided" {
				return abortf("voided claims proven-never-dispatched but both invocations dispatched: %s", fmtAdmissions(rows))
			}
		}
		switch {
		case first.State == "admitted":
			return fmt.Errorf("crashed invocation %s still admitted (reconciler sweep has not run): %s", firstInvocation, fmtAdmissions(rows))
		case first.State != "unresolved":
			return abortf("crashed invocation %s reached %s, want 'unresolved': %s", firstInvocation, first.State, fmtAdmissions(rows))
		case !first.ResolveReason.Valid || first.ResolveReason.String != reasonGraceElapsed:
			return abortf("crashed invocation %s unresolved with reason %q, want %q: %s", firstInvocation, first.ResolveReason.String, reasonGraceElapsed, fmtAdmissions(rows))
		case !first.ResolvedAt.Valid:
			return abortf("crashed invocation %s unresolved without resolved_at: %s", firstInvocation, fmtAdmissions(rows))
		case second.State == "admitted":
			return fmt.Errorf("completed invocation still admitted: %s", fmtAdmissions(rows))
		case second.State != "reconciled":
			return fmt.Errorf("completed invocation reached %s, want 'reconciled': %s", second.State, fmtAdmissions(rows))
		case second.ResolveReason.String != reasonEventLive:
			return abortf("completed invocation reconciled with reason %q, want %q: %s", second.ResolveReason.String, reasonEventLive, fmtAdmissions(rows))
		}
		return nil
	})
	// The unresolved transition must not have produced or disturbed any
	// accounting for the billed invocation.
	s.requireSettlementIntents(t, rid, s.oracleDB.orgID, "client retry final", kinds)
	t.Logf("client retry: crashed invocation %s -> unresolved/%s; completed invocation reconciled/%s; exactly one charge",
		firstInvocation, reasonGraceElapsed, reasonEventLive)

	s.controlRequestOpts(t, "redelivery-post", s.oracleDB.orgID, chatOptions{stream: true})
}
