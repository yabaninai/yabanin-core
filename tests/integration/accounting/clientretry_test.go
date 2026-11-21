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
// admission reaches 'reconciled' ('event_delivered'); the crashed one may
// end 'unresolved' but never 'voided' (the dispatch happened) and never
// stay 'admitted'.
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
	s.fixture.Hold(rid)

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
	if s.oracleTableExists(t, "request_admissions") && s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID) == 0 {
		t.Fatalf("durable start: no admission at barrier for %s", rid)
	}

	// Crash invocation 1 mid-flight (after dispatch, before finalize).
	s.killGatewaySIGKILL()
	s.fixture.ReleaseAll()
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

	// Exactly one billed row across both invocations; crashed row silent.
	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "client retry")
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "client retry")
	s.requireCrashedRowSilent(t, rid, s.oracleDB.orgID, "client retry")

	// Exactly one wallet debit, signed -32 micro-USD.
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "client retry")
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs > 2 {
		t.Fatalf("client retry: settlement jobs = %d, want <= 2 (one per invocation at most)", jobs)
	}

	// Admissions: exactly two minted invocations under the correlation id,
	// the completed one reconciled with the live-delivery reason, the
	// crashed one may be unresolved, never voided, never stuck.
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — client-retry single-charge cannot be verified by invocation identity")
	}
	pollUntil(t, 6*time.Minute, "client retry admissions settle", func() error {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		if len(rows) != 2 {
			return fmt.Errorf("admissions = %d (%s), want exactly 2 minted invocations", len(rows), fmtAdmissions(rows))
		}
		reconciled, unresolved, admitted := 0, 0, 0
		for _, a := range rows {
			requireAdmissionVocabulary(t, a)
			switch a.State {
			case "reconciled":
				reconciled++
			case "unresolved":
				unresolved++
			case "admitted":
				admitted++
			case "voided":
				return abortf("voided claims proven-never-dispatched but both invocations dispatched: %s", fmtAdmissions(rows))
			}
		}
		if admitted > 0 {
			return fmt.Errorf("admission still open: %s", fmtAdmissions(rows))
		}
		if reconciled != 1 {
			return fmt.Errorf("want exactly 1 reconciled (completed invocation), got %d: %s", reconciled, fmtAdmissions(rows))
		}
		if unresolved > 1 {
			return fmt.Errorf("at most 1 unresolved (crashed invocation), got %d: %s", unresolved, fmtAdmissions(rows))
		}
		for _, a := range rows {
			if a.State == "reconciled" && a.ResolveReason.String != reasonEventLive {
				return abortf("reconciled reason = %q, want %q: %s", a.ResolveReason.String, reasonEventLive, fmtAdmissions(rows))
			}
		}
		return nil
	})
	t.Logf("client retry: two invocations, one reconciled (%s), exactly one charge", reasonEventLive)

	s.controlRequestOpts(t, "redelivery-post", s.oracleDB.orgID, chatOptions{stream: true})
}
