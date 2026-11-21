//go:build integration

package accounting

import (
	"fmt"
	"testing"
	"time"
)

// TestAccountingUnresolvedAfterGraceNoFacts: crash after the paid dispatch
// but before the response is finalized must leave an EXPLICIT,
// tenant-scoped unresolved identification — 0028 state 'unresolved' with
// resolve_reason 'grace_elapsed_no_terminal_facts' after the grace window
// (deterministic path: age ONLY the target's admission — captured by its
// server-minted UUID at the pre-kill barrier — past grace, only after the
// crash; never age still-live controls) — with no invented usage, no
// wallet debit and no fabricated request_logs success. Exactly that one
// UUID — never a duplicate mint, never a replacement — must surface as
// the unresolved row through the restart. Discovery through the admission
// row is sufficient; a request_logs row is NOT forced (and if one exists
// it must not claim success/usage/cost).
//
// Baseline (4e9895d) truth: request_admissions does not exist — the case
// must fail there with an explicit defect message, not pass vacuously.
func TestAccountingUnresolvedAfterGraceNoFacts(t *testing.T) {
	s := startStand(t)

	// Chargeability precondition + healthy paid control.
	balanceBefore := s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "unresolved-pre")

	rid := s.reqPrefix + "tgt-unresolved"
	before := s.fixture.Snapshot()
	s.fixture.Hold(rid)

	type chatResult struct {
		status int
		body   string
		err    error
	}
	clientDone := make(chan chatResult, 1)
	go func() {
		status, body, err := s.chat(t, rid, 60*time.Second)
		clientDone <- chatResult{status: status, body: body, err: err}
	}()

	if !s.fixture.WaitForDispatch(rid, 20*time.Second) {
		t.Fatalf("target: provider dispatch never happened (fixture hold gates AFTER arrival recording but BEFORE dispatch; hold released at kill)")
	}
	if arr, disp, _ := s.fixture.Counts(rid); arr != 1 || disp != 1 {
		t.Fatalf("target: fixture arr/disp = %d/%d, want 1/1 before crash", arr, disp)
	}

	// Durable start at the crash barrier: on the candidate an 'admitted'
	// row exists BEFORE the first paid call returned; the dispatch observed
	// above proves the paid call happened, so the admission must exist now.
	// Exactly one admission may exist for this single HTTP invocation, and
	// its server-minted UUID is captured here: every later assertion —
	// grace expiry and the post-restart terminal state — is bound to this
	// exact UUID, so a duplicate mint under the same call cannot hide
	// behind a first-row read.
	hasAdmissions := s.oracleTableExists(t, "request_admissions")
	admAtBarrier := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if hasAdmissions && len(admAtBarrier) != 1 {
		t.Fatalf("durable start: dispatch observed for %s but admissions at barrier = %d (%s), want exactly 1", rid, len(admAtBarrier), fmtAdmissions(admAtBarrier))
	}
	targetUUID := ""
	for _, a := range admAtBarrier {
		requireAdmissionVocabulary(t, a)
		if a.State != "admitted" {
			t.Fatalf("durable start: admission state at barrier = %q, want 'admitted' (pre-terminal)", a.State)
		}
		targetUUID = a.InvocationID
	}

	// Crash: gateway only (SIGKILL), release the held response into a dead
	// client path. The dispatch stands; the receipt never lands (the dead
	// gateway cannot receive the provider's bytes).
	s.killGatewaySIGKILL()
	s.fixture.ReleaseAll()
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 0 {
		t.Fatalf("target: ledger after crash arr/disp/recv = %d/%d/%d, want 1/1/0 (dispatch stands, client gone)", delta.arrivals, delta.dispatches, delta.receipts)
	}
	select {
	case r := <-clientDone:
		if r.err == nil && r.status == httpOK {
			t.Fatalf("target: client received a successful completion (%d) although the gateway died mid-flight", r.status)
		}
		t.Logf("target: client observed the crash (status=%d err=%v)", r.status, r.err)
	case <-time.After(10 * time.Second):
		t.Fatalf("target: client request did not terminate after the gateway was killed")
	}

	// Deterministic grace expiry (after the crash, target-only).
	if hasAdmissions {
		s.ageAdmissionPastGrace(t, rid, s.oracleDB.orgID)
	}

	s.restartGateway()

	if !hasAdmissions {
		t.Fatalf("PRODUCT DEFECT (baseline): no explicit unresolved identification mechanism — "+
			"crashed dispatched request %s has no request_admissions row to transition to 'unresolved'; "+
			"the start is silently lost instead of explicitly visible", rid)
	}

	// Strict unresolved for the EXACT captured UUID: poll until precisely
	// one admission exists under this correlation id, it is the barrier
	// UUID, and it is 'unresolved' with the exact contract reason.
	// 'admitted' (stuck), 'voided' (claims proven-never-dispatched —
	// false, the fixture observed the dispatch) and 'reconciled' (claims
	// terminal evidence that does not exist) are all explicit defects, as
	// is any duplicate mint under the single HTTP invocation.
	pollUntil(t, 6*time.Minute, "target admission reaches 'unresolved'", func() error {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		switch {
		case len(rows) == 0:
			return errTransient("no admission rows after restart")
		case len(rows) > 1:
			return abortf("duplicate admissions minted under one HTTP invocation: %s (captured UUID %s)", fmtAdmissions(rows), targetUUID)
		}
		a := rows[0]
		if a.InvocationID != targetUUID {
			return abortf("admission UUID changed across the restart: barrier %s, now %s", targetUUID, a.InvocationID)
		}
		requireAdmissionVocabulary(t, a)
		switch a.State {
		case "unresolved":
			if !a.ResolveReason.Valid || a.ResolveReason.String != reasonGraceElapsed {
				return abortf("unresolved with wrong resolve_reason: %s", fmtAdmissions(rows))
			}
			if !a.ResolvedAt.Valid {
				return abortf("unresolved without resolved_at: %s", fmtAdmissions(rows))
			}
			return nil
		case "admitted":
			return errTransient("still admitted (reconciler sweep has not run or grace not honored): " + fmtAdmissions(rows))
		case "voided":
			return abortf("voided claims proven-never-dispatched, but the fixture observed the dispatch: %s", fmtAdmissions(rows))
		case "reconciled":
			return abortf("reconciled claims terminal evidence that does not exist: %s", fmtAdmissions(rows))
		}
		return errTransient("no terminal state recognized: " + fmtAdmissions(rows))
	})
	t.Logf("target: admission %s reached 'unresolved' with reason %s", targetUUID, reasonGraceElapsed)

	// No invented usage, no wallet debit, no fabricated request_logs claim.
	s.requireNoWalletDebit(t, rid, s.oracleDB.orgID, "unresolved")
	if balanceAfter, _ := s.oracleWalletBalance(t, s.oracleDB.orgID); balanceAfter != balanceBefore {
		t.Fatalf("unresolved: wallet balance moved %d -> %d with no chargeable evidence for %s", balanceBefore, balanceAfter, rid)
	}
	logRows := s.oracleRequestLogRows(t, rid, s.oracleDB.orgID)
	for _, r := range logRows {
		if r.Status == httpOK {
			t.Fatalf("unresolved: request_logs row claims 200 for crashed %s (fabricated success)", rid)
		}
		if r.TokensIn > 0 || r.TokensOut > 0 || r.CostUSD > 0 {
			t.Fatalf("unresolved: request_logs row invents usage/cost for crashed %s: status=%d tokens=%d/%d cost=%v", rid, r.Status, r.TokensIn, r.TokensOut, r.CostUSD)
		}
	}
	if len(logRows) == 0 {
		t.Logf("unresolved: no request_logs row for %s (acceptable: discovery through the admission row)", rid)
	} else {
		t.Logf("unresolved: content-free request_logs row present for %s (acceptable: no usage claimed)", rid)
	}
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs > 1 {
		t.Fatalf("unresolved: settlement jobs = %d, want <= 1", jobs)
	}

	// Post-recovery control: the system still serves and charges exactly once.
	s.controlRequest(t, "unresolved-post")
}

// errTransient wraps a not-yet state for pollUntil (opposite of abortf).
func errTransient(msg string) error { return fmt.Errorf("poll: %s", msg) }
