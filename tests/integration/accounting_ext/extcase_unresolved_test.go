//go:build integration

package accountingext

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestExtUnresolvedStartExplicit: crash after the paid dispatch but before
// the response is finalized must leave an EXPLICIT, tenant-scoped unresolved
// identification — 0028 state 'unresolved' with resolve_reason
// 'grace_elapsed_no_terminal_facts' after the grace window (deterministic
// path: age ONLY the target's admission past grace, only after the crash;
// never age still-live controls) — with no invented usage, no wallet debit
// and no fabricated request_logs success. Discovery through the admission
// row is sufficient; a request_logs row is NOT forced (and if one exists it
// must not claim success/usage/cost).
//
// Baseline (4e9895d) truth: request_admissions does not exist — the case
// must fail there with an explicit defect message, not pass vacuously.
func TestExtUnresolvedStartExplicit(t *testing.T) {
	s := startExtStand(t)
	s.waitGatewayHealthy(t)

	// Chargeability precondition + healthy paid control (buffered).
	s.assertWalletConfigured(t, s.orgIDA, "pre-control")
	s.controlRequest(t, "unresolved-pre", s.apiKeyA, modelA, s.orgIDA, false)

	rid := "target-unresolved-" + s.runID
	before := s.fixture.Snapshot()
	s.fixture.Hold(rid)

	clientDone := make(chan chatResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		clientDone <- s.chat(ctx, rid, false)
	}()

	if !s.fixture.WaitForDispatch(rid, 20*time.Second) {
		t.Fatalf("target: provider dispatch never happened (fixture hold gates AFTER arrival recording but BEFORE dispatch; hold released at kill)")
	}
	arr, disp, _ := s.fixture.Counts(rid)
	if disp != 1 || arr != 1 {
		t.Fatalf("target: fixture arr/disp = %d/%d, want 1/1 before crash", arr, disp)
	}

	// Durable start at the crash barrier: on the candidate an 'admitted'
	// row exists BEFORE the first paid call returned; the dispatch observed
	// above proves the paid call happened, so the admission must exist now.
	admAtBarrier := s.oracleAdmissions(t, s.orgIDA, rid)
	hasAdmissions := s.oracleTableExists(t, "request_admissions")
	if hasAdmissions && len(admAtBarrier) == 0 {
		t.Fatalf("durable start: dispatch observed for %s but no admission row under org %s", rid, s.orgIDA)
	}
	if hasAdmissions {
		for _, a := range admAtBarrier {
			requireAdmissionVocabulary(t, a)
			if a.OrgID != s.orgIDA {
				t.Fatalf("durable start: admission org %q, want %q (tenant binding)", a.OrgID, s.orgIDA)
			}
			if a.State != "admitted" {
				t.Fatalf("durable start: admission state at barrier = %q, want 'admitted' (pre-terminal)", a.State)
			}
		}
	}

	// Crash: gateway only (SIGKILL), release the held response into a dead
	// client path. The provider finishes its receipt write, the gateway
	// never finalizes accounting.
	s.killGateway(t)
	s.fixture.ReleaseAll()
	dArr, dDisp, dRecv := s.fixture.Since(before)
	if dArr != 1 || dDisp != 1 || dRecv != 1 {
		t.Fatalf("target: ledger after crash arr/disp/recv = %d/%d/%d, want 1/1/1 (receipt completes; client sees nothing)", dArr, dDisp, dRecv)
	}

	// Deterministic grace expiry (after the crash, target-only).
	if hasAdmissions {
		if aged := s.ageAdmissionsPastGrace(t, s.orgIDA, rid); aged == 0 {
			t.Fatalf("grace aging: no still-open admission to age for %s", rid)
		}
	}

	s.restartGateway(t)

	if !hasAdmissions {
		t.Fatalf("PRODUCT DEFECT (baseline): no explicit unresolved identification mechanism — "+
			"crashed dispatched request %s has no request_admissions row to transition to 'unresolved'; "+
			"the start is silently lost instead of explicitly visible", rid)
	}

	// Strict unresolved: poll for state 'unresolved' with the exact contract
	// reason. 'admitted' (stuck), 'voided' (claims proven-never-dispatched —
	// false, the fixture observed the dispatch) and 'reconciled' (claims
	// terminal evidence that does not exist) are all explicit defects.
	eventually(t, 6*time.Minute, pollEvery, "target admission reaches 'unresolved'", func() error {
		rows := s.oracleAdmissions(t, s.orgIDA, rid)
		if len(rows) == 0 {
			return fmt.Errorf("no admission rows after restart")
		}
		for _, a := range rows {
			requireAdmissionVocabulary(t, a)
			switch a.State {
			case "unresolved":
				if !a.ResolveReas.Valid || a.ResolveReas.String != reasonGraceElapsed {
					return fmt.Errorf("unresolved with wrong resolve_reason: %s", fmtAdmissions(rows))
				}
				if !a.ResolvedAt.Valid {
					return fmt.Errorf("unresolved without resolved_at: %s", fmtAdmissions(rows))
				}
				return nil
			case "admitted":
				return fmt.Errorf("still admitted (reconciler sweep has not run or grace not honored): %s", fmtAdmissions(rows))
			case "voided":
				return fatalf("voided claims proven-never-dispatched, but the fixture observed the dispatch: %s", fmtAdmissions(rows))
			case "reconciled":
				return fatalf("reconciled claims terminal evidence that does not exist: %s", fmtAdmissions(rows))
			}
		}
		return fmt.Errorf("no admission reached a grace-terminal state: %s", fmtAdmissions(rows))
	})
	t.Logf("target: admission reached 'unresolved' with reason %s", reasonGraceElapsed)

	// No invented usage, no wallet debit, no fabricated request_logs claim.
	s.requireNoWalletDebit(t, s.orgIDA, rid, "unresolved")
	logRows := s.oracleRequestLogRows(t, s.orgIDA, rid)
	if len(logRows) > 0 {
		for _, r := range logRows {
			if r.Status == http.StatusOK {
				t.Fatalf("unresolved: request_logs row claims 200 for crashed %s (fabricated success)", rid)
			}
			if r.TokensIn > 0 || r.TokensOut > 0 || r.CostUSD > 0 {
				t.Fatalf("unresolved: request_logs row invents usage/cost for crashed %s: %+v", rid, r)
			}
		}
		t.Logf("unresolved: content-free request_logs row present for %s (acceptable: no usage claimed)", rid)
	} else {
		t.Logf("unresolved: no request_logs row for %s (acceptable: discovery through the admission row)", rid)
	}
	if jobs := s.settlementJobCount(t, s.orgIDA, rid); jobs > 1 {
		t.Fatalf("unresolved: settlement jobs = %d, want <= 1", jobs)
	}

	// Tenant scoping: the target's correlation id must have no admission in
	// the other org.
	if rows := s.oracleAdmissions(t, s.orgIDB, rid); len(rows) != 0 {
		t.Fatalf("tenant scoping: admissions for %s leaked into org B: %s", rid, fmtAdmissions(rows))
	}

	// Post-recovery control: the system still serves and charges exactly once.
	s.controlRequest(t, "unresolved-post", s.apiKeyA, modelA, s.orgIDA, false)

	// The abandoned client's transport result is irrelevant post-crash; drain.
	select {
	case r := <-clientDone:
		t.Logf("abandoned client finished after crash: status=%d err=%v (ignored by design)", r.StatusCode, r.Err)
	default:
	}
}
