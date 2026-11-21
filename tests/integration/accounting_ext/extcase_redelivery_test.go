//go:build integration

package accountingext

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestExtRedeliverySingleCharge: a crashed streamed invocation followed by a
// redelivery under the SAME client correlation id must bill EXACTLY ONCE:
// two legitimate invocations (distinct minted UUIDs per 0028) share the
// correlation id and bill independently — only the completed one charges —
// with exactly one signed wallet debit of -32 micro-USD, exactly one billed
// request_logs row, and the crashed invocation's row (if any) never claiming
// success/usage. The completed admission reaches 'reconciled'
// ('event_delivered'); the crashed one may end 'unresolved' but never
// 'voided' (the dispatch happened) and never stay 'admitted'.
func TestExtRedeliverySingleCharge(t *testing.T) {
	s := startExtStand(t)
	s.waitGatewayHealthy(t)

	s.assertWalletConfigured(t, s.orgIDA, "pre-control")
	// Streamed healthy control proves the SSE path is billed + charged.
	s.controlRequest(t, "redelivery-pre", s.apiKeyA, modelA, s.orgIDA, true)

	rid := "target-redelivery-" + s.runID
	before := s.fixture.Snapshot()
	s.fixture.Hold(rid)

	clientDone := make(chan chatResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		clientDone <- s.chat(ctx, rid, true)
	}()

	if !s.fixture.WaitForDispatch(rid, 20*time.Second) {
		t.Fatalf("target: first invocation never dispatched")
	}
	if rows := s.oracleAdmissions(t, s.orgIDA, rid); s.oracleTableExists(t, "request_admissions") && len(rows) == 0 {
		t.Fatalf("durable start: no admission at barrier for %s", rid)
	}

	// Crash invocation 1 mid-flight (after dispatch, before finalize).
	s.killGateway(t)
	s.fixture.ReleaseAll()
	s.restartGateway(t)

	// Invocation 2: same client correlation id, streamed, served to completion.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()
	res := s.chat(ctx2, rid, true)
	if res.Err != nil {
		t.Fatalf("redelivery: client error: %v", res.Err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("redelivery: status %d, want 200", res.StatusCode)
	}
	if res.Usage == nil || res.Usage.PromptTokens != extPromptTokens || res.Usage.CompletionTokens != extCompletionTokens {
		t.Fatalf("redelivery: usage = %+v, want %d/%d", res.Usage, extPromptTokens, extCompletionTokens)
	}

	arr, disp, recv := s.fixture.Counts(rid)
	if arr != 2 || disp != 2 || recv != 2 {
		t.Fatalf("redelivery: ledger arr/disp/recv = %d/%d/%d, want 2/2/2 (both invocations complete provider-side)", arr, disp, recv)
	}
	dArr, dDisp, dRecv := s.fixture.Since(before)
	if dArr != 2 || dDisp != 2 || dRecv != 2 {
		t.Fatalf("redelivery: ledger delta = %d/%d/%d, want 2/2/2", dArr, dDisp, dRecv)
	}

	// Exactly one billed row across both invocations; crashed row silent.
	s.requireExactlyOneBilledRow(t, s.orgIDA, rid, "redelivery")
	s.requireCrashedRowNeverClaimsUsageAllowingBilled(t, s.orgIDA, rid)

	// Exactly one wallet debit, signed -32 micro-USD, exactly once overall.
	s.requireWalletChargedExactlyOnce(t, s.orgIDA, rid, extCostMicroUSD, "redelivery")
	if jobs := s.settlementJobCount(t, s.orgIDA, rid); jobs > 2 {
		t.Fatalf("redelivery: settlement jobs = %d, want <= 2 (one per invocation at most)", jobs)
	}

	// Admissions: exactly two minted invocations under the correlation id,
	// the completed one reconciled with the live-delivery reason, the
	// crashed one may be unresolved (or reconciled-from-nothing is NOT
	// acceptable: it had no terminal facts), never voided, never stuck.
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — redelivery single-charge cannot be verified by invocation identity")
	}
	eventually(t, 6*time.Minute, pollEvery, "redelivery admissions settle", func() error {
		rows := s.oracleAdmissions(t, s.orgIDA, rid)
		if len(rows) != 2 {
			return errf("admissions = %d (%s), want exactly 2 minted invocations", len(rows), fmtAdmissions(rows))
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
				return fatalf("voided claims proven-never-dispatched but both invocations dispatched: %s", fmtAdmissions(rows))
			}
		}
		if admitted > 0 {
			return errf("admission still open: %s", fmtAdmissions(rows))
		}
		if reconciled != 1 {
			return errf("want exactly 1 reconciled (completed invocation), got %d: %s", reconciled, fmtAdmissions(rows))
		}
		if unresolved > 1 {
			return errf("at most 1 unresolved (crashed invocation), got %d: %s", unresolved, fmtAdmissions(rows))
		}
		// The reconciled one must carry the live-delivery reason.
		for _, a := range rows {
			if a.State == "reconciled" && a.ResolveReas.String != reasonEventLive {
				return fatalf("reconciled reason = %q, want %q: %s", a.ResolveReas.String, reasonEventLive, fmtAdmissions(rows))
			}
		}
		return nil
	})
	t.Logf("redelivery: two invocations, one reconciled (%s), exactly one charge", reasonEventLive)

	s.controlRequest(t, "redelivery-post", s.apiKeyA, modelA, s.orgIDA, true)
}

// requireCrashedRowNeverClaimsUsageAllowingBilled: any NON-billed row for
// the correlation id (the crashed invocation's materialization, if any) must
// not claim success, usage or cost; exactly one billed row is allowed.
func (s *extStand) requireCrashedRowNeverClaimsUsageAllowingBilled(t *testing.T, orgID, rid string) {
	t.Helper()
	for _, r := range s.oracleRequestLogRows(t, orgID, rid) {
		if r.Status == http.StatusOK {
			continue // the billed invocation (checked separately)
		}
		if r.TokensIn > 0 || r.TokensOut > 0 || r.CostUSD > 0 {
			t.Fatalf("redelivery: crashed invocation's row invents usage/cost for %s: %+v", rid, r)
		}
	}
}

func errf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}
