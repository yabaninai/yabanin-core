//go:build integration

package accounting

import (
	"fmt"
	"testing"
	"time"
)

// TestAccountingSameOrgTwoPaidInvocationsSharedCorrelationId: TWO
// SUCCESSFUL paid HTTP invocations in the SAME org under the SAME client
// correlation id (distinct bodies, so no prompt-derived cache hit can
// suppress the second paid call), one buffered and one streamed. Per 0028
// the correlation id is correlation-only: two distinct minted invocation
// IDs must bill INDEPENDENTLY — a signed wallet debit of -32 micro-USD
// EACH, two billed request_logs rows, two independent provider receipts,
// and two admissions that each reconcile.
//
// Baseline truth (4e9895d): the legacy settlement/usage identity keys are
// (org_id, request_id, charge_kind) and GLOBAL (request_id) — the second
// invocation's accounting cannot land independently (it collides and must
// fail loudly into requires_attention, never silently double-charge). The
// case therefore FAILS on baseline by design and pins the 0028 contract.
func TestAccountingSameOrgTwoPaidInvocationsSharedCorrelationId(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "samerid-pre")

	rid := s.reqPrefix + "tgt-samerid"
	before := s.fixture.Snapshot()

	// Invocation 1: buffered, distinct body A.
	statusA, _, errA := s.chatFull(t, rid, 30*time.Second, chatOptions{
		content: "Same-rid distinct body A " + s.runID,
	})
	if errA != nil || statusA != httpOK {
		t.Fatalf("same-rid: invocation A status=%d err=%v", statusA, errA)
	}

	// Invocation 2: streamed, distinct body B (no cache hit on the pair).
	statusB, _, errB := s.chatFull(t, rid, 30*time.Second, chatOptions{
		stream:  true,
		content: "Same-rid distinct body B " + s.runID,
	})
	if errB != nil || statusB != httpOK {
		t.Fatalf("same-rid: invocation B status=%d err=%v", statusB, errB)
	}

	// Two independent provider receipts for the correlation id.
	arr, disp, recv := s.fixture.Counts(rid)
	if arr != 2 || disp != 2 || recv != 2 {
		t.Fatalf("same-rid: ledger arr/disp/recv = %d/%d/%d, want 2/2/2 (two independent paid calls)", arr, disp, recv)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 2 || delta.dispatches != 2 || delta.receipts != 2 {
		t.Fatalf("same-rid: ledger delta = %d/%d/%d, want 2/2/2", delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Two billed rows, each with the exact token usage (cost is validated
	// per-row by requireBilledRow on the correlation id's rows below).
	billed := 0
	for _, r := range s.oracleRequestLogRows(t, rid, s.oracleDB.orgID) {
		if r.Status == httpOK && r.TokensIn == fixturePromptTokens && r.TokensOut == fixtureCompletionTokens {
			billed++
		}
	}
	if billed != 2 {
		t.Fatalf("same-rid: billed rows = %d, want exactly 2 — two successful paid invocations must bill independently under one correlation id (0028 minted-identity domain)", billed)
	}
	for _, r := range s.oracleRequestLogRows(t, rid, s.oracleDB.orgID) {
		if r.Status == httpOK && (r.TokensIn != fixturePromptTokens || r.TokensOut != fixtureCompletionTokens) {
			t.Fatalf("same-rid: billed row carries unexpected usage tokens=%d/%d", r.TokensIn, r.TokensOut)
		}
	}

	// Wallet: TWO usage rows, EACH a signed -32 micro-USD debit.
	usage := s.oracleWalletUsageRows(t, rid, s.oracleDB.orgID)
	if len(usage) != 2 {
		t.Fatalf("same-rid: wallet usage rows = %d (%v), want exactly 2 — independent billing", len(usage), usage)
	}
	for i, micro := range usage {
		if micro != int64(-fixtureMicroUSDCost) {
			t.Fatalf("same-rid: usage row %d signed micro = %d, want %d (each invocation)", i+1, micro, -fixtureMicroUSDCost)
		}
	}
	t.Logf("same-rid: two independent wallet debits of -%d micro-USD each", fixtureMicroUSDCost)

	// Two DISTINCT minted invocation IDs, both reconciled via live delivery.
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — minted-identity independence unverifiable")
	}
	pollUntil(t, 6*time.Minute, "both same-rid admissions reconcile", func() error {
		adms := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		if len(adms) != 2 {
			return fmt.Errorf("admissions = %d (%s), want exactly 2 minted invocations", len(adms), fmtAdmissions(adms))
		}
		if adms[0].InvocationID == adms[1].InvocationID {
			return abortf("both invocations share minted id %s", adms[0].InvocationID)
		}
		for _, a := range adms {
			requireAdmissionVocabulary(t, a)
			switch a.State {
			case "reconciled":
				if a.ResolveReason.String != reasonEventLive {
					return abortf("reconciled reason %q, want %q", a.ResolveReason.String, reasonEventLive)
				}
			case "admitted":
				return fmt.Errorf("still admitted: %s", fmtAdmissions(adms))
			default:
				return abortf("state %s for a fully served invocation: %s", a.State, fmtAdmissions(adms))
			}
		}
		return nil
	})

	// Settlement intents: at most one per (invocation, kind) — two here.
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs > 2 {
		t.Fatalf("same-rid: settlement jobs = %d, want <= 2", jobs)
	}

	s.controlRequest(t, "samerid-post")
}
