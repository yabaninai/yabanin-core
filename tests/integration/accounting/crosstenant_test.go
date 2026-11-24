//go:build integration

package accounting

import (
	"fmt"
	"testing"
	"time"
)

// TestAccountingCrossTenantScoping: the SAME client correlation id used by
// two tenants in overlapping time must remain fully tenant-scoped: each
// org sees only its own billed row, its own wallet debit, its own
// admissions; no org's accounting row, charge or admission appears under
// the other org. Per 0028, a minted uuid can never collide across orgs and
// the client X-Request-ID is correlation-only, so the shared id must NOT
// dedupe or cross-wire anything.
func TestAccountingCrossTenantScoping(t *testing.T) {
	s := startStand(t)

	// The neighbor tenant: same controlled-elevation seed path, its own
	// wallet, key and zero-markup provisioning.
	s.seedSecondOrg(t)
	orgA, orgB := s.oracleDB.orgID, s.orgB.orgID

	s.assertWalletConfigured(t, orgA, "org A")
	s.assertWalletConfigured(t, orgB, "org B")

	// Healthy controls in both orgs, one per response mode.
	s.controlRequest(t, "xt-pre-a")
	s.controlRequestOpts(t, "xt-pre-b", orgB, chatOptions{stream: true, apiKey: s.orgB.apiKey})

	rid := s.reqPrefix + "tgt-xt-shared"
	s.runSharedCorrelationPair(t, rid)

	// The consumer writes the logs asynchronously. Wait for both durable
	// reconciliation records before inspecting either tenant's ledger.
	s.requireAdmissionsReconciledPerOrg(t, rid, orgA, orgB)

	// Exactly one billed row per org, bound to that org only.
	s.requireSharedCorrelationBilled(t, rid, orgA, orgB)

	idA := s.requireCrossTenantDebit(t, rid, orgA)
	idB := s.requireCrossTenantDebit(t, rid, orgB)
	if idA == idB {
		t.Fatal("independent tenant requests received the same invocation ID")
	}
	for _, pair := range []struct{ invocation, otherOrg string }{{idA, orgB}, {idB, orgA}} {
		if n := s.oracleCount(t, `SELECT count(*) FROM credit_transactions WHERE invocation_id=$1::uuid AND org_id=$2`, pair.invocation, pair.otherOrg); n != 0 {
			t.Fatalf("invocation %s has %d credit transactions in the other tenant", pair.invocation, n)
		}
	}

	s.controlRequest(t, "xt-post-a")
	s.controlRequestOpts(t, "xt-post-b", orgB, chatOptions{stream: true, apiKey: s.orgB.apiKey})
}

// Debit settlement is asynchronous even after request admission reconciliation.
func (s *stand) requireCrossTenantDebit(t *testing.T, rid, org string) string {
	t.Helper()
	requireEventually(t, time.Minute, 100*time.Millisecond, func() bool {
		return s.oracleCount(t, `SELECT count(*) FROM settlement_jobs
			WHERE request_id=$1 AND org_id=$2 AND status='settled'
			  AND charge_kind IN ('resale_deduction','team_spend')`, rid, org) == 2
	}, "the tenant must settle both the wallet debit and the team spend")
	id := s.requireUUIDKeyedCharge(t, rid, org, "cross-tenant")
	c := s.oracleUsageByInvocation(t, id, org)
	if c.SumCents > 0 || c.TopupRows != 0 {
		t.Fatalf("unexpected wallet totals for invocation %s: %+v", id, c)
	}
	s.requireSettlementIntents(t, rid, org, "cross-tenant", map[string]int{"resale_deduction": 1, "team_spend": 1})
	const scopedCharges = `SELECT count(*) FROM settlement_jobs j
		WHERE j.org_id=$1 AND j.request_id=$2 AND j.invocation_id=$3::uuid
		  AND j.amount_micro_usd=$4 AND j.status='settled'
		  AND (j.charge_kind='resale_deduction' OR
		       (j.charge_kind='team_spend' AND EXISTS (
		            SELECT 1 FROM organizations_teams team
		            WHERE team.id::text=j.payload->>'team_id' AND team.org_id::text=j.org_id)))`
	if got := s.oracleCount(t, scopedCharges, org, rid, id, fixtureMicroUSDCost); got != 2 {
		t.Fatalf("tenant %s invocation %s has %d settled, correctly attributed charges of %d micro-USD, want 2", org, id, got, fixtureMicroUSDCost)
	}
	return id
}

// runSharedCorrelationPair drives the buffered org-A request and the
// streamed org-B request under the SAME client correlation id, then
// asserts the provider saw exactly two independent dispatches: the
// shared id must not dedupe or cross-wire either tenant's invocation.
func (s *stand) runSharedCorrelationPair(t *testing.T, rid string) {
	t.Helper()

	// Org A completes a buffered request under the shared correlation id.
	statusA, _, errA := s.chatFull(t, rid, 30*time.Second, chatOptions{
		content: "cross-tenant org A body " + s.runID,
	})
	if errA != nil || statusA != httpOK {
		t.Fatalf("cross-tenant: org A request status=%d err=%v", statusA, errA)
	}

	// Org B completes a streamed request under the SAME correlation id.
	statusB, _, errB := s.chatFull(t, rid, 30*time.Second, chatOptions{
		stream:  true,
		apiKey:  s.orgB.apiKey,
		content: "cross-tenant org B body " + s.runID,
	})
	if errB != nil || statusB != httpOK {
		t.Fatalf("cross-tenant: org B request status=%d err=%v", statusB, errB)
	}

	// Provider saw exactly two dispatches for the correlation id; neither
	// tenant's request was suppressed by the other's.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 2 || disp != 2 || recv != 2 {
		t.Fatalf("cross-tenant: ledger arr/disp/recv = %d/%d/%d, want 2/2/2 (independent invocations)", arr, disp, recv)
	}
}

// requireSharedCorrelationBilled asserts each org's request log holds
// exactly one httpOK billed row for the shared correlation id.
func (s *stand) requireSharedCorrelationBilled(t *testing.T, rid, orgA, orgB string) {
	t.Helper()
	rowsA := s.oracleRequestLogRows(t, rid, orgA)
	rowsB := s.oracleRequestLogRows(t, rid, orgB)
	if len(rowsA) != 1 || rowsA[0].Status != httpOK {
		t.Fatalf("cross-tenant: org A rows = %+v, want exactly 1 billed", rowsA)
	}
	if len(rowsB) != 1 || rowsB[0].Status != httpOK {
		t.Fatalf("cross-tenant: org B rows = %+v, want exactly 1 billed", rowsB)
	}
	s.requireBilledRow(t, rid, orgA, "cross-tenant A")
	s.requireBilledRow(t, rid, orgB, "cross-tenant B")
}

// requireAdmissionsReconciledPerOrg waits until every org holds exactly
// one vocabulary-valid admission for the shared correlation id in state
// reconciled with the live-event reason: completed requests must never
// void and must never appear under the neighbor org.
func (s *stand) requireAdmissionsReconciledPerOrg(t *testing.T, rid, orgA, orgB string) {
	t.Helper()
	// Admissions are org-bound (text column): one admission per org, never
	// leaked, vocabulary-valid; both eventually reconciled (both completed).
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — cross-tenant admission binding unverifiable")
	}
	pollUntil(t, 6*time.Minute, "cross-tenant admissions settle per org", func() error {
		for _, tc := range []struct {
			org, label string
		}{{orgA, "A"}, {orgB, "B"}} {
			rows := s.oracleAdmissions(t, rid, tc.org)
			if len(rows) != 1 {
				return fmt.Errorf("org %s admissions = %d (%s), want exactly 1", tc.label, len(rows), fmtAdmissions(rows))
			}
			a := rows[0]
			requireAdmissionVocabulary(t, a)
			if a.State == "voided" {
				return abortf("org %s admission voided but the request completed: %s", tc.label, fmtAdmissions(rows))
			}
			if a.State != "reconciled" {
				return fmt.Errorf("org %s admission state %s, want reconciled: %s", tc.label, a.State, fmtAdmissions(rows))
			}
			if a.ResolveReason.String != reasonEventLive {
				return fmt.Errorf("org %s reconciled reason %q, want %q", tc.label, a.ResolveReason.String, reasonEventLive)
			}
		}
		return nil
	})
}
