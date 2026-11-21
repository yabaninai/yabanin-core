//go:build integration

package accountingext

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestExtCrossTenantScoping: the SAME client correlation id used by two
// tenants in overlapping time must remain fully tenant-scoped: each org sees
// only its own billed row, its own wallet debit, its own admissions; no
// org's accounting row, charge or admission appears under the other org.
// Per 0028, a minted uuid can never collide across orgs and the client
// X-Request-ID is correlation-only, so the shared id must NOT dedupe or
// cross-wire anything.
func TestExtCrossTenantScoping(t *testing.T) {
	s := startExtStand(t)
	s.waitGatewayHealthy(t)

	s.assertWalletConfigured(t, s.orgIDA, "org A")
	s.assertWalletConfigured(t, s.orgIDB, "org B")

	// Healthy controls in both orgs, one per response mode.
	s.controlRequest(t, "xt-pre-a", s.apiKeyA, modelA, s.orgIDA, false)
	s.controlRequest(t, "xt-pre-b", s.apiKeyB, modelB, s.orgIDB, true)

	rid := "xt-shared-" + s.runID

	// Org A completes a buffered request under the shared correlation id.
	ctxA, cancelA := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelA()
	resA := s.chatFor(ctxA, s.apiKeyA, modelA, rid, false)
	if resA.Err != nil || resA.StatusCode != http.StatusOK {
		t.Fatalf("org A request: status=%d err=%v", resA.StatusCode, resA.Err)
	}

	// Org B completes a streamed request under the SAME correlation id.
	ctxB, cancelB := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelB()
	resB := s.chatFor(ctxB, s.apiKeyB, modelB, rid, true)
	if resB.Err != nil || resB.StatusCode != http.StatusOK {
		t.Fatalf("org B request: status=%d err=%v", resB.StatusCode, resB.Err)
	}

	// Provider saw exactly two dispatches for the correlation id; neither
	// tenant's request was suppressed by the other's.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 2 || disp != 2 || recv != 2 {
		t.Fatalf("cross-tenant: ledger arr/disp/recv = %d/%d/%d, want 2/2/2 (independent invocations)", arr, disp, recv)
	}

	// Exactly one billed row per org, bound to that org only.
	rowsA := s.oracleRequestLogRows(t, s.orgIDA, rid)
	rowsB := s.oracleRequestLogRows(t, s.orgIDB, rid)
	if len(rowsA) != 1 || rowsA[0].Status != http.StatusOK {
		t.Fatalf("cross-tenant: org A rows = %+v, want exactly 1 billed", rowsA)
	}
	if len(rowsB) != 1 || rowsB[0].Status != http.StatusOK {
		t.Fatalf("cross-tenant: org B rows = %+v, want exactly 1 billed", rowsB)
	}
	s.requireBilledRow(t, s.orgIDA, rid, "cross-tenant A")
	s.requireBilledRow(t, s.orgIDB, rid, "cross-tenant B")

	// Each wallet debited exactly once, signed, in its own org ledger.
	s.requireWalletChargedExactlyOnce(t, s.orgIDA, rid, extCostMicroUSD, "cross-tenant A")
	s.requireWalletChargedExactlyOnce(t, s.orgIDB, rid, extCostMicroUSD, "cross-tenant B")

	// Admissions are org-bound (text column): one admission per org, never
	// leaked, vocabulary-valid; both eventually reconciled (both completed).
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): no admissions — cross-tenant admission binding unverifiable")
	}
	eventually(t, 6*time.Minute, pollEvery, "cross-tenant admissions settle per org", func() error {
		for _, tc := range []struct {
			org, label string
		}{{s.orgIDA, "A"}, {s.orgIDB, "B"}} {
			rows := s.oracleAdmissions(t, tc.org, rid)
			if len(rows) != 1 {
				return errf("org %s admissions = %d (%s), want exactly 1", tc.label, len(rows), fmtAdmissions(rows))
			}
			a := rows[0]
			requireAdmissionVocabulary(t, a)
			if a.OrgID != tc.org {
				return fatalf("org %s admission carries org %q (cross-tenant leak): %s", tc.label, a.OrgID, fmtAdmissions(rows))
			}
			if a.State == "voided" {
				return fatalf("org %s admission voided but the request completed: %s", tc.label, fmtAdmissions(rows))
			}
			if a.State != "reconciled" {
				return errf("org %s admission state %s, want reconciled: %s", tc.label, a.State, fmtAdmissions(rows))
			}
			if a.ResolveReas.String != reasonEventLive {
				return errf("org %s reconciled reason %q, want %q", tc.label, a.ResolveReas.String, reasonEventLive)
			}
		}
		return nil
	})

	// Settlement intents stay org-scoped too.
	if jobsA, jobsB := s.settlementJobCount(t, s.orgIDA, rid), s.settlementJobCount(t, s.orgIDB, rid); jobsA > 1 || jobsB > 1 {
		t.Fatalf("cross-tenant: settlement jobs A/B = %d/%d, want <= 1 each", jobsA, jobsB)
	}

	s.controlRequest(t, "xt-post-a", s.apiKeyA, modelA, s.orgIDA, false)
	s.controlRequest(t, "xt-post-b", s.apiKeyB, modelB, s.orgIDB, true)
}
