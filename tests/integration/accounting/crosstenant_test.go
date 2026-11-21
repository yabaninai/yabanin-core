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

	// Exactly one billed row per org, bound to that org only.
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

	// Each wallet debited exactly once, signed, in its own org ledger.
	s.requireWalletChargedExactlyOnce(t, rid, orgA, "cross-tenant A")
	s.requireWalletChargedExactlyOnce(t, rid, orgB, "cross-tenant B")

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

	// Settlement intents stay org-scoped too.
	if jobsA, jobsB := s.oracleSettlementJobs(t, rid, orgA), s.oracleSettlementJobs(t, rid, orgB); jobsA > 1 || jobsB > 1 {
		t.Fatalf("cross-tenant: settlement jobs A/B = %d/%d, want <= 1 each", jobsA, jobsB)
	}

	s.controlRequest(t, "xt-post-a")
	s.controlRequestOpts(t, "xt-post-b", orgB, chatOptions{stream: true, apiKey: s.orgB.apiKey})
}
