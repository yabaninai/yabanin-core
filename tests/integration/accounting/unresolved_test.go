//go:build integration

package accounting

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
// the unresolved row through the restart, bound to this tenant only (the
// same correlation id read under a foreign org must return nothing). The
// state/reason resolution is eventual: the accepted bound is the
// 15-minute grace contract, so the poll uses that window with early exit.
// Discovery through the admission row is sufficient; a request_logs row
// is NOT forced (and if one exists it must not claim success/usage/cost).
//
// Baseline (4e9895d) truth: request_admissions does not exist — the case
// must fail there with an explicit defect message, not pass vacuously.
func TestAccountingUnresolvedAfterGraceNoFacts(t *testing.T) {
	s := startStand(t)

	// Chargeability precondition + healthy paid control.
	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	hasAdmissions := s.oracleTableExists(t, "request_admissions")
	s.controlRequest(t, "unresolved-pre")
	var balanceBefore walletSnapshot
	if hasAdmissions {
		controlID := s.reqPrefix + "ctl-unresolved-pre"
		requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
			return s.oracleCreditTotals(t, controlID, s.oracleDB.orgID).UsageRows > 0
		}, "pre-control debit did not settle before measuring the fault window")
		s.requireWalletChargedExactlyOnce(t, controlID, s.oracleDB.orgID, "unresolved pre-control")
		balanceBefore = s.exactWalletSnapshot(t)
	}

	rid := s.reqPrefix + "tgt-unresolved"
	before := s.fixture.Snapshot()
	targetUUID := s.crashHeldChat(t, rid, chatOptions{}, 60*time.Second)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1}, s.fixture.Since(before))

	// Deterministic grace expiry (after the crash, target-only).
	if hasAdmissions {
		s.ageAdmissionByInvocationPastGrace(t, targetUUID, s.oracleDB.orgID)
	}

	s.restartGateway()

	if !hasAdmissions {
		t.Fatalf("PRODUCT DEFECT (baseline): no explicit unresolved identification mechanism — "+
			"crashed dispatched request %s has no request_admissions row to transition to 'unresolved'; "+
			"the start is silently lost instead of explicitly visible", rid)
	}

	// Strict unresolved for the EXACT captured UUID: poll until precisely
	// one admission exists under this correlation id, it is the barrier
	// UUID, and it is 'unresolved' with the exact contract reason. The
	// window is the accepted eventual bound (15 minutes, matching the
	// grace contract) with early exit on success. 'admitted' (stuck),
	// 'voided' (claims proven-never-dispatched — false, the fixture
	// observed the dispatch) and 'reconciled' (claims terminal evidence
	// that does not exist) are all explicit defects, as is any duplicate
	// mint under the single HTTP invocation.
	pollUntil(t, 15*time.Minute, "target admission reaches 'unresolved'", func() error {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		return unresolvedState(t, rows, targetUUID)
	})
	t.Logf("target: admission %s reached 'unresolved' with reason %s", targetUUID, reasonGraceElapsed)

	s.requireUnresolvedEvidence(t, rid, balanceBefore)

	// Post-recovery control: the system still serves and charges exactly once.
	s.controlRequest(t, "unresolved-post")
}

type walletSnapshot struct {
	Cents             int64
	RemainderMicroUSD int64
}

func (s *stand) exactWalletSnapshot(t *testing.T) walletSnapshot {
	t.Helper()
	var snapshot walletSnapshot
	err := s.oracleDB.db.QueryRow("SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id=$1", s.oracleDB.orgID).Scan(&snapshot.Cents, &snapshot.RemainderMicroUSD)
	if err != nil {
		t.Fatalf("read exact wallet balance: %v", err)
	}
	return snapshot
}

func unresolvedState(t *testing.T, rows []admissionRow, targetUUID string) error {
	t.Helper()
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
}

func (s *stand) requireUnresolvedEvidence(t *testing.T, rid string, balanceBefore walletSnapshot) {
	t.Helper()
	// Tenant binding: the unresolved row must surface only under this
	// stand's org — the same correlation id read under a foreign tenant
	// must return nothing (storage-level tenant scope; org-facing API
	// exposure is reviewed separately).
	if foreign := s.oracleAdmissions(t, rid, "org-not-this-tenant"); len(foreign) != 0 {
		t.Fatalf("unresolved: admission rows for %s leaked under a foreign org: %s", rid, fmtAdmissions(foreign))
	}

	// No terminal evidence may ever have appeared: the classification is
	// 'no terminal facts' — a facts row here would mean the unresolved
	// state sits on fabricated evidence.
	if n := s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("unresolved: %d terminal facts row(s) for %s although the provider response was never delivered back — fabricated evidence behind the unresolved classification", n, rid)
	}

	// No invented usage, no wallet debit, no fabricated request_logs claim.
	s.requireNoWalletDebit(t, rid, s.oracleDB.orgID, "unresolved")
	if balanceAfter := s.exactWalletSnapshot(t); balanceAfter != balanceBefore {
		t.Fatalf("unresolved: wallet balance moved %+v -> %+v with no chargeable evidence for %s", balanceBefore, balanceAfter, rid)
	}
	logRows := s.oracleRequestLogRows(t, rid, s.oracleDB.orgID)
	requireNoFabricatedRequestLogRows(t, rid, s.oracleDB.orgID, logRows, "unresolved")
	if len(logRows) == 0 {
		t.Logf("unresolved: no request_logs row for %s (acceptable: discovery through the admission row)", rid)
	} else {
		t.Logf("unresolved: content-free request_logs row present for %s (acceptable: no usage claimed)", rid)
	}
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs != 0 {
		t.Fatalf("unresolved: %d settlement job(s) for %s although zero terminal facts exist — settlement without evidence", jobs, rid)
	}

}

// errTransient wraps a not-yet state for pollUntil (opposite of abortf).
func errTransient(msg string) error { return fmt.Errorf("poll: %s", msg) }

// crashHeldChat kills the gateway after one provider dispatch and before the
// provider returns. Any candidate admission must already exist at this barrier.
func (s *stand) crashHeldChat(t *testing.T, rid string, opts chatOptions, timeout time.Duration) string {
	t.Helper()
	s.fixture.Hold(rid)
	type outcome struct {
		status int
		err    error
	}
	done := make(chan outcome, 1)
	go func() { status, _, err := s.chatFull(t, rid, timeout, opts); done <- outcome{status, err} }()
	require.True(t, s.fixture.WaitForDispatch(rid, 20*time.Second), "missing provider dispatch")
	a, d, r := s.fixture.Counts(rid)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1}, fixtureTotals{arrivals: a, dispatches: d, receipts: r})
	id := ""
	if s.oracleTableExists(t, "request_admissions") {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		require.Len(t, rows, 1)
		require.Equal(t, "admitted", rows[0].State)
		id = rows[0].InvocationID
		require.NotEmpty(t, id)
	}
	s.killGatewaySIGKILL()
	s.fixture.ReleaseAll()
	select {
	case o := <-done:
		require.False(t, o.err == nil && o.status == httpOK, "client received a successful response after the crash")
	case <-time.After(10 * time.Second):
		t.Fatal("client request did not terminate after gateway crash")
	}
	return id
}
