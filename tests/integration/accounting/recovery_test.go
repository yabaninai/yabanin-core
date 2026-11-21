//go:build integration

package accounting

import (
	"strings"
	"testing"
	"time"
)

// TestAccountingAdmittedRequestRecovery is the owner-approved
// admitted-request recovery case: once a request is irrevocably dispatched
// to the provider (the fixture has accepted and recorded the dispatch, the
// response is held at the provider's barrier), killing only the gateway
// process and restarting it against the same storage must leave exactly
// one provider contact, a durable record that already existed at the
// barrier, a discoverable attempt after recovery, at most one charge, and
// the unresolved usage identified by persisted positive state rather than
// invented or silently dropped.
func TestAccountingAdmittedRequestRecovery(t *testing.T) {
	s := startStand(t)

	// Healthy control first: proves both detectors and the whole stand
	// work, so a missing durable record below is a product gap, not a
	// harness blind spot.
	s.controlRequest(t, "pre-crash")

	rid := s.reqPrefix + "tgt-recovery"
	s.fixture.Hold(rid)

	type chatResult struct {
		status int
		body   string
		err    error
	}
	result := make(chan chatResult, 1)
	go func() {
		status, body, err := s.chat(t, rid, 120*time.Second)
		result <- chatResult{status: status, body: body, err: err}
	}()

	// Harness validity: the provider must actually accept the dispatch
	// (barrier reached) while the client keeps waiting.
	if !s.fixture.WaitForDispatch(rid, 30*time.Second) {
		t.Fatalf("harness: target request never reached the provider dispatch barrier — cannot test recovery of an admitted request")
	}
	select {
	case r := <-result:
		t.Fatalf("harness: target request already finished (status=%d err=%v) before the crash — the case requires an in-flight request", r.status, r.err)
	case <-time.After(500 * time.Millisecond):
		// Still in flight, as required.
	}

	// Product assertion: a durable start record for this request must
	// exist NOW, before the crash — this is the fact that makes recovery
	// of an admitted request possible at all. The record must positively
	// exist (admission row, or a request_logs row that does not claim
	// successful completion); its absence is the baseline defect.
	s.requireDurableStartAtBarrier(t, rid)

	// Crash only the gateway. loggerd, PostgreSQL, Redis and the provider
	// keep running.
	before := s.fixture.Snapshot()
	s.killGatewaySIGKILL()

	// Release the held response: the dead gateway cannot receive it. The
	// dispatch stands, the client gets its connection torn down.
	s.fixture.ReleaseAll()
	select {
	case r := <-result:
		if r.err == nil && r.status == 200 {
			t.Fatalf("harness: client received a successful completion (%d) although the gateway died mid-flight", r.status)
		}
		t.Logf("harness: client observed the crash as expected (status=%d err=%v)", r.status, r.err)
	case <-time.After(10 * time.Second):
		t.Fatalf("harness: client request did not terminate after the gateway was killed")
	}

	// Restart the gateway against the same storage.
	s.restartGateway()

	// Independent provider oracle: the whole case (including the restart)
	// must have caused exactly one provider contact and one accepted
	// dispatch. A recovery that re-dispatches bills twice.
	s.fixture.VerifyEvidence()
	if delta := s.fixture.Since(before); delta.arrivals != 0 {
		t.Fatalf("product: recovery case: %d additional provider contact(s) after the accepted dispatch (restart must not re-dispatch)", delta.arrivals)
	}
	if a, d, r := s.fixture.Counts(rid); a != 1 || d != 1 || r != 0 {
		t.Fatalf("product: recovery case: provider arrivals/dispatches/receipts for %s = %d/%d/%d, want 1/1/0 (the response was never delivered back)", rid, a, d, r)
	}

	// Storage oracle: the attempt must be discoverable after recovery —
	// exactly one durable row for the request, bound to this stand's org.
	requireEventually(t, 90*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 1
	}, "product: recovery case: the crashed request %s is not discoverable in request_logs after gateway restart (rows=%d, admission rows=%d)",
		rid, s.oracleRequestLogCount(t, rid, s.oracleDB.orgID), s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID))
	if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 1 {
		t.Fatalf("product: recovery case: request_logs rows for %s = %d, want exactly 1 (duplicate accounting)", rid, n)
	}
	if n := s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID); n > 1 {
		t.Fatalf("product: recovery case: %d admission rows for %s, want at most 1 (duplicate accounting)", n, rid)
	}

	// Positive unresolved-usage state: the durable record must explicitly
	// carry that this request did not complete. A row claiming a 200
	// completion with zero delivered provider receipts is fabricated
	// success; silent absence is not accepted either (the row exists and
	// is examined here).
	s.requireUnresolvedDurableState(t, rid, "after restart")

	// No duplicate charge: at most one usage transaction and one
	// settlement job; a present usage transaction must be the signed
	// wallet debit of the independently known fixture billing — the crash
	// response was never delivered, so under the candidate contract the
	// charge may legitimately never have been taken (0 rows) or have been
	// taken exactly once as a signed -32 micro-USD debit.
	credits := s.oracleCreditTotals(t, rid, s.oracleDB.orgID)
	switch {
	case credits.UsageRows > 1:
		t.Fatalf("product: recovery case: %d usage transactions for %s, want at most 1 (duplicate charge)", credits.UsageRows, rid)
	case credits.UsageRows == 1:
		const expectedMicroUSD = int64(-fixtureMicroUSDCost) // signed wallet debit: 7 @ $2/M + 3 @ $6/M under zero markup
		if credits.SumMicroUSD != expectedMicroUSD {
			t.Errorf("product: recovery case: usage transaction for %s bills %d micro-USD, independently computed the signed debit %d",
				rid, credits.SumMicroUSD, expectedMicroUSD)
		}
	}
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs > 1 {
		t.Fatalf("product: recovery case: %d settlement jobs for %s, want at most 1", jobs, rid)
	}

	// The stand must still be healthy after recovery.
	s.controlRequest(t, "post-recovery")
	t.Logf("product: recovery case passed (request id %s)", rid)
}

// requireDurableStartAtBarrier asserts that a durable start record for
// rid positively exists while the request is irrevocably dispatched but
// still unanswered. It accepts either an admission row (candidate
// schema's dedicated start record) or a request_logs row that does not
// claim successful completion; observed evidence is logged. No record at
// all is the baseline defect: the gateway dispatches without a durable
// start.
func (s *stand) requireDurableStartAtBarrier(t *testing.T, rid string) {
	t.Helper()
	if state, ok := s.oracleAdmissionState(t, rid, s.oracleDB.orgID); ok {
		t.Logf("product: recovery case: durable start at barrier via request_admissions (state=%q)", state)
		return
	}
	if row, ok := s.oracleRequestRow(t, rid, s.oracleDB.orgID); ok {
		if row.OrgID != s.oracleDB.orgID {
			t.Fatalf("product: recovery case: barrier row for %s is bound to org %s, not this stand's org", rid, row.OrgID)
		}
		if row.Status == 200 {
			t.Fatalf("product: recovery case: barrier row for %s already claims a 200 completion while the provider response is still held — fabricated success", rid)
		}
		t.Logf("product: recovery case: durable start at barrier via request_logs (status=%d)", row.Status)
		return
	}
	t.Fatalf("product: recovery case: no durable start record exists for %s while the request is irrevocably dispatched (request_logs=0, request_admissions=0) — the gateway dispatches without a durable start",
		rid)
}

// requireUnresolvedDurableState asserts the persisted record positively
// identifies the request as unresolved (not successfully completed),
// rather than fabricating success. The success-vocabulary guard on the
// observed admission state exists so a renamed success marker cannot slip
// through; the actual observed values are logged as evidence.
func (s *stand) requireUnresolvedDurableState(t *testing.T, rid, phase string) {
	t.Helper()
	row, ok := s.oracleRequestRow(t, rid, s.oracleDB.orgID)
	if !ok {
		t.Fatalf("%s: recovery case: no request_logs row for %s to examine", phase, rid)
	}
	if row.OrgID != s.oracleDB.orgID {
		t.Fatalf("%s: recovery case: row for %s is bound to org %s, not this stand's org", phase, rid, row.OrgID)
	}
	if row.Status == 200 {
		t.Fatalf("%s: recovery case: request_logs row for %s claims a 200 completion although the provider response was never delivered back — unresolved usage was fabricated as success (receipts for this request: 0)", phase, rid)
	}
	t.Logf("product: recovery case: %s: unresolved usage positively persisted (status=%d, error=%q)", phase, row.Status, row.Err.String)
	if state, ok := s.oracleAdmissionState(t, rid, s.oracleDB.orgID); ok {
		if isSuccessState(state) {
			t.Fatalf("%s: recovery case: admission state for %s is %q — claims completion although the provider response was never delivered back", phase, rid, state)
		}
		t.Logf("product: recovery case: %s: admission state persisted as %q", phase, state)
	}
}

// isSuccessState reports whether an observed admission-state value is a
// completion/success claim. The vocabulary is broad on purpose: any
// success-shaped value fails the unresolved-state assertion.
func isSuccessState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "completed", "complete", "succeeded", "success", "successful", "settled", "done", "finished", "ok", "200":
		return true
	}
	return false
}
