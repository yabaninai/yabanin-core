//go:build integration

package accounting

import (
	"testing"
	"time"
)

// TestAccountingAdmittedRequestRecovery is the owner-approved
// admitted-request recovery case: once a request is irrevocably dispatched
// to the provider (the fixture has accepted and recorded the dispatch, the
// response is held at the provider's barrier), killing only the gateway
// process and restarting it against the same storage must, BEFORE the
// grace window has elapsed, preserve the in-flight identity of the
// admitted request: exactly one provider contact (no redispatch), the
// same single durable start record carrying the same server-minted
// invocation identity still in state 'admitted' (not voided, not
// reconciled, not prematurely unresolved), no fabricated terminal
// evidence, and no charge — with zero terminal facts, any debit is a
// charge without evidence. Legacy request_logs rows, where a build still
// writes them, must never claim success or usage for the crashed request.
// The EVENTUAL explicit unresolved identification after the grace window
// is the sibling case (TestAccountingUnresolvedAfterGraceNoFacts), not
// this one. Discoverability here is asserted at storage level; whether
// the org-facing history API exposes this state is reviewed separately
// and is neither proven nor weakened by this case.
func TestAccountingAdmittedRequestRecovery(t *testing.T) {
	s := startStand(t)

	// Healthy control first: proves both detectors and the whole stand
	// work, so a missing durable record below is a product gap, not a
	// harness blind spot.
	s.controlRequest(t, "pre-crash")

	rid := s.reqPrefix + "tgt-recovery"
	disconnected := s.fixture.Hold(rid)

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
	// of an admitted request possible at all. Its identity is captured
	// here so the post-restart window can prove it is the SAME request.
	start := s.requireDurableStartAtBarrier(t, rid)

	// Crash only the gateway. loggerd, PostgreSQL, Redis and the provider
	// keep running.
	before := s.fixture.Snapshot()
	s.killGatewaySIGKILL()

	// Release the held response: the dead gateway cannot receive it. The
	// dispatch stands, the client gets its connection torn down.
	s.fixture.releaseAfterDisconnect(disconnected)
	select {
	case r := <-result:
		if r.err == nil && r.status == httpOK {
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

	// Storage oracle, pre-grace window: the restarted system must still
	// know this exact in-flight request — same identity, still admitted,
	// no fabricated terminal evidence, no charge — and must not have
	// silently dropped it.
	s.requireInFlightIdentityBeforeGrace(t, rid, start)

	// The stand must still be healthy after recovery.
	s.controlRequest(t, "post-recovery")
	t.Logf("product: recovery case passed (request id %s)", rid)
}

// durableStart captures what the dispatch barrier required: which record
// class proved the dispatched request had a durable start and — for an
// admission-backed start — the exact server-minted invocation UUID that
// every post-restart identity assertion must match.
type durableStart struct {
	invocationUUID string // "" when the start record was legacy request_logs
	hadRequestLog  bool
}

// requireDurableStartAtBarrier asserts that a durable start record for
// rid positively exists while the request is irrevocably dispatched but
// still unanswered, and returns its captured identity. When the
// request_admissions table exists, the record must be exactly one row in
// state 'admitted' — pre-terminal by definition while the response is
// held — and its UUID is captured. Otherwise a request_logs row that does
// not claim successful completion is accepted as the legacy start
// record. No record at all is the baseline defect: the gateway dispatches
// without a durable start.
func (s *stand) requireDurableStartAtBarrier(t *testing.T, rid string) durableStart {
	t.Helper()
	if s.oracleTableExists(t, "request_admissions") {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		if len(rows) != 1 {
			t.Fatalf("product: recovery case: %d admission rows for %s at the dispatch barrier (%s), want exactly 1 — the gateway dispatches without a durable admitted start",
				len(rows), rid, fmtAdmissions(rows))
		}
		a := rows[0]
		requireAdmissionVocabulary(t, a)
		if a.State != "admitted" {
			t.Fatalf("product: recovery case: admission state at the barrier is %q, want 'admitted' (the response is still held; any terminal claim is fabricated)", a.State)
		}
		t.Logf("product: recovery case: durable start at barrier via request_admissions (invocation=%s state=%q)", a.InvocationID, a.State)
		return durableStart{invocationUUID: a.InvocationID}
	}
	row, ok := s.oracleRequestRow(t, rid, s.oracleDB.orgID)
	if !ok {
		t.Fatalf("product: recovery case: no durable start record exists for %s while the request is irrevocably dispatched (request_logs=0, request_admissions table absent) — the gateway dispatches without a durable start",
			rid)
	}
	if row.OrgID != s.oracleDB.orgID {
		t.Fatalf("product: recovery case: barrier row for %s is bound to org %s, not this stand's org", rid, row.OrgID)
	}
	if row.Status == httpOK {
		t.Fatalf("product: recovery case: barrier row for %s already claims a 200 completion while the provider response is still held — fabricated success", rid)
	}
	t.Logf("product: recovery case: durable start at barrier via request_logs (status=%d)", row.Status)
	return durableStart{hadRequestLog: true}
}

// requireInFlightIdentityBeforeGrace verifies the post-restart, pre-grace
// window of a dispatched-but-never-answered request: it must remain
// discoverable as the SAME in-flight admission — exactly one row, the
// barrier UUID, still 'admitted' with nothing resolved, because the grace
// window has not elapsed (a premature 'unresolved' is as wrong as a
// fabricated 'reconciled' or a false 'voided') — with no terminal
// evidence, no legacy success/usage claim and no charge: zero terminal
// facts must mean zero usage transactions and zero settlement jobs.
func (s *stand) requireInFlightIdentityBeforeGrace(t *testing.T, rid string, start durableStart) {
	t.Helper()
	if start.invocationUUID != "" {
		s.requireAdmissionIdentityBeforeGrace(t, rid, start)
	}

	// No fabricated terminal evidence: the provider response was never
	// delivered back, so no terminal facts row may exist for this request.
	if n := s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: recovery case: %d terminal facts row(s) for %s although the provider response was never delivered back — fabricated terminal evidence", n, rid)
	}

	// Legacy projection, negative-only: no request_logs row may claim
	// success or usage for the crashed request, and duplicates are
	// duplicate accounting. Pre-grace this is NOT a materialization
	// requirement — the admission row is the durable record — so zero
	// rows is acceptable on an admissions build.
	logRows := s.oracleRequestLogRows(t, rid, s.oracleDB.orgID)
	requireNoFabricatedRequestLogRows(t, rid, s.oracleDB.orgID, logRows, "product: recovery case: after restart")
	requireCrashedRequestDiscoverable(t, rid, start, logRows)

	// No charge without evidence: zero terminal facts must mean zero
	// usage transactions and zero settlement jobs for this request.
	credits := s.oracleCreditTotals(t, rid, s.oracleDB.orgID)
	if credits.UsageRows != 0 {
		t.Fatalf("product: recovery case: %d usage transaction(s) for %s totaling %d micro-USD although zero terminal facts exist — a debit without terminal evidence",
			credits.UsageRows, rid, credits.SumMicroUSD)
	}
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs != 0 {
		t.Fatalf("product: recovery case: %d settlement job(s) for %s although zero terminal facts exist — settlement without evidence", jobs, rid)
	}
}

// requireAdmissionIdentityBeforeGrace asserts the admission row itself
// survived the restart unchanged: exactly one row under the barrier
// invocation UUID, still 'admitted', nothing resolved.
func (s *stand) requireAdmissionIdentityBeforeGrace(t *testing.T, rid string, start durableStart) {
	t.Helper()
	rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	switch {
	case len(rows) == 0:
		t.Fatalf("product: recovery case: the admitted request %s vanished from request_admissions after the restart — silently dropped, not recoverable", rid)
	case len(rows) > 1:
		t.Fatalf("product: recovery case: %d admission rows for %s after the restart (%s), want exactly the barrier row — duplicate accounting", len(rows), rid, fmtAdmissions(rows))
	}
	a := rows[0]
	requireAdmissionVocabulary(t, a)
	if a.InvocationID != start.invocationUUID {
		t.Fatalf("product: recovery case: in-flight identity changed across the restart: barrier invocation %s, now %s — the admitted request was replaced, not recovered", start.invocationUUID, a.InvocationID)
	}
	if a.State != "admitted" {
		t.Fatalf("product: recovery case: admission %s is %q before the grace window has elapsed (%s), want 'admitted' — premature unresolved, or a void/reconcile fabricated without evidence", a.InvocationID, a.State, fmtAdmissions(rows))
	}
	if a.ResolvedAt.Valid {
		t.Fatalf("product: recovery case: admission %s carries resolved_at=%s while still admitted pre-grace — contradictory resolution record", a.InvocationID, a.ResolvedAt.Time.Format(time.RFC3339))
	}
	t.Logf("product: recovery case: in-flight identity preserved across restart (invocation=%s state=%q)", a.InvocationID, a.State)
}

// requireCrashedRequestDiscoverable asserts the crashed request is still
// discoverable somewhere after the restart: with an admission row, zero
// request_logs rows are acceptable pre-grace (the admission row is the
// durable record); without one, the request_logs start row itself must
// have survived.
func requireCrashedRequestDiscoverable(t *testing.T, rid string, start durableStart, logRows []requestRow) {
	t.Helper()
	switch {
	case start.invocationUUID == "" && len(logRows) == 0 && start.hadRequestLog:
		t.Fatalf("product: recovery case: the request_logs start row for %s did not survive the gateway restart — the attempt became undiscoverable", rid)
	case start.invocationUUID == "" && len(logRows) == 0:
		t.Fatalf("product: recovery case: crashed request %s is discoverable nowhere after restart (request_logs=0, request_admissions table absent)", rid)
	case start.invocationUUID != "" && len(logRows) == 0:
		t.Logf("product: recovery case: no request_logs row for %s (acceptable pre-grace: the admission row is the durable record; legacy materialization is not waited for)", rid)
	}
}

// requireNoFabricatedRequestLogRows is the negative-only legacy oracle
// shared by the recovery cases: whatever request_logs rows exist for a
// request whose provider response was never delivered back, at most one
// may exist (duplicates are duplicate accounting), it must be bound to
// this stand's org, and it must not claim success (200) or carry
// usage/cost — fabricated success for a crashed request.
func requireNoFabricatedRequestLogRows(t *testing.T, rid, orgID string, rows []requestRow, phase string) {
	t.Helper()
	if len(rows) > 1 {
		t.Fatalf("%s: %d request_logs rows for %s, want at most 1 — duplicate accounting", phase, len(rows), rid)
	}
	for _, r := range rows {
		if r.OrgID != orgID {
			t.Fatalf("%s: request_logs row for %s is bound to org %s, not org %s", phase, rid, r.OrgID, orgID)
		}
		if r.Status == httpOK {
			t.Fatalf("%s: request_logs row for %s claims a 200 completion although the provider response was never delivered back — fabricated success", phase, rid)
		}
		if r.TokensIn > 0 || r.TokensOut > 0 || r.CostUSD > 0 {
			t.Fatalf("%s: request_logs row for %s carries usage (tokens=%d/%d cost=%v) although the response was never delivered back — invented usage", phase, rid, r.TokensIn, r.TokensOut, r.CostUSD)
		}
	}
}
