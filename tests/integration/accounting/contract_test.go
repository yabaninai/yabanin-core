//go:build integration

package accounting

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Contract literals from the consumer record (2026-11-21): the reconciler's
// resolve_reason vocabulary is part of the product's observable contract, so
// the oracle binds to the exact published strings, never a pattern.
const (
	reasonEventLive    = "event_delivered"
	reasonRecovered    = "recovered_from_facts"
	reasonGraceElapsed = "grace_elapsed_no_terminal_facts"
)

// pollAbort wraps an error whose observation is already a verdict: polling
// must stop and fail immediately instead of retrying, because no future
// sweep can repair it (e.g. 'voided' for a request the fixture observed
// dispatched, or a reconciled reason that contradicts the injected fault).
type pollAbort struct{ err error }

func (e pollAbort) Error() string { return e.err.Error() }

// abortf marks a poll error as terminal for pollUntil.
func abortf(format string, args ...any) error { return pollAbort{fmt.Errorf(format, args...)} }

// pollUntil polls cond until deadline. A nil return passes; a pollAbort
// fails immediately; any other error is retried and reported on timeout.
// Distinguishing the two is what keeps a wrong-terminal-state observation
// from being retried into an accidental pass.
func pollUntil(t *testing.T, d time.Duration, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		err := cond()
		if err == nil {
			return
		}
		var abort pollAbort
		if errors.As(err, &abort) {
			t.Fatalf("%s: %v", what, abort.err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// admissionStates is the 0028 lifecycle vocabulary. Observing any other
// value is a product defect in itself, not an unknown to tolerate.
var admissionStates = map[string]bool{
	"admitted":   true,
	"voided":     true,
	"reconciled": true,
	"unresolved": true,
}

// requireAdmissionVocabulary fails on any admission state outside the
// published 0028 lifecycle vocabulary.
func requireAdmissionVocabulary(t *testing.T, a admissionRow) {
	t.Helper()
	if !admissionStates[a.State] {
		t.Fatalf("product: admission state %q is outside the 0028 vocabulary %q", a.State, "admitted|voided|reconciled|unresolved")
	}
}

// fmtAdmissions renders admission rows for failure messages and logs.
func fmtAdmissions(rows []admissionRow) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, a := range rows {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "{inv=%s state=%s resolved_at=%v reason=%q}",
			a.InvocationID, a.State, a.ResolvedAt.Time.Format(time.RFC3339), a.ResolveReason.String)
	}
	b.WriteByte(']')
	return b.String()
}

// controlRequestOpts issues a healthy control request with explicit
// credentials and response mode, bound to orgID, and asserts the same full
// round trip as controlRequest: client response, exactly one whole-ledger
// provider contact, retained evidence and a durable billed row carrying the
// independently known usage and rates. The org binding is explicit so a
// second tenant's control can never be satisfied by the first tenant's rows.
func (s *stand) controlRequestOpts(t *testing.T, label, orgID string, opts chatOptions) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := s.reqPrefix + "ctl-" + label
	status, body, err := s.chatFull(t, rid, 30*time.Second, opts)
	if err != nil || status != httpOK {
		t.Fatalf("harness: control request %s failed (status=%d err=%v body=%s): stand or fault restoration is broken, product assertions below would be meaningless", label, status, err, body)
	}
	if !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("harness: control request %s: unexpected body %q", label, body)
	}
	s.fixture.VerifyEvidence()
	delta := s.fixture.Since(before)
	if delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		a, d, r := s.fixture.Counts(rid)
		t.Fatalf("harness: control %s: whole-ledger delta arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1 (id-matched %d/%d/%d); the provider-contact detector itself must be proven by a passing control before any fault window",
			label, delta.arrivals, delta.dispatches, delta.receipts, a, d, r)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, orgID) == 1
	}, "harness: control request %s never became durable in request_logs", label)
	s.requireBilledRow(t, rid, orgID, "harness: control "+label)
	t.Logf("harness: control %s ok (request id %s)", label, rid)
}

// assertWalletConfigured proves the chargeability precondition for an org:
// a wallet row with a positive balance. Without it a later zero-charge
// observation could be excused as refused-for-funds instead of an
// accounting property. Returns the observed balance for delta assertions.
func (s *stand) assertWalletConfigured(t *testing.T, orgID, phase string) int64 {
	t.Helper()
	cents, ok := s.oracleWalletBalance(t, orgID)
	if !ok {
		t.Fatalf("harness: %s: org %s has no wallet row (org_credits) — the chargeability precondition is unmet", phase, orgID)
	}
	if cents <= 0 {
		t.Fatalf("harness: %s: org %s wallet balance is %d cents — charges would be refused for funds, not for accounting properties", phase, orgID, cents)
	}
	return cents
}

// requireExactlyOneBilledRow asserts exactly one successful request_logs
// row for rid in orgID. Callers with additional per-row obligations (usage
// values, cost) compose it with requireBilledRow.
func (s *stand) requireExactlyOneBilledRow(t *testing.T, rid, orgID, phase string) {
	t.Helper()
	billed := 0
	for _, r := range s.oracleRequestLogRows(t, rid, orgID) {
		if r.Status == http.StatusOK {
			billed++
		}
	}
	if billed != 1 {
		t.Fatalf("%s: billed (200) request_logs rows for %s = %d, want exactly 1", phase, rid, billed)
	}
}

// requireNoWalletDebit asserts zero usage transactions for rid in orgID —
// the no-charge outcome for invocations that never delivered terminal
// evidence.
func (s *stand) requireNoWalletDebit(t *testing.T, rid, orgID, phase string) {
	t.Helper()
	if c := s.oracleCreditTotals(t, rid, orgID); c.UsageRows != 0 {
		t.Fatalf("%s: %d wallet usage transaction(s) for %s, want 0 (no terminal evidence was ever delivered)", phase, c.UsageRows, rid)
	}
}

// requireCrashedRowSilent asserts that any non-successful request_logs row
// for rid (the crashed invocation's materialization, if any) claims no
// usage or cost. Exactly one successful row is allowed and checked
// separately.
func (s *stand) requireCrashedRowSilent(t *testing.T, rid, orgID, phase string) {
	t.Helper()
	for _, r := range s.oracleRequestLogRows(t, rid, orgID) {
		if r.Status == http.StatusOK {
			continue // the completed invocation, validated elsewhere
		}
		if r.TokensIn > 0 || r.TokensOut > 0 || r.CostUSD > 0 {
			t.Fatalf("%s: crashed invocation's request_logs row invents usage/cost for %s: status=%d tokens=%d/%d cost=%v",
				phase, rid, r.Status, r.TokensIn, r.TokensOut, r.CostUSD)
		}
	}
}
