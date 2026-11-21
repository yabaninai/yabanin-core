//go:build integration

package accountingext

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Oracle: privileged owner-role DB observer/injector plus response decoding.
// Org typing is bound to the real schemas:
//   - request_logs.org_id        uuid  -> cast $n::uuid
//   - request_admissions.org_id  text  -> plain string (0028)
//   - credit_transactions.org_id text  -> plain string (0001)
//   - settlement_jobs.org_id     text  -> plain string (0001)

const admissionStateVocabulary = "admitted|voided|reconciled|unresolved"

// Contract literals from the published consumer record
// (2026-11-21-preview2-accounting-consumer.md, sha256 4cba809d...).
const (
	reasonGraceElapsed = "grace_elapsed_no_terminal_facts"
	reasonEventLive    = "event_delivered"
	reasonRecovered    = "recovered_from_facts"
)

type extRequestLogRow struct {
	Status    int
	TokensIn  int
	TokensOut int
	CostUSD   float64
	HasInvoc  bool
}

type extAdmissionRow struct {
	InvocationID string
	OrgID        string
	Kind         string
	State        string
	ResolveReas  sql.NullString
	AdmittedAt   time.Time
	ResolvedAt   sql.NullTime
}

type extWalletRow struct {
	AmountMicro  int64 // signed: usage rows are negative (pkg/credits Deduct)
	AmountCents  int64
	BalanceAfter int64
	Type         string
}

func (s *extStand) oracleQueryCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func (s *extStand) oracleTableExists(t *testing.T, table string) bool {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	var n int
	err := s.owner.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = $1`, table).Scan(&n)
	if err != nil {
		t.Fatalf("oracle: table-exists probe for %s: %v", table, err)
	}
	return n > 0
}

// oracleRequestLogCount: request_logs.org_id is uuid.
func (s *extStand) oracleRequestLogCount(t *testing.T, orgID, rid string) int {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	var n int
	err := s.owner.QueryRowContext(ctx, `
		SELECT count(*) FROM request_logs
		WHERE request_id = $1 AND org_id = $2::uuid`, rid, orgID).Scan(&n)
	if err != nil {
		t.Fatalf("oracle: request_logs count: %v", err)
	}
	return n
}

func (s *extStand) oracleRequestLogRows(t *testing.T, orgID, rid string) []extRequestLogRow {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	rows, err := s.owner.QueryContext(ctx, `
		SELECT COALESCE(status_code, 0), COALESCE(tokens_in, 0), COALESCE(tokens_out, 0),
		       COALESCE(cost_in_usd, 0), invocation_id IS NOT NULL
		FROM request_logs
		WHERE request_id = $1 AND org_id = $2::uuid`, rid, orgID)
	if err != nil {
		t.Fatalf("oracle: request_logs rows: %v", err)
	}
	defer rows.Close()
	var out []extRequestLogRow
	for rows.Next() {
		var r extRequestLogRow
		if err := rows.Scan(&r.Status, &r.TokensIn, &r.TokensOut, &r.CostUSD, &r.HasInvoc); err != nil {
			t.Fatalf("oracle: request_logs scan: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// oracleAdmissions: 0028 text org binding; one row per minted invocation,
// keyed by client_request_id correlation.
func (s *extStand) oracleAdmissions(t *testing.T, orgID, rid string) []extAdmissionRow {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return nil
	}
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	rows, err := s.owner.QueryContext(ctx, `
		SELECT invocation_id::text, org_id, kind, state, resolve_reason, admitted_at, resolved_at
		FROM request_admissions
		WHERE client_request_id = $1 AND org_id = $2
		ORDER BY admitted_at`, rid, orgID)
	if err != nil {
		t.Fatalf("oracle: request_admissions rows: %v", err)
	}
	defer rows.Close()
	var out []extAdmissionRow
	for rows.Next() {
		var a extAdmissionRow
		if err := rows.Scan(&a.InvocationID, &a.OrgID, &a.Kind, &a.State, &a.ResolveReas, &a.AdmittedAt, &a.ResolvedAt); err != nil {
			t.Fatalf("oracle: request_admissions scan: %v", err)
		}
		out = append(out, a)
	}
	return out
}

// oracleTerminalFactsPresent: durable terminal evidence exists for the
// (org, client_request_id) pair — the pre-publish commit 0028 requires.
func (s *extStand) oracleTerminalFactsPresent(t *testing.T, orgID, rid string) bool {
	t.Helper()
	if !s.oracleTableExists(t, "request_terminal_facts") {
		return false
	}
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	var n int
	err := s.owner.QueryRowContext(ctx, `
		SELECT count(*) FROM request_terminal_facts
		WHERE client_request_id = $1 AND org_id = $2`, rid, orgID).Scan(&n)
	if err != nil {
		t.Fatalf("oracle: request_terminal_facts count: %v", err)
	}
	return n > 0
}

// oracleWalletUsage: signed ledger rows (type='usage') for the request.
func (s *extStand) oracleWalletUsage(t *testing.T, orgID, rid string) []extWalletRow {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	rows, err := s.owner.QueryContext(ctx, `
		SELECT COALESCE(amount_micro_usd, 0), amount_cents, balance_after, type
		FROM credit_transactions
		WHERE request_id = $1 AND org_id = $2 AND type = 'usage'
		ORDER BY id`, rid, orgID)
	if err != nil {
		t.Fatalf("oracle: credit usage rows: %v", err)
	}
	defer rows.Close()
	var out []extWalletRow
	for rows.Next() {
		var w extWalletRow
		if err := rows.Scan(&w.AmountMicro, &w.AmountCents, &w.BalanceAfter, &w.Type); err != nil {
			t.Fatalf("oracle: credit scan: %v", err)
		}
		out = append(out, w)
	}
	return out
}

// oracleWalletBalanceCents reads org_credits (wallet state, cents domain).
func (s *extStand) oracleWalletBalanceCents(t *testing.T, orgID string) (int64, bool) {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	var bal int64
	err := s.owner.QueryRowContext(ctx, `
		SELECT balance_cents FROM org_credits WHERE org_id = $1`, orgID).Scan(&bal)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		t.Fatalf("oracle: org_credits read: %v", err)
	}
	return bal, true
}

// assertWalletConfigured proves the wallet is chargeable before the target:
// seed opening topup recorded and positive balance present.
func (s *extStand) assertWalletConfigured(t *testing.T, orgID, label string) {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	var n int
	if err := s.owner.QueryRowContext(ctx, `
		SELECT count(*) FROM credit_transactions
		WHERE org_id = $1 AND type = 'topup' AND invoice_ref = 'seed-opening-balance'`,
		orgID).Scan(&n); err != nil {
		t.Fatalf("oracle: opening topup probe (%s): %v", label, err)
	}
	if n < 1 {
		t.Fatalf("wallet not configured for %s: no seed opening topup for org %s", label, orgID)
	}
	bal, ok := s.oracleWalletBalanceCents(t, orgID)
	if !ok || bal <= 0 {
		t.Fatalf("wallet not chargeable for %s: org_credits balance = %d (present=%v)", label, bal, ok)
	}
	t.Logf("wallet configured for %s: balance=%d cents", label, bal)
}

// requireWalletChargedExactlyOnce: the signed wallet delta for the request is
// exactly one debit of micro µUSD (Deduct stores -amount for usage rows).
func (s *extStand) requireWalletChargedExactlyOnce(t *testing.T, orgID, rid string, micro int64, label string) {
	t.Helper()
	rows := s.oracleWalletUsage(t, orgID, rid)
	if len(rows) != 1 {
		t.Fatalf("%s: wallet usage rows for %s = %d, want exactly 1 (found %+v)", label, rid, len(rows), rows)
	}
	if got := rows[0].AmountMicro; got != -micro {
		t.Fatalf("%s: wallet signed micro delta for %s = %d, want %d", label, rid, got, -micro)
	}
	if rows[0].AmountMicro > 0 {
		t.Fatalf("%s: wallet usage row for %s is a credit (+%d), want a debit", label, rid, rows[0].AmountMicro)
	}
	t.Logf("%s: wallet charged exactly once for %s: %d micro-USD (signed)", label, rid, rows[0].AmountMicro)
}

// requireNoWalletDebit: no usage row may exist for the request — an
// unresolved start with no recoverable usage must never debit the wallet.
func (s *extStand) requireNoWalletDebit(t *testing.T, orgID, rid, label string) {
	t.Helper()
	if rows := s.oracleWalletUsage(t, orgID, rid); len(rows) != 0 {
		t.Fatalf("%s: invented wallet debit for unresolved %s: %+v", label, rid, rows)
	}
}

// requireBilledRow: the completed invocation's request_logs row carries the
// exact token usage and exact micro cost, org-bound.
func (s *extStand) requireBilledRow(t *testing.T, orgID, rid string, label string) extRequestLogRow {
	t.Helper()
	rows := s.oracleRequestLogRows(t, orgID, rid)
	for _, r := range rows {
		if r.Status == http.StatusOK {
			if r.TokensIn != extPromptTokens || r.TokensOut != extCompletionTokens {
				t.Fatalf("%s: billed row tokens for %s = %d/%d, want %d/%d", label, rid,
					r.TokensIn, r.TokensOut, extPromptTokens, extCompletionTokens)
			}
			const wantCost = float64(extCostMicroUSD) / 1_000_000
			if r.CostUSD < wantCost*0.999 || r.CostUSD > wantCost*1.001 {
				t.Fatalf("%s: billed row cost for %s = %.9f, want %.9f (32 micro-USD)", label, rid, r.CostUSD, wantCost)
			}
			return r
		}
	}
	t.Fatalf("%s: no billed (200) request_logs row for %s under its org (rows=%+v)", label, rid, rows)
	return extRequestLogRow{}
}

// requireExactlyOneBilledRow: across ALL rows for the correlation id (two
// invocations may legitimately log), exactly one may claim success+usage.
func (s *extStand) requireExactlyOneBilledRow(t *testing.T, orgID, rid, label string) {
	t.Helper()
	rows := s.oracleRequestLogRows(t, orgID, rid)
	billed, other := 0, 0
	for _, r := range rows {
		if r.Status == http.StatusOK && (r.TokensIn > 0 || r.TokensOut > 0) {
			billed++
		} else {
			other++
		}
		if r.Status == http.StatusOK && r.TokensIn == 0 && r.TokensOut == 0 {
			t.Fatalf("%s: row for %s claims 200 with zero usage (fabricated success)", label, rid)
		}
	}
	if billed != 1 {
		t.Fatalf("%s: billed rows for %s = %d (other=%d, rows=%+v), want exactly 1", label, rid, billed, other, rows)
	}
}

// ageAdmissionsPastGrace moves ONLY the target's still-open admissions past
// the 15m default grace (directive: age only the target admission, only
// after the gateway crash; never still-live controls). Returns rows aged.
func (s *extStand) ageAdmissionsPastGrace(t *testing.T, orgID, rid string) int64 {
	t.Helper()
	if !s.oracleTableExists(t, "request_admissions") {
		return 0
	}
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	res, err := s.owner.ExecContext(ctx, `
		UPDATE request_admissions
		SET admitted_at = now() - interval '16 minutes'
		WHERE client_request_id = $1 AND org_id = $2 AND state = 'admitted'`, rid, orgID)
	if err != nil {
		t.Fatalf("oracle: age admissions for %s: %v", rid, err)
	}
	n, _ := res.RowsAffected()
	t.Logf("oracle: aged %d still-open admission(s) for %s past the 15m grace", n, rid)
	return n
}

// settlementJobCount: text org binding on settlement_jobs.
func (s *extStand) settlementJobCount(t *testing.T, orgID, rid string) int {
	t.Helper()
	ctx, cancel := s.oracleQueryCtx()
	defer cancel()
	var n int
	err := s.owner.QueryRowContext(ctx, `
		SELECT count(*) FROM settlement_jobs WHERE request_id = $1 AND org_id = $2`, rid, orgID).Scan(&n)
	if err != nil {
		t.Fatalf("oracle: settlement_jobs count: %v", err)
	}
	return n
}

// fatalError aborts an eventually() poll immediately: the observed state is
// a definitive contract violation, not a not-yet condition.
type fatalError struct{ err error }

func (e fatalError) Error() string { return e.err.Error() }

// fatalf builds a fatalError (see eventually).
func fatalf(format string, args ...interface{}) error {
	return fatalError{fmt.Errorf(format, args...)}
}

// eventually polls fn until it returns nil or the budget expires; retryable
// errors keep polling, fatalError aborts immediately.
func eventually(t *testing.T, budget time.Duration, every time.Duration, what string, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		switch err := fn(); {
		case err == nil:
			return
		default:
			if fe, ok := err.(fatalError); ok {
				t.Fatalf("eventually: %s: %v", what, fe)
			}
			last = err
		}
		time.Sleep(every)
	}
	t.Fatalf("eventually: %s did not hold within %s: %v", what, budget, last)
}

// requireAdmissionVocabulary guards the 0028 CHECK domain.
func requireAdmissionVocabulary(t *testing.T, a extAdmissionRow) {
	t.Helper()
	for _, ok := range []string{"admitted", "voided", "reconciled", "unresolved"} {
		if a.State == ok {
			return
		}
	}
	t.Fatalf("admission %s state %q outside vocabulary [%s]", a.InvocationID, a.State, admissionStateVocabulary)
}

func fmtAdmissions(rows []extAdmissionRow) string {
	out := ""
	for _, a := range rows {
		out += fmt.Sprintf("{inv=%s state=%s reason=%s resolved=%v kind=%s}",
			a.InvocationID[:8], a.State, a.ResolveReas.String, a.ResolvedAt.Valid, a.Kind)
	}
	return out
}
