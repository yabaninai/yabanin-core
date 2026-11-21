//go:build integration

package accounting

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAccountingRefusalBeforeDispatch is the owner-approved predispatch
// refusal case: while the provider remains reachable, the product must be
// unable to serve a paid request when it cannot durably record the start
// of that request — it must refuse the client with the documented
// history-unavailable 503 contract, contact no provider (no first attempt,
// no retry, no fallback hop), record no charge, and resume normal service
// for healthy controls before and after the outage with the same
// credentials, route and provider.
//
// The outage is injected with real infrastructure controls only: a BEFORE
// INSERT/UPDATE trigger on the request-accounting table(s) raises an
// exception, which is exactly the state an operator has when the durable
// write path is broken while reads (authentication, model resolution,
// budget capacity) keep working. The arming is verified both in the
// catalog and behaviorally before any product assertion is made, so a
// broken injection can never masquerade as product compliance. No product
// test hook exists or is needed.
func TestAccountingRefusalBeforeDispatch(t *testing.T) {
	s := startStand(t)

	// Healthy control with the fault absent: proves the stand (credentials,
	// route, provider, detectors) is valid before anything is asked of the
	// product's refusal behavior.
	s.controlRequest(t, "pre-fault")

	// Inject the durable-write outage on the request accounting surface
	// and prove it took effect before asking the product anything.
	s.armAccountingWriteOutage(t)
	defer s.disarmAccountingWriteOutage(t)

	// The target request must be refused, not served.
	before := s.fixture.Snapshot()
	rid := s.reqPrefix + "tgt-refusal"
	status, body, err := s.chat(t, rid, 45*time.Second)

	// Documented refusal contract (reservation gate, I40 family):
	// HTTP 503 with a structured error envelope whose error.code is
	// history_unavailable. A 401/402/403/500, a network drop or an
	// unstructured body each fail the case explicitly.
	switch {
	case err != nil:
		t.Fatalf("product: refusal case: client transport error %v — the request must be refused with the documented 503 history_unavailable contract, not dropped", err)
	case status != 503:
		t.Fatalf("product: refusal case: client status %d, want 503 (body %s) — denied or served for the wrong reason; the documented history_unavailable refusal is missing", status, clip(body))
	}
	code, ok := decodeErrorCode(body)
	if !ok {
		t.Fatalf("product: refusal case: 503 body is not the documented structured error envelope (body %s)", clip(body))
	}
	if code != "history_unavailable" {
		t.Fatalf("product: refusal case: 503 error.code %q, want history_unavailable (body %s)", code, clip(body))
	}

	// Independent provider oracle: zero provider contact in the window —
	// the fixture ledger records every arrival regardless of the request
	// id the gateway forwarded, authorized or not.
	s.fixture.VerifyEvidence()
	if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
		t.Fatalf("product: refusal case: whole-ledger provider contact during the outage arrivals/dispatches/receipts = %d/%d/%d, want 0/0/0 — the request must never be dispatched, retried or failed over",
			delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Independent storage oracle: nothing was recorded or charged for the
	// refused request (org-bound queries; cross-org rows cannot satisfy
	// them).
	if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal case: %d request_logs row(s) exist for the refused request", n)
	}
	if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: refusal case: credit transactions exist for the refused request (%+v)", c)
	}
	if n := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal case: %d settlement job(s) exist for the refused request", n)
	}
	if n := s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal case: %d admission row(s) exist for the refused request", n)
	}

	// Restore the write path (verified), then prove the stand is still
	// good with the same credentials, route and provider: the refusal was
	// caused by the accounting outage, nothing else.
	s.disarmAccountingWriteOutage(t)
	s.controlRequest(t, "post-fault")

	// The refused request must never retroactively bill.
	if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: refusal case: %d request_logs row(s) appeared for the refused request after restoration", n)
	}
	if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows != 0 {
		t.Fatalf("product: refusal case: %d usage transaction(s) appeared for the refused request after restoration", c.UsageRows)
	}
	t.Logf("product: refusal case passed (request id %s)", rid)
}

// armAccountingWriteOutage installs the real-infrastructure fault and
// verifies it took effect. The trigger raises on any INSERT/UPDATE
// touching the request accounting table(s). Reads continue to work, so
// authentication, model resolution and budget capacity remain healthy —
// the refusal can only come from the missing durable start guarantee.
func (s *stand) armAccountingWriteOutage(t *testing.T) {
	t.Helper()
	tables := s.accountingWriteTables(t)
	s.oracleExec(t, "install outage function",
		`CREATE OR REPLACE FUNCTION acc_test_refuse_write() RETURNS trigger
		 LANGUAGE plpgsql AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'acceptance outage: durable request-accounting write refused on %', TG_TABLE_NAME;
		 END
		 $fn$`)
	for _, table := range tables {
		s.oracleExec(t, "arm outage trigger on "+table,
			fmt.Sprintf(`DROP TRIGGER IF EXISTS acc_test_refuse_write ON %s;
			 CREATE TRIGGER acc_test_refuse_write BEFORE INSERT OR UPDATE ON %s
			 FOR EACH ROW EXECUTE FUNCTION acc_test_refuse_write()`, table, table))
	}

	// Catalog verification: exactly one armed trigger per target table.
	if n := s.oracleCount(t, `SELECT count(*) FROM pg_trigger WHERE tgname = 'acc_test_refuse_write'`); n != len(tables) {
		t.Fatalf("harness: outage armed on %d trigger(s), want %d (tables %v)", n, len(tables), tables)
	}
	// Behavioral verification: a probe write on each target table must
	// actually raise the outage exception. INSERT ... DEFAULT VALUES names
	// no columns, so the probe is independent of each table's column
	// types; the BEFORE trigger aborts the statement before any
	// constraint or default evaluation can matter, and the surrounding
	// transaction is rolled back regardless.
	for _, table := range tables {
		errText := s.probeInsert(t, table)
		if !strings.Contains(errText, "acceptance outage") {
			t.Fatalf("harness: outage probe on %s did not raise the outage exception (got %q) — the fault is not in effect; product assertions would be meaningless", table, errText)
		}
	}
	t.Logf("harness: accounting write outage armed and verified on %v", tables)
}

// disarmAccountingWriteOutage reverses the fault completely and verifies
// the reversal both in the catalog and behaviorally.
func (s *stand) disarmAccountingWriteOutage(t *testing.T) {
	t.Helper()
	for _, table := range s.accountingWriteTables(t) {
		s.oracleExec(t, "disarm outage trigger on "+table,
			fmt.Sprintf(`DROP TRIGGER IF EXISTS acc_test_refuse_write ON %s`, table))
	}
	s.oracleExec(t, "drop outage function", `DROP FUNCTION IF EXISTS acc_test_refuse_write()`)

	if n := s.oracleCount(t, `SELECT count(*) FROM pg_trigger WHERE tgname = 'acc_test_refuse_write'`); n != 0 {
		t.Fatalf("harness: %d outage trigger(s) remain after disarm", n)
	}
	for _, table := range s.accountingWriteTables(t) {
		errText := s.probeInsert(t, table)
		if strings.Contains(errText, "acceptance outage") {
			t.Fatalf("harness: outage probe on %s still raises the outage exception after disarm", table)
		}
	}
	t.Logf("harness: accounting write outage disarmed and verified")
}

// probeInsert attempts one no-column INSERT on table inside a transaction
// that is always rolled back, and returns the resulting error text ("" on
// success). It leaves no row behind either way.
func (s *stand) probeInsert(t *testing.T, table string) string {
	t.Helper()
	tx, err := s.oracleDB.db.Begin()
	if err != nil {
		t.Fatalf("harness: probe tx on %s: %v", table, err)
	}
	_, execErr := tx.Exec(fmt.Sprintf(`INSERT INTO %s DEFAULT VALUES`, table))
	errText := ""
	if execErr != nil {
		errText = execErr.Error()
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("harness: probe rollback on %s: %v", table, err)
	}
	return errText
}

// accountingWriteTables lists the tables whose writes constitute the
// durable request accounting surface for this build: request_logs always;
// request_admissions and request_terminal_facts conditionally, so the
// same test replays unchanged against the durable-accounting candidate
// whose draft migration adds those tables. Expected behavior is defined
// independently of this list; it is only the injection surface.
func (s *stand) accountingWriteTables(t *testing.T) []string {
	t.Helper()
	tables := []string{"request_logs"}
	for _, candidate := range []string{"request_admissions", "request_terminal_facts"} {
		if s.oracleTableExists(t, candidate) {
			tables = append(tables, candidate)
		}
	}
	return tables
}

// clip shortens a response body for failure messages.
func clip(body string) string {
	const max = 400
	if len(body) <= max {
		return body
	}
	return body[:max] + "…"
}
