//go:build integration

package accounting

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAccountingFactsRecoverySettlementCommitBoundary proves the
// atomicity contract of the facts-sweep settlement boundary (Astra
// acceptance finding): a failure injected BETWEEN the sweep's
// request_logs insert and its settlement-intent commit must roll back
// the ENTIRE sweep transaction — zero request_logs rows, zero
// settlement jobs, zero wallet debit, and a non-reconciled admission at
// that boundary — and, once the fault is removed, the sweep must retry
// from the intact facts and materialize exactly once (billed 7+3 tokens,
// the single signed -32 micro-USD debit, admission reconciled with
// reason recovered_from_facts), after which the existing late-live
// event dedupe contract still holds.
//
// The fault is an AFTER INSERT trigger on settlement_jobs scoped to the
// recovered invocation. It bumps a private sequence and then raises.
// nextval is nontransactional, so the increment survives the rollback:
// it is the independent, direct proof that a MATCHING settlement insert
// was attempted, without relying on any product log or state that the
// rollback itself erases. Fault injection runs on the stand owner login
// (the same oracle role the ACK case uses for its trigger), inside this
// private disposable stand only; triggers/functions/sequences are
// removed mid-test and again via cleanup.
//
// The production recovery this case qualifies is implemented on commit
// 4192351; real-stand runs happen under the heavy lease. On the frozen
// baseline this case must fail with an explicit PRODUCT DEFECT fatal
// (no request_admissions/request_terminal_facts to recover from).
func TestAccountingFactsRecoverySettlementCommitBoundary(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "settlement fault pre-control")
	s.controlRequest(t, "settlefault-pre")

	rid := s.reqPrefix + "tgt-settlefault"
	rdb := s.redisClient(t)

	// Consumer down before the target: the notification queues in Redis
	// while serving must stay up (the serving path is consumer-free).
	s.stopLoggerd()
	defer func() {
		if s.loggerdCmd == nil {
			s.restartLoggerd()
		}
	}()

	before := s.fixture.Snapshot()
	status, body, err := s.chat(t, rid, 60*time.Second)
	if err != nil || status != httpOK || !strings.Contains(body, fixtureAssistantContent) {
		t.Fatalf("settlement fault: target invocation status=%d body=%q err=%v — serving must not depend on the consumer", status, body, err)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		t.Fatalf("settlement fault: ledger delta = %d/%d/%d, want 1/1/1 (one dispatch, one receipt)", delta.arrivals, delta.dispatches, delta.receipts)
	}

	// Durable terminal facts exist while the consumer is down — they are
	// the recovery source this whole scenario depends on.
	if !s.oracleTableExists(t, "request_terminal_facts") {
		t.Fatalf("PRODUCT DEFECT (baseline): request_terminal_facts absent — no durable pre-publish terminal evidence to recover from")
	}
	if s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID) == 0 {
		t.Fatalf("settlement fault: no terminal facts row for served %s while the consumer is down", rid)
	}

	// Remove the owned Redis carrier for this run: recovery must come
	// from facts alone, not from a live (re)delivered event.
	entries := s.findStreamEntries(t, rdb, rid)
	if len(entries) == 0 {
		t.Fatalf("settlement fault: no stream entries found for %s — construction failed", rid)
	}
	var ids []string
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	s.deleteStreamEntriesFor(t, rdb, rid, ids)
	s.assertNoRetryCarrier(t, rdb, rid)
	if cursor, ok := s.groupDeliveryCursor(t, rdb); ok {
		for _, id := range ids {
			if !entryIDAfter(id, cursor) {
				t.Fatalf("settlement fault: stream entry %s at or before delivery cursor %s — event was consumed before the consumer stopped; construction failed", id, cursor)
			}
		}
	}

	// Bind the server-minted invocation identity while the consumer is
	// down and the admission is stable.
	if !s.oracleTableExists(t, "request_admissions") {
		t.Fatalf("PRODUCT DEFECT (baseline): request_admissions absent — the settlement boundary cannot be scoped to the invocation")
	}
	rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(rows) != 1 || rows[0].InvocationID == "" {
		t.Fatalf("settlement fault: admissions for %s = %d, want exactly one invocation-minted admission", rid, len(rows))
	}
	targetUUID := rows[0].InvocationID

	// Deterministic sweep visit: age the (single) admission past the
	// 15-minute grace window before the consumer restarts.
	s.ageAdmissionPastGrace(t, rid, s.oracleDB.orgID)

	// Install the boundary fault, scoped to this invocation only: any
	// settlement_jobs insert for it records one nontransactional
	// sequence increment and then aborts its transaction.
	const (
		seqName = "acc_settlement_boundary_seq"
		fnName  = "acc_settlement_boundary_fault"
		trgName = "acc_settlement_boundary"
	)
	s.oracleExec(t, "create boundary sequence", fmt.Sprintf(`CREATE SEQUENCE %s`, seqName))
	s.oracleExec(t, "create boundary fault function", fmt.Sprintf(
		`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('%s'); RAISE EXCEPTION 'injected settlement commit boundary failure'; END $$`,
		fnName, seqName))
	s.oracleExec(t, "create boundary trigger", fmt.Sprintf(
		`CREATE TRIGGER %s AFTER INSERT ON settlement_jobs FOR EACH ROW WHEN (NEW.invocation_id = '%s'::uuid) EXECUTE FUNCTION %s()`,
		trgName, targetUUID, fnName))
	dropFault := func() {
		s.oracleExec(t, "drop boundary trigger", fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON settlement_jobs`, trgName))
		s.oracleExec(t, "drop boundary function", fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fnName))
	}
	t.Cleanup(func() {
		dropFault()
		s.oracleExec(t, "drop boundary sequence", fmt.Sprintf(`DROP SEQUENCE IF EXISTS %s`, seqName))
	})
	attempts := func() int64 {
		var n int64
		if err := s.oracleDB.db.QueryRow(fmt.Sprintf(
			`SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM %s`, seqName)).Scan(&n); err != nil {
			t.Fatalf("settlement fault: read attempt counter: %v", err)
		}
		return n
	}

	// Restart the consumer: the facts sweep visits the aged admission and
	// must reach the settlement boundary (the matching insert), inside an
	// explicit horizon.
	s.restartLoggerd()

	pollUntil(t, 3*time.Minute, "sweep attempts the settlement insert", func() error {
		if attempts() == 0 {
			return fmt.Errorf("no matching settlement_jobs insert attempted for invocation %s yet", targetUUID)
		}
		return nil
	})
	t.Logf("settlement fault: %d matching insert attempt(s) recorded by the nontransactional counter", attempts())

	// The boundary state: the ENTIRE sweep transaction rolled back. No
	// partial accounting may survive a failure between the request_logs
	// insert and the settlement-intent commit.
	if got := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); got != 0 {
		t.Fatalf("settlement fault boundary: request_logs rows = %d for %s, want 0 — the sweep's request_logs insert leaked past the rolled-back settlement commit", got, rid)
	}
	if jobs := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); jobs != 0 {
		t.Fatalf("settlement fault boundary: settlement jobs = %d for %s, want 0 (trigger must abort the insert)", jobs, rid)
	}
	if invJobs := s.oracleCount(t,
		`SELECT count(*) FROM settlement_jobs WHERE invocation_id = $1::uuid AND org_id = $2`,
		targetUUID, s.oracleDB.orgID); invJobs != 0 {
		t.Fatalf("settlement fault boundary: settlement jobs = %d under invocation %s, want 0", invJobs, targetUUID)
	}
	s.requireNoWalletDebit(t, rid, s.oracleDB.orgID, "settlement fault boundary")
	if s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID) == 0 {
		t.Fatalf("settlement fault boundary: terminal facts vanished for %s — they must survive the failed sweep (they are the recovery source)", rid)
	}
	adm, ok := s.oracleAdmissionByInvocation(t, targetUUID, s.oracleDB.orgID)
	if !ok {
		t.Fatalf("settlement fault boundary: admission for invocation %s vanished", targetUUID)
	}
	requireAdmissionVocabulary(t, adm)
	switch adm.State {
	case "reconciled":
		t.Fatalf("settlement fault boundary: admission %s is reconciled while its accounting rolled back — a charge-less reconcile at the boundary", targetUUID)
	case "voided":
		t.Fatalf("settlement fault boundary: admission %s is voided although terminal facts exist", targetUUID)
	default:
		t.Logf("settlement fault boundary: admission %s non-reconciled in state %q with its accounting fully rolled back", targetUUID, adm.State)
	}

	// Remove the fault; the sweep retries from the intact facts and
	// materializes exactly once, inside an explicit horizon.
	dropFault()

	pollUntil(t, 6*time.Minute, "sweep retries and materializes after fault removal", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row for %s yet", rid)
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows == 0 {
			return fmt.Errorf("no wallet usage row for %s yet", rid)
		}
		return nil
	})
	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "settlement fault retry")
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "settlement fault retry")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "settlement fault retry")
	kinds := s.requireWalletIntentPresent(t, rid, s.oracleDB.orgID, "settlement fault retry")

	pollUntil(t, 6*time.Minute, "admission reconciles via facts after retry", func() error {
		a, ok := s.oracleAdmissionByInvocation(t, targetUUID, s.oracleDB.orgID)
		if !ok {
			return abortf("admission for invocation %s vanished after successful materialization", targetUUID)
		}
		requireAdmissionVocabulary(t, a)
		switch a.State {
		case "reconciled":
			if a.ResolveReason.String != reasonRecovered {
				return abortf("admission %s reconciled with reason %q, want %q (facts are present; the live event never existed)", targetUUID, a.ResolveReason.String, reasonRecovered)
			}
			if !a.ResolvedAt.Valid {
				return abortf("admission %s reconciled without resolved_at", targetUUID)
			}
			return nil
		case "admitted", "unresolved":
			return fmt.Errorf("admission %s still %q after the sweep materialized its accounting", targetUUID, a.State)
		}
		return abortf("admission %s in unexpected state %q", targetUUID, a.State)
	})
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("settlement fault: ledger after recovery = %d/%d/%d, want 1/1/1 — the sweep must not re-dispatch the provider call", arr, disp, recv)
	}

	// The existing late-live dedupe contract must still hold after
	// facts-based materialization: the original event surfaces late under
	// fresh stream ids and must be claimed, drained, and deduped.
	var replayIDs []string
	for _, e := range entries {
		replayIDs = append(replayIDs, s.replayEntryUnderFreshID(t, rdb, e))
	}
	s.requireInboxClaimsCommitted(t, rdb, replayIDs)
	s.requireGroupDrainedWithin(t, rdb, 2*time.Minute)
	s.assertNoRetryCarrier(t, rdb, rid)

	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "after late live replay")
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "after late live replay")
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "after late live replay")
	s.requireSettlementIntents(t, rid, s.oracleDB.orgID, "after late live replay", kinds)
	rows = s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(rows) != 1 || rows[0].InvocationID != targetUUID || rows[0].State != "reconciled" || rows[0].ResolveReason.String != reasonRecovered {
		t.Fatalf("settlement fault: late live replay changed the admission record: %+v, want the single %s reconciled via %s", rows, targetUUID, reasonRecovered)
	}
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("settlement fault: ledger after late live replay = %d/%d/%d, want 1/1/1 — the replay must be fully deduped", arr, disp, recv)
	}

	s.controlRequest(t, "settlefault-post")
}
