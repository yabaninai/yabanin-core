//go:build integration

package accounting

import (
	"fmt"
	"github.com/stretchr/testify/require"
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

	s.serveWhileConsumerDown(t, rid)
	targetUUID := s.requireTerminalFactsWhileConsumerDown(t, rid)
	entries := s.removeUndeliveredFactsNotification(t, rdb, rid)
	s.ageAdmissionByInvocationPastGrace(t, targetUUID, s.oracleDB.orgID)

	// Install the boundary fault, scoped to this invocation only: any
	// settlement_jobs insert for it records one nontransactional
	// sequence increment and then aborts its transaction.
	const (
		seqName = "acc_settlement_boundary_seq"
		fnName  = "acc_settlement_boundary_fault"
		trgName = "acc_settlement_boundary"
	)
	s.oracleExec(t, "create boundary sequence", fmt.Sprintf(`CREATE SEQUENCE %s`, seqName))
	s.oracleExec(t, "allow consumer trigger to record attempts", "GRANT USAGE ON SEQUENCE "+seqName+" TO yabanin_app")
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
	org := s.oracleDB.orgID
	require.Zero(t, s.oracleRequestLogCount(t, rid, org))
	require.Zero(t, s.oracleSettlementJobs(t, rid, org))
	require.Zero(t, s.oracleCount(t, "SELECT count(*) FROM settlement_jobs WHERE invocation_id=$1::uuid AND org_id=$2", targetUUID, org))
	s.requireNoWalletDebit(t, rid, org, "settlement fault boundary")
	require.Equal(t, 1, s.oracleTerminalFactsCount(t, rid, org))
	adm, ok := s.oracleAdmissionByInvocation(t, targetUUID, org)
	require.True(t, ok)
	require.Equal(t, "admitted", adm.State)
	require.False(t, adm.ResolvedAt.Valid)
	require.False(t, adm.ResolveReason.Valid)

	dropFault()
	s.waitForRecoveredBilling(t, rid, 6*time.Minute)
	s.requireExactlyOneBilledRow(t, rid, org, "settlement fault retry")
	s.requireBilledRow(t, rid, org, "settlement fault retry")
	s.requireWalletChargedExactlyOnce(t, rid, org, "settlement fault retry")
	kinds := map[string]int{"resale_deduction": 1, "team_spend": 1}
	s.requireSettlementIntents(t, rid, org, "settlement fault retry", kinds)
	s.requireReconciledFromFacts(t, rid)
	s.requireRecoveredChargeIdentity(t, rid, targetUUID, "settlement fault retry")

	s.replayAfterFactsRecovery(t, rdb, rid, entries, kinds)
	s.requireRecoveredChargeIdentity(t, rid, targetUUID, "settlement fault late replay")
	s.controlRequest(t, "settlefault-post")
}
