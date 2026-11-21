//go:build integration

package accounting

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAccountingCrashClientRetrySingleCharge: crash + CLIENT RETRY
// semantics. A crashed streamed invocation followed by a SECOND, distinct
// HTTP invocation under the SAME client correlation id must bill EXACTLY
// ONCE for the completed work: two legitimate invocations (distinct minted
// UUIDs per 0028) share the correlation id and bill independently — only
// the completed one charges — with exactly one signed wallet debit of -32
// micro-USD, exactly one billed request_logs row, and the crashed
// invocation's row (if any) never claiming success/usage. The completed
// admission reaches 'reconciled' ('event_delivered'); the crashed one —
// identified by the server UUID captured at the pre-kill barrier and
// deterministically expired past grace by that UUID, never its same-rid
// sibling — must reach EXACTLY 'unresolved' ('grace_elapsed_no_terminal_
// facts', resolved_at set). Monetary totals are asserted only after the
// consumer's actual completion (polled materialization), and the exact
// per-kind settlement intent set of the billed invocation must survive
// the unresolved transition unchanged.
//
// NOTE: this is NOT an event-redelivery case (no Redis replay happens
// here); see TestAccountingRedisEventRedeliveryIdempotent and
// TestAccountingFactsRecoveryWithoutLiveEvent for those.
func TestAccountingCrashClientRetrySingleCharge(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	// Streamed healthy control proves the SSE path is billed + charged.
	s.controlRequestOpts(t, "redelivery-pre", s.oracleDB.orgID, chatOptions{stream: true})

	rid := s.reqPrefix + "tgt-redelivery"
	before := s.fixture.Snapshot()
	firstInvocation := s.crashHeldChat(t, rid, chatOptions{stream: true}, 90*time.Second)
	s.restartGateway()

	// Invocation 2: same client correlation id, streamed, served to
	// completion. Distinct body so no prompt-derived cache can suppress
	// the second paid call.
	status, body, err := s.chatFull(t, rid, 60*time.Second, chatOptions{
		stream:  true,
		content: "client retry after crash, distinct body " + s.runID,
	})
	require.NoError(t, err)
	require.Equal(t, httpOK, status, body)
	validateChatSSE(t, s, body)
	arr, disp, recv := s.fixture.Counts(rid)
	want := fixtureTotals{arrivals: 2, dispatches: 2, receipts: 1}
	require.Equal(t, want, fixtureTotals{arrivals: arr, dispatches: disp, receipts: recv})
	require.Equal(t, want, s.fixture.Since(before))

	// Monetary totals only AFTER the consumer actually completed: wait for
	// the second invocation's accounting to materialize before asserting
	// anything about rows, debits or intents.
	pollUntil(t, 3*time.Minute, "retry accounting materializes", func() error {
		if s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 0 {
			return fmt.Errorf("no request_logs row yet")
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows == 0 {
			return fmt.Errorf("no wallet usage row yet")
		}
		return nil
	})

	// Exactly one billed row across both invocations; crashed row silent.
	s.requireExactlyOneBilledRow(t, rid, s.oracleDB.orgID, "client retry")
	s.requireBilledRow(t, rid, s.oracleDB.orgID, "client retry")
	s.requireCrashedRowSilent(t, rid, s.oracleDB.orgID, "client retry")

	// Exactly one wallet debit, signed -32 micro-USD.
	s.requireWalletChargedExactlyOnce(t, rid, s.oracleDB.orgID, "client retry")
	// The seed key belongs to a team. These calls supply no session or agent.
	wantKinds := map[string]int{"resale_deduction": 1, "team_spend": 1}
	s.requireSettlementIntents(t, rid, s.oracleDB.orgID, "client retry", wantKinds)
	require.NotEmpty(t, firstInvocation, "no durable admission identity for the crashed invocation")
	s.ageAdmissionByInvocationPastGrace(t, firstInvocation, s.oracleDB.orgID)
	var completedID string
	pollUntil(t, 6*time.Minute, "client retry admissions settle per invocation", func() error {
		rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
		var err error
		completedID, err = retryAdmissionPair(t, rows, firstInvocation)
		return err
	})
	s.requireSettlementIntents(t, rid, s.oracleDB.orgID, "client retry final", wantKinds)
	require.Zero(t, s.oracleUsageByInvocation(t, firstInvocation, s.oracleDB.orgID).UsageRows)
	charge := s.oracleUsageByInvocation(t, completedID, s.oracleDB.orgID)
	require.EqualValues(t, 1, charge.UsageRows)
	require.EqualValues(t, -fixtureMicroUSDCost, charge.SumMicroUSD)
	require.Equal(t, 2, s.oracleCount(t, `SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND invocation_id=$3::uuid`, s.oracleDB.orgID, rid, completedID))

	s.controlRequestOpts(t, "redelivery-post", s.oracleDB.orgID, chatOptions{stream: true})
}

func retryAdmissionPair(t *testing.T, rows []admissionRow, crashedID string) (string, error) {
	t.Helper()
	if len(rows) != 2 {
		return "", fmt.Errorf("want two admissions, got %s", fmtAdmissions(rows))
	}
	crashed, completed := rows[0], rows[1]
	if completed.InvocationID == crashedID {
		crashed, completed = completed, crashed
	}
	if crashed.InvocationID != crashedID || completed.InvocationID == crashedID {
		return "", abortf("captured %s does not identify exactly one of %s", crashedID, fmtAdmissions(rows))
	}
	if err := unresolvedState(t, []admissionRow{crashed}, crashedID); err != nil {
		return "", err
	}
	requireAdmissionVocabulary(t, completed)
	if completed.State == "admitted" {
		return "", errTransient("completed invocation still admitted")
	}
	if completed.State != "reconciled" || !completed.ResolvedAt.Valid || !completed.ResolveReason.Valid || completed.ResolveReason.String != reasonEventLive {
		return "", abortf("wrong completed invocation outcome: %s", fmtAdmissions(rows))
	}
	return completed.InvocationID, nil
}

func TestRetryAdmissionPairMatchesPhysicalIdentities(t *testing.T) {
	done := sql.NullTime{Time: time.Unix(1, 0), Valid: true}
	crashed := admissionRow{InvocationID: "first", State: "unresolved", ResolveReason: sql.NullString{String: reasonGraceElapsed, Valid: true}, ResolvedAt: done}
	completed := admissionRow{InvocationID: "second", State: "reconciled", ResolveReason: sql.NullString{String: reasonEventLive, Valid: true}, ResolvedAt: done}
	for _, rows := range [][]admissionRow{{crashed, completed}, {completed, crashed}} {
		id, err := retryAdmissionPair(t, rows, "first")
		require.NoError(t, err)
		require.Equal(t, "second", id)
	}
	for _, rows := range [][]admissionRow{{completed, completed}, {crashed, crashed}, {crashed}, {crashed, completed, completed}} {
		_, err := retryAdmissionPair(t, rows, "first")
		require.Error(t, err)
	}
	completed.ResolvedAt.Valid = false
	_, err := retryAdmissionPair(t, []admissionRow{crashed, completed}, "first")
	require.Error(t, err)
}
