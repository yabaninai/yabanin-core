//go:build integration

package accounting

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAccountingSameOrgTwoPaidInvocationsSharedCorrelationId: TWO
// SUCCESSFUL paid HTTP invocations in the SAME org under the SAME client
// correlation id (distinct bodies, so no prompt-derived cache hit can
// suppress the second paid call), one buffered and one streamed. Per 0028
// the correlation id is correlation-only: two distinct minted invocation
// IDs must bill INDEPENDENTLY — a signed wallet debit of -32 micro-USD
// EACH, two billed request_logs rows, two independent provider receipts,
// and two admissions that each reconcile.
//
// Baseline truth (4e9895d): the legacy settlement/usage identity keys are
// (org_id, request_id, charge_kind) and GLOBAL (request_id) — the second
// invocation's accounting cannot land independently (it collides and must
// fail loudly into requires_attention, never silently double-charge). The
// case therefore FAILS on baseline by design and pins the 0028 contract.
func TestAccountingSameOrgTwoPaidInvocationsSharedCorrelationId(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "samerid-pre")

	rid := s.reqPrefix + "tgt-samerid"
	before := s.fixture.Snapshot()

	org := s.oracleDB.orgID
	status, body, err := s.chatFull(t, rid, 30*time.Second, chatOptions{content: "Same-rid distinct body A " + s.runID})
	require.NoError(t, err)
	require.Equal(t, httpOK, status, body)
	validateChatReply(t, s, body)
	first := s.oracleAdmissions(t, rid, org)
	require.Len(t, first, 1)
	require.NotEmpty(t, first[0].InvocationID)

	status, body, err = s.chatFull(t, rid, 30*time.Second, chatOptions{stream: true, content: "Same-rid distinct body B " + s.runID})
	require.NoError(t, err)
	require.Equal(t, httpOK, status, body)
	validateChatSSE(t, s, body)
	arr, disp, recv := s.fixture.Counts(rid)
	expected := fixtureTotals{arrivals: 2, dispatches: 2, receipts: 2}
	require.Equal(t, expected, fixtureTotals{arrivals: arr, dispatches: disp, receipts: recv})
	require.Equal(t, expected, s.fixture.Since(before))

	// Settlement runs asynchronously. A provider receipt alone does not
	// establish that the second wallet debit is already visible.
	requireEventually(t, 3*time.Minute, 500*time.Millisecond, func() bool {
		return s.oracleCreditTotals(t, rid, org).UsageRows >= 2
	}, "both paid invocations must settle independently")
	wantDebit := int64(-fixtureMicroUSDCost)
	require.Equal(t, []int64{wantDebit, wantDebit}, s.oracleWalletUsageRows(t, rid, org))
	rows := s.oracleRequestLogRows(t, rid, org)
	require.Len(t, rows, 2)
	for _, row := range rows {
		require.EqualValues(t, httpOK, row.Status)
		require.EqualValues(t, fixturePromptTokens, row.TokensIn)
		require.EqualValues(t, fixtureCompletionTokens, row.TokensOut)
		require.InDelta(t, s.expectedFixtureCostUSD(), row.CostUSD, 1e-9)
	}
	admissions := s.oracleAdmissions(t, rid, org)
	require.Len(t, admissions, 2)
	require.NotEqual(t, admissions[0].InvocationID, admissions[1].InvocationID)
	require.Contains(t, []string{admissions[0].InvocationID, admissions[1].InvocationID}, first[0].InvocationID)
	for _, a := range admissions {
		require.Equal(t, "reconciled", a.State)
		require.True(t, a.ResolvedAt.Valid)
		require.Equal(t, sql.NullString{String: reasonEventLive, Valid: true}, a.ResolveReason)
		charge := s.oracleUsageByInvocation(t, a.InvocationID, org)
		require.EqualValues(t, 1, charge.UsageRows)
		require.Equal(t, wantDebit, charge.SumMicroUSD)
		for _, kind := range []string{"resale_deduction", "team_spend"} {
			require.Equal(t, 1, s.oracleCount(t, "SELECT count(*) FROM settlement_jobs WHERE invocation_id=$1::uuid AND org_id=$2 AND request_id=$3 AND charge_kind=$4", a.InvocationID, org, rid, kind))
		}
		require.Equal(t, 1, s.oracleCount(t, `SELECT count(*) FROM request_terminal_facts f
			JOIN request_logs l ON l.invocation_id=f.invocation_id AND l.org_id::text=f.org_id
			WHERE f.invocation_id=$1::uuid AND f.org_id=$2 AND f.client_request_id=$3 AND l.request_id=$3`, a.InvocationID, org, rid))
	}
	s.requireSettlementIntents(t, rid, org, "same correlation", map[string]int{"resale_deduction": 2, "team_spend": 2})
	s.controlRequest(t, "samerid-post")
}
