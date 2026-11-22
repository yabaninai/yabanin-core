//go:build integration

package accounting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAccountingRedisEventRedeliveryIdempotent: EVENT REDELIVERY semantics
// at the Redis boundary (no second HTTP call, no gateway involvement after
// the original completion). The ORIGINAL committed event's exact field map
// is XADDed under FRESH entry IDs twice. Proof obligations:
//
//  1. the original invocation succeeded for the client (status and body)
//     and its accounting fully materialized (billed row, wallet debit,
//     wallet intent present — the non-vacuity anchor);
//  2. the replayed entry IDs are distinct from each other and from the
//     original entry's ID (XRANGE/XADD evidence);
//  3. the consumer actually claimed each replay: a committed event_inbox
//     row per fresh entry id with the stand's stream as source and the
//     observed consumer group as consumer — fresh ids are never
//     inbox-deduped, so this is durable processing evidence, unlike a
//     delivery cursor which only proves the group saw an entry;
//  4. nothing is parked or lost: the consumer group's pending list is
//     empty and no retry/dead-letter/parking stream carries a copy;
//  5. idempotence: still exactly ONE billed request_logs row, ONE signed
//     wallet usage debit (-32 micro-USD), the EXACT per-kind settlement
//     intent set for the seeded team key, one admission still 'reconciled'/'event_delivered', and an
//     UNCHANGED provider ledger (1/1/1 — no re-dispatch).
func TestAccountingRedisEventRedeliveryIdempotent(t *testing.T) {
	s := startStand(t)

	s.assertWalletConfigured(t, s.oracleDB.orgID, "pre-control")
	s.controlRequest(t, "replay-pre")

	rid := s.reqPrefix + "tgt-replay"
	before := s.fixture.Snapshot()

	// Original committed invocation: the client must have succeeded.
	status, body, err := s.chat(t, rid, 30*time.Second)
	require.NoError(t, err)
	require.Equal(t, httpOK, status, body)
	validateChatReply(t, s, body)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, s.fixture.Since(before))

	s.waitForRecoveredBilling(t, rid, 3*time.Minute)
	original := s.requireReplayAccounting(t, rid, "original")
	rdb := s.redisClient(t)

	// Locate the original committed event entries for the target.
	entries := s.findStreamEntries(t, rdb, rid)
	require.Len(t, entries, 1, "expected one original stream notification for %s", rid)
	entry := entries[0]
	first := s.replayEntryUnderFreshID(t, rdb, entry)
	second := s.replayEntryUnderFreshID(t, rdb, entry)
	require.NotEqual(t, entry.ID, first)
	require.NotEqual(t, entry.ID, second)
	require.NotEqual(t, first, second)
	replayIDs := []string{first, second}

	// Processing proof per replay: a committed event_inbox claim row for
	// every fresh entry id (correct stream source and consumer group),
	// then a fully drained group and no parked copies anywhere.
	s.requireInboxClaimsCommitted(t, rdb, replayIDs)
	time.Sleep(5 * time.Second) // let any duplicate processing finish loudly if broken
	s.requireGroupDrained(t, rdb)
	s.assertNoRetryCarrier(t, rdb, rid)

	require.Equal(t, original, s.requireReplayAccounting(t, rid, "after redelivery"))

	// Provider ledger unchanged: redelivery is a pure consumer-side event.
	if arr, disp, recv := s.fixture.Counts(rid); arr != 1 || disp != 1 || recv != 1 {
		t.Fatalf("replay: provider ledger arr/disp/recv = %d/%d/%d, want 1/1/1 (unchanged)", arr, disp, recv)
	}

	s.controlRequest(t, "replay-post")
}

func (s *stand) requireReplayAccounting(t *testing.T, rid, phase string) string {
	t.Helper()
	org := s.oracleDB.orgID
	s.requireDurableControlEvidence(t, "chat", phase, rid, fixtureCompletionTokens)
	s.requireBilledRow(t, rid, org, phase)
	s.requireExactlyOneBilledRow(t, rid, org, phase)
	s.requireWalletChargedExactlyOnce(t, rid, org, phase)
	s.requireSettlementIntents(t, rid, org, phase, map[string]int{"resale_deduction": 1, "team_spend": 1})
	rows := s.oracleAdmissions(t, rid, org)
	require.Len(t, rows, 1, phase)
	a := rows[0]
	require.Equal(t, "reconciled", a.State, phase)
	require.True(t, a.ResolvedAt.Valid, phase)
	require.True(t, a.ResolveReason.Valid, phase)
	require.Equal(t, reasonEventLive, a.ResolveReason.String, phase)
	charge := s.oracleUsageByInvocation(t, a.InvocationID, org)
	require.EqualValues(t, 1, charge.UsageRows, phase)
	require.EqualValues(t, -fixtureMicroUSDCost, charge.SumMicroUSD, phase)
	require.Equal(t, 2, s.oracleCount(t, "SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND invocation_id=$3::uuid", org, rid, a.InvocationID), phase)
	return a.InvocationID
}
