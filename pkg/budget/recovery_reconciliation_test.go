package budget

// N12-P02-T04 — failure-recovery observability tests (owner decisions
// I40/I44/I45). The card: recover services and show backlog/gaps/
// reconciliation without repeating unknown external actions. These tests
// pin the gateway-process half of that surface (the loggerd backlog
// gauges live in services/loggerd/consumer):
//
//   - GAPS (I44, acceptance): every admission served under the explicit
//     allow_loss profile while history could not be persisted is counted
//     — in the RecoverySnapshot ledger AND history_loss_admissions_total —
//     and the loss window stamps its open/recovery times. The gap volume
//     survives recovery: recovery never rewrites lost history into
//     "complete".
//   - GAPS (I40, negative): the default reject profile NEVER counts a
//     loss — a disk-full / DB-unavailable capacity refusal is a refusal
//     (rejected_buffer_full), not a persisted or loss-accepted status, and
//     a later recovery on that profile stamps no loss bookkeeping at all.
//   - RECONCILIATION (I45, negative): an admission attempt whose dedup
//     claim lapsed UNFINISHED past the TTL has an UNKNOWN outcome — it is
//     counted as uncertain (snapshot + history_attempts_uncertain_total),
//     never reported persisted/authorized/settled anywhere, and its key
//     re-opens only as a genuinely NEW attempt: no fabricated recorded
//     outcome rides the reap. A finished claim expiring is NOT uncertain —
//     its outcome was known.
//
// The -race discipline: the counters share the ledger's mutex; the
// concurrent test below exists so the race detector sees reap/replay/
// snapshot traffic interleaved.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// lossMetric reads the N12-P02-T04 loss counter.
func lossMetric(t *testing.T) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.HistoryLossAdmissionsTotal)
}

// uncertainMetric reads the N12-P02-T04 uncertain-attempt counter.
func uncertainMetric(t *testing.T) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.HistoryAttemptsUncertainTotal)
}

// TestRecoveryLossGapVisibilitySeamPath: under allow_loss, admissions that
// the capacity check refuses are served WITH a visible loss — counted per
// admission (not per transition), stamped, and the window's recovery is
// stamped when the durable path accepts again. The gap volume survives
// recovery (I44: incomplete history never appears complete).
func TestRecoveryLossGapVisibilitySeamPath(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeAllowLoss)
	stub := newHistoryCheck(errBufferFull)
	adm.SetHistoryCapacity(stub.evaluate)
	adm.SetClock(func() time.Time { return now })

	lossBefore := lossMetric(t)

	// Outage window: every admission is served with history LOSS.
	_, dec1, err := adm.AdmitWithHistory(ctx, historyRequest("org-gap"), "gap-1")
	require.NoError(t, err, "allow_loss serves through the buffer refusal")
	require.Equal(t, HistoryLossAccepted, dec1.State)
	require.True(t, dec1.Loss, "the loss marker must ride the decision")
	_, dec2, err := adm.AdmitWithHistory(ctx, historyRequest("org-gap"), "gap-2")
	require.NoError(t, err)
	require.Equal(t, HistoryLossAccepted, dec2.State)

	snap := adm.RecoverySnapshot()
	assert.EqualValues(t, 2, snap.LossAdmissions, "each loss admission is one gap record")
	assert.True(t, snap.LossWindowOpen, "the loss window is open while the outage lasts")
	assert.True(t, snap.LossActive, "allow_loss + refusing capacity = serving with loss")
	assert.Equal(t, HistoryModeAllowLoss, snap.Mode)
	assert.Equal(t, now, snap.LastLossAt, "the most recent loss is stamped")
	assert.True(t, snap.LastRecoveryAt.IsZero(), "no recovery yet")
	assert.InDelta(t, lossBefore+2, lossMetric(t), 1e-9,
		"the Prometheus counter mirrors the ledger")
	assert.Equal(t, 0, snap.PendingInFlight,
		"AdmitWithHistory claims and completes its attempt keys inline — none stay in flight")

	// Recovery: the durable path accepts again — the window closes with a
	// stamp, but the gap volume STAYS.
	now = now.Add(time.Second)
	stub.err = nil
	_, dec3, err := adm.AdmitWithHistory(ctx, historyRequest("org-gap"), "gap-3")
	require.NoError(t, err)
	require.Equal(t, HistoryPersisted, dec3.State)
	require.False(t, dec3.Loss, "a persisted decision carries no loss marker")

	snap = adm.RecoverySnapshot()
	assert.EqualValues(t, 2, snap.LossAdmissions,
		"recovery never resets the gap volume (I44)")
	assert.False(t, snap.LossWindowOpen, "the window closed on the persisted decision")
	assert.False(t, snap.LossActive)
	assert.Equal(t, now, snap.LastRecoveryAt, "the recovery is stamped")
	assert.Equal(t, now.Add(-time.Second), snap.LastLossAt, "the last loss stamp survives")
}

// TestRecoveryRejectProfileNeverCountsLoss: the default reject profile —
// the disk-full / DB-unavailable shape — refuses (rejected_buffer_full),
// never serves, never counts a loss, and a later recovery on that profile
// stamps no loss bookkeeping (there was no loss window to recover).
func TestRecoveryRejectProfileNeverCountsLoss(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeReject) // the fail-safe default
	stub := newHistoryCheck(errBufferFull)
	adm.SetHistoryCapacity(stub.evaluate)
	adm.SetClock(func() time.Time { return now })

	lossBefore := lossMetric(t)
	refusalBefore := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(HistoryDenialScope))

	_, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-rej"), "rej-1")
	require.ErrorIs(t, err, ErrHistoryCapacity,
		"disk-full under the default profile refuses the attempt")
	require.Equal(t, HistoryRejectedFull, dec.State,
		"the refusal is a typed refusal — never persisted, never loss-accepted")
	require.False(t, dec.Loss)

	require.InDelta(t, refusalBefore+1,
		testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(HistoryDenialScope)), 1e-9,
		"the refusal is counted as a denial")
	require.InDelta(t, lossBefore, lossMetric(t), 1e-9,
		"a refusal is NOT a loss admission — the reject profile never serves a gap")

	// The durable path recovers; the profile admits — with zero loss
	// bookkeeping anywhere.
	now = now.Add(time.Second)
	stub.err = nil
	_, dec, err = adm.AdmitWithHistory(ctx, historyRequest("org-rej"), "rej-2")
	require.NoError(t, err)
	require.Equal(t, HistoryPersisted, dec.State)

	snap := adm.RecoverySnapshot()
	assert.EqualValues(t, 0, snap.LossAdmissions)
	assert.True(t, snap.LastLossAt.IsZero())
	assert.True(t, snap.LastRecoveryAt.IsZero(),
		"no loss window was open — a clean recovery stamps nothing")
	assert.False(t, snap.LossWindowOpen)
	assert.False(t, snap.LossActive)
}

// TestRecoveryLossVisibilityArmedGatePath: the same gap accounting applies
// when the N10-P04-T03 HistoryAdmission is armed — the delegated wiring
// must feed the identical reconciliation surface (one vocabulary, one
// accounting).
func TestRecoveryLossVisibilityArmedGatePath(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	gate := newTestHistoryAdmission(HistoryModeAllowLoss, &probeOut{state: HistoryStateWriteUnavailable})
	adm.SetHistoryAdmission(gate)
	adm.SetHistoryMode(HistoryModeAllowLoss)
	adm.SetClock(func() time.Time { return now })

	lossBefore := lossMetric(t)
	_, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-gate"), "gate-1")
	require.NoError(t, err, "allow_loss serves through the store outage")
	require.Equal(t, HistoryLossAccepted, dec.State)

	snap := adm.RecoverySnapshot()
	assert.EqualValues(t, 1, snap.LossAdmissions)
	assert.True(t, snap.LossActive, "the armed gate owns LossActive")
	assert.True(t, snap.LossWindowOpen)
	assert.Equal(t, now, snap.LastLossAt)
	assert.InDelta(t, lossBefore+1, lossMetric(t), 1e-9)

	// Probe recovers → persisted → recovery stamped once.
	now = now.Add(time.Second)
	gateProbe := gate.probe.(*probeOut)
	gateProbe.state = HistoryStateOK
	gateProbe.err = nil
	_, dec, err = adm.AdmitWithHistory(ctx, historyRequest("org-gate"), "gate-2")
	require.NoError(t, err)
	require.Equal(t, HistoryPersisted, dec.State)

	snap = adm.RecoverySnapshot()
	assert.EqualValues(t, 1, snap.LossAdmissions, "the gap volume survives recovery")
	assert.False(t, snap.LossWindowOpen)
	assert.False(t, snap.LossActive)
	assert.Equal(t, now, snap.LastRecoveryAt)
}

// TestUncertainAttemptReconciliation: the I45 reconciliation teeth. An
// in-flight claim reaped past the TTL = an attempt with UNKNOWN outcome —
// counted once as uncertain, never fabricated into a recorded outcome,
// never counted as persisted/settled. A finished claim expiring is not
// uncertain (its outcome was known).
func TestUncertainAttemptReconciliation(t *testing.T) {
	now := time.Now()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeReject)
	adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate)
	adm.SetClock(func() time.Time { return now })
	ctx := context.Background()

	uncertainBefore := uncertainMetric(t)

	// A claim whose owner dies mid-attempt (never completed).
	if _, claimed := adm.claimAttempt("crash-1"); !claimed {
		t.Fatal("the fresh claim must be grantable")
	}
	snap := adm.RecoverySnapshot()
	require.Equal(t, 1, snap.PendingInFlight, "the live claim is in flight")

	// The TTL lapses; the next touch of the key reaps the unfinished claim
	// as UNCERTAIN and re-opens the key as a NEW attempt.
	now = now.Add(DefaultHistoryAttemptTTL + time.Second)
	rec, claimed := adm.claimAttempt("crash-1")
	require.True(t, claimed, "the reaped key re-opens as a genuinely new attempt")
	require.False(t, rec.done, "no fabricated recorded outcome rides the reap")

	snap = adm.RecoverySnapshot()
	assert.EqualValues(t, 1, snap.UncertainAttempts, "the unknown outcome is counted once")
	assert.Equal(t, now, snap.LastUncertainAt)
	assert.InDelta(t, uncertainBefore+1, uncertainMetric(t), 1e-9,
		"the Prometheus counter mirrors the reconciliation ledger")
	assert.Equal(t, 1, snap.PendingInFlight, "the new claim is the live one")

	// The successor completes with an honest, freshly-evaluated admission
	// (a distinct key: the reaped attempt's key is still held in flight) —
	// the OLD uncertain count stays.
	_, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-recon"), "recon-1")
	require.NoError(t, err)
	require.Equal(t, HistoryPersisted, dec.State,
		"the successor attempt is a fresh, honestly-evaluated admission")
	assert.EqualValues(t, 1, adm.RecoverySnapshot().UncertainAttempts,
		"completing a successor never rewrites the predecessor's uncertainty")

	// A FINISHED claim expiring is NOT uncertain: the outcome was known.
	if _, claimed := adm.claimAttempt("done-1"); !claimed {
		t.Fatal("fresh claim")
	}
	now = now.Add(time.Second)
	adm.completeAttempt("done-1", HistoryDecision{Mode: HistoryModeReject, State: HistoryPersisted}, true, nil)
	now = now.Add(DefaultHistoryAttemptTTL + time.Second)
	if _, claimed := adm.claimAttempt("done-1"); !claimed {
		t.Fatal("the expired finished claim re-opens")
	}
	assert.EqualValues(t, 1, adm.RecoverySnapshot().UncertainAttempts,
		"an expired finished claim is history, not uncertainty")
	assert.InDelta(t, uncertainBefore+1, uncertainMetric(t), 1e-9,
		"reaping a finished claim must not bump the uncertain counter")
}

// TestUncertainReplayHasNoFabricatedOutcome: the negative retry tooth —
// while a reaped-then-reclaimed key is still in flight, a replay under
// that key is REFUSED without any outcome claim (the claim has no recorded
// decision yet): retrying must not reproduce an unknown result, and the
// refusal must not invent persisted/settled state.
func TestUncertainReplayHasNoFabricatedOutcome(t *testing.T) {
	now := time.Now()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeReject)
	adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate)
	adm.SetClock(func() time.Time { return now })
	ctx := context.Background()

	// Crash mid-attempt, reap, re-claim as a new attempt (still in flight).
	_, _ = adm.claimAttempt("replay-k")
	now = now.Add(DefaultHistoryAttemptTTL + time.Second)
	_, _ = adm.claimAttempt("replay-k")

	// Concurrent duplicate of the in-flight successor: refused, and the
	// ridden decision must carry no outcome state (nothing is recorded
	// yet) — never persisted, never loss-accepted.
	rsv, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-replay"), "replay-k")
	require.ErrorIs(t, err, ErrAttemptReplayed, "a duplicate of an in-flight attempt is refused")
	require.Nil(t, rsv, "a refused duplicate holds no reservation")
	assert.Equal(t, HistoryNotGated, dec.State,
		"no outcome exists for an in-flight claim — the refusal must not fabricate one")
	assert.False(t, dec.Loss)
	assert.EqualValues(t, 0, adm.RecoverySnapshot().LossAdmissions,
		"the refusal fabricates no loss — this controller's ledger stays clean")
}

// TestRecoverySnapshotConcurrentTraffic: reap/replay/decision bookkeeping
// stays consistent under concurrent attempts (the race detector is the
// real judge; the assertion is the invariant, not a count freeze). The
// clock advances one TTL per read via an atomic counter: some claims lapse
// unfinished (uncertain reap) and some completed (history reap) — both
// reap paths race against replays and snapshots with no shared mutable
// clock variable.
func TestRecoverySnapshotConcurrentTraffic(t *testing.T) {
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeReject)
	adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate)
	var tick int64
	base := time.Now()
	adm.SetClock(func() time.Time {
		return base.Add(time.Duration(atomic.AddInt64(&tick, 1)) * (DefaultHistoryAttemptTTL + time.Second))
	})
	ctx := context.Background()

	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				key := fmt.Sprintf("race-%d-%d", w, i%10)
				_, _, _ = adm.AdmitWithHistory(ctx, historyRequest("org-race"), key)
				_ = adm.RecoverySnapshot()
			}
		}(w)
	}
	wg.Wait()

	// Every worker's claims completed inline (or were reaped and deleted),
	// so nothing may remain in flight once the traffic stops.
	snap := adm.RecoverySnapshot()
	assert.Equal(t, 0, snap.PendingInFlight,
		"completed-or-reaped attempt claims never stay in flight")
	assert.Equal(t, HistoryModeReject, snap.Mode)
	assert.False(t, snap.LossWindowOpen, "reject profile never opens a loss window")
	assert.False(t, snap.LossActive)
}
