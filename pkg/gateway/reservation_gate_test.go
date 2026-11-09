package cli

// NEXT-18c unit tests for the gateway reservation embedding: the D4 input
// profile, the §9 denial mapping, the finalize actuals (mirroring the
// consumer's charge resolution) and the off/nil safety of the gate.

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/money"
)

func TestReservationInputProfile(t *testing.T) {
	// Plain text: bytes unchanged, no images.
	b, img := reservationInputProfile([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	require.Zero(t, img)
	require.Equal(t, int64(len(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)), b)

	// OpenAI data-URI image: the base64 span leaves the byte estimate, the
	// image prices flat.
	body := []byte(`{"image_url":{"url":"data:image/png;base64,` + b64Of(600) + `"}}`)
	b, img = reservationInputProfile(body)
	require.Equal(t, int64(1), img)
	require.Less(t, b, int64(len(body)))
	require.GreaterOrEqual(t, b, int64(len(`{"image_url":{"url":"data:image/png;base64,"}}`)))

	// Anthropic base64 source block.
	anth := []byte(`{"source":{"type":"base64","media_type":"image/png","data":"` + b64Of(600) + `"}}`)
	b, img = reservationInputProfile(anth)
	require.Equal(t, int64(1), img)
	require.Less(t, b, int64(len(anth)))
}

// b64Of renders n characters of base64-shaped payload (well past the strip
// threshold).
func b64Of(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i%64]
	}
	return string(out)
}

func TestWriteReservationDenialMapping(t *testing.T) {
	cases := []struct {
		name    string
		denial  *budget.Denial
		status  int
		code    string
		message string
	}{
		{
			name:   "wallet exhaustion is 402",
			denial: &budget.Denial{Scope: budget.ScopeWallet, Err: budget.ErrInsufficientCapacity},
			status: 402, code: "insufficient_credits",
		},
		{
			name:   "team exhaustion is 429",
			denial: &budget.Denial{Scope: budget.ScopeTeamMonth, Err: budget.ErrInsufficientCapacity},
			status: 429, code: "budget_exceeded",
		},
		{
			name:   "agent exhaustion is 429",
			denial: &budget.Denial{Scope: budget.ScopeAgentDay, Err: budget.ErrInsufficientCapacity},
			status: 429, code: "agent_budget_exceeded",
		},
		{
			name:   "session exhaustion is 429",
			denial: &budget.Denial{Scope: budget.ScopeSession, Err: budget.ErrInsufficientCapacity},
			status: 429, code: "session_budget_exceeded",
		},
		{
			name:   "unpriced is 403 model_unpriced (I3)",
			denial: &budget.Denial{Scope: budget.ScopeWallet, Err: budget.ErrUnpricedModel},
			status: 403, code: "model_unpriced",
		},
		{
			name:   "missing team budget is fail-closed 403 (D14)",
			denial: &budget.Denial{Scope: budget.ScopeTeamMonth, Err: budget.ErrNoCapacitySource},
			status: 403, code: "budget_not_configured",
		},
		{
			name:   "missing wallet is 402",
			denial: &budget.Denial{Scope: budget.ScopeWallet, Err: budget.ErrNoCapacitySource},
			status: 402, code: "insufficient_credits",
		},
		{
			name:   "store outage is 503",
			denial: &budget.Denial{Scope: budget.ScopeWallet, Err: errors.New("boom")},
			status: 503,
		},
		{
			name:   "history outage is 503 history_unavailable (I40, N12-P01-T02)",
			denial: &budget.Denial{Scope: budget.ScopeWallet, Err: budget.ErrHistoryUnavailable},
			status: 503, code: "history_unavailable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeReservationDenial(rec, tc.denial)
			require.Equal(t, tc.status, rec.Code)
			if tc.code != "" {
				require.Contains(t, rec.Body.String(), tc.code)
			}
		})
	}
}

// TestReservationActualsMirrorConsumer pins the finalize actuals to the
// consumer's charge resolution: wallet = resale (positive only), budgets =
// base quote (including zero), unknown never a zero.
func TestReservationActualsMirrorConsumer(t *testing.T) {
	wallet, budgeted := reservationActuals(1.5, 1.0)
	require.Equal(t, money.MicroUSD(1_500_000), wallet)
	require.Equal(t, money.MicroUSD(1_000_000), budgeted)

	// Resale missing (no markup pricer): wallet falls back to base.
	wallet, _ = reservationActuals(0, 0.25)
	require.Equal(t, money.MicroUSD(250_000), wallet)

	// Unknown price: no wallet spend, no budget spend.
	wallet, budgeted = reservationActuals(0, -3)
	require.Zero(t, int64(wallet))
	require.Zero(t, int64(budgeted))

	// Genuine zero is a legitimate zero for the budget areas.
	_, budgeted = reservationActuals(0, 0)
	require.Zero(t, int64(budgeted))
}

// TestReservationGateNilAndOffSafety: every pipeline touchpoint tolerates a
// nil gate (off mode — the legacy behavior).
func TestReservationGateNilAndOffSafety(t *testing.T) {
	var nilGate *reservationGate
	ctx := withReservationGate(context.Background(), nilGate)
	require.Nil(t, reservationGateFrom(ctx))
	require.NotPanics(t, func() {
		require.True(t, nilGate.reserve(context.Background()))
		ev := &eventpub.Event{}
		nilGate.attach(ev, budget.TerminationCompleted)
		require.Empty(t, ev.Reservations)
		require.Empty(t, ev.Termination)
		nilGate.finalize(ev, 1, 1, budget.TerminationCompleted)
		nilGate.finalizeNoEvent(budget.TerminationUpstreamErr)
	})

	offGate := &reservationGate{plan: &budget.Plan{Mode: budget.ModeOff}}
	require.True(t, offGate.off())
	require.NotPanics(t, func() {
		require.True(t, offGate.reserve(context.Background()))
		ev := &eventpub.Event{}
		offGate.finalize(ev, 1, 1, budget.TerminationCompleted)
		require.Empty(t, ev.Reservations)
	})
}

// TestCompletionTerminationClassify: a dead request context means the
// client walked away (§5.3).
func TestCompletionTerminationClassify(t *testing.T) {
	require.Equal(t, budget.TerminationCompleted, completionTermination(context.Background()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, budget.TerminationClientCancel, completionTermination(ctx))
}
