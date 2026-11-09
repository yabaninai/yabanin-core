package cli

// N12-P01-T02 (owner decision 2026-11-04): gateway-side production wiring of
// the N10-P04-T03 durable request-history admission (I40/I44). Pins:
//   - knob resolution is explicit and fail-closed (an enabled knob with a
//     missing dependency aborts startup; unknown modes resolve to reject);
//   - a history-only deployment (reservations off, nil store, no DB pool)
//     still arms the per-request consult and denies on outage;
//   - the outage denial answers 503 history_unavailable and lands on the
//     dedicated "history" metric scope, not wallet;
//   - allow_loss serves through an outage (I44) with the money leg off;
//   - the default config leaves the request path bit-for-bit.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// deadRedis returns a client pointed at a freshly closed listener port: the
// probe reads every dial failure as "state unverifiable", which the T01
// contract fails closed to a write outage. Deterministic without a live
// Redis (no well-known port is assumed).
func deadRedis(t *testing.T) *redis.Client {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return redis.NewClient(&redis.Options{
		Addr:        addr,
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
		MaxRetries:  -1,
	})
}

func historyTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// historyArmedCfg returns the default config with the knob armed for the
// given event stream.
func historyArmedCfg(stream, mode string) config.Gateway {
	cfg := config.DefaultGateway()
	cfg.HistoryAdmissionEnabled = true
	cfg.EventStream = stream
	cfg.HistoryMode = mode
	return cfg
}

func TestBuildHistoryAdmissionDisabledByDefault(t *testing.T) {
	cfg := config.DefaultGateway()
	require.False(t, cfg.HistoryAdmissionEnabled)
	gate, err := buildHistoryAdmission(cfg, &redis.Client{}, historyTestLogger())
	require.NoError(t, err)
	require.Nil(t, gate, "the default config must leave the request path bit-for-bit (no gate, no probe round-trips)")
}

func TestBuildHistoryAdmissionGuards(t *testing.T) {
	t.Run("enabled without redis is a startup error", func(t *testing.T) {
		gate, err := buildHistoryAdmission(historyArmedCfg("events:queue", ""), nil, historyTestLogger())
		require.Error(t, err)
		require.Nil(t, gate)
		require.Contains(t, err.Error(), "Redis")
	})

	t.Run("empty event stream is a startup error", func(t *testing.T) {
		gate, err := buildHistoryAdmission(historyArmedCfg("", ""), &redis.Client{}, historyTestLogger())
		require.Error(t, err)
		require.Nil(t, gate)
		require.Contains(t, err.Error(), "event_stream")
	})

	t.Run("negative depth bound is a startup error", func(t *testing.T) {
		cfg := historyArmedCfg("events:queue", "")
		cfg.HistoryProbeMaxEntries = -1
		gate, err := buildHistoryAdmission(cfg, &redis.Client{}, historyTestLogger())
		require.Error(t, err)
		require.Nil(t, gate)
		require.Contains(t, err.Error(), "history_probe_max_entries")
	})
}

func TestBuildHistoryAdmissionModes(t *testing.T) {
	cases := []struct {
		raw  string
		want budget.HistoryMode
	}{
		{"", budget.HistoryModeReject},
		{"reject", budget.HistoryModeReject},
		{"allow_loss", budget.HistoryModeAllowLoss},
		// config.Validate rejects unknown values at startup; the runtime
		// resolution still fail-closes to reject (T01 contract — a value
		// that skips Validate must never open the gate by accident).
		{"allow-loss", budget.HistoryModeReject},
		{"enforce", budget.HistoryModeReject},
	}
	for _, tc := range cases {
		t.Run("mode '"+tc.raw+"'", func(t *testing.T) {
			gate, err := buildHistoryAdmission(historyArmedCfg("events:queue", tc.raw), &redis.Client{}, historyTestLogger())
			require.NoError(t, err)
			require.NotNil(t, gate)
			require.Equal(t, tc.want, gate.Mode())
		})
	}
}

// TestBuildGatewayAccountingHistoryOnlyPoolLess pins the pool-less wiring
// branch: with the knob armed and no DB pool, the metering facet stays nil
// (historical gate) but the admission controller exists and consults the
// history gate per request — a real probe against an unreachable Redis
// makes the state unverifiable, which rejects terminally with 503
// history_unavailable on the dedicated metric scope (the full fail-closed
// chain through the production wiring, no live Redis needed).
func TestBuildGatewayAccountingHistoryOnlyPoolLess(t *testing.T) {
	rdb := deadRedis(t)
	t.Cleanup(func() { _ = rdb.Close() })

	w := &gatewayWiring{cfg: historyArmedCfg("events:queue", ""), rdb: rdb, l: historyTestLogger()}
	gw := &gateway{}
	require.NoError(t, buildGatewayAccounting(context.Background(), w, gw))
	require.NotNil(t, gw.admission, "an armed knob must produce the per-request consult even without a DB pool")

	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	// Delta-based metric assertions: the promauto registry is global to the
	// package, so other tests may touch the wallet scope (shuffle-safe).
	before := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(budget.HistoryDenialScope))
	walletBefore := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues("wallet"))

	gate, ok := gw.reservationPlan(rec, r, "chat.completions", budget.Request{})
	require.False(t, ok, "an unverifiable history state must deny terminally under the default reject policy")
	require.Nil(t, gate)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "history_unavailable")
	require.Contains(t, rec.Body.String(), "durable request history temporarily unavailable")

	after := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(budget.HistoryDenialScope))
	require.InDelta(t, before+1, after, 0, "the refusal must land on the history scope, not wallet")
	require.InDelta(t, walletBefore,
		testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues("wallet")), 0,
		"no wallet-scope denial may be recorded for a history outage")
}

// TestBuildGatewayAccountingKnobOffKeepsLegacy pins the disabled side of the
// same branch: no controller is built, reservationPlan passes untouched.
func TestBuildGatewayAccountingKnobOffKeepsLegacy(t *testing.T) {
	w := &gatewayWiring{cfg: config.DefaultGateway(), rdb: nil, l: historyTestLogger()}
	gw := &gateway{}
	require.NoError(t, buildGatewayAccounting(context.Background(), w, gw))
	require.Nil(t, gw.admission, "the default config must not build an admission controller")

	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	gate, ok := gw.reservationPlan(rec, r, "chat.completions", budget.Request{})
	require.True(t, ok)
	require.Nil(t, gate)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Body.String())
}

// TestBuildGatewayAccountingHistoryAdmissionMisconfiguredAborts pins the
// fail-closed posture at the wiring call site: an enabled knob without
// Redis aborts gateway startup (buildGatewayAccounting returns the error),
// it never degrades to serve-without-history.
func TestBuildGatewayAccountingHistoryAdmissionMisconfiguredAborts(t *testing.T) {
	w := &gatewayWiring{cfg: historyArmedCfg("events:queue", ""), rdb: nil, l: historyTestLogger()}
	gw := &gateway{}
	err := buildGatewayAccounting(context.Background(), w, gw)
	require.Error(t, err)
	require.Nil(t, gw.admission)
}

// stubHistoryProbe is the controllable HistoryProbe for the decision-table
// tests below (the armed-gate seam takes the interface).
type stubHistoryProbe struct {
	state budget.HistoryState
	err   error
}

func (s stubHistoryProbe) ProbeHistory(ctx context.Context) (budget.HistoryState, error) {
	return s.state, s.err
}

// historyOnlyController mirrors the wiring shape buildGatewayAccounting uses
// for a history-only deployment: nil store, ModeOff money leg, armed gate.
func historyOnlyController(t *testing.T, probe budget.HistoryProbe, mode budget.HistoryMode) *budget.Admission {
	t.Helper()
	adm := budget.NewAdmission(nil, budget.ScopedRateSource{}, historyTestLogger(),
		"test-replica", budget.ModeOff, nil, budget.DefaultAdmissionConfig())
	adm.SetHistoryAdmission(budget.NewHistoryAdmission(probe, mode, historyTestLogger()))
	adm.Start(context.Background()) // no-ops on ModeOff; kept for wiring parity
	return adm
}

func TestReservationPlanHistoryOutageDecisionTable(t *testing.T) {
	outage := stubHistoryProbe{state: budget.HistoryStateWriteUnavailable, err: errors.New("loggerd signal stale")}

	t.Run("reject denies with 503 history_unavailable", func(t *testing.T) {
		gw := &gateway{admission: historyOnlyController(t, outage, budget.HistoryModeReject)}
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
		before := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(budget.HistoryDenialScope))

		gate, ok := gw.reservationPlan(rec, r, "chat.completions", budget.Request{})
		require.False(t, ok)
		require.Nil(t, gate)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "history_unavailable")
		require.InDelta(t, before+1,
			testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(budget.HistoryDenialScope)), 0)
	})

	t.Run("buffer_full state also denies (saturated stream)", func(t *testing.T) {
		gw := &gateway{admission: historyOnlyController(t,
			stubHistoryProbe{state: budget.HistoryStateBufferFull}, budget.HistoryModeReject)}
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/embeddings", nil)
		gate, ok := gw.reservationPlan(rec, r, "embeddings", budget.Request{})
		require.False(t, ok)
		require.Nil(t, gate)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "history_unavailable")
	})

	t.Run("allow_loss serves through the outage (I44)", func(t *testing.T) {
		gw := &gateway{admission: historyOnlyController(t, outage, budget.HistoryModeAllowLoss)}
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
		gate, ok := gw.reservationPlan(rec, r, "chat.completions", budget.Request{})
		require.True(t, ok, "the explicit allow_loss opt-in must serve through the outage")
		require.Nil(t, gate, "the money leg stays off — no reservation gate")
		require.Empty(t, rec.Body.String(), "no denial body may be written")
	})

	t.Run("healthy history serves with the money leg off", func(t *testing.T) {
		gw := &gateway{admission: historyOnlyController(t,
			stubHistoryProbe{state: budget.HistoryStateOK}, budget.HistoryModeReject)}
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
		gate, ok := gw.reservationPlan(rec, r, "chat.completions", budget.Request{})
		require.True(t, ok)
		require.Nil(t, gate, "reservations off — the plan is ModeOff even though the gate consulted")
		require.Empty(t, rec.Body.String())
	})
}

// TestWriteReservationDenialHistoryEnvelope pins the response envelope for
// the typed outage wrapper (errors.Is through HistoryOutageError.Unwrap).
func TestWriteReservationDenialHistoryEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	writeReservationDenial(rec, &budget.Denial{
		Scope: budget.ScopeWallet,
		Err:   &budget.HistoryOutageError{State: budget.HistoryStateBufferFull},
	})
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "history_unavailable")
	require.Contains(t, rec.Body.String(), "YABANIN_HISTORY_MODE")
}
