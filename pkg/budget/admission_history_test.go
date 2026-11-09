package budget

// N10-P04-T03 policy tests (owner decisions I40/I44). The invariants under
// pin:
//   - default reject: any durable-history outage (buffer full, write
//     unavailable, unverifiable state) denies admission under the default
//     mode, typed as ErrHistoryUnavailable — never as budget exhaustion;
//   - allow_loss is a strictly narrower opt-in: it serves with a loud,
//     exactly-once loss flag but never relaxes spend accounting (an
//     enforce-mode store outage still denies) and never bypasses the
//     reservations machinery;
//   - the gate is deployment-level: it consults BEFORE the reservations
//     mode checks (orgs with reservations off are still history-gated);
//   - the Redis probe fails CLOSED: read errors and unparseable signals are
//     outages, not healthy states.
// Unit-level on purpose: probeOut/fakeRedis stand in for the inter-process
// seam, no live Redis or Postgres.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// probeOut is a canned HistoryProbe.
type probeOut struct {
	state HistoryState
	err   error
	calls int
}

func (p *probeOut) ProbeHistory(context.Context) (HistoryState, error) {
	p.calls++
	return p.state, p.err
}

func newTestHistoryAdmission(mode HistoryMode, probe HistoryProbe) *HistoryAdmission {
	return NewHistoryAdmission(probe, mode, slog.New(slog.DiscardHandler))
}

func TestResolveHistoryMode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want HistoryMode
	}{
		{"default empty", "", HistoryModeReject},
		{"explicit reject", "reject", HistoryModeReject},
		{"explicit allow_loss", "allow_loss", HistoryModeAllowLoss},
		{"unknown value fails closed", "serve_anyway", HistoryModeReject},
		{"wrong case fails closed", "Allow_Loss", HistoryModeReject},
		{"near miss fails closed", "allow loss", HistoryModeReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveHistoryMode(tc.in))
		})
	}
}

func TestHistoryAdmission_DisarmedByDefault(t *testing.T) {
	// No probe wired: the gate must be a no-op (wiring the reader is an
	// explicit deployment step, and tests without Redis stay inert).
	h := newTestHistoryAdmission(HistoryModeReject, nil)
	require.NoError(t, h.Admit(context.Background()))
	assert.Equal(t, HistoryState(""), h.State(), "no observation without a probe")
	assert.False(t, h.LossActive())

	var nilGate *HistoryAdmission
	require.NoError(t, nilGate.Admit(context.Background()), "nil receiver is disarmed")
	assert.Equal(t, HistoryModeReject, nilGate.Mode())
}

func TestHistoryAdmission_RejectModeFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		probe     probeOut
		wantState HistoryState
	}{
		{"buffer full", probeOut{state: HistoryStateBufferFull}, HistoryStateBufferFull},
		{"write unavailable", probeOut{state: HistoryStateWriteUnavailable}, HistoryStateWriteUnavailable},
		{"probe error is unverifiable", probeOut{err: errors.New("redis timeout")}, HistoryStateWriteUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.probe
			h := newTestHistoryAdmission(HistoryModeReject, &p)
			ctx := context.Background()

			err := h.Admit(ctx)
			require.Error(t, err, "default policy must deny on outage")
			var outage *HistoryOutageError
			require.ErrorAs(t, err, &outage)
			assert.Equal(t, tc.wantState, outage.State)
			require.ErrorIs(t, err, ErrHistoryUnavailable,
				"denial identity must be the history outage, not budget exhaustion")
			var notADenial *Denial
			assert.NotErrorAs(t, err, &notADenial, "the outage must not surface as a budget-scope denial")
			assert.Equal(t, tc.wantState, h.State())
			assert.False(t, h.LossActive(), "reject mode never serves with loss")

			// Steady state: repeated admits keep the denial and keep
			// re-consulting the probe (an outage is never cached healthy).
			err = h.Admit(ctx)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrHistoryUnavailable)
			assert.Equal(t, 2, p.calls)
		})
	}
}

func TestHistoryAdmission_AllowLossServesAndFlags(t *testing.T) {
	var buf logBuffer
	p := &probeOut{state: HistoryStateBufferFull}
	h := NewHistoryAdmission(p, HistoryModeAllowLoss, buf.logger())
	ctx := context.Background()

	require.NoError(t, h.Admit(ctx), "allow_loss serves through a buffer outage")
	assert.True(t, h.LossActive(), "the loss flag must be observable")
	assert.Equal(t, HistoryStateBufferFull, h.State())
	logs := buf.take()
	require.Len(t, logs, 1, "the loss transition logs exactly once")
	assert.Contains(t, logs[0], "allow_loss")
	assert.Contains(t, logs[0], "fail-closed")

	// Steady outage: no log spam.
	require.NoError(t, h.Admit(ctx))
	assert.Empty(t, buf.take())

	// Recovery clears the flag and logs once.
	p.state = HistoryStateOK
	require.NoError(t, h.Admit(ctx))
	assert.False(t, h.LossActive())
	logs = buf.take()
	require.Len(t, logs, 1)
	assert.Contains(t, logs[0], "recovered")

	// A NEW outage warns again (not exactly-once forever — once per
	// transition).
	p.state = HistoryStateWriteUnavailable
	require.NoError(t, h.Admit(ctx))
	assert.True(t, h.LossActive())
	require.Len(t, buf.take(), 1)
}

func TestHistoryAdmission_RejectModeLogsTransitionsExactlyOnce(t *testing.T) {
	var buf logBuffer
	p := &probeOut{state: HistoryStateOK}
	h := NewHistoryAdmission(p, HistoryModeReject, buf.logger())
	ctx := context.Background()

	require.NoError(t, h.Admit(ctx)) // first observation: arm (Info)
	logs := buf.take()
	require.Len(t, logs, 1, "arming is logged once, at Info")
	assert.Contains(t, logs[0], "armed")
	require.NoError(t, h.Admit(ctx))
	assert.Empty(t, buf.take(), "steady healthy is silent")

	p.state = HistoryStateWriteUnavailable
	require.Error(t, h.Admit(ctx))
	logs = buf.take()
	require.Len(t, logs, 1)
	assert.Contains(t, logs[0], "REJECTED")

	require.Error(t, h.Admit(ctx))
	assert.Empty(t, buf.take(), "steady outage must not spam")

	p.state = HistoryStateOK
	require.NoError(t, h.Admit(ctx))
	logs = buf.take()
	require.Len(t, logs, 1)
	assert.Contains(t, logs[0], "recovered")
}

func TestPlan_HistoryGateIsDeploymentLevel(t *testing.T) {
	outage := &probeOut{state: HistoryStateWriteUnavailable}
	req := Request{OrgID: "org-h", Chain: []ChainHop{{Provider: "prov", Model: "model-1"}}, InputBytes: 1024}

	// Armed + reject + outage + reservations OFF: the history denial wins
	// — the gate runs before the ModeOff early return.
	adm := newOutageAdmission(ModeOff)
	adm.SetHistoryAdmission(newTestHistoryAdmission(HistoryModeReject, outage))
	_, err := adm.Plan(context.Background(), req)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryUnavailable)

	// Same shape for a blank org (the other ModeOff early return).
	_, err = adm.Plan(context.Background(), Request{Chain: req.Chain})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHistoryUnavailable)

	// Armed + allow_loss + reservations OFF: served, with the loss flag set.
	lossy := &probeOut{state: HistoryStateBufferFull}
	lossGate := newTestHistoryAdmission(HistoryModeAllowLoss, lossy)
	adm.SetHistoryAdmission(lossGate)
	plan, err := adm.Plan(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, ModeOff, plan.Mode, "reservations mode still governs the plan shape")
	assert.True(t, lossGate.LossActive())
	assert.Positive(t, lossy.calls, "the probe was consulted before the mode checks")
}

// TestPlan_HistoryDisarmedPreservesLegacyMode pins the bit-identical legacy
// path: no gate wired (or disarmed) → the §9 mode early returns are
// untouched, including the nil receiver.
func TestPlan_HistoryDisarmedPreservesLegacyMode(t *testing.T) {
	adm := newOutageAdmission(ModeOff)
	req := Request{OrgID: "org-h", Chain: []ChainHop{{Provider: "prov", Model: "model-1"}}}
	plan, err := adm.Plan(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, ModeOff, plan.Mode)

	var nilAdmission *Admission
	plan, err = nilAdmission.Plan(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, ModeOff, plan.Mode)
}

// TestHistoryLossNeverRelaxesSpendAccounting is the I44 isolation pin:
// serving through a history outage must not turn a failed money check into
// a reservation. Enforce mode with an unreachable Postgres still denies on
// Reserve even while allow_loss is active.
func TestHistoryLossNeverRelaxesSpendAccounting(t *testing.T) {
	p := &probeOut{state: HistoryStateWriteUnavailable}
	adm := newOutageAdmission(ModeEnforce)
	adm.SetHistoryAdmission(newTestHistoryAdmission(HistoryModeAllowLoss, p))

	plan, err := adm.Plan(context.Background(), outageRequest())
	require.NoError(t, err, "allow_loss admits the plan through the history outage")
	assert.True(t, adm.history.LossActive())

	rsv, err := adm.Reserve(context.Background(), plan)
	require.Error(t, err, "the money check stays fail-closed under loss")
	require.Nil(t, rsv)
	var denial *Denial
	require.ErrorAs(t, err, &denial)
	assert.Equal(t, ScopeWallet, denial.Scope)
}

// TestHistoryRejectDeniesBeforeBudgetStore pins that the default-reject
// outage denial surfaces BEFORE any budget-store round trip: the money
// path is not even consulted while durable history cannot be guaranteed.
func TestHistoryRejectDeniesBeforeBudgetStore(t *testing.T) {
	p := &probeOut{state: HistoryStateBufferFull, err: nil}
	adm := newOutageAdmission(ModeEnforce)
	adm.SetHistoryAdmission(newTestHistoryAdmission(HistoryModeReject, p))

	_, err := adm.Plan(context.Background(), outageRequest())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHistoryUnavailable)
}

// --- wire contract -------------------------------------------------------

func TestHistorySignalWireContract(t *testing.T) {
	key := HistorySignalKey("events:queue")
	assert.Equal(t, "events:history:admission:events:queue", key)

	in := HistorySignal{State: HistoryStateBufferFull, Detail: "depth", Depth: 42, UnixSec: 1700000000}
	raw, err := EncodeHistorySignal(in)
	require.NoError(t, err)
	out, err := ParseHistorySignal(raw)
	require.NoError(t, err)
	assert.Equal(t, in, out)

	// Zero depth normalizes to unknown (-1) in both directions.
	raw, err = EncodeHistorySignal(HistorySignal{State: HistoryStateOK, UnixSec: 1})
	require.NoError(t, err)
	out, err = ParseHistorySignal(raw)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), out.Depth)

	// Unknown states and garbage are hard parse errors (a future writer
	// must not silently downgrade the policy).
	_, err = ParseHistorySignal([]byte(`{"state":"who_knows","unix_sec":1}`))
	require.Error(t, err)
	_, err = ParseHistorySignal([]byte("not json"))
	require.Error(t, err)
}

// --- Redis probe ---------------------------------------------------------

// fakeRedis is a HistoryRedis double: one canned GET result and a stream
// depth for XLen.
type fakeRedis struct {
	getVal  string
	getErr  error
	xlen    int64
	xlenErr error
}

func (f *fakeRedis) Get(ctx context.Context, _ string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	if f.getErr != nil {
		cmd.SetErr(f.getErr)
		return cmd
	}
	cmd.SetVal(f.getVal)
	return cmd
}

func (f *fakeRedis) XLen(ctx context.Context, _ string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	if f.xlenErr != nil {
		cmd.SetErr(f.xlenErr)
		return cmd
	}
	cmd.SetVal(f.xlen)
	return cmd
}

func mustSignal(t *testing.T, s HistorySignal) string {
	t.Helper()
	raw, err := EncodeHistorySignal(s)
	require.NoError(t, err)
	return string(raw)
}

func TestRedisHistoryProbe_DecisionTable(t *testing.T) {
	okPayload := mustSignal(t, HistorySignal{State: HistoryStateOK, UnixSec: 1})
	fullPayload := mustSignal(t, HistorySignal{State: HistoryStateBufferFull, UnixSec: 1})
	downPayload := mustSignal(t, HistorySignal{State: HistoryStateWriteUnavailable, UnixSec: 1})

	cases := []struct {
		name       string
		rdb        fakeRedis
		maxEntries int64
		wantState  HistoryState
		wantErr    bool
	}{
		{"missing key + shallow stream", fakeRedis{getErr: redis.Nil, xlen: 10}, 100, HistoryStateOK, false},
		{"missing key + no depth check", fakeRedis{getErr: redis.Nil}, 0, HistoryStateOK, false},
		{"fresh ok heartbeat + shallow", fakeRedis{getVal: okPayload, xlen: 10}, 100, HistoryStateOK, false},
		{"ok heartbeat but stream saturated", fakeRedis{getVal: okPayload, xlen: 100}, 100, HistoryStateBufferFull, false},
		{"buffer_full signal wins regardless of depth", fakeRedis{getVal: fullPayload, xlen: 0}, 100, HistoryStateBufferFull, false},
		{"write_unavailable signal", fakeRedis{getVal: downPayload}, 0, HistoryStateWriteUnavailable, false},
		{"depth check disabled ignores saturation", fakeRedis{getVal: okPayload, xlen: 999999}, 0, HistoryStateOK, false},
		{"GET error fails closed", fakeRedis{getErr: errors.New("conn refused")}, 0, "", true},
		{"garbage payload fails closed", fakeRedis{getVal: "{oops"}, 0, "", true},
		{"unknown state fails closed", fakeRedis{getVal: `{"state":"??","unix_sec":1}`}, 0, "", true},
		{"XLen error fails closed", fakeRedis{getVal: okPayload, xlenErr: errors.New("conn refused")}, 100, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewRedisHistoryProbe(&tc.rdb, "events:queue", tc.maxEntries)
			state, err := p.ProbeHistory(context.Background())
			if tc.wantErr {
				require.Error(t, err, "unverifiable must error so the policy fails closed")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantState, state)
		})
	}
}

func TestRedisHistoryProbe_DisarmedFailsClosed(t *testing.T) {
	var nilProbe *RedisHistoryProbe
	_, err := nilProbe.ProbeHistory(context.Background())
	require.Error(t, err)
	_, err = NewRedisHistoryProbe(nil, "events:queue", 0).ProbeHistory(context.Background())
	require.Error(t, err)
}

// --- small test helpers --------------------------------------------------

// logBuffer captures slog output for exactly-once transition assertions.
type logBuffer struct {
	lines []string
}

func (b *logBuffer) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&lineWriter{b}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (b *logBuffer) take() []string {
	out := b.lines
	b.lines = nil
	return out
}

type lineWriter struct{ b *logBuffer }

func (w *lineWriter) Write(p []byte) (int, error) {
	w.b.lines = append(w.b.lines, strings.TrimSpace(string(p)))
	return len(p), nil
}
