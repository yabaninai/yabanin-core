package budget

// History-profile admission tests (N12-P02-T03; owner decisions I40/I44/I45).
//
// Pins, in order of owner risk:
//
//   - the DEFAULT profile refuses new requests when the durable history
//     buffer cannot accept history — saturated or unverifiable — with the
//     503-class ErrHistoryCapacity, and never enters the loss mode by
//     itself (I40);
//   - the explicit allow_loss profile keeps serving but
//     carries the visible loss marker, and NEVER relaxes the money leg:
//     a loss marker with a store outage is still a wallet refusal (I44,
//     RPO=0 for money/rights/audit);
//   - the gate is deployment-level: org mode shadow/off cannot bypass it,
//     and it runs BEFORE the money leg, so a history refusal outranks a
//     simultaneous outage (and vice versa: a money refusal with a healthy
//     buffer reports history persisted);
//   - recorded attempts never replay blindly: refusals replay refusals,
//     admissions refuse duplicates (ErrAttemptReplayed, no double escrow),
//     and the ledger is bounded (FIFO + TTL) (I45).
//
// Unit-level on purpose: the buffer capacity is a func seam (the consumer
// side lives in services/loggerd/consumer, which imports this package),
// the healthy store is the recovery corpus' in-memory escrowDB, and the
// outage store is the T02 outageDB. Live-Postgres flows stay under the
// integration tag — cited, not faked.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// errBufferFull is the saturated-buffer refusal (the consumer-side gate
// returns a wrapped ErrHistoryBufferFull; any non-nil error means "no
// durable capacity" to this seam).
var errBufferFull = errors.New("history buffer full: events:queue at cap")

// errProbeUnverifiable is the fail-closed probe shape: capacity exists in
// principle but cannot be verified right now.
var errProbeUnverifiable = errors.New("history buffer probe: redis i/o timeout")

// historyCheckStub counts evaluations and answers a canned verdict.
type historyCheckStub struct {
	mu    sync.Mutex
	calls int
	err   error
}

func newHistoryCheck(err error) *historyCheckStub { return &historyCheckStub{err: err} }

func (h *historyCheckStub) evaluate(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	return h.err
}

func (h *historyCheckStub) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// capturedLog is a minimal slog.Handler recording every record. WithAttrs
// and WithGroup return the receiver so NewAdmission's log.With(...) wrapper
// keeps landing in the same buffer.
type capturedLog struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *capturedLog) Enabled(context.Context, slog.Level) bool { return true }

func (c *capturedLog) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r)
	return nil
}

func (c *capturedLog) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capturedLog) WithGroup(string) slog.Handler      { return c }

func (c *capturedLog) snapshot() []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]slog.Record(nil), c.records...)
}

// newHistoryStoreAdmission wires a history-test controller over the
// recovery corpus' escrowDB (healthy store).
func newHistoryStoreAdmission(t *testing.T, mode Mode) (*Admission, *escrowDB) {
	t.Helper()
	db := newEscrowDB(3000, 500) // $30 balance, $5 floor → $25.00 free
	adm := newRecoveryAdmission(t, mode, newRecoveryStore(t, db), recoveryRates())
	return adm, db
}

// newCapturedAdmission wires a controller whose logs land in capture.
func newCapturedAdmission(t *testing.T, capture *capturedLog) *Admission {
	t.Helper()
	store := newRecoveryStore(t, newEscrowDB(3000, 500))
	adm := NewAdmission(store, recoveryRates(), slog.New(capture),
		"history-replica", ModeEnforce, (&corpusLoader{stored: ModeEnforce}).load, AdmissionConfig{})
	t.Cleanup(adm.Stop)
	return adm
}

func historyRequest(org string) Request {
	return recoveryImageRequest(org, 4) // a $1.00 wallet bound
}

func historyMetricDelta(t *testing.T, before float64, wantBumped bool) {
	t.Helper()
	after := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(HistoryDenialScope))
	if wantBumped {
		require.InDelta(t, before+1, after, 1e-9,
			"a history-capacity refusal must be counted under the history scope, not a budget-area scope")
		return
	}
	require.InDelta(t, before, after, 1e-9,
		"this decision must not count as an applied refusal")
}

// TestResolveHistoryModeStrictFailsafe: the resolver is strict and
// fail-safe — only the exact opt-in string widens to allow_loss (the
// vocabulary shared with the N10-P04-T03 layer in admission_history.go);
// empty, unknown, or differently-cased values stay on reject so a mistyped
// configuration can never widen the loss permission.
func TestResolveHistoryModeStrictFailsafe(t *testing.T) {
	cases := []struct {
		in   string
		want HistoryMode
	}{
		{"", HistoryModeReject},
		{"reject", HistoryModeReject},
		{"allow_loss", HistoryModeAllowLoss},
		{"ALLOW_LOSS", HistoryModeReject},
		{"Allow_Loss", HistoryModeReject},
		{"allow-loss", HistoryModeReject},
		{"accept-with-history-loss", HistoryModeReject},
		{"loss", HistoryModeReject},
		{" reject", HistoryModeReject},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, ResolveHistoryMode(tc.in), "profile %q", tc.in)
	}

	// The zero-value controller resolves to reject (fail-safe default).
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	require.Equal(t, HistoryModeReject, adm.historyProfile(),
		"a controller without an explicit profile must default to reject")

	adm.SetHistoryMode("")
	require.Equal(t, HistoryModeReject, adm.historyProfile(), "an empty profile resolves to reject")
	adm.SetHistoryMode(HistoryMode("garbage"))
	require.Equal(t, HistoryModeReject, adm.historyProfile(), "an unknown profile resolves to reject")
	adm.SetHistoryMode(HistoryModeAllowLoss)
	require.Equal(t, HistoryModeAllowLoss, adm.historyProfile())
}

// TestAdmitWithHistoryProfileMatrix walks mode × buffer state × store
// health and pins, per case, the typed decision, the error class, the
// escrow effect and the applied-denial counter.
func TestAdmitWithHistoryProfileMatrix(t *testing.T) {
	type want struct {
		state       HistoryPersistState
		loss        bool  // the visible history-loss marker
		outcome     error // nil = admitted; otherwise the sentinel the error must wrap ("denied" = wallet *Denial)
		notReserved bool
		grants      int  // durable grant delta (healthy escrowDB only)
		historyDeny bool // reservations_denied_total{history} bumped
	}
	denied := errors.New("wallet denial")
	cases := []struct {
		name   string
		mode   Mode              // org/global reservations mode
		prof   HistoryMode       // I40 profile
		check  *historyCheckStub // nil = ungated
		outage bool              // money store unreachable
		bound  float64           // image qty; 4 = $1.00 (admits), 400 = $100.00 (exhausts the wallet)
		w      want
	}{
		{
			name: "ungated default keeps legacy behavior",
			mode: ModeEnforce, prof: HistoryModeReject, check: nil,
			w: want{state: HistoryNotGated, outcome: nil, grants: 1},
		},
		{
			name: "reject profile admits through a healthy buffer",
			mode: ModeEnforce, prof: HistoryModeReject, check: newHistoryCheck(nil),
			w: want{state: HistoryPersisted, outcome: nil, grants: 1},
		},
		{
			name: "reject profile refuses on a full buffer",
			mode: ModeEnforce, prof: HistoryModeReject, check: newHistoryCheck(errBufferFull),
			w: want{state: HistoryRejectedFull, outcome: ErrHistoryCapacity, historyDeny: true},
		},
		{
			name: "reject profile refuses closed on an unverifiable buffer",
			mode: ModeEnforce, prof: HistoryModeReject, check: newHistoryCheck(errProbeUnverifiable),
			w: want{state: HistoryRejectedFull, outcome: ErrHistoryCapacity, historyDeny: true},
		},
		{
			name: "loss profile admits a full buffer with the loss marker",
			mode: ModeEnforce, prof: HistoryModeAllowLoss, check: newHistoryCheck(errBufferFull),
			w: want{state: HistoryLossAccepted, loss: true, outcome: nil, grants: 1},
		},
		{
			name: "loss profile admits an unverifiable buffer with the loss marker",
			mode: ModeEnforce, prof: HistoryModeAllowLoss, check: newHistoryCheck(errProbeUnverifiable),
			w: want{state: HistoryLossAccepted, loss: true, outcome: nil, grants: 1},
		},
		{
			name: "healthy buffer never masks a store outage",
			mode: ModeEnforce, prof: HistoryModeReject, check: newHistoryCheck(nil), outage: true,
			w: want{state: HistoryPersisted, outcome: denied},
		},
		{
			name: "loss marker never relaxes the money leg",
			mode: ModeEnforce, prof: HistoryModeAllowLoss, check: newHistoryCheck(errBufferFull), outage: true,
			w: want{state: HistoryLossAccepted, loss: true, outcome: denied},
		},
		{
			name: "history gate outranks a simultaneous outage",
			mode: ModeEnforce, prof: HistoryModeReject, check: newHistoryCheck(errBufferFull), outage: true,
			w: want{state: HistoryRejectedFull, outcome: ErrHistoryCapacity, historyDeny: true},
		},
		{
			name: "shadow org cannot bypass the deployment gate",
			mode: ModeShadow, prof: HistoryModeReject, check: newHistoryCheck(errBufferFull),
			w: want{state: HistoryRejectedFull, outcome: ErrHistoryCapacity, historyDeny: true},
		},
		{
			name: "off org cannot bypass the deployment gate",
			mode: ModeOff, prof: HistoryModeReject, check: newHistoryCheck(errBufferFull),
			w: want{state: HistoryRejectedFull, outcome: ErrHistoryCapacity, historyDeny: true},
		},
		{
			name: "shadow org proceeds unreserved under loss mode",
			mode: ModeShadow, prof: HistoryModeAllowLoss, check: newHistoryCheck(errBufferFull), outage: true,
			w: want{state: HistoryLossAccepted, loss: true, outcome: ErrNotReserved, notReserved: true},
		},
		{
			name: "money exhaustion stays a budget answer, not a history refusal",
			mode: ModeEnforce, prof: HistoryModeReject, check: newHistoryCheck(nil),
			bound: 400, // $100.00 bound > $25.00 free
			w:     want{state: HistoryPersisted, outcome: ErrInsufficientCapacity},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var adm *Admission
			var db *escrowDB
			if tc.outage {
				adm = newOutageAdmission(tc.mode)
			} else {
				adm, db = newHistoryStoreAdmission(t, tc.mode)
			}
			adm.SetHistoryMode(tc.prof)
			if tc.check != nil {
				adm.SetHistoryCapacity(tc.check.evaluate)
			}

			qty := tc.bound
			if qty == 0 {
				qty = 4
			}
			req := recoveryImageRequest("org-hist", qty)
			if tc.outage {
				// The outage store rides corpusRates (no unit catalog), so
				// outage cases use the token-shaped T02 request.
				req = outageRequest()
			}

			before := testutil.ToFloat64(metrics.ReservationsDeniedTotal.WithLabelValues(HistoryDenialScope))
			grantsBefore := 0
			if db != nil {
				grantsBefore = db.grantCount()
			}

			rsv, dec, err := adm.AdmitWithHistory(context.Background(), req, "attempt-"+tc.name)

			// The typed decision, in every case.
			require.Equal(t, tc.prof, dec.Mode, "the decision always carries the resolved profile")
			require.Equal(t, tc.w.state, dec.State, "typed durability state")
			require.Equal(t, tc.w.loss, dec.Loss, "the visible loss marker")
			if tc.w.loss {
				require.Error(t, dec.Reason, "a loss marker must carry the buffer's refusal as its reason")
			}
			if tc.w.state == HistoryRejectedFull {
				require.False(t, dec.Admitted(), "the reject state refuses the history leg")
				require.Error(t, dec.Reason, "the refusal carries the buffer's verdict")
			} else {
				require.True(t, dec.Admitted(), "every other state admits the history leg")
			}

			// The overall outcome and its error class.
			switch {
			case tc.w.outcome == nil:
				require.NoError(t, err)
				require.NotNil(t, rsv, "an admitted enforce/shadow-funded request gets a reservation")
			case errors.Is(tc.w.outcome, ErrHistoryCapacity):
				require.ErrorIs(t, err, ErrHistoryCapacity)
				require.Nil(t, rsv)
				require.NotErrorIs(t, err, ErrInsufficientCapacity,
					"a history-capacity refusal is not budget exhaustion")
				require.NotErrorIs(t, err, ErrNoCapacitySource)
				require.NotErrorIs(t, err, ErrNotReserved)
				var denial *Denial
				require.NotErrorAs(t, err, &denial,
					"a history-capacity refusal is not a budget-area denial")
			case errors.Is(tc.w.outcome, ErrNotReserved):
				require.ErrorIs(t, err, ErrNotReserved)
				require.Nil(t, rsv)
				require.NotErrorIs(t, err, ErrHistoryCapacity)
			case errors.Is(tc.w.outcome, ErrInsufficientCapacity):
				require.ErrorIs(t, err, ErrInsufficientCapacity)
				require.Nil(t, rsv)
				require.NotErrorIs(t, err, ErrHistoryCapacity,
					"money exhaustion must not masquerade as a history refusal")
			default: // wallet *Denial (store outage)
				require.Error(t, err)
				require.Nil(t, rsv)
				var denial *Denial
				require.ErrorAs(t, err, &denial)
				require.Equal(t, ScopeWallet, denial.Scope)
				require.ErrorContains(t, err, "reservation store unavailable")
				require.NotErrorIs(t, err, ErrHistoryCapacity,
					"an outage must not masquerade as a history refusal")
				require.NotErrorIs(t, err, ErrInsufficientCapacity,
					"an outage must not masquerade as budget exhaustion")
			}

			// Escrow and counter effects.
			if db != nil {
				require.Equal(t, tc.w.grants, db.grantCount()-grantsBefore, "durable grant delta")
				require.Zero(t, adm.LocalEscrow(),
					"the granted escrow is fully in flight; a refused attempt moves nothing")
			}
			historyMetricDelta(t, before, tc.w.historyDeny)
		})
	}
}

// TestAdmitWithHistoryReplayIdempotency: the I45 attempt ledger returns the
// recorded outcome for a repeated key instead of re-evaluating or
// re-reserving — refusals replay refusals, admissions refuse duplicates,
// loss markers survive the replay, and the TTL hands the key back to a
// fresh evaluation.
func TestAdmitWithHistoryReplayIdempotency(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	cases := []struct {
		name    string
		prof    HistoryMode
		first   *historyCheckStub // buffer verdict for the first attempt
		resat   *historyCheckStub // verdict the replay would see IF re-evaluated
		firstOK bool              // first attempt admits (nil error)
	}{
		{
			name:    "admission refuses its duplicate instead of re-reserving",
			prof:    HistoryModeReject,
			first:   newHistoryCheck(nil),
			resat:   newHistoryCheck(nil),
			firstOK: true,
		},
		{
			name:    "loss admission replay keeps the loss marker",
			prof:    HistoryModeAllowLoss,
			first:   newHistoryCheck(errBufferFull),
			resat:   newHistoryCheck(errBufferFull),
			firstOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adm, db := newHistoryStoreAdmission(t, ModeEnforce)
			adm.SetHistoryMode(tc.prof)
			adm.SetClock(func() time.Time { return now })

			adm.SetHistoryCapacity(tc.first.evaluate)
			key := "attempt-1"
			rsv1, dec1, err1 := adm.AdmitWithHistory(ctx, historyRequest("org-replay"), key)
			require.NoError(t, err1)
			require.NotNil(t, rsv1)
			require.Equal(t, 1, tc.first.callCount(),
				"the first attempt evaluates the buffer exactly once")
			grantsBefore, escrowBefore := db.grantCount(), adm.LocalEscrow()

			// The replay must NOT re-evaluate the buffer, must not grant
			// again, and must refuse the duplicate with the recorded
			// decision riding along.
			adm.SetHistoryCapacity(tc.resat.evaluate)
			rsv2, dec2, err2 := adm.AdmitWithHistory(ctx, historyRequest("org-replay"), key)
			require.Zero(t, tc.resat.callCount(),
				"the replay must return the record, not re-evaluate")
			require.Equal(t, grantsBefore, db.grantCount(), "the replay reserves nothing new")
			require.Equal(t, escrowBefore, adm.LocalEscrow(), "the replay moves no escrow")
			require.ErrorIs(t, err2, ErrAttemptReplayed,
				"an admitted attempt refuses its duplicate (I45)")
			require.Nil(t, rsv2, "the duplicate gets no reservation")
			require.Equal(t, dec1, dec2, "the replay returns the recorded decision")
			require.Equal(t, tc.prof == HistoryModeAllowLoss, dec2.Loss,
				"the recorded loss marker survives the replay")
		})
	}
}

// TestAdmitWithHistoryReplayRefusals: refused attempts replay exactly the
// recorded refusal — the history refusal, the outage denial — without
// re-evaluating the buffer (split from the table above for clarity of the
// error-class pins).
func TestAdmitWithHistoryReplayRefusals(t *testing.T) {
	now := time.Now()
	ctx := context.Background()

	t.Run("history refusal replays without re-evaluation", func(t *testing.T) {
		adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
		adm.SetHistoryMode(HistoryModeReject)
		adm.SetClock(func() time.Time { return now })
		adm.SetHistoryCapacity(newHistoryCheck(errBufferFull).evaluate)

		_, _, err1 := adm.AdmitWithHistory(ctx, historyRequest("org-replay"), "k")
		require.ErrorIs(t, err1, ErrHistoryCapacity)

		adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate) // healthy on replay
		_, dec2, err2 := adm.AdmitWithHistory(ctx, historyRequest("org-replay"), "k")
		require.ErrorIs(t, err2, ErrHistoryCapacity,
			"a refusal replays as the same refusal even though the buffer recovered")
		require.Equal(t, HistoryRejectedFull, dec2.State, "the recorded decision rides the replay")
	})

	t.Run("outage denial replays as the same wallet refusal", func(t *testing.T) {
		adm := newOutageAdmission(ModeEnforce)
		adm.SetHistoryMode(HistoryModeReject)
		adm.SetClock(func() time.Time { return now })
		stub := newHistoryCheck(nil)
		adm.SetHistoryCapacity(stub.evaluate)

		// The outage store rides corpusRates (no unit catalog): the
		// token-shaped T02 request.
		_, _, err1 := adm.AdmitWithHistory(ctx, outageRequest(), "k")
		require.Error(t, err1)
		var denial1 *Denial
		require.ErrorAs(t, err1, &denial1)
		require.Equal(t, ScopeWallet, denial1.Scope)

		_, _, err2 := adm.AdmitWithHistory(ctx, outageRequest(), "k")
		require.Error(t, err2)
		var denial2 *Denial
		require.ErrorAs(t, err2, &denial2)
		require.Equal(t, denial1.Scope, denial2.Scope, "the recorded denial replays")
		require.Zero(t, stub.callCount()-1, "the replay must not re-evaluate the buffer")
	})
}

// TestAdmitWithHistoryDistinctAndExpiredKeys: distinct keys evaluate
// independently; past the TTL a key is a fresh attempt with whatever the
// buffer now reports.
func TestAdmitWithHistoryDistinctAndExpiredKeys(t *testing.T) {
	now := time.Now()
	ctx := context.Background()

	t.Run("distinct keys evaluate independently", func(t *testing.T) {
		adm, db := newHistoryStoreAdmission(t, ModeEnforce)
		adm.SetHistoryMode(HistoryModeReject)
		adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate)
		_, _, err := adm.AdmitWithHistory(ctx, historyRequest("org-replay"), "a")
		require.NoError(t, err)
		_, _, err = adm.AdmitWithHistory(ctx, historyRequest("org-replay"), "b")
		require.NoError(t, err)
		require.Equal(t, 2, db.grantCount(), "two logical attempts, two durable grants")
	})

	t.Run("ttl expiry re-opens the key", func(t *testing.T) {
		adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
		adm.SetHistoryMode(HistoryModeReject)
		adm.SetHistoryCapacity(newHistoryCheck(errBufferFull).evaluate)
		adm.SetClock(func() time.Time { return now })

		_, _, err := adm.AdmitWithHistory(ctx, historyRequest("org-ttl"), "k")
		require.ErrorIs(t, err, ErrHistoryCapacity)

		now = now.Add(DefaultHistoryAttemptTTL + time.Second)
		adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate)
		rsv, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-ttl"), "k")
		require.NoError(t, err, "an expired refusal key is a new attempt")
		require.NotNil(t, rsv)
		require.Equal(t, HistoryPersisted, dec.State)
	})
}

// TestHistoryAttemptLedgerBounded: the ledger caps memory (FIFO eviction
// beyond DefaultHistoryAttemptLedgerMax) and a first outcome is final
// within the window.
func TestHistoryAttemptLedgerBounded(t *testing.T) {
	now := time.Now()
	adm, _ := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeReject)
	adm.SetHistoryCapacity(newHistoryCheck(errBufferFull).evaluate)
	adm.SetClock(func() time.Time { return now })
	ctx := context.Background()

	total := DefaultHistoryAttemptLedgerMax + 8
	for i := 0; i < total; i++ {
		_, _, err := adm.AdmitWithHistory(ctx, historyRequest("org-cap"), fmt.Sprintf("k-%04d", i))
		require.ErrorIs(t, err, ErrHistoryCapacity)
	}
	adm.mu.Lock()
	size := len(adm.attempts)
	_, oldestAlive := adm.attempts["k-0000"]
	newestAlive := false
	adm.mu.Unlock()
	require.Equal(t, DefaultHistoryAttemptLedgerMax, size,
		"the ledger never grows past its cap")
	require.False(t, oldestAlive, "the oldest entries are evicted FIFO")

	// An evicted key is a fresh attempt again (it re-evaluates: prove it by
	// flipping the checker — the fresh verdict wins).
	adm.SetHistoryCapacity(newHistoryCheck(nil).evaluate)
	_, _, err := adm.AdmitWithHistory(ctx, historyRequest("org-cap"), "k-0000")
	require.NoError(t, err, "an evicted key is evaluated fresh")

	// First outcome wins inside the window: a recorded admission replays as
	// ErrAttemptReplayed no matter how often the caller retries.
	_, _, err = adm.AdmitWithHistory(ctx, historyRequest("org-cap"), "live-key")
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, dec, err := adm.AdmitWithHistory(ctx, historyRequest("org-cap"), "live-key")
		require.ErrorIs(t, err, ErrAttemptReplayed)
		require.Equal(t, HistoryPersisted, dec.State, "the recorded decision rides every replay")
	}
	adm.mu.Lock()
	_, newestAlive = adm.attempts["live-key"]
	adm.mu.Unlock()
	require.True(t, newestAlive, "the newest entries survive eviction")
}

// TestHistoryLossTransitionLogsExactlyOnce: the loss visibility rides the
// typed decision plus exactly-once state-transition logs — Warn when
// admitting with loss starts, Info when it clears — and the default reject
// profile never emits a loss transition at all.
func TestHistoryLossTransitionLogsExactlyOnce(t *testing.T) {
	ctx := context.Background()
	full := func(context.Context) error { return errBufferFull }
	healthy := func(context.Context) error { return nil }

	t.Run("loss mode warns once and recovers once", func(t *testing.T) {
		capture := &capturedLog{}
		adm := newCapturedAdmission(t, capture)
		adm.SetHistoryMode(HistoryModeAllowLoss)

		adm.SetHistoryCapacity(full)
		adm.CheckHistory(ctx) // loss starts
		adm.CheckHistory(ctx) // stays losing
		adm.SetHistoryCapacity(healthy)
		adm.CheckHistory(ctx) // recovers
		adm.CheckHistory(ctx) // stays healthy

		var warns, infos int
		for _, r := range capture.snapshot() {
			switch r.Level {
			case slog.LevelWarn:
				warns++
				require.Contains(t, strings.ToLower(r.Message), "history loss")
				marked := false
				r.Attrs(func(a slog.Attr) bool {
					if a.Key == "history_loss" && a.Value.Bool() {
						marked = true
					}
					return true
				})
				require.True(t, marked, "the loss warn carries the history_loss=true marker")
			case slog.LevelInfo:
				infos++
				require.Contains(t, strings.ToLower(r.Message), "recovered")
			}
		}
		require.Equal(t, 1, warns, "the loss start warns exactly once")
		require.Equal(t, 1, infos, "the recovery logs exactly once")
	})

	t.Run("reject profile never logs loss transitions", func(t *testing.T) {
		capture := &capturedLog{}
		adm := newCapturedAdmission(t, capture)
		adm.SetHistoryMode(HistoryModeReject)
		adm.SetHistoryCapacity(newHistoryCheck(errBufferFull).evaluate)

		dec1 := adm.CheckHistory(ctx)
		require.Equal(t, HistoryRejectedFull, dec1.State)
		dec2 := adm.CheckHistory(ctx)
		require.Equal(t, HistoryRejectedFull, dec2.State)
		require.Empty(t, capture.snapshot(),
			"the reject profile refuses per-decision, without loss-transition logs")
	})
}

// TestAdmitWithHistoryConcurrentSmoke exercises the ledger and the gate
// under concurrency with the race detector (distinct keys plus a contended
// hot key). The hot key's claim is atomic: exactly one worker's first
// attempt admits; every loser — in-flight or already recorded — must see
// the duplicate refusal. Volume stays inside the seeded wallet ($17 of
// $1.00 bounds against $25.00 free). No metric assertions here —
// sequential counter tests above own those pins.
func TestAdmitWithHistoryConcurrentSmoke(t *testing.T) {
	adm, db := newHistoryStoreAdmission(t, ModeEnforce)
	adm.SetHistoryMode(HistoryModeAllowLoss)
	adm.SetHistoryCapacity(newHistoryCheck(errBufferFull).evaluate)
	ctx := context.Background()

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers+workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			if _, _, err := adm.AdmitWithHistory(ctx, historyRequest("org-race"),
				fmt.Sprintf("k-%d", w)); err != nil {
				errs <- err
			}
			// The contended hot key.
			if _, _, err := adm.AdmitWithHistory(ctx, historyRequest("org-race"), "hot"); err != nil {
				errs <- err
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	var replay, other int
	for err := range errs {
		if errors.Is(err, ErrAttemptReplayed) {
			replay++
		} else {
			other++
		}
	}
	require.GreaterOrEqual(t, replay, workers-1,
		"every loser of the hot-key race must see the recorded duplicate refusal")
	require.Zero(t, other, "no other error class may appear in the smoke")
	require.LessOrEqual(t, db.grantCount(), workers+1,
		"grants never exceed admitted attempts (the hot key admits at most once)")
	adm.mu.Lock()
	size := len(adm.attempts)
	adm.mu.Unlock()
	require.LessOrEqual(t, size, DefaultHistoryAttemptLedgerMax, "the ledger stays bounded")
}
