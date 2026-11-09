// N12-P02-T03 — I40/I44/I45 history-profile wiring at the admission layer.
//
// Owner decisions in force:
//
//   - I40: request-history persistence first goes to the bounded durable
//     buffer (the Redis stream events:queue, guarded by the consumer-side
//     HistoryBufferGate, N10-P04-T02). When history cannot be accepted even
//     into the buffer — saturated, or the capacity cannot be verified — new
//     requests are REJECTED by default. The continue-serving option is an
//     explicit, separately configured mode; it is never entered
//     automatically when the buffer fills.
//   - I44: acknowledged accounting, authorization and audit records have
//     RPO=0. The loss mode below relaxes ONLY the request-history record;
//     it never skips or downgrades the money leg.
//   - I45: an attempt whose outcome is recorded is never blindly replayed —
//     the attempt ledger returns the recorded outcome (refusals replay as
//     refusals, admissions refuse their duplicates) instead of
//     re-evaluating or re-reserving.
//   - I36: mandatory authorization checks stay fail-closed in every profile
//     — the money leg (Plan/Reserve) runs unchanged in both modes.
//
// Mode vocabulary (REVISE R1 reconciliation): there is ONE history-mode
// concept in this package — HistoryMode, HistoryModeReject,
// HistoryModeAllowLoss and ResolveHistoryMode, declared in
// admission_history.go (N10-P04-T03). This card's earlier
// "accept-with-history-loss" profile is folded into that type as the
// HistoryModeAllowLoss opt-in ("allow_loss"); the string vocabulary never
// forks. The enforcement layers are composed, not stacked: CheckHistory
// delegates to the armed HistoryAdmission when one is wired (see
// SetHistoryAdmission) and uses the HistoryCapacityCheck seam only when no
// policy object is armed, so a request's history leg is evaluated exactly
// once no matter which wiring a deployment chose.
//
// Layering: the consumer-side backpressure gate lives in
// services/loggerd/consumer and that package imports pkg/budget, so the
// seam here is the HistoryCapacityCheck func type — the deployment adapter
// is one line at the wiring site
// (`adm.SetHistoryCapacity(gate.Evaluate)`; Evaluate's nil / wrapped
// ErrHistoryBufferFull results satisfy the contract exactly, including its
// fail-closed probe semantics). A nil check (the default) leaves admission
// ungated: an unmeasurable buffer must not fabricate a saturation signal,
// so deployments without the signal keep their exact legacy behavior.
package budget

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// The HistoryMode type, its values (HistoryModeReject / HistoryModeAllowLoss)
// and the fail-safe ResolveHistoryMode resolver are declared in
// admission_history.go (N10-P04-T03) — this card reuses them verbatim so
// callers see one history-mode concept. HistoryModeAllowLoss is the explicit
// keep-serving opt-in this card calls the loss profile: keep serving when
// the durable buffer cannot accept history, with a visible loss marker on
// every admission decision (HistoryDecision.Loss / the history_loss_accepted
// state). It relaxes ONLY request history: the authorization/spend leg still
// runs and still refuses (I44 RPO=0 for money, rights and audit).

// ErrHistoryCapacity is the root sentinel of an I40 admission refusal: the
// durable history buffer cannot accept more history (saturated, or its
// capacity could not be verified — both fail-closed). Callers match it with
// errors.Is; through the legacy Denial mapping it lands in the default
// branch (503), the same class as a reservation-store outage. It is never
// ErrInsufficientCapacity/ErrNoCapacitySource — a history-capacity refusal
// is not a budget-area or wallet answer.
var ErrHistoryCapacity = errors.New("history: durable buffer cannot accept history")

// ErrAttemptReplayed marks the duplicate of an attempt the ledger has
// already seen admitted — or that is currently in flight under the same
// key: the retry is refused instead of re-reserving a second escrow or
// serving the request unreserved (I45 — retries never duplicate a recorded
// outcome; the caller reconciles or issues a NEW attempt key). The claim
// is atomic, so concurrent duplicates are refused too, not just sequential
// replays.
var ErrAttemptReplayed = errors.New("history: admission attempt already recorded")

// HistoryDenialScope is the reservations_denied_total scope_kind label
// value under which I40 refusals are counted: a request-level capacity
// class, not a budget area.
const HistoryDenialScope = "history"

// HistoryCapacityCheck reports whether the durable history buffer can
// accept another history record: nil means yes; ANY non-nil error means
// history cannot be persisted durably right now — saturation and an
// unreachable/failed capacity probe alike (fail-closed, I40: an
// unverifiable capacity is treated as no capacity). See the package comment
// for the layering and the one-line deployment adapter.
type HistoryCapacityCheck func(ctx context.Context) error

// HistoryPersistState is the TYPED durability state of one admission
// attempt's history leg (N12-P02 negative clause: disk-full and DB outages
// must not be able to surface as a clean persisted status — the state is
// enumerated, never inferred from the absence of an error).
type HistoryPersistState string

const (
	// HistoryNotGated is the no-capacity-signal state: admission is
	// unchanged (legacy deployments).
	HistoryNotGated HistoryPersistState = "not_gated"
	// HistoryPersisted means the buffer accepted (or could accept) the
	// attempt's history durably. Never reported while the capacity is
	// unverified.
	HistoryPersisted HistoryPersistState = "persisted"
	// HistoryRejectedFull means the buffer could not accept history and the
	// default reject profile refused the attempt. No authorized /
	// persisted status may be derived from this decision.
	HistoryRejectedFull HistoryPersistState = "rejected_buffer_full"
	// HistoryLossAccepted means the explicit allow_loss (loss-accepting)
	// profile admitted the attempt despite the buffer's refusal — the
	// request's history record is LOST and the loss marker
	// (HistoryDecision.Loss) is set. Never produced by the default profile.
	HistoryLossAccepted HistoryPersistState = "history_loss_accepted"
)

// HistoryDecision is the history leg of one admission attempt. When the
// attempt as a whole was refused (non-nil error from AdmitWithHistory) no
// history record exists for it — a refused request can never be reported
// as accepted, with or without loss.
type HistoryDecision struct {
	// Mode is the resolved profile the decision was taken under (never
	// empty).
	Mode HistoryMode
	// State is the typed durability outcome of the capacity leg.
	State HistoryPersistState
	// Loss is the visible history-loss marker: true iff the attempt was
	// admitted while its history could not be persisted (the explicit
	// allow_loss profile only).
	Loss bool
	// Reason carries the buffer's refusal (saturation or probe failure)
	// when State is rejected_buffer_full or history_loss_accepted.
	Reason error
}

// Admitted reports whether the history leg allowed the attempt.
func (d HistoryDecision) Admitted() bool {
	return d.State != HistoryRejectedFull
}

// Replay bounds of the attempt ledger. The TTL doubles as the dedup
// contract window: within it a repeated attempt key gets the recorded
// outcome, past it the caller is issuing a genuinely new attempt.
const (
	// DefaultHistoryAttemptLedgerMax bounds the ledger (FIFO eviction
	// beyond it, so memory is capped regardless of traffic).
	DefaultHistoryAttemptLedgerMax = 4096
	// DefaultHistoryAttemptTTL is the replay window.
	DefaultHistoryAttemptTTL = time.Minute
)

// historyAttempt is one attempt-key claim. The claim exists from the
// moment an attempt with that key starts until its outcome lands (done):
// concurrent duplicates hit the uncompleted claim and are refused exactly
// like replays of a completed admission.
type historyAttempt struct {
	dec      HistoryDecision
	err      error
	admitted bool
	done     bool
	at       time.Time
}

// SetHistoryMode pins the deployment's I40 profile. An empty or unknown
// value resolves to reject (the fail-safe default). Wire before serving.
// When an N10-P04-T03 HistoryAdmission is armed, it owns the ACTIVE mode
// (the single vocabulary owner): the resolution is applied to it as well,
// so this setter never forks the mode between the layers.
func (a *Admission) SetHistoryMode(m HistoryMode) {
	if a == nil {
		return
	}
	resolved := ResolveHistoryMode(string(m))
	if h := a.history; h != nil {
		// Wiring-time only, like SetHistoryAdmission: the gate reads its
		// mode without a lock on the hot path.
		h.setMode(resolved)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.historyMode = resolved
}

// SetHistoryCapacity wires the durable history buffer's capacity signal.
// nil (the default) disarms the gate: admission is ungated. When an
// N10-P04-T03 HistoryAdmission is already armed, it takes precedence as
// the gate's signal source (the deployment-level probe is the richer
// observation) and this seam stays inert — the layers never stack into a
// double evaluation (see CheckHistory).
func (a *Admission) SetHistoryCapacity(check HistoryCapacityCheck) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.historyCheck = check
}

// historyProfile reads the wired profile; the mode is resolved on read so
// a zero-value controller is still reject. The armed HistoryAdmission (if
// any) owns the active mode — one vocabulary, one owner.
func (a *Admission) historyProfile() HistoryMode {
	if h := a.history; h != nil {
		// Same wiring-time contract as Plan's field read: the gate is
		// armed before serving and not swapped afterwards.
		return h.Mode()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return ResolveHistoryMode(string(a.historyMode))
}

// CheckHistory evaluates the I40 profile without touching the money leg —
// the seam for wirings that enforce at their own point in the request
// pipeline. Not-gated deployments get HistoryNotGated with no other effect.
//
// Single enforcement point (REVISE R1): when an N10-P04-T03
// HistoryAdmission is armed, it IS the gate — its verdict is translated
// into the typed decision here, and its state transitions are already
// logged inside HistoryAdmission.Admit (no lane-side loss logging, no
// second signal source). The HistoryCapacityCheck seam runs only when no
// policy object is armed. AdmitWithHistory therefore never evaluates the
// history leg more than once, whichever wiring a deployment chose.
// The loss marker's state transition is logged exactly once on the seam
// path (Warn when admitting with loss starts, Info when it clears),
// mirroring the consumer-side gate's bounded transition logging.
//
// N12-P02-T04: every evaluated decision is also folded into the
// failure-recovery bookkeeping (loss volume, loss window open/recovered
// stamps) via observeDecision — the reconciliation surface must see every
// decision, no matter which wiring produced it.
func (a *Admission) CheckHistory(ctx context.Context) HistoryDecision {
	dec := a.checkHistory(ctx)
	a.observeDecision(dec)
	return dec
}

// checkHistory is the pre-T04 CheckHistory body: the policy evaluation
// only — no recovery bookkeeping (that lives in observeDecision so both
// wirings are counted at exactly one place).
func (a *Admission) checkHistory(ctx context.Context) HistoryDecision {
	mode := a.historyProfile()

	if h := a.history; h != nil {
		err := h.Admit(ctx)
		if err == nil {
			if h.LossActive() {
				// Serving through a durable-history outage under the
				// explicit allow_loss opt-in: surface the loss exactly
				// like the seam path does.
				return HistoryDecision{Mode: mode, State: HistoryLossAccepted,
					Loss: true, Reason: historyStateReason(h.State(), mode)}
			}
			return HistoryDecision{Mode: mode, State: HistoryPersisted}
		}
		// *HistoryOutageError (errors.Is ErrHistoryUnavailable) under the
		// default reject profile — the typed refusal keeps the outage as
		// its reason, so the ErrHistoryCapacity wrapper below carries both
		// identities for callers of either layer.
		return HistoryDecision{Mode: mode, State: HistoryRejectedFull, Reason: err}
	}

	a.mu.Lock()
	check := a.historyCheck
	a.mu.Unlock()
	if check == nil {
		return HistoryDecision{Mode: mode, State: HistoryNotGated}
	}

	err := check(ctx)
	if err == nil {
		a.logLossTransition(false, nil)
		return HistoryDecision{Mode: mode, State: HistoryPersisted}
	}
	if mode == HistoryModeAllowLoss {
		a.logLossTransition(true, err)
		return HistoryDecision{Mode: mode, State: HistoryLossAccepted, Loss: true, Reason: err}
	}
	return HistoryDecision{Mode: mode, State: HistoryRejectedFull, Reason: err}
}

// observeDecision folds one evaluated history decision into the
// failure-recovery bookkeeping (N12-P02-T04) and the Prometheus counters:
//
//   - HistoryLossAccepted — one more history record lost under the
//     explicit allow_loss profile: the cumulative loss counter (both the
//     in-process ledger and history_loss_admissions_total) advances and
//     the loss window stays/marks open. I44: the gap volume stays visible;
//     recovery never resets it.
//   - HistoryPersisted after an open loss window — the durable path
//     recovered: lastRecoveryAt stamps the recovery (once per window).
//
// Every other state is bookkeeping-neutral. No logging here: the loss and
// recovery transitions already log exactly once on their own paths
// (logLossTransition / HistoryAdmission.record).
func (a *Admission) observeDecision(dec HistoryDecision) {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	switch dec.State {
	case HistoryLossAccepted:
		a.lossAdmissions++
		a.lastLossAt = now
		a.lossWindowOpen = true
		metrics.HistoryLossAdmissionsTotal.Inc()
	case HistoryPersisted:
		if a.lossWindowOpen {
			a.lastRecoveryAt = now
			a.lossWindowOpen = false
		}
	}
}

// RecoverySnapshot is the operator-facing view of one admission
// controller's failure-recovery state (N12-P02-T04: show backlog/gaps/
// reconciliation without repeating unknown external actions):
//
//   - Mode/LossActive/LossWindowOpen — the ACTIVE I40 profile and whether
//     requests are currently served through (or since) a durable-history
//     outage;
//   - LossAdmissions/LastLossAt — the cumulative history-gap volume and
//     its most recent stamp (I44: incomplete history never appears
//     complete);
//   - LastRecoveryAt — the most recent loss→persisted recovery stamp
//     (zero until the first recovery);
//   - UncertainAttempts/LastUncertainAt — the I45 reconciliation
//     population: attempts whose claim was reaped unfinished (owner died /
//     crash), outcome UNKNOWN — never counted as persisted, authorized or
//     settled anywhere, and never automatically re-dispatched;
//   - PendingInFlight — claims currently live (their dedup contract is
//     still held by a caller).
//
// It is a consistent point-in-time read under one lock; Now is the read
// stamp (from the controller's clock seam).
type RecoverySnapshot struct {
	Mode              HistoryMode
	LossActive        bool
	LossWindowOpen    bool
	LossAdmissions    uint64
	UncertainAttempts uint64
	PendingInFlight   int
	LastLossAt        time.Time
	LastRecoveryAt    time.Time
	LastUncertainAt   time.Time
	Now               time.Time
}

// RecoverySnapshot reads the controller's recovery state. The loss-active
// flag follows the armed N10-P04-T03 gate when one is wired (it owns the
// active state), otherwise the seam path's own loss marker.
func (a *Admission) RecoverySnapshot() RecoverySnapshot {
	snap := RecoverySnapshot{Mode: a.historyProfile(), Now: a.now()}
	a.mu.Lock()
	defer a.mu.Unlock()
	if h := a.history; h != nil {
		snap.LossActive = h.LossActive()
	} else {
		snap.LossActive = a.lossLogged
	}
	snap.LossWindowOpen = a.lossWindowOpen
	snap.LossAdmissions = a.lossAdmissions
	snap.UncertainAttempts = a.attemptsUncertain
	snap.LastLossAt = a.lastLossAt
	snap.LastRecoveryAt = a.lastRecoveryAt
	snap.LastUncertainAt = a.lastUncertainAt
	for _, rec := range a.attempts {
		if !rec.done {
			snap.PendingInFlight++
		}
	}
	return snap
}

// historyStateReason fabricates the decision Reason for the delegated
// (armed-gate) path when the gate admitted with loss: HistoryAdmission
// already consumed the outage error internally, but the loss marker's
// contract keeps the buffer's refusal visible — the typed outage state is
// that refusal.
func historyStateReason(state HistoryState, mode HistoryMode) error {
	return fmt.Errorf("history admission: durable history state %s (served under %s)", state, mode)
}

// logLossTransition logs the loss-mode state change exactly once. Only the
// loss-accepting profile moves the marker; the reject profile's visibility
// is the per-refusal reservations_denied_total{scope_kind="history"} count.
func (a *Admission) logLossTransition(losing bool, cause error) {
	a.mu.Lock()
	changed := losing != a.lossLogged
	a.lossLogged = losing
	a.mu.Unlock()
	if !changed {
		return
	}
	if losing {
		a.log.Warn("history capacity unavailable — admitting requests with history loss (I40 allow_loss profile)",
			slog.Bool("history_loss", true), slog.Any("error", cause))
		return
	}
	a.log.Info("history capacity recovered — history-loss admissions cleared",
		slog.Bool("history_loss", false))
}

// AdmitWithHistory is the I40-aware admission entry for one new request:
// the durable-history capacity gate first (default profile: reject), then
// the normal §5.1/§5.3 money pipeline (planAfterHistory + Reserve — the
// post-history-consult Plan body, so the history gate is evaluated exactly
// once here and never re-consulted by the money leg) — the history profile
// never relaxes the mandatory money leg (I36/I44).
//
// attemptKey is the caller's idempotency key for the logical attempt
// ("" = no dedup contract). The key is claimed atomically when the attempt
// starts and the FIRST complete outcome is recorded into the claim: a
// replay with the same key — sequential or racing — receives exactly that
// recorded outcome (a refused attempt replays its refusal without
// re-evaluating the buffer; an admitted attempt refuses its duplicate with
// ErrAttemptReplayed instead of re-reserving escrow or serving
// unreserved, I45). An expired claim (TTL) is a genuinely new attempt.
//
// Return contract:
//   - err wrapping ErrHistoryCapacity — the default profile refused on
//     history capacity (decision State rejected_buffer_full); no
//     reservation, no escrow movement. The buffer's own verdict is wrapped
//     too: under a delegated armed gate the chain carries
//     ErrHistoryUnavailable (+ typed *HistoryOutageError), under the seam
//     the check's own sentinel — callers of either layer match with
//     errors.Is.
//   - err wrapping ErrAttemptReplayed — duplicate of a recorded or
//     in-flight admission; the recorded decision rides along (a loss
//     admission keeps its loss marker; an in-flight duplicate — outcome
//     not yet known — rides not_gated and must not be retried under the
//     same key).
//   - err wrapping ErrNotReserved — history admitted, reservations
//     inactive/off for this request: the existing proceed-unreserved
//     convention.
//   - any other error — the money leg refused (typed Denial as usual); the
//     decision still reports the history leg. A loss marker with a non-nil
//     error does NOT mean the request was accepted.
//   - nil error — admitted; rsv is non-nil for reserved (enforce/shadow
//     funded) requests and the decision carries persisted or (explicit
//     profile only) the loss-accepted marker.
func (a *Admission) AdmitWithHistory(ctx context.Context, req Request, attemptKey string) (rsv *Reservation, dec HistoryDecision, err error) {
	if a == nil {
		return nil, HistoryDecision{Mode: HistoryModeReject, State: HistoryNotGated},
			fmt.Errorf("%w: admission controller absent", ErrNotReserved)
	}
	if attemptKey != "" {
		rec, claimed := a.claimAttempt(attemptKey)
		if !claimed {
			if rec.done && !rec.admitted {
				return nil, rec.dec, rec.err
			}
			if rec.dec.Mode == "" {
				// In-flight claim: no outcome exists yet — never fabricate
				// one, just refuse the duplicate.
				rec.dec = HistoryDecision{Mode: a.historyProfile(), State: HistoryNotGated}
			}
			return nil, rec.dec, fmt.Errorf("%w: attempt already admitted or in flight; refusing the duplicate (I45)",
				ErrAttemptReplayed)
		}
		defer func() { a.completeAttempt(attemptKey, dec, err == nil || errors.Is(err, ErrNotReserved), err) }()
	}

	dec = a.CheckHistory(ctx)
	if !dec.Admitted() {
		// The refusal keeps the buffer's verdict IN the error chain (%w,
		// guarded): under a delegated N10-P04-T03 gate the chain then
		// carries ErrHistoryUnavailable/typed outage beside this card's
		// ErrHistoryCapacity, so callers of either layer match; under the
		// seam it carries the check's own sentinel (e.g. the consumer
		// gate's ErrHistoryBufferFull).
		if dec.Reason != nil {
			err = fmt.Errorf("%w: profile %q: %w", ErrHistoryCapacity, dec.Mode, dec.Reason)
		} else {
			err = fmt.Errorf("%w: profile %q", ErrHistoryCapacity, dec.Mode)
		}
		metrics.ReservationsDeniedTotal.WithLabelValues(HistoryDenialScope).Inc()
		return nil, dec, err
	}

	plan, perr := a.planAfterHistory(ctx, req)
	if perr != nil {
		return nil, dec, perr
	}
	rsv, err = a.Reserve(ctx, plan)
	if err != nil && !errors.Is(err, ErrNotReserved) {
		return nil, dec, err
	}
	return rsv, dec, err
}

// claimAttempt claims key for the caller: it returns (record, false) when
// a fresh claim already exists (done = replay its outcome; in-flight =
// refuse the duplicate) and (zero, true) when the caller owns the new
// claim — it must complete it. Expired claims (past the TTL, done or not —
// an expired in-flight claim means its owner died mid-attempt) are deleted
// and the key re-claimed.
func (a *Admission) claimAttempt(key string) (historyAttempt, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.attempts == nil {
		a.attempts = map[string]historyAttempt{}
	}
	if rec, ok := a.attempts[key]; ok {
		if now.Sub(rec.at) <= DefaultHistoryAttemptTTL {
			return rec, false
		}
		// TTL reap (N12-P02-T04, I45): an UNFINISHED claim whose window
		// lapsed means its owner died (or the process crashed) before any
		// outcome landed — the attempt's external effect is UNKNOWN. It is
		// never reported persisted/authorized/settled anywhere and never
		// re-dispatched; the reconciliation surface (RecoverySnapshot,
		// history_attempts_uncertain_total) counts it, and the key re-opens
		// below only as a genuinely NEW attempt with a fresh evaluation —
		// no fabricated recorded outcome rides the reap. A slow-but-alive
		// owner past the TTL is counted here too: over-counting uncertainty
		// is the safe direction; fabricating certainty never is.
		if !rec.done {
			a.attemptsUncertain++
			a.lastUncertainAt = now
			metrics.HistoryAttemptsUncertainTotal.Inc()
		}
		delete(a.attempts, key)
	}
	a.attempts[key] = historyAttempt{at: now}
	a.attemptOrder = append(a.attemptOrder, key)
	a.evictAttemptsLocked()
	return historyAttempt{}, true
}

// completeAttempt records the owner's first outcome into its claim. The
// deferred call in AdmitWithHistory evaluates the named results at return
// time, so every exit path (refusal, money denial, admission) records
// exactly once.
func (a *Admission) completeAttempt(key string, dec HistoryDecision, admitted bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.attempts[key]
	if !ok || rec.done {
		return // claim evicted mid-flight, or already completed (first wins)
	}
	rec.dec, rec.err, rec.admitted, rec.done = dec, err, admitted, true
	a.attempts[key] = rec
}

// evictAttemptsLocked bounds the ledger: the oldest completed claims are
// dropped FIFO past the cap. In-flight claims are pinned — they hold their
// caller's dedup contract — and are transient (completed or TTL-reaped on
// the next claim), so the cap can only be exceeded while callers with
// live claims are mid-attempt.
func (a *Admission) evictAttemptsLocked() {
	if len(a.attempts) <= DefaultHistoryAttemptLedgerMax {
		return
	}
	kept := a.attemptOrder[:0]
	for _, key := range a.attemptOrder {
		rec, ok := a.attempts[key]
		switch {
		case !ok: // stale order key (TTL-reaped earlier)
		case len(a.attempts) <= DefaultHistoryAttemptLedgerMax, !rec.done:
			kept = append(kept, key)
		default:
			delete(a.attempts, key)
		}
	}
	a.attemptOrder = kept
}
