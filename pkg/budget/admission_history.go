// History admission policy (N10-P04-T03; owner decisions I40/I44).
//
// The durable request-history path (loggerd) can fail independently of the
// gateway process: its HistoryBufferGate may saturate (T02) or Redis writes
// may be unavailable. This file makes the deployment-level decision for how
// request admission must behave in those windows, and it makes the decision
// observable across the process boundary:
//
//   - reject (default, I40): when the durable history path cannot guarantee
//     a write (buffer full, loggerd offline) or the state cannot be
//     verified, new requests are REJECTED. Denials surface as
//     HistoryOutageError wrapping ErrHistoryUnavailable — never as budget
//     exhaustion (402/429) — so callers can map them to the dedicated
//     unavailable status.
//   - allow_loss (explicit opt-in, I44): new requests are served even when
//     durable history would be lost. The permission is strictly narrower
//     than any availability concern: it never relaxes rights or policy
//     (this gate runs after route+policy), never relaxes spend accounting
//     (Reserve/enforce store outages still deny — see the tests), and never
//     touches the mandatory audit journal (pkg/adminstore audit + its
//     outbox stay fail-closed regardless of this setting).
//
// Because loggerd and the gateway are separate processes, the loggerd state
// reaches this policy through a Redis signal key written by the consumer's
// HistorySignalPublisher (services/loggerd/consumer/history_signal.go):
// HistorySignalKey(stream) holds a HistorySignal JSON payload with a short
// TTL heartbeat. A missing or expired key means "loggerd down but the
// durable stream itself is intact" — the buffer is still being written by
// the store, so admission stays open. Every Redis error here fails CLOSED:
// an unverifiable state must not silently become "serve as if nothing
// happened" under the default policy.
//
// The gate consult happens in Admission.Plan BEFORE the reservations-mode
// checks (this is a deployment-level setting, independent of per-org §9
// modes): an org with reservations off still gets history-gated admission.
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/redis/go-redis/v9"
)

// HistoryMode is the deployment-level N10-P04-T03 admission setting.
type HistoryMode string

const (
	// HistoryModeReject is the default: new requests are refused while the
	// durable history path cannot guarantee writes (I40).
	HistoryModeReject HistoryMode = "reject"
	// HistoryModeAllowLoss is the explicit opt-in: requests are served even
	// when durable history would be lost, with the loss surfaced in logs,
	// the typed admission state and the Plan denial surface (I44).
	HistoryModeAllowLoss HistoryMode = "allow_loss"
)

// ResolveHistoryMode maps a raw settings value to a HistoryMode. The empty
// value and ANY unknown value resolve to the default reject policy: a
// typo in the setting must fail closed, never open.
func ResolveHistoryMode(s string) HistoryMode {
	if HistoryMode(s) == HistoryModeAllowLoss {
		return HistoryModeAllowLoss
	}
	return HistoryModeReject
}

// HistoryState is the last observed durable-history health, as reported by
// a HistoryProbe (and mirrored into the inter-process signal payload).
type HistoryState string

const (
	// HistoryStateOK is the healthy state: durable history writes are
	// guaranteed.
	HistoryStateOK HistoryState = "ok"
	// HistoryStateBufferFull is the saturated state: the loggerd
	// HistoryBufferGate cannot keep up (T02).
	HistoryStateBufferFull HistoryState = "buffer_full"
	// HistoryStateWriteUnavailable is the outage state: the durable write
	// path is down (Redis/store unreachable from loggerd).
	HistoryStateWriteUnavailable HistoryState = "write_unavailable"
)

// ErrHistoryUnavailable is the sentinel wrapped by every history-admission
// denial. Callers branch on it with errors.Is to map the denial to the
// dedicated "history unavailable" status instead of budget exhaustion.
var ErrHistoryUnavailable = errors.New("history admission: durable request history unavailable")

// HistoryOutageError is the typed denial produced by the default reject
// policy. State says which outage was observed; Cause (when non-nil) is the
// probe failure that made the state unverifiable.
type HistoryOutageError struct {
	State HistoryState
	Cause error
}

func (e *HistoryOutageError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("%v (state %s)", ErrHistoryUnavailable, e.State)
	}
	return fmt.Sprintf("%v (state %s: %v)", ErrHistoryUnavailable, e.State, e.Cause)
}

// Unwrap exposes only the sentinel: the denial identity is the outage
// itself, not its transport cause.
func (e *HistoryOutageError) Unwrap() error { return ErrHistoryUnavailable }

// HistoryProbe reports the durable history path's health. Implementations
// must be cheap (a couple of Redis round-trips) and must fail CLOSED: an
// error return means "state unverifiable", which the default policy treats
// as HistoryStateWriteUnavailable.
type HistoryProbe interface {
	ProbeHistory(ctx context.Context) (HistoryState, error)
}

// HistoryAdmission is the N10-P04-T03 policy evaluated on every Plan: probe
// the durable-history health, then either admit, deny (default reject), or
// admit-with-loss (explicit allow_loss) while tracking the loss flag for
// observability. It is safe for concurrent use. The zero value with a nil
// probe is disarmed (Admit always succeeds) so wiring the probe remains an
// explicit deployment step.
type HistoryAdmission struct {
	probe HistoryProbe
	mode  HistoryMode
	log   *slog.Logger

	mu         sync.Mutex
	state      HistoryState // last decided state ("" until first Admit)
	lossActive bool         // serving while an outage is observed
}

// NewHistoryAdmission builds the policy. probe may be nil (disarmed — used
// by tests and by deployments that have not wired the signal reader yet);
// mode should come from ResolveHistoryMode.
func NewHistoryAdmission(probe HistoryProbe, mode HistoryMode, log *slog.Logger) *HistoryAdmission {
	if log == nil {
		log = slog.Default()
	}
	return &HistoryAdmission{probe: probe, mode: mode, log: log}
}

// Mode reports the configured HistoryMode.
func (h *HistoryAdmission) Mode() HistoryMode {
	if h == nil {
		return HistoryModeReject
	}
	return h.mode
}

// setMode re-pins the policy's mode with the same fail-safe resolution as
// ResolveHistoryMode. Composition seam (used by Admission.SetHistoryMode):
// the armed gate owns the ACTIVE mode, so the profile setter must reach it
// instead of forking a second mode. Wiring-time only, like
// SetHistoryAdmission — mode is read without a lock on the hot path.
func (h *HistoryAdmission) setMode(m HistoryMode) {
	if h == nil {
		return
	}
	h.mode = ResolveHistoryMode(string(m))
}

// State reports the last decided state ("" before the first Admit).
func (h *HistoryAdmission) State() HistoryState {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// LossActive reports whether requests are currently being served despite a
// durable-history outage (only possible under the explicit allow_loss
// opt-in). This flag is the loss observable required by I44; it is
// deliberately scoped to history durability — rights, spend accounting and
// the mandatory audit journal never consult it.
func (h *HistoryAdmission) LossActive() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lossActive
}

// Admit evaluates the durable-history health against the configured mode.
// It returns a *HistoryOutageError (errors.Is ErrHistoryUnavailable) only
// under the default reject policy with an outage observed; under allow_loss
// it always admits and records the loss flag.
func (h *HistoryAdmission) Admit(ctx context.Context) error {
	if h == nil || h.probe == nil {
		return nil
	}
	state, err := h.probe.ProbeHistory(ctx)
	if err != nil {
		// Fail closed on the unverified case: an unreadable signal is
		// treated as the worst plausible state, never as healthy.
		state = HistoryStateWriteUnavailable
	}
	if state == HistoryStateOK {
		h.record(HistoryStateOK)
		return nil
	}
	// Record before deciding: the state and its transition log are
	// observable under BOTH modes (the loss flag only ever arms under
	// allow_loss — record() derives it from the mode).
	h.record(state)
	if h.mode == HistoryModeAllowLoss {
		return nil
	}
	return &HistoryOutageError{State: state, Cause: err}
}

// record updates the decided state/loss flag and logs each transition
// exactly once (the consumer heartbeats the signal every second, so the
// transition — not the observation — is the log-worthy event).
func (h *HistoryAdmission) record(state HistoryState) {
	h.mu.Lock()
	prev := h.state
	// lossActive means "requests are being SERVED through an outage"
	// (LossActive's contract), which is only possible under the explicit
	// allow_loss opt-in — reject mode denies, so it never serves a loss.
	loss := h.mode == HistoryModeAllowLoss && state != HistoryStateOK
	h.state, h.lossActive = state, loss
	h.mu.Unlock()
	if prev == state {
		return
	}
	switch {
	case prev == "":
		// First observation: log at Info so deployments see the gate arm.
		if state == HistoryStateOK {
			h.log.Info("history admission armed: durable history healthy",
				"mode", string(h.mode))
		} else {
			h.logOutage(state)
		}
	case state == HistoryStateOK:
		h.log.Info("history admission recovered: durable history healthy again",
			"mode", string(h.mode), "previous_state", string(prev))
	default:
		h.logOutage(state)
	}
}

func (h *HistoryAdmission) logOutage(state HistoryState) {
	if h.mode == HistoryModeAllowLoss {
		// I44: the loss is served, but it must be loud and its scope
		// explicit — this permission never extends beyond durability.
		h.log.Warn("history outage: serving new requests with durable history LOSS permitted (explicit allow_loss opt-in); rights, spend accounting and mandatory audit remain fail-closed",
			"state", string(state))
		return
	}
	h.log.Warn("history outage: new requests REJECTED until durable history is guaranteed (default reject policy, I40)",
		"state", string(state))
}

// HistorySignal is the wire payload the loggerd consumer publishes (see
// services/loggerd/consumer/history_signal.go) and this package parses. It
// is the inter-process seam between the two binaries.
type HistorySignal struct {
	// State is the observed durable-history health.
	State HistoryState `json:"state"`
	// Detail carries the short human-readable cause for operators.
	Detail string `json:"detail,omitempty"`
	// Depth is the buffer depth (items) at observation time, -1 unknown.
	Depth int64 `json:"depth"`
	// UnixSec is the observation timestamp (signal freshness is enforced by
	// the key TTL, not by comparing clocks).
	UnixSec int64 `json:"unix_sec"`
}

// HistorySignalKeyPrefix namespaces the loggerd signal keys.
const HistorySignalKeyPrefix = "events:history:admission:"

// HistorySignalKey is the Redis key the loggerd consumer heartbeats for the
// given stream name. Both processes must agree on the stream name (the
// gateway deployment knows which stream it configures loggerd with).
func HistorySignalKey(stream string) string {
	return HistorySignalKeyPrefix + stream
}

// EncodeHistorySignal renders the payload for the signal key.
func EncodeHistorySignal(s HistorySignal) ([]byte, error) {
	if s.Depth == 0 {
		s.Depth = -1 // 0 is ambiguous; normalize to "unknown"
	}
	return json.Marshal(s)
}

// ParseHistorySignal validates and decodes a signal payload. Unknown states
// are an error (a future writer must not silently downgrade the policy).
func ParseHistorySignal(b []byte) (HistorySignal, error) {
	var s HistorySignal
	if err := json.Unmarshal(b, &s); err != nil {
		return HistorySignal{}, fmt.Errorf("history signal: %w", err)
	}
	switch s.State {
	case HistoryStateOK, HistoryStateBufferFull, HistoryStateWriteUnavailable:
	default:
		return HistorySignal{}, fmt.Errorf("history signal: unknown state %q", s.State)
	}
	if s.Depth == 0 {
		s.Depth = -1
	}
	return s, nil
}

// HistoryRedis is the minimal Redis surface the probe needs; *redis.Client
// satisfies it. Kept narrow so tests can fake it without a server.
type HistoryRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	XLen(ctx context.Context, stream string) *redis.IntCmd
}

// RedisHistoryProbe reads the loggerd admission signal and, as a second
// line of defense, the stream depth directly. maxEntries ≤ 0 disables the
// depth check (the signal alone decides); with it set, a saturated stream
// is caught even if the signal key expired mid-outage.
type RedisHistoryProbe struct {
	rdb        HistoryRedis
	stream     string
	maxEntries int64
}

// NewRedisHistoryProbe builds the probe for one loggerd stream.
func NewRedisHistoryProbe(rdb HistoryRedis, stream string, maxEntries int64) *RedisHistoryProbe {
	return &RedisHistoryProbe{rdb: rdb, stream: stream, maxEntries: maxEntries}
}

// ProbeHistory implements HistoryProbe. Errors mean "unverifiable" and the
// policy fails closed on them.
func (p *RedisHistoryProbe) ProbeHistory(ctx context.Context) (HistoryState, error) {
	if p == nil || p.rdb == nil {
		return "", errors.New("history probe not wired")
	}
	raw, err := p.rdb.Get(ctx, HistorySignalKey(p.stream)).Result()
	switch {
	case err == nil:
		sig, perr := ParseHistorySignal([]byte(raw))
		if perr != nil {
			return "", perr
		}
		switch sig.State {
		case HistoryStateBufferFull:
			return HistoryStateBufferFull, nil
		case HistoryStateWriteUnavailable:
			return HistoryStateWriteUnavailable, nil
		}
		// HistoryStateOK falls through to the direct depth check: a fresh
		// "ok" heartbeat from loggerd is necessary but the stream may have
		// saturated between heartbeats.
	case errors.Is(err, redis.Nil):
		// No live signal: loggerd is down (or has never run) but the
		// durable stream itself is intact — the history store still
		// accepts writes, so admission stays open unless the depth check
		// below observes saturation.
	default:
		return "", fmt.Errorf("read history signal: %w", err)
	}
	if p.maxEntries > 0 {
		depth, err := p.rdb.XLen(ctx, p.stream).Result()
		if err != nil {
			return "", fmt.Errorf("probe history depth: %w", err)
		}
		if depth >= p.maxEntries {
			return HistoryStateBufferFull, nil
		}
	}
	return HistoryStateOK, nil
}

// SetHistoryAdmission arms the N10-P04-T03 history-outage gate on an
// admission controller. It must be called before the controller starts
// serving (before the first Plan) — Plan reads the field without a lock, as
// it does for the other immutable wiring. Passing nil disarms the gate.
func (a *Admission) SetHistoryAdmission(h *HistoryAdmission) {
	if a == nil {
		return
	}
	a.history = h
}
