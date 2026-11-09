package cli

// N12-P01-T02 (owner decision 2026-11-04): production wiring for the
// N10-P04-T03 durable request-history admission (I40/I44). The gateway
// probes loggerd's admission signal (Redis key
// events:history:admission:<event_stream>) and, as a second line of
// defense, the event stream depth directly; while the durable history path
// cannot guarantee writes, Admission.Plan refuses new requests (default
// reject) or serves with the loss surfaced (explicit allow_loss).
//
// Arming is an explicit deployment step (YABANIN_HISTORY_ADMISSION=true):
// the T01 contract keeps the un-armed request path bit-for-bit, and an
// ENABLED knob with a missing dependency is a startup error — never a
// silent degradation to serve-without-history (fail-closed defaults).
// Vocabulary and bound knobs are validated at startup by
// config.Gateway.Validate; this builder is the second, wiring-level guard
// for programmatic configs that skip Validate.

import (
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
)

// buildHistoryAdmission resolves the deployment knobs into an armed
// budget.HistoryAdmission. Returns (nil, nil) when the knob is off — the
// historical request path continues unchanged with no probe round-trips.
//
// Guards (each a startup error, never a warn-and-continue):
//   - enabled without Redis: the probe needs the loggerd signal key and the
//     stream depth; without Redis the I40 state is permanently unverifiable
//     and reject mode would deny every request on an error the operator
//     cannot fix at runtime.
//   - empty event stream: the probe must watch the same stream loggerd
//     consumes (the signal key is namespaced by stream name); an empty name
//     would silently read a key no writer produces.
//   - negative probe bound: the operator asked for a depth bound and
//     mistyped; config.Validate rejects the same value up front.
//
// The mode resolves through budget.ResolveHistoryMode: "" and any unknown
// value fail closed to reject (config.Validate rejects unknown values at
// startup, so the runtime resolution only ever sees the documented
// vocabulary).
func buildHistoryAdmission(cfg config.Gateway, rdb *redis.Client, l *slog.Logger) (*budget.HistoryAdmission, error) {
	if !cfg.HistoryAdmissionEnabled {
		//nolint:nilnil // documented off contract: (nil, nil) is the disabled knob, not an error
		return nil, nil
	}
	if rdb == nil {
		return nil, fmt.Errorf("history_admission_enabled requires Redis (env YABANIN_HISTORY_ADMISSION): the loggerd admission signal and stream-depth probe are unwireable without it")
	}
	if cfg.EventStream == "" {
		return nil, fmt.Errorf("history_admission_enabled requires event_stream: the probe must watch the same stream loggerd consumes")
	}
	if cfg.HistoryProbeMaxEntries < 0 {
		return nil, fmt.Errorf("history_probe_max_entries must be >= 0 (env YABANIN_HISTORY_PROBE_MAX_ENTRIES), got %d", cfg.HistoryProbeMaxEntries)
	}
	mode := budget.ResolveHistoryMode(cfg.HistoryMode)
	probe := budget.NewRedisHistoryProbe(rdb, cfg.EventStream, cfg.HistoryProbeMaxEntries)
	return budget.NewHistoryAdmission(probe, mode, l.With("component", "history-admission")), nil
}

// logHistoryAdmissionArmed emits the operator-facing arming line: the
// resolved outage policy, the watched stream (the probe's signal key is
// namespaced by it — it must equal loggerd's stream_name), the depth bound,
// and how the gate composes with the reservations money leg.
func logHistoryAdmissionArmed(w *gatewayWiring, h *budget.HistoryAdmission, gateMode budget.Mode) {
	w.l.Info("history admission armed",
		"mode", string(h.Mode()),
		"probe_stream", w.cfg.EventStream,
		"probe_max_entries", w.cfg.HistoryProbeMaxEntries,
		"reservations_gate", string(gateMode))
}
