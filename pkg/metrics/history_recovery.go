// History failure-recovery observability (N12-P02-T04; owner decisions
// I40/I44/I45).
//
// The failure-recovery family already makes history outages fail-closed
// (admission reject / explicit allow_loss, N10-P04-T03 + N12-P02-T03); this
// file adds the operations-visible recovery surface so a recovery cycle is
// observable end to end on /metrics:
//
//   - BACKLOG: the durable history buffer's depth and backpressure state,
//     exported by the loggerd consume loop (the only process that measures
//     it). A backlog draining to 0 after an outage IS the recovery
//     observable; -1 depth means "no observation yet" (gate disarmed or
//     consumer not running) and must never be read as "empty".
//   - GAPS: the cumulative count of admissions served with history loss
//     under the explicit allow_loss profile (I44: the loss must stay
//     visible; incomplete history must never appear complete). The default
//     reject profile never increments it.
//   - RECONCILIATION: the cumulative count of admission attempts whose
//     dedup claim lapsed unfinished past the TTL — the owner died (or the
//     process crashed) before an outcome landed, so the attempt's external
//     effect is UNKNOWN. The unknown population is never auto-ported to a
//     persisted/authorized/settled status and never re-dispatched (I45);
//     it is counted here and in budget.Admission.RecoverySnapshot so
//     reconciliation can proceed from an honest uncertainty surface.
//
// Counts are per-process (the gateway and loggerd are separate binaries);
// aggregates come from scraping both processes' /metrics endpoints.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// historySubsystem namespaces the N12-P02-T04 failure-recovery metrics.
const historySubsystem = "history"

var (
	// HistoryBufferDepth gauges the durable history buffer's depth (stream
	// entries) as last observed by the loggerd consume loop (N10-P04-T02
	// gate probe, exported per iteration). -1 = unobserved (gate disarmed,
	// or consumer not running — the gauge then holds its last value; treat
	// staleness via the scrape timestamp, not the value). This is the
	// backlog observable: growth during an outage, drain to ~0 as the
	// recovery completes.
	HistoryBufferDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: historySubsystem,
			Name:      "buffer_depth",
			Help:      "Durable history buffer depth (stream entries) as last observed by loggerd; -1 = unobserved (N12-P02-T04 backlog visibility).",
		},
	)

	// HistoryBufferSaturated is 1 while the durable buffer's backpressure
	// signal is active (depth at/over the bound, hysteresis held, or a
	// fail-closed probe failure — an unverifiable capacity counts as
	// saturated, never as healthy), 0 when clear. Mirrors the state the
	// inter-process signal folds into the gateway's admission policy.
	HistoryBufferSaturated = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: historySubsystem,
			Name:      "buffer_saturated",
			Help:      "1 while the durable history buffer's fail-closed backpressure signal is active (saturation or unverifiable capacity), 0 when clear (N12-P02-T04).",
		},
	)

	// HistoryLossAdmissionsTotal counts admissions served while their
	// request history could not be persisted durably — only possible under
	// the explicit allow_loss profile (I40 default is reject). Each count
	// is one lost history record: the visible volume of the history GAP
	// (I44). The counter never resets on recovery; gap volume accumulates
	// across outage windows.
	HistoryLossAdmissionsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: historySubsystem,
			Name:      "loss_admissions_total",
			Help:      "Admissions served with request-history loss (explicit allow_loss profile only; each count is one lost history record — the visible gap volume, N12-P02-T04).",
		},
	)

	// HistoryAttemptsUncertainTotal counts admission attempts whose dedup
	// claim lapsed unfinished past the replay TTL: the owner died or the
	// process crashed before any outcome was recorded, so the attempt's
	// external effect is UNKNOWN. These attempts are never reported as
	// persisted/authorized/settled and never automatically re-dispatched
	// (I45); they form the reconciliation population an operator resolves
	// (via the reservation reconcile worker and settlement records), and
	// the key re-opens only as a genuinely NEW attempt.
	HistoryAttemptsUncertainTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: historySubsystem,
			Name:      "attempts_uncertain_total",
			Help:      "Admission attempts reaped unfinished past the dedup TTL — outcome UNKNOWN after crash/owner death; visible for reconciliation, never auto-re-dispatched (I45, N12-P02-T04).",
		},
	)
)
