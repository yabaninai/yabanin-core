package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Durable budget reservation metrics (ADR-0001 rev. 3 §7.2, NEXT-18e).
// Names follow §7.2 verbatim; no org/key/session labels (cardinality and
// privacy rule AF-16) — per-org values are the admin API's job, not labels.

// admissionSecondsBuckets bound the D17 gate: the exit criterion is
// p95(budget_admission_overhead_seconds) ≤ 5ms (§7.3), so 5ms is a bucket.
var admissionSecondsBuckets = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1}

var budgetCollectors = []prometheus.Collector{
	BudgetReservedMicroUSD,
	BudgetAllowanceReleasedTotal,
	BudgetStrandedMicroUSD,
	SettlementLagSeconds,
	BudgetReservedDivergenceMicroUSD,
	BudgetWalletHeadroomMicroUSD,
	BudgetWalletInvariantViolations,
	BudgetGrantsTotal,
	BudgetGrantDurationSeconds,
	BudgetLocalAdmitTotal,
	BudgetAdmissionOverheadSeconds,
	BudgetBoundViolationTotal,
	BudgetBoundOvershootMicroUSDTotal,
}

func init() {
	allCollectors = append(allCollectors, budgetCollectors...)
}

var (
	// BudgetReservedMicroUSD gauges the capacity every hard money scope
	// currently holds frozen for in-flight and unsettled work (ADR-0001
	// §7.2). Labels: scope_kind. Set by the reconcile worker's invariant
	// pass (loggerd side).
	BudgetReservedMicroUSD = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "reserved_micro_usd",
			Help:      "Capacity frozen by reservations per hard scope kind, µUSD (ADR-0001 §7.2).",
		},
		[]string{"scope_kind"},
	)

	// BudgetAllowanceReleasedTotal counts reconcile releases (ADR-0001
	// §7.1.1/§7.1.2). Labels: reason — expired_safety_window (replica died,
	// lease lapsed past the safety window), zero_remainder (draining /
	// expired with nothing left to return) or crash_orphan (orphan escrow
	// closed by an explicit permanently-lost-replica verdict,
	// CloseAbandonedReplica / N06-P05 crash reconciliation). A sustained
	// expired_safety_window rate means replicas die without draining;
	// sustained crash_orphan means recovery keeps finding replicas that
	// never drained either.
	BudgetAllowanceReleasedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "allowance_released_total",
			Help:      "Allowances released by reconcile by reason (ADR-0001 §7.1.1/§7.1.2).",
		},
		[]string{"reason"},
	)

	// BudgetStrandedMicroUSD gauges capacity frozen by non-released
	// allowances whose lease already lapsed — money a dead replica keeps
	// blocking until the safety window passes (ADR-0001 §12). Sustained
	// growth = frozen capital + spurious denials on other replicas.
	BudgetStrandedMicroUSD = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "stranded_micro_usd",
			Help:      "Capacity held by lapsed non-released allowances, µUSD (ADR-0001 §12).",
		},
	)

	// SettlementLagSeconds gauges the age of the oldest unsettled
	// settlement job (pending/retry/processing). §5.4: a lag above 30 min
	// means the settlement worker is not keeping up (or is down) — while it
	// stalls, reconcile conservatively releases nothing and the reserve
	// stays frozen.
	SettlementLagSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "",
			Name:      "settlement_lag_seconds",
			Help:      "Age of the oldest unsettled settlement job, seconds (ADR-0001 §5.4/§7.2).",
		},
	)

	// BudgetReservedDivergenceMicroUSD gauges the §7.1.3 scope invariant
	// breach: Σ|reserved_µ(row) − Σ remainders of the row's non-released
	// allowances| per scope kind. Money-conserving paths keep this at 0;
	// anything above zero is drift (bug or manual tampering) — alert.
	BudgetReservedDivergenceMicroUSD = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "reserved_divergence_micro_usd",
			Help:      "Scope-invariant divergence reserved vs Σ non-released allowance remainders, µUSD (ADR-0001 §7.1.3).",
		},
		[]string{"scope_kind"},
	)

	// BudgetWalletHeadroomMicroUSD gauges the worst-case §7.1.4 wallet
	// invariant left-hand side across orgs: min(balance − remainder − floor
	// − reserved). Negative values are transiently legal only within the
	// recorded bound-overshoot of the window; sustained negativity is the
	// invariant breach alert.
	BudgetWalletHeadroomMicroUSD = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "wallet_headroom_micro_usd",
			Help:      "Worst-case wallet headroom balance − floor − reserved across orgs, µUSD (ADR-0001 §7.1.4).",
		},
	)

	// BudgetWalletInvariantViolations gauges how many org wallets currently
	// sit below zero headroom (§7.1.4). Transient dips absorb a bound
	// overshoot through grace; sustained > 0 is the breach alert (the
	// window is encoded in the alert rule, not in the gauge).
	BudgetWalletInvariantViolations = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "wallet_invariant_violations",
			Help:      "Org wallets with balance − floor − reserved < 0 (ADR-0001 §7.1.4).",
		},
	)

	// BudgetGrantsTotal counts store.Grant outcomes by scope and result:
	// granted | insufficient | no_source | error. result=error includes
	// store outages (§5.4 fail-closed posture).
	BudgetGrantsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "grants_total",
			Help:      "Reservation grant outcomes by scope_kind and result (ADR-0001 §7.2).",
		},
		[]string{"scope_kind", "result"},
	)

	// BudgetGrantDurationSeconds measures store.Grant latency. Grants are
	// the synchronous PG round trip of the admission path; a rise here
	// moves budget_admission_overhead_seconds with it.
	BudgetGrantDurationSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "grant_duration_seconds",
			Help:      "Reservation grant (PG escrow) latency, seconds (ADR-0001 §7.2).",
			Buckets:   admissionSecondsBuckets,
		},
	)

	// BudgetLocalAdmitTotal counts how Reserve funded a request: local
	// (existing escrow slice), grant (new PG escrow) or refused (no
	// capacity in shadow/enforce).
	BudgetLocalAdmitTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "local_admit_total",
			Help:      "Admission funding path per reserved request: local | grant | refused (ADR-0001 §7.2).",
		},
		[]string{"result"},
	)

	// BudgetAdmissionOverheadSeconds measures the synchronous admission
	// latency the reservation layer adds to a request (Plan + Reserve).
	// D17 shadow-exit gate: p95 ≤ 5ms (§7.3).
	BudgetAdmissionOverheadSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "admission_overhead_seconds",
			Help:      "Synchronous admission overhead added by reservations, seconds (D17 gate: p95 ≤ 5ms).",
			Buckets:   admissionSecondsBuckets,
		},
	)

	// BudgetBoundViolationTotal counts finalized requests whose actual cost
	// exceeded their bound (actual > bound, §4.2) — the only legitimate
	// source of overspend. D17 shadow-exit gate: ≤ 0.1% of reserved
	// requests for 7 consecutive days.
	BudgetBoundViolationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "bound_violation_total",
			Help:      "Requests finalized with actual > bound, by scope_kind (ADR-0001 §4.2/§7.2).",
		},
		[]string{"scope_kind"},
	)

	// BudgetBoundOvershootMicroUSDTotal accumulates (actual − bound)+ in
	// µUSD. The wallet invariant alert (§7.1.4) compares sustained negative
	// headroom against this counter's windowed increase: overspend beyond
	// grace becomes durable debt.
	BudgetBoundOvershootMicroUSDTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: "budget",
			Name:      "bound_overshoot_micro_usd_total",
			Help:      "Accumulated (actual − bound)+ overshoot, µUSD, by scope_kind (ADR-0001 §4.2/§7.2).",
		},
		[]string{"scope_kind"},
	)
)
