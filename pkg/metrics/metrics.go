package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Residency metrics are declared in residency.go (PA.8).

// Subsystem is the Prometheus subsystem name for all gateway metrics.
const subsystem = "gateway"

var (
	// ---- HTTP request metrics ----

	// RequestsTotal counts all incoming HTTP requests, labelled by method, path pattern and status code.
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests received.",
		},
		[]string{"method", "path", "status"},
	)

	// RequestDurationSeconds measures the histogram of request durations in seconds.
	RequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "http_request_duration_seconds",
			Help:      "Duration of HTTP requests in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// ---- Loggerd consumer metrics ----

	// EventsInFlight tracks the number of events currently being processed by the loggerd consumer.
	EventsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "loggerd_events_in_flight",
			Help:      "Number of events currently in flight (being processed) by the loggerd consumer.",
		},
	)

	// EventsConsumedTotal counts the total number of events successfully consumed and persisted.
	EventsConsumedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "loggerd_events_consumed_total",
			Help:      "Total number of events successfully consumed by the loggerd consumer.",
		},
		[]string{"event_type"},
	)

	// Circuit breaker metrics

	// CircuitState tracks the classifier circuit breaker state.
	// State transitions tracked as a gauge: 0=closed, 1=open, 2=half-open.
	CircuitState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "circuit_breaker_state",
			Help:      "Circuit breaker state (0=closed, 1=open, 2=half-open), labelled by upstream.",
		},
		[]string{"upstream"},
	)

	// CircuitFailures counts circuit breaker failures.
	// TotalFailures counts the total number of failures recorded by each circuit breaker.
	CircuitFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "circuit_breaker_failures_total",
			Help:      "Total number of failures recorded by the circuit breaker.",
		},
		[]string{"upstream"},
	)

	// CircuitRecoveries counts circuit breaker recoveries.
	// TotalRecoveries counts the total number of times a circuit breaker recovered (closed → open or half-open → closed).
	CircuitRecoveries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "circuit_breaker_recoveries_total",
			Help:      "Total number of circuit breaker state recoveries.",
		},
		[]string{"upstream"},
	)

	// CircuitRejects counts requests rejected because the circuit breaker was
	// key (scheme://host) in per-endpoint scope — cardinality is bounded by
	// the configured upstream allow-list and the breaker map LRU cap — or ""
	// for the legacy global scope.
	CircuitRejects = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "circuit_breaker_rejects_total",
			Help:      "Requests rejected because the circuit breaker was open.",
		},
		[]string{"upstream"},
	)

	// ---- Whitelist ----

	// WlCheckErrors counts the total number of errors encountered during whitelist checks.
	WlCheckErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "whitelist_check_errors_total",
			Help:      "Total number of errors encountered during model-whitelist checks.",
		},
	)

	// ---- Classifier + Tier Routing (P5) ----

	// ClassifierClassTotal counts classification results by class and source.
	ClassifierClassTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "classifier_class_total",
			Help:      "Total number of classification decisions, labelled by complexity class and classifier source.",
		},
		[]string{"class", "source"},
	)

	// ClassifierConfidence measures the distribution of confidence scores across all classifiers.
	ClassifierConfidence = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "classifier_confidence",
			Help:      "Distribution of classifier confidence scores (0..1).",
			Buckets:   []float64{0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		},
	)

	// ClassifierLatencySeconds measures classification duration in seconds per source.
	ClassifierLatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "classifier_latency_seconds",
			Help:      "Classification decision latency in seconds.",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"source"},
	)

	// TierRoutingTotal counts model selections by tier class, original model and selected model.
	TierRoutingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "tier_routing_total",
			Help:      "Total number of tier routing decisions, labelled by class, from_model and to_model.",
		},
		[]string{"class", "from_model", "to_model"},
	)

	// SessionAffinityTotal counts KV-cache-aware model stickiness outcomes.
	SessionAffinityTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "session_affinity_total",
			Help:      "Total number of session-affinity lookups in tier selection, labelled by outcome (used|miss).",
		},
		[]string{"outcome"},
	)

	// CanaryArmTotal counts requests whose selected model matched an active rollout's base model
	// increments arm="canary" or arm="base" for that rollout, so the actual
	// traffic share is canary / (canary + base) per rollout label.
	CanaryArmTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "canary_arm_total",
			Help:      "Total number of canary rollout arm decisions, labelled by arm (canary|base), rollout name and served model.",
		},
		[]string{"arm", "rollout", "model"},
	)

	// TierRoutingSkippedTotal counts reasons for skipping tier routing (low confidence, disabled mode).
	TierRoutingSkippedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "tier_routing_skipped_total",
			Help:      "Total number of skipped tier routing decisions, labelled by reason.",
		},
		[]string{"reason"},
	)

	// ClassifierCacheHitTotal counts classifier cache hits by type (exact, semantic).
	ClassifierCacheHitTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "classifier_cache_hit_total",
			Help:      "Total number of classifier cache hits, labelled by cache type.",
		},
		[]string{"type"},
	)

	// ---- Router / registry ----

	// EvalgateVerdictTotal counts evalgate verdicts by outcome.
	// P5.9: Evalgate judge metrics
	EvalgateVerdictTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "evalgate_verdict_total",
			Help:      "Total evalgate judge verdicts, labelled by should_upgrade.",
		},
		[]string{"should_upgrade"},
	)

	// EvalgateLatencySeconds observes evalgate judge latency.
	// EvalgateLatencySeconds.
	EvalgateLatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "evalgate_latency_seconds",
			Help:      "Evalgate judge latency in seconds.",
			Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0},
		},
		[]string{},
	)

	// ClassifierCircuitState tracks the classifier circuit breaker state gauge.
	// P5.14: Classifier circuit breaker state gauge
	ClassifierCircuitState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "classifier_circuit_breaker_state",
			Help:      "Classifier circuit breaker state (0=closed, 1=open, 2=half-open).",
		},
		[]string{"classifier"},
	)

	// ResellerUnknownModelTotal tracks requests for models with no pricing data (potential revenue leak).
	ResellerUnknownModelTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "reseller_unknown_model_total",
			Help:      "Total number of requests for models with no pricing data (potential revenue leak).",
		},
	)

	// CreditDeductionSkippedTotal counts credit deduction skips due to zero-cost events.
	CreditDeductionSkippedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "credit_deduction_skipped_total",
			Help:      "Total number of credit deductions skipped (reason labels: zero_quote, no_wallet, insufficient).",
		},
		[]string{"reason"},
	)

	// SettlementJobsTotal counts durable settlement job executions by charge
	// kind and result (AF-06). result labels: settled, retry,
	// requires_attention. A transient execution error is retry, never
	// settled — money side effects are only counted settled after commit.
	SettlementJobsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "settlement_jobs_total",
			Help:      "Settlement job executions by charge_kind and result (settled, retry, requires_attention).",
		},
		[]string{"charge_kind", "result"},
	)

	// SettlementIntentConflicts counts duplicate settlement identities
	// (org, request, charge kind) delivered with a DIFFERENT amount than the
	// already-known job. The first amount stays authoritative; the conflict
	// is a diagnostic, never a second charge.
	SettlementIntentConflicts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "settlement_intent_conflicts_total",
			Help:      "Duplicate settlement identities delivered with a changed amount (diagnostic; no double charge).",
		},
		[]string{"charge_kind"},
	)

	// SettlementBacklog gauges the settlement backlog by state so a growing
	// pending/retry/requires_attention population is observable (AF-06:
	// durable pending rows must never be an invisible, unbounded queue).
	SettlementBacklog = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "settlement_jobs_backlog",
			Help:      "Current settlement_jobs rows per state (pending, retry, processing, requires_attention).",
		},
		[]string{"state"},
	)

	// WouldBillPartialMicroUSD accumulates the micro-USD that partial-usage
	// failures (client cancel, idle timeout, upstream error — ADR-0001 §6,
	// D5/D6) WOULD bill in enforce mode, observed while the org's
	// reservations mode is shadow. Shadow never changes charges: this is the
	// D17 exit-report input. Labels: scope_kind.
	WouldBillPartialMicroUSD = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "would_bill_partial_micro_usd_total",
			Help:      "Partial-usage failure cost (µUSD) enforce would bill, observed in shadow (ADR-0001 I2).",
		},
		[]string{"scope_kind"},
	)

	// UnchargedUnknownTotal accumulates the reserved bound micro-USD of
	// reservation-backed events whose usage/price is unknown (ADR-0001 §6):
	// never billed, never reported as zero, released by reconcile. Labels:
	// scope_kind. No org/key labels (cardinality and privacy rule AF-16).
	UnchargedUnknownTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "uncharged_unknown_total",
			Help:      "Reserved bound µUSD of unknown-usage reservation events, not billed and visible in reconcile (ADR-0001 §6).",
		},
		[]string{"scope_kind"},
	)

	// SettlementBatchSize observes how many jobs one org-batch settlement
	// transaction applies (ADR-0001 §5.5/§7.2, D11); empty batches are not
	// recorded.
	SettlementBatchSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "settlement_batch_size",
			Help:      "Jobs per org-batch settlement transaction (ADR-0001 §5.5).",
			Buckets:   []float64{1, 2, 5, 10, 25, 50, 100, 200},
		},
	)

	// ReservationsWouldDenyTotal counts admission refusals observed while
	// the org's reservations mode is shadow (ADR-0001 §9): the request is
	// served anyway and the counter is the D17 exit-report input. Labels:
	// scope_kind (wallet/team_month/agent_day/session) plus "unpriced" for
	// I3 refusals (no priced candidate in the planned chain).
	ReservationsWouldDenyTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "reservations_would_deny_total",
			Help:      "Admission refusals reservations enforce would produce, observed in shadow (ADR-0001 §9).",
		},
		[]string{"scope_kind"},
	)

	// ReservationsDeniedTotal counts refusals actually applied in enforce
	// mode — the service denials themselves (402/429/403 per §9). Labels:
	// scope_kind, same values as would_deny.
	ReservationsDeniedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "reservations_denied_total",
			Help:      "Admission refusals applied in enforce mode (ADR-0001 §9).",
		},
		[]string{"scope_kind"},
	)

	// SettlementPendingPriceExpiredTotal counts unknown-cost pending_price
	// settlement records that reached their deadline and terminated as
	// zero — the expiry makes the unresolved cost durably visible instead.
	SettlementPendingPriceExpiredTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "settlement_pending_price_expired_total",
			Help:      "Unknown-cost pending_price settlement records expired to terminal 'unknown' (never billed; R041 D2).",
		},
	)

	// AbsorbedUpstreamErrorMicroUSD accumulates the micro-USD of partial
	// usage on upstream failures (termination=upstream_error) that the
	// Labels: scope_kind.
	AbsorbedUpstreamErrorMicroUSD = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "absorbed_upstream_error_micro_usd_total",
			Help:      "Partial-usage cost (µUSD) absorbed by the platform on upstream errors, never billed to the org (R041 D3).",
		},
		[]string{"scope_kind"},
	)

	// BudgetSelfReapedAllowances counts allowance rows a replica's startup
	// sweep flipped from active to draining for its own crashed previous
	// leases only; the safety window still governs the money release (D3).
	BudgetSelfReapedAllowances = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "",
			Subsystem: subsystem,
			Name:      "budget_self_reaped_allowances_total",
			Help:      "Allowances flipped to draining by the own-replica startup sweep (lapsed leases of crashed incarnations; R042 D1/D2).",
		},
	)

	// All registered collectors so Init() can register them atomically.
	allCollectors = []prometheus.Collector{
		RequestsTotal,
		RequestDurationSeconds,
		EventsInFlight,
		EventsConsumedTotal,
		CircuitState,
		CircuitFailures,
		CircuitRecoveries,
		CircuitRejects,
		WlCheckErrors,
		ClassifierClassTotal,
		ClassifierConfidence,
		ClassifierLatencySeconds,
		TierRoutingTotal,
		SessionAffinityTotal,
		TierRoutingSkippedTotal,
		ClassifierCacheHitTotal,
		EvalgateVerdictTotal,
		EvalgateLatencySeconds,
		ClassifierCircuitState,
		ResellerUnknownModelTotal,
		CreditDeductionSkippedTotal,
		SettlementJobsTotal,
		SettlementIntentConflicts,
		SettlementBacklog,
		WouldBillPartialMicroUSD,
		UnchargedUnknownTotal,
		SettlementBatchSize,
		ReservationsWouldDenyTotal,
		ReservationsDeniedTotal,
		SettlementPendingPriceExpiredTotal,
		AbsorbedUpstreamErrorMicroUSD,
		BudgetSelfReapedAllowances,
		HistoryBufferDepth,
		HistoryBufferSaturated,
		HistoryLossAdmissionsTotal,
		HistoryAttemptsUncertainTotal,
	}
)

// Init registers all gateway metrics with the default Prometheus registry.
// It is idempotent — calling it multiple times is safe.
func Init() {
	for _, c := range allCollectors {
		if err := prometheus.Register(c); err != nil {
			// Already registered (e.g. via promauto) — ignore.
			if strings.Contains(err.Error(), "duplicate metrics") {
				continue
			}
			prometheus.MustRegister(c) // re-panic on real errors
		}
	}
}

// ToolPolicyDeniedTotal counts tool-policy denials on the model-response
// surfaces (JSON and SSE). TOOL-02: denied calls are stripped from the
// response the client sees, so this counter is the tracking surface for
// policy decisions.
var ToolPolicyDeniedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gateway_tool_policy_denied_total",
		Help: "Tool calls denied by org tool policy, per org and tool name. Denied calls never reach the client.",
	},
	[]string{"org_id", "tool"},
)
