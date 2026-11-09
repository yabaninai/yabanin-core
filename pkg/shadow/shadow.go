// Package shadow implements v9 shadow-mode: a sampled fraction of real,
// already-served (non-streaming) production traffic is silently re-sent to a
// candidate model/provider. The client's response is fully determined BEFORE
// the shadow call fires, so shadow errors, timeouts, panics and a dead shadow
// provider are invisible to the client (mandatory passthrough).
//
// Design constraints (see docs/plans/QWEN27B_TASK_PLAN_9.md):
//   - fire-and-forget: the dispatcher never blocks or fails the primary path
//   - bounded: concurrency semaphore + per-call timeout + optional daily budget
//   - accounting: each completed shadow call emits one "request.shadow_completed"
//     event (same request_id, ab_group="shadow") so loggerd stores it as its
//     own request_logs row; it is never passed to the credit Deductor
//   - the package is provider-agnostic: the upstream call, usage parsing and
//     cost computation are injected as closures by the gateway (pkg/gateway).
package shadow

import (
	"context"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
)

const subsystem = "yabanin"

// semaphoreGrace bounds how long Run waits for a free concurrency slot before
// skipping the shadow call.
const semaphoreGrace = 250 * time.Millisecond

// Skip reasons returned by ShouldMirror. They are Prometheus label values, so
// they must stay a closed set.
const (
	SkipNone            = ""
	SkipDisabled        = "disabled"
	SkipSameModel       = "same_model"
	SkipResidency       = "residency"
	SkipSampling        = "sampling"
	SkipBudget          = "budget"
	SkipBudgetExhausted = "budget_exhausted"
	// SkipPolicy (RT-03): the shadow candidate failed the shared per-attempt
	// policy gate (access whitelist / ZAI / residency) — no call is made.
	SkipPolicy = "policy_denied"
)

// Result outcomes counted by shadow_requests_total.
const (
	OutcomeCompleted = "completed"
	OutcomeError     = "error"
	OutcomeTimeout   = "timeout"
	OutcomePanic     = "panic"
	OutcomeSkipped   = "skipped"
)

var (
	// RequestsTotal counts shadow outcomes by result label.
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "shadow_requests_total",
			Help:      "Shadow-mode outcomes by result (completed/error/timeout/panic/skipped).",
		},
		[]string{"result"},
	)

	// SkippedTotal counts requests that were not mirrored, by reason.
	SkippedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "shadow_skipped_total",
			Help:      "Shadow-mode skip decisions by reason.",
		},
		[]string{"reason"},
	)

	// LatencySeconds times the shadow upstream call itself.
	LatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "shadow_latency_seconds",
			Help:      "Shadow upstream call duration.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"model"},
	)

	// CostUSDTotal accumulates real USD spent on shadow calls.
	CostUSDTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "shadow_cost_usd_total",
			Help:      "Real USD spent on shadow-mode calls (lifetime of the process).",
		},
		[]string{"model"},
	)

	// BudgetExhaustedTotal counts requests skipped because the daily budget
	// was already used up.
	BudgetExhaustedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "shadow_budget_exhausted_total",
			Help:      "Shadow requests skipped due to daily budget exhaustion.",
		},
	)

	// Enabled reports the runtime kill-switch state (1 on, 0 off).
	Enabled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "shadow_enabled",
			Help:      "Shadow-mode runtime state (1 enabled, 0 disabled).",
		},
	)
)

// shadowCollectors is the package's collector set. The gateway registers it
// alongside pkg/metrics (RunGatewayServer, V9/S5). promauto has already
// attached each collector to the default registry at package load, so
// registration is idempotent; this slice exists so the gateway can log what
// is exposed and keep the list explicit.
var shadowCollectors = []prometheus.Collector{
	RequestsTotal, SkippedTotal, LatencySeconds, CostUSDTotal,
	BudgetExhaustedTotal, Enabled,
}

// Collectors returns the package's Prometheus collectors.
func Collectors() []prometheus.Collector { return shadowCollectors }

// Config holds the static shadow-mode configuration (env-driven, validated).
type Config struct {
	Enabled        bool          `yaml:"enabled"`
	Model          string        `yaml:"model"`            // candidate model to mirror traffic to
	UpstreamURL    string        `yaml:"upstream_url"`     // "" = use the primary upstream
	APIKey         string        `yaml:"api_key"`          // "" = use the gateway key
	SampleRate     float64       `yaml:"sample_rate"`      // fraction of eligible requests to mirror
	Timeout        time.Duration `yaml:"timeout"`          // per-shadow-call deadline
	MaxConcurrent  int           `yaml:"max_concurrent"`   // in-flight shadow calls cap
	DailyBudgetUSD float64       `yaml:"daily_budget_usd"` // 0 = unlimited
}

// DefaultConfig returns the safe defaults: everything off, 10% sample,
// 30s timeout, 4 in-flight calls, unlimited budget.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		SampleRate:    0.10,
		Timeout:       30 * time.Second,
		MaxConcurrent: 4,
	}
}

// Validate clamps out-of-range values to safe ones and reports what needed an
// operator decision (enabled with no model is the only hard error). Clamping
// is not an error: a mistyped sample rate of 7 must not take the gateway down.
// Clamps run before the hard-error check, so the returned config is safe to
// use even alongside the error — a zero MaxConcurrent can never reach a
// dispatcher and build a zero-capacity semaphore.
func (c Config) Validate() (Config, error) {
	if math.IsNaN(c.SampleRate) || c.SampleRate < 0 || c.SampleRate > 1 {
		c.SampleRate = clampSample(c.SampleRate)
	}
	if c.MaxConcurrent < 1 {
		c.MaxConcurrent = 1
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	if c.DailyBudgetUSD < 0 {
		c.DailyBudgetUSD = 0
	}
	if c.Enabled && c.Model == "" {
		return c, errMissingModel{}
	}
	return c, nil
}

func clampSample(v float64) float64 {
	switch {
	case math.IsNaN(v), v < 0:
		return 0
	default:
		return 1
	}
}

type errMissingModel struct{}

func (errMissingModel) Error() string {
	return "shadow: enabled but no model configured (YABANIN_SHADOW_MODEL)"
}

// PinnedOrgFunc reports whether an org is residency-pinned (must not have its
// traffic mirrored to another provider). The gateway supplies this from the
// same RegionResolver closure the residency enforcer uses.
type PinnedOrgFunc func(ctx context.Context, orgID string) bool

// Job describes one shadow call. The gateway injects Call/ParseUsage/
// ComputeCost so this package stays provider-agnostic and trivially testable.
type Job struct {
	RequestID    string
	SessionID    string
	OrgID        string
	TeamID       string
	PrimaryModel string
	ShadowModel  string
	Body         []byte // original (non-streaming) request body

	// Call performs the shadow upstream request with its own context. It must
	// not touch the primary request context or the HTTP response writer.
	Call func(ctx context.Context) ([]byte, error)
	// ParseUsage extracts token usage from the raw shadow response.
	ParseUsage func(body []byte) provider.Usage
	// ComputeCost converts usage to USD (provider.ComputeCost in practice).
	ComputeCost func(usage provider.Usage, providerName, model string) float64
	// StatusCode is the upstream HTTP status the Call closure actually
	// observed, when it can report one; 0 = unknown. Non-2xx upstream
	// responses normally surface as Call errors (no event), so this only
	// refines the status of completed calls.
	StatusCode int
	// Publish emits the request.shadow_completed event. It owns its retries and
	// timeout (the gateway wires cli.publishEvent semantics here) and never
	// blocks the caller for more than a few seconds. nil = no accounting.
	Publish func(ev *eventpub.Event)
}

// budgetState tracks the in-memory daily spend guard. A single mutex guards
// the pair (day, microUSD); the budget is advisory, not billing-grade.
//
// Unit decision (remediation O00): the canonical internal unit is integer
// micro-USD (1e-6 USD). The daily limit (USD, float) is converted to micro
// ONCE, at compare time, with half-up rounding; each observed cost is added
// in full with half-up rounding — no per-operation truncation, so
// accumulated micro-cost calls do reach the limit. Rounding the limit
// (rather than the running total) keeps the "spend == limit ⇒ no headroom"
// boundary exact: an operator-set $1.00 limit stops at $1.00, not at
// $1.0000005. Pre-O00 the code stored cents and compared float64(cents)
// against the USD limit, which both blocked after $0.01 of a $1.00 limit and
// silently dropped sub-$0.005 costs.
type budgetState struct {
	mu       sync.Mutex
	day      string // UTC "2006-01-02"
	microUSD int64
	nowFn    func() time.Time // injectable clock (tests freeze time)
}

// toMicro converts a USD float to integer micro-USD with half-up rounding.
func toMicro(usd float64) int64 {
	if usd <= 0 || math.IsNaN(usd) {
		return 0
	}
	v := usd * 1e6
	if math.IsInf(v, 1) {
		return int64(math.MaxInt64 / 2)
	}
	return int64(v + 0.5)
}

func (b *budgetState) spentUSD() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	return float64(b.microUSD) / 1e6
}

// hasHeadroom reports whether the daily limit still has room for another call.
// The check is against pre-call spend only (the cost is unknown in advance).
// limitUSD <= 0 means unlimited (returns true).
func (b *budgetState) hasHeadroom(limitUSD float64) bool {
	if limitUSD <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	return b.microUSD < toMicro(limitUSD)
}

func (b *budgetState) add(costUSD float64) {
	if costUSD <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	b.microUSD += toMicro(costUSD)
}

func (b *budgetState) roll() {
	day := b.now().UTC().Format("2006-01-02")
	if day != b.day {
		b.day = day
		b.microUSD = 0
	}
}

// now uses the injected clock when set (tests), else wall clock.
func (b *budgetState) now() time.Time {
	if b.nowFn != nil {
		return b.nowFn()
	}
	return time.Now()
}

// Dispatcher is the runtime shadow-mode engine. Construct with NewDispatcher;
// it is safe for concurrent use.
type Dispatcher struct {
	cfg     Config
	sem     chan struct{}
	enabled atomic.Bool
	budget  budgetState
	// randFn/sampleFn and nowFn are injectable for deterministic tests.
	randFn func() float64
	nowFn  func() time.Time
	pinned PinnedOrgFunc
	log    *slog.Logger
}

// NewDispatcher builds a Dispatcher. cfg is passed through Validate so a raw
// zero value can never construct a zero-capacity semaphore (which made every
// Run burn the grace window and skip); log may be nil (slog.Default). The
// enabled state starts at cfg.Enabled. The single hard error
// (enabled-without-model) is logged here and remains the gateway's config
// validation concern.
func NewDispatcher(cfg Config, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	cfg, err := cfg.Validate()
	if err != nil {
		log.Warn("shadow: invalid dispatcher config", "error", err)
	}
	d := &Dispatcher{
		cfg:    cfg,
		sem:    make(chan struct{}, cfg.MaxConcurrent),
		randFn: randFloat,
		nowFn:  time.Now,
		log:    log,
	}
	d.budget.nowFn = d.nowFn
	d.enabled.Store(cfg.Enabled)
	Enabled.Set(boolToFloat(d.enabled.Load()))
	return d
}

// SetPinnedOrgFunc wires the residency pin check (nil disables the check).
func (d *Dispatcher) SetPinnedOrgFunc(f PinnedOrgFunc) { d.pinned = f }

// Enabled reports the runtime kill-switch state.
func (d *Dispatcher) Enabled() bool { return d.enabled.Load() }

// SetEnabled flips the runtime kill-switch (S4 admin endpoint). In-flight
// calls finish; no new call starts while disabled.
func (d *Dispatcher) SetEnabled(on bool) {
	d.enabled.Store(on)
	Enabled.Set(boolToFloat(on))
}

// Status is the operator-facing view for GET /admin/shadow/status.
// APIKey is intentionally absent — never expose credentials.
type Status struct {
	Enabled        bool          `json:"enabled"`
	Model          string        `json:"model"`
	UpstreamURL    string        `json:"upstream_url,omitempty"`
	SampleRate     float64       `json:"sample_rate"`
	Timeout        time.Duration `json:"timeout"`
	MaxConcurrent  int           `json:"max_concurrent"`
	DailyBudgetUSD float64       `json:"daily_budget_usd"`
	BudgetUsedUSD  float64       `json:"budget_used_usd"`
	Day            string        `json:"day"`
}

// Status returns the current state without secrets.
func (d *Dispatcher) Status() Status {
	now := d.nowFn()
	return Status{
		Enabled:        d.enabled.Load(),
		Model:          d.cfg.Model,
		UpstreamURL:    d.cfg.UpstreamURL,
		SampleRate:     d.cfg.SampleRate,
		Timeout:        d.cfg.Timeout,
		MaxConcurrent:  d.cfg.MaxConcurrent,
		DailyBudgetUSD: d.cfg.DailyBudgetUSD,
		BudgetUsedUSD:  d.budget.spentUSD(),
		Day:            now.UTC().Format("2006-01-02"),
	}
}

// ShouldMirror decides, per request, whether to mirror and why not. Exactly
// one skip reason is returned (the first failing gate); the caller emits the
// skip metric. Order matters: cheap in-memory checks first, the DB-backed
// residency check only when everything else passed.
//
// The transport of the primary request (streaming or not) is deliberately NOT
// a gate: a shadow call is always a plain non-streaming request to the
// candidate (the gateway forces "stream": false in the shadow body), so a
// streaming primary is mirrored exactly like a non-streaming one. What the
// candidate "would have cost" is the same question either way.
func (d *Dispatcher) ShouldMirror(ctx context.Context, model string, orgID string) (bool, string) {
	if !d.enabled.Load() {
		return false, SkipDisabled
	}
	if model == d.cfg.Model {
		return false, SkipSameModel
	}
	if d.cfg.SampleRate < 1 && d.randFn() >= d.cfg.SampleRate {
		return false, SkipSampling
	}
	if d.pinned != nil && orgID != "" && d.pinned(ctx, orgID) {
		return false, SkipResidency
	}
	return true, SkipNone
}

// Run executes one shadow call. It must be invoked in its own goroutine by the
// gateway; Run never panics and never blocks longer than cfg.Timeout plus the
// semaphore grace window plus scheduler slack. It is safe to call Run when
// disabled — it returns immediately with a skip.
func (d *Dispatcher) Run(job Job) {
	defer func() {
		if r := recover(); r != nil {
			RequestsTotal.WithLabelValues(OutcomePanic).Inc()
			d.log.Error("shadow: panic recovered", "panic", r, "request_id", job.RequestID, "model", job.ShadowModel)
		}
	}()

	if !d.enabled.Load() {
		RequestsTotal.WithLabelValues(OutcomeSkipped).Inc()
		return
	}
	if job.Call == nil {
		d.log.Warn("shadow: job without Call, skipping", "request_id", job.RequestID)
		RequestsTotal.WithLabelValues(OutcomeSkipped).Inc()
		return
	}

	if !d.budget.hasHeadroom(d.cfg.DailyBudgetUSD) {
		SkippedTotal.WithLabelValues(SkipBudgetExhausted).Inc()
		BudgetExhaustedTotal.Inc()
		d.log.Debug("shadow: daily budget exhausted, skipping", "request_id", job.RequestID)
		return
	}

	// Concurrency cap: wait for a slot with a short grace deadline, then
	// skip. Shadow traffic runs detached, so the cost of the wait is shadow
	// capacity only — but it must never queue unboundedly.
	//
	// Token ownership stays with the waiter goroutine: after taking a slot it
	// hands it back as soon as Run releases it (close(release) is deferred, so
	// every path — success, error, panic, grace timeout — signals it). A late
	// win after the grace deadline already expired is therefore drained
	// immediately instead of stranding the token, which used to shrink
	// capacity by one per timed-out attempt until the dispatcher starved.
	// Each side carries its own timer: a fired timer delivers exactly one
	// tick, and sharing one channel would let the waiter consume Run's wake-up.
	acquired := make(chan struct{})
	release := make(chan struct{})
	waitTimer := time.NewTimer(semaphoreGrace)
	defer waitTimer.Stop()
	graceTimer := time.NewTimer(semaphoreGrace)
	defer graceTimer.Stop()
	defer close(release) // the waiter returns any slot it holds once this fires
	go func() {
		select {
		case d.sem <- struct{}{}:
			close(acquired)
			<-release // hold the slot for the duration of the shadow call
			<-d.sem   // No leak: this slot is returned on every path.
		case <-graceTimer.C:
			// Grace expired before a slot freed up: no token taken, nothing
			// to drain.
		}
	}()
	select {
	case <-acquired:
	case <-waitTimer.C:
		SkippedTotal.WithLabelValues("semaphore").Inc()
		d.log.Debug("shadow: concurrency cap reached, skipping", "request_id", job.RequestID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout)
	defer cancel()

	start := d.nowFn()
	resp, err := job.Call(ctx)
	latency := d.nowFn().Sub(start)
	LatencySeconds.WithLabelValues(job.ShadowModel).Observe(latency.Seconds())

	if err != nil {
		outcome := OutcomeError
		if ctx.Err() == context.DeadlineExceeded {
			outcome = OutcomeTimeout
		}
		RequestsTotal.WithLabelValues(outcome).Inc()
		d.log.Debug("shadow: call failed", "error", err, "outcome", outcome, "request_id", job.RequestID, "model", job.ShadowModel)
		return
	}

	var usage provider.Usage
	if job.ParseUsage != nil {
		usage = job.ParseUsage(resp)
	}
	cost := 0.0
	if job.ComputeCost != nil {
		cost = job.ComputeCost(usage, "", job.ShadowModel)
	}
	d.budget.add(cost)
	if cost > 0 {
		CostUSDTotal.WithLabelValues(job.ShadowModel).Add(cost)
	}

	RequestsTotal.WithLabelValues(OutcomeCompleted).Inc()

	if job.Publish != nil {
		ev := buildEvent(job, usage, cost, latency)
		job.Publish(ev)
	}
}

// buildEvent shapes the request.shadow_completed event. It mirrors the
// request.completed shape (same loggerd insert path) with the shadow
// discriminator ab_group="shadow". The mirrored request body rides the
// same media-history rule (I62): inline base64/data-URL media spans are
// stripped to metadata markers; text content is kept verbatim. The raw
// job body itself is untouched (the strip applies to the event payload
// only). counterfactual_cost_usd is left zero: that column belongs to the
// cache-counterfactual and must not carry a routing shadow cost (see the
// v9 plan, S3).
func buildEvent(job Job, usage provider.Usage, costUSD float64, latency time.Duration) *eventpub.Event {
	return &eventpub.Event{
		EventType:           "request.shadow_completed",
		Source:              "gateway",
		RequestID:           job.RequestID,
		SessionID:           job.SessionID,
		Payload:             eventpub.StripInlineMedia(string(job.Body)),
		OrgID:               job.OrgID,
		TeamID:              job.TeamID,
		ModelRequested:      job.PrimaryModel,
		ModelUsed:           job.ShadowModel,
		StatusCode:          eventStatusCode(job),
		DurationMs:          int64(latency.Milliseconds()),
		TokensIn:            usage.PromptTokens,
		TokensOut:           usage.CompletionTokens,
		CacheReadTokens:     usage.CacheReadTokens,
		CacheCreationTokens: usage.CacheCreationTokens,
		EstimatedCostUSD:    costUSD,
		Method:              "POST",
		ABGroup:             "shadow",
	}
}

// eventStatusCode derives the status recorded on the shadow event from the
// actual outcome. A job-reported upstream status wins when the Call closure
// captured one; otherwise a completed shadow call — the only outcome that
// ever builds an event — records 200. Failure outcomes never reach this path;
// they are counted in RequestsTotal (error/timeout) instead.
func eventStatusCode(job Job) int64 {
	if job.StatusCode > 0 {
		return int64(job.StatusCode)
	}
	return http.StatusOK
}

// boolToFloat renders a bool for the Enabled gauge.
func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// randFloat is the default sampling draw; tests replace d.randFn.
func randFloat() float64 { return rand.Float64() } //nolint:gosec // G404: traffic sampling draw, not a security-sensitive random
