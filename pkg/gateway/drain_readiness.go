package cli

// N12-P03-T03 — readiness managed before stop.
//
// The drain sequence on SIGINT/SIGTERM (or parent cancellation) is, in order:
//
//  1. readiness=false — /healthz reports 503 "draining" so load balancers and
//     orchestrator readiness probes stop routing NEW work to this process
//     while the listener is still accepting;
//  2. bounded readiness-propagation window (YABANIN_READINESS_DRAIN_DELAY,
//     default 3s, clamp 0s–10s) — gives the probe interval + LB convergence
//     time to observe the not-ready signal BEFORE the port closes;
//  3. stop accepting — http.Server.Shutdown closes the listeners and drains
//     the in-flight requests under its own bounded budget;
//  4. drain in-flight with bounded timeout — every subsequent stage (admin
//     listener, lineage ledger close, reservation-escrow release) gets its
//     OWN deadline so a saturated stage can never starve the later ones
//     (the N12-P03-T01/T02 flagged gap: one shared 5s ctx let a wedged HTTP
//     drain consume the escrow-release budget);
//  5. release leases — admission escrow release runs last, after in-flight
//     work settled or hit its bound.
//
// The whole sequence is itself bounded from the outside by the process grace
// (YABANIN_SHUTDOWN_GRACE, services/run, N12-P03-T02): worst case with the
// default delay is 3+5+2+5+5 = 20s < the 30s default grace, so SIGTERM under
// load leaves bounded unfinished operations — the outer grace is the
// authoritative bound, these budgets order the work inside it. A second
// signal or a forced kill during any stage force-exits (outer awaitShutdownExit);
// that never leaves eternal leases: session-scoped advisory locks die with
// the process and every recovery lease's authority is TTL-bounded, so
// takeover happens via TTL expiry (owner decisions I42–I45, I67, I70: drain
// state is bounded, unknown-outcome work is never replayed, recovery inside
// the 60s node-loss window).

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// envReadinessDrainDelay bounds the window between readiness=false and
	// closing the listeners. Read HERE (wiring by env knob, same convention
	// as YABANIN_HTTP_MAX_HEADER_BYTES in this package), deliberately not in
	// pkg/config.
	envReadinessDrainDelay = "YABANIN_READINESS_DRAIN_DELAY"

	// defaultReadinessDrainDelay covers this repo's deployment shape
	// (deploy/helm probes poll /healthz every 10s; compose healthchecks are
	// tighter): 3s catches fast pollers without eating the drain budgets.
	// Operators running default-period (10s) k8s probes raise it via env.
	defaultReadinessDrainDelay = 3 * time.Second

	// maxReadinessDrainDelay keeps the worst-case inner drain under the 30s
	// default outer grace: 10+5+2+5+5 = 27s. 0 disables the window (tests,
	// single-instance stands where nobody polls readiness).
	maxReadinessDrainDelay = 10 * time.Second
)

// Drain-stage budgets (production). Per-stage, not shared: a saturated stage
// must not starve the later ones — the escrow release (lease return) always
// gets its full budget.
const (
	drainHTTPBudget    = 5 * time.Second // in-flight requests/streams (I45: unfinished ⇒ unknown outcome, never replayed)
	drainAdminBudget   = 2 * time.Second // debug/metrics listener, non-streaming
	drainLineageBudget = 5 * time.Second // lineage async ledger flush
	drainEscrowBudget  = 5 * time.Second // reservation escrow release (leases released last)
)

// ReadinessDrainDelay resolves the readiness-propagation window.
// Empty/absent = 3s. 0 is legal (no window). Invalid or out-of-range values
// FAIL STARTUP rather than silently falling back: the knob orders the drain,
// and a typo must not quietly produce a different shutdown shape.
func ReadinessDrainDelay() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(envReadinessDrainDelay))
	if raw == "" {
		return defaultReadinessDrainDelay, nil
	}
	delay, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", envReadinessDrainDelay, raw, err)
	}
	if delay < 0 || delay > maxReadinessDrainDelay {
		return 0, fmt.Errorf("%s must be between 0s and %s, got %s",
			envReadinessDrainDelay, maxReadinessDrainDelay, delay)
	}
	return delay, nil
}

// stageShutdowner is the part of *http.Server the drain sequence needs.
type stageShutdowner interface {
	Shutdown(ctx context.Context) error
}

// DrainReadiness is the process readiness gate shared by the gateway and
// loggerd health endpoints. Nil-safe: a nil gate always reports ready, so
// test compositions (and any wiring that never starts the servers) keep the
// pre-T03 always-ready behavior. Flips exactly once per process — there is
// no un-drain.
type DrainReadiness struct {
	draining atomic.Bool
	delay    time.Duration
}

// NewDrainReadiness builds the gate from YABANIN_READINESS_DRAIN_DELAY;
// an invalid value is a startup error (fail-closed knob convention).
func NewDrainReadiness() (*DrainReadiness, error) {
	delay, err := ReadinessDrainDelay()
	if err != nil {
		return nil, err
	}
	return &DrainReadiness{delay: delay}, nil
}

// SetDraining flips readiness to not-ready. Idempotent.
func (d *DrainReadiness) SetDraining() {
	if d == nil {
		return
	}
	d.draining.Store(true)
}

// Draining reports whether the process stopped (or is about to stop)
// accepting new work.
func (d *DrainReadiness) Draining() bool {
	return d != nil && d.draining.Load()
}

// Ready is the health-endpoint predicate.
func (d *DrainReadiness) Ready() bool { return !d.Draining() }

// PropagationDelay is the configured readiness-propagation window.
func (d *DrainReadiness) PropagationDelay() time.Duration {
	if d == nil {
		return 0
	}
	return d.delay
}

// WaitPropagation holds the readiness=false state for the propagation window
// BEFORE the listeners close, so readiness pollers observe not-ready while
// the port still accepts (the whole point of managing readiness before
// stop). Bounded by construction. A second signal during the wait force-exits
// from the outer shutdown path (services/run), which is the intended
// "second signal accelerates exit" behavior.
func (d *DrainReadiness) WaitPropagation() {
	delay := d.PropagationDelay()
	if delay <= 0 {
		return
	}
	time.Sleep(delay)
}

// drainBudgets are the per-stage deadlines. Production uses
// defaultDrainBudgets; tests inject millisecond budgets so the sequence runs
// deterministically without wall-clock waits.
type drainBudgets struct {
	http, admin, lineage, escrow time.Duration
}

func defaultDrainBudgets() drainBudgets {
	return drainBudgets{
		http:    drainHTTPBudget,
		admin:   drainAdminBudget,
		lineage: drainLineageBudget,
		escrow:  drainEscrowBudget,
	}
}

// runGatewayDrain executes the drain sequence. srv and adminSrv may be nil
// (never started / already closed) — nil means the feature was off;
// closeLineage and releaseLeases are the process-owned cleanup hooks
// (lineage ledger close, admission escrow release). Stage parameters must be
// untyped nil or non-nil — never a typed-nil pointer wrapped in the
// interface (drainServers does the conversion; see its comment).
// release) — nil means the feature was off.
func runGatewayDrain(
	readiness *DrainReadiness,
	srv, adminSrv stageShutdowner,
	closeLineage func(time.Duration),
	releaseLeases func(context.Context),
	l *slog.Logger,
) {
	runGatewayDrainBudgets(readiness, srv, adminSrv, closeLineage, releaseLeases, defaultDrainBudgets(), l)
}

// runGatewayDrainBudgets is runGatewayDrain with injectable stage budgets
// (test seam; production always passes defaultDrainBudgets).
func runGatewayDrainBudgets(
	readiness *DrainReadiness,
	srv, adminSrv stageShutdowner,
	closeLineage func(time.Duration),
	releaseLeases func(context.Context),
	budgets drainBudgets,
	l *slog.Logger,
) {
	readiness.SetDraining()
	l.Info("shutting down gateway...", "readiness", "draining",
		"readiness_propagation_delay", readiness.PropagationDelay().String())
	readiness.WaitPropagation()
	drainStage("http server", srv, budgets.http, l)
	drainStage("admin server", adminSrv, budgets.admin, l)
	if closeLineage != nil {
		closeLineage(budgets.lineage)
	}
	if releaseLeases != nil {
		ctx, cancel := context.WithTimeout(context.Background(), budgets.escrow)
		defer cancel()
		releaseLeases(ctx)
	}
	l.Info("gateway drain complete",
		"http_budget", budgets.http.String(),
		"admin_budget", budgets.admin.String(),
		"lineage_budget", budgets.lineage.String(),
		"escrow_budget", budgets.escrow.String())
}

// drainStage runs one bounded shutdown stage. A stage that exceeds its budget
// (hung handler ignoring ctx, stalled dependency) is abandoned with an error
// log — the remaining unfinished operations are bounded by the budget, never
// the process lifetime.
func drainStage(name string, srv stageShutdowner, budget time.Duration, l *slog.Logger) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		l.Error("drain stage exceeded its budget — remaining in-flight operations abandoned (bounded unfinished operations)",
			"stage", name, "budget", budget.String(), "error", err)
	}
}

// drainServers is the production wiring of runGatewayDrain for this gateway:
// it adapts the process-owned cleanup hooks (nil-guarded lineage close,
// admission escrow release) and runs the readiness-first sequence. Escrow
// release runs LAST (after in-flight work finished or hit its bound).
//
// Nil servers are converted to untyped nil BEFORE the stageShutdowner
// conversion: a typed-nil *http.Server wrapped in the interface would slip
// past drainStage's `srv == nil` guard and panic inside http.Server.Shutdown
// (caught by the golden SIGTERM test on a no-admin-listen stand — a panic in
// the shutdown path is itself an ungraceful exit).
func (gw *gateway) drainServers(srv, adminSrv *http.Server, l *slog.Logger) {
	var closeLineage func(time.Duration)
	if gw.lineageAsync != nil {
		closeLineage = gw.lineageAsync.Close
	}
	var releaseLeases func(context.Context)
	if gw.admission != nil {
		releaseLeases = gw.admission.Shutdown
	}
	var srvStage, adminStage stageShutdowner
	if srv != nil {
		srvStage = srv
	}
	if adminSrv != nil {
		adminStage = adminSrv
	}
	runGatewayDrain(gw.drain, srvStage, adminStage, closeLineage, releaseLeases, l)
}
