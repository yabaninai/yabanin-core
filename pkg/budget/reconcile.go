// Package budget: reservation reconcile worker (NEXT-18e, ADR-0001 rev. 3
// §7.1). A bounded ticker on the loggerd side that closes the loop around
// the escrow lifecycle:
//
//  1. releases allowances whose lease lapsed past the safety window and
//     returns their remainder to the scopes, and releases draining/expired
//     allowances with zero remainder immediately (§7.1.1/§7.1.2 — the
//     release mechanics are ReservationStore.ReconcileRelease, NEXT-18a);
//  2. checks the scope invariant reserved_µ(S) = Σ remainders of the
//     non-released allowances of S and the wallet invariant
//     balance − floor − reserved ≥ −(overspend of the window) (§7.1.3/§7.1.4);
//     divergence is exported as metrics (alerting feeds on them) and logged;
//  3. gauges settlement lag — the age of the oldest unsettled job (§5.4);
//  4. runs the bounded 'released' retention (§7.1.5), shaped after the
//     AF-06/AF-16 settled-jobs retention: batched id-scoped deletes, passes
//     per pass, cadence-gated.
//
// Every step is conservative: an error inside a pass never releases
// anything and never stops the worker — the next tick retries. A stalled
// settlement worker stalls reconcile too (nothing is released while jobs
// are unsettled): that is the §5.4 safe direction, and the
// settlement_lag_seconds alert watches the blind spot.
package budget

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// ReconcileConfig bounds the worker. Zero/negative fields fall back to
// DefaultReconcileConfig.
type ReconcileConfig struct {
	// Interval is the release+invariant pass cadence.
	Interval time.Duration
	// SafetyWindow is how long past lease expiry an allowance may keep
	// freezing capacity before it is released (§14, D13).
	SafetyWindow time.Duration
	// ReleasedRetention bounds how long a 'released' allowance row stays
	// visible for forensics and late-settle lookups before the §7.1.5
	// retention deletes it. Default 90d — the same horizon as the settled
	// settlement_jobs retention (AF-16): the exactly-once authority for
	// money is the settlement job identity, not the allowance row, and job
	// lifetimes are bounded by the retry budget (~hours), so 90d exceeds
	// every settle horizon by orders of magnitude.
	ReleasedRetention time.Duration
	// RetentionEvery / RetentionBatch / RetentionPasses gate and bound the
	// §7.1.5 cleanup: at most RetentionPasses batches of RetentionBatch
	// rows per cadence window.
	RetentionEvery  time.Duration
	RetentionBatch  int64
	RetentionPasses int
	// ViolationLogLimit caps how many divergent/violating rows one pass
	// logs (logs may carry identifiers, metrics may not — AF-16).
	ViolationLogLimit int
}

// DefaultReconcileConfig returns production-safe defaults (§7.1/§14).
func DefaultReconcileConfig() ReconcileConfig {
	return ReconcileConfig{
		Interval:          5 * time.Minute,
		SafetyWindow:      ReservationSafetyWindow,
		ReleasedRetention: 90 * 24 * time.Hour,
		RetentionEvery:    time.Hour,
		RetentionBatch:    500,
		RetentionPasses:   40,
		ViolationLogLimit: 10,
	}
}

func (c ReconcileConfig) withDefaults() ReconcileConfig {
	d := DefaultReconcileConfig()
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.SafetyWindow <= 0 {
		c.SafetyWindow = d.SafetyWindow
	}
	if c.ReleasedRetention <= 0 {
		c.ReleasedRetention = d.ReleasedRetention
	}
	if c.RetentionEvery <= 0 {
		c.RetentionEvery = d.RetentionEvery
	}
	if c.RetentionBatch <= 0 {
		c.RetentionBatch = d.RetentionBatch
	}
	if c.RetentionPasses <= 0 {
		c.RetentionPasses = d.RetentionPasses
	}
	if c.ViolationLogLimit <= 0 {
		c.ViolationLogLimit = d.ViolationLogLimit
	}
	return c
}

// ReconcileWorker runs the §7.1 passes. Run owns one goroutine; Tick is
// safe for concurrent use in tests.
type ReconcileWorker struct {
	db    reservationDB
	store *ReservationStore
	log   *slog.Logger
	cfg   ReconcileConfig

	mu            sync.Mutex
	lastRetention time.Time
	nower         func() time.Time
}

// NewReconcileWorker builds the worker over a pool (or any reservationDB).
func NewReconcileWorker(db reservationDB, log *slog.Logger, cfg ReconcileConfig) *ReconcileWorker {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	return &ReconcileWorker{
		db:    db,
		store: NewReservationStoreWithConfig(db, log, DefaultReservationConfig()),
		log:   log.With("component", "budget-reconcile"),
		cfg:   cfg,
		nower: time.Now,
	}
}

// SetClock pins the clock (tests drive the retention cadence).
func (w *ReconcileWorker) SetClock(now func() time.Time) { w.nower = now }

// Run drives the worker until ctx is cancelled: one immediate pass, then
// the ticker. Ticker-driven — never a busy loop.
func (w *ReconcileWorker) Run(ctx context.Context) error {
	w.log.Info("budget reconcile worker started",
		"interval", w.cfg.Interval,
		"safety_window", w.cfg.SafetyWindow,
		"released_retention", w.cfg.ReleasedRetention,
		"retention_every", w.cfg.RetentionEvery,
	)
	w.Tick(ctx)
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.log.Info("budget reconcile worker stopping", "reason", ctx.Err().Error())
			return nil
		case <-ticker.C:
			w.Tick(ctx)
		}
	}
}

// Tick performs one bounded reconcile pass (§7.1). A failure in any step is
// logged and retried on the next tick — never fatal, never releasing
// half-verified state.
func (w *ReconcileWorker) Tick(ctx context.Context) {
	if _, err := w.ReleasePass(ctx); err != nil {
		w.log.Warn("reconcile release pass failed", "error", err)
	}
	if err := w.checkInvariants(ctx); err != nil {
		w.log.Warn("reconcile invariant check failed", "error", err)
	}
	if err := w.checkSettlementLag(ctx); err != nil {
		w.log.Warn("reconcile settlement lag check failed", "error", err)
	}
	w.retentionTick(ctx)
}

// ReleasePass runs §7.1.1/§7.1.2 and records the release-reason metrics.
func (w *ReconcileWorker) ReleasePass(ctx context.Context) (ReconcileSummary, error) {
	summary, err := w.store.ReconcileRelease(ctx, w.cfg.SafetyWindow)
	if err != nil {
		return summary, err
	}
	metrics.BudgetAllowanceReleasedTotal.WithLabelValues(ReleaseReasonExpiredSafety).
		Add(float64(summary.ExpiredSafetyReleased))
	metrics.BudgetAllowanceReleasedTotal.WithLabelValues(ReleaseReasonZeroRemainder).
		Add(float64(summary.ZeroRemainderReleased))
	if summary.Released > 0 {
		w.log.Info("reconcile released allowances",
			"released", summary.Released,
			"returned_micro_usd", summary.ReturnedMicroUSD,
			"expired_safety_window", summary.ExpiredSafetyReleased,
			"zero_remainder", summary.ZeroRemainderReleased,
		)
	}
	return summary, nil
}

// Release reasons (metric label values, ADR §7.1.1/§7.1.2).
const (
	ReleaseReasonExpiredSafety = "expired_safety_window"
	ReleaseReasonZeroRemainder = "zero_remainder"
	// ReleaseReasonCrashOrphan marks closures by an explicit
	// permanently-lost-replica verdict (CloseAbandonedReplica, N06-P05
	// crash reconciliation) as opposed to the passive §7.1.1 window: the
	// recovery path asserts the owner replica is gone for good and closes
	// its provably non-renewing rows. Distinct from expired_safety_window
	// so crash-recovery convergence ("no eternal reservations") is
	// observable per cause.
	ReleaseReasonCrashOrphan = "crash_orphan"
)

// scopeRowKey identifies one scope capacity row (kind + natural key).
type scopeRowKey struct {
	kind   ScopeKind
	key    string
	period string
}

// InvariantReport is the outcome of one §7.1.3/§7.1.4 pass.
type InvariantReport struct {
	// ReservedPerScope is the total reserved µUSD per scope kind (gauge
	// budget_reserved_micro_usd).
	ReservedPerScope map[ScopeKind]int64
	// DivergencePerScope is Σ|row divergence| per scope kind (§7.1.3).
	DivergencePerScope map[ScopeKind]int64
	// StrandedMicroUSD is capacity frozen by lapsed non-released
	// allowances (§12).
	StrandedMicroUSD int64
	// WalletHeadroomMin is the worst-case wallet headroom across orgs
	// (§7.1.4 LHS), MinInt64 when there are no wallets.
	WalletHeadroomMin int64
	// WalletViolatingOrgs lists orgs with negative headroom, capped at
	// ViolationLogLimit (logs carry identifiers, metrics may not — AF-16).
	// WalletViolationCount is the exact total, independent of the cap.
	WalletViolatingOrgs  []string
	WalletViolationCount int
}

// checkInvariants runs §7.1.3/§7.1.4, exports the gauges and logs the
// divergent rows (bounded).
func (w *ReconcileWorker) checkInvariants(ctx context.Context) error {
	report, err := w.CheckInvariants(ctx)
	if err != nil {
		return err
	}

	// Every canonical scope kind gets an explicit value (0 included), so a
	// cleared divergence actually drops the gauge instead of going stale.
	for _, kind := range []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
		metrics.BudgetReservedMicroUSD.WithLabelValues(string(kind)).
			Set(float64(report.ReservedPerScope[kind]))
		metrics.BudgetReservedDivergenceMicroUSD.WithLabelValues(string(kind)).
			Set(float64(report.DivergencePerScope[kind]))
		if v := report.DivergencePerScope[kind]; v > 0 {
			w.log.Warn("scope reserve invariant divergence detected (§7.1.3)",
				"scope_kind", string(kind), "divergence_micro_usd", v)
		}
	}
	metrics.BudgetStrandedMicroUSD.Set(float64(report.StrandedMicroUSD))
	if report.WalletHeadroomMin != math.MinInt64 {
		metrics.BudgetWalletHeadroomMicroUSD.Set(float64(report.WalletHeadroomMin))
	}
	metrics.BudgetWalletInvariantViolations.Set(float64(report.WalletViolationCount))
	for _, org := range report.WalletViolatingOrgs {
		w.log.Warn("wallet invariant violation (§7.1.4)", "org", org)
	}
	if report.WalletViolationCount > len(report.WalletViolatingOrgs) {
		w.log.Warn("wallet invariant violations truncated",
			"violations", report.WalletViolationCount, "logged", len(report.WalletViolatingOrgs))
	}
	return nil
}

// reservedRowQueries reads the non-zero reserves of every scope row. All
// four statements return (key, period, reserved) with the period rendered
// the same way the allowance rows carry it.
var reservedRowQueries = []struct {
	kind ScopeKind
	sql  string
}{
	{ScopeWallet, `SELECT org_id::text, '', reserved_micro_usd FROM org_credits WHERE reserved_micro_usd <> 0`},
	{ScopeTeamMonth, `SELECT team_id::text, period, reserved_micro_usd FROM team_spend_monthly WHERE reserved_micro_usd <> 0`},
	{ScopeAgentDay, `SELECT agent_id::text, day::text, reserved_micro_usd FROM agent_spend_daily WHERE reserved_micro_usd <> 0`},
	{ScopeSession, `SELECT session_key_id::text, '', reserved_micro_usd FROM session_spend WHERE reserved_micro_usd <> 0`},
}

// allowanceRemainderQuery aggregates the §7.1.3 remainder of every
// non-released allowance per scope row: granted − returned − Σ settled
// (the settle-decrement contract key of NEXT-18d, same as the 18a
// releaseOne math).
const allowanceRemainderQuery = `
	SELECT a.scope_kind, a.scope_key, a.period,
	       SUM(GREATEST(a.granted_micro_usd - a.returned_micro_usd - COALESCE(j.settled, 0), 0))
	FROM budget_allowances a
	LEFT JOIN (
		SELECT allowance_id,
		       SUM(CASE WHEN jsonb_typeof(payload) = 'object'
		                THEN COALESCE((payload->>$1)::bigint, 0)
		                ELSE 0 END) AS settled
		FROM settlement_jobs WHERE allowance_id IS NOT NULL
		GROUP BY allowance_id
	) j ON j.allowance_id = a.id
	WHERE a.status <> $2
	GROUP BY a.scope_kind, a.scope_key, a.period`

// strandedQuery sums the same remainder over non-released allowances whose
// lease already lapsed (§12 stranded capacity).
const strandedQuery = `
	SELECT COALESCE(SUM(GREATEST(a.granted_micro_usd - a.returned_micro_usd - COALESCE(j.settled, 0), 0)), 0)
	FROM budget_allowances a
	LEFT JOIN (
		SELECT allowance_id,
		       SUM(CASE WHEN jsonb_typeof(payload) = 'object'
		                THEN COALESCE((payload->>$1)::bigint, 0)
		                ELSE 0 END) AS settled
		FROM settlement_jobs WHERE allowance_id IS NOT NULL
		GROUP BY allowance_id
	) j ON j.allowance_id = a.id
	WHERE a.status <> $2 AND a.lease_until < now()`

// walletViolationQuery lists orgs with negative §7.1.4 headroom, worst
// first, bounded by the log limit.
const walletViolationQuery = `
	SELECT org_id::text,
	       balance_cents::bigint * 10000 - remainder_micro_usd
	         - COALESCE(grace_floor_cents, $1)::bigint * 10000
	         - reserved_micro_usd AS headroom_micro
	FROM org_credits
	WHERE balance_cents::bigint * 10000 - remainder_micro_usd
	        - COALESCE(grace_floor_cents, $1)::bigint * 10000
	        - reserved_micro_usd < 0
	ORDER BY headroom_micro
	LIMIT $2`

// walletViolationCountQuery is the exact §7.1.4 violator total — the gauge
// must not inherit the log list's cap.
const walletViolationCountQuery = `
	SELECT COUNT(*) FROM org_credits
	WHERE balance_cents::bigint * 10000 - remainder_micro_usd
	        - COALESCE(grace_floor_cents, $1)::bigint * 10000
	        - reserved_micro_usd < 0`

// walletHeadroomMinQuery is the worst-case headroom across all orgs (NULL
// when the table is empty).
const walletHeadroomMinQuery = `
	SELECT MIN(balance_cents::bigint * 10000 - remainder_micro_usd
	           - COALESCE(grace_floor_cents, $1)::bigint * 10000
	           - reserved_micro_usd)
	FROM org_credits`

// CheckInvariants computes the §7.1.3/§7.1.4 report. Read-only: it never
// mutates money — a divergence is an alarm condition for humans, and the
// conservative release path (releaseOne) re-checks everything under the
// advisory lock before it touches a reserve.
func (w *ReconcileWorker) CheckInvariants(ctx context.Context) (InvariantReport, error) {
	report := InvariantReport{
		ReservedPerScope:    map[ScopeKind]int64{},
		DivergencePerScope:  map[ScopeKind]int64{},
		WalletHeadroomMin:   math.MinInt64,
		WalletViolatingOrgs: []string{},
	}

	// Scope reserves per row (§7.1.3 side A).
	reserved := map[scopeRowKey]int64{}
	for _, q := range reservedRowQueries {
		rows, err := w.db.Query(ctx, q.sql)
		if err != nil {
			return report, err
		}
		for rows.Next() {
			var key, period string
			var value int64
			if err := rows.Scan(&key, &period, &value); err != nil {
				rows.Close()
				return report, err
			}
			reserved[scopeRowKey{q.kind, key, period}] = value
			report.ReservedPerScope[q.kind] += value
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return report, err
		}
		rows.Close()
	}

	// Allowance remainders per scope row (§7.1.3 side B).
	remainders := map[scopeRowKey]int64{}
	rows, err := w.db.Query(ctx, allowanceRemainderQuery, reconcileSettleKey, AllowanceReleased)
	if err != nil {
		return report, err
	}
	for rows.Next() {
		var kind, key, period string
		var value int64
		if err := rows.Scan(&kind, &key, &period, &value); err != nil {
			rows.Close()
			return report, err
		}
		k := scopeRowKey{ScopeKind(kind), key, period}
		remainders[k] = value
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return report, err
	}
	rows.Close()

	mergeDivergence(report.DivergencePerScope, reserved, remainders)

	if err := w.db.QueryRow(ctx, strandedQuery, reconcileSettleKey, AllowanceReleased).
		Scan(&report.StrandedMicroUSD); err != nil {
		return report, err
	}

	floor := w.store.cfg.DefaultGraceFloorCents
	var minHeadroom *int64
	if err := w.db.QueryRow(ctx, walletHeadroomMinQuery, floor).Scan(&minHeadroom); err != nil {
		return report, err
	}
	if minHeadroom != nil { // NULL = no wallets at all: keep the sentinel unset
		report.WalletHeadroomMin = *minHeadroom
	}
	var violationCount int64
	if err := w.db.QueryRow(ctx, walletViolationCountQuery, floor).Scan(&violationCount); err != nil {
		return report, err
	}
	report.WalletViolationCount = int(violationCount)
	vrows, err := w.db.Query(ctx, walletViolationQuery, floor, w.cfg.ViolationLogLimit)
	if err != nil {
		return report, err
	}
	defer vrows.Close()
	for vrows.Next() {
		var org string
		var headroom int64
		if err := vrows.Scan(&org, &headroom); err != nil {
			return report, err
		}
		report.WalletViolatingOrgs = append(report.WalletViolatingOrgs, org)
	}
	return report, vrows.Err()
}

// mergeDivergence folds the per-row §7.1.3 divergence into per-kind
// Σ|reserved − remainders|. Only non-zero divergences are recorded (a
// healthy kind stays absent). Pure — unit-tested against drift shapes.
func mergeDivergence(out map[ScopeKind]int64, reserved, remainders map[scopeRowKey]int64) {
	abs := func(v int64) int64 {
		if v < 0 {
			return -v
		}
		return v
	}
	add := func(kind ScopeKind, v int64) {
		if v != 0 {
			out[kind] += v
		}
	}
	for k, rv := range reserved {
		add(k.kind, abs(rv-remainders[k]))
	}
	for k, mv := range remainders {
		if _, ok := reserved[k]; !ok {
			add(k.kind, abs(mv))
		}
	}
}

// settlementLagQuery ages the oldest unsettled job (§5.4 alert input).
const settlementLagQuery = `
	SELECT COALESCE(EXTRACT(EPOCH FROM (now() - MIN(created_at))), 0)
	FROM settlement_jobs
	WHERE status IN ('pending', 'retry', 'processing')`

// checkSettlementLag exports settlement_lag_seconds (§5.4: alert > 30 min).
func (w *ReconcileWorker) checkSettlementLag(ctx context.Context) error {
	var seconds float64
	if err := w.db.QueryRow(ctx, settlementLagQuery).Scan(&seconds); err != nil {
		return err
	}
	metrics.SettlementLagSeconds.Set(seconds)
	return nil
}

// releasedRetentionDelete removes one bounded batch of terminal 'released'
// allowance rows past the retention window (§7.1.5), shaped after the
// AF-16/AF-06 settled-jobs retention: id-scoped, oldest first, LIMIT-bound.
// Only 'released' rows are removable — active/expired/draining rows freeze
// live capacity and are reconcile's input, never retention's.
const releasedRetentionDelete = `DELETE FROM budget_allowances WHERE id IN (
		SELECT id FROM budget_allowances
		WHERE status = $1 AND updated_at < now() - make_interval(secs => $2)
		ORDER BY updated_at, id
		LIMIT $3
	)`

// retentionTick runs the cadence-gated §7.1.5 retention.
func (w *ReconcileWorker) retentionTick(ctx context.Context) {
	w.mu.Lock()
	due := w.nower().Sub(w.lastRetention) >= w.cfg.RetentionEvery
	if due {
		w.lastRetention = w.nower()
	}
	w.mu.Unlock()
	if !due {
		return
	}
	deleted, err := w.RetentionPass(ctx)
	if err != nil {
		w.log.Warn("released allowance retention failed", "error", err)
		return
	}
	if deleted > 0 {
		w.log.Info("released allowance retention",
			"deleted", deleted,
			"retention", w.cfg.ReleasedRetention,
			"batch", w.cfg.RetentionBatch,
		)
	}
}

// RetentionPass deletes released allowances past the retention window in
// bounded batches and returns the total deleted (§7.1.5).
func (w *ReconcileWorker) RetentionPass(ctx context.Context) (int64, error) {
	var total int64
	for pass := 0; pass < w.cfg.RetentionPasses; pass++ {
		tag, err := w.db.Exec(ctx, releasedRetentionDelete,
			AllowanceReleased, int64(w.cfg.ReleasedRetention/time.Second), w.cfg.RetentionBatch)
		if err != nil {
			return total, err
		}
		n := tag.RowsAffected()
		total += n
		if n < w.cfg.RetentionBatch {
			return total, nil // window drained
		}
	}
	return total, nil
}
