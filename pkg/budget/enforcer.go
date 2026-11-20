package budget

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
)

// Sentinel errors returned by CheckBudget. Callers (the gateway) map them to
// distinct HTTP statuses so clients can tell "no budget configured" (403) and
// "budget store unavailable" (503) apart from "limit exceeded" (429).
var (
	// ErrNoBudget indicates no budget row is configured for the team.
	ErrNoBudget = errors.New("no budget configured")
	// ErrBudgetExceeded indicates the team's hard monthly limit was reached.
	ErrBudgetExceeded = errors.New("team budget exceeded")
	// ErrBudgetUnavailable indicates the budget store could not be queried
	// (e.g. Postgres degraded). The enforcer fails closed: it denies rather than
	// allow unbounded spend during a datastore outage.
	ErrBudgetUnavailable = errors.New("budget check unavailable")
)

// dbConn is the minimal database interface used by the enforcer.
// pgxpool.Pool implements this interface, allowing injection of test doubles.
type dbConn interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error)
}

// Enforcer checks team budget limits in real-time against the AUTHORITATIVE
// database state: one snapshot query per check returns the team's current
// finite limit together with the current month's exact spend, so a committed
// budget write (PUT/DELETE /api/teams/{id}/budget) is visible to the very
// next request.
//
// There is deliberately NO in-memory limit/absence cache. The previous
// 1-minute TTL cache served a stale cached absence after a first budget was
// configured (the immediate 403 after an authorized PUT) and, symmetrically,
// could serve a stale limit after a change/delete; a cached row is not proof
// of the current cap. Caching the limit also saved no round trips: the exact
// monthly spend — same team, same request — was already read from
// team_spend_monthly on EVERY permitted request. Folding both into one
// snapshot keeps the per-check round-trip count at exactly one, needs no
// cross-process invalidation channel between the admin API and the gateway
// (separate processes in production), and degrades fail-closed: any read
// failure denies (ErrBudgetUnavailable) instead of serving a last-known
// limit.
type Enforcer struct {
	db  dbConn
	log *slog.Logger
}

// teamBudgetSnapshot is ONE authoritative read of a team's budget state.
type teamBudgetSnapshot struct {
	monthlyLimitUSD float64
	// monthlyLimitMicroUSD is the limit converted to exact micro-USD once
	// per snapshot (ADR-0001 §13): the spend comparison runs on the exact
	// bigint accumulator, never on floats.
	monthlyLimitMicroUSD int64
	hardLimit            bool
	// spendMicroUSD is the month's exact micro-USD accumulator; a missing
	// team_spend_monthly row reads as zero spend.
	spendMicroUSD int64
}

// NewEnforcer creates a budget enforcer backed by the database.
// Accepts any type implementing dbConn (e.g., *pgxpool.Pool).
func NewEnforcer(db dbConn, log *slog.Logger) *Enforcer {
	return &Enforcer{
		db:  db,
		log: log.With("component", "budget-enforcer"),
	}
}

// CheckBudget verifies whether a team can make a request given its current spend.
//
// Semantics (fail-safe for a prepaid product):
//   - No team identity, or no datastore configured → allow. Identity is the auth
//     middleware's responsibility; a nil store means budget was not wired for
//     this deployment.
//   - No budget row (ErrNoBudget) → deny. A team without a configured budget may
//     not spend; configure a row to enable it.
//   - Datastore error → deny (ErrBudgetUnavailable). Never allow unbounded spend
//     during a Postgres outage.
//   - Hard limit exceeded → deny (ErrBudgetExceeded).
//   - Soft limit exceeded → allow (warn only).
func (e *Enforcer) CheckBudget(ctx context.Context, teamID string) error {
	if teamID == "" || e.db == nil {
		return nil
	}

	snap, err := e.getBudgetSnapshot(ctx, teamID)
	if err != nil {
		if errors.Is(err, ErrNoBudget) {
			return ErrNoBudget
		}
		e.log.Warn("budget lookup unavailable, denying request", "team_id", teamID, "error", err)
		return fmt.Errorf("%w: %v", ErrBudgetUnavailable, err)
	}

	if snap.spendMicroUSD >= snap.monthlyLimitMicroUSD {
		if snap.hardLimit {
			return fmt.Errorf("%w: spent $%.2f of $%.2f limit",
				ErrBudgetExceeded,
				float64(snap.spendMicroUSD)/float64(money.MicroPerUSD),
				snap.monthlyLimitUSD)
		}
		e.log.Warn("team budget soft limit exceeded",
			"team_id", teamID,
			"spend_micro_usd", snap.spendMicroUSD,
			"limit", snap.monthlyLimitUSD,
		)
	}

	return nil
}

// RecordTeamSpendExact applies an exact micro-USD team spend for one budget
// team_spend side effect). It replaces the legacy RecordSpend float path
// (ADR-0001 F7: that writer had no working-code callers and was not
// idempotent) — this exact path is the ONLY writer of team spend rows.
//
//   - amount is applied verbatim to the durable spend_micro_usd accumulator
//     (AF-05 contract): no per-event cent rounding is re-derived from floats.
//     The spend_usd column keeps its rounded compatibility projection.
//   - period ("2006-01", UTC) is supplied by the caller and is fixed by the
//     request time (ADR I5), not by the — possibly much later — settle time.
//   - Idempotency comes from the caller: the spend and the settlement-job
//     transition to 'settled' commit in ONE transaction, so a retry after a
//     crash re-executes from a job that never settled — the spend is never
//     added twice for one job.
func RecordTeamSpendExact(ctx context.Context, db SpendExecutor, teamID, period string, amount money.MicroUSD) error {
	if teamID == "" || period == "" || db == nil {
		return nil
	}
	if amount < 0 {
		amount = 0
	}

	_, err := db.Exec(ctx,
		`INSERT INTO team_spend_monthly (team_id, period, spend_usd, spend_micro_usd, request_count)
		 VALUES ($1, $2, $3::bigint / 1000000.0, $3, 1)
		 ON CONFLICT (team_id, period)
		 DO UPDATE SET spend_usd       = team_spend_monthly.spend_usd + ($3::bigint / 1000000.0),
		               spend_micro_usd = team_spend_monthly.spend_micro_usd + $3,
		               request_count   = team_spend_monthly.request_count + 1`,
		teamID, period, int64(amount),
	)
	if err != nil {
		return fmt.Errorf("record exact team spend: %w", err)
	}
	return nil
}

// getBudgetSnapshot reads the team's current finite limit and the current
// month's exact spend in ONE round trip (both sides are primary-key probes:
// team_budgets by team_id, team_spend_monthly by (team_id, period)).
//
//   - no team_budgets row → pgx.ErrNoRows → ErrNoBudget (fail-closed denial,
//     the same signal the gateway maps to 403 budget_not_configured);
//   - no team_spend_monthly row → COALESCE reads as zero spend;
//   - any read failure → returned verbatim and mapped by CheckBudget to
//     ErrBudgetUnavailable: a freshness failure is a denial, never a
//     last-known cached limit.
func (e *Enforcer) getBudgetSnapshot(ctx context.Context, teamID string) (*teamBudgetSnapshot, error) {
	period := time.Now().UTC().Format("2006-01")

	var monthlyLimit float64
	var hardLimit bool
	var spendMicro int64
	err := e.db.QueryRow(ctx,
		`SELECT b.monthly_limit_usd,
		        b.hard_limit,
		        COALESCE(s.spend_micro_usd, 0)
		   FROM team_budgets b
		   LEFT JOIN team_spend_monthly s
		          ON s.team_id = b.team_id
		         AND s.period  = $2
		  WHERE b.team_id = $1`,
		teamID, period,
	).Scan(&monthlyLimit, &hardLimit, &spendMicro)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoBudget
	}
	if err != nil {
		return nil, err
	}

	return &teamBudgetSnapshot{
		monthlyLimitUSD:      monthlyLimit,
		monthlyLimitMicroUSD: int64(math.Round(monthlyLimit * float64(money.MicroPerUSD))),
		hardLimit:            hardLimit,
		spendMicroUSD:        spendMicro,
	}, nil
}

// ClearCache is retained for Go source compatibility with existing callers.
// It is a deliberate no-op: every CheckBudget reads the authoritative
// limit+spend snapshot, so there is no cached state left to invalidate.
func (e *Enforcer) ClearCache(teamID string) {}
