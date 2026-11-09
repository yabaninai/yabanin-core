package budget

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
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

// Enforcer checks team budget limits in real-time.
// Uses DB for persistence and an in-memory cache for fast lookups.
type Enforcer struct {
	db    dbConn
	log   *slog.Logger
	cache map[string]*teamBudget
	mu    sync.RWMutex
	ttl   time.Duration
}

type teamBudget struct {
	monthlyLimitUSD float64
	// monthlyLimitMicroUSD is the limit converted to exact micro-USD once at
	// load time (ADR-0001 §13): the spend comparison runs on the exact
	// bigint accumulator, never on floats.
	monthlyLimitMicroUSD int64
	hardLimit            bool
	// absent marks a cached negative lookup (no budget row). It preserves the
	// ErrNoBudget signal across cache hits so a $0 zero-value entry is never
	// mistaken for a real budget.
	absent   bool
	cachedAt time.Time
}

// NewEnforcer creates a budget enforcer backed by the database.
// Accepts any type implementing dbConn (e.g., *pgxpool.Pool).
func NewEnforcer(db dbConn, log *slog.Logger) *Enforcer {
	return &Enforcer{
		db:    db,
		log:   log.With("component", "budget-enforcer"),
		cache: make(map[string]*teamBudget),
		ttl:   1 * time.Minute,
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

	budget, err := e.getBudget(ctx, teamID)
	if err != nil {
		if errors.Is(err, ErrNoBudget) {
			return ErrNoBudget
		}
		e.log.Warn("budget lookup unavailable, denying request", "team_id", teamID, "error", err)
		return fmt.Errorf("%w: %v", ErrBudgetUnavailable, err)
	}

	spendMicro, err := e.getSpendThisMonthMicro(ctx, teamID)
	if err != nil {
		e.log.Warn("budget spend lookup unavailable, denying request", "team_id", teamID, "error", err)
		return fmt.Errorf("%w: %v", ErrBudgetUnavailable, err)
	}

	if spendMicro >= budget.monthlyLimitMicroUSD {
		if budget.hardLimit {
			return fmt.Errorf("%w: spent $%.2f of $%.2f limit",
				ErrBudgetExceeded,
				float64(spendMicro)/float64(money.MicroPerUSD),
				budget.monthlyLimitUSD)
		}
		e.log.Warn("team budget soft limit exceeded",
			"team_id", teamID,
			"spend_micro_usd", spendMicro,
			"limit", budget.monthlyLimitUSD,
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

func (e *Enforcer) getBudget(ctx context.Context, teamID string) (*teamBudget, error) {
	// Fast path: a fresh entry answers under the read lock, so concurrent
	// checks of DIFFERENT teams never contend on the writer.
	e.mu.RLock()
	if b, ok := e.cache[teamID]; ok && time.Since(b.cachedAt) < e.ttl {
		e.mu.RUnlock()
		return e.budgetFromCache(b)
	}
	e.mu.RUnlock()

	// Miss: the DB query runs OUTSIDE every lock (pattern: credits.Store.
	// GetBalance) — the write lock below guards only the cache write, so a
	// slow budget read for one team never serializes every other tenant.
	// Concurrent misses for the same team may each query; the row is
	// identical, so the last write wins without any caller observing a
	// torn entry.
	var monthlyLimit float64
	var hardLimit bool
	err := e.db.QueryRow(ctx,
		`SELECT monthly_limit_usd, hard_limit FROM team_budgets WHERE team_id = $1`,
		teamID,
	).Scan(&monthlyLimit, &hardLimit)

	b := &teamBudget{cachedAt: time.Now()}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Cache the absence — no budget configured for this team.
			b.absent = true
			e.mu.Lock()
			e.cache[teamID] = b
			e.mu.Unlock()
			return nil, ErrNoBudget
		}
		return nil, err
	}

	b.monthlyLimitUSD = monthlyLimit
	b.monthlyLimitMicroUSD = int64(math.Round(monthlyLimit * float64(money.MicroPerUSD)))
	b.hardLimit = hardLimit
	e.mu.Lock()
	e.cache[teamID] = b
	e.mu.Unlock()
	return b, nil
}

// budgetFromCache unwraps a cached entry. A cached negative lookup (absent) is
// reported as ErrNoBudget so the caller keeps denying until the cache expires;
// a real entry is returned as a usable budget.
func (e *Enforcer) budgetFromCache(b *teamBudget) (*teamBudget, error) {
	if b.absent {
		return nil, ErrNoBudget
	}
	return b, nil
}

// getSpendThisMonthMicro reads the exact micro-USD accumulator for the
// column written by the settlement worker, never on the spend_usd
// compatibility projection. No row → zero spend for the period.
func (e *Enforcer) getSpendThisMonthMicro(ctx context.Context, teamID string) (int64, error) {
	period := time.Now().UTC().Format("2006-01")

	var spend int64
	err := e.db.QueryRow(ctx,
		`SELECT COALESCE(spend_micro_usd, 0) FROM team_spend_monthly WHERE team_id = $1 AND period = $2`,
		teamID, period,
	).Scan(&spend)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return spend, nil
}

// ClearCache invalidates cached budget for a team (called after budget updates).
func (e *Enforcer) ClearCache(teamID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.cache, teamID)
}
