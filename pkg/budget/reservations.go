// Package budget: reservation store primitives (NEXT-18a, ADR-0001 rev. 3
// §5.3/§13/§14). Durable per-replica escrow allocations ("allowances") keep
// the admission invariant reserved + Δ ≤ L for every hard money scope under
// concurrent load: a replica pre-reserves a slice of each scope's capacity
// in Postgres and admits locally from that slice.
//
// The store is authority-adjacent money code: every mutation runs in ONE
// transaction under the same per-org advisory lock the settlement path uses
// (pg_advisory_xact_lock(hashtext(org))), with rows locked FOR UPDATE in the
// fixed scope order wallet → team_month → agent_day → session, so grant /
// return / settle-decrement / reconcile can never deadlock among themselves
// or with DeductMicro. Capacities L(S) come from the same rows settlement
// already writes (ADR §4.1); limits are converted to exact micro-USD in SQL.
package budget

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
)

// ScopeKind names a limit area (ADR §4.1). The constants below are declared
// in the canonical transaction lock order.
type ScopeKind string

// Scope constants for the four §4.1 limit areas.
const (
	ScopeWallet    ScopeKind = "wallet"
	ScopeTeamMonth ScopeKind = "team_month"
	ScopeAgentDay  ScopeKind = "agent_day"
	ScopeSession   ScopeKind = "session"
)

// Allowance statuses (ADR §5.2/§13).
const (
	AllowanceActive   = "active"
	AllowanceExpired  = "expired"
	AllowanceDraining = "draining"
	AllowanceReleased = "released"
)

// ReservationSafetyWindow is how long past lease expiry an allowance may
// keep freezing capacity before reconcile releases it (ADR §14, D13).
const ReservationSafetyWindow = 2 * time.Hour

// ReservationConfig carries the §14 escrow parameters. Zero/negative fields
// fall back to the §14 defaults via DefaultReservationConfig.
type ReservationConfig struct {
	// TTL is the allowance lease lifetime; replicas renew every 60 s.
	TTL time.Duration
	// EscrowHorizon sizes one grant: rate × horizon µUSD of predicted spend.
	EscrowHorizon time.Duration
	// EscrowMaxFraction caps a grant at this fraction of the scope's free
	// capacity (capital-freeze containment after a replica dies).
	EscrowMaxFraction float64
	// EscrowLowWaterBounds: when free capacity < this many average bounds,
	// grants degrade to exactly one request bound (stranded-capacity guard).
	EscrowLowWaterBounds int64
	// DefaultGraceFloorCents is the wallet floor used when the org has no
	// explicit grace_floor_cents (the global GracePeriodCents default, §8).
	DefaultGraceFloorCents int64
}

// DefaultReservationConfig returns the §14 defaults.
func DefaultReservationConfig() ReservationConfig {
	return ReservationConfig{
		TTL:                    10 * time.Minute,
		EscrowHorizon:          5 * time.Second,
		EscrowMaxFraction:      0.1,
		EscrowLowWaterBounds:   20,
		DefaultGraceFloorCents: -100, // -$1.00, credits.DefaultConfig
	}
}

func (c ReservationConfig) withDefaults() ReservationConfig {
	def := DefaultReservationConfig()
	if c.TTL <= 0 {
		c.TTL = def.TTL
	}
	if c.EscrowHorizon <= 0 {
		c.EscrowHorizon = def.EscrowHorizon
	}
	if c.EscrowMaxFraction <= 0 || c.EscrowMaxFraction > 1 {
		c.EscrowMaxFraction = def.EscrowMaxFraction
	}
	if c.EscrowLowWaterBounds <= 0 {
		c.EscrowLowWaterBounds = def.EscrowLowWaterBounds
	}
	return c
}

// Sentinel errors. Callers map them to HTTP: ErrInsufficientCapacity →
// 402/429 limit exceeded, ErrNoCapacitySource → fail-closed denial (D14),
// the rest are internal invariants.
var (
	// ErrInsufficientCapacity: the scope's free capacity cannot cover the
	// request bound — the whole grant is refused (§4.2).
	ErrInsufficientCapacity = errors.New("reservation: insufficient capacity")
	// ErrNoCapacitySource: the limit/wallet row backing a requested hard
	// scope is missing (no budget row, no wallet, no key limit). Fail-closed.
	ErrNoCapacitySource = errors.New("reservation: capacity source missing")
	// ErrAllowanceNotFound: no allowance row for the given identity.
	ErrAllowanceNotFound = errors.New("reservation: allowance not found")
	// ErrAllowanceReleased: the allowance is released; its reserve is gone.
	ErrAllowanceReleased = errors.New("reservation: allowance already released")
	// ErrAllowanceUnderflow: a return exceeds granted − returned.
	ErrAllowanceUnderflow = errors.New("reservation: return exceeds allowance available")
	// ErrReservedUnderflow: the scope row's reserve is smaller than the
	// amount being released — invariant drift (§7.1.3), never silently clamped.
	ErrReservedUnderflow = errors.New("reservation: scope reserve underflow")
	// ErrInvalidRequest: malformed grant (empty, unknown scope, duplicates).
	ErrInvalidRequest = errors.New("reservation: invalid request")
)

// reservationDB is the store's surface (*pgxpool.Pool in production).
// QueryRow backs the admission layer's read-only pre-check probes
// (NEXT-18c); Begin/Exec/Query cover the write primitives.
type reservationDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

// ReservationStore implements the §5.3 store primitives.
type ReservationStore struct {
	db  reservationDB
	log *slog.Logger
	cfg ReservationConfig
}

// NewReservationStore builds a store with §14 defaults.
func NewReservationStore(db *pgxpool.Pool, log *slog.Logger) *ReservationStore {
	return NewReservationStoreWithConfig(db, log, DefaultReservationConfig())
}

// NewReservationStoreWithConfig builds a store with explicit parameters
// (tests, shadow-phase tuning).
func NewReservationStoreWithConfig(db reservationDB, log *slog.Logger, cfg ReservationConfig) *ReservationStore {
	if log == nil {
		log = slog.Default()
	}
	return &ReservationStore{
		db:  db,
		log: log.With("component", "budget-reservations"),
		cfg: cfg.withDefaults(),
	}
}

// GrantRequest asks for capacity in one scope. Bound is the request's cost
// estimate (§4.3); RatePerSecond is the replica's observed spend rate for
// the scope (0 → escrow degenerates to per-request reserves); AvgBound is
// the replica's rolling average bound (0 → Bound is used).
type GrantRequest struct {
	Scope         ScopeKind
	Key           string
	Period        string
	Bound         money.MicroUSD
	RatePerSecond money.MicroUSD
	AvgBound      money.MicroUSD
}

// ScopeGrant reports one applied scope increment.
type ScopeGrant struct {
	Scope       ScopeKind
	Key         string
	Period      string
	AllowanceID int64
	Delta       money.MicroUSD
}

// Grant reserves capacity for every requested scope in ONE transaction
// (ADR §5.3): per-org advisory lock, rows locked FOR UPDATE in the fixed
// scope order, Δ = clamp(rate×EscrowHorizon, bound, EscrowMaxFraction×free)
// — exactly bound near exhaustion. Refusal of any scope rolls back all of
// them (a multi-scope request is admitted only as a whole). On success each
// scope's allowance row is created or extended and its lease renewed.
func (s *ReservationStore) Grant(ctx context.Context, replicaID, orgID string, reqs []GrantRequest) ([]ScopeGrant, error) {
	if replicaID == "" || orgID == "" {
		return nil, fmt.Errorf("%w: replica_id and org_id are required", ErrInvalidRequest)
	}
	if len(reqs) == 0 {
		return nil, fmt.Errorf("%w: no scopes requested", ErrInvalidRequest)
	}
	ordered, err := sortGrantRequests(reqs)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("grant begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize money writers per org — same lock key as DeductMicro.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return nil, fmt.Errorf("grant advisory lock: %w", err)
	}

	grants := make([]ScopeGrant, 0, len(ordered))
	for _, req := range ordered {
		g, err := s.grantScope(ctx, tx, replicaID, orgID, req)
		if err != nil {
			return nil, err // deferred rollback undoes every earlier scope
		}
		grants = append(grants, g)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("grant commit: %w", err)
	}
	return grants, nil
}

// grantScope applies one scope inside the caller's transaction: read the
// capacity row FOR UPDATE, compute Δ, guard the reserve update with the
// capacity predicate, then create/extend the allowance.
func (s *ReservationStore) grantScope(ctx context.Context, tx pgx.Tx, replicaID, orgID string, req GrantRequest) (ScopeGrant, error) {
	if req.Bound < 0 {
		return ScopeGrant{}, fmt.Errorf("%w: negative bound %d", ErrInvalidRequest, req.Bound)
	}

	free, unlimited, err := s.scopeFreeCapacity(ctx, tx, orgID, req)
	if err != nil {
		return ScopeGrant{}, err
	}

	delta, err := grantDelta(int64(free), int64(req.Bound), int64(req.RatePerSecond), int64(req.AvgBound), unlimited, s.cfg)
	if err != nil {
		return ScopeGrant{}, fmt.Errorf("%w: scope %s key %s: %v", ErrInsufficientCapacity, req.Scope, req.Key, err)
	}

	if err := s.applyReserve(ctx, tx, orgID, req, delta, free, unlimited); err != nil {
		return ScopeGrant{}, err
	}

	allowanceID, _, err := upsertAllowance(ctx, tx, replicaID, orgID, req, int64(delta), s.cfg.TTL)
	if err != nil {
		return ScopeGrant{}, err
	}
	return ScopeGrant{Scope: req.Scope, Key: req.Key, Period: req.Period, AllowanceID: allowanceID, Delta: money.MicroUSD(delta)}, nil
}

// scopeFreeCapacity returns L(S) − reserved(S) in µUSD. unlimited is true
// only for advisory scopes (soft team budgets, ADR I6): accounting still
// happens, capacity is not enforced.
func (s *ReservationStore) scopeFreeCapacity(ctx context.Context, tx pgx.Tx, orgID string, req GrantRequest) (int64, bool, error) {
	switch req.Scope {
	case ScopeWallet:
		// Same row DeductMicro locks; floor per org or global default (§8).
		var balanceCents, remainder, reserved int64
		var floor *int64
		err := tx.QueryRow(ctx,
			`SELECT balance_cents, remainder_micro_usd, grace_floor_cents, reserved_micro_usd
			 FROM org_credits WHERE org_id = $1 FOR UPDATE`,
			orgID).Scan(&balanceCents, &remainder, &floor, &reserved)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, fmt.Errorf("%w: no wallet for org", ErrNoCapacitySource)
		}
		if err != nil {
			return 0, false, fmt.Errorf("grant wallet read: %w", err)
		}
		floorCents := s.cfg.DefaultGraceFloorCents
		if floor != nil {
			floorCents = *floor
		}
		balanceMicro, err := centsToMicro(balanceCents)
		if err != nil {
			return 0, false, fmt.Errorf("grant wallet capacity: %w", err)
		}
		floorMicro, err := centsToMicro(floorCents)
		if err != nil {
			return 0, false, fmt.Errorf("grant wallet floor: %w", err)
		}
		return balanceMicro - remainder - floorMicro - reserved, false, nil

	case ScopeTeamMonth:
		var limitMicro int64
		var hardLimit bool
		err := tx.QueryRow(ctx,
			`SELECT (monthly_limit_usd * 1000000)::bigint, hard_limit
			 FROM team_budgets WHERE team_id = $1::uuid`,
			req.Key).Scan(&limitMicro, &hardLimit)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, fmt.Errorf("%w: no team budget for %s", ErrNoCapacitySource, req.Key)
		}
		if err != nil {
			return 0, false, fmt.Errorf("grant team read: %w", err)
		}
		if !hardLimit {
			// Advisory scope (I6): accounting continues, capacity is not
			// enforced. The period row still exists so the reserve has a
			// home; the MaxInt64 sentinel keeps every clamp inert.
			if _, err := tx.Exec(ctx,
				`INSERT INTO team_spend_monthly (team_id, period) VALUES ($1::uuid, $2)
				 ON CONFLICT (team_id, period) DO NOTHING`,
				req.Key, req.Period); err != nil {
				return 0, false, fmt.Errorf("grant team upsert period: %w", err)
			}
			return math.MaxInt64, true, nil
		}
		// Upsert the period row, then lock it (§5.3).
		if _, err := tx.Exec(ctx,
			`INSERT INTO team_spend_monthly (team_id, period) VALUES ($1::uuid, $2)
			 ON CONFLICT (team_id, period) DO NOTHING`,
			req.Key, req.Period); err != nil {
			return 0, false, fmt.Errorf("grant team upsert period: %w", err)
		}
		var spendMicro, reserved int64
		if err := tx.QueryRow(ctx,
			`SELECT spend_micro_usd, reserved_micro_usd FROM team_spend_monthly
			 WHERE team_id = $1::uuid AND period = $2 FOR UPDATE`,
			req.Key, req.Period).Scan(&spendMicro, &reserved); err != nil {
			return 0, false, fmt.Errorf("grant team period read: %w", err)
		}
		return limitMicro - spendMicro - reserved, false, nil

	case ScopeAgentDay:
		var limitCents int64
		err := tx.QueryRow(ctx,
			`SELECT daily_limit_cents FROM agent_budgets WHERE agent_id = $1::uuid`,
			req.Key).Scan(&limitCents)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, fmt.Errorf("%w: no agent budget for %s", ErrNoCapacitySource, req.Key)
		}
		if err != nil {
			return 0, false, fmt.Errorf("grant agent read: %w", err)
		}
		limitMicro, err := centsToMicro(limitCents)
		if err != nil {
			return 0, false, fmt.Errorf("grant agent capacity: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO agent_spend_daily (agent_id, day) VALUES ($1::uuid, $2::date)
			 ON CONFLICT (agent_id, day) DO NOTHING`,
			req.Key, req.Period); err != nil {
			return 0, false, fmt.Errorf("grant agent upsert day: %w", err)
		}
		var costMicro, reserved int64
		if err := tx.QueryRow(ctx,
			`SELECT cost_micro_usd, reserved_micro_usd FROM agent_spend_daily
			 WHERE agent_id = $1::uuid AND day = $2::date FOR UPDATE`,
			req.Key, req.Period).Scan(&costMicro, &reserved); err != nil {
			return 0, false, fmt.Errorf("grant agent day read: %w", err)
		}
		ownFree := limitMicro - costMicro - reserved
		// AUDIT-P1-03: a delegated child's capacity is additionally bounded
		// by its parent's remaining headroom (subtree cost + reserved against
		// the parent cap). A root key (or a synthetic id without an
		// agent_keys row) has no ancestor and keeps the own-only bound.
		parentFree, hasParent, err := agentAncestorFreeMicro(ctx, tx, req.Key, req.Period)
		if err != nil {
			return 0, false, err
		}
		if hasParent && parentFree < ownFree {
			return parentFree, false, nil
		}
		return ownFree, false, nil

	case ScopeSession:
		var limitMicro *int64
		err := tx.QueryRow(ctx,
			`SELECT (max_cost_usd * 1000000)::bigint FROM session_keys WHERE id = $1::uuid`,
			req.Key).Scan(&limitMicro)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, fmt.Errorf("%w: no session key %s", ErrNoCapacitySource, req.Key)
		}
		if err != nil {
			return 0, false, fmt.Errorf("grant session read: %w", err)
		}
		if limitMicro == nil {
			// A session scope was requested but the key has no money cap:
			// misconfiguration — refuse (D14 fail-closed), never unlimited.
			return 0, false, fmt.Errorf("%w: session key %s has no max_cost_usd", ErrNoCapacitySource, req.Key)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO session_spend (session_key_id) VALUES ($1::uuid)
			 ON CONFLICT (session_key_id) DO NOTHING`,
			req.Key); err != nil {
			return 0, false, fmt.Errorf("grant session upsert: %w", err)
		}
		var spentMicro, reserved int64
		if err := tx.QueryRow(ctx,
			`SELECT spent_micro_usd, reserved_micro_usd FROM session_spend
			 WHERE session_key_id = $1::uuid FOR UPDATE`,
			req.Key).Scan(&spentMicro, &reserved); err != nil {
			return 0, false, fmt.Errorf("grant session spend read: %w", err)
		}
		return *limitMicro - spentMicro - reserved, false, nil

	default:
		return 0, false, fmt.Errorf("%w: unknown scope kind %q", ErrInvalidRequest, req.Scope)
	}
}

// queryRower is the read-row surface shared by pgx.Tx and pgxpool.Pool, so
// the ancestor-capacity helper reads identically inside grant transactions
// and from the admission probe (grant and probe must never drift).
type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// agentAncestorFreeMicro reports the remaining headroom (µUSD) of the
// parent budget for agent key `key`: parent daily limit minus the parent's
// subtree usage (own cost/reserved plus every direct child's, for the day).
// hasParent is false for root keys and synthetic ids without an agent_keys
// row — no ancestor bound applies. A parent whose budget row is missing is
// corruption (AUDIT-P1-03 invariant): the caller refuses with
// ErrNoCapacitySource instead of granting unbounded money.
func agentAncestorFreeMicro(ctx context.Context, q queryRower, key, period string) (int64, bool, error) {
	var parent *string
	err := q.QueryRow(ctx,
		`SELECT parent_id::text FROM agent_keys WHERE id = $1::uuid`,
		key,
	).Scan(&parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil // no key row: synthetic agent id, no ancestor
	}
	if err != nil {
		return 0, false, fmt.Errorf("grant agent parent read: %w", err)
	}
	if parent == nil {
		return 0, false, nil // root key
	}

	var limitCents int64
	err = q.QueryRow(ctx,
		`SELECT daily_limit_cents FROM agent_budgets WHERE agent_id = $1::uuid`,
		*parent,
	).Scan(&limitCents)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, fmt.Errorf("%w: parent agent %s has no budget", ErrNoCapacitySource, *parent)
	}
	if err != nil {
		return 0, false, fmt.Errorf("grant agent parent budget read: %w", err)
	}
	limitMicro, err := centsToMicro(limitCents)
	if err != nil {
		return 0, false, fmt.Errorf("grant agent parent capacity: %w", err)
	}

	var usedMicro int64
	err = q.QueryRow(ctx, `
		SELECT COALESCE(SUM(s.cost_micro_usd + s.reserved_micro_usd), 0)
		FROM agent_keys k
		LEFT JOIN agent_spend_daily s ON s.agent_id = k.id AND s.day = $2::date
		WHERE k.id = $1::uuid OR k.parent_id = $1::uuid`,
		*parent, period,
	).Scan(&usedMicro)
	if err != nil {
		return 0, false, fmt.Errorf("grant agent subtree read: %w", err)
	}
	return limitMicro - usedMicro, true, nil
}

// applyReserve increments the scope row's reserve. The WHERE capacity
// predicate re-checks the invariant in SQL (defense in depth: the row is
// already locked and the advisory lock held, so this never fails silently).
// Advisory scopes (unlimited) keep the accounting without the capacity
// predicate.
func (s *ReservationStore) applyReserve(ctx context.Context, tx pgx.Tx, orgID string, req GrantRequest, delta int64, free int64, unlimited bool) error {
	var (
		tag pgconn.CommandTag
		err error
	)
	switch req.Scope {
	case ScopeWallet:
		tag, err = tx.Exec(ctx,
			`UPDATE org_credits SET
				reserved_micro_usd = reserved_micro_usd + $2,
				updated_at = now()
			 WHERE org_id = $1
			   AND reserved_micro_usd + $2 <= balance_cents::bigint * 10000
			                          - remainder_micro_usd
			                          - COALESCE(grace_floor_cents, $3)::bigint * 10000`,
			orgID, delta, s.cfg.DefaultGraceFloorCents)

	case ScopeTeamMonth:
		if unlimited { // advisory scope: no capacity guard
			tag, err = tx.Exec(ctx,
				`UPDATE team_spend_monthly SET reserved_micro_usd = reserved_micro_usd + $3
				 WHERE team_id = $1::uuid AND period = $2`,
				req.Key, req.Period, delta)
		} else {
			tag, err = tx.Exec(ctx,
				`UPDATE team_spend_monthly SET reserved_micro_usd = reserved_micro_usd + $3
				 WHERE team_id = $1::uuid AND period = $2
				   AND reserved_micro_usd + $3 <= (SELECT (monthly_limit_usd * 1000000)::bigint
				                                   FROM team_budgets WHERE team_id = $1::uuid)
				                                   - spend_micro_usd`,
				req.Key, req.Period, delta)
		}

	case ScopeAgentDay:
		// AUDIT-P1-03: the ancestor clause mirrors the grant-side bound.
		// Invariant: the parent's committed subtree after this grant —
		// Σ(cost+reserved over the parent's own day row and every child
		// row, which already includes THIS child's current reserve) plus
		// delta — must stay within the parent cap, so only the delta is
		// checked against the remaining headroom. Limit and SUM live in
		// separate subqueries (an aggregate cannot mix a bare column with
		// SUM — the SQL contract test caught exactly that). The IS NULL
		// disjunct keeps ROOT keys unaffected (parent_id NULL would
		// otherwise make the scalar subqueries NULL and silently filter
		// the row out); for a child whose parent budget row went missing
		// the subquery is NULL → the row is excluded → the grant is
		// refused (fail-closed defense in depth on top of the grant-side
		// check).
		tag, err = tx.Exec(ctx,
			`UPDATE agent_spend_daily SET reserved_micro_usd = reserved_micro_usd + $3
			 WHERE agent_id = $1::uuid AND day = $2::date
			   AND reserved_micro_usd + $3 <= (SELECT daily_limit_cents::bigint * 10000
			                                   FROM agent_budgets WHERE agent_id = $1::uuid)
			                                   - cost_micro_usd
			   AND (
			     (SELECT parent_id FROM agent_keys WHERE id = $1::uuid) IS NULL
			     OR $3 <= (
			          (SELECT daily_limit_cents::bigint * 10000 FROM agent_budgets
			            WHERE agent_id = (SELECT parent_id FROM agent_keys WHERE id = $1::uuid))
			          - COALESCE((
			              SELECT SUM(s.cost_micro_usd + s.reserved_micro_usd)
			              FROM agent_keys k
			              LEFT JOIN agent_spend_daily s ON s.agent_id = k.id AND s.day = $2::date
			              WHERE k.id    = (SELECT parent_id FROM agent_keys WHERE id = $1::uuid)
			                 OR k.parent_id = (SELECT parent_id FROM agent_keys WHERE id = $1::uuid)), 0)
			     )
			   )`,
			req.Key, req.Period, delta)

	case ScopeSession:
		tag, err = tx.Exec(ctx,
			`UPDATE session_spend SET reserved_micro_usd = reserved_micro_usd + $2, updated_at = now()
			 WHERE session_key_id = $1::uuid
			   AND reserved_micro_usd + $2 <= (SELECT (max_cost_usd * 1000000)::bigint
			                                   FROM session_keys WHERE id = $1::uuid)
			                                   - spent_micro_usd`,
			req.Key, delta)

	default:
		return fmt.Errorf("%w: unknown scope kind %q", ErrInvalidRequest, req.Scope)
	}
	if err != nil {
		return fmt.Errorf("grant reserve update (%s): %w", req.Scope, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: scope %s key %s (free=%d)", ErrInsufficientCapacity, req.Scope, req.Key, free)
	}
	return nil
}

// upsertAllowance creates or extends the replica's allocation row and
// returns its id and cumulative granted amount.
func upsertAllowance(ctx context.Context, tx pgx.Tx, replicaID, orgID string, req GrantRequest, delta int64, ttl time.Duration) (int64, int64, error) {
	leaseUntil := time.Now().UTC().Add(ttl)
	var id, granted int64
	err := tx.QueryRow(ctx, `
		INSERT INTO budget_allowances
			(replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, status, lease_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (replica_id, scope_kind, scope_key, period) DO UPDATE SET
			granted_micro_usd = budget_allowances.granted_micro_usd + EXCLUDED.granted_micro_usd,
			status = $7,
			lease_until = EXCLUDED.lease_until,
			updated_at = now()
		RETURNING id, granted_micro_usd`,
		replicaID, string(req.Scope), req.Key, req.Period, orgID, delta, AllowanceActive, leaseUntil,
	).Scan(&id, &granted)
	if err != nil {
		return 0, 0, fmt.Errorf("grant allowance upsert: %w", err)
	}
	return id, granted, nil
}

// ReturnRequest gives back unused escrow for one scope (idle return or
// graceful shutdown, ADR §5.3 Return): u = granted_local − spent_local −
// inflight, computed by the replica.
type ReturnRequest struct {
	Scope  ScopeKind
	Key    string
	Period string
	Amount money.MicroUSD
}

// Return releases unused reserved capacity in one transaction: the scope
// row's reserve drops by the returned amount and the allowance records it
// in returned_micro_usd. Released allowances cannot absorb returns.
func (s *ReservationStore) Return(ctx context.Context, orgID, replicaID string, reqs []ReturnRequest) error {
	if orgID == "" || replicaID == "" {
		return fmt.Errorf("%w: org_id and replica_id are required", ErrInvalidRequest)
	}
	if len(reqs) == 0 {
		return nil
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("return begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return fmt.Errorf("return advisory lock: %w", err)
	}

	for _, req := range reqs {
		if err := s.returnScope(ctx, tx, orgID, replicaID, req); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *ReservationStore) returnScope(ctx context.Context, tx pgx.Tx, orgID, replicaID string, req ReturnRequest) error {
	if req.Amount < 0 {
		return fmt.Errorf("%w: negative return amount %d", ErrInvalidRequest, req.Amount)
	}
	if req.Amount == 0 {
		return nil
	}
	var id int64
	var granted, returned int64
	var status string
	err := tx.QueryRow(ctx, `
		SELECT id, granted_micro_usd, returned_micro_usd, status FROM budget_allowances
		WHERE replica_id = $1 AND scope_kind = $2 AND scope_key = $3 AND period = $4
		FOR UPDATE`,
		replicaID, string(req.Scope), req.Key, req.Period).Scan(&id, &granted, &returned, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s %s %s", ErrAllowanceNotFound, req.Scope, req.Key, req.Period)
	}
	if err != nil {
		return fmt.Errorf("return allowance read: %w", err)
	}
	if status == AllowanceReleased {
		return fmt.Errorf("%w: allowance %d", ErrAllowanceReleased, id)
	}
	if int64(req.Amount) > granted-returned {
		return fmt.Errorf("%w: allowance %d available=%d requested=%d",
			ErrAllowanceUnderflow, id, granted-returned, req.Amount)
	}

	if err := decrementScopeReserve(ctx, tx, orgID, req.Scope, req.Key, req.Period, int64(req.Amount)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE budget_allowances SET returned_micro_usd = returned_micro_usd + $2, updated_at = now()
		WHERE id = $1`, id, int64(req.Amount)); err != nil {
		return fmt.Errorf("return allowance update: %w", err)
	}
	return nil
}

// decrementScopeReserve lowers a scope row's reserve by amount. The
// reserved >= amount predicate makes underflow an explicit error instead of
// a silent CHECK failure; wallet rows ride the same FOR UPDATE row the
// settlement path serializes on.
func decrementScopeReserve(ctx context.Context, tx pgx.Tx, orgID string, scope ScopeKind, key, period string, amount int64) error {
	if amount == 0 {
		return nil
	}
	var (
		tag pgconn.CommandTag
		err error
	)
	switch scope {
	case ScopeWallet:
		tag, err = tx.Exec(ctx,
			`UPDATE org_credits SET reserved_micro_usd = reserved_micro_usd - $2, updated_at = now()
			 WHERE org_id = $1 AND reserved_micro_usd >= $2`,
			orgID, amount)
	case ScopeTeamMonth:
		tag, err = tx.Exec(ctx,
			`UPDATE team_spend_monthly SET reserved_micro_usd = reserved_micro_usd - $3
			 WHERE team_id = $1::uuid AND period = $2 AND reserved_micro_usd >= $3`,
			key, period, amount)
	case ScopeAgentDay:
		tag, err = tx.Exec(ctx,
			`UPDATE agent_spend_daily SET reserved_micro_usd = reserved_micro_usd - $3
			 WHERE agent_id = $1::uuid AND day = $2::date AND reserved_micro_usd >= $3`,
			key, period, amount)
	case ScopeSession:
		tag, err = tx.Exec(ctx,
			`UPDATE session_spend SET reserved_micro_usd = reserved_micro_usd - $2, updated_at = now()
			 WHERE session_key_id = $1::uuid AND reserved_micro_usd >= $2`,
			key, amount)
	default:
		return fmt.Errorf("%w: unknown scope kind %q", ErrInvalidRequest, scope)
	}
	if err != nil {
		return fmt.Errorf("reserve decrement (%s): %w", scope, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: scope %s key %s amount=%d", ErrReservedUnderflow, scope, key, amount)
	}
	return nil
}

// Renewal extends every active or expired allowance of the replica by one
// TTL and returns lapsed leases to active (ADR §5.3): a renewal is legal
// until the allowance is released — the money stayed reserved the whole
// time. Called every 60 s by the replica.
func (s *ReservationStore) Renewal(ctx context.Context, replicaID string) (int64, error) {
	if replicaID == "" {
		return 0, fmt.Errorf("%w: replica_id is required", ErrInvalidRequest)
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE budget_allowances
		 SET lease_until = now() + $2::interval, status = $3, updated_at = now()
		 WHERE replica_id = $1 AND status IN ($4, $5)`,
		replicaID, formatInterval(s.cfg.TTL), AllowanceActive, AllowanceActive, AllowanceExpired)
	if err != nil {
		return 0, fmt.Errorf("renewal: %w", err)
	}
	return tag.RowsAffected(), nil
}

// MarkDraining flips a replica's active allowances to draining (graceful
// shutdown start, §5.3 Return): renewals stop, in-flight requests finish,
// reconcile releases drained-out allowances with zero remainder.
func (s *ReservationStore) MarkDraining(ctx context.Context, replicaID string) (int64, error) {
	if replicaID == "" {
		return 0, fmt.Errorf("%w: replica_id is required", ErrInvalidRequest)
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE budget_allowances SET status = $2, updated_at = now()
		 WHERE replica_id = $1 AND status = $3`,
		replicaID, AllowanceDraining, AllowanceActive)
	if err != nil {
		return 0, fmt.Errorf("mark draining: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SelfReapCrashedIncarnations implements automatic startup reaping (D1),
// limited to this replica family (D2), with the existing safety window (D3).
// A hard-killed replica's allowances stay active with a
// lapsed lease until the periodic reconcile frees them; this pass flips the
// PREVIOUS incarnations of this very replica family — rows whose replica_id
// shares hostPrefix (the sweeping process's own host; the id is
// host-pid-nanos, so the family is exactly this host's boots) and whose
// lease already lapsed (the owner is provably not renewing) — from active
// to draining, the same transition the graceful Shutdown path applies.
//
// Scope guards (D2):
//   - only rows of the own host family match: the anchored pattern
//     ^prefix-[0-9]+-[0-9]+$ (metacharacters escaped) is exactly the id
//     shape reservationReplicaID builds (host-pid-nanos), so a FOREIGN
//     host whose name merely starts with prefix+"-" (e.g. "gwbox-extra")
//     can never match the "gwbox" family — a LIKE prefix alone would;
//   - a live sibling on the same host never matches because it renews its
//     lease well inside the TTL, and the lapsed-lease predicate excludes
//     everything still renewing;
//   - foreign hosts' rows (including crashed ones) are never touched —
//     there is no cross-replica liveliness authority here.
//
// Money guards (D3): the sweep never releases escrow itself and never
// shortens the safety window. Draining rows with a zero remainder release
// on the next §7.1.2 reconcile tick; rows still holding a remainder wait
// out ReservationSafetyWindow exactly as before, then
// ReconcileRelease returns them once.
//
// Idempotent by construction: draining/released rows are not active, so a
// second run (another restart) flips nothing and reports 0.
func (s *ReservationStore) SelfReapCrashedIncarnations(ctx context.Context, hostPrefix string) (int64, error) {
	if hostPrefix == "" {
		return 0, fmt.Errorf("%w: host prefix is required", ErrInvalidRequest)
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE budget_allowances SET status = $1, updated_at = now()
		 WHERE status = $2
		   AND lease_until < now()
		   AND replica_id ~ ('^' || $3 || '-[0-9]+-[0-9]+$')`,
		AllowanceDraining, AllowanceActive, escapeRegex(hostPrefix))
	if err != nil {
		return 0, fmt.Errorf("self reap crashed incarnations: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 {
		metrics.BudgetSelfReapedAllowances.Add(float64(n))
		s.log.Info("self-reaped crashed previous incarnations' allowances",
			"host_prefix", hostPrefix, "drained", n)
	}
	return tag.RowsAffected(), nil
}

// escapeRegex escapes the POSIX regular-expression metacharacters so a
// host prefix matches literally inside the anchored family pattern
// ^prefix-[0-9]+-[0-9]+$ the self-reap sweep matches replica ids with.
func escapeRegex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SettleResult reports the outcome of one settle-side reserve release.
type SettleResult struct {
	Applied bool           // false when the allowance was already released
	Amount  money.MicroUSD // min(actual, bound) actually released
}

// SettleDecrement applies the settle-side reserve release (ADR §5.3
// Settle, step 2): while the allowance is not released, the scope row's
// reserve drops by min(actual, bound). A late settle after reconcile
// released the allowance is ledger-only: Applied=false, the reserve is not
// decremented twice. Ledger writes themselves stay in the settlement
// worker's transaction (NEXT-18d) — this primitive only owns the reserve.
func (s *ReservationStore) SettleDecrement(ctx context.Context, orgID string, allowanceID int64, actual, bound money.MicroUSD) (SettleResult, error) {
	if orgID == "" || allowanceID <= 0 {
		return SettleResult{}, fmt.Errorf("%w: org_id and allowance_id are required", ErrInvalidRequest)
	}
	if actual < 0 {
		actual = 0
	}
	if bound < 0 {
		bound = 0
	}
	d := actual
	if bound < d {
		d = bound
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return SettleResult{}, fmt.Errorf("settle begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return SettleResult{}, fmt.Errorf("settle advisory lock: %w", err)
	}

	var scope, key, period, status string
	err = tx.QueryRow(ctx, `
		SELECT scope_kind, scope_key, period, status FROM budget_allowances
		WHERE id = $1 FOR SHARE`, allowanceID).Scan(&scope, &key, &period, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return SettleResult{}, fmt.Errorf("%w: id %d", ErrAllowanceNotFound, allowanceID)
	}
	if err != nil {
		return SettleResult{}, fmt.Errorf("settle allowance read: %w", err)
	}
	if status == AllowanceReleased {
		// Late settle after reconcile: reserve already returned — ledger only.
		return SettleResult{Applied: false, Amount: 0}, tx.Commit(ctx)
	}

	if err := decrementScopeReserve(ctx, tx, orgID, ScopeKind(scope), key, period, int64(d)); err != nil {
		return SettleResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SettleResult{}, fmt.Errorf("settle commit: %w", err)
	}
	return SettleResult{Applied: true, Amount: d}, nil
}

// SettleDecrementTx is the caller-transaction form of SettleDecrement
// settlement transaction the caller owns, so the scope-row decrement and
// the job's settle mark (carrying the reconcile payload key) commit
// atomically — the per-job form of the batch executor's decrement
// (settlement_batch.go markBatchSettled). Same semantics, per entry:
//
//   - the per-org advisory lock is (re-)taken — the caller is expected to
//     hold it already; pg_advisory_xact_lock is re-entrant within a
//     transaction, so taking it again is a cheap local no-op;
//   - the allowance is read FOR SHARE; a released allowance (late settle
//     after reconcile) and a vanished row are ledger-only: 0 applied;
//   - a live allowance has its scope row's reserve dropped by
//     min(actual, bound) under the reserved >= amount predicate —
//     invariant drift (§7.1.3) is the explicit ErrReservedUnderflow,
//     never a silent clamp;
//   - the applied amount is returned so the caller can record it under
//     the reconcile key exactly when the reserve moved.
//
// The caller owns Begin/Commit/Rollback: on error the whole settlement
// transaction (money side effect + settle mark included) rolls back and
// the job retries — the fail-safe freeze direction.
func SettleDecrementTx(ctx context.Context, tx pgx.Tx, orgID string, allowanceID int64, actual, bound money.MicroUSD) (int64, error) {
	if allowanceID <= 0 {
		// No reserve linkage (legacy payload): a ledger-only settle, the
		// same disposition the batch applies to unlinked entries.
		return 0, nil
	}
	if orgID == "" {
		return 0, fmt.Errorf("%w: org_id is required", ErrInvalidRequest)
	}
	if actual < 0 {
		actual = 0
	}
	if bound < 0 {
		bound = 0
	}
	d := int64(actual)
	if int64(bound) < d {
		d = int64(bound)
	}

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return 0, fmt.Errorf("settle decrement advisory lock: %w", err)
	}

	var scope, key, period, status string
	err := tx.QueryRow(ctx, `
		SELECT scope_kind, scope_key, period, status FROM budget_allowances
		WHERE id = $1 FOR SHARE`, allowanceID).Scan(&scope, &key, &period, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		// The allowance row is gone (retention): nothing left to release —
		// ledger-only, the batch's `!ok` disposition.
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("settle decrement allowance read: %w", err)
	}
	if status == AllowanceReleased {
		// Late settle after reconcile: reserve already returned — ledger only.
		return 0, nil
	}
	if d <= 0 {
		return 0, nil
	}

	if err := decrementScopeReserve(ctx, tx, orgID, ScopeKind(scope), key, period, d); err != nil {
		return 0, err
	}
	return d, nil
}

// ReconcileSummary reports one reconcile pass (§7.1).
type ReconcileSummary struct {
	Released         int64
	ReturnedMicroUSD int64
	// ReleasedByReason breakdown for budget_allowance_released_total{reason}
	// (NEXT-18e, §7.1.1/§7.1.2): expired_safety_window — lease lapsed past
	// the safety window with money left; zero_remainder — draining/expired
	// with nothing left to return. Sums to Released.
	ExpiredSafetyReleased int64
	ZeroRemainderReleased int64
}

// reconcileSettleKey is the settlement_jobs.payload key carrying the µUSD
// amount a settled job already removed from the scope reserve
// (min(actual, bound)); the settlement worker (NEXT-18d) writes it.
const reconcileSettleKey = "settle_decrement_micro_usd"

// ReconcileRelease releases lapsed allowances and returns their remainder
// to the scopes (§7.1.1/§7.1.2): any non-released allowance whose lease
// lapsed more than window ago, plus draining/expired allowances with zero
// remainder. Remainder = granted − returned − settled (settled read from
// settlement_jobs via allowance_id, §5.4). Each candidate commits in its
// own transaction so one bad row cannot stall the pass; rows are re-checked
// FOR UPDATE before release. Uses now() from the database as the clock.
func (s *ReservationStore) ReconcileRelease(ctx context.Context, window time.Duration) (ReconcileSummary, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, org_id, scope_kind, scope_key, period, granted_micro_usd, returned_micro_usd, status
		FROM budget_allowances
		WHERE status <> $1
		  AND (lease_until < now() - $2::interval OR status IN ($3, $4))
		ORDER BY id`,
		AllowanceReleased, formatInterval(window), AllowanceDraining, AllowanceExpired)
	if err != nil {
		return ReconcileSummary{}, fmt.Errorf("reconcile candidates: %w", err)
	}
	type candidate struct {
		id                int64
		org, scope, key   string
		period            string
		granted, returned int64
		status            string
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.org, &c.scope, &c.key, &c.period, &c.granted, &c.returned, &c.status); err != nil {
			rows.Close()
			return ReconcileSummary{}, fmt.Errorf("reconcile scan: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return ReconcileSummary{}, fmt.Errorf("reconcile rows: %w", err)
	}
	rows.Close()

	var summary ReconcileSummary
	for _, c := range candidates {
		released, returned, reason, err := s.releaseOne(ctx, c.id, c.org, ScopeKind(c.scope), c.key, c.period, c.granted, c.returned, c.status, window)
		if err != nil {
			return summary, err
		}
		if released {
			summary.Released++
			summary.ReturnedMicroUSD += returned
			switch reason {
			case ReleaseReasonExpiredSafety:
				summary.ExpiredSafetyReleased++
			case ReleaseReasonZeroRemainder:
				summary.ZeroRemainderReleased++
			}
		}
	}
	return summary, nil
}

// releaseOne releases a single allowance if it still qualifies: lease
// lapsed past the safety window, or zero remainder while draining/expired.
// The returned reason is the §7.1.1/§7.1.2 cause: expired_safety_window
// when money was still frozen past the window, zero_remainder otherwise.
func (s *ReservationStore) releaseOne(ctx context.Context, id int64, orgID string, scope ScopeKind, key, period string, granted, returned int64, status string, window time.Duration) (bool, int64, string, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, 0, "", fmt.Errorf("reconcile begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return false, 0, "", fmt.Errorf("reconcile advisory lock: %w", err)
	}

	var curStatus string
	var curGranted, curReturned int64
	var lapsed bool
	err = tx.QueryRow(ctx, `
		SELECT status, granted_micro_usd, returned_micro_usd,
		       lease_until < now() - $2::interval
		FROM budget_allowances WHERE id = $1 FOR UPDATE`,
		id, formatInterval(window)).Scan(&curStatus, &curGranted, &curReturned, &lapsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, "", nil // released between query and lock
	}
	if err != nil {
		return false, 0, "", fmt.Errorf("reconcile allowance read: %w", err)
	}
	if curStatus == AllowanceReleased {
		return false, 0, "", nil
	}

	settled, err := settledMicro(ctx, tx, id)
	if err != nil {
		return false, 0, "", err
	}
	remainder := curGranted - curReturned - settled
	if remainder < 0 {
		remainder = 0
	}
	if !lapsed && remainder > 0 {
		return false, 0, "", nil // draining/expired but still holds money and lease is young
	}

	if remainder > 0 {
		if err := decrementScopeReserve(ctx, tx, orgID, scope, key, period, remainder); err != nil {
			// Invariant drift must not wedge reconcile: releasing without the
			// decrement leaves capacity frozen (safe direction) and observable.
			s.log.Warn("reconcile reserve decrement failed; releasing anyway",
				"allowance_id", id, "scope", string(scope), "key", key, "error", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE budget_allowances
		SET returned_micro_usd = returned_micro_usd + $2, status = $3, updated_at = now()
		WHERE id = $1 AND status <> $3`,
		id, remainder, AllowanceReleased); err != nil {
		return false, 0, "", fmt.Errorf("reconcile release update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, 0, "", fmt.Errorf("reconcile commit: %w", err)
	}
	if remainder > 0 {
		// Money was still frozen past the safety window — §7.1.1.
		return true, remainder, ReleaseReasonExpiredSafety, nil
	}
	// Nothing left to return — §7.1.2 releases it immediately.
	return true, 0, ReleaseReasonZeroRemainder, nil
}

// settledMicro sums the µUSD amounts already removed from the scope reserve
// by settled jobs of this allowance (§5.4). Non-object payloads contribute 0.
func settledMicro(ctx context.Context, tx pgx.Tx, allowanceID int64) (int64, error) {
	var settled int64
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(SUM(CASE WHEN jsonb_typeof(payload) = 'object'
		                         THEN COALESCE((payload->>$2)::bigint, 0)
		                         ELSE 0 END), 0)
		FROM settlement_jobs WHERE allowance_id = $1`,
		allowanceID, reconcileSettleKey).Scan(&settled)
	if err != nil {
		return 0, fmt.Errorf("reconcile settled read: %w", err)
	}
	return settled, nil
}

// AbandonedReplicaSummary reports one CloseAbandonedReplica pass (N06-P05).
type AbandonedReplicaSummary struct {
	// Closed counts allowance rows this pass flipped to released.
	Closed int64
	// ReturnedMicroUSD is the Σ remainder this pass returned to the scopes.
	ReturnedMicroUSD int64
	// SkippedLive counts rows still holding money whose lease had not
	// lapsed past the safety window when the pass reached them — the
	// live-reserve guard: the permanently-lost verdict only closes rows
	// no live owner could still be renewing (§7.1.1 predicate).
	SkippedLive int64
	// AlreadyReleased counts rows found released (or gone) before this
	// pass reached them — the losing side of a reconciler race, never a
	// double return.
	AlreadyReleased int64
}

// orphanClosureState classifies the outcome of one targeted closure.
type orphanClosureState int

const (
	orphanClosed orphanClosureState = iota
	orphanSkippedLive
	orphanAlreadyReleased
)

// CloseAbandonedReplica closes the orphan reservations of ONE replica
// declared permanently lost (crash reconciliation, N06-P05): the lapsed
// escrow of a replica that will never renew, settle or return its
// allowances is released back to the scopes exactly once, so recovery
// converges to a single ledger without eternal reservations.
//
// The per-row mechanics are the §7.1.1/§7.1.2 reconcile release mechanics
// (releaseOne), so the targeted verdict and the periodic pass are two
// callers of the same exactly-once state machine and can race freely:
// per-org advisory lock, FOR UPDATE re-read under the lock, remainder =
// granted − returned − Σ settled (the NEXT-18d payload key), a
// status-guarded flip to released, and a ledger-only late settle after the
// close. A row qualifies only when its lease lapsed past the safety window
// (or it is draining/expired with a zero remainder, §7.1.2): a live
// reserve — money held under a young, possibly renewing lease — is never
// freed, even though the caller asserts the replica is gone (negative
// criterion; a paused-but-alive incarnation renews well inside the window
// and re-qualifies its rows for closure only after the window lapses
// again).
//
// The window is fail-closed (orphanWindow, N06-P05-T04): window <= 0
// falls back to ReservationSafetyWindow, and a positive override shorter
// than the default is floored back up to it — an unfenced verdict never
// gets a window shorter than the §14 D13 default, so a stale or
// mis-configured caller cannot release a reserve a live owner could
// still renew. The deliberate short-window override is
// CloseAbandonedReplicaFenced: under a held fencing lease a serialized,
// TTL-bounded verdict may close sooner.
//
// Closing counts under
// budget_allowance_released_total{reason="crash_orphan"} — the diagnostic
// distinction between "lease ran out" (expired_safety_window) and "crash
// recovery closed an orphan". Idempotent: the candidate scan includes
// already-released rows, so a second call classifies each of them under
// AlreadyReleased instead of reporting a silent all-zero pass.
//
// Cross-host by design: unlike SelfReapCrashedIncarnations (own host
// family only, no cross-replica liveness authority), this primitive
// acts on an explicit lost-replica verdict and needs no host-family
// match. Production callers: the fenced verdict is
// CloseAbandonedReplicaFenced (N06-P05-T04); the boot sweep is wired by
// N13.
func (s *ReservationStore) CloseAbandonedReplica(ctx context.Context, replicaID string, window time.Duration) (AbandonedReplicaSummary, error) {
	if replicaID == "" {
		return AbandonedReplicaSummary{}, fmt.Errorf("%w: replica_id is required", ErrInvalidRequest)
	}
	return s.closeAbandonedCandidates(ctx, replicaID, "unfenced", orphanWindow(window), nil)
}

// closeAbandonedCandidates is the shared exactly-once core of both orphan
// verdicts: scan the replica's allowance rows (candidates include
// already-released rows so a re-verdict observes the exactly-once losing
// side), then close each through closeAbandonedOne. stop, when non-nil,
// runs before every row and aborts the pass with its error (the fenced
// lease's TTL check); closer labels the closing log line. Closing counts
// under budget_allowance_released_total{reason="crash_orphan"} exactly
// once per closed row, whichever verdict wins the race.
func (s *ReservationStore) closeAbandonedCandidates(ctx context.Context, replicaID, closer string, window time.Duration, stop func() error) (AbandonedReplicaSummary, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, org_id, scope_kind, scope_key, period
		FROM budget_allowances
		WHERE replica_id = $1
		ORDER BY id`,
		replicaID)
	if err != nil {
		return AbandonedReplicaSummary{}, fmt.Errorf("orphan close candidates: %w", err)
	}
	type orphanCandidate struct {
		id              int64
		org, scope, key string
		period          string
	}
	var candidates []orphanCandidate
	for rows.Next() {
		var c orphanCandidate
		if err := rows.Scan(&c.id, &c.org, &c.scope, &c.key, &c.period); err != nil {
			rows.Close()
			return AbandonedReplicaSummary{}, fmt.Errorf("orphan close scan: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return AbandonedReplicaSummary{}, fmt.Errorf("orphan close rows: %w", err)
	}
	rows.Close()

	var summary AbandonedReplicaSummary
	for _, c := range candidates {
		if stop != nil {
			if err := stop(); err != nil {
				return summary, err
			}
		}
		state, returned, err := s.closeAbandonedOne(ctx, c.id, c.org, ScopeKind(c.scope), c.key, c.period, window)
		if err != nil {
			return summary, err
		}
		switch state {
		case orphanClosed:
			summary.Closed++
			summary.ReturnedMicroUSD += returned
		case orphanSkippedLive:
			summary.SkippedLive++
		case orphanAlreadyReleased:
			summary.AlreadyReleased++
		}
	}
	if summary.Closed > 0 {
		metrics.BudgetAllowanceReleasedTotal.WithLabelValues(ReleaseReasonCrashOrphan).Add(float64(summary.Closed))
		s.log.Info("closed abandoned replica's orphan reservations",
			"replica_id", replicaID,
			"closer", closer,
			"closed", summary.Closed,
			"returned_micro_usd", summary.ReturnedMicroUSD,
			"skipped_live", summary.SkippedLive,
			"already_released", summary.AlreadyReleased,
		)
	}
	return summary, nil
}

// closeAbandonedOne closes a single allowance of the declared-lost replica
// if it still qualifies: lease lapsed past the safety window, or zero
// remainder while draining/expired (§7.1.1/§7.1.2 — the same qualification
// releaseOne applies, so the targeted verdict and the periodic pass can
// never both move the same money).
func (s *ReservationStore) closeAbandonedOne(ctx context.Context, id int64, orgID string, scope ScopeKind, key, period string, window time.Duration) (orphanClosureState, int64, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("orphan close begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return 0, 0, fmt.Errorf("orphan close advisory lock: %w", err)
	}

	var curStatus string
	var curGranted, curReturned int64
	var lapsed bool
	err = tx.QueryRow(ctx, `
		SELECT status, granted_micro_usd, returned_micro_usd,
		       lease_until < now() - $2::interval
		FROM budget_allowances WHERE id = $1 FOR UPDATE`,
		id, formatInterval(window)).Scan(&curStatus, &curGranted, &curReturned, &lapsed)
	if errors.Is(err, pgx.ErrNoRows) {
		// Released (and possibly retention-deleted) between the candidate
		// query and the lock — a reconciler race this pass lost; terminal.
		return orphanAlreadyReleased, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("orphan close allowance read: %w", err)
	}
	if curStatus == AllowanceReleased {
		// Another reconciler closed it first — the exactly-once losing side.
		return orphanAlreadyReleased, 0, nil
	}

	settled, err := settledMicro(ctx, tx, id)
	if err != nil {
		return 0, 0, err
	}
	remainder := curGranted - curReturned - settled
	if remainder < 0 {
		remainder = 0
	}
	if !lapsed && remainder > 0 {
		// Live-reserve guard (negative criterion): money held under a
		// young lease is not provably orphaned — the owner may be a paused
		// incarnation that renews on comeback. Stay frozen.
		return orphanSkippedLive, 0, nil
	}

	if remainder > 0 {
		if err := decrementScopeReserve(ctx, tx, orgID, scope, key, period, remainder); err != nil {
			// Same invariant-drift disposition as releaseOne: closing
			// without the decrement leaves the reserve observable as §7.1.3
			// divergence (safe direction) instead of wedging crash recovery.
			s.log.Warn("orphan close reserve decrement failed; releasing anyway",
				"allowance_id", id, "scope", string(scope), "key", key, "error", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE budget_allowances
		SET returned_micro_usd = returned_micro_usd + $2, status = $3, updated_at = now()
		WHERE id = $1 AND status <> $3`,
		id, remainder, AllowanceReleased); err != nil {
		return 0, 0, fmt.Errorf("orphan close release update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("orphan close commit: %w", err)
	}
	return orphanClosed, remainder, nil
}

// grantDelta is the pure §5.3 sizing rule:
//
//	Δ = clamp(rate × EscrowHorizon, min = bound, max = EscrowMaxFraction × free)
//
// The min side always wins when it conflicts with the max side (near
// exhaustion issues exactly bound; §5.3/§4.4). unlimited (advisory scopes)
// skips the fraction cap. All values are µUSD.
func grantDelta(free, bound, rate, avgBound int64, unlimited bool, cfg ReservationConfig) (int64, error) {
	if free < 0 {
		return 0, fmt.Errorf("free capacity %d is negative", free)
	}
	if bound > free {
		return 0, fmt.Errorf("bound %d exceeds free capacity %d", bound, free)
	}

	ref := avgBound
	if ref <= 0 {
		ref = bound
	}
	// Near exhaustion: exactly one bound (stranded-capacity guard).
	if ref > 0 {
		lowWater, overflow := mulNonNegative(cfg.EscrowLowWaterBounds, ref)
		if overflow {
			lowWater = math.MaxInt64
		}
		if lowWater > 0 && free < lowWater {
			return bound, nil
		}
	}

	delta := int64(0)
	if rate > 0 {
		scaled, overflow := mulNonNegative(rate, int64(cfg.EscrowHorizon))
		if overflow {
			delta = math.MaxInt64
		} else {
			delta = scaled / int64(time.Second)
		}
	}
	if delta < bound {
		delta = bound
	}
	if !unlimited && cfg.EscrowMaxFraction > 0 {
		if maxDelta := int64(float64(free) * cfg.EscrowMaxFraction); delta > maxDelta {
			delta = maxDelta
		}
	}
	if delta > free {
		delta = free
	}
	if delta < bound {
		delta = bound // bound fits (checked above) and always wins
	}
	return delta, nil
}

// sortGrantRequests orders requests into the canonical lock order and
// rejects duplicates/unknown scopes.
func sortGrantRequests(reqs []GrantRequest) ([]GrantRequest, error) {
	rank := func(k ScopeKind) (int, error) {
		switch k {
		case ScopeWallet:
			return 0, nil
		case ScopeTeamMonth:
			return 1, nil
		case ScopeAgentDay:
			return 2, nil
		case ScopeSession:
			return 3, nil
		default:
			return 0, fmt.Errorf("%w: unknown scope kind %q", ErrInvalidRequest, k)
		}
	}
	seen := make(map[ScopeKind]map[string]bool, len(reqs))
	ordered := make([]GrantRequest, len(reqs))
	copy(ordered, reqs)
	for i := range ordered {
		if _, err := rank(ordered[i].Scope); err != nil {
			return nil, err
		}
		if ordered[i].Key == "" {
			return nil, fmt.Errorf("%w: empty scope key for %s", ErrInvalidRequest, ordered[i].Scope)
		}
		if seen[ordered[i].Scope] == nil {
			seen[ordered[i].Scope] = map[string]bool{}
		}
		if seen[ordered[i].Scope][ordered[i].Key] {
			return nil, fmt.Errorf("%w: duplicate scope %s key %s", ErrInvalidRequest, ordered[i].Scope, ordered[i].Key)
		}
		seen[ordered[i].Scope][ordered[i].Key] = true
		// Insertion sort by canonical rank: n ≤ 4.
		for j := i; j > 0; j-- {
			rj, _ := rank(ordered[j-1].Scope)
			rCur, _ := rank(ordered[j].Scope)
			if rj <= rCur {
				break
			}
			ordered[j-1], ordered[j] = ordered[j], ordered[j-1]
		}
	}
	return ordered, nil
}

// centsToMicro converts a signed cents amount (wallet balances, negative
// grace floors) to µUSD with an overflow check — a wrapped value would
// silently corrupt capacity math.
func centsToMicro(cents int64) (int64, error) {
	const limit = math.MaxInt64 / int64(money.MicroPerCent)
	if cents > limit || cents < -limit {
		return 0, fmt.Errorf("%w: %d cents", money.ErrRange, cents)
	}
	return cents * int64(money.MicroPerCent), nil
}

func mulNonNegative(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, false
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64, true
	}
	return a * b, false
}

// formatInterval renders a duration as a PostgreSQL interval literal
// (durations here are whole seconds/milliseconds by construction).
func formatInterval(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	return fmt.Sprintf("%d milliseconds", ms)
}
