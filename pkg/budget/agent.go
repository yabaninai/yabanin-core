package budget

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
)

// Sentinel errors for the per-agent budget (G2). Mirrors the team enforcer's
// fail-closed semantics: an agent without a configured budget row may not spend
// (ErrNoBudgetConfigured), and a datastore outage denies rather than allowing
// unbounded spend (ErrAgentBudgetUnavailable).
var (
	// ErrNoAgentBudget indicates no agent budget row is configured.
	ErrNoAgentBudget = errors.New("no agent budget configured")
	// ErrAgentBudgetExceeded indicates the agent's daily limit was reached.
	ErrAgentBudgetExceeded = errors.New("agent budget exceeded")
	// ErrAgentBudgetUnavailable indicates the agent budget store could not be
	// queried (fail-closed: deny during a datastore outage).
	ErrAgentBudgetUnavailable = errors.New("agent budget check unavailable")
)

// agentBudget is the cached per-agent daily budget row.
type agentBudget struct {
	dailyLimitCents int64
	// absent marks a cached negative lookup (no budget row) so the
	// ErrNoAgentBudget signal survives cache hits.
	absent   bool
	cachedAt time.Time
}

// AgentEnforcer checks per-agent daily budget limits in real-time. It is a
// second, independent enforcer from the team Enforcer: agents are G1
// principals (yag_* keys) and spend is tracked per (agent_id, day) in
// agent_spend_daily. Uses the same dbConn interface and an in-memory cache.
type AgentEnforcer struct {
	db    dbConn
	log   *slog.Logger
	cache map[string]*agentBudget
	mu    sync.RWMutex
	ttl   time.Duration
	now   func() time.Time // injectable for tests
}

// NewAgentEnforcer creates an agent budget enforcer backed by the database.
// Accepts any type implementing dbConn (e.g., *pgxpool.Pool).
func NewAgentEnforcer(db dbConn, log *slog.Logger) *AgentEnforcer {
	return &AgentEnforcer{
		db:    db,
		log:   log.With("component", "agent-budget-enforcer"),
		cache: make(map[string]*agentBudget),
		ttl:   1 * time.Minute,
		now:   time.Now,
	}
}

// CheckAgentBudget verifies whether an agent may make a request given its
// current daily spend. Semantics mirror CheckBudget (fail-safe):
//   - No agent identity, or no datastore → allow (not wired for this deploy).
//   - No budget row (ErrNoAgentBudget) → deny; configure a row to enable it.
//   - Datastore error → deny (ErrAgentBudgetUnavailable).
//   - Daily limit exceeded → deny (ErrAgentBudgetExceeded).
//
// AUDIT-P1-03 (delegated keys): after the agent's own cap passes, the
// DELEGATION chain is walked — a child key is additionally denied when any
// ancestor's budget is missing (fail-closed) or exhausted by its subtree
// spend (the ancestor's own spend plus everything attributed to its
// children). Both denials reuse the existing gateway mappings
// (ErrNoAgentBudget → 403 agent_budget_not_configured,
// ErrAgentBudgetExceeded → 429 agent_budget_exceeded) and name the
// offending ancestor in the wrapped message.
func (e *AgentEnforcer) CheckAgentBudget(ctx context.Context, agentID string) error {
	if agentID == "" || e.db == nil {
		return nil
	}

	day := e.now().UTC().Format("2006-01-02")

	b, err := e.getBudget(ctx, agentID)
	if err != nil {
		if errors.Is(err, ErrNoAgentBudget) {
			return ErrNoAgentBudget
		}
		e.log.Warn("agent budget lookup unavailable, denying request", "agent_id", agentID, "error", err)
		return fmt.Errorf("%w: %v", ErrAgentBudgetUnavailable, err)
	}

	spend, err := e.getSpendToday(ctx, agentID, day)
	if err != nil {
		e.log.Warn("agent budget spend lookup unavailable, denying request", "agent_id", agentID, "error", err)
		return fmt.Errorf("%w: %v", ErrAgentBudgetUnavailable, err)
	}

	if spend >= b.dailyLimitCents {
		return fmt.Errorf("%w: spent %d of %d cents limit", ErrAgentBudgetExceeded, spend, b.dailyLimitCents)
	}

	// AUDIT-P1-03: the delegation invariant is enforced on the real spend
	// path too, not only at delegation time — a pre-gate child (or a parent
	// cap lowered after delegation) can never overspend its parent.
	return e.checkAncestorBudgets(ctx, agentID, day)
}

// maxAgentAncestorDepth bounds the delegation walk. The admin API only ever
// creates depth-1 delegations (children cannot delegate further); the cap
// is defense in depth against legacy or hand-crafted deeper chains.
const maxAgentAncestorDepth = 4

// checkAncestorBudgets walks the parent chain of agentID (via
// agent_keys.parent_id) and enforces every ancestor's budget against its
// subtree spend. Each hop:
//   - missing ancestor budget row → ErrNoAgentBudget (fail-closed: the child
//     cannot legitimately spend under an uncapped parent),
//   - subtree spend ≥ ancestor limit → ErrAgentBudgetExceeded,
//   - lookup failure → ErrAgentBudgetUnavailable (deny).
//
// A root key (parent_id NULL, or no agent_keys row at all — synthetic ids)
// ends the walk. A cycle in the chain is corruption; it denies fail-closed
// instead of looping.
func (e *AgentEnforcer) checkAncestorBudgets(ctx context.Context, agentID, day string) error {
	visited := map[string]bool{agentID: true}
	child := agentID
	for depth := 0; depth < maxAgentAncestorDepth; depth++ {
		parent, err := e.agentParentID(ctx, child)
		if err != nil {
			e.log.Warn("agent ancestor lookup unavailable, denying request",
				"agent_id", agentID, "child", child, "error", err)
			return fmt.Errorf("%w: %v", ErrAgentBudgetUnavailable, err)
		}
		if parent == "" {
			return nil // root key — the walk is done
		}
		if visited[parent] {
			return fmt.Errorf("%w: delegation chain cycle at ancestor %s", ErrAgentBudgetUnavailable, parent)
		}
		visited[parent] = true

		b, err := e.getBudget(ctx, parent)
		if err != nil {
			if errors.Is(err, ErrNoAgentBudget) {
				return fmt.Errorf("%w: ancestor %s has no daily budget configured", ErrNoAgentBudget, parent)
			}
			e.log.Warn("ancestor budget lookup unavailable, denying request",
				"agent_id", agentID, "ancestor", parent, "error", err)
			return fmt.Errorf("%w: %v", ErrAgentBudgetUnavailable, err)
		}

		subtree, err := e.agentSubtreeSpendCents(ctx, parent, day)
		if err != nil {
			e.log.Warn("ancestor subtree spend lookup unavailable, denying request",
				"agent_id", agentID, "ancestor", parent, "error", err)
			return fmt.Errorf("%w: %v", ErrAgentBudgetUnavailable, err)
		}
		if subtree >= b.dailyLimitCents {
			return fmt.Errorf("%w: ancestor %s subtree spent %d of %d cents limit",
				ErrAgentBudgetExceeded, parent, subtree, b.dailyLimitCents)
		}
		child = parent
	}
	return nil
}

// agentParentID returns the parent of an agent key ("" when the row is
// absent — e.g. synthetic/test agent ids — or the key is a root).
func (e *AgentEnforcer) agentParentID(ctx context.Context, agentID string) (string, error) {
	var parent *string
	err := e.db.QueryRow(ctx,
		`SELECT parent_id::text FROM agent_keys WHERE id = $1::uuid`,
		agentID,
	).Scan(&parent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if parent == nil {
		return "", nil
	}
	return *parent, nil
}

// agentSubtreeSpendCents sums the cents spend of the ancestor itself and
// everything attributed to its direct children for the given day. Spent
// money counts regardless of whether the child key was later revoked —
// the budget already funded it.
func (e *AgentEnforcer) agentSubtreeSpendCents(ctx context.Context, ancestorID, day string) (int64, error) {
	var spend int64
	err := e.db.QueryRow(ctx,
		`SELECT COALESCE(SUM(s.cost_cents), 0)
		 FROM agent_keys k
		 LEFT JOIN agent_spend_daily s ON s.agent_id = k.id AND s.day = $2
		 WHERE k.id = $1::uuid OR k.parent_id = $1::uuid`,
		ancestorID, day,
	).Scan(&spend)
	if err != nil {
		return 0, err
	}
	return spend, nil
}

// RecordAgentSpend upserts the daily (agent_id, day) spend rollup. costCents is
// floored at 0; tokens are accumulated additively. Called by the loggerd
// consumer after inserting a request log that carries an agent_id.
//
// DEPRECATED for mandatory accounting (AF-06): this call is NOT idempotent —
// replaying the same request would add its cost twice, and the amount is
// cent-rounded. It remains for callers that have no durable work item
// (compatibility paths); the settlement worker uses RecordAgentSpendExact.
func (e *AgentEnforcer) RecordAgentSpend(ctx context.Context, agentID string, costCents int64, tokensIn, tokensOut int64) error {
	if agentID == "" || e.db == nil {
		return nil
	}
	if costCents < 0 {
		costCents = 0
	}
	day := e.now().UTC().Format("2006-01-02")

	_, err := e.db.Exec(ctx,
		`INSERT INTO agent_spend_daily (agent_id, day, cost_cents, tokens_in, tokens_out)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (agent_id, day)
		 DO UPDATE SET cost_cents = agent_spend_daily.cost_cents + $3,
		               tokens_in  = agent_spend_daily.tokens_in + $4,
		               tokens_out = agent_spend_daily.tokens_out + $5`,
		agentID, day, costCents, tokensIn, tokensOut,
	)
	if err != nil {
		return fmt.Errorf("record agent spend: %w", err)
	}
	return nil
}

// SpendExecutor is the transactional write surface the exact agent-spend
// path runs on (a pgx.Tx in production). Sharing the caller's transaction
// with the settlement-job state update is what makes the spend exactly-once:
// a crash rolls the spend and the job transition back together.
type SpendExecutor interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
}

// RecordAgentSpendExact applies an exact micro-USD agent spend inside the
// caller's transaction (AF-06 settlement worker), bucketing the day by the
// settle time — the backwards-compatible default. Callers carrying the
// request's own time use RecordAgentSpendExactAt (ADR I5).
func (e *AgentEnforcer) RecordAgentSpendExact(ctx context.Context, db SpendExecutor, agentID string, amount money.MicroUSD, tokensIn, tokensOut int64) error {
	return e.RecordAgentSpendExactAt(ctx, db, agentID, amount, tokensIn, tokensOut, time.Time{})
}

// RecordAgentSpendExactAt applies an exact micro-USD agent spend inside the
// caller's transaction, bucketing the (agent_id, day) rollup by the
// REQUEST's own time — the same "period fixed by request time" semantics
// as the team path's caller-supplied period (enforcer.go). A request served
// before UTC midnight therefore lands in the day it was served in, never in
// the — possibly much later — settle day. A zero requestTime keeps the
// settle-time default for callers that predate the field.
//
// The intent's amount_micro_usd is applied verbatim to the durable
// cost_micro_usd accumulator — no per-event cent rounding is re-derived
// from floats; the cost_cents column keeps its rounded compatibility
// projection (derived from the exact amount, half away from zero, same
// rounding as the wallet projection) for the cents-denominated daily
// budget limit.
//
// Idempotency comes from the caller: the spend and the settlement-job
// transition to 'settled' commit in ONE transaction, so a retry after a
// crash re-executes from a job that never settled — the spend is never
// added twice for one job.
func (e *AgentEnforcer) RecordAgentSpendExactAt(ctx context.Context, db SpendExecutor, agentID string, amount money.MicroUSD, tokensIn, tokensOut int64, requestTime time.Time) error {
	if agentID == "" || db == nil {
		return nil
	}
	if amount < 0 {
		amount = 0
	}
	day := e.now().UTC().Format("2006-01-02")
	if !requestTime.IsZero() {
		day = requestTime.UTC().Format("2006-01-02")
	}

	_, err := db.Exec(ctx,
		`INSERT INTO agent_spend_daily (agent_id, day, cost_cents, cost_micro_usd, tokens_in, tokens_out)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (agent_id, day)
		 DO UPDATE SET cost_cents      = agent_spend_daily.cost_cents + $3,
		               cost_micro_usd  = agent_spend_daily.cost_micro_usd + $4,
		               tokens_in       = agent_spend_daily.tokens_in + $5,
		               tokens_out      = agent_spend_daily.tokens_out + $6`,
		agentID, day, amount.Cents(), int64(amount), tokensIn, tokensOut,
	)
	if err != nil {
		return fmt.Errorf("record exact agent spend: %w", err)
	}
	return nil
}

func (e *AgentEnforcer) getBudget(ctx context.Context, agentID string) (*agentBudget, error) {
	// Fast path under the read lock — different agents never contend here.
	e.mu.RLock()
	if b, ok := e.cache[agentID]; ok && time.Since(b.cachedAt) < e.ttl {
		e.mu.RUnlock()
		return e.fromCache(b)
	}
	e.mu.RUnlock()

	// Miss: the DB query runs OUTSIDE every lock (pattern:
	// credits.Store.GetBalance) — the write lock below guards only the
	// cache write, so a slow budget read for one agent never serializes
	// every other tenant. Concurrent misses for the same agent may each
	// query; the row is identical, so the last write wins safely.
	var limit int64
	err := e.db.QueryRow(ctx,
		`SELECT daily_limit_cents FROM agent_budgets WHERE agent_id = $1`,
		agentID,
	).Scan(&limit)

	b := &agentBudget{cachedAt: e.now()}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			b.absent = true
			e.mu.Lock()
			e.cache[agentID] = b
			e.mu.Unlock()
			return nil, ErrNoAgentBudget
		}
		return nil, err
	}

	b.dailyLimitCents = limit
	e.mu.Lock()
	e.cache[agentID] = b
	e.mu.Unlock()
	return b, nil
}

func (e *AgentEnforcer) fromCache(b *agentBudget) (*agentBudget, error) {
	if b.absent {
		return nil, ErrNoAgentBudget
	}
	return b, nil
}

func (e *AgentEnforcer) getSpendToday(ctx context.Context, agentID, day string) (int64, error) {
	var spend int64
	err := e.db.QueryRow(ctx,
		`SELECT COALESCE(cost_cents, 0) FROM agent_spend_daily WHERE agent_id = $1 AND day = $2`,
		agentID, day,
	).Scan(&spend)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return spend, nil
}

// ClearCache invalidates a cached agent budget (called after budget updates).
func (e *AgentEnforcer) ClearCache(agentID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.cache, agentID)
}

// --- internal model/tool loop accounting (N06-P07-T03) ---

// ErrLoopBudgetExceeded is returned by LoopBudget.Admit when an external
// request's internal model/tool loop (policy-invoked detector calls, agent
// loops) exhausted its per-episode hop allowance. Callers must treat it as
// fail-closed: the internal hop does not run, and the surrounding policy's
// on_error semantics decide the request outcome.
var ErrLoopBudgetExceeded = errors.New("internal loop budget exceeded")

// DefaultLoopMaxHops bounds the internal model hops one external request may
// trigger. Real policy chains compose a handful of detector steps (parallel
// groups share one episode); a single-digit cap leaves every legitimate
// configuration room while pinning a runaway loop to a bounded multiple of
// one hop's §5 bound instead of an unbounded hop count.
const DefaultLoopMaxHops = 8

// DefaultLoopTTL bounds how long an episode's counter survives inactivity.
// The TTL is the leak guard: the best-effort Release at request end may
// never fire (crash, missing hook), so idle episodes expire.
const DefaultLoopTTL = time.Minute

// loopEpisode tracks one external request's admitted internal hops.
type loopEpisode struct {
	hops     int
	lastSeen time.Time
}

// LoopBudget bounds the INTERNAL model hops a single external request may
// spend (N06-P07-T03). Interactive traffic is bounded per request by §5
// admission; the hops a policy detector or an agent tool loop triggers
// INSIDE one external request previously had no loop-level bound. The
// budget is in-memory and best-effort by design — exactly one bound per
// episode, the count of internal hops. Per-hop spend admission and
// settlement stay with the §5 controller; losing this map only costs the
// loop-level bound, never correctness (the fail-open shape of the G3 token
// budgets).
//
// A nil *LoopBudget disables loop accounting: Admit always allows. Deploys
// opt in by wiring a non-nil budget.
type LoopBudget struct {
	mu      sync.Mutex
	maxHops int
	ttl     time.Duration
	now     func() time.Time
	byKey   map[string]*loopEpisode
}

// NewLoopBudget builds the loop budget. maxHops <= 0 selects
// DefaultLoopMaxHops; ttl <= 0 selects DefaultLoopTTL.
func NewLoopBudget(maxHops int, ttl time.Duration) *LoopBudget {
	if maxHops <= 0 {
		maxHops = DefaultLoopMaxHops
	}
	if ttl <= 0 {
		ttl = DefaultLoopTTL
	}
	return &LoopBudget{
		maxHops: maxHops,
		ttl:     ttl,
		now:     time.Now,
		byKey:   make(map[string]*loopEpisode),
	}
}

// Admit counts one internal model hop for episode (the external request's
// request id). Unknown episodes start a fresh counter; an episode at the cap
// returns ErrLoopBudgetExceeded and does NOT count the refused hop. An empty
// episode is unattributable (no request id rode the context) and allows
// without tracking — the same allow-on-missing-identity shape the agent
// enforcer uses. Episodes idle past the TTL are swept lazily.
func (b *LoopBudget) Admit(episode string) error {
	if b == nil || episode == "" {
		return nil
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(now)
	ep, ok := b.byKey[episode]
	if !ok {
		b.byKey[episode] = &loopEpisode{hops: 1, lastSeen: now}
		return nil
	}
	if ep.hops >= b.maxHops {
		return fmt.Errorf("%w: episode %q already spent %d internal model hops", ErrLoopBudgetExceeded, episode, ep.hops)
	}
	ep.hops++
	ep.lastSeen = now
	return nil
}

// Hops reports the episode's admitted hop count (0 for unknown episodes).
func (b *LoopBudget) Hops(episode string) int {
	if b == nil || episode == "" {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ep, ok := b.byKey[episode]; ok {
		return ep.hops
	}
	return 0
}

// Release drops the episode's accounting when the external request ends.
// Best-effort: the TTL sweep bounds any leaked episode.
func (b *LoopBudget) Release(episode string) {
	if b == nil || episode == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byKey, episode)
}

// sweepLocked prunes episodes idle past the TTL. Caller holds b.mu.
func (b *LoopBudget) sweepLocked(now time.Time) {
	for k, ep := range b.byKey {
		if now.Sub(ep.lastSeen) > b.ttl {
			delete(b.byKey, k)
		}
	}
}
