package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
)

// Settlement worker (AF-06): the durable executor of settlement_jobs.
//
// Cost-field contract on request events (explicit, per the card):
//
//   - estimated_cost_usd  — BASE cost: what the upstream provider charge is
//     estimated at. Drives the agent_spend budget side effect and is the
//     FALLBACK for the wallet charge when no resale price exists.
//   - resale_cost_usd     — RESALE price: the org-facing charge. When a
//     positive quote exists it wins over the base cost for the
//     resale_deduction wallet charge (resale==0 keeps the legacy meaning
//     "no resale price, fall back to base").
//   - shadow rows         — request.shadow_completed mirrors are NEVER
//     charged (no resale_deduction / agent_spend intent is created; the
//     consumer double-charge guard). Cache hits and request.budget_exceeded
//     keep the existing accounting contract: a completed cache-hit event
//     still carries quotes and settles normally; budget-blocked requests
//     create no charge intents at all. request.failed bills priced partial
//     usage in enforce mode (NEXT-18d) EXCEPT termination=upstream_error,
//     in any mode, would-be cost exported to absorbed_upstream_error.
//
// Both quote fields are validated at the event boundary (eventQuote): exact
// micro-USD, with unknown price/usage a distinct state that never bills.
//
// Execution model:
//
//   - Unique business identity (org_id, request_id, charge_kind) — the
//     settlement_jobs unique constraint. One charge per identity, ever.
//   - States: pending → processing (leased) → settled | retry |
//     requires_attention. retry jobs re-enter after next_attempt_at
//     (exponential backoff with full jitter — no busy loop); a 'processing'
//     job whose lease expired is recovered back to 'retry' (crashed
//     executor). requires_attention is the durable-debt / diagnostic
//     terminal state: insufficient funds after the cost was already
//     incurred, missing wallet, an identity conflict, or an exhausted retry
//     budget. Those rows stay visible in reconcile queries and metrics —
//     they never silently disappear and never silently bill zero.
//   - Transient error ≠ terminal success: only a committed side effect
//     settles a job.
//   - Idempotency of every money/budget side effect:
//       resale_deduction → credits.Store.DeductMicro, DB-unique per
//       (org, request_id, 'usage'); a retry after a committed charge is a
//       no-op (one charge, exact amount_micro_usd — the AF-05 contract, not
//       the legacy cent-rounded path).
//       agent_spend     → spend upsert + job settle commit in ONE
//       transaction (RecordAgentSpendExact): a crash rolls both back, a
//       retry re-executes cleanly, the spend is never added twice.
//       team_spend      → spend upsert + job settle commit in ONE
//       monthly budget accounting has the same exactly-once guarantee, with
//       the period ("2006-01") frozen in the intent payload at request time
//       (ADR I5) and the exact micro-USD amount applied verbatim to
//       team_spend_monthly.spend_micro_usd.
//   - The grace floor is never bypassed: charges go through DeductMicro,
//     which enforces it; insufficiency becomes durable debt, not an
//     overdraft-free force-through.
//
// This card does NOT make concurrent in-flight admission cost bounded —
// durable settlement keeps the debt and retries, the billing hard cap
// remains NEXT-18 (reservations) and is not claimed here.

// ErrPoisonJob marks a settlement job whose payload or charge kind violates
// the intent contract: it can never succeed, so it goes to
// requires_attention immediately instead of burning the retry budget (no
// infinite busy loop on an undecodable job).
var ErrPoisonJob = errors.New("settlement job violates the intent contract")

// SettlementDB is the database surface of the settlement worker. The real
// implementation is *pgxpool.Pool.
type SettlementDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
}

const (
	// claimReadyJobs leases due jobs atomically: SKIP LOCKED lets two
	// replicas work the same queue without colliding; the subquery locks
	// exactly the rows the outer UPDATE takes. The CTE re-ordering gives a
	// deterministic execution order (creation order): UPDATE ... RETURNING
	// alone makes no row-order promise.
	claimReadyJobsQuery = `WITH claimed AS (
			UPDATE settlement_jobs SET
				status = 'processing',
				attempts = attempts + 1,
				lease_until = now() + make_interval(secs => $1),
				updated_at = now()
			WHERE id IN (
				SELECT id FROM settlement_jobs
				WHERE status IN ('pending', 'retry') AND next_attempt_at <= now()
				ORDER BY created_at, id
				LIMIT $2
				FOR UPDATE SKIP LOCKED
			)
			RETURNING id, org_id, request_id, charge_kind, amount_micro_usd, amount_cents, payload, attempts
		)
		SELECT id, org_id, request_id, charge_kind, amount_micro_usd, amount_cents, payload, attempts
		FROM claimed
		ORDER BY id`

	// recoverExpiredLeases returns processing jobs whose executor died
	// (lease deadline passed) to the retry queue. The attempts counter
	// already includes the dead attempt; the normal retry budget and
	// backoff apply from here.
	recoverExpiredLeasesQuery = `UPDATE settlement_jobs SET
			status = 'retry',
			next_attempt_at = now(),
			lease_until = NULL,
			updated_at = now()
		WHERE status = 'processing'
		  AND lease_until IS NOT NULL AND lease_until < now()`

	// markSettledQuery marks a job settled and records the §5.3 Settle
	// terminal-state write the batch executor does (settlement_batch.go
	// writeTerminalStates): the key lands exactly when the reserve
	// decrement applied ($2 NULL — legacy/ledger-only settle — keeps the
	// payload untouched), so the NEXT-18e reconcile sums the released
	// remainder from keys that are atomic with status='settled'.
	// W-LOGG: the update is conditioned on status='processing' — the state
	// the claim lease holds — and the caller checks the affected row count:
	// a lease lost to the expired-lease recovery between claim and settle
	// must roll the whole settlement transaction back instead of settling
	// (or double-settling) a job another worker already owns.
	markSettledQuery = `UPDATE settlement_jobs SET
			status = 'settled',
			lease_until = NULL,
			last_error = NULL,
			updated_at = now(),
			payload = CASE WHEN $2::bigint IS NULL THEN payload
				ELSE jsonb_set(COALESCE(payload, '{}'::jsonb), '{` + budget.ReconcileSettleKey + `}', to_jsonb($2::bigint), true) END
		WHERE id = $1 AND status = 'processing'`

	// settlementAdvisoryLockQuery is the per-org money-writer lock (§5.3):
	// the same key DeductMicro, Grant, Return, SettleDecrement and the
	// batch executor serialize on, so a per-job settle transaction can
	// never interleave with them on one scope row.
	settlementAdvisoryLockQuery = `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`

	markRetryQuery = `UPDATE settlement_jobs SET
			status = 'retry',
			next_attempt_at = now() + make_interval(secs => $2),
			lease_until = NULL,
			last_error = $3,
			updated_at = now()
		WHERE id = $1`

	markRequiresAttentionQuery = `UPDATE settlement_jobs SET
			status = 'requires_attention',
			lease_until = NULL,
			last_error = $2,
			updated_at = now()
		WHERE id = $1`

	settlementBacklogQuery = `SELECT status, count(*) FROM settlement_jobs
		WHERE status IN ('pending', 'retry', 'processing', 'requires_attention', 'pending_price', 'unknown')
		GROUP BY status`

	// unknown-cost pending_price records past their deadline as terminal
	// 'unknown': never billed, never a confirmed zero, durably visible. The
	// rows are never claimable, so this pass is the only state transition
	// they ever take; 'unknown' rows are never deleted by the settled
	// retention (only 'settled' rows are).
	expirePendingPriceQuery = `UPDATE settlement_jobs SET
			status = 'unknown',
			lease_until = NULL,
			last_error = $2,
			updated_at = now()
		WHERE status = 'pending_price'
		  AND created_at < now() - make_interval(secs => $1)`

	// inboxRetentionDelete removes one bounded batch of expired inbox rows.
	// The durable inbox is the delivery authority; rows older than the
	// retention window cannot be re-delivered by the stream (PEL reclaim
	// and DLQ horizons are days, retention is a month), and every monetary
	// side effect stays idempotent even if a row were removed early.
	inboxRetentionDeleteQuery = `DELETE FROM event_inbox WHERE id IN (
			SELECT id FROM event_inbox
			WHERE created_at < now() - make_interval(secs => $1)
			ORDER BY created_at, id
			LIMIT $2
		)`

	// settledRetentionDeleteQuery (AF-16, handed off by AF-06) removes one
	// bounded batch of terminal 'settled' jobs past the retention window, so
	// the durable work queue cannot grow without bound. ONLY 'settled' rows
	// are removed: pending/retry/processing are live work, requires_attention
	// rows are durable debts that must stay visible for reconciliation. A
	// settled row may be deleted only because the retention window exceeds
	// every possible redelivery horizon of the source stream (PEL reclaim and
	// DLQ horizons are days; default retention is 90 days) — the unique
	// business identity (org_id, request_id, charge_kind) is the exactly-once
	// authority for the agent-spend side effect, so an identity must never be
	// re-inserted within a replay horizon.
	settledRetentionDeleteQuery = `DELETE FROM settlement_jobs WHERE id IN (
			SELECT id FROM settlement_jobs
			WHERE status = 'settled' AND updated_at < now() - make_interval(secs => $1)
			ORDER BY updated_at, id
			LIMIT $2
		)`
)

// SettlementConfig bounds the worker loop. Zero fields fall back to
// DefaultSettlementConfig values.
type SettlementConfig struct {
	// Interval is the poll tick. The loop never spins between ticks.
	Interval time.Duration
	// BatchSize is the claim batch per query.
	BatchSize int
	// MaxBatchesPerTick bounds how much one tick drains.
	MaxBatchesPerTick int
	// LeaseTTL is how long a claim stays 'processing' before another
	// worker may recover it (must exceed the slowest execution).
	LeaseTTL time.Duration
	// BackoffBase / BackoffMax shape the full-jitter retry backoff.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// MaxAttempts is the execution budget before a repeatedly-failing job
	// becomes requires_attention (no infinite retry, no silent drop).
	MaxAttempts int
	// InboxRetention bounds event_inbox age; InboxCleanupEvery the cleanup
	// cadence; InboxCleanupBatch the per-statement delete bound.
	InboxRetention     time.Duration
	InboxCleanupEvery  time.Duration
	InboxCleanupBatch  int64
	InboxCleanupPasses int
	// SettledRetention bounds 'settled' settlement_jobs age (AF-16, handed
	// off by AF-06); SettledCleanupEvery/Batch/Passes bound the cleanup the
	// same way as the inbox retention. Non-settled states are never removed.
	SettledRetention     time.Duration
	SettledCleanupEvery  time.Duration
	SettledCleanupBatch  int64
	SettledCleanupPasses int
	// WalletFloorCents is the grace floor the batched wallet settlement
	// falls back to when an org has no explicit grace_floor_cents (ADR-0001
	// §8; the credits.Store default, −$1.00). WalletFloorSet distinguishes
	// an explicit "no overdraft" 0 from the unset case.
	WalletFloorCents int64
	WalletFloorSet   bool
	// PendingPriceExpiry is how long an unknown-cost pending_price record
	// stays visible before the expiry pass terminates it as 'unknown' (the
	// durable never-billed end state; owner decision 2026-10-18: 24 hours).
	PendingPriceExpiry time.Duration
}

// DefaultSettlementConfig returns production-safe defaults.
func DefaultSettlementConfig() SettlementConfig {
	return SettlementConfig{
		Interval:           time.Second,
		BatchSize:          50,
		MaxBatchesPerTick:  10,
		LeaseTTL:           30 * time.Second,
		BackoffBase:        time.Second,
		BackoffMax:         5 * time.Minute,
		MaxAttempts:        12,
		InboxRetention:     30 * 24 * time.Hour,
		InboxCleanupEvery:  time.Hour,
		InboxCleanupBatch:  500,
		InboxCleanupPasses: 40,
		// 90 days: the agent-spend exactly-once authority is the unique
		// (org_id, request_id, charge_kind) job row, so settled rows may be
		// removed only far beyond any stream redelivery horizon (days).
		SettledRetention:     90 * 24 * time.Hour,
		SettledCleanupEvery:  time.Hour,
		SettledCleanupBatch:  500,
		SettledCleanupPasses: 40,
		// Batched wallet settlement shares the credits.Store grace default
		// (AF-01); an org's explicit grace_floor_cents column (ADR §8) wins
		// over this fallback inside the batch transaction.
		WalletFloorCents: -100,
		WalletFloorSet:   true,
		// 'unknown' after 24 hours (never billed, never a confirmed zero).
		PendingPriceExpiry: 24 * time.Hour,
	}
}

func (c SettlementConfig) withDefaults() SettlementConfig {
	d := DefaultSettlementConfig()
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = d.BatchSize
	}
	if c.MaxBatchesPerTick <= 0 {
		c.MaxBatchesPerTick = d.MaxBatchesPerTick
	}
	if c.LeaseTTL <= 0 {
		c.LeaseTTL = d.LeaseTTL
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = d.BackoffBase
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = d.BackoffMax
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = d.MaxAttempts
	}
	if c.InboxRetention <= 0 {
		c.InboxRetention = d.InboxRetention
	}
	if c.InboxCleanupEvery <= 0 {
		c.InboxCleanupEvery = d.InboxCleanupEvery
	}
	if c.InboxCleanupBatch <= 0 {
		c.InboxCleanupBatch = d.InboxCleanupBatch
	}
	if c.InboxCleanupPasses <= 0 {
		c.InboxCleanupPasses = d.InboxCleanupPasses
	}
	if c.SettledRetention <= 0 {
		c.SettledRetention = d.SettledRetention
	}
	if c.SettledCleanupEvery <= 0 {
		c.SettledCleanupEvery = d.SettledCleanupEvery
	}
	if c.SettledCleanupBatch <= 0 {
		c.SettledCleanupBatch = d.SettledCleanupBatch
	}
	if c.SettledCleanupPasses <= 0 {
		c.SettledCleanupPasses = d.SettledCleanupPasses
	}
	if !c.WalletFloorSet {
		c.WalletFloorCents = d.WalletFloorCents
		c.WalletFloorSet = true
	}
	if c.PendingPriceExpiry <= 0 {
		c.PendingPriceExpiry = d.PendingPriceExpiry
	}
	return c
}

// settlementJob is one claimed work item. AmountMicro is the exact charge
// (AF-05 contract); AmountCents stays the rounded compatibility projection.
type settlementJob struct {
	ID          int64
	OrgID       string
	RequestID   string
	ChargeKind  string
	AmountMicro money.MicroUSD
	AmountCents int64
	Payload     []byte
	Attempts    int
	NextBackoff time.Duration // filled at claim time for observability
}

// SettlementWorker drains and settles settlement_jobs. Run owns one
// goroutine; tick is safe for concurrent use in tests but production wiring
// starts exactly one worker per process (replicas coordinate via SKIP
// LOCKED, not via shared memory).
type SettlementWorker struct {
	db           SettlementDB
	creditStore  *credits.Store
	deductor     *Deductor
	agentSpender AgentSpender
	cfg          SettlementConfig
	logger       *slog.Logger

	cleanupMu    sync.Mutex
	lastCleanup  time.Time
	lastSettled  time.Time
	cleanupNower func() time.Time
}

// NewSettlementWorker builds the worker over a database pool, the credit
// store (nil disables resale execution) and the exact agent spender (nil
// disables agent-spend execution). Jobs of a disabled kind are parked in
// requires_attention with a diagnostic instead of being retried forever.
func NewSettlementWorker(db SettlementDB, store *credits.Store, agentSpender AgentSpender, logger *slog.Logger) *SettlementWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &SettlementWorker{
		db:           db,
		creditStore:  store,
		deductor:     NewDeductor(store, logger),
		agentSpender: agentSpender,
		cfg:          DefaultSettlementConfig(),
		logger:       logger.With("component", "settlement-worker"),
		cleanupNower: time.Now,
	}
}

// WithConfig overrides the loop configuration (tests, tuned deployments).
func (w *SettlementWorker) WithConfig(cfg SettlementConfig) *SettlementWorker {
	w.cfg = cfg.withDefaults()
	return w
}

// Run drives the worker until ctx is cancelled: recover dead leases, drain
// due jobs in bounded batches, publish backlog visibility, and run the
// bounded event_inbox retention. Ticker-driven — never a busy loop.
func (w *SettlementWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	w.logger.Info("settlement worker started",
		slog.Duration("interval", w.cfg.Interval),
		slog.Int("batch_size", w.cfg.BatchSize),
		slog.Duration("lease_ttl", w.cfg.LeaseTTL),
		slog.Int("max_attempts", w.cfg.MaxAttempts),
	)
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("settlement worker stopping", slog.String("reason", ctx.Err().Error()))
			return nil
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick performs one bounded maintenance pass. Errors are logged, never
// fatal: a failed pass is retried on the next tick.
func (w *SettlementWorker) tick(ctx context.Context) {
	if err := w.recoverExpiredLeases(ctx); err != nil {
		w.logger.Warn("lease recovery failed", slog.String("error", err.Error()))
	}
	w.expirePendingPrice(ctx)

	for batch := 0; batch < w.cfg.MaxBatchesPerTick; batch++ {
		jobs, err := w.claimBatch(ctx)
		if err != nil {
			w.logger.Warn("settlement claim failed", slog.String("error", err.Error()))
			return
		}
		if len(jobs) == 0 {
			break
		}
		// NEXT-18d (§5.5): jobs of one org apply as ONE batch transaction —
		// ledger, spend upserts, job transitions and the reserve decrement
		// commit together, semantically equivalent to the sequential
		// per-job execution. Singletons and any failed batch fall back to
		// the per-job executor, which is the reference semantics.
		for _, group := range groupJobsByOrg(jobs) {
			if len(group) > 1 && w.executeOrgBatch(ctx, group) {
				continue
			}
			for i := range group {
				w.executeJob(ctx, &group[i])
			}
		}
	}

	w.publishBacklog(ctx)
	w.cleanupInbox(ctx)
	w.cleanupSettledJobs(ctx)
}

// settleAllowanceLink decodes the reserve linkage an intent payload carries
// (NEXT-18d): the allocation whose reserve the settle decrements and the
// request's per-scope bound. Legacy payloads decode to zero values — a
// ledger-only settle, no reserve interaction. SettledDecrementMicroUSD is
// status='settled', so its presence in a re-claimed job's payload means the
// earlier settle already released the reserve — this one is a no-op.
type settleAllowanceLink struct {
	AllowanceID   int64 `json:"allowance_id"`
	BoundMicroUSD int64 `json:"bound_micro_usd"`
	// SettledDecrementMicroUSD is non-nil when the job's settle already
	// committed its reserve release (the crash-window replay marker).
	SettledDecrementMicroUSD *int64 `json:"settle_decrement_micro_usd"`
}

func decodeSettleAllowanceLink(payload []byte) settleAllowanceLink {
	var link settleAllowanceLink
	if err := json.Unmarshal(payload, &link); err != nil {
		metrics.SilentFailure("audit_ingest_decode", "settlement_link")
	}
	if link.AllowanceID < 0 || link.BoundMicroUSD < 0 {
		return settleAllowanceLink{}
	}
	return link
}

// groupJobsByOrg partitions claimed jobs into per-org groups, preserving the
// claim's (created_at, id) order inside every group — the order the §5.5
// sequential-equivalence contract is defined on.
func groupJobsByOrg(jobs []settlementJob) [][]settlementJob {
	groups := make([][]settlementJob, 0, len(jobs))
	index := make(map[string]int, len(jobs))
	for _, job := range jobs {
		if idx, ok := index[job.OrgID]; ok {
			groups[idx] = append(groups[idx], job)
			continue
		}
		index[job.OrgID] = len(groups)
		groups = append(groups, []settlementJob{job})
	}
	return groups
}

// executeOrgBatch applies one org's claimed jobs through the §5.5 batch
// executor and reports the committed dispositions. It returns true when the
// batch transaction committed (the jobs are terminal — no per-job work is
// left); false means the caller must fall back to the per-job executor
// (nothing committed on an error path, so re-execution is safe).
func (w *SettlementWorker) executeOrgBatch(ctx context.Context, group []settlementJob) bool {
	entries := make([]budget.SettleEntry, 0, len(group))
	for _, job := range group {
		link := decodeSettleAllowanceLink(job.Payload)
		entries = append(entries, budget.SettleEntry{
			JobID:       job.ID,
			RequestID:   job.RequestID,
			Kind:        job.ChargeKind,
			Amount:      job.AmountMicro,
			Payload:     job.Payload,
			AllowanceID: link.AllowanceID,
			Bound:       money.MicroUSD(link.BoundMicroUSD),
		})
	}

	// The wallet floor is the credit store's — the exact floor the per-job
	// DeductMicro path enforces; the config field only covers deployments
	// without a configured store.
	floorCents := w.cfg.WalletFloorCents
	if w.creditStore != nil {
		floorCents = w.creditStore.GracePeriodCents()
	}

	dispositions, err := budget.SettleOrgBatch(ctx, w.db, group[0].OrgID, floorCents, entries, budget.BatchSpenders{Agent: w.agentSpender})
	if err != nil {
		w.logger.Warn("settlement org batch failed — falling back to per-job execution",
			slog.String("org_id", group[0].OrgID),
			slog.Int("jobs", len(group)),
			slog.String("error", err.Error()),
		)
		return false
	}
	metrics.SettlementBatchSize.Observe(float64(len(entries)))

	for _, job := range group {
		d := dispositions[job.ID]
		if d.Settled {
			metrics.SettlementJobsTotal.WithLabelValues(job.ChargeKind, "settled").Inc()
			w.logger.Info("settlement job settled (batch)",
				slog.Int64("job_id", job.ID),
				slog.String("charge_kind", job.ChargeKind),
				slog.String("org_id", job.OrgID),
				slog.String("request_id", job.RequestID),
				slog.Int64("amount_micro_usd", int64(job.AmountMicro)),
				slog.Int64("reserve_decrement_micro_usd", d.DecrementMicroUSD),
			)
			continue
		}
		if d.Reason == budget.ReasonInsufficientCredits {
			metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient").Inc()
		}
		if d.Reason == budget.ReasonNoWallet {
			metrics.CreditDeductionSkippedTotal.WithLabelValues("no_wallet").Inc()
		}
		metrics.SettlementJobsTotal.WithLabelValues(job.ChargeKind, "requires_attention").Inc()
		w.logger.Error("settlement job requires attention (batch) — parked as durable debt/diagnostic",
			slog.Int64("job_id", job.ID),
			slog.String("charge_kind", job.ChargeKind),
			slog.String("org_id", job.OrgID),
			slog.String("request_id", job.RequestID),
			slog.Int64("amount_micro_usd", int64(job.AmountMicro)),
			slog.String("reason", d.Reason),
		)
	}
	return true
}

func (w *SettlementWorker) recoverExpiredLeases(ctx context.Context) error {
	tag, err := w.db.Exec(ctx, recoverExpiredLeasesQuery)
	if err != nil {
		return fmt.Errorf("recover expired settlement leases: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 {
		w.logger.Warn("recovered settlement jobs with expired leases", slog.Int64("count", n))
	}
	return nil
}

// pending_price records older than the configured expiry terminate as
// 'unknown' — the durable, never-billed end state of an unresolved price.
func (w *SettlementWorker) expirePendingPrice(ctx context.Context) {
	tag, err := w.db.Exec(ctx, expirePendingPriceQuery, w.cfg.PendingPriceExpiry.Seconds(),
		"pending price expired after deadline (R041 D2): cost stayed unknown, never billed")
	if err != nil {
		w.logger.Warn("pending_price expiry pass failed", slog.String("error", err.Error()))
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		metrics.SettlementPendingPriceExpiredTotal.Add(float64(n))
		w.logger.Warn("unknown-cost pending_price records expired to 'unknown'",
			slog.Int64("count", n),
			slog.Duration("deadline", w.cfg.PendingPriceExpiry),
		)
	}
}

func (w *SettlementWorker) claimBatch(ctx context.Context) ([]settlementJob, error) {
	rows, err := w.db.Query(ctx, claimReadyJobsQuery, w.cfg.LeaseTTL.Seconds(), w.cfg.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("claim settlement jobs: %w", err)
	}
	defer rows.Close()

	var jobs []settlementJob
	for rows.Next() {
		var job settlementJob
		var amountMicro int64
		if err := rows.Scan(&job.ID, &job.OrgID, &job.RequestID, &job.ChargeKind, &amountMicro, &job.AmountCents, &job.Payload, &job.Attempts); err != nil {
			return nil, fmt.Errorf("scan settlement job: %w", err)
		}
		job.AmountMicro = money.MicroUSD(amountMicro)
		job.NextBackoff = w.backoff(job.Attempts)
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// executeJob runs one claimed job and records the outcome. Only a committed
// side effect settles; every failure is classified by classifyFailure.
func (w *SettlementWorker) executeJob(ctx context.Context, job *settlementJob) {
	err := w.execute(ctx, job)
	if err == nil {
		w.settle(ctx, job)
		return
	}

	disposition, reason := w.classifyFailure(err, job.Attempts)
	if disposition == "retry" {
		metrics.SettlementJobsTotal.WithLabelValues(job.ChargeKind, "retry").Inc()
		w.markRetry(ctx, job, err)
		return
	}
	metrics.SettlementJobsTotal.WithLabelValues(job.ChargeKind, "requires_attention").Inc()
	w.markRequiresAttention(ctx, job, err, reason)
}

// execute performs the money side effect for the job's charge kind.
func (w *SettlementWorker) execute(ctx context.Context, job *settlementJob) error {
	switch job.ChargeKind {
	case ChargeKindResaleDeduction:
		return w.executeResaleDeduction(ctx, job)
	case ChargeKindAgentSpend:
		return w.executeAgentSpend(ctx, job)
	case ChargeKindTeamSpend:
		return w.executeTeamSpend(ctx, job)
	case ChargeKindSessionSpend:
		return w.executeSessionSpend(ctx, job)
	default:
		return fmt.Errorf("%w: job %d has unknown charge kind %q", ErrPoisonJob, job.ID, job.ChargeKind)
	}
}

// executeResaleDeduction charges the wallet the exact intent amount.
// Idempotency: credits.Store rejects a second usage row for the same
// (org, request) — a retry after a committed charge is a no-op.
func (w *SettlementWorker) executeResaleDeduction(ctx context.Context, job *settlementJob) error {
	if w.creditStore == nil || w.deductor == nil {
		return fmt.Errorf("%w: resale credit store is not configured", ErrNoChargeTarget)
	}
	var payload resaleChargePayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("%w: decode resale payload for job %d: %v", ErrPoisonJob, job.ID, err)
	}
	return w.deductor.ProcessDeduction(ctx, job.OrgID, payload.Model, job.RequestID, job.AmountMicro, money.QuotePositive, payload.TokensIn, payload.TokensOut)
}

// beginMoneyTx opens a settlement transaction under the per-org advisory
// lock (§5.3 canonical lock order: the lock before any scope row — the
// order DeductMicro, Grant, Return, SettleDecrement and the batch executor
// use, so a per-job settle can neither interleave with them on a scope row
// nor deadlock against them).
func (w *SettlementWorker) beginMoneyTx(ctx context.Context, orgID string) (pgx.Tx, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin settlement transaction: %w", err)
	}
	if _, err := tx.Exec(ctx, settlementAdvisoryLockQuery, orgID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("settlement advisory lock: %w", err)
	}
	return tx, nil
}

// settleReserveRelease applies the §5.3 Settle step 2 for the job's
// the µUSD amount that left the scope reserve. Zero means a ledger-only
// settle: a legacy payload without a linkage, a released allowance (late
// settle after reconcile), a zero decrement — or a replay of an
// already-settled job, whose payload still carries the reconcile key its
// committed settle wrote (the key is the exactly-once marker: it lands
// atomically with status='settled', never without the decrement).
func (w *SettlementWorker) settleReserveRelease(ctx context.Context, tx pgx.Tx, job *settlementJob) (int64, error) {
	link := decodeSettleAllowanceLink(job.Payload)
	if link.AllowanceID <= 0 || link.SettledDecrementMicroUSD != nil {
		return 0, nil
	}
	return budget.SettleDecrementTx(ctx, tx, job.OrgID, link.AllowanceID, job.AmountMicro, money.MicroUSD(link.BoundMicroUSD))
}

// markSettledWithRelease settles a job the way the batch executor does
// the settle mark — carrying the reconcile payload key exactly when the
// reserve moved — commit in ONE transaction. Any failure rolls the whole
// settlement back: the job retries and never reads as settled.
func (w *SettlementWorker) markSettledWithRelease(ctx context.Context, tx pgx.Tx, job *settlementJob) error {
	decrement, err := w.settleReserveRelease(ctx, tx, job)
	if err != nil {
		return err
	}
	var decAmt any
	if decrement > 0 {
		decAmt = decrement
	}
	tag, err := tx.Exec(ctx, markSettledQuery, job.ID, decAmt)
	if err != nil {
		return fmt.Errorf("mark settled: %w", err)
	}
	// W-LOGG: zero rows means the job is no longer 'processing' (the lease
	// was recovered by another worker between the claim and this settle).
	// The error rolls back the money side effect in this same transaction,
	// so the re-owning worker re-executes cleanly — exactly once.
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("mark settled: job %d is not in processing state (lease lost or already settled)", job.ID)
	}
	return nil
}

// executeAgentSpend records the agent's daily spend and settles the job in
// ONE transaction — the exactly-once guard for this side effect. The same
// transaction releases the reserve of the intent's allowance (§5.3 Settle
// step 2) and records the reconcile payload key.
func (w *SettlementWorker) executeAgentSpend(ctx context.Context, job *settlementJob) error {
	if w.agentSpender == nil {
		return fmt.Errorf("%w: agent budget spender is not configured", ErrNoChargeTarget)
	}
	var payload agentSpendPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("%w: decode agent spend payload for job %d: %v", ErrPoisonJob, job.ID, err)
	}
	if payload.AgentID == "" {
		return fmt.Errorf("%w: agent spend job %d carries no agent id", ErrPoisonJob, job.ID)
	}

	tx, err := w.beginMoneyTx(ctx, job.OrgID)
	if err != nil {
		return err
	}
	if err := w.agentSpender.RecordAgentSpendExact(ctx, tx, payload.AgentID, job.AmountMicro, payload.TokensIn, payload.TokensOut); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("record agent spend: %w", err)
	}
	if err := w.markSettledWithRelease(ctx, tx, job); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("mark agent spend settled: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit agent spend: %w", err)
	}
	return nil
}

// executeTeamSpend records the team's monthly budget spend and settles the
// job in ONE transaction — the exactly-once guard for this side effect
// time, ADR I5); a job without team or period can never succeed and is
// poison, not a retry loop.
func (w *SettlementWorker) executeTeamSpend(ctx context.Context, job *settlementJob) error {
	var payload teamSpendPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("%w: decode team spend payload for job %d: %v", ErrPoisonJob, job.ID, err)
	}
	if payload.TeamID == "" {
		return fmt.Errorf("%w: team spend job %d carries no team id", ErrPoisonJob, job.ID)
	}
	if payload.Period == "" {
		return fmt.Errorf("%w: team spend job %d carries no budget period", ErrPoisonJob, job.ID)
	}

	tx, err := w.beginMoneyTx(ctx, job.OrgID)
	if err != nil {
		return err
	}
	if err := budget.RecordTeamSpendExact(ctx, tx, payload.TeamID, payload.Period, job.AmountMicro); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("record team spend: %w", err)
	}
	if err := w.markSettledWithRelease(ctx, tx, job); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("mark team spend settled: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit team spend: %w", err)
	}
	return nil
}

// executeSessionSpend records a session key's spend against its money cap
// (NEXT-18d, ADR-0001 §13) and settles the job in ONE transaction — the
// exactly-once guard for this side effect, mirroring the team path. A job
// without a session key id can never succeed and is poison, not a retry
// loop.
func (w *SettlementWorker) executeSessionSpend(ctx context.Context, job *settlementJob) error {
	var payload sessionSpendPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("%w: decode session spend payload for job %d: %v", ErrPoisonJob, job.ID, err)
	}
	if payload.SessionKeyID == "" {
		return fmt.Errorf("%w: session spend job %d carries no session key id", ErrPoisonJob, job.ID)
	}

	tx, err := w.beginMoneyTx(ctx, job.OrgID)
	if err != nil {
		return err
	}
	if err := budget.RecordSessionSpendExact(ctx, tx, payload.SessionKeyID, job.AmountMicro); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("record session spend: %w", err)
	}
	if err := w.markSettledWithRelease(ctx, tx, job); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("mark session spend settled: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit session spend: %w", err)
	}
	return nil
}

// settle marks a successfully executed resale job settled and releases its
// semantics the batch executor applies per entry. The wallet charge itself
// commits in its own DeductMicro transaction (before this one); the settle
// transaction owns the reserve decrement and the settle mark carrying the
// reconcile payload key, so a crash rolls both back and a retry re-applies
// them exactly once. A re-claimed job whose payload already carries the
// key (settled once, mark externally lost — the pre-batch crash window)
// re-marks settled without touching the reserve again. The agent, team and
// session spend paths settle inside their spend transaction.
func (w *SettlementWorker) settle(ctx context.Context, job *settlementJob) {
	if job.ChargeKind == ChargeKindAgentSpend || job.ChargeKind == ChargeKindTeamSpend || job.ChargeKind == ChargeKindSessionSpend {
		metrics.SettlementJobsTotal.WithLabelValues(job.ChargeKind, "settled").Inc()
		return
	}

	tx, err := w.beginMoneyTx(ctx, job.OrgID)
	if err != nil {
		// The charge is committed; the settle mark is retried after the
		// lease expires and re-runs the (idempotent) charge — never a
		// second charge.
		w.logger.Error("settlement charge committed but settle transaction failed",
			slog.Int64("job_id", job.ID),
			slog.String("error", err.Error()),
		)
		return
	}
	if err := w.markSettledWithRelease(ctx, tx, job); err != nil {
		_ = tx.Rollback(ctx)
		w.logger.Error("settlement charge committed but settle mark failed",
			slog.Int64("job_id", job.ID),
			slog.String("error", err.Error()),
		)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		w.logger.Error("settlement charge committed but settle mark failed",
			slog.Int64("job_id", job.ID),
			slog.String("error", err.Error()),
		)
		return
	}
	metrics.SettlementJobsTotal.WithLabelValues(job.ChargeKind, "settled").Inc()
	w.logger.Info("settlement job settled",
		slog.Int64("job_id", job.ID),
		slog.String("charge_kind", job.ChargeKind),
		slog.String("org_id", job.OrgID),
		slog.String("request_id", job.RequestID),
		slog.Int64("amount_micro_usd", int64(job.AmountMicro)),
	)
}

func (w *SettlementWorker) markRetry(ctx context.Context, job *settlementJob, execErr error) {
	if _, err := w.db.Exec(ctx, markRetryQuery, job.ID, job.NextBackoff.Seconds(), truncateErr(execErr)); err != nil {
		// The lease will expire and recovery re-queues the job — the retry
		// is not lost, only delayed past the lease TTL.
		w.logger.Error("settlement retry mark failed (lease recovery will requeue)",
			slog.Int64("job_id", job.ID),
			slog.String("error", err.Error()),
		)
		return
	}
	w.logger.Warn("settlement job failed, will retry",
		slog.Int64("job_id", job.ID),
		slog.String("charge_kind", job.ChargeKind),
		slog.String("org_id", job.OrgID),
		slog.String("request_id", job.RequestID),
		slog.Int("attempts", job.Attempts),
		slog.Duration("backoff", job.NextBackoff),
		slog.String("error", execErr.Error()),
	)
}

func (w *SettlementWorker) markRequiresAttention(ctx context.Context, job *settlementJob, execErr error, reason string) {
	if _, err := w.db.Exec(ctx, markRequiresAttentionQuery, job.ID, truncateErr(execErr)); err != nil {
		w.logger.Error("settlement requires-attention mark failed",
			slog.Int64("job_id", job.ID),
			slog.String("error", err.Error()),
		)
		return
	}
	w.logger.Error("settlement job requires attention — parked as durable debt/diagnostic",
		slog.Int64("job_id", job.ID),
		slog.String("charge_kind", job.ChargeKind),
		slog.String("org_id", job.OrgID),
		slog.String("request_id", job.RequestID),
		slog.Int64("amount_micro_usd", int64(job.AmountMicro)),
		slog.Int("attempts", job.Attempts),
		slog.String("reason", reason),
		slog.String("error", execErr.Error()),
	)
}

// classifyFailure maps an execution failure to the job disposition.
// Terminal outcomes (insufficient funds after incurred cost, no wallet,
// identity conflicts, poison payloads, exhausted retry budget) become
// requires_attention — durable and visible, never a silent zero.
// Everything else is transient → retry with backoff.
func (w *SettlementWorker) classifyFailure(err error, attempts int) (disposition, reason string) {
	switch {
	case errors.Is(err, ErrNoChargeTarget):
		return "requires_attention", "charge_target_not_configured"
	case errors.Is(err, ErrPoisonJob):
		return "requires_attention", "poison_payload"
	case credits.IsNoWallet(err):
		metrics.CreditDeductionSkippedTotal.WithLabelValues("no_wallet").Inc()
		return "requires_attention", "no_wallet"
	case credits.IsInsufficientCredits(err):
		// The cost was already incurred serving the request: this is
		// durable debt, not a retryable condition and not a silent zero.
		metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient").Inc()
		return "requires_attention", "insufficient_credits"
	case isUniqueViolation(err):
		// A usage ledger row for this request already exists under a
		// DIFFERENT org (the idempotency index is global on request_id) —
		// conflicting identity, charge must not be counted for this job.
		return "requires_attention", "request_identity_conflict"
	case attempts >= w.cfg.MaxAttempts:
		return "requires_attention", "retry_budget_exhausted"
	default:
		return "retry", "transient_error"
	}
}

// isUniqueViolation reports a PostgreSQL unique-violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// backoff computes the full-jitter delay for a job that has burned
// `attempts` attempts: uniform over [0, min(base·2^(attempts-1), max)).
// math/rand is acceptable here — retry jitter, not crypto.
func (w *SettlementWorker) backoff(attempts int) time.Duration {
	window := w.cfg.BackoffBase << uint(maxInt(attempts-1, 0))
	if window > w.cfg.BackoffMax || window <= 0 {
		window = w.cfg.BackoffMax
	}
	//nolint:gosec // safe for exponential-backoff jitter only
	return time.Duration(rand.Int63n(int64(window)))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// truncateErr keeps last_error bounded (payload-controlled strings must not
// grow the row unboundedly).
func truncateErr(err error) string {
	s := err.Error()
	const maxErrLen = 1024
	if len(s) > maxErrLen {
		return s[:maxErrLen]
	}
	return s
}

// publishBacklog updates the per-state backlog gauges (reconcile
// visibility: pending/retry/requires_attention must never grow unseen).
func (w *SettlementWorker) publishBacklog(ctx context.Context) {
	rows, err := w.db.Query(ctx, settlementBacklogQuery)
	if err != nil {
		w.logger.Warn("settlement backlog query failed", slog.String("error", err.Error()))
		return
	}
	defer rows.Close()

	counts := map[string]int64{"pending": 0, "retry": 0, "processing": 0, "requires_attention": 0, "pending_price": 0, "unknown": 0}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			w.logger.Warn("settlement backlog scan failed", slog.String("error", err.Error()))
			return
		}
		counts[status] = n
	}
	if err := rows.Err(); err != nil {
		w.logger.Warn("settlement backlog rows failed", slog.String("error", err.Error()))
		return
	}
	for state, n := range counts {
		metrics.SettlementBacklog.WithLabelValues(state).Set(float64(n))
	}
}

// cleanupInbox runs the bounded event_inbox retention (AF-04 risk closed
// here): deletes at most BatchSize×Passes rows per pass and only every
// InboxCleanupEvery.
func (w *SettlementWorker) cleanupInbox(ctx context.Context) {
	w.cleanupMu.Lock()
	now := w.cleanupNower()
	due := now.Sub(w.lastCleanup) >= w.cfg.InboxCleanupEvery
	if due {
		w.lastCleanup = now
	}
	w.cleanupMu.Unlock()
	if !due {
		return
	}

	var total int64
	for pass := 0; pass < w.cfg.InboxCleanupPasses; pass++ {
		tag, err := w.db.Exec(ctx, inboxRetentionDeleteQuery, w.cfg.InboxRetention.Seconds(), w.cfg.InboxCleanupBatch)
		if err != nil {
			w.logger.Warn("event_inbox retention cleanup failed", slog.String("error", err.Error()))
			return
		}
		deleted := tag.RowsAffected()
		total += deleted
		if deleted < w.cfg.InboxCleanupBatch {
			break
		}
	}
	if total > 0 {
		w.logger.Info("event_inbox retention cleanup", slog.Int64("deleted", total), slog.Duration("retention", w.cfg.InboxRetention))
	}
}

// cleanupSettledJobs runs the bounded 'settled' settlement_jobs retention
// (AF-16, handed off by AF-06): deletes at most SettledCleanupBatch×Passes
// terminal rows per pass, only every SettledCleanupEvery, and never touches
// pending/retry/processing/requires_attention rows (durable work and debts).
func (w *SettlementWorker) cleanupSettledJobs(ctx context.Context) {
	w.cleanupMu.Lock()
	now := w.cleanupNower()
	due := now.Sub(w.lastSettled) >= w.cfg.SettledCleanupEvery
	if due {
		w.lastSettled = now
	}
	w.cleanupMu.Unlock()
	if !due {
		return
	}

	var total int64
	for pass := 0; pass < w.cfg.SettledCleanupPasses; pass++ {
		tag, err := w.db.Exec(ctx, settledRetentionDeleteQuery, w.cfg.SettledRetention.Seconds(), w.cfg.SettledCleanupBatch)
		if err != nil {
			w.logger.Warn("settled jobs retention cleanup failed", slog.String("error", err.Error()))
			return
		}
		deleted := tag.RowsAffected()
		total += deleted
		if deleted < w.cfg.SettledCleanupBatch {
			break
		}
	}
	if total > 0 {
		w.logger.Info("settled jobs retention cleanup", slog.Int64("deleted", total), slog.Duration("retention", w.cfg.SettledRetention))
	}
}

// resaleChargePayload mirrors the intent payload written by the consumer.
type resaleChargePayload struct {
	Model     string  `json:"model"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	ResaleUSD float64 `json:"resale_usd"`
}

// agentSpendPayload mirrors the agent intent payload.
type agentSpendPayload struct {
	AgentID   string `json:"agent_id"`
	TokensIn  int64  `json:"tokens_in"`
	TokensOut int64  `json:"tokens_out"`
}

// "2006-01" budget month fixed at request time (ADR I5).
type teamSpendPayload struct {
	TeamID string `json:"team_id"`
	Period string `json:"period"`
}

// sessionSpendPayload mirrors the session intent payload (NEXT-18d). The
// key id is the `session` scope key (ADR-0001 §4.1).
type sessionSpendPayload struct {
	SessionKeyID string `json:"session_key_id"`
}
