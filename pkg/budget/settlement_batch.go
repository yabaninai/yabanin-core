// Package budget: batched settlement execution (NEXT-18d, ADR-0001 rev. 3
// §5.3 Settle + §5.5). One transaction per org applies every claimed
// settlement job of that org — wallet ledger rows, the exact spend upserts
// of the team/agent/session areas, the job transitions and the reserve
// decrement — so a crash rolls all of a batch back and a retry re-executes
// it cleanly. The batch is semantically EQUIVALENT to applying the jobs
// sequentially in id order (§5.5, property-tested against the per-job
// reference implementations):
//
//   - the sub-cent remainder (AF-05) carries job by job in id order;
//   - a job whose sequential application would cross the grace floor becomes
//     requires_attention WITHOUT touching the wallet, exactly like the
//     per-job path, and later jobs still apply;
//   - usage ledger rows rely on the production partial unique index
//     (ON CONFLICT DO NOTHING): a conflict for the same org is an
//     idempotent no-op settle for that job, a conflict under a DIFFERENT
//     org is the request-identity conflict (never charged here);
//   - the wallet row is updated once with the sum of applied jobs;
//   - reserved_micro_usd of every scope row drops by the sum of
//     min(actual, bound) of APPLIED jobs whose allocation is not released
//     (§5.3 Settle step 2 — the batch form of the NEXT-18a SettleDecrement:
//     same advisory lock, same FOR SHARE released check, same explicit
//     underflow error). A released allocation is ledger-only; the settle
//     amount of every applied decrement is recorded in the job payload
//     under ReconcileSettleKey, the key the NEXT-18a reconcile sums by
//     allowance_id.
//
// Cancel/partial/late-usage semantics (N06-P04 ratified contract D1–D3,
// artifacts/internal-delivery-program/N06-P04/contract.md): cancel and late usage
// complete ONE operation —
//
//   - D1 priced partial (a native provider-usage cancel or an adapted
//     estimated-usage cancel alike — the batch is asymmetry-blind: both
//     arrive as the same positive-amount resale entry, and the entry's
//     Amount, never its payload shape, moves money): exactly one charge of
//     the consumed prefix; a repeated delivery of the same event replays
//     the same job and settles as an idempotent no-op — never a second
//     debit and never a second reserve decrement.
//   - D2 unknown outcome: the producer never creates a claimable wallet
//     intent for an unknown price (the pending_price row stays
//     non-claimable instead). A non-positive wallet entry that reaches
//     the batch is a producer-contract violation surfaced as poison
//     requires_attention — never applied as a zero charge and never
//     written as a zero ledger row (a zero row would poison the request
//     identity against the real late priced event).
//   - D3 absorbed upstream error: the producer creates no charge intents
//     in any mode, so nothing reaches the batch for it.
//   - A usage identity already charged under a DIFFERENT org is the
//     request-identity conflict: parked requires_attention, never
//     charged here.
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
)

// Settle charge kinds — the wire values written by the consumer's intent
// inserts (services/loggerd/consumer) and read here. One kind per reserve
// scope (§4.1).
const (
	SettleKindResale  = "resale_deduction" // wallet scope
	SettleKindTeam    = "team_spend"       // team_month scope
	SettleKindAgent   = "agent_spend"      // agent_day scope
	SettleKindSession = "session_spend"    // session scope
)

// ReconcileSettleKey is the settlement_jobs payload key carrying the µUSD
// amount a settled job removed from its scope reserve (min(actual, bound)).
// The NEXT-18a reservation reconcile sums it per allowance_id to compute the
// released remainder. Keep byte-identical with the store's key.
const ReconcileSettleKey = "settle_decrement_micro_usd"

// Reserve scope kinds (§4.1) as the batch sees them. Unexported mirrors of
// the reservation store's (NEXT-18a) canonical constants: the two lanes
// merge into one package, so these deliberately carry distinct names.
type settleScope string

const (
	settleScopeWallet    settleScope = "wallet"
	settleScopeTeamMonth settleScope = "team_month"
	settleScopeAgentDay  settleScope = "agent_day"
	settleScopeSession   settleScope = "session"

	// settleAllowanceReleased marks an allocation whose reserve reconcile
	// already returned; a late settle is ledger-only for it (§5.3).
	settleAllowanceReleased = "released"
)

// Batch requires-attention reasons — the same disposition strings the
// per-job classification produces, so worker metrics and rows stay uniform.
const (
	ReasonInsufficientCredits = "insufficient_credits"
	ReasonNoWallet            = "no_wallet"
	ReasonIdentityConflict    = "request_identity_conflict"
	ReasonPoisonPayload       = "poison_payload"
	ReasonNoChargeTarget      = "charge_target_not_configured"
)

// ErrBatchReservedUnderflow shape-matches the reservation store's underflow
// sentinel for callers that inspect it; the batch wraps its own instance so
// the two stay distinguishable at the log site.
var ErrBatchReservedUnderflow = errors.New("settlement batch: scope reserve underflow")

// ErrStaleSettlementToken reports a settlement attempt fenced by a newer
// claim of the same settlement job.
var ErrStaleSettlementToken = errors.New("settlement batch: stale fencing token")

// SettleEntry is one claimed settlement job projected for batch execution.
// AllowanceID > 0 links the job to the allocation whose reserve it
// decrements; Bound is that allocation's request bound (§5.3 Finalize
// tuple). Entries MUST be ordered by job id — the sequential-equivalence
// contract is defined on that order.
type SettleEntry struct {
	JobID int64
	// FencingToken is the settlement_jobs.attempts value returned by the
	// worker's claim. Zero preserves compatibility for legacy callers; new
	// settlement workers must pass the claimed value.
	FencingToken int32
	RequestID    string
	Kind         string
	Amount       money.MicroUSD
	Payload      []byte
	AllowanceID  int64
	Bound        money.MicroUSD
	// RequestedAt is the request's own time (ADR I5). When set, the
	// agent-day spend bucket uses it instead of the settle time; zero keeps
	// the settle-time default for callers that predate this field.
	RequestedAt time.Time
}

// BatchDisposition reports one entry's outcome. Settled entries committed
// their side effect (or were an idempotent no-op); non-settled entries are
// parked requires_attention inside the same transaction, with Reason in the
// row's last_error and in the disposition.
type BatchDisposition struct {
	Settled           bool
	Applied           bool   // money moved THIS run (wallet debit or spend upsert)
	DecrementMicroUSD int64  // reserve µUSD removed for this job (0 when none)
	Reason            string // requires_attention reason when !Settled
}

// BatchDB is the store surface of the batch executor (pgx pool in
// production); the executor opens and owns its single transaction.
type BatchDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// BatchAgentSpender is the exact agent-spend writer the batch uses — the
// production implementation is *AgentEnforcer (consumer wiring passes the
// same spender the per-job path uses, so both paths share the day clock).
type BatchAgentSpender interface {
	RecordAgentSpendExact(ctx context.Context, db SpendExecutor, agentID string, amount money.MicroUSD, tokensIn, tokensOut int64) error
}

// BatchAgentSpenderAt is the optional upgrade a batch agent spender
// implements to bucket the agent-day by REQUEST time (ADR I5) instead of
// settle time. *AgentEnforcer implements it; spenders that do not implement
// it keep the settle-time default of BatchAgentSpender.
type BatchAgentSpenderAt interface {
	RecordAgentSpendExactAt(ctx context.Context, db SpendExecutor, agentID string, amount money.MicroUSD, tokensIn, tokensOut int64, requestTime time.Time) error
}

// BatchSpenders carries the exact spend writers that live behind enforcers.
// A nil Agent parks agent_spend entries as charge_target_not_configured —
// the same disposition the per-job path produces for an unconfigured
// spender. Team and session upserts are store-free functions.
type BatchSpenders struct {
	Agent BatchAgentSpender
}

// SettleOrgBatch applies every entry of ONE org in one transaction (§5.5).
// The returned dispositions are durable: settled and requires_attention
// rows are written inside the transaction, so a crash after commit cannot
// re-apply money and a crash before commit cannot lose a job. A returned
// error means NOTHING committed — the caller falls back to the per-job
// executor, which re-runs the whole group from scratch (safe: rollback).
//
// graceFloorCents is the global grace fallback (credits.GracePeriodCents);
// an org's explicit grace_floor_cents column (ADR §8) wins when present.
func SettleOrgBatch(ctx context.Context, db BatchDB, orgID string, graceFloorCents int64, entries []SettleEntry, spenders BatchSpenders) (map[int64]BatchDisposition, error) {
	if orgID == "" {
		return nil, fmt.Errorf("settlement batch: empty org id")
	}
	if db == nil {
		return nil, fmt.Errorf("settlement batch: nil db")
	}
	// Dispositions are keyed by JobID, so a batch that lists the same job
	// twice would collapse two settle attempts into one disposition (an
	// applied entry overwritten by its replay's Applied=false would even
	// hide the decrement). One job = one claimed row = one entry; refuse
	// anything else and let the per-job fallback execute each job exactly
	// once — a repeated event must never charge twice.
	seenJobs := make(map[int64]struct{}, len(entries))
	for _, e := range entries {
		if _, dup := seenJobs[e.JobID]; dup {
			return nil, fmt.Errorf("settlement batch: duplicate job id %d", e.JobID)
		}
		seenJobs[e.JobID] = struct{}{}
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("settlement batch begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// pgx's zero-value TxOptions issues a plain BEGIN and leaves
	// synchronous_commit at the server/session setting. Pin WAL flush
	// acknowledgement locally for this financial transaction, independently
	// of an operator's weaker session default.
	if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		return nil, fmt.Errorf("settlement batch synchronous commit: %w", err)
	}

	// Serialize money writers per org — the same lock key as DeductMicro,
	// Grant and SettleDecrement, so batch and per-job executors can never
	// interleave on one wallet.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return nil, fmt.Errorf("settlement batch advisory lock: %w", err)
	}
	if err := verifySettlementFencing(ctx, tx, entries); err != nil {
		return nil, err
	}

	dispositions := make(map[int64]BatchDisposition, len(entries))

	// Wallet first (canonical lock order §5.3), then the spend areas in
	// team_month → agent_day → session order.
	if err := settleWalletEntries(ctx, tx, orgID, graceFloorCents, entries, dispositions); err != nil {
		return nil, err
	}
	if err := settleSpendEntries(ctx, tx, entries, spenders, dispositions); err != nil {
		return nil, err
	}
	if err := markBatchSettled(ctx, tx, orgID, entries, dispositions); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("settlement batch commit: %w", err)
	}
	return dispositions, nil
}

// verifySettlementFencing locks claimed jobs and ensures each non-zero claim
// token still matches settlement_jobs.attempts. A retry/claim increments
// attempts, so a paused worker cannot settle after a newer worker acquired
// the same job. Rows are locked in id order to preserve a stable lock order.
func verifySettlementFencing(ctx context.Context, tx pgx.Tx, entries []SettleEntry) error {
	ids := make([]int64, 0, len(entries))
	expected := make(map[int64]int32, len(entries))
	for _, entry := range entries {
		if entry.FencingToken <= 0 {
			continue
		}
		if prior, ok := expected[entry.JobID]; ok && prior != entry.FencingToken {
			return fmt.Errorf("%w: conflicting tokens for job %d", ErrStaleSettlementToken, entry.JobID)
		}
		if _, ok := expected[entry.JobID]; !ok {
			ids = append(ids, entry.JobID)
			expected[entry.JobID] = entry.FencingToken
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, attempts FROM settlement_jobs
		WHERE id = ANY($1::bigint[])
		ORDER BY id
		FOR UPDATE`, ids)
	if err != nil {
		return fmt.Errorf("settlement batch fencing read: %w", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id int64
		var attempts int32
		if err := rows.Scan(&id, &attempts); err != nil {
			return fmt.Errorf("settlement batch fencing scan: %w", err)
		}
		seen++
		if expected[id] != attempts {
			return fmt.Errorf("%w: job %d claim=%d current=%d", ErrStaleSettlementToken, id, expected[id], attempts)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("settlement batch fencing rows: %w", err)
	}
	if seen != len(ids) {
		return fmt.Errorf("%w: one or more claimed jobs no longer exist", ErrStaleSettlementToken)
	}
	return nil
}

// settleWalletEntries applies the resale_deduction entries against one
// wallet read: sequential carry in id order, floor-blocked jobs parked
// without touching the running state, one wallet UPDATE for the applied sum.
func settleWalletEntries(ctx context.Context, tx pgx.Tx, orgID string, graceFloorCents int64, entries []SettleEntry, out map[int64]BatchDisposition) error {
	wallet := make([]SettleEntry, 0, len(entries))
	for _, e := range entries {
		if e.Kind == SettleKindResale {
			wallet = append(wallet, e)
		}
	}
	if len(wallet) == 0 {
		return nil
	}

	var balance, remainder int64
	var floor *int64
	err := tx.QueryRow(ctx, `
		SELECT balance_cents, remainder_micro_usd, grace_floor_cents
		FROM org_credits WHERE org_id = $1 FOR UPDATE`, orgID).Scan(&balance, &remainder, &floor)
	if errors.Is(err, pgx.ErrNoRows) {
		// No wallet: every resale entry is durable debt, exactly like the
		// per-job path's no_wallet disposition. The wallet UPDATE below is
		// skipped (nothing applied).
		for _, e := range wallet {
			out[e.JobID] = BatchDisposition{Reason: ReasonNoWallet}
		}
		return nil
	}
	if isUndefinedColumn(err) {
		// Pre-reservation schema (grace_floor_cents lands with NEXT-18a's
		// migration): read the row without the column and fall back to the
		// global grace floor — the exact per-job semantics until the
		// reservation schema exists.
		err = tx.QueryRow(ctx, `
			SELECT balance_cents, remainder_micro_usd
			FROM org_credits WHERE org_id = $1 FOR UPDATE`, orgID).Scan(&balance, &remainder)
	}
	if err != nil {
		return fmt.Errorf("settlement batch wallet read: %w", err)
	}
	floorCents := graceFloorCents
	if floor != nil {
		floorCents = *floor
	}

	anyApplied := false
	for _, e := range wallet {
		if e.RequestID == "" || e.Amount <= 0 {
			out[e.JobID] = BatchDisposition{Reason: ReasonPoisonPayload}
			continue
		}
		// Idempotency FIRST — the exact DeductMicro order (advisory lock →
		// idempotency read → floor math). A replayed job whose charge
		// already committed settles as a no-op regardless of the wallet's
		// current depth under the floor; the §5.5 equivalence is defined on
		// that order.
		existingOrg, exists, err := existingUsageOrg(ctx, tx, e.RequestID)
		if err != nil {
			return err
		}
		if exists {
			if existingOrg != orgID {
				out[e.JobID] = BatchDisposition{Reason: ReasonIdentityConflict}
				continue
			}
			// The earlier run committed this charge, its settle-mark and
			// its reserve decrement atomically — an idempotent no-op
			// settle, never a second debit (§5.5).
			out[e.JobID] = BatchDisposition{Settled: true}
			continue
		}
		newBalance, newRemainder, chargeCents, applied := carryWalletCharge(balance, remainder, int64(e.Amount), floorCents)
		if !applied {
			out[e.JobID] = BatchDisposition{Reason: ReasonInsufficientCredits}
			continue
		}
		if err := insertWalletLedgerRow(ctx, tx, orgID, e, newBalance, chargeCents); err != nil {
			return err
		}
		balance, remainder = newBalance, newRemainder
		anyApplied = true
		out[e.JobID] = BatchDisposition{Settled: true, Applied: true}
	}

	if anyApplied {
		if _, err := tx.Exec(ctx,
			`UPDATE org_credits SET balance_cents = $2, remainder_micro_usd = $3, updated_at = now() WHERE org_id = $1`,
			orgID, balance, remainder); err != nil {
			return fmt.Errorf("settlement batch wallet update: %w", err)
		}
	}
	return nil
}

// existingUsageOrg reads the idempotency state of one usage identity: the
// owning org when the ledger already has the row. The per-org advisory lock
// makes the read stable against concurrent writers, exactly like the
// per-job path's idempotency SELECT.
func existingUsageOrg(ctx context.Context, tx pgx.Tx, requestID string) (org string, exists bool, err error) {
	err = tx.QueryRow(ctx, `
		SELECT org_id FROM credit_transactions
		WHERE request_id = $1 AND type = 'usage'`, requestID).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("settlement batch idempotency read: %w", err)
	}
	return org, true, nil
}

// insertWalletLedgerRow writes one usage row. The production partial unique
// index backs the idempotency read above (§5.5 ON CONFLICT DO NOTHING): the
// advisory lock makes a race impossible, the arbiter keeps the insert safe
// even if a foreign writer ever bypassed the lock, and a swallowed conflict
// would under-charge — so a zero-row insert is an explicit error, never a
// silent no-op.
func insertWalletLedgerRow(ctx context.Context, tx pgx.Tx, orgID string, e SettleEntry, balanceAfter, chargeCents int64) error {
	var rp struct {
		Model     string `json:"model"`
		TokensIn  int64  `json:"tokens_in"`
		TokensOut int64  `json:"tokens_out"`
	}
	_ = json.Unmarshal(e.Payload, &rp) // decode failure degrades metadata, never money
	meta, _ := json.Marshal(map[string]any{
		"model":            rp.Model,
		"tokens":           rp.TokensIn + rp.TokensOut,
		"amount_micro_usd": int64(e.Amount),
	})

	tag, err := tx.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, metadata, amount_micro_usd)
		VALUES ($1, $2, $3, 'usage', $4, $5::jsonb, $6)
		ON CONFLICT (request_id) WHERE request_id IS NOT NULL AND type = 'usage' DO NOTHING`,
		orgID, -chargeCents, balanceAfter, e.RequestID, string(meta), -int64(e.Amount))
	if err != nil {
		return fmt.Errorf("settlement batch ledger insert: %w", err)
	}
	if tag.RowsAffected() != 1 {
		// Unreachable under the per-org advisory lock (the idempotency read
		// above would have taken the no-op path) — a swallowed conflict
		// would silently drop a charge, so fail loudly instead.
		return fmt.Errorf("settlement batch ledger insert: usage identity %q vanished mid-transaction", e.RequestID)
	}
	return nil
}

// decodePayload decodes one intent payload, reporting whether it holds a
// usable JSON object. A decode failure marks the entry poison (it can never
// succeed) without turning into a transaction error.
func decodePayload(payload []byte, dst any) bool {
	return json.Unmarshal(payload, dst) == nil
}

// settleSpendEntries applies the exact spend upserts (§5.5: the team, agent
// and session upserts batch the same way as the wallet). Entries of a kind
// whose required payload field is missing are poison — they can never
// succeed and must not burn the retry budget.
func settleSpendEntries(ctx context.Context, tx pgx.Tx, entries []SettleEntry, spenders BatchSpenders, out map[int64]BatchDisposition) error {
	apply := func(e SettleEntry) error {
		switch e.Kind {
		case SettleKindTeam:
			var p struct {
				TeamID string `json:"team_id"`
				Period string `json:"period"`
			}
			if !decodePayload(e.Payload, &p) || p.TeamID == "" || p.Period == "" {
				out[e.JobID] = BatchDisposition{Reason: ReasonPoisonPayload}
				return nil
			}
			if err := RecordTeamSpendExact(ctx, tx, p.TeamID, p.Period, e.Amount); err != nil {
				return err
			}
			out[e.JobID] = BatchDisposition{Settled: true, Applied: true}
		case SettleKindAgent:
			if spenders.Agent == nil {
				out[e.JobID] = BatchDisposition{Reason: ReasonNoChargeTarget}
				return nil
			}
			var p struct {
				AgentID   string `json:"agent_id"`
				TokensIn  int64  `json:"tokens_in"`
				TokensOut int64  `json:"tokens_out"`
			}
			if !decodePayload(e.Payload, &p) || p.AgentID == "" {
				out[e.JobID] = BatchDisposition{Reason: ReasonPoisonPayload}
				return nil
			}
			// ADR I5: when the entry carries the request's own time and the
			// spender implements the *At upgrade, the day bucket is the
			// request's day — the same "fixed by request time" semantics as
			// the team path. Spenders without the upgrade (and zero request
			// times) keep the settle-time default.
			var execErr error
			if at, ok := spenders.Agent.(BatchAgentSpenderAt); ok && !e.RequestedAt.IsZero() {
				execErr = at.RecordAgentSpendExactAt(ctx, tx, p.AgentID, e.Amount, p.TokensIn, p.TokensOut, e.RequestedAt)
			} else {
				execErr = spenders.Agent.RecordAgentSpendExact(ctx, tx, p.AgentID, e.Amount, p.TokensIn, p.TokensOut)
			}
			if execErr != nil {
				return execErr
			}
			out[e.JobID] = BatchDisposition{Settled: true, Applied: true}
		case SettleKindSession:
			var p struct {
				SessionKeyID string `json:"session_key_id"`
			}
			if !decodePayload(e.Payload, &p) || p.SessionKeyID == "" {
				out[e.JobID] = BatchDisposition{Reason: ReasonPoisonPayload}
				return nil
			}
			if err := RecordSessionSpendExact(ctx, tx, p.SessionKeyID, e.Amount); err != nil {
				return err
			}
			out[e.JobID] = BatchDisposition{Settled: true, Applied: true}
		default:
			// Unknown charge kind: no money path can ever apply, so the
			// entry parks durably as poison (requires_attention) instead
			// of surviving every settle attempt — symmetric with the
			// per-job executor's unknown-kind ErrPoisonJob, which
			// classifyFailure also parks rather than retries.
			out[e.JobID] = BatchDisposition{Reason: ReasonPoisonPayload}
		}
		return nil
	}

	// Canonical order: team_month → agent_day → session (§5.3). Unknown
	// kinds run last: they carry no money path, only the poison parking,
	// so their position relative to real spend entries is immaterial —
	// but they must REACH apply at all, or the job would stay claimed
	// forever (the infinite requeue this default closes). Wallet entries
	// are settled by the wallet phase above and must not be re-read here.
	for _, kind := range []string{SettleKindTeam, SettleKindAgent, SettleKindSession} {
		for _, e := range entries {
			if e.Kind != kind {
				continue
			}
			if err := apply(e); err != nil {
				return err
			}
		}
	}
	for _, e := range entries {
		if e.Kind == SettleKindResale || e.Kind == SettleKindTeam || e.Kind == SettleKindAgent || e.Kind == SettleKindSession {
			continue
		}
		if err := apply(e); err != nil {
			return err
		}
	}
	return nil
}

// markBatchSettled writes the terminal states and the §5.3 reserve
// decrement. For every APPLIED entry with an allocation link: the allowance
// is read FOR SHARE (the NEXT-18a SettleDecrement check) — released
// allocations are ledger-only; live ones have their scope row's reserve
// dropped by min(actual, bound), one UPDATE per scope row for the summed
// amounts, and the per-job settle amount lands in the payload under
// ReconcileSettleKey (the reconcile's remainder input). Un-applied entries
// (no-op, attention) never touch the reserve.
func markBatchSettled(ctx context.Context, tx pgx.Tx, orgID string, entries []SettleEntry, out map[int64]BatchDisposition) error {
	type link struct {
		entry  SettleEntry
		amount int64
	}
	var links []link
	for _, e := range entries {
		d, ok := out[e.JobID]
		if !ok || !d.Settled || !d.Applied || e.AllowanceID <= 0 {
			continue
		}
		links = append(links, link{entry: e, amount: settleDecrementMicro(e.Amount, e.Bound)})
	}
	if len(links) == 0 {
		// Still write terminal states: settled no-ops and attention rows.
		return writeTerminalStates(ctx, tx, entries, out)
	}

	ids := make([]int64, 0, len(links))
	for _, l := range links {
		ids = append(ids, l.entry.AllowanceID)
	}
	rows, err := tx.Query(ctx, `
		SELECT id, scope_kind, scope_key, period, status FROM budget_allowances
		WHERE id = ANY($1::bigint[]) FOR SHARE`, ids)
	if err != nil {
		return fmt.Errorf("settlement batch allowance read: %w", err)
	}
	statuses := make(map[int64]string, len(links))
	scopes := make(map[int64]settleScopeRow, len(links))
	for rows.Next() {
		var id int64
		var scope, key, period, status string
		if err := rows.Scan(&id, &scope, &key, &period, &status); err != nil {
			rows.Close()
			return fmt.Errorf("settlement batch allowance scan: %w", err)
		}
		statuses[id] = status
		scopes[id] = settleScopeRow{scope: settleScope(scope), key: key, period: period}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("settlement batch allowance rows: %w", err)
	}
	rows.Close()

	// Sum the settle amounts per scope row; a job whose allowance vanished
	// or is released is ledger-only (§5.3: the reserve is never decremented
	// twice).
	totals := make(map[settleScopeRow]int64)
	for _, l := range links {
		status, ok := statuses[l.entry.AllowanceID]
		if !ok || status == settleAllowanceReleased {
			continue
		}
		sk := scopes[l.entry.AllowanceID]
		totals[sk] += l.amount
		d := out[l.entry.JobID]
		d.DecrementMicroUSD = l.amount
		out[l.entry.JobID] = d
	}

	for _, scope := range []settleScope{settleScopeWallet, settleScopeTeamMonth, settleScopeAgentDay, settleScopeSession} {
		for sk, sum := range totals {
			if sk.scope != scope || sum <= 0 {
				continue
			}
			if err := decrementScopeReserveBatch(ctx, tx, orgID, sk, sum); err != nil {
				return err
			}
		}
	}
	return writeTerminalStates(ctx, tx, entries, out)
}

// writeTerminalStates marks every entry settled (with the recorded settle
// amount in the payload) or requires_attention (with its reason).
func writeTerminalStates(ctx context.Context, tx pgx.Tx, entries []SettleEntry, out map[int64]BatchDisposition) error {
	for _, e := range entries {
		d, ok := out[e.JobID]
		if !ok {
			continue
		}
		if d.Settled {
			var decAmt any
			if d.DecrementMicroUSD > 0 {
				decAmt = d.DecrementMicroUSD
			}
			if _, err := tx.Exec(ctx, `
				UPDATE settlement_jobs SET
					status = 'settled',
					lease_until = NULL,
					last_error = NULL,
					updated_at = now(),
					payload = CASE WHEN $2::bigint IS NULL THEN payload
						ELSE jsonb_set(COALESCE(payload, '{}'::jsonb), '{`+ReconcileSettleKey+`}', to_jsonb($2::bigint), true) END
				WHERE id = $1`, e.JobID, decAmt); err != nil {
				return fmt.Errorf("settlement batch settle mark: %w", err)
			}
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE settlement_jobs SET
				status = 'requires_attention',
				lease_until = NULL,
				last_error = $2,
				updated_at = now()
			WHERE id = $1`, e.JobID, d.Reason); err != nil {
			return fmt.Errorf("settlement batch attention mark: %w", err)
		}
	}
	return nil
}

// settleScopeRow identifies the scope row a reserve decrement targets
// (§4.1): the wallet row by org, the period rows by their natural keys.
type settleScopeRow struct {
	scope  settleScope
	key    string
	period string
}

// decrementScopeReserveBatch lowers one scope row's reserve by the batch's
// summed settle amount. The reserved >= sum predicate turns invariant drift
// into an explicit error (never a silent clamp) — the whole batch rolls
// back and the caller falls back to the per-job executor, keeping the drift
// visible. The wallet row is already FOR UPDATE-locked by the wallet read.
func decrementScopeReserveBatch(ctx context.Context, tx pgx.Tx, orgID string, sk settleScopeRow, sum int64) error {
	if sum <= 0 {
		return nil
	}
	var (
		tag pgconn.CommandTag
		err error
	)
	switch sk.scope {
	case settleScopeWallet:
		tag, err = tx.Exec(ctx,
			`UPDATE org_credits SET reserved_micro_usd = reserved_micro_usd - $2, updated_at = now()
			 WHERE org_id = $1 AND reserved_micro_usd >= $2`, orgID, sum)
	case settleScopeTeamMonth:
		tag, err = tx.Exec(ctx,
			`UPDATE team_spend_monthly SET reserved_micro_usd = reserved_micro_usd - $3
			 WHERE team_id = $1::uuid AND period = $2 AND reserved_micro_usd >= $3`, sk.key, sk.period, sum)
	case settleScopeAgentDay:
		tag, err = tx.Exec(ctx,
			`UPDATE agent_spend_daily SET reserved_micro_usd = reserved_micro_usd - $3
			 WHERE agent_id = $1::uuid AND day = $2::date AND reserved_micro_usd >= $3`, sk.key, sk.period, sum)
	case settleScopeSession:
		tag, err = tx.Exec(ctx,
			`UPDATE session_spend SET reserved_micro_usd = reserved_micro_usd - $2, updated_at = now()
			 WHERE session_key_id = $1::uuid AND reserved_micro_usd >= $2`, sk.key, sum)
	default:
		return fmt.Errorf("%w: unknown scope kind %q", ErrBatchReservedUnderflow, sk.scope)
	}
	if err != nil {
		return fmt.Errorf("settlement batch reserve decrement (%s): %w", sk.scope, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: scope %s key %s sum=%d", ErrBatchReservedUnderflow, sk.scope, sk.key, sum)
	}
	return nil
}

// RecordSessionSpendExact applies an exact micro-USD session-key spend
// inside the caller's transaction (ADR §13: session_spend is the `session`
// scope's spend/reserve row). Mirrors RecordTeamSpendExact: the amount is
// applied verbatim to the durable spent_micro_usd accumulator; idempotency
// comes from the caller — the spend and the settlement-job transition to
// 'settled' commit in ONE transaction, so a retry after a crash re-executes
// from a job that never settled.
func RecordSessionSpendExact(ctx context.Context, db SpendExecutor, sessionKeyID string, amount money.MicroUSD) error {
	if sessionKeyID == "" || db == nil {
		return nil
	}
	if amount < 0 {
		amount = 0
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO session_spend (session_key_id, spent_micro_usd, updated_at)
		 VALUES ($1::uuid, $2, now())
		 ON CONFLICT (session_key_id)
		 DO UPDATE SET spent_micro_usd = session_spend.spent_micro_usd + $2, updated_at = now()`,
		sessionKeyID, int64(amount)); err != nil {
		return fmt.Errorf("record exact session spend: %w", err)
	}
	return nil
}

// settleDecrementMicro is the §5.3 Settle amount: min(actual, bound), with
// negative inputs clamped to zero (the NEXT-18a SettleDecrement clamp).
func settleDecrementMicro(actual, bound money.MicroUSD) int64 {
	a := int64(actual)
	if a < 0 {
		a = 0
	}
	b := int64(bound)
	if b < 0 {
		b = 0
	}
	if b < a {
		return b
	}
	return a
}

// carryWalletCharge is the sequential §5.5 wallet step — the exact AF-05
// semantics of credits.DeductMicro as a pure function: the amount splits
// into whole cents plus a sub-cent residue carried by the wallet; the
// residue that reaches a cent is charged immediately; the charge applies
// only when the post-charge wallet stays above the grace floor (or lands
// exactly on it with a zero remainder). The returned applied=false leaves
// the wallet state untouched — later jobs of the batch apply against the
// unchanged wallet, exactly like sequential per-job executions.
func carryWalletCharge(balanceCents, remainderMicro, amountMicro, floorCents int64) (newBalance, newRemainder, chargeCents int64, applied bool) {
	dedCents := amountMicro / int64(money.MicroPerCent)
	dedRem := amountMicro % int64(money.MicroPerCent)

	// Overflow-safe running carry: remainder < 1 cent by schema CHECK, so
	// remainder + dedRem < 2 cents and the division cannot overflow.
	chargeCents = dedCents + (remainderMicro+dedRem)/int64(money.MicroPerCent)
	newRemainder = (remainderMicro + dedRem) % int64(money.MicroPerCent)

	// Guard the subtraction: a charge larger than the representable
	// balance space is simply not appliable, never a wrapped value.
	if chargeCents > 0 && balanceCents < math.MinInt64+chargeCents {
		return balanceCents, remainderMicro, chargeCents, false
	}
	newBalance = balanceCents - chargeCents
	applied = newBalance > floorCents || (newBalance == floorCents && newRemainder == 0)
	if !applied {
		return balanceCents, remainderMicro, chargeCents, false
	}
	return newBalance, newRemainder, chargeCents, true
}

// isUndefinedColumn reports PostgreSQL SQLSTATE 42703 — the batch's only
// schema-version fallback (org grace column pre-reservation-schema).
func isUndefinedColumn(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42703"
}
