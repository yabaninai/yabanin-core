// Package credits manages prepaid credit wallets per org.
// Balances are stored as integer cents (balance_cents) plus a durable
// sub-cent remainder in micro-USD (remainder_micro_usd, AF-05): internal
// cost accounting is exact to the micro-USD, while every public/admin
// amount remains integer cents. 1 cent = 10_000 µUSD (pkg/money).
// Grace period: effective balance can go down to Config.GracePeriodCents
// (overdraft).
package credits

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
)

var (
	// ErrInsufficientCredits returned when the balance is at or below the
	// grace period threshold.
	ErrInsufficientCredits = errors.New("insufficient credits")
	// ErrNoWallet means the org has no billing wallet yet.
	ErrNoWallet = errors.New("no billing wallet found; contact admin to set up credits")
	// ErrChargeIdentityConflict means a usage row exists under the charged
	// invocation identity but its org or exact amount disagrees with the
	// charge: the identity is authoritative and globally unique, so this
	// is an integrity violation (poison for the settlement worker), never
	// an idempotent success and never a re-charge.
	ErrChargeIdentityConflict = errors.New("charge identity conflict")
)

// invocationColumnProbeQuery reports whether credit_transactions carries the
// invocation_id column (migration 0028+). column_name is a bind parameter
// so a probe against an unexpected surface cannot echo a row back as
// truth. The probe runs on the pool before any transaction is held and
// only a successful read is cached.
const invocationColumnProbeQuery = `SELECT count(*) FROM information_schema.columns
	WHERE table_schema = current_schema() AND table_name = 'credit_transactions' AND column_name = $1`

// creditInvocationColumn resolves (per store) whether the ledger carries
// the invocation identity column. A transient read failure returns the
// error — the caller fails the deduction and the settlement worker
// retries, instead of caching "old schema" forever and mis-keying every
// subsequent idempotency lookup.
func (s *Store) creditInvocationColumn(ctx context.Context) (bool, error) {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	if s.ledgerResolved {
		return s.ledgerHasInvCol, nil
	}
	if s.db == nil {
		return false, nil
	}
	var n int
	if err := s.db.QueryRow(ctx, invocationColumnProbeQuery, "invocation_id").Scan(&n); err != nil {
		return false, err
	}
	s.ledgerResolved, s.ledgerHasInvCol = true, n > 0
	return s.ledgerHasInvCol, nil
}

// IsInsufficientCredits returns true if the error indicates insufficient credits (including no wallet).
func IsInsufficientCredits(err error) bool {
	return errors.Is(err, ErrInsufficientCredits) || errors.Is(err, ErrNoWallet)
}

// IsNoWallet returns true if the error indicates no wallet exists.
func IsNoWallet(err error) bool {
	return errors.Is(err, ErrNoWallet)
}

// Config holds tunable parameters for the credits store.
type Config struct {
	// GracePeriodCents is the maximum overdraft allowed (e.g., -100 = -$1.00).
	// Every value is preserved exactly as given — including 0, which is a
	// valid explicit configuration meaning "no overdraft allowed". There is
	// no implicit default for this field: callers wanting the standard grace
	// must start from DefaultConfig() (or use NewStore).
	GracePeriodCents int64
	// CacheTTL controls how long balance lookups are cached in memory.
	// The zero value means "not set" and falls back to the DefaultConfig TTL.
	CacheTTL time.Duration
}

const (
	// maxDeductRetries is the number of retry attempts for serializable conflict (SQLSTATE 40001).
	// Sized so the per-attempt abort probability under replica-class
	// contention (p ≈ 0.1) exhausts the budget with probability ~1e-6 per
	// charge; every retry re-runs the idempotent deduction from a fresh
	// serializable snapshot, so a longer budget cannot double-charge.
	maxDeductRetries = 5
	// deductRetryBaseDelay is the base delay before retries, with exponential backoff.
	deductRetryBaseDelay = 50 * time.Millisecond
)

// GracePeriodCents returns the store's configured grace floor (cents).
// The batched settlement worker (NEXT-18d) reads it so the batched wallet
// path applies exactly the same floor the per-job DeductMicro path applies;
// an org's explicit grace_floor_cents column (ADR-0001 §8) wins over this
// store-level fallback inside the batch transaction.
func (s *Store) GracePeriodCents() int64 {
	return s.cfg.GracePeriodCents
}

// DefaultConfig returns sensible defaults for dev/staging.
func DefaultConfig() Config {
	return Config{
		GracePeriodCents: -100, // -$1.00 overdraft
		CacheTTL:         30 * time.Second,
	}
}

// isSerializationFailure returns true if the error indicates a PostgreSQL
// serializable conflict (SQLSTATE 40001) or deadlock (40P01). errors.As
// recurses through all wrapped errors, so deeply-nested PgError pointers
// are found correctly. Both codes mean the transaction cannot proceed and
// the caller should retry with backoff.
func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "40001", // serialization_failure
		"40P01": // deadlock_detected
		return true
	}
	return false
}

// Balance represents an org's credit wallet state.
//
// BalanceCents is the effective whole-cent balance: wallet cents minus the
// accrued sub-cent remainder, rounded toward the wallet (floor of the exact
// micro balance) so displayed amounts never overstate spendable money.
// BalanceMicroUSD is the exact effective balance (walletCents*10000 −
// remainder) and is the authoritative admission/billing figure; the cents
// value is its public projection.
type Balance struct {
	OrgID             string    `json:"org_id"`
	BalanceCents      int64     `json:"balance_cents"`               // effective whole cents (remainder-aware)
	BalanceMicroUSD   int64     `json:"balance_micro_usd,omitempty"` // exact effective balance in µUSD
	RemainderMicroUSD int64     `json:"remainder_micro_usd,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// effectiveBalance derives the remainder-aware balance view from the raw
// wallet row. The remainder is always in [0, 10000) µUSD (schema CHECK), so
// it lowers the effective balance by at most one cent: effective = floor(
// (walletCents*10000 − remainder) / 10000). Balances may be negative within
// the grace overdraft, so the µUSD conversion is a signed overflow-checked
// multiply — an out-of-range wallet is an error, never a wrapped (possibly
// sign-flipping) value that would silently corrupt admission decisions.
func effectiveBalance(orgID string, walletCents int64, remainder int64, updatedAt time.Time) (*Balance, error) {
	ceilCent := (remainder + int64(money.MicroPerCent) - 1) / int64(money.MicroPerCent) // 0 or 1
	effCents := walletCents - ceilCent
	const microLimit = math.MaxInt64 / int64(money.MicroPerCent)
	if effCents > microLimit || effCents < -microLimit {
		return nil, fmt.Errorf("balance %d cents out of representable range", effCents)
	}
	// Exact µUSD residue above effCents: (10000 − remainder) mod 10000,
	// i.e. effCents*10000 + residue == walletCents*10000 − remainder.
	residue := (int64(money.MicroPerCent) - remainder%int64(money.MicroPerCent)) % int64(money.MicroPerCent)
	return &Balance{
		OrgID:             orgID,
		BalanceCents:      effCents,
		BalanceMicroUSD:   effCents*int64(money.MicroPerCent) + residue,
		RemainderMicroUSD: remainder,
		UpdatedAt:         updatedAt,
	}, nil
}

// Transaction represents a single line item in the credit ledger.
// amount_cents is the public whole-cent amount (negative = deduction);
// AmountMicroUSD carries the exact signed micro-USD amount for rows written
// from AF-05 on. Historical rows predate exact micro accounting and have a
// nil AmountMicroUSD — they are never recalculated.
type Transaction struct {
	ID           int64                  `json:"id"`
	OrgID        string                 `json:"org_id"`
	AmountCents  int64                  `json:"amount_cents"`  // positive=top-up, negative=deduction
	BalanceAfter int64                  `json:"balance_after"` // balance in cents after this tx
	Type         string                 `json:"type"`          // "topup" or "usage"
	RequestID    *string                `json:"request_id,omitempty"`
	InvoiceRef   *string                `json:"invoice_ref,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	AmountMicro  *int64                 `json:"amount_micro_usd,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// Store manages credit wallets and ledger entries.
type Store struct {
	cfg   Config
	db    *pgxpool.Pool
	log   *slog.Logger
	cache map[string]*cachedBalance
	mu    sync.RWMutex

	// Ledger schema probe: whether credit_transactions carries the
	// invocation_id column (migration 0028+). Only a successful probe is
	// cached — a transient failure propagates and the next deduction
	// re-probes, never a silent legacy fallback that would mis-key the
	// idempotency lookup.
	ledgerMu        sync.Mutex
	ledgerResolved  bool
	ledgerHasInvCol bool
}

type cachedBalance struct {
	walletCents       int64
	remainderMicroUSD int64
	walletUpdatedAt   time.Time
	cachedAt          time.Time
}

// NewStore creates a credits store backed by the database.
func NewStore(db *pgxpool.Pool, log *slog.Logger) *Store {
	return NewStoreWithConfig(db, log, DefaultConfig())
}

// NewStoreWithConfig creates a credits store with custom configuration.
// Defaults are applied per field: an unset (zero) CacheTTL falls back to the
// DefaultConfig TTL. GracePeriodCents is never substituted — an explicit 0
// stays 0 (no overdraft allowed), negative values keep the intentional
// overdraft, and DefaultConfig() remains the compatible explicit default
// constructor yielding the historical -$1.00 grace.
func NewStoreWithConfig(db *pgxpool.Pool, log *slog.Logger, cfg Config) *Store {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = DefaultConfig().CacheTTL
	}
	if log == nil {
		log = slog.Default()
	}
	return &Store{
		cfg:   cfg,
		db:    db,
		log:   log.With("component", "credits-store"),
		cache: make(map[string]*cachedBalance),
	}
}

// GetBalance returns the current balance for an org. The returned value is
// remainder-aware: BalanceCents is the effective whole-cent balance and
// BalanceMicroUSD the exact µUSD figure.
func (s *Store) GetBalance(ctx context.Context, orgID string) (*Balance, error) {
	if orgID == "" || s.db == nil {
		return &Balance{OrgID: orgID}, nil // no org or no DB → zero balance
	}

	// Try cache first.
	s.mu.RLock()
	if cb, ok := s.cache[orgID]; ok && time.Since(cb.cachedAt) < s.cfg.CacheTTL {
		s.mu.RUnlock()
		return effectiveBalance(orgID, cb.walletCents, cb.remainderMicroUSD, cb.walletUpdatedAt)
	}
	s.mu.RUnlock()

	// Query DB.
	var walletCents int64
	var remainder int64
	var updatedAt time.Time
	err := s.db.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd, updated_at FROM org_credits WHERE org_id = $1`,
		orgID,
	).Scan(&walletCents, &remainder, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoWallet
		}
		return nil, fmt.Errorf("get balance: %w", err)
	}

	// Update cache.
	s.mu.Lock()
	s.cache[orgID] = &cachedBalance{
		walletCents: walletCents, remainderMicroUSD: remainder,
		walletUpdatedAt: updatedAt, cachedAt: time.Now(),
	}
	s.mu.Unlock()

	return effectiveBalance(orgID, walletCents, remainder, updatedAt)
}

// CheckBalance verifies whether an org can proceed. Returns the current balance.
// Admission is rejected with ErrInsufficientCredits when the effective balance
// is at or below the grace period threshold.
//
// Exact µUSD admission rule: admit iff (walletCents − floor)*10000 >
// remainder. Because the remainder is always < 10000 µUSD (one cent), this
// reduces to walletCents > floor: at balance == floor the effective balance
// can never exceed the floor (matching the AF-01 inclusive rejection), and a
// full cent of headroom always admits regardless of the sub-cent remainder.
// The check therefore stays in overflow-free cent space — it compares the
// reconstructed raw wallet cents, not the floored display value, so a
// pending remainder never rejects a request one cent early.
func (s *Store) CheckBalance(ctx context.Context, orgID string) (*Balance, error) {
	balance, err := s.GetBalance(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Reconstruct the raw wallet cents from the effective view:
	// wallet = effCents + ceil(remainder / 10000), ceil ∈ {0, 1}.
	walletCents := balance.BalanceCents + (balance.RemainderMicroUSD+int64(money.MicroPerCent)-1)/int64(money.MicroPerCent)
	if walletCents <= s.cfg.GracePeriodCents {
		return balance, ErrInsufficientCredits
	}

	return balance, nil
}

// TopUp adds credits to an org's wallet. This is a manual admin action.
// invoiceRef is the reference for the manual invoice (bank transfer, crypto tx, etc.).
// TopUp is whole-cents by contract and never touches the sub-cent remainder:
// the exact amount is recorded as amount_micro_usd on the new ledger row.
func (s *Store) TopUp(ctx context.Context, orgID string, amountCents int64, invoiceRef string) error {
	if orgID == "" || s.db == nil {
		return fmt.Errorf("top-up: invalid parameters")
	}

	if amountCents <= 0 {
		return fmt.Errorf("top-up: amount must be positive, got %d cents", amountCents)
	}

	amountMicro, err := money.FromCents(amountCents)
	if err != nil {
		return fmt.Errorf("top-up: %w", err)
	}

	query := `
	WITH updated AS (
		INSERT INTO org_credits (org_id, balance_cents, updated_at)
		VALUES ($1,
			COALESCE((SELECT balance_cents FROM org_credits WHERE org_id = $1), 0) + $2,
			now()
		)
		ON CONFLICT (org_id) DO UPDATE SET
			balance_cents = org_credits.balance_cents + $2,
			updated_at = now()
		RETURNING balance_cents, updated_at
	)
	INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, invoice_ref, created_at, amount_micro_usd)
	SELECT $1, $2, balance_cents, 'topup', $3, now(), $4 FROM updated;
	`

	if _, err := s.db.Exec(ctx, query, orgID, amountCents, invoiceRef, int64(amountMicro)); err != nil {
		return fmt.Errorf("top-up: %w", err)
	}

	// Invalidate cache.
	s.mu.Lock()
	delete(s.cache, orgID)
	s.mu.Unlock()

	s.log.Info("credit top-up", "org_id", orgID, "amount_cents", amountCents, "invoice_ref", invoiceRef)
	return nil
}

// Deduct deducts whole cents for a completed request. Returns
// ErrInsufficientCredits if the effective balance would drop below the grace
// period threshold, or ErrNoWallet if no wallet exists.
//
// Idempotency: if the same request_id has already been deducted (same org), this call
// is a no-op and returns nil — callers may safely retry without double-charging.
//
// Retry logic: on serializable conflict (SQLSTATE 40001), retries up to maxDeductRetries
// times with exponential backoff + jitter before returning the error. This prevents
// silent revenue loss under concurrent load.
func (s *Store) Deduct(ctx context.Context, orgID string, amountCents int64, requestID string, metadata map[string]interface{}) error {
	amount, err := money.FromCents(amountCents)
	if err != nil {
		return fmt.Errorf("deduct: %w", err)
	}
	return s.DeductMicro(ctx, orgID, amount, requestID, metadata)
}

// DeductMicroInvocation deducts an exact micro-USD amount keyed by the
// billed invocation identity (0028+). invocationID is either empty — the
// legacy request-keyed domain above — or a canonical uuid (nil, URN,
// braced or re-spelled variants are rejected before touching the database,
// so a malformed identity can never reach an idempotency key). On 0028+
// schemas the usage row's idempotency key is the invocation alone
// (uniq_credit_transactions_invocation), verified against the charged org
// and the exact signed amount before counting as idempotent: two
// legitimate invocations from one org sharing a client request id bill
// independently, while the same identity under another tenant or a
// different amount is an integrity conflict, never a silent no-op. On a
// pre-0028 schema the invocation-keyed insert fails loudly (missing
// column) — retry, then requires_attention — instead of billing under the
// shared legacy key.
func (s *Store) DeductMicroInvocation(ctx context.Context, orgID string, amount money.MicroUSD, requestID, invocationID string, metadata map[string]interface{}) error {
	if invocationID != "" {
		if id, err := uuid.Parse(invocationID); err != nil || id == uuid.Nil || id.String() != invocationID {
			return fmt.Errorf("deduct: invocation id %q is not a canonical non-nil UUID", invocationID)
		}
	}
	hasInvocationColumn, err := s.creditInvocationColumn(ctx)
	if err != nil {
		return fmt.Errorf("deduct: resolve ledger schema: %w", err)
	}
	return s.deductMicroKeyed(ctx, orgID, amount, requestID, invocationID, metadata, hasInvocationColumn)
}

// DeductMicro deducts an exact micro-USD amount for a completed request
// (AF-05). The amount is applied to the wallet in two durable parts within
// one serializable transaction: whole cents reduce balance_cents (and are
// what the credit_transactions ledger row records), while the sub-cent
// residue accumulates in remainder_micro_usd; when the residue reaches a
// whole cent, that cent is charged atomically in the same transaction. A
// $0.004 charge therefore bills exactly $4.00 across 1000 requests — the
// precision is durable, not in-memory.
//
// Floor: the charge is rejected with ErrInsufficientCredits unless the
// post-charge effective balance stays above the grace floor. Because the
// carried remainder is sub-cent, this is exactly: newWalletCents > floor,
// or (newWalletCents == floor AND the new remainder is exactly 0).
//
// Idempotency, retries and error semantics mirror Deduct.
func (s *Store) DeductMicro(ctx context.Context, orgID string, amount money.MicroUSD, requestID string, metadata map[string]interface{}) error {
	return s.DeductMicroInvocation(ctx, orgID, amount, requestID, "", metadata)
}

func (s *Store) deductMicroKeyed(ctx context.Context, orgID string, amount money.MicroUSD, requestID, invocationID string, metadata map[string]interface{}, hasInvocationColumn bool) error {
	if orgID == "" || s.db == nil {
		return fmt.Errorf("deduct: invalid parameters")
	}

	if amount <= 0 {
		return fmt.Errorf("deduct: amount must be positive, got %d µUSD", int64(amount))
	}

	var lastErr error
	for attempt := 0; attempt <= maxDeductRetries; attempt++ {
		lastErr = s.deductOnceMicro(ctx, orgID, amount, requestID, invocationID, metadata, hasInvocationColumn)
		if lastErr == nil {
			return nil
		}

		// On serialization failure, retry with backoff. Full jitter (uniform
		// over the exponentially growing window) decorrelates concurrent
		// retriers: with a fixed schedule, replicas that abort together
		// reproduce the same conflict on every synchronized retry wave.
		if isSerializationFailure(lastErr) && attempt < maxDeductRetries {
			// math/rand is acceptable here — this is retry backoff jitter,
			// not cryptographic or auth-related randomness.
			//nolint:gosec // safe for exponential-backoff jitter only
			delay := time.Duration(rand.Int63n(int64(deductRetryBaseDelay) << uint(attempt+1)))

			s.log.Warn("deduct serialization conflict, retrying",
				"org_id", orgID, "attempt", attempt+1, "max_attempts", maxDeductRetries+1, "delay_ms", delay.Milliseconds())
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			continue
		}

		// Non-retryable error or last attempt exhausted — return.
		return lastErr
	}
	return lastErr
}

// deductOnceMicro performs a single attempt at the exact micro-USD credit
// deduction. Correctness rests on a transaction-scoped advisory lock per org
// instead of serializable retry luck: concurrent writers queue per wallet,
// so the floor check and the idempotency read are evaluated against a stable
// wallet state and never race. Serializable conflicts (deadlocks etc.) stay
// retryable by the caller as a safety net. Each step below names its own
// invariant; every pre-commit failure rolls the attempt back.
func (s *Store) deductOnceMicro(ctx context.Context, orgID string, amount money.MicroUSD, requestID, invocationID string, metadata map[string]interface{}, hasInvocationColumn bool) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("deduct begin tx: %w", err)
	}

	// Step 0: serialize deduction writers for this org.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		s.rollbackDeduct(ctx, tx)
		return fmt.Errorf("deduct advisory lock: %w", err)
	}

	// Step 1: is this charge already applied?
	applied, err := s.deductAlreadyApplied(ctx, tx, orgID, amount, requestID, invocationID, hasInvocationColumn)
	if err != nil || applied {
		s.rollbackDeduct(ctx, tx)
		return err
	}

	// Steps 2–3: charge the exact amount and update the wallet.
	newBalance, newRemainder, chargeCents, err := s.applyMicroCharge(ctx, tx, orgID, amount)
	if err != nil {
		s.rollbackDeduct(ctx, tx)
		return err
	}

	// Step 4: the usage ledger row, then commit.
	metaBytes, err := usageMetadataJSON(metadata)
	if err != nil {
		s.rollbackDeduct(ctx, tx)
		return err
	}
	if err := s.insertUsageTransaction(ctx, tx, orgID, requestID, invocationID, chargeCents, newBalance, amount, metaBytes, hasInvocationColumn); err != nil {
		s.rollbackDeduct(ctx, tx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deduct commit: %w", err)
	}

	// Invalidate cache.
	s.mu.Lock()
	delete(s.cache, orgID)
	s.mu.Unlock()

	s.log.Info("credit deducted",
		"org_id", orgID,
		"request_id", requestID,
		"charge_cents", chargeCents,
		"amount_micro_usd", int64(amount),
		"new_balance", newBalance,
		"new_remainder_micro_usd", newRemainder)
	return nil
}

// rollbackDeduct rolls back a failed deduction attempt. A rollback error is
// logged, never returned — the original failure is the reportable one.
func (s *Store) rollbackDeduct(ctx context.Context, tx pgx.Tx) {
	if rerr := tx.Rollback(ctx); rerr != nil {
		s.log.Warn("deduct rollback failed", "error", rerr)
	}
}

// deductAlreadyApplied resolves the Step 1 idempotency question: is this
// charge already durable? The key follows the domain of the row being
// written. An invocation-keyed charge matches the invocation alone
// (server-minted uuids are globally unique; exactly
// uniq_credit_transactions_invocation) and must then verify the charged org
// and the exact signed amount before counting as idempotent — a row under
// the same identity but another tenant or a different amount is an
// integrity conflict (ErrChargeIdentityConflict), never a silent no-op. A
// legacy charge matches the (org, request) pair constrained to the legacy
// domain (invocation_id IS NULL on 0028+ schemas, exactly
// uniq_credit_transactions_usage_legacy): an invoked row under the same
// correlation must never suppress a genuine legacy charge. Pre-0028 schemas
// keep the original bytes — no invoked rows can exist there.
func (s *Store) deductAlreadyApplied(ctx context.Context, tx pgx.Tx, orgID string, amount money.MicroUSD, requestID, invocationID string, hasInvocationColumn bool) (bool, error) {
	var existingID int64
	var err error
	if invocationID != "" {
		var rowOrg string
		var rowMicro int64
		err = tx.QueryRow(ctx, `SELECT org_id, amount_micro_usd FROM credit_transactions WHERE invocation_id = $1 AND type = 'usage'`, invocationID).Scan(&rowOrg, &rowMicro)
		if err == nil {
			if rowOrg != orgID || rowMicro != -int64(amount) {
				s.log.Error("usage row found under the charged invocation with a different org or amount — integrity conflict, never idempotent",
					"org_id", orgID,
					"invocation_id", invocationID,
					"row_org_id", rowOrg,
					"amount_micro_usd", int64(amount),
					"row_amount_micro_usd", rowMicro,
				)
				return false, ErrChargeIdentityConflict
			}
			// Already deducted under the authoritative identity.
			return true, nil
		}
	} else if hasInvocationColumn {
		err = tx.QueryRow(ctx, `SELECT id FROM credit_transactions WHERE org_id = $1 AND request_id = $2 AND type = 'usage' AND invocation_id IS NULL`, orgID, requestID).Scan(&existingID)
	} else {
		err = tx.QueryRow(ctx, `SELECT id FROM credit_transactions WHERE org_id = $1 AND request_id = $2 AND type = 'usage'`, orgID, requestID).Scan(&existingID)
	}
	if err == nil {
		// Already deducted — idempotent success (no-op).
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("deduct idempotency check: %w", err)
	}
	return false, nil
}

// applyMicroCharge performs Steps 2 and 3: it charges the exact amount —
// split into whole cents plus the sub-cent residue carried by
// remainder_micro_usd. The residue that reaches a whole cent is charged
// immediately (carry), keeping the invariant: charged µUSD = charged
// cents*10000 + remainder growth. The effective floor is the wallet's own
// grace_floor_cents override when set, otherwise the store's global grace
// period — the same resolution the batch executor applies, so the
// outcome never depends on how many jobs the queue groups. A missing
// wallet row is ErrNoWallet; an existing wallet below the floor is
// ErrInsufficientCredits — distinct facts with distinct dispositions.
// Only new_wallet_cents > floor, or new_wallet_cents == floor with an
// exactly zero new remainder, may stand (only an exact floor landing).
func (s *Store) applyMicroCharge(ctx context.Context, tx pgx.Tx, orgID string, amount money.MicroUSD) (newBalance, newRemainder, chargeCents int64, err error) {
	var allowed bool
	err = tx.QueryRow(ctx, `
		WITH wallet AS (
			SELECT balance_cents, remainder_micro_usd, grace_floor_cents
			FROM org_credits WHERE org_id = $1 FOR UPDATE
		),
		parts AS (
			SELECT w.balance_cents,
				   w.remainder_micro_usd,
				   COALESCE(w.grace_floor_cents, $3::bigint) AS floor_cents,
				   $2::bigint / 10000 AS ded_cents,
				   $2::bigint % 10000 AS ded_rem
			FROM wallet w
		),
		carry AS (
			SELECT balance_cents,
				   floor_cents,
				   ded_cents + (remainder_micro_usd + ded_rem) / 10000 AS charge_cents,
				   (remainder_micro_usd + ded_rem) % 10000 AS new_remainder
			FROM parts
		)
		SELECT balance_cents - charge_cents AS new_balance,
			   new_remainder,
			   charge_cents,
			   (balance_cents - charge_cents > floor_cents
			    OR (balance_cents - charge_cents = floor_cents AND new_remainder = 0)) AS allowed
		FROM carry
	`, orgID, int64(amount), s.cfg.GracePeriodCents).Scan(&newBalance, &newRemainder, &chargeCents, &allowed)

	if errors.Is(err, pgx.ErrNoRows) {
		// No wallet row: a missing billing wallet, not a floor rejection.
		return 0, 0, 0, ErrNoWallet
	}
	if err != nil {
		return 0, 0, 0, fmt.Errorf("deduct balance check: %w", err)
	}
	if !allowed {
		// The wallet exists but the charge would land below its floor.
		return 0, 0, 0, ErrInsufficientCredits
	}

	_, err = tx.Exec(ctx,
		`UPDATE org_credits SET balance_cents = $2, remainder_micro_usd = $3, updated_at = now() WHERE org_id = $1`,
		orgID, newBalance, newRemainder)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("deduct update balance: %w", err)
	}
	return newBalance, newRemainder, chargeCents, nil
}

// usageMetadataJSON renders the deduction metadata payload, defaulting to
// an empty object.
func usageMetadataJSON(metadata map[string]interface{}) ([]byte, error) {
	if len(metadata) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("deduct marshal metadata: %w", err)
	}
	return b, nil
}

// insertUsageTransaction writes the Step 4 usage ledger row: whole cents on
// the legacy amount_cents column, the exact amount in micro-USD. Zero-cent
// rows are legitimate: they carry a purely fractional charge whose residue
// is durable on the wallet. The invocation identity column participates
// whenever the schema has it — an explicit NULL for a legacy-domain row is
// the same stored value as the omitted column, so both 0028 domains share
// one statement; only pre-0028 schemas (no column) need the original bytes.
func (s *Store) insertUsageTransaction(ctx context.Context, tx pgx.Tx, orgID, requestID, invocationID string, chargeCents, newBalance int64, amount money.MicroUSD, metaBytes []byte, hasInvocationColumn bool) error {
	// Use sql.NullString for request_id — empty string becomes NULL.
	reqID := sql.NullString{String: requestID, Valid: requestID != ""}

	if invocationID == "" && !hasInvocationColumn {
		_, err := tx.Exec(ctx, `
			INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, metadata, amount_micro_usd)
			VALUES ($1, $2, $3, 'usage', $4, $5::jsonb, $6)
		`, orgID, -chargeCents, newBalance, reqID, string(metaBytes), -int64(amount))
		if err != nil {
			return fmt.Errorf("deduct insert transaction: %w", err)
		}
		return nil
	}

	var invocationArg any
	if invocationID != "" {
		invocationArg = invocationID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, metadata, amount_micro_usd, invocation_id)
		VALUES ($1, $2, $3, 'usage', $4, $5::jsonb, $6, $7)
	`, orgID, -chargeCents, newBalance, reqID, string(metaBytes), -int64(amount), invocationArg)
	if err != nil {
		return fmt.Errorf("deduct insert transaction: %w", err)
	}
	return nil
}

// GetTransactions returns recent transactions for an org, ordered by created_at DESC.
func (s *Store) GetTransactions(ctx context.Context, orgID string, limit int) ([]Transaction, error) {
	if orgID == "" || s.db == nil {
		return nil, nil
	}

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(ctx,
		`SELECT id, org_id, amount_cents, balance_after, type, request_id, invoice_ref, metadata, amount_micro_usd, created_at
		 FROM credit_transactions
 		 WHERE org_id = $1
 		 ORDER BY created_at DESC
 		 LIMIT $2`,
		orgID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("get transactions: %w", err)
	}
	defer rows.Close()

	var txns []Transaction
	for rows.Next() {
		var t Transaction
		var reqID, invRef *string
		var meta map[string]interface{}
		if err := rows.Scan(&t.ID, &t.OrgID, &t.AmountCents, &t.BalanceAfter, &t.Type, &reqID, &invRef, &meta, &t.AmountMicro, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}
		t.RequestID = reqID
		t.InvoiceRef = invRef
		t.Metadata = meta
		txns = append(txns, t)
	}

	return txns, rows.Err()
}

// LowBalanceOrgs returns all orgs with balance below the given threshold.
func (s *Store) LowBalanceOrgs(ctx context.Context, thresholdCents int64, limit int) ([]string, error) {
	if s.db == nil {
		return nil, nil
	}

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.db.Query(ctx,
		`SELECT org_id FROM org_credits WHERE balance_cents < $1 ORDER BY balance_cents ASC LIMIT $2`,
		thresholdCents, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("low balance orgs: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return nil, fmt.Errorf("scan org_id: %w", err)
		}
		orgIDs = append(orgIDs, orgID)
	}

	return orgIDs, rows.Err()
}
