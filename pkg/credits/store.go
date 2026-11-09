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
)

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
}

type cachedBalance struct {
	walletCents       int64
	remainderMicroUSD int64
	updated           time.Time
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
	if cb, ok := s.cache[orgID]; ok && time.Since(cb.updated) < s.cfg.CacheTTL {
		s.mu.RUnlock()
		return effectiveBalance(orgID, cb.walletCents, cb.remainderMicroUSD, cb.updated)
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
	s.cache[orgID] = &cachedBalance{walletCents: walletCents, remainderMicroUSD: remainder, updated: time.Now()}
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
	if orgID == "" || s.db == nil {
		return fmt.Errorf("deduct: invalid parameters")
	}

	if amount <= 0 {
		return fmt.Errorf("deduct: amount must be positive, got %d µUSD", int64(amount))
	}

	var lastErr error
	for attempt := 0; attempt <= maxDeductRetries; attempt++ {
		lastErr = s.deductOnceMicro(ctx, orgID, amount, requestID, metadata)
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
// retryable by the caller as a safety net.
func (s *Store) deductOnceMicro(ctx context.Context, orgID string, amount money.MicroUSD, requestID string, metadata map[string]interface{}) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("deduct begin tx: %w", err)
	}

	// Step 0: serialize deduction writers for this org. The lock lives for
	// the transaction; hashtext collisions only add harmless extra
	// serialization between unrelated orgs. (hashtext is stable within a
	// cluster, which is all a lock key needs.)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return fmt.Errorf("deduct advisory lock: %w", err)
	}

	// Step 1: Idempotency check — is this request_id already deducted?
	var existingID int64
	err = tx.QueryRow(ctx, `SELECT id FROM credit_transactions WHERE org_id = $1 AND request_id = $2 AND type = 'usage'`, orgID, requestID).Scan(&existingID)
	if err == nil {
		// Already deducted — idempotent success (no-op).
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return nil
	}
	if err != pgx.ErrNoRows {
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return fmt.Errorf("deduct idempotency check: %w", err)
	}

	// Step 2: Charge the exact amount — split into whole cents plus the
	// sub-cent residue carried by remainder_micro_usd. The residue that
	// reaches a whole cent is charged immediately (carry), keeping the
	// invariant: charged µUSD = charged cents*10000 + remainder growth.
	// The wallet row is rejected (no row → ErrInsufficientCredits) unless
	// new_wallet_cents > floor, or new_wallet_cents == floor with an exactly
	// zero new remainder (only an exact floor landing may stand).
	var newBalance int64
	var newRemainder int64
	var chargeCents int64
	err = tx.QueryRow(ctx, `
		WITH wallet AS (
			SELECT balance_cents, remainder_micro_usd
			FROM org_credits WHERE org_id = $1 FOR UPDATE
		),
		parts AS (
			SELECT w.balance_cents,
				   w.remainder_micro_usd,
				   $2::bigint / 10000 AS ded_cents,
				   $2::bigint % 10000 AS ded_rem
			FROM wallet w
		),
		carry AS (
			SELECT balance_cents,
				   ded_cents + (remainder_micro_usd + ded_rem) / 10000 AS charge_cents,
				   (remainder_micro_usd + ded_rem) % 10000 AS new_remainder
			FROM parts
		)
		SELECT balance_cents - charge_cents AS new_balance,
			   new_remainder,
			   charge_cents
		FROM carry
		WHERE balance_cents - charge_cents > $3
		   OR (balance_cents - charge_cents = $3 AND new_remainder = 0)
	`, orgID, int64(amount), s.cfg.GracePeriodCents).Scan(&newBalance, &newRemainder, &chargeCents)

	if err == pgx.ErrNoRows {
		// Insufficient credits — rollback and return error.
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return ErrInsufficientCredits
	}
	if err != nil {
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return fmt.Errorf("deduct balance check: %w", err)
	}

	// Step 3: Update the wallet balance and its sub-cent remainder.
	_, err = tx.Exec(ctx,
		`UPDATE org_credits SET balance_cents = $2, remainder_micro_usd = $3, updated_at = now() WHERE org_id = $1`,
		orgID, newBalance, newRemainder)
	if err != nil {
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return fmt.Errorf("deduct update balance: %w", err)
	}

	// Step 4: Insert transaction record — whole cents on the legacy column,
	// the exact amount in micro-USD. Zero-cent rows are legitimate: they
	// carry a purely fractional charge whose residue is durable on the wallet.
	var metaBytes []byte
	if len(metadata) > 0 {
		b, jerr := json.Marshal(metadata)
		if jerr != nil {
			if rerr := tx.Rollback(ctx); rerr != nil {
				s.log.Warn("deduct rollback failed", "error", rerr)
			}
			return fmt.Errorf("deduct marshal metadata: %w", jerr)
		}
		metaBytes = b
	} else {
		metaBytes = []byte("{}")
	}

	// Use sql.NullString for request_id — empty string becomes NULL.
	var reqID sql.NullString
	if requestID != "" {
		reqID = sql.NullString{String: requestID, Valid: true}
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, metadata, amount_micro_usd)
		VALUES ($1, $2, $3, 'usage', $4, $5::jsonb, $6)
	`, orgID, -chargeCents, newBalance, reqID, string(metaBytes), -int64(amount)); err != nil {
		if rerr := tx.Rollback(ctx); rerr != nil {
			s.log.Warn("deduct rollback failed", "error", rerr)
		}
		return fmt.Errorf("deduct insert transaction: %w", err)
	}

	// Commit.
	err = tx.Commit(ctx)
	if err != nil {
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
