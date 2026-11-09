// Beta starter grant (W-CRED): a server-side, exactly-once-per-org credit
// top-up applied when an organization is created. Both org-creation paths —
// `yabanin seed` (services/run/seed.go) and the admin create-org API
// (POST /api/organizations, the org+invite flow) — call EnsureStarterGrant.
//
// The amount comes from BETA_STARTER_CREDITS_CENTS (default 5000 = $50.00;
// zero or negative disables the grant). The grant is journalled on the
// credit ledger with invoice_ref "beta-starter-grant", which doubles as the
// idempotency marker: an org receives the grant exactly once, no matter how
// many times either creation path re-runs (both are idempotent re-entrant).
package credits

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/money"
)

// StarterGrantReason marks the starter grant on the ledger (invoice_ref) and
// in the audit journal (the server-side equivalent of the X-Audit-Reason
// operator motive the top-up surface journals).
const StarterGrantReason = "beta-starter-grant"

// StarterGrantEnvVar is the env knob for the starter grant amount (cents).
const StarterGrantEnvVar = "BETA_STARTER_CREDITS_CENTS"

// DefaultStarterGrantCents is the grant when the env knob is unset ($50.00).
const DefaultStarterGrantCents int64 = 5000

// StarterGrantCents resolves the configured grant amount: the value of
// BETA_STARTER_CREDITS_CENTS when set to a valid integer, the default
// otherwise (an unparseable value fails toward the intended beta grant).
// A value of zero or less means "disabled" — callers skip the grant.
func StarterGrantCents() int64 {
	if v := strings.TrimSpace(os.Getenv(StarterGrantEnvVar)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return DefaultStarterGrantCents
}

// GrantDB is the minimal database handle EnsureStarterGrant needs: a handle
// that can open a transaction (*pgxpool.Pool and pgx.Tx both qualify).
type GrantDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// EnsureStarterGrant applies the beta starter grant to an org's wallet
// exactly once. The ledger row (type 'topup', invoice_ref StarterGrantReason)
// is the durable idempotency marker: a repeated call — or a concurrent one —
// observes the marker and is a no-op. Concurrency is serialized per org with
// the same transaction-scoped advisory lock the deduction path uses, so two
// simultaneous creations of the same org can never double-grant.
//
// amountCents <= 0 means disabled: (false, nil), no database round-trip.
// The returned bool reports whether this call granted (true) or the grant
// already existed / was disabled (false).
func EnsureStarterGrant(ctx context.Context, db GrantDB, orgID string, amountCents int64) (bool, error) {
	if db == nil || orgID == "" {
		return false, fmt.Errorf("starter grant: invalid parameters")
	}
	if amountCents <= 0 {
		return false, nil // disabled by configuration
	}
	amountMicro, err := money.FromCents(amountCents)
	if err != nil {
		return false, fmt.Errorf("starter grant: %w", err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("starter grant begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	// Serialize granters per org (hashtext lock family, mirrors the deduct
	// path): the marker check and the wallet write below read a stable
	// wallet state.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		return false, fmt.Errorf("starter grant advisory lock: %w", err)
	}

	// Idempotency marker: exactly one starter-grant row per org, ever.
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM credit_transactions WHERE org_id = $1 AND type = 'topup' AND invoice_ref = $2)`,
		orgID, StarterGrantReason,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("starter grant idempotency check: %w", err)
	}
	if exists {
		return false, nil
	}

	// Wallet upsert + ledger row in one transaction (mirrors TopUp's CTE
	// write, including the exact amount_micro_usd on the new row).
	if _, err := tx.Exec(ctx, `
		WITH updated AS (
			INSERT INTO org_credits (org_id, balance_cents, updated_at)
			VALUES ($1, $2, now())
			ON CONFLICT (org_id) DO UPDATE SET
				balance_cents = org_credits.balance_cents + $2,
				updated_at = now()
			RETURNING balance_cents
		)
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, invoice_ref, created_at, amount_micro_usd)
		SELECT $1, $2, balance_cents, 'topup', $3, now(), $4 FROM updated
	`, orgID, amountCents, StarterGrantReason, int64(amountMicro)); err != nil {
		return false, fmt.Errorf("starter grant apply: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("starter grant commit: %w", err)
	}
	return true, nil
}

// EnsureStarterGrant applies the beta starter grant through the store,
// invalidating the balance cache when the wallet moved. See the package-level
// EnsureStarterGrant for the exactly-once semantics.
func (s *Store) EnsureStarterGrant(ctx context.Context, orgID string, amountCents int64) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("starter grant: no database")
	}
	granted, err := EnsureStarterGrant(ctx, s.db, orgID, amountCents)
	if err != nil {
		return granted, err
	}
	if granted {
		s.mu.Lock()
		delete(s.cache, orgID)
		s.mu.Unlock()
		s.log.Info("beta starter grant applied",
			"org_id", orgID, "amount_cents", amountCents, "reason", StarterGrantReason)
	}
	return granted, nil
}
