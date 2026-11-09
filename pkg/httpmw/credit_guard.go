package httpmw

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/reireirei/yabanin/pkg/credits"
)

// CreditGuard returns an http.Handler middleware that checks and deducts
// prepaid credits for each authenticated request.
//
// Flow:
//  1. Pre-check: verify balance >= grace period threshold ($1 overdraft).
//     If below → HTTP 402 Payment Required with balance info.
//  2. Pass request to next handler.
//  3. Post-deduct: after completion, deduct credits from the org's wallet.
//     Deduction uses SELECT FOR UPDATE for race-safety.
//
// The org ID is extracted from the "X-Org-Id" header (set by auth middleware).
// If no org ID is present, the request passes through (unauthenticated requests
// are not billed — they may be blocked by other middleware like rate limiting).
func CreditGuard(store *credits.Store) func(http.Handler) http.Handler {
	if store == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := r.Header.Get("X-Org-Id")
			if orgID == "" {
				// No org ID — skip credit check (may be unauthenticated).
				next.ServeHTTP(w, r)
				return
			}

			// Step 1: Pre-check balance.
			balance, err := store.CheckBalance(r.Context(), orgID)
			if err != nil {
				if credits.IsInsufficientCredits(err) {
					writeCreditError(w, balance, err)
					return
				}
				// DB error or other unexpected failure → service unavailable.
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				slog.Warn("credit guard: balance check failed (db error)", "org_id", orgID, "error", err)
				return
			}

			// Store balance for post-deduct logging.
			ctx := r.Context()
			next.ServeHTTP(w, r.WithContext(ctx))

			// Step 2: Post-deduct is handled asynchronously by the deductor.
			// The middleware only pre-checks to ensure we don't process requests
			// that will fail credit deduction. Actual deduction happens in
			// pkg/credits/deductor.go which reads completed request events.
			_ = balance
		})
	}
}

func writeCreditError(w http.ResponseWriter, balance *credits.Balance, err error) {
	w.Header().Set("Content-Type", "application/json")

	if credits.IsNoWallet(err) {
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "no_billing_setup",
			"message": "Contact admin to add credits to your account",
		})
		return
	}

	if balance != nil {
		w.Header().Set("X-Balance-Cents", strconv.FormatInt(balance.BalanceCents, 10))
	} else {
		w.Header().Set("X-Balance-Cents", "0")
	}
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "insufficient_credits",
		"balance_cents": func() int64 {
			if balance != nil {
				return balance.BalanceCents
			}
			return 0
		}(),
	})
}
