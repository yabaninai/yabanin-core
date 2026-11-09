package run

// Admin guard-pack surface wiring: the admin lifecycle routes were mounted
// and root-gated but never wired — they answered 503. This helper builds the
// admin process's GuardPackHandlers through the SAME durable reconciliation
// the gateway startup uses (cli.HydrateGuardPackLifecycle): the pack root
// comes from the shared YABANIN_GUARD_PACK_DIR knob, the CAS is the durable
// guard_pack_state row (policystore.NewGuardPolicyCAS), and the lifecycle is
// hydrated read-only from the durable record. The pack-signature verifier is
// resolved once from the same three-state env config the gateway startup
// uses: a configured-but-broken key set keeps the routes loudly unwired
// (never a half-verified surface), nothing configured keeps the nil verifier
// (unsigned packs load, declared signatures fail closed), a valid key set
// verifies every signed pack this surface decodes, loads or hydrates.
//
// The admin and gateway processes each hold their own lifecycle instance —
// in-memory hook chains cannot be shared across processes — which is safe by
// construction: the durable row is the coordination point (one-statement
// CAS in migration 0013), so activation state converges across both
// processes and every replica.

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/config"
	cli "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// guardPackHandlersForAdmin builds the admin guard-pack surface over the
// durable coordination point. A nil result keeps the routes mounted but
// unwired (they answer 503, the established optional-group convention):
// without a DB pool there is nothing to coordinate with, a broken verifier
// configuration would make every signed decode fail closed, and an
// unreadable durable record would leave the routes with doomed CAS
// preconditions — never a half-working surface.
func guardPackHandlersForAdmin(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, mode guardhooks.Mode, packDir string, verifyCfg config.GuardPackVerifyConfig) *handlers.GuardPackHandlers {
	if pool == nil {
		return nil
	}
	verifier, configured, err := guardhooks.NewVerifierFromConfig(verifyCfg.KeysDir, verifyCfg.InlineKeys)
	if err != nil {
		logger.Error("admin guard-pack routes stay unwired (503) — guard pack verifier configuration is broken", "error", err)
		return nil
	}
	if configured {
		logger.Info("admin guard pack signature verification enabled")
	}
	durable, err := cli.HydrateGuardPackLifecycle(ctx, pool, logger, mode, packDir, verifier)
	if err != nil {
		logger.Error("admin guard-pack routes stay unwired (503) — durable guard policy state is unreadable", "error", err)
		return nil
	}
	return handlers.NewGuardPackHandlers(packDir, durable.Lifecycle, durable.Policy, verifier)
}
