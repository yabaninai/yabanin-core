package regionrouter

import (
	"context"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// regionIDRe restricts the region string to safe characters before it is used
// in a Postgres GUC. set_config binds the value as a parameter, but we still
// validate defensively to reject anything weird early.
var regionIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// AppRole is the dedicated non-owner application role every pool connection
// must assume (migration 0022). The role cannot bypass region RLS: it is no
// table owner, NOBYPASSRLS, and table owners are FORCE-bound anyway.
const AppRole = "yabanin_app"

// ValidateRegion returns an error if the region id is not a safe token.
func ValidateRegion(region string) error {
	if !regionIDRe.MatchString(region) {
		return fmt.Errorf("invalid region id %q (must match %s)", region, regionIDRe)
	}
	return nil
}

// setRegionGUC binds the app.region GUC for the connection's lifetime so the
// region_isolation policies resolve to the pool's deployment region.
func setRegionGUC(ctx context.Context, conn *pgx.Conn, region string) error {
	if _, err := conn.Exec(ctx, "SELECT set_config('app.region', $1, false)", region); err != nil {
		return fmt.Errorf("set app.region RLS context: %w", err)
	}
	return nil
}

// assumeAppRole downgrades the session to AppRole before any query runs. It
// is the fixed role name from migration 0022, never user input, so it is
// inlined as a literal (SET ROLE cannot take bind parameters). Failing here
// fails the connection: a pool that cannot drop owner/superuser privileges
// must not serve traffic (fail closed).
func assumeAppRole(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, "SET ROLE yabanin_app"); err != nil {
		return fmt.Errorf("assume app role %q: %w", AppRole, err)
	}
	return nil
}

// AfterConnectRegion returns a pgxpool.AfterConnect hook that only sets the
// app.region GUC on every pooled connection. Test stands and constrained
// readers use it; production pools go through ConfigurePool, which also
// assumes the non-owner AppRole.
func AfterConnectRegion(region string) func(ctx context.Context, conn *pgx.Conn) error {
	return func(ctx context.Context, conn *pgx.Conn) error {
		if err := ValidateRegion(region); err != nil {
			return err
		}
		return setRegionGUC(ctx, conn, region)
	}
}

// ConfigurePool sets the AfterConnect hook on a pool config. Call before
// pgxpool.NewWithConfig. Production wiring: every pooled connection first
// downgrades to the non-owner AppRole (SET ROLE), then binds the app.region
// GUC, so RLS policies are enforced and scoped no matter which login the DSN
// carries. Connections fail closed when the role is missing — i.e. when the
// migrations (0022) have not been applied.
func ConfigurePool(cfg *pgxpool.Config, region string) error {
	if err := ValidateRegion(region); err != nil {
		return err
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if err := assumeAppRole(ctx, conn); err != nil {
			return err
		}
		return setRegionGUC(ctx, conn, region)
	}
	return nil
}
