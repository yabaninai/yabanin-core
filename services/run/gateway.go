package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/config"
	cli "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/reireirei/yabanin/pkg/kms"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/reireirei/yabanin/pkg/redisutil"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/reireirei/yabanin/pkg/tracing"
)

// errNoDatabaseConfigured signals that no pg_uri was configured, so the gateway
// runs without Postgres (resolver-fallback-only mode). It is a sentinel, not a
// hard failure: callers handle it explicitly instead of treating it as fatal.
var errNoDatabaseConfigured = errors.New("no pg_uri configured: gateway running in resolver-fallback-only mode")

// policyWiringFromEnv resolves the OP-8 policy-pipeline knobs. The env is read
// HERE (wiring), deliberately not in pkg/config: the kill-switch is a
//
//   - YABANIN_POLICY_MODE = off | shadow | enforce (default off — the pipeline
//     stays off and request behavior is bit-for-bit pre-OP-8);
//   - YABANIN_POLICY_COLD_FAILURE_MODE = fail-closed | fail-open (default
//     fail-closed when an org has no successful policy snapshot);
//   - YABANIN_POLICY_CALLOUT_ALLOW_HOSTS = comma-separated ssrf.ParseDomain
//     patterns; empty (the default) disables callout steps entirely (policies
//     referencing them fail to load, egress can never be wider than this list).
func policyWiringFromEnv(l *slog.Logger) (cli.PolicyWiring, error) {
	mode, note := cli.ResolvePolicyMode(os.Getenv("YABANIN_POLICY_MODE"))
	if note != "" {
		return cli.PolicyWiring{}, errors.New("invalid YABANIN_POLICY_MODE")
	}
	coldMode, coldNote := cli.ResolvePolicyColdFailureMode(os.Getenv("YABANIN_POLICY_COLD_FAILURE_MODE"))
	if coldNote != "" {
		l.Warn(coldNote)
	}
	wiring := cli.PolicyWiring{Mode: mode, ColdFailureMode: coldMode}
	if hosts := strings.TrimSpace(os.Getenv("YABANIN_POLICY_CALLOUT_ALLOW_HOSTS")); hosts != "" {
		for _, h := range strings.Split(hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				wiring.CalloutAllowHosts = append(wiring.CalloutAllowHosts, h)
			}
		}
	}
	return wiring, nil
}

// env is read HERE (wiring), deliberately not in pkg/config: the kill-switch
//
//	YABANIN_CIRCUIT_SCOPE = per-endpoint | global (default per-endpoint).
//	per-endpoint gives every upstream endpoint (scheme://host) its own
func circuitScopeWiringFromEnv(l *slog.Logger) cli.CircuitScopeWiring {
	scope, note := cli.ResolveCircuitScope(os.Getenv("YABANIN_CIRCUIT_SCOPE"))
	if note != "" {
		l.Warn(note)
	}
	return cli.CircuitScopeWiring{Scope: scope}
}

// contract — keep in sync with cli.JWTWiring):
//
//	YABANIN_JWT_JWKS_URL         JWKS endpoint of the identity provider.
//	                             Empty/absent = JWT auth OFF (default; the
//	                             legacy API-key path is bit-for-bit
//	                             unchanged). Must be https:// unless the
//	                             host is loopback (local IdP / tests) — a
//	                             violation DISABLES the JWT path (fail
//	                             closed: JWT requests then get the legacy
//	                             401, never a bypass).
//	YABANIN_JWT_ISSUER           required iss claim value; empty skips
//	                             issuer validation.
//	YABANIN_JWT_AUDIENCE         required aud claim value; empty skips
//	                             audience validation.
//	YABANIN_JWT_ORG_CLAIM        claim that maps the verified token to a
//	                             gateway org (default "org_id"). The claim
//	                             must be a non-empty string; a token
//	                             without it is rejected (401).
//	YABANIN_JWT_KEY_LABEL_CLAIM  optional claim whose value(s) become the
//	                             LOCKED "key" principal labels, narrowing
//	                             OP-8 policy attachments exactly like an
//	                             API key's labels. Unset = no labels from
//	                             JWTs.
//
// All knobs are read HERE (wiring), deliberately not in pkg/config: they are
// RS256/ES256 only (alg allow-list), exp required, 30s leeway, JWKS cached
// with jittered TTL + background refresh + bounded staleness (fail-closed
// 503 when no live cache can serve).
const (
	envJWJJWKSURL     = "YABANIN_JWT_JWKS_URL"
	envJWTIssuer      = "YABANIN_JWT_ISSUER"
	envJWTAudience    = "YABANIN_JWT_AUDIENCE"
	envJWTOrgClaim    = "YABANIN_JWT_ORG_CLAIM"
	envJWTKeyLabelClm = "YABANIN_JWT_KEY_LABEL_CLAIM"
)

// jwtWiringFromEnv resolves the JWT auth knobs. The
// scheme guard is enforced here, at the boundary where operator input enters
// the process: the JWKS URL must be https, except loopback hosts where plain
// http is tolerated for local identity providers and tests.
func jwtWiringFromEnv(l *slog.Logger) cli.JWTWiring {
	raw := strings.TrimSpace(os.Getenv(envJWJJWKSURL))
	if raw == "" {
		return cli.JWTWiring{}
	}
	wiring := cli.JWTWiring{
		JWKSURL:       raw,
		Issuer:        strings.TrimSpace(os.Getenv(envJWTIssuer)),
		Audience:      strings.TrimSpace(os.Getenv(envJWTAudience)),
		OrgClaim:      strings.TrimSpace(os.Getenv(envJWTOrgClaim)),
		KeyLabelClaim: strings.TrimSpace(os.Getenv(envJWTKeyLabelClm)),
	}
	if wiring.OrgClaim == "" {
		wiring.OrgClaim = "org_id"
	}

	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		l.Error("invalid YABANIN_JWT_JWKS_URL — JWT auth disabled", "error", err)
		return cli.JWTWiring{}
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		l.Error("YABANIN_JWT_JWKS_URL must be https (plain http only for loopback) — JWT auth disabled",
			"host", u.Hostname())
		return cli.JWTWiring{}
	}

	l.Info("jwt auth wiring enabled",
		"jwks_url", raw,
		"issuer", wiring.Issuer != "",
		"audience", wiring.Audience != "",
		"org_claim", wiring.OrgClaim,
		"key_label_claim", wiring.KeyLabelClaim != "")
	return wiring
}

// isLoopbackHost reports whether host is a loopback address or "localhost".
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

const (
	// envShutdownGrace bounds the whole gateway shutdown drain (N12-P03-T02):
	// after the stop request, in-flight streams, jobs and the audit/event
	// flush get exactly this window to finish before the process force-exits.
	// The default covers the inner drain worst case (pkg/gateway: ~5s HTTP
	// server + ~5s lineage close + reservation-escrow drain) with headroom
	// while staying bounded. Read HERE (wiring), deliberately not in
	// pkg/config, like the other kill-switch knobs in this file.
	envShutdownGrace = "YABANIN_SHUTDOWN_GRACE"

	defaultShutdownGrace = 30 * time.Second
	minShutdownGrace     = 1 * time.Second
	maxShutdownGrace     = time.Hour
)

// shutdownGraceFromEnv resolves the bounded shutdown-drain window.
// Empty/absent = 30s. Invalid or out-of-range values FAIL STARTUP rather
// than silently falling back: the knob exists to bound the drain, and a
// typo must not quietly produce an effectively eternal wait.
func shutdownGraceFromEnv() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(envShutdownGrace))
	if raw == "" {
		return defaultShutdownGrace, nil
	}
	grace, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", envShutdownGrace, raw, err)
	}
	if grace < minShutdownGrace || grace > maxShutdownGrace {
		return 0, fmt.Errorf("%s must be between %s and %s, got %s",
			envShutdownGrace, minShutdownGrace, maxShutdownGrace, grace)
	}
	return grace, nil
}

// errForcedShutdown is returned by awaitShutdownExit on its forced-shutdown
// paths. In production forceExit terminates the process, so these returns are
// unreachable; they exist so tests can stub forceExit and assert on it.
var errForcedShutdown = errors.New("gateway forced shutdown")

// forceExit is the process-exit seam for forced shutdown; tests replace it.
var forceExit = os.Exit

// awaitShutdownExit waits for the gateway server goroutine (already asked to
// stop via ctx cancellation) to report its terminal error, bounded by grace.
// N12-P03-T02: streams, jobs and the audit/event flush get that deadline to
// finish, so SIGTERM under load leaves bounded unfinished operations — never
// an unbounded wait on a stuck drain. A second SIGINT/SIGTERM while waiting,
// or the grace expiring, force-exits the process with code 1 instead of
// hanging. Forced exit drops in-flight work deliberately: session-scoped
// advisory locks (including the budget recovery fence) die with the process,
// and every recovery lease's TTL bounds its authority in wall-clock time, so
// neither the second signal nor a forced kill leaves eternal leases.
func awaitShutdownExit(errCh <-chan error, quit <-chan os.Signal, grace time.Duration, l *slog.Logger) error {
	waitCtx, waitCancel := context.WithTimeout(context.Background(), grace)
	defer waitCancel()
	select {
	case err := <-errCh:
		return err
	case <-quit:
		l.Error("forced shutdown: second signal received while draining — in-flight streams, jobs and audit flush are abandoned; session-scoped locks die with the process and recovery leases stay TTL-bounded")
		forceExit(1)
		return fmt.Errorf("%w: second signal", errForcedShutdown)
	case <-waitCtx.Done():
		l.Error("forced shutdown: drain grace elapsed — in-flight streams, jobs and audit flush are abandoned; session-scoped locks die with the process and recovery leases stay TTL-bounded",
			"grace", grace.String())
		forceExit(1)
		return fmt.Errorf("%w: grace %s expired", errForcedShutdown, grace)
	}
}

// Gateway starts the gateway API server: config load/validation, tracing, KMS,
// the Postgres pool, and the HTTP server with graceful shutdown on
// SIGINT/SIGTERM or parentCtx cancellation. The drain is bounded
// (YABANIN_SHUTDOWN_GRACE, default 30s): in-flight streams, jobs and the
// audit/event flush get that window, then the process force-exits; a second
// signal during the drain force-exits immediately (N12-P03-T02 — bounded
// unfinished operations, no eternal leases after a forced kill). Both the
// standalone gateway binary
// (services/gateway/cmd) and the unified binary's "gateway" subcommand
// delegate here, so their startup and shutdown behavior — and therefore their
// logs — are identical by construction.
//
// The no-database sentinel (errNoDatabaseConfigured) and the NEXT-24
// zombie-guard (exit immediately when the server goroutine reports a startup
// error instead of waiting for a signal) live only in this unified path;
// per-binary mains must not re-implement them.
func Gateway(parentCtx context.Context) error {
	policyWiring, err := policyWiringFromEnv(slog.Default())
	if err != nil {
		return err
	}

	// N12-P03-T02: the bounded shutdown-drain window; resolved at the top so
	// an invalid YABANIN_SHUTDOWN_GRACE fails startup before any I/O.
	shutdownGrace, err := shutdownGraceFromEnv()
	if err != nil {
		return err
	}

	// Kubernetes deployments configure via env only; fall back to defaults
	// when no config file exists and none was requested explicitly.
	cfgFile := config.PathFromEnv()
	if cfgFile == "" {
		if _, statErr := os.Stat("config.yaml"); statErr == nil {
			cfgFile = "config.yaml"
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("failed to load config", "error", err)
		return err
	}

	if err := cfg.Gateway.Validate(); err != nil {
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("invalid gateway config", "error", err)
		return err
	}

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Initialize tracing if an OTEL endpoint is configured.
	if cfg.Gateway.TracingEnabled() {
		if err := tracing.Init(ctx, "gateway", cfg.Gateway.OTELTracingEndpoint, cfg.Gateway.OTELTracingSample); err != nil {
			logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Warn("tracing init failed, continuing without tracing", "error", err)
		}
		//nolint:contextcheck // closure runs after ctx is cancelled at shutdown; deriving from the cancelled parent would abort the flush immediately
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = tracing.Shutdown(shutdownCtx)
		}()
	}

	l := logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat)
	rdb := redisutil.NewClient(cfg.Gateway.RedisAddr)

	// OP-8: the policy-pipeline kill-switch + callout allow-list (env knobs,
	// resolved in this wiring file by policyWiringFromEnv).
	// here by jwtWiringFromEnv). Zero wiring = JWT path off.
	jwtWiring := jwtWiringFromEnv(l)

	// circuitScopeWiringFromEnv). Default = per-endpoint circuits.
	circuitWiring := circuitScopeWiringFromEnv(l)

	// PB2.8: instantiate the per-region KMS provider for envelope encryption.
	var km kms.Provider
	if cfg.Gateway.KMSProvider != "" {
		var err error
		km, err = kms.New(cfg.Gateway.KMSProvider, cfg.Gateway.KMSKeyID)
		if err != nil {
			l.Warn("KMS init failed; per-model key encryption unavailable", "error", err)
		} else {
			l.Info("KMS provider initialized", "provider", cfg.Gateway.KMSProvider, "region", cfg.Gateway.Region)
		}
	}

	pool, err := openGatewayPool(ctx, cfg, l)
	if err != nil {
		if errors.Is(err, errNoDatabaseConfigured) {
			l.Info("no database configured — running in resolver-fallback-only mode")
		} else {
			return err
		}
	}
	if pool != nil {
		defer pool.Close()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- cli.RunGatewayServerWithJWT(cfg.Gateway, rdb, pool, km, l, ctx, jwtWiring, circuitWiring, policyWiring)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	// NEXT-24 finding: a STARTUP failure (bad secret, bad config reached here,
	// listener bind error) used to sit in errCh unseen until a signal arrived —
	// a zombie "Up" container no orchestrator would restart. Exit immediately
	// when the server goroutine reports an error.
	select {
	case err := <-errCh:
		if err != nil {
			logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("gateway exited with error", "error", err)
			return err
		}
		return nil
	case <-quit:
	case <-parentCtx.Done():
	}

	l.Info("shutting down gateway...", "grace", shutdownGrace.String())
	cancel()

	// N12-P03-T02: bounded drain — wait for the server goroutine (streams,
	// jobs, audit/event flush happen inside its shutdown) at most
	// shutdownGrace; a second signal or the grace expiring force-exits
	// instead of hanging forever on a stuck drain.
	if err := awaitShutdownExit(errCh, quit, shutdownGrace, l); err != nil {
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("gateway exited with error", "error", err)
		return err
	}
	return nil
}

// openGatewayPool builds the Postgres connection pool for the gateway from the
// configured PGURI. It returns errNoDatabaseConfigured when no PGURI is set, so
// the gateway can run in resolver-fallback-only mode.
//
// The pool is returned via the return statement rather than assigned to an
// outer-scope variable. This makes the pool-shadowing regression (where the
// unified binary passed a nil pool to RunGatewayServer) structurally impossible
// to reintroduce — the caller cannot silently lose the pointer.
func openGatewayPool(ctx context.Context, cfg config.All, l *slog.Logger) (*pgxpool.Pool, error) {
	if cfg.Gateway.PGURI == "" {
		return nil, errNoDatabaseConfigured
	}

	// pgxpool.ParseConfig (not pgx.ParseConfig + manual wrap) so the pool
	// config carries the createdByParseConfig flag that
	// pgxpool.NewWithConfig requires in pgx v5.10.
	pc, err := pgxpool.ParseConfig(cfg.Gateway.PGURI)
	if err != nil {
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("failed to parse pg_uri", "error", err)
		return nil, err
	}
	if cfg.Gateway.Region != "" {
		if err := regionrouter.ConfigurePool(pc, cfg.Gateway.Region); err != nil {
			logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("failed to configure RLS region hook", "error", err)
			return nil, err
		}
		l.Info("RLS region context configured", "region", cfg.Gateway.Region)
	}

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("failed to connect to database", "error", err)
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		l.Warn("database ping failed, resolver will use fallback only", "error", err)
	} else {
		l.Info("connected to database")
	}
	return pool, nil
}
