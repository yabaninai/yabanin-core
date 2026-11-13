package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/feedback"
	cli "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/inventory"
	"github.com/reireirei/yabanin/pkg/kms"
	"github.com/reireirei/yabanin/pkg/license"
	"github.com/reireirei/yabanin/pkg/lineage"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	tplmarket "github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/policystore"
	"github.com/reireirei/yabanin/pkg/pprof"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/reireirei/yabanin/pkg/rulestore"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/reireirei/yabanin/pkg/tracing"
	"github.com/reireirei/yabanin/pkg/whitelist"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// adminMaxHeaderBytes mirrors pkg/gateway's gatewayMaxHeaderBytes: the
// YABANIN_HTTP_MAX_HEADER_BYTES aggregate request-header override with a 1 MiB
// default and a 16 MiB ceiling. Invalid overrides fail startup rather than
// silently weakening configuration. (The gateway helper is unexported; keep
// the semantics identical so a future consolidation stays behavior-neutral.)
const defaultAdminMaxHeaderBytes = 1 << 20
const maxAdminMaxHeaderBytes = 16 << 20

func adminMaxHeaderBytes() (int, error) {
	if raw := strings.TrimSpace(os.Getenv("YABANIN_HTTP_MAX_HEADER_BYTES")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("YABANIN_HTTP_MAX_HEADER_BYTES must be an integer: %w", err)
		}
		if n <= 0 || n > maxAdminMaxHeaderBytes {
			return 0, fmt.Errorf("YABANIN_HTTP_MAX_HEADER_BYTES must be between 1 and %d bytes", maxAdminMaxHeaderBytes)
		}
		return n, nil
	}
	return defaultAdminMaxHeaderBytes, nil
}

// newAdminHTTPServer builds the admin panel listener with the same env-driven
// aggregate header cap as the gateway listeners: an operator override (or a
// slow-header client) must not leave the admin surface weaker than the
// public one. Deadlines keep the admin panel's existing values.
func newAdminHTTPServer(addr string, handler http.Handler) (*http.Server, error) {
	maxHeaderBytes, err := adminMaxHeaderBytes()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}, nil
}

// adminStartup carries the resolved, defaulted startup inputs shared by the
// admin wiring stages: deployment config, logger, session identity with
// rotation grace, and listener defaults.
type adminStartup struct {
	cfg                   config.All
	admin                 config.AdminAdmin
	logger                *slog.Logger
	sessionSecret         string
	previousSessionSecret string
	sessionGrace          time.Duration
	sessionGraceStarted   time.Time
	adminDomain           string
	listenAddr            string
}

// adminResolveStartup validates and defaults the admin startup inputs:
// the datastore URI and session-secret policy are fail-closed gates, the
// domain/listener/grace knobs fall back to their documented defaults.
func adminResolveStartup(cfg config.All) (*adminStartup, error) {
	adminCfg := cfg.Admin
	logger := logging.New(adminCfg.LogLevel, adminCfg.LogFormat)
	if adminCfg.PGURI == "" {
		logger.Error("YABANIN_PG_URI is required")
		return nil, errors.New("admin: YABANIN_PG_URI is required")
	}

	sessionSecret, generated, err := adminauth.ResolveSessionSecret(adminCfg.SessionKey, adminProductionEnv())
	if err != nil {
		logger.Error("admin: session secret rejected", "error", err)
		return nil, err
	}

	s := &adminStartup{
		cfg:           cfg,
		admin:         adminCfg,
		logger:        logger,
		sessionSecret: sessionSecret,
		sessionGrace:  24 * time.Hour,
		adminDomain:   adminCfg.AdminDomain,
		listenAddr:    adminCfg.ListenAddr,
	}
	if s.adminDomain == "" {
		s.adminDomain = "localhost"
	}
	if s.listenAddr == "" {
		s.listenAddr = ":8086"
	}

	_, previousSessionSecret, graceValue := config.AdminSessionRotationFromEnv()
	s.previousSessionSecret = previousSessionSecret
	if graceValue != "" {
		grace, err := time.ParseDuration(graceValue)
		if err != nil || grace < 0 {
			return nil, fmt.Errorf("admin: invalid YABANIN_ADMIN_SESSION_SECRET_GRACE duration")
		}
		s.sessionGrace = grace
	}
	s.sessionGraceStarted = time.Now()
	if generated {
		logger.Warn("admin: session secret generated at startup (ephemeral: sessions do not survive restart)")
	}
	return s, nil
}

// adminVerifyLicenseChain enforces the fail-closed license activation gate:
// if EITHER activation env var is set, BOTH must be, and an activated pair
// must verify. Returns the license path for the entitlement-diagnostics
// adapter.
func adminVerifyLicenseChain(logger *slog.Logger, lic config.LicenseEnv) (string, error) {
	licensePath, rootPubHex, crlPath := lic.File, lic.RootPubKey, lic.CRLFile

	if licensePath != "" && rootPubHex == "" {
		fmt.Fprintf(os.Stderr, "FATAL: YABANIN_LICENSE_ROOT_PUBKEY is required when YABANIN_LICENSE_FILE is set\n")
		return "", errors.New("admin: license env incomplete (missing root pubkey)")
	}
	if rootPubHex != "" && licensePath == "" {
		fmt.Fprintf(os.Stderr, "FATAL: YABANIN_LICENSE_FILE is required when YABANIN_LICENSE_ROOT_PUBKEY is set\n")
		return "", errors.New("admin: license env incomplete (missing license file)")
	}

	if licensePath != "" && rootPubHex != "" {
		if err := license.VerifyLicenseChain(licensePath, rootPubHex, crlPath); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: LICENSE INVALID — %v — admin cannot start without a valid license\n", err)
			return "", fmt.Errorf("admin: license invalid: %w", err)
		}
		logger.Info("License verified successfully")
	}
	return licensePath, nil
}

// adminGateModuleEntitlement applies the same fail-closed posture as the
// chain gate to the offline paid-module entitlement: unconfigured runs
// enterprise-free; a configured-but-invalid contour refuses startup. The
// full offline/no-phone-home/perpetual-run contract is documented on
// resolveModuleEntitlement.
func adminGateModuleEntitlement(logger *slog.Logger) error {
	modEnt, entErr := resolveModuleEntitlement()
	if entErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: MODULE ENTITLEMENT INVALID — %v — fix or unset %s/%s\n",
			entErr, licenseModuleEntitlementFileEnv, licenseModuleEntitlementDeploymentEnv)
		return fmt.Errorf("admin: module entitlement invalid: %w", entErr)
	}
	logModuleEntitlementStatus(logger, modEnt)
	return nil
}

// adminInitTracing initializes OTEL tracing when an endpoint is configured.
// The returned flush must be deferred by the caller: it runs with its own
// background deadline because the run context is already cancelled by then,
// and deriving from it would abort the flush immediately. Init failures are
// non-fatal (the admin plane runs without tracing).
func adminInitTracing(ctx context.Context, adminCfg config.AdminAdmin, logger *slog.Logger) func() {
	if !adminCfg.TracingEnabled() {
		return func() {}
	}
	if err := tracing.Init(ctx, "admin", adminCfg.OTELTracingEndpoint, adminCfg.OTELTracingSample); err != nil {
		logger.Warn("tracing init failed, continuing without tracing", "error", err)
	}
	return func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = tracing.Shutdown(shutdownCtx)
	}
}

// adminConnectPool opens the admin datastore pool with the RLS region hook:
// every pooled connection assumes the non-owner app role and binds
// app.region, so RLS policies hold no matter which login the DSN carries.
func adminConnectPool(ctx context.Context, cfg config.All, logger *slog.Logger) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.Admin.PGURI)
	if err != nil {
		logger.Error("failed to parse pg_uri", "error", err)
		return nil, err
	}
	region := cfg.Gateway.Region
	if region == "" {
		region = "sg"
	}
	if err := regionrouter.ConfigurePool(pc, region); err != nil {
		logger.Error("failed to configure RLS region hook", "error", err)
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		logger.Error("database ping failed", "error", err)
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// adminNewStore builds the adminstore.Store with versioned-credential KMS
// adoption and the plaintext-secret migration. A configured-but-unusable
// keyset logs loudly and keeps legacy envelopes (same warn-and-continue
// posture as the gateway KMS provider): writes stay enc: until the keyset
// loads. The migration is idempotent and a no-op without an encryption key.
func adminNewStore(ctx context.Context, pool *pgxpool.Pool, enc *encryption.Encryptor, logger *slog.Logger) *adminstore.Store {
	store := adminstore.New(pool, logger, enc)
	if kms.KeysetConfigured() {
		kv, err := kms.NewVersionedFromEnv()
		if err != nil {
			logger.Warn("versioned credential keyset configured but unusable; org credentials keep legacy envelopes", "error", err)
		} else {
			store.AdoptCredentialKMS(kv)
			logger.Info("org credential envelopes: versioned keyset adopted", "env", "YABANIN_KMS_KEYSET_FILE")
		}
	}
	if n, err := store.MigratePlaintextSecrets(ctx); err != nil {
		logger.Warn("plaintext upstream_api_key migration failed; will retry on next start", "error", err)
	} else if n > 0 {
		logger.Info("migrated plaintext upstream_api_key rows to encrypted storage", "count", n)
	}
	return store
}

// adminNewHandlers builds the AdminHandlers core: session identity with
// rotation grace, the served license state for entitlement diagnostics, and
// the store-backed read planes. The returned stop function halts the
// diagnostics adapter's re-verification loop at shutdown.
func adminNewHandlers(ctx context.Context, s *adminStartup, store *adminstore.Store, licensePath string) (*handlers.AdminHandlers, func()) {
	h := handlers.New(store, s.sessionSecret, s.adminDomain, s.cfg.Gateway.TrustedProxies)
	h.SetReservationsGate(s.cfg.Gateway.Reservations)
	h.SetSessionSecretGrace(s.previousSessionSecret, s.sessionGraceStarted, s.sessionGrace)
	licDiag := newAdminEntitlementDiagnostics(licensePath)
	h.SetEntitlementDiagnostics(licDiag)
	h.SetLabelPolicyStore(store)
	h.SetAnalyticsViewStore(store)
	// The diagnostics stop runs at AdminServer return alongside the other
	// shutdown defers. Close discards the context, but the parent ctx is
	// cancelled during shutdown, so derive a never-cancelled context
	// instead of a raw Background to keep the inherited-context contract.
	return h, func() { licDiag.Close(context.WithoutCancel(ctx)) }
}

// adminWireAccessKeys mounts the optional credential-gated surfaces. Each
// stays dark without its key and the key values themselves are never logged:
// the shared gateway /metrics bearer key (empty keeps the documented
// network-restriction-only default), the read-only /internal service API,
// and the EE session-validation relay (fail-closed verdict from the same
// validation path as the console middleware).
func adminWireAccessKeys(h *handlers.AdminHandlers, cfg config.All, logger *slog.Logger) {
	if cfg.Gateway.MetricsBearerKey != "" {
		h.SetMetricsBearerKey(cfg.Gateway.MetricsBearerKey)
		logger.Info("admin: /metrics bearer auth enabled")
	}
	if internalAdminKey := config.InternalAdminKey(); internalAdminKey != "" {
		h.SetInternalServiceKey(internalAdminKey)
		logger.Info("admin: /internal service API enabled (YABANIN_ADMIN_API_KEY set)")
	}
	if eeToken := config.EEInternalToken(); eeToken != "" {
		h.SetEEInternalToken(eeToken)
		logger.Info("admin: EE session-validation endpoint enabled (EE_INTERNAL_TOKEN set)")
	}
}

// adminWireFeedback mounts the feedback plane: the collector authenticates
// /v1/feedback callers and attributes the org server-side with no cache
// (feedback is low-QPS; revocation freshness of the key state matters more
// than latency), plus the root-only list/export routes. The beta metrics SQL
// views bootstrap idempotently over a short-lived DSN-login pool (the app
// pool runs as the NOBYPASSRLS role and cannot CREATE in the public
// schema); failure is non-fatal — the owner page and Grafana panels answer
// empty until the next start.
func adminWireFeedback(ctx context.Context, h *handlers.AdminHandlers, pool *pgxpool.Pool, adminCfg config.AdminAdmin, logger *slog.Logger) *feedback.Collector {
	feedbackCollector := feedback.NewCollector(pool, logger.With("component", "feedback"))
	h.SetFeedbackCollector(feedbackCollector, auth.NewResolver(pool, nil, 0, nil))
	h.SetFeedbackLister(feedback.NewLister(pool))
	if err := feedback.EnsureMetricsViewsURI(ctx, adminCfg.PGURI); err != nil {
		logger.Warn("beta metrics views bootstrap failed; dashboards stay empty until next start", "error", err)
	} else {
		logger.Info("beta metrics views ready", "views", len(feedback.MetricsViewNames()))
	}
	return feedbackCollector
}

// adminWireBilling mounts the billing plane: the DB-backed pricer (the
// gateway reads models_pricing through it), the durable rates-catalog
// store (admin promotes against and serves the active-of-record in
// rates_catalog_state), and the credits store for reseller billing admin.
func adminWireBilling(h *handlers.AdminHandlers, store *adminstore.Store, pool *pgxpool.Pool, cfg config.All, logger *slog.Logger) {
	h.SetDBPricer(pricing.NewDBPricer(pool))
	h.SetRatesCatalogStore(store)

	storeCfg := credits.DefaultConfig()
	storeCfg.GracePeriodCents = cfg.Gateway.CreditsGraceCents
	if ttl, err := time.ParseDuration(cfg.Gateway.CreditsCacheTTL); err == nil && ttl > 0 {
		storeCfg.CacheTTL = ttl
	}
	creditStore := credits.NewStoreWithConfig(pool, logger.With("component", "admin-credits"), storeCfg)
	h.SetCreditStore(creditStore, pool)
}

// adminWireRegistries mounts the external-integration registries: the MCP
// server registry with its SSRF domain allow-list (the deployment's
// YABANIN_MCP_ALLOWED_UPSTREAMS; empty = fail-closed: no domain allowed),
// the observable asset registry with its two import runners, the
// server-level MCP credential store (nil version bumper = TTL-only
// staleness bound) and grant-CRUD lifecycle hook, the A2A agent registry
// (its allow-list reuses the MCP list — one operator-managed dial-out
// surface), and the tool-policy registry sharing the gateway's engine so
// CRUD invalidates the gateway cache. Import runners that fail to construct
// leave their route 503-wired while the read surface stays up; the import
// proxy runs with an EMPTY identity, so per-server tool listing stays a
// miss until the importer identity carries list grants. A bundled pricing
// pack that cannot load downgrades model import to run without pricing
// provenance (warn, never fatal).
func adminWireRegistries(h *handlers.AdminHandlers, store *adminstore.Store, pool *pgxpool.Pool, cfg config.All, logger *slog.Logger) {
	h.SetMCPStore(mcpagg.NewStore(pool), cfg.Gateway.MCPAllowedUpstreams)

	invStore := inventory.NewStore(pool)
	var invMCP handlers.InventoryImporter
	var invModels handlers.InventoryModelImporter
	invProxy := mcpagg.NewProxy(mcpagg.NewStore(pool), mcpagg.NewDefaultConfig(), ssrf.AllowList{}, nil, nil)
	if r, err := inventory.NewImportRunner(invStore, mcpagg.NewStore(pool), &inventory.ProxyToolSource{Proxy: invProxy}); err != nil {
		logger.Error("inventory importer wiring failed; the MCP import route answers 503", "error", err)
	} else {
		invMCP = r
	}
	invPack, packErr := inventory.BundledPricingPack()
	if packErr != nil {
		logger.Warn("bundled pricing pack unavailable; model import runs without pricing provenance", "error", packErr)
		invPack = nil
	}
	if r, err := inventory.NewModelImportRunner(invStore, inventory.NewDBModelRegistrySource(pool), inventory.ProviderCatalog{Cat: nil}, invPack); err != nil {
		logger.Error("model importer wiring failed; the model import route answers 503", "error", err)
	} else {
		invModels = r
	}
	h.SetInventory(invStore, invMCP, invModels)

	h.SetMCPCredentialStore(store, nil)
	h.SetMCPUserCredLifecycle(store)
	h.SetA2AStore(a2aagg.NewStore(pool))

	policyEngine := toolpolicy.NewEngine(toolpolicy.NewStore(pool), 5*time.Second)
	h.SetToolPolicyStore(toolpolicy.NewStore(pool), policyEngine)
}

// adminWireOIDC mounts the console OIDC SSO routes (opt-in). A complete
// issuer/client/secret/redirect tuple wires SSO; a discovery failure keeps
// the password flow and logs loudly — never a half-working SSO mount.
func adminWireOIDC(ctx context.Context, h *handlers.AdminHandlers, cfg config.All, logger *slog.Logger) {
	if cfg.Admin.OIDCIssuer != "" && cfg.Admin.OIDCClientID != "" &&
		cfg.Admin.OIDCClientSecret != "" && cfg.Admin.OIDCRedirectURL != "" {
		oidcClient, err := adminauth.NewOIDCClient(ctx,
			cfg.Admin.OIDCIssuer, cfg.Admin.OIDCClientID,
			cfg.Admin.OIDCClientSecret, cfg.Admin.OIDCRedirectURL)
		if err != nil {
			logger.Error("admin oidc sso disabled — provider init failed", "error", err)
		} else {
			h.SetOIDCClient(oidcClient)
			logger.Info("admin oidc sso enabled", "issuer", cfg.Admin.OIDCIssuer)
		}
	}
}

// adminWireSAML mounts the console SAML SSO routes (opt-in). The IdP
// metadata URL is the only required knob (YABANIN_SAML_IDP_METADATA_URL or
// its _FILE docker-secret variant); without it the routes never mount.
// Entity ID and ACS derive deterministically when unset: the ACS from the
// admin domain (https://<admin_domain>/auth/saml/acs), the entity ID from
// the ACS origin. A metadata fetch/init failure logs loudly and keeps the
// password flow — never a half-mounted SSO. The metadata refresh loop
// takes rollover into effect without a restart; a failed refresh keeps the
// cached metadata serving (fail-open). Interval knob:
// YABANIN_SAML_METADATA_REFRESH_SECONDS (default 3600, 0 = off).
func adminWireSAML(ctx context.Context, h *handlers.AdminHandlers, cfg config.All, logger *slog.Logger) {
	samlOpts := adminauth.SAMLOptionsFromEnv()
	if samlOpts == nil {
		return
	}
	if samlOpts.ACSURL == "" {
		samlOpts.ACSURL = adminauth.SAMLDeriveACSURL(cfg.Admin.AdminDomain)
	}
	samlSP, err := adminauth.NewSAMLSP(ctx, *samlOpts)
	if err != nil {
		logger.Error("admin saml sso disabled — provider init failed", "error", err)
		return
	}
	h.SetSAMLSP(samlSP)
	logger.Info("admin saml sso enabled",
		"idp_entity", samlSP.IDPEntityID(),
		"sp_entity", samlSP.SP.EntityID,
		"acs", samlSP.SP.AcsURL.String())
	if interval := adminauth.SAMLMetadataRefreshInterval(); interval > 0 {
		go samlSP.RunMetadataRefresh(ctx, interval, logger)
		logger.Info("admin saml metadata refresh loop started", "interval", interval.String())
	}
}

// adminWirePortal mounts the developer portal (opt-in). The portal OIDC
// tuple is optional; a provider init failure mounts the portal without SSO
// and logs loudly.
func adminWirePortal(ctx context.Context, h *handlers.AdminHandlers, store *adminstore.Store, cfg config.All, logger *slog.Logger) {
	if !cfg.Admin.PortalEnabled {
		return
	}
	var portalClient *adminauth.OIDCClient
	if cfg.Admin.PortalOIDCIssuer != "" && cfg.Admin.PortalOIDCClientID != "" &&
		cfg.Admin.PortalOIDCSecret != "" && cfg.Admin.PortalOIDCRedirectURL != "" {
		client, err := adminauth.NewOIDCClient(ctx,
			cfg.Admin.PortalOIDCIssuer, cfg.Admin.PortalOIDCClientID,
			cfg.Admin.PortalOIDCSecret, cfg.Admin.PortalOIDCRedirectURL)
		if err != nil {
			logger.Error("developer portal oidc disabled — provider init failed", "error", err)
		} else {
			portalClient = client
		}
	}
	h.SetPortal(handlers.PortalOptions{
		Enabled:        true,
		Provisioning:   cfg.Admin.PortalProvisioning,
		AllowedDomains: cfg.Admin.PortalAllowedDomains,
		DefaultOrg:     cfg.Admin.PortalDefaultOrg,
		DefaultTeam:    cfg.Admin.PortalDefaultTeam,
		MaxKeys:        cfg.Admin.PortalMaxKeys,
		KeyTTLDays:     cfg.Admin.PortalKeyTTLDays,
		GatewayURL:     cfg.Admin.PortalGatewayURL,
		Client:         portalClient,
		Store:          store,
	})
	logger.Info("developer portal enabled", "provisioning", cfg.Admin.PortalProvisioning)
}

// adminWireContentPlane mounts the content and governance surfaces: CORS,
// the vertical compliance pack, the policy template marketplace, the
// feedback exporter with the retrain trigger (the data flywheel), and the
// sovereign model marketplace + region routing admin handlers.
func adminWireContentPlane(h *handlers.AdminHandlers, pool *pgxpool.Pool, store *adminstore.Store, cfg config.All, feedbackCollector *feedback.Collector) {
	h.SetAllowedOrigins(cfg.Admin.AllowedOrigins)

	vh := handlers.NewVerticalHandlers(store, store.Log())
	h.SetVerticalHandlers(vh)

	if pool != nil {
		mp := tplmarket.NewTemplateMarketplace(pool)
		th := handlers.NewPolicyTemplateHandlers(mp, store)
		h.SetTemplateHandlers(th)

		exporter := feedback.NewExporter(pool)
		h.SetFeedbackExporter(exporter)

		trigger := classifier.NewFeedbackDrivenRetrainTrigger()
		rh := handlers.NewRetrainHandlers(exporter, trigger)
		rh.SetFeedbackCollector(feedbackCollector)
		h.SetRetrainHandlers(rh)
	}

	h.SetSovereignHandlers(handlers.NewSovereignHandlers(store, nil))
	h.SetRegionHandlers(handlers.NewRegionHandlers(store, nil))
}

// adminConnectRedis connects the shared gateway Redis (cache/whitelist
// components ride the same instance). An unreachable Redis disables those
// features with a warning instead of failing startup.
func adminConnectRedis(ctx context.Context, cfg config.All, logger *slog.Logger) *redis.Client {
	if cfg.Gateway.RedisAddr == "" {
		return nil
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Gateway.RedisAddr,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		DialTimeout:  3 * time.Second,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Warn("redis not available, cache/whitelist features disabled", "error", err)
		return nil
	}
	return rdb
}

// adminWireRedisCaches mounts the Redis-backed invalidation paths: instant
// key-revocation propagation (revocations purge org:resolve:<hash> so a
// revoked key dies now; TTL stays the fallback when Redis is absent), the
// rule-mutation cache purge (new/updated/deleted rules visible without the
// TTL wait), and the rate limiter (fails open when Redis is down:
// admin_ratelimit_fallback_total + throttled WARN).
func adminWireRedisCaches(h *handlers.AdminHandlers, rdb *redis.Client, store *adminstore.Store, logger *slog.Logger) {
	if rdb == nil {
		return
	}
	h.SetResolverCache(redisResolverCache{c: rdb})
	h.SetRuleCacheInvalidator(rulestore.New(nil, rdb, 0, nil, logger.With("component", "rule-cache-inv")))
	h.SetRateLimitRedis(rdb)
}

// adminWireDataPlane mounts the store-backed policy and data surfaces over
// the pool and, when Redis is present, the version-key bumpers that drop
// the gateway's caches immediately on mutation (orgcreds:ver:, policystore:
// ver:, canarystore:ver:<orgID> — the adminstore version-key-prefix
// contracts). Without Redis the bumps are skipped and staleness is bounded
// by the gateway's TTL fallbacks (30s probe for org creds).
func adminWireDataPlane(ctx context.Context, h *handlers.AdminHandlers, pool *pgxpool.Pool, rdb *redis.Client, store *adminstore.Store, cfg config.All, logger *slog.Logger) {
	if pool == nil {
		return
	}

	cacheStore := cache.NewStore(pool)
	if rdb != nil {
		redisStore := cache.NewRedisStore(rdb, 24*time.Hour)
		h.SetCacheInvalidator(cache.NewInvalidator(redisStore, cacheStore, rdb))
		// cache.Warmer was removed (it wrote unsigned entries the gateway
		// always rejected); POST /api/cache/warm answers 410 from the handler.
	}
	h.SetPolicyLoader(cache.NewPolicyCache(60 * time.Second))

	// Unwired deployments answer 501 on the experiment routes.
	h.SetExperimentStore(cache.NewExperimentStore(pool))

	if rdb != nil {
		h.SetWhitelistLoader(whitelist.NewLoader(store, rdb, 5*time.Minute, logger.With("component", "wl-loader")))
	}

	h.SetPolicyPackStore(policystore.New(pool))
	h.SetOrgResidencyStore(store) // *adminstore.Store satisfies OrgResidencyStore

	// Org provider-credential CRUD + SSRF-guarded connection test.
	// AllowHTTPPrivate admits http:// literal-private-IP base URLs
	// (on-prem vLLM/TGI/Ollama) behind an explicit env knob; hostname
	// targets stay https-only either way.
	credOpts := handlers.OrgCredentialHandlerOptions{
		AllowHTTPPrivate: envBool("YABANIN_ORG_CRED_ALLOW_HTTP_PRIVATE", false),
	}
	if rdb != nil {
		credOpts.VersionBumper = cli.NewOrgCredsVersionStore(rdb, logger.With("component", "orgcreds-versions"))
	}
	h.SetOrgCredentialHandlers(handlers.NewOrgCredentialHandlers(store, credOpts, store.Log()))

	if rdb != nil {
		store.SetPolicyVersionBumper(adminstore.NewPolicyVersionCache(rdb, logger.With("component", "policy-versions")))
	}
	h.SetPolicyPipelineHandlers(handlers.NewPolicyPipelineHandlers(store))

	if rdb != nil {
		store.SetCanaryVersionBumper(adminstore.NewCanaryVersionCache(rdb, logger.With("component", "canary-versions")))
	}
	h.SetCanaryRolloutHandlers(handlers.NewCanaryRolloutHandlers(store))
	// Decision-log read API and prompt studio ride the same store (RLS
	// org isolation).
	h.SetPolicyDecisionHandlers(handlers.NewPolicyDecisionHandlers(store))
	h.SetPromptStudioHandlers(handlers.NewPromptStudioHandlers(store))

	// Lineage: the store satisfies LineageStore via GetLineageByRequestID;
	// the verifier does full Ed25519 signature verification (read-only
	// key access).
	h.SetLineageStore(store)
	ks := lineage.NewKeyStore(pool, nil)
	ls := lineage.NewLedgerStore(pool)
	h.SetLineageVerifier(handlers.NewLineageVerifier(store, ks, ls))

	adminWireGuardPacks(ctx, h, pool, cfg, logger)
}

// adminWireGuardPacks mounts the guard detector-pack lifecycle routes
// (root-only, audited). The lifecycle is hydrated READ-ONLY from the
// durable guard_pack_state row — the same coordination point the gateway
// startup activates through — so activate/rollback CAS from the live
// durable versions immediately after an admin restart. The admin process
// never re-asserts env packs at startup; env-based activation belongs to
// the gateway. An unreadable coordination point keeps the routes unwired
// (503).
func adminWireGuardPacks(ctx context.Context, h *handlers.AdminHandlers, pool *pgxpool.Pool, cfg config.All, logger *slog.Logger) {
	packCfg := cfg.Gateway.GuardPacks() // same YABANIN_GUARD_PACK_DIR source as the gateway
	mode, modeNote := guardhooks.ResolveMode(cfg.Gateway.GuardMode)
	if modeNote != "" {
		logger.Warn(modeNote)
	}
	if gp := guardPackHandlersForAdmin(ctx, pool, logger, mode, packCfg.Dir, cfg.Gateway.GuardPackVerify()); gp != nil {
		h.SetGuardPackHandlers(gp)
		logger.Info("admin guard-pack lifecycle routes wired", "pack_dir", packCfg.Dir, "mode", mode)
	}
}

// adminPprofHandler gates the pprof endpoints behind the root admin
// session cookie: the admin server can be publicly reachable, so profiling
// is served only to an authenticated root session.
func adminPprofHandler(sessionSecret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sessVal string
		for _, c := range r.Cookies() {
			if c.Name == "yabanin_admin_session" {
				sessVal = c.Value
				break
			}
		}
		if sessVal == "" {
			http.Error(w, "unauthorized: root access required", http.StatusUnauthorized)
			return
		}
		sess, err := adminauth.ParseAdminSessionCookie(sessVal, sessionSecret)
		if err != nil || !sess.IsRoot {
			http.Error(w, "unauthorized: root access required", http.StatusUnauthorized)
			return
		}
		pprof.Handler().ServeHTTP(w, r)
	})
}

// adminBuildMux assembles the final admin handler: the router, optionally
// the authenticated root-only pprof endpoints, and the tracing middleware.
func adminBuildMux(h *handlers.AdminHandlers, sessionSecret string, cfg config.All, logger *slog.Logger) http.Handler {
	mux := h.SetupRouter()

	if cfg.Gateway.DebugPprof {
		combined := http.NewServeMux()
		combined.Handle("/", mux)
		combined.Handle("/debug/pprof/", adminPprofHandler(sessionSecret))
		mux = combined
		logger.Info("pprof endpoints enabled on admin server (authenticated root-only)")
	}

	if cfg.Admin.TracingEnabled() {
		logger.Info("tracing enabled")
		mux = tracing.WrapHandler(mux)
	}
	return mux
}

// adminServe runs the HTTP listener and the background spend-alert checker
// until SIGINT/SIGTERM or ctx cancellation, then drains both before
// returning. The checker runs on a child context cancelled at shutdown,
// before the listener drain, so wg.Wait cannot deadlock on it.
func adminServe(ctx context.Context, srv *http.Server, store *adminstore.Store, h *handlers.AdminHandlers, logger *slog.Logger, listenAddr string) {
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("admin panel starting", "addr", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin panel error", "error", err)
		}
	}()

	// Background spend alert checker.
	wg.Add(1)
	go func() {
		defer wg.Done()
		checker := adminstore.NewSpendAlertChecker(store, logger)
		checker.Run(serveCtx)
	}()

	logger.Info("admin panel running", "addr", listenAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
	case <-ctx.Done():
	}

	logger.Info("shutting down admin panel...")
	serveCancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	//nolint:contextcheck // shutdown runs after cancel(); a context derived from the cancelled ctx would time out instantly
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin shutdown failed", "error", err)
	}

	h.Stop()

	wg.Wait()
}

// AdminServer starts the admin HTTP control-plane server and blocks until
// SIGINT/SIGTERM. Config, license and datastore failures return an error
// (fail-closed: the caller must not start a degraded admin plane).
func AdminServer(ctx context.Context) error {
	cfg, err := config.Load("")
	if err != nil {
		logging.New(cfg.Admin.LogLevel, cfg.Admin.LogFormat).Error("failed to load config", "error", err)
		return err
	}

	s, err := adminResolveStartup(cfg)
	if err != nil {
		return err
	}
	logger := s.logger

	licensePath, err := adminVerifyLicenseChain(logger, config.LicenseFromEnv())
	if err != nil {
		return err
	}
	if err := adminGateModuleEntitlement(logger); err != nil {
		return err
	}

	var enc *encryption.Encryptor
	if s.admin.EncryptionKey != "" {
		enc, err = encryption.New(s.admin.EncryptionKey)
		if err != nil {
			logging.New(s.admin.LogLevel, s.admin.LogFormat).Error("failed to create encryptor", "error", err)
			return err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer adminInitTracing(ctx, s.admin, logger)()

	pool, err := adminConnectPool(ctx, s.cfg, logger)
	if err != nil {
		return err
	}
	defer pool.Close()

	store := adminNewStore(ctx, pool, enc, logger)
	h, stopEntitlementDiag := adminNewHandlers(ctx, s, store, licensePath)
	defer stopEntitlementDiag()

	adminWireAccessKeys(h, s.cfg, logger)
	feedbackCollector := adminWireFeedback(ctx, h, pool, s.admin, logger)
	adminWireBilling(h, store, pool, s.cfg, logger)
	adminWireRegistries(h, store, pool, s.cfg, logger)
	adminWireOIDC(ctx, h, s.cfg, logger)
	adminWireSAML(ctx, h, s.cfg, logger)
	adminWirePortal(ctx, h, store, s.cfg, logger)
	adminWireContentPlane(h, pool, store, s.cfg, feedbackCollector)

	rdb := adminConnectRedis(ctx, s.cfg, logger)
	adminWireRedisCaches(h, rdb, store, logger)
	adminWireDataPlane(ctx, h, pool, rdb, store, s.cfg, logger)

	mux := adminBuildMux(h, s.sessionSecret, s.cfg, logger)
	srv, err := newAdminHTTPServer(s.listenAddr, mux)
	if err != nil {
		logger.Error("admin panel: rejected header byte cap", "error", err)
		return err
	}

	adminServe(ctx, srv, store, h, logger, s.listenAddr)
	return nil
}

// redisResolverCache adapts *redis.Client to handlers.ResolverCache
// (Del returns *redis.IntCmd, not error).
type redisResolverCache struct{ c *redis.Client }

func (r redisResolverCache) Del(ctx context.Context, keys ...string) error {
	return r.c.Del(ctx, keys...).Err()
}

// adminProductionEnv — fail-closed определение production: только явные
// dev/test значения переменной окружения YABANIN_ENV считаются
// непродакшеном; пустое значение и всё остальное — production (слабый
// секрет отказывает в старте).
func adminProductionEnv() bool {
	switch strings.ToLower(strings.TrimSpace(config.DeploymentEnv())) {
	case "dev", "development", "test":
		return false
	default:
		return true
	}
}

// envBool reads a boolean env knob (W-VER integration feed for the BYOK
// http-private allowance). Unset/unparseable → the default.
func envBool(name string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
