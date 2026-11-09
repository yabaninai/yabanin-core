package run

import (
	"context"
	"errors"
	"fmt"
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

// AdminServer starts the admin HTTP control-plane server and blocks until
// SIGINT/SIGTERM. Config, license and datastore failures return an error
// (fail-closed: the caller must not start a degraded admin plane).
func AdminServer(ctx context.Context) error {
	cfg, err := config.Load("")
	if err != nil {
		logging.New(cfg.Admin.LogLevel, cfg.Admin.LogFormat).Error("failed to load config", "error", err)
		return err
	}

	adminCfg := cfg.Admin
	if adminCfg.PGURI == "" {
		logging.New(adminCfg.LogLevel, adminCfg.LogFormat).Error("YABANIN_PG_URI is required")
		return errors.New("admin: YABANIN_PG_URI is required")
	}

	sessionSecret, generated, err := adminauth.ResolveSessionSecret(adminCfg.SessionKey, adminProductionEnv())
	if err != nil {
		logging.New(adminCfg.LogLevel, adminCfg.LogFormat).Error("admin: session secret rejected", "error", err)
		return err
	}

	adminDomain := adminCfg.AdminDomain
	if adminDomain == "" {
		adminDomain = "localhost"
	}

	listenAddr := adminCfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":8086"
	}

	logger := logging.New(adminCfg.LogLevel, adminCfg.LogFormat)
	_, previousSessionSecret, graceValue := config.AdminSessionRotationFromEnv()
	sessionGrace := 24 * time.Hour
	if graceValue != "" {
		sessionGrace, err = time.ParseDuration(graceValue)
		if err != nil || sessionGrace < 0 {
			return fmt.Errorf("admin: invalid YABANIN_ADMIN_SESSION_SECRET_GRACE duration")
		}
	}
	sessionGraceStarted := time.Now()
	if generated {
		logger.Warn("admin: session secret generated at startup (ephemeral: sessions do not survive restart)")
	}

	// Verify license at startup (fail-closed: if EITHER env var is set, BOTH must be set).
	lic := config.LicenseFromEnv()
	licensePath, rootPubHex, crlPath := lic.File, lic.RootPubKey, lic.CRLFile

	if licensePath != "" && rootPubHex == "" {
		fmt.Fprintf(os.Stderr, "FATAL: YABANIN_LICENSE_ROOT_PUBKEY is required when YABANIN_LICENSE_FILE is set\n")
		return errors.New("admin: license env incomplete (missing root pubkey)")
	}
	if rootPubHex != "" && licensePath == "" {
		fmt.Fprintf(os.Stderr, "FATAL: YABANIN_LICENSE_FILE is required when YABANIN_LICENSE_ROOT_PUBKEY is set\n")
		return errors.New("admin: license env incomplete (missing license file)")
	}

	if licensePath != "" && rootPubHex != "" {
		if err := license.VerifyLicenseChain(licensePath, rootPubHex, crlPath); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: LICENSE INVALID — %v — admin cannot start without a valid license\n", err)
			return fmt.Errorf("admin: license invalid: %w", err)
		}
		logger.Info("License verified successfully")
	}

	// N11-P05-T03: offline paid-module entitlement (I24/I25). Optional: an
	// unconfigured contour runs enterprise-free (no enforcement, no
	// failure); a configured-but-invalid entitlement refuses startup
	// (fail-closed, same posture as the chain gate above). Verification is
	// fully offline (local file + embedded vendor key); the maintenance end
	// never blocks startup — the paid version keeps running after it (I24).
	modEnt, entErr := resolveModuleEntitlement()
	if entErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: MODULE ENTITLEMENT INVALID — %v — fix or unset %s/%s\n",
			entErr, licenseModuleEntitlementFileEnv, licenseModuleEntitlementDeploymentEnv)
		return fmt.Errorf("admin: module entitlement invalid: %w", entErr)
	}
	logModuleEntitlementStatus(logger, modEnt)

	var enc *encryption.Encryptor
	if adminCfg.EncryptionKey != "" {
		enc, err = encryption.New(adminCfg.EncryptionKey)
		if err != nil {
			logging.New(adminCfg.LogLevel, adminCfg.LogFormat).Error("failed to create encryptor", "error", err)
			return err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Initialize tracing if an OTEL endpoint is configured.
	if adminCfg.TracingEnabled() {
		if err := tracing.Init(ctx, "admin", adminCfg.OTELTracingEndpoint, adminCfg.OTELTracingSample); err != nil {
			logging.New(adminCfg.LogLevel, adminCfg.LogFormat).Warn("tracing init failed, continuing without tracing", "error", err)
		}
		//nolint:contextcheck // closure runs after ctx is cancelled at shutdown; deriving from the cancelled parent would abort the flush immediately
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = tracing.Shutdown(shutdownCtx)
		}()
	}

	pc, err := pgxpool.ParseConfig(adminCfg.PGURI)
	if err != nil {
		logger.Error("failed to parse pg_uri", "error", err)
		return err
	}
	region := cfg.Gateway.Region
	if region == "" {
		region = "sg"
	}
	if err := regionrouter.ConfigurePool(pc, region); err != nil {
		logger.Error("failed to configure RLS region hook", "error", err)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return err
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		logger.Error("database ping failed", "error", err)
		return err
	}

	store := adminstore.New(pool, logger, enc)
	// N01-P04 successor: adopt versioned credential envelopes only when a
	// keyset is configured (YABANIN_KMS_KEYSET_FILE); the legacy single-key
	// default is unchanged. A configured-but-unusable keyset logs loudly and
	// keeps legacy envelopes (same warn-and-continue posture as the gateway
	// KMS provider) — writes stay enc: until the keyset loads.
	if kms.KeysetConfigured() {
		kv, err := kms.NewVersionedFromEnv()
		if err != nil {
			logger.Warn("versioned credential keyset configured but unusable; org credentials keep legacy envelopes", "error", err)
		} else {
			store.AdoptCredentialKMS(kv)
			logger.Info("org credential envelopes: versioned keyset adopted", "env", "YABANIN_KMS_KEYSET_FILE")
		}
	}
	// Idempotent; without an encryption key it is a no-op (plaintext stays
	// readable-only until a key is configured).
	if n, err := store.MigratePlaintextSecrets(ctx); err != nil {
		logger.Warn("plaintext upstream_api_key migration failed; will retry on next start", "error", err)
	} else if n > 0 {
		logger.Info("migrated plaintext upstream_api_key rows to encrypted storage", "count", n)
	}
	h := handlers.New(store, sessionSecret, adminDomain, cfg.Gateway.TrustedProxies)
	h.SetReservationsGate(cfg.Gateway.Reservations)
	h.SetSessionSecretGrace(previousSessionSecret, sessionGraceStarted, sessionGrace)
	// E01-P05 W04-C02: root-only entitlement diagnostics — the served
	// license state (activation plane) adapted onto the admin API. The
	// chain was already verified above; the adapter's re-verification loop
	// is stopped at shutdown.
	licDiag := newAdminEntitlementDiagnostics(licensePath)
	h.SetEntitlementDiagnostics(licDiag)
	//nolint:contextcheck // closure runs at RunAdmin return, after ctx is cancelled at shutdown; Background is deliberate (same as the tracing flush above)
	defer func() { licDiag.Close(context.Background()) }()
	h.SetLabelPolicyStore(store)
	h.SetAnalyticsViewStore(store)

	// W-SECADM: the admin /metrics scrape requires the shared gateway bearer
	// key (YABANIN_METRICS_BEARER_KEY) when one is configured. An empty key
	// keeps the documented network-restriction-only default.
	if cfg.Gateway.MetricsBearerKey != "" {
		h.SetMetricsBearerKey(cfg.Gateway.MetricsBearerKey)
		logger.Info("admin: /metrics bearer auth enabled")
	}

	// Optional read-only /internal service API for trcli/automation. Disabled
	// unless the key is present; never log the value itself.
	if internalAdminKey := config.InternalAdminKey(); internalAdminKey != "" {
		h.SetInternalServiceKey(internalAdminKey)
		logger.Info("admin: /internal service API enabled (YABANIN_ADMIN_API_KEY set)")
	}

	// D-UI-4 (owner decision 2026-11-06): internal EE session-validation
	// endpoint (POST /auth/ee/session). The EE backend relays the browser's
	// Cookie header and receives a fail-closed verdict from the same
	// validation path as the admin console middleware. Feature-dark without
	// the token; never log the value itself.
	if eeToken := config.EEInternalToken(); eeToken != "" {
		h.SetEEInternalToken(eeToken)
		logger.Info("admin: EE session-validation endpoint enabled (EE_INTERNAL_TOKEN set)")
	}

	// Wire P5.13 feedback collector (online learning hooks). The resolver
	// authenticates /v1/feedback callers and attributes the org server-side
	// (NEXT-15-F2): no cache — feedback is low-QPS and freshness of the
	// key state (revoked/expired) matters more than latency here.
	feedbackCollector := feedback.NewCollector(pool, logger.With("component", "feedback"))
	h.SetFeedbackCollector(feedbackCollector, auth.NewResolver(pool, nil, 0, nil))

	// W-FEED: owner feedback list/export routes (root-only).
	h.SetFeedbackLister(feedback.NewLister(pool))

	// W-FEED: bootstrap the beta metrics SQL views idempotently (card W-FEED
	// forbids a new migration file). The app pool runs as the NOBYPASSRLS
	// role (SET ROLE) which cannot CREATE in the public schema, so the
	// bootstrap opens its own short-lived pool as the DSN login (the
	// migration owner). Failure is non-fatal: the views are observability —
	// the owner page and Grafana panels answer empty until the next start.
	if err := feedback.EnsureMetricsViewsURI(ctx, adminCfg.PGURI); err != nil {
		logger.Warn("beta metrics views bootstrap failed; dashboards stay empty until next start", "error", err)
	} else {
		logger.Info("beta metrics views ready", "views", len(feedback.MetricsViewNames()))
	}

	// Wire P6.1 DB-backed pricing pricer.
	h.SetDBPricer(pricing.NewDBPricer(pool))
	// AUDIT-P1-04: durable rates-catalog promotion — the admin handlers
	// promote against and serve the active-of-record in rates_catalog_state
	// (the gateway itself reads models_pricing via the DBPricer above).
	h.SetRatesCatalogStore(store)

	// PR1: Wire credits store for reseller billing admin endpoints.
	storeCfg := credits.DefaultConfig()
	storeCfg.GracePeriodCents = cfg.Gateway.CreditsGraceCents
	if ttl, err := time.ParseDuration(cfg.Gateway.CreditsCacheTTL); err == nil && ttl > 0 {
		storeCfg.CacheTTL = ttl
	}
	creditStore := credits.NewStoreWithConfig(pool, logger.With("component", "admin-credits"), storeCfg)
	h.SetCreditStore(creditStore, pool)

	// MCP-02: external MCP server registry CRUD (admin) + the SSRF domain
	// allow-list for server URLs. The list is the deployment's
	// YABANIN_MCP_ALLOWED_UPSTREAMS (empty = fail-closed: no domain allowed).
	h.SetMCPStore(mcpagg.NewStore(pool), cfg.Gateway.MCPAllowedUpstreams)

	// E02-P01: observable asset registry — the root-only admin read surface
	// plus the two import runners (MCP registry snapshot, model/provider
	// reference planes) over the same pool. The import proxy runs with an
	// EMPTY identity: per-server tool listing stays a miss (ToolsSynced
	// false) until the importer identity carries list grants — an operator
	// item disclosed in OPENAPI-DELTA.md; servers and configs import
	// regardless. The bundled pricing pack is the provenance reference; when
	// it cannot load, the model import runs without pricing metadata (warn,
	// never fatal — the registry planes still materialize). A runner that
	// fails to construct (impossible with non-nil seams) leaves that route
	// 503-wired while the read surface stays up — per-seam nils are the
	// documented dark-importer posture.
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

	// MC-1: the server-level MCP credential store. The version bumper (the
	// gateway resolver-cache invalidation) is wired with the MC-2 gateway
	// side; nil keeps the TTL-only staleness bound.
	h.SetMCPCredentialStore(store, nil)
	// MC-3: the grant-CRUD orphan/restore hook over the same store.
	h.SetMCPUserCredLifecycle(store)

	// A2A-01: external A2A agent registry CRUD. The SSRF allow-list reuses
	// the deployment MCP list — one operator-managed dial-out surface.
	h.SetA2AStore(a2aagg.NewStore(pool))

	// TOOL-01: tool policy registry + the shared engine (same engine the
	// gateway consults — here for cache invalidation on CRUD).
	policyEngine := toolpolicy.NewEngine(toolpolicy.NewStore(pool), 5*time.Second)
	h.SetToolPolicyStore(toolpolicy.NewStore(pool), policyEngine)

	// ENT-01: OIDC SSO for the console (opt-in). A complete
	// issuer/client/secret/redirect tuple wires the SSO routes; a discovery
	// failure keeps the password flow and logs loudly — never a half-working
	// SSO mount.
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

	// OIDC block). The IdP metadata URL is the only required knob —
	// YABANIN_SAML_IDP_METADATA_URL (or the docker-secret
	// YABANIN_SAML_IDP_METADATA_URL_FILE); without it the SAML routes never
	// mount. Entity ID and ACS derive deterministically when unset: the ACS
	// from the admin domain (https://<admin_domain>/auth/saml/acs), the
	// entity ID from the ACS origin. A metadata fetch/init failure logs
	// loudly and keeps the password flow — never a half-mounted SSO.
	if samlOpts := adminauth.SAMLOptionsFromEnv(); samlOpts != nil {
		if samlOpts.ACSURL == "" {
			samlOpts.ACSURL = adminauth.SAMLDeriveACSURL(cfg.Admin.AdminDomain)
		}
		samlSP, err := adminauth.NewSAMLSP(ctx, *samlOpts)
		if err != nil {
			logger.Error("admin saml sso disabled — provider init failed", "error", err)
		} else {
			h.SetSAMLSP(samlSP)
			logger.Info("admin saml sso enabled",
				"idp_entity", samlSP.IDPEntityID(),
				"sp_entity", samlSP.SP.EntityID,
				"acs", samlSP.SP.AcsURL.String())
			// rollover takes effect without a restart; a failed refresh keeps
			// the cached metadata serving (fail-open). Interval knob:
			// YABANIN_SAML_METADATA_REFRESH_SECONDS (default 3600, 0 = off).
			if interval := adminauth.SAMLMetadataRefreshInterval(); interval > 0 {
				go samlSP.RunMetadataRefresh(ctx, interval, logger)
				logger.Info("admin saml metadata refresh loop started", "interval", interval.String())
			}
		}
	}

	if cfg.Admin.PortalEnabled {
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

	// PH.4: Wire CORS for admin panel if configured.
	h.SetAllowedOrigins(cfg.Admin.AllowedOrigins)

	// PC2: Wire vertical compliance pack admin handlers.
	vh := handlers.NewVerticalHandlers(store, store.Log())
	h.SetVerticalHandlers(vh)

	// PC3: Wire policy template marketplace + feedback exporter + retrain trigger.
	if pool != nil {
		mp := tplmarket.NewTemplateMarketplace(pool)
		th := handlers.NewPolicyTemplateHandlers(mp, store)
		h.SetTemplateHandlers(th)

		exporter := feedback.NewExporter(pool)
		h.SetFeedbackExporter(exporter)

		// Data flywheel: retrain trigger + status handler.
		trigger := classifier.NewFeedbackDrivenRetrainTrigger()
		rh := handlers.NewRetrainHandlers(exporter, trigger)
		rh.SetFeedbackCollector(feedbackCollector)
		h.SetRetrainHandlers(rh)
	}

	// PB4.9: Sovereign model marketplace admin handlers.
	h.SetSovereignHandlers(handlers.NewSovereignHandlers(store, nil))
	// PB2.7: Region routing admin handlers.
	h.SetRegionHandlers(handlers.NewRegionHandlers(store, nil))

	// F2.5: Wire all remaining admin SetXxx setters.
	// Redis client for cache/whitelist components (admin shares same Redis as gateway).
	var rdb *redis.Client
	if cfg.Gateway.RedisAddr != "" {
		rdb = redis.NewClient(&redis.Options{
			Addr:         cfg.Gateway.RedisAddr,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			DialTimeout:  3 * time.Second,
		})
		if err := rdb.Ping(ctx).Err(); err != nil {
			logger.Warn("redis not available, cache/whitelist features disabled", "error", err)
			rdb = nil
		}
	}
	// S02: instant key-revocation propagation — the admin shares the gateway's
	// Redis; revocations purge org:resolve:<hash> so a revoked key dies now
	// (TTL stays the fallback when Redis is absent).
	if rdb != nil {
		h.SetResolverCache(redisResolverCache{c: rdb})
		// RT-06: rule mutations purge the gateway rule cache (shared Redis)
		// so new/updated/deleted rules are visible without the TTL wait.
		h.SetRuleCacheInvalidator(rulestore.New(nil, rdb, 0, nil, logger.With("component", "rule-cache-inv")))
		// its window via the same Redis; the limiter fails open when Redis is
		// down (admin_ratelimit_fallback_total + throttled WARN).
		h.SetRateLimitRedis(rdb)
	}

	if pool != nil {
		// Cache components.
		cacheStore := cache.NewStore(pool)
		if rdb != nil {
			redisStore := cache.NewRedisStore(rdb, 24*time.Hour)
			h.SetCacheInvalidator(cache.NewInvalidator(redisStore, cacheStore, rdb))
			// W-CACHE: cache.Warmer removed (wrote unsigned entries RT-05 always
			// rejected); POST /api/cache/warm now answers 410 from the handler.
		}
		h.SetPolicyLoader(cache.NewPolicyCache(60 * time.Second))

		// I10: A/B experiments use the real cache.ExperimentStore (the adminstore
		// no-op stubs are gone). Unwired deployments answer 501 on these routes.
		h.SetExperimentStore(cache.NewExperimentStore(pool))

		// Whitelist loader (needs Redis for caching).
		if rdb != nil {
			h.SetWhitelistLoader(whitelist.NewLoader(store, rdb, 5*time.Minute, logger.With("component", "wl-loader")))
		}

		// Policy pack + residency (DB-backed).
		h.SetPolicyPackStore(policystore.New(pool))
		h.SetOrgResidencyStore(store) // *adminstore.Store satisfies OrgResidencyStore

		// W-BYOK: org provider-credential CRUD + SSRF-guarded connection test
		// over the real store. The version bumper shares the gateway's Redis
		// (orgcreds:ver:<orgID>) so CRUD drops the gateway's negative lookups
		// immediately; without Redis the bump is skipped and staleness is
		// bounded by the gateway's 30s probe TTL.
		credOpts := handlers.OrgCredentialHandlerOptions{
			// W-VER integration feed: admit http:// literal-private-IP base
			// URLs (on-prem vLLM/TGI/Ollama) behind an explicit env knob;
			// hostname targets stay https-only either way.
			AllowHTTPPrivate: envBool("YABANIN_ORG_CRED_ALLOW_HTTP_PRIVATE", false),
		}
		if rdb != nil {
			credOpts.VersionBumper = cli.NewOrgCredsVersionStore(rdb, logger.With("component", "orgcreds-versions"))
		}
		h.SetOrgCredentialHandlers(handlers.NewOrgCredentialHandlers(store, credOpts, store.Log()))

		// OP-0b: policy pipeline CRUD over the real store. The version-key
		// bumper shares the gateway's Redis (policystore:ver:<orgID>, the
		// adminstore.PolicyVersionKeyPrefix contract) so every policy
		// mutation drops the gateway's compiled-pipeline caches immediately
		// is skipped and staleness is bounded by OP-8's TTL fallback.
		if rdb != nil {
			store.SetPolicyVersionBumper(adminstore.NewPolicyVersionCache(rdb, logger.With("component", "policy-versions")))
		}
		h.SetPolicyPipelineHandlers(handlers.NewPolicyPipelineHandlers(store))

		// pattern). The version-key bumper shares the gateway's Redis
		// (canarystore:ver:<orgID>, the adminstore.CanaryVersionKeyPrefix
		// contract) so every rollout mutation drops the gateway's cached
		// rollout snapshots immediately; without Redis the bump is skipped
		// and staleness is bounded by the resolver's TTL fallback.
		if rdb != nil {
			store.SetCanaryVersionBumper(adminstore.NewCanaryVersionCache(rdb, logger.With("component", "canary-versions")))
		}
		h.SetCanaryRolloutHandlers(handlers.NewCanaryRolloutHandlers(store))
		// OP-9: the decision-log read API rides the same store (RLS read path).
		h.SetPolicyDecisionHandlers(handlers.NewPolicyDecisionHandlers(store))
		// the same store (RLS org isolation in the 0010 posture).
		h.SetPromptStudioHandlers(handlers.NewPromptStudioHandlers(store))

		// Lineage (store already satisfies LineageStore via GetLineageByRequestID).
		h.SetLineageStore(store)

		// Wire lineage verifier with full Ed25519 signature verification.
		ks := lineage.NewKeyStore(pool, nil) // read-only: public key only
		ls := lineage.NewLedgerStore(pool)
		h.SetLineageVerifier(handlers.NewLineageVerifier(store, ks, ls))

		// Guard detector-pack lifecycle routes (root-only, audited). The
		// lifecycle is hydrated READ-ONLY from the durable guard_pack_state
		// row — the same coordination point the gateway startup activates
		// through — so activate/rollback CAS from the live durable versions
		// immediately after an admin restart. The admin process never
		// re-asserts env packs at startup; env-based startup activation
		// belongs to the gateway. An unreadable coordination point keeps the
		// routes unwired (503).
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

	mux := h.SetupRouter()

	// Wire pprof profiling endpoints on the admin server (authenticated + root-only).
	if cfg.Gateway.DebugPprof {
		combined := http.NewServeMux()
		combined.Handle("/", mux)
		// Gate pprof behind session cookie validation + root check to prevent
		// unauthenticated access when the admin server is publicly reachable.
		combined.Handle("/debug/pprof/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}))
		mux = combined
		logger.Info("pprof endpoints enabled on admin server (authenticated root-only)")
	}

	// Wrap with tracing middleware if enabled.
	if adminCfg.TracingEnabled() {
		logger.Info("tracing enabled")
		mux = tracing.WrapHandler(mux)
	}

	srv, err := newAdminHTTPServer(listenAddr, mux)
	if err != nil {
		logger.Error("admin panel: rejected header byte cap", "error", err)
		return err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("admin panel starting", "addr", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin panel error", "error", err)
		}
	}()

	// P6.9: Background spend alert checker.
	wg.Add(1)
	go func() {
		defer wg.Done()
		checker := adminstore.NewSpendAlertChecker(store, logger)
		checker.Run(ctx)
	}()

	logger.Info("admin panel running", "addr", listenAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
	case <-ctx.Done():
	}

	logger.Info("shutting down admin panel...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	//nolint:contextcheck // shutdown runs after cancel(); a context derived from the cancelled ctx would time out instantly
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin shutdown failed", "error", err)
	}

	h.Stop()

	wg.Wait()
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
