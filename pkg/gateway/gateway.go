package cli

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"

	cryptorand "crypto/rand"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/validation"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/agenteval/results"
	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/clientip"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/encryption"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/evalgate"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/kms"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/lineage"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/mcpserver"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/mlpack"
	"github.com/reireirei/yabanin/pkg/policy"
	asiapacks "github.com/reireirei/yabanin/pkg/policy/asia_packs"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
	"github.com/reireirei/yabanin/pkg/shadow"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/reireirei/yabanin/pkg/tracing"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/reireirei/yabanin/pkg/verticals"
	carbonpack "github.com/reireirei/yabanin/pkg/verticals/carbon"
	defensepack "github.com/reireirei/yabanin/pkg/verticals/defense"
	educationpack "github.com/reireirei/yabanin/pkg/verticals/education"
	financepack "github.com/reireirei/yabanin/pkg/verticals/finance"
	halalpack "github.com/reireirei/yabanin/pkg/verticals/halal"
	healthpack "github.com/reireirei/yabanin/pkg/verticals/health"
	legalpack "github.com/reireirei/yabanin/pkg/verticals/legal"
	retailpack "github.com/reireirei/yabanin/pkg/verticals/retail"
	"github.com/reireirei/yabanin/pkg/whitelist"
)

// RunGatewayServer starts the gateway HTTP server with graceful shutdown.
// km is the per-region KMS provider for envelope encryption (nil = AES-GCM fallback).
//
// AF-17: this function is HTTP composition only — middleware, per-request
// timeouts and server lifecycle. Every dependency the request pipeline uses
// is wired once in buildGateway (the composition root).
//
// OP-8: the optional policy wiring carries the env-resolved kill-switch and
// callout allow-list (resolved in services/run; pkg/config stays untouched).
// Zero/absent wiring = policy pipeline off — bit-for-bit pre-OP-8 behavior.
//
// the JWT→gateway-key path call RunGatewayServerWithJWT (Go allows one
// variadic per signature and PolicyWiring already occupies it; the split
// keeps every existing call site compiling unchanged).
func RunGatewayServer(cfg config.Gateway, rdb *redis.Client, pool *pgxpool.Pool, km kms.Provider, l *slog.Logger, ctx context.Context, policy ...PolicyWiring) error {
	return RunGatewayServerWithJWT(cfg, rdb, pool, km, l, ctx, JWTWiring{}, CircuitScopeWiring{}, policy...)
}

// RunGatewayServerWithJWT starts the gateway HTTP server exactly like
// auth path: jwtw zero value = JWT auth off (bit-for-bit legacy behavior).
// to per-endpoint scope (the W-VER default).
func RunGatewayServerWithJWT(cfg config.Gateway, rdb *redis.Client, pool *pgxpool.Pool, km kms.Provider, l *slog.Logger, ctx context.Context, jwtw JWTWiring, circuits CircuitScopeWiring, policy ...PolicyWiring) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid gateway config: %w", err)
	}

	httpRouter := chi.NewRouter()

	// Wire CORS if configured
	if len(cfg.AllowedOrigins) > 0 {
		httpRouter.Use(validation.NewCORSMiddleware(validation.CORSConfig{
			AllowedOrigins:   cfg.AllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Request-ID", "Accept", "Origin"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	// Initialize metrics subsystem (no-op if disabled).
	if cfg.MetricsEnabled {
		metrics.Init()
		// V9: shadow-mode collectors are promauto-registered at package load
		// (pkg/shadow); re-register them through the same idempotent path so
		// the /metrics exposition is complete when shadow is enabled.
		if cfg.Shadow.Enabled {
			for _, c := range shadow.Collectors() {
				if err := prometheus.Register(c); err != nil {
					if !strings.Contains(err.Error(), "duplicate metrics") {
						l.Warn("shadow metric registration failed", "error", err)
					}
				}
			}
		}
		httpRouter.Use(metrics.PrometheusMiddleware())
		l.Info("metrics enabled")
	}

	httpRouter.Use(middleware.RequestID)
	// Per-request timeout for LLM proxying. Reasoning models can legitimately
	// exceed 60s (stand eval uses 300s); default preserves prior behavior.
	requestTimeout, err := time.ParseDuration(cfg.RequestTimeout)
	if err != nil || requestTimeout <= 0 {
		requestTimeout = 60 * time.Second
	}
	// /v1/ streams run for minutes (coding-agent sessions); they get a
	// separate ceiling (stream_max_duration, default 30m) instead of the 60s
	// JSON default, plus an idle watchdog (stream_idle_timeout, default 5m)
	// that serveStream arms on the upstream body.
	streamMaxDuration, err := time.ParseDuration(cfg.StreamMaxDuration)
	if err != nil || streamMaxDuration <= 0 {
		streamMaxDuration = 30 * time.Minute
		l.Warn("invalid stream_max_duration, using 30m default", "value", cfg.StreamMaxDuration)
	}
	streamIdleTimeout, err := time.ParseDuration(cfg.StreamIdleTimeout)
	if err != nil || streamIdleTimeout <= 0 {
		streamIdleTimeout = 5 * time.Minute
		l.Warn("invalid stream_idle_timeout, using 5m default", "value", cfg.StreamIdleTimeout)
	}
	// RM-03: providers whose streaming hops get stream_options.include_usage
	// injected so usage (tokens, cost, budgets) is non-zero for streams.
	// The documented unset-fallback applies here too — a programmatic
	// Gateway struct with an unset provider list must not silently disable
	// usage collection (N07-P01-T06 defect 1, 2026-11-03 acceptance record;
	// config.Load's env parse already applies the same fallback).
	streamUsageProviders := streamUsageEnabled(config.StreamUsageProvidersOrDefault(cfg.StreamUsageProviders))
	httpRouter.Use(httpmw.TimeoutByPrefix(requestTimeout, streamMaxDuration, "/v1/"))
	// Ingress budget invariant: net/http bounds aggregate header bytes before
	// routing; MaxBytesReader bounds actual wire body bytes (including chunked
	// requests) before multipart parsing. Multipart consumers additionally
	// cap part/field sizes before retaining their capped buffers.
	// D3 file cap plus multipart-envelope slack instead.
	httpRouter.Use(httpmw.MaxBodyByPrefix(10*1024*1024, batchstore.MaxFileSizeBytes+(1<<20), "/v1/files"))
	httpRouter.Use(httpmw.RateLimiter(httpmw.RateLimitConfig{ // per-IP rate limiting (prevents abuse)
		RequestsPerSecond: 50,
		BurstSize:         100,
		TrustedProxies:    cfg.TrustedProxies,
	}))
	httpRouter.Use(httpmw.SecurityHeaders()) // security headers on all responses
	httpRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := logctx.WithLogger(r.Context(), l)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	httpRouter.Use(middleware.Recoverer)

	if cfg.TracingEnabled() {
		httpRouter.Use(tracing.HTTPMiddleware())
		l.Info("tracing enabled")
	}

	gw, err := buildGateway(cfg, rdb, pool, l, ctx, jwtw, circuits, policy...)
	if err != nil {
		return err
	}
	gw.streamIdleTimeout = streamIdleTimeout
	gw.streamUsageProviders = streamUsageProviders

	// P6: DB-backed base costs for cost analytics. The process-global default
	// pricer is installed exactly once, at server boot and before any request
	// can be served — never in the buildGateway composition root, which tests
	// execute without a server lifetime (w21-06 order-independence pin).
	if gw.dbPricer != nil {
		pricing.SetDefaultPricer(gw.dbPricer)
	}

	healthHandler(gw, httpRouter, l)
	gw.routes(httpRouter)

	return startGatewayServers(gw, httpRouter, cfg, l, ctx)
}

// buildGateway is the gateway composition root (AF-17): every dependency the
// request pipeline uses — upstream pool, resolvers, breaker, cache, budgets,
// classifier, residency, lineage, proxies — is wired here exactly once, with
// each optional feature degrading explicitly (a nil field = feature off).
// RunGatewayServer keeps the HTTP concerns; nothing here may touch routing or
// middleware.
//
// config facets (egress, accounting, routing, compliance, observability).
// They share one gatewayWiring; each fills its facet of the gateway struct.
// The historical ordering is preserved: shared wiring first, then egress
// proxies (mcpParamGuard must see the gw pointer and read guard hooks live at
// scan time), accounting, routing, compliance hooks, and observability last
// (it consumes the routing facet's ML classifier for calibration).
func buildGateway(cfg config.Gateway, rdb *redis.Client, pool *pgxpool.Pool, l *slog.Logger, ctx context.Context, jwtw JWTWiring, circuits CircuitScopeWiring, policy ...PolicyWiring) (*gateway, error) {
	var pw PolicyWiring
	if len(policy) > 0 {
		pw = policy[0]
	}
	w, err := newGatewayWiring(cfg, rdb, pool, l, ctx, pw, jwtw, circuits)
	if err != nil {
		return nil, err
	}

	gw := newGatewaySkeleton(ctx, w)
	if err := buildGatewayEgress(ctx, w, gw); err != nil {
		return nil, err
	}
	if err := buildGatewayAccounting(ctx, w, gw); err != nil {
		return nil, err
	}
	mlClassifier, err := buildGatewayRouting(ctx, w, gw)
	if err != nil {
		return nil, err
	}
	buildGatewayCompliance(ctx, w, gw)
	buildGatewayObservability(ctx, w, gw, mlClassifier)
	return gw, nil
}

// gatewayWiring carries the dependencies built once from cfg/pool/rdb and
// consumed by more than one facet builder: the per-model decrypter, the cache
// HMAC signer, the shared event publisher, the DB pricer, and the adminstore.
// A nil field means its precondition (encryption key / secret / DB pool) is
// request context is not stored here: every facet builder takes it as its
// first parameter so it stays inherited end-to-end.
type gatewayWiring struct {
	cfg        config.Gateway
	rdb        *redis.Client
	pool       *pgxpool.Pool
	l          *slog.Logger
	enc        *encryption.Encryptor
	signer     *auth.CacheSigner
	pub        *eventpub.RedisPublisher
	dbPricer   pricing.Pricer
	adminStore *adminstore.Store
	// policy is the OP-8 env-resolved wiring (kill-switch mode + callout
	// allow-list); zero value = pipeline off.
	policy PolicyWiring
	// JWT auth off.
	jwt JWTWiring
	// zero value = per-endpoint scope.
	circuits CircuitScopeWiring
}

// newGatewayWiring assembles the shared dependency set of the composition
// (invalid encryption_key, invalid cache_hmac_secret); everything else
// degrades with a warning and a nil field.
func newGatewayWiring(cfg config.Gateway, rdb *redis.Client, pool *pgxpool.Pool, l *slog.Logger, ctx context.Context, policy PolicyWiring, jwt JWTWiring, circuits CircuitScopeWiring) (*gatewayWiring, error) {
	w := &gatewayWiring{cfg: cfg, rdb: rdb, pool: pool, l: l, policy: policy, jwt: jwt, circuits: circuits}

	// Build the per-model upstream_api_key decrypter. Empty encryption key
	// disables per-model keys — resolver.UpstreamAPIKey stays "" and the
	// gateway falls back to cfg.APIKey / cfg.FallbackKey. Also reused for
	// adminstore (whitelist, encryption) below.
	if cfg.EncryptionKey != "" {
		e, err := encryption.New(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption_key for gateway: %w", err)
		}
		w.enc = e
		l.Info("per-model upstream_api_key decryption enabled")
	}

	if cfg.CacheHMACSecret != "" {
		s, err := auth.NewCacheSigner(cfg.CacheHMACSecret)
		if err != nil {
			return nil, fmt.Errorf("invalid cache_hmac_secret: %w", err)
		}
		w.signer = s
		l.Info("cache HMAC signer initialized")
	}

	// Per-gateway DB-backed pricing (P6): consumed locally by the reseller
	// markup pricer and the budget base-rate source. The composition root
	// deliberately does NOT touch the process-global default pricer — that
	// install lives at server boot (RunGatewayServerWithJWT) so composing a
	// gateway without serving it (tests) never mutates process state
	// (w21-06: a leaked dead-pool DBPricer made bundled-only models price
	// as unknown_price in later tests, order-dependent under -shuffle).
	if pool != nil {
		w.dbPricer = pricing.NewDBPricer(pool)
	}

	// The event publisher is shared by the request path and the MCP/A2A audit
	// loggers (MCP-03) — all publish to the same loggerd stream.
	w.pub = eventpub.NewRedisPublisher(rdb, cfg.EventStream)

	// adminstore is shared by the whitelist loader, key rate limits, the
	// routing-mode loader, residency, the MCP agent-name resolver, and the V9
	// upstream_api_key rows. Idempotent; no-op without an encryption key.
	if pool != nil {
		w.adminStore = adminstore.New(pool, l.With("component", "adminstore"), w.enc)
		if n, err := w.adminStore.MigratePlaintextSecrets(ctx); err != nil {
			l.Warn("plaintext upstream_api_key migration failed; will retry on next start", "error", err)
		} else if n > 0 {
			l.Info("migrated plaintext upstream_api_key rows to encrypted storage", "count", n)
		}

		// N01-P04 successor: adopt versioned credential envelopes only when
		// a keyset is configured (YABANIN_KMS_KEYSET_FILE); the legacy
		// single-key default is unchanged. A configured-but-unusable keyset
		// logs loudly and keeps legacy envelopes (same warn-and-continue
		// posture as the KMS provider init above) — writes stay enc: until
		// the keyset loads.
		if kms.KeysetConfigured() {
			kv, err := kms.NewVersionedFromEnv()
			if err != nil {
				l.Warn("versioned credential keyset configured but unusable; org credentials keep legacy envelopes", "error", err)
			} else {
				w.adminStore.AdoptCredentialKMS(kv)
				l.Info("org credential envelopes: versioned keyset adopted", "env", "YABANIN_KMS_KEYSET_FILE")
			}
		}
	}

	return w, nil
}

// newGatewaySkeleton allocates the gateway with its core facet: transport
// handles (config, logger, redis, DB/session), the auth middleware with its
// org resolver and last-used tracker, the rule engine snapshot cache + rule
// store, the shared event publisher, and retry/policy defaults. Facet
// builders fill the remaining facets.
func newGatewaySkeleton(ctx context.Context, w *gatewayWiring) *gateway {
	var orgResolver *auth.Resolver
	if w.pool != nil && w.rdb != nil {
		// S02: the resolver cache TTL is the key-revocation propagation bound
		// (a revoked key stays resolvable until the cached entry expires).
		// Clamp to a positive value so a bad env var cannot disable expiry.
		resolverTTL := w.cfg.OrgResolverTTL
		if resolverTTL < 1 {
			w.l.Warn("invalid org resolver TTL, using 300s default", "value", resolverTTL)
			resolverTTL = 300
		}
		orgResolver = auth.NewResolver(w.pool, w.rdb, resolverTTL, w.signer)
		w.l.Info("org resolver initialized", "cache_ttl_seconds", resolverTTL)
	}

	// workers; at most one UPDATE per key per minute, never on the request
	// path. Nil when there is no DB pool.
	var lastUsedTracker *auth.LastUsedTracker
	if w.pool != nil {
		// Detached from the server lifetime: queued samples must flush even
		// while the process is shutting down.
		lastUsedTracker = auth.NewLastUsedTracker(context.WithoutCancel(ctx), w.pool,
			auth.DefaultLastUsedQueue, auth.DefaultLastUsedWorkers, auth.DefaultLastUsedInterval)
		w.l.Info("last-used tracker initialized",
			"interval", auth.DefaultLastUsedInterval.String(),
			"queue", auth.DefaultLastUsedQueue, "workers", auth.DefaultLastUsedWorkers)
	}

	gw := &gateway{
		gatewayCore: gatewayCore{
			cfg:                w.cfg,
			trustedProxies:     w.cfg.TrustedProxies,
			rdb:                w.rdb,
			log:                w.l,
			auth:               NewAuthMiddleware(w.cfg, orgResolver),
			eng:                evaluator.NewSnapshotCache(0, 0),
			ruleStore:          rulestore.New(w.pool, w.rdb, 5*time.Minute, w.signer, w.l.With("component", "rulestore")),
			publisher:          w.pub,
			retryPolicy:        retry.DefaultPolicy(),
			unknownModelPolicy: w.cfg.UnknownModelPolicy,
			dbPool:             w.pool,     // DB pool for evalgate/feedback stores (P5.9+)
			dbPricer:           w.dbPricer, // P6 pricer handle; installed as the process-global default only at server boot
			nowFn:              time.Now,
		},
	}
	gw.bindModelLister(w.pool)
	gw.auth.SetLastUsedTracker(lastUsedTracker)
	// Authenticator returns nil for the zero wiring, so JWT-off deployments
	// keep the legacy auth middleware untouched (SetJWTAuthenticator(nil)).
	if jwtAuth := NewJWTAuthenticator(w.jwt, w.l); jwtAuth != nil {
		gw.auth.SetJWTAuthenticator(jwtAuth)
		w.l.Info("jwt service-account auth enabled",
			"jwks_url", w.jwt.JWKSURL, "org_claim", w.jwt.OrgClaim,
			"issuer", w.jwt.Issuer != "", "audience", w.jwt.Audience != "")
	}
	return gw
}

// buildGatewayEgress wires the outbound facet: the upstream client pool, the
// circuit breaker, the opt-in MCP/A2A aggregator proxies, the built-in tool
// executor, and the MCP agent-name resolver. A nil field = feature off;
// misconfiguration degrades with a log, never a failed boot.
func buildGatewayEgress(ctx context.Context, w *gatewayWiring, gw *gateway) error {
	if err := loadGuardHooks(ctx, w, gw); err != nil {
		return err
	}
	// Build the upstream client pool. P3.1: pool keeps one *Client per
	// unique URL; for now we still route everything through cfg.Provider,
	// but the indirection lets P3.2 forward per-model upstream_url without
	// touching the gateway struct again.
	upstreamOpts := upstream.Options{
		BaseURL:          w.cfg.Provider,
		Timeout:          upstream.DefaultNonStreamTimeout,
		AllowedUpstreams: allowedUpstreamsForGateway(w.cfg.AllowedUpstreams, w.cfg.ZAICodingEnabled, provider.ZAICodingEndpoint(w.cfg.ZAICodingBaseURL), w.cfg.Provider),
	}
	// Configurable upstream HTTP budgets: cold-start upstreams (NVIDIA NIM
	// et al.) need minutes before response headers; defaults keep the
	// historical 20s/60s. Parse errors degrade to the defaults, never a
	// failed boot (validated earlier in config.Load).
	if d, err := time.ParseDuration(w.cfg.UpstreamResponseHeaderTimeout); err == nil && d > 0 {
		upstreamOpts.ResponseHeaderTimeout = d
	}
	if d, err := time.ParseDuration(w.cfg.UpstreamNonStreamTimeout); err == nil && d > 0 {
		upstreamOpts.Timeout = d
	}
	gw.pool = upstream.NewPool(upstreamOpts)

	// default — one independent breaker per normalized scheme://host endpoint,
	// LRU-bounded; YABANIN_CIRCUIT_SCOPE=global restores the single shared
	// breaker). Thresholds stay deployment-wide for every breaker.
	if w.cfg.CircuitEnabled {
		openTimeout, _ := time.ParseDuration(w.cfg.CircuitOpenTimeout)
		window, _ := time.ParseDuration(w.cfg.CircuitWindow)
		gw.circuitScope = w.circuits.ResolvedScope()
		gw.circuits = circuit.NewMap(circuit.Config{
			Enabled:          true,
			FailureThreshold: w.cfg.CircuitFailureThreshold,
			SuccessThreshold: w.cfg.CircuitSuccessThreshold,
			OpenTimeout:      openTimeout,
			Window:           window,
		}, circuit.DefaultMaxEndpoints, w.l.With("component", "circuit"))
		w.l.Info("circuit breaker initialized",
			"scope", gw.circuitScope,
			"failure_threshold", w.cfg.CircuitFailureThreshold,
			"success_threshold", w.cfg.CircuitSuccessThreshold,
			"open_timeout", openTimeout,
			"window", window,
		)
	}

	// TOOL-01 + OP-6: ONE shared tool-policy engine (the chat-path tool
	// gate, the built-in executor guard AND the MCP invoke guardrails).
	// Zero rows = allow-all — the wiring is free. Built before the MCP
	// proxy block so the proxy can attach the guardrails; the TOOL-01/03
	// block below reuses the same engine (one cache, one Invalidate path).
	if w.pool != nil && gw.toolPolicies == nil {
		gw.toolPolicies = toolpolicy.NewEngine(toolpolicy.NewStore(w.pool), 5*time.Second)
	}

	// MCP-02/03/06: build the MCP aggregator proxy AFTER gw exists, so the
	// param guard (mcpParamGuard) can read gw.guardHooks live at Scan time
	// (the hooks are initialized by the compliance facet builder). Nil when
	// YABANIN_MCP_GATEWAY is not set or no DB pool — the /api/mcp/invoke route
	// group is then not mounted.
	if w.cfg.MCPGatewayEnabled {
		if w.pool == nil {
			w.l.Warn("mcp gateway enabled but no database configured — proxy disabled")
		} else {
			allow, err := ssrf.NewAllowList(w.cfg.MCPAllowedUpstreams)
			if err != nil {
				w.l.Error("mcp gateway: invalid allowed upstreams — proxy disabled", "error", err)
			} else {
				mcpCfg := mcpagg.NewDefaultConfig()
				// MCP-03: audit every tool call to the loggerd stream (request_logs
				// with task_id + agent_id). MCP-06: guard tool params with the
				// gateway's guard hooks (off/log/redact/deny inherited from
				// guard_mode); the adapter reads gw.guardHooks live.
				// MC-2: the credential source resolves per-user → server-level
				// upstream credentials; token-endpoint refreshes are held to the
				// SAME SSRF allow-list as the server URLs (a credential never
				// widens the egress surface).
				var mcpVersions MCPCredsVersionStore
				if w.rdb != nil {
					mcpVersions = NewMCPCredsVersionStore(w.rdb, w.l.With("component", "mcpcreds-versions"))
				}
				mcpCredsSrc := newMCPCredsSource(mcpCredsSourceConfig{
					Store:    w.adminStore,
					Versions: mcpVersions,
					Allow:    mcpTokenURLGuard(allow),
					TTL:      orgCredsProbeTTL,
					Log:      w.l.With("component", "mcpcreds"),
				})
				gw.mcpProxy = mcpagg.NewProxy(mcpagg.NewStore(w.pool), mcpCfg, allow,
					&mcpParamGuard{gw: gw},
					&mcpAuditLogger{publisher: w.pub, log: w.l.With("component", "mcp-audit")}).
					WithToolGuard(gw.toolPolicies).
					WithCredsSource(mcpCredsSrc)
				// aggregator: the catalog reads the registry through the
				// store, tools/call re-enters the proxy (full guard chain),
				// sessions are stateless HMAC ids (a fresh per-process key —
				// a restart rotates them and clients re-initialize).
				gw.mcpStore = mcpagg.NewStore(w.pool)
				sessionSecret := make([]byte, 32)
				if _, err := cryptorand.Read(sessionSecret); err != nil {
					w.l.Error("mcp gateway: session key generation failed — native endpoint disabled", "error", err)
				} else {
					gw.mcpStreamable = mcpserver.New(mcpserver.Config{
						Principal: mcpStreamablePrincipal(gw),
					}, mcpServerBackend{gw: gw}, w.l.With("component", "mcpserver"), sessionSecret)
				}
				w.l.Info("mcp gateway proxy enabled",
					"allowed_upstreams", len(w.cfg.MCPAllowedUpstreams),
					"read_timeout", mcpCfg.ReadTimeout.String(),
					"creds_version_store", mcpVersions != nil)
			}
		}
	}

	// A2A-01: build the A2A agent proxy with the same wiring discipline as
	// the MCP aggregator (guard hook + audit to the loggerd stream). Nil
	// when YABANIN_A2A_GATEWAY is not set or no DB pool — the /api/a2a/send
	// route group is then not mounted.
	if w.cfg.A2AGatewayEnabled {
		if w.pool == nil {
			w.l.Warn("a2a gateway enabled but no database configured — proxy disabled")
		} else {
			a2aAllow, err := ssrf.NewAllowList(w.cfg.A2AAllowedUpstreams)
			if err != nil {
				w.l.Error("a2a gateway: invalid allowed upstreams — proxy disabled", "error", err)
			} else {
				a2aCfg := a2aagg.NewDefaultConfig()
				gw.a2aProxy = a2aagg.NewProxy(a2aagg.NewStore(w.pool), a2aCfg, a2aAllow,
					&mcpParamGuard{gw: gw},
					&a2aAuditLogger{publisher: w.pub, log: w.l.With("component", "a2a-audit")})
				w.l.Info("a2a gateway proxy enabled",
					"allowed_upstreams", len(w.cfg.A2AAllowedUpstreams),
					"read_timeout", a2aCfg.ReadTimeout.String())
			}
		}
	}

	// TOOL-01/03: tool policies + the built-in server-side executor. The
	// engine is built above (shared with the MCP invoke guardrails); the
	// executor reuses the MCP SSRF allow-list so the deployment
	// has ONE dial-out surface.
	if w.pool != nil {
		mcpAllow, mcpAllowErr := ssrf.NewAllowList(w.cfg.MCPAllowedUpstreams)
		if mcpAllowErr != nil {
			w.l.Error("tool executor disabled — invalid MCP allowed upstreams", "error", mcpAllowErr)
		} else {
			execValidate := func(urlStr string) error { //nolint:contextcheck // bounded ssrf check — same call shape as mcpagg.Invoke (QG2-D3)
				return execURLGuard(urlStr, mcpAllow)
			}
			gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), execValidate, &mcpParamGuard{gw: gw}).
				// executor path too — per-tool AND per-argument permissions
				// on the same engine the MCP invoke path uses.
				WithToolGuard(gw.toolPolicies)
		}
	}

	// MCP-04: resolve an agent-principal ID to its display name for the
	// upstream X-Yabanin-Agent-Name header. Nil-safe in mcpInvoke (the
	// header is simply omitted when this is unset or the agent is unknown).
	// Only wired when the MCP proxy is active (it requires a pool).
	if gw.mcpProxy != nil {
		gw.mcpAgentName = func(ctx context.Context, agentID string) string {
			ak, err := w.adminStore.GetAgentKeyByID(ctx, agentID)
			if err != nil || ak == nil {
				return ""
			}
			return ak.Name
		}
	}

	// W-BYOK-CORE: org credential (BYOK) resolution. The assertion stays
	// keep the pre-BYOK key chain bit-for-bit (resolveUpstreamKey skips the
	// org step when orgCreds is nil).
	if ocs, ok := orgKeyResolver(w.adminStore); ok {
		gw.orgCreds = ocs
		if w.rdb != nil {
			gw.orgCredsVersions = NewOrgCredsVersionStore(w.rdb, w.l.With("component", "orgcreds-versions"))
		}
		gw.orgCredsProbe = newOrgCredsProbe(gw.orgCreds, gw.orgCredsVersions, orgCredsProbeTTL, w.l.With("component", "orgcreds-probe"))
		if cps, ok := orgCredsPoolStore(w.adminStore); ok {
			gw.credPool = newOrgCredsPool(cps, gw.orgCredsVersions, orgCredsPoolTTL, w.l.With("component", "orgcreds-pool"))
			w.l.Info("org credential pool (R107 multi-key balancing) enabled")
		}
		w.l.Info("org credential (BYOK) key resolution enabled")
	}
	return nil
}

// loadGuardHooks loads, verifies, stages, and activates configured local packs
// during construction. The lifecycle is retained on gateway for the lifetime
// of the request runtime; a broken configured pack is a startup error.
func loadGuardHooks(ctx context.Context, w *gatewayWiring, gw *gateway) error {
	mode, note := guardhooks.ResolveMode(w.cfg.GuardMode)
	if note != "" {
		w.l.Warn(note)
	}
	gw.guardHooks = guardhooks.New(mode)
	// Pack-signature verifier (scheme guardpack-sig.v1), resolved ONCE from
	// the shared env config and threaded through every load surface below —
	// the startup reconciliation, the prior/hydration loads and the runtime
	// watcher's materializations. Three states: a configured-but-broken key
	// set refuses the startup (fail loud — never run without the
	// verification the operator asked for); nothing configured keeps the nil
	// verifier (unsigned packs load freely, declared signatures fail closed
	// exactly as before); a valid key set verifies every signed pack.
	verifyCfg := w.cfg.GuardPackVerify()
	verifier, verifierConfigured, err := guardhooks.NewVerifierFromConfig(verifyCfg.KeysDir, verifyCfg.InlineKeys)
	if err != nil {
		return fmt.Errorf("startup refused (guard pack verifier): %w", err)
	}
	if verifierConfigured {
		w.l.Info("guard pack signature verification enabled")
	}
	packCfg := w.cfg.GuardPacks()
	if packCfg.Dir == "" {
		return nil
	}
	if len(packCfg.ActivePacks) == 0 {
		return errors.New("startup refused (guard pack): pack directory configured but no active pack IDs configured")
	}
	// A configured root that is absent or not a directory is treated like the
	// feature being unconfigured: warn and keep the built-in hooks only, the
	// same wiring-granularity fail-open the other optional facets use (e.g.
	// key rate limits without redis). A root that exists but holds a broken
	// pack stays a startup error below: the operator asked for guard packs,
	// and serving without them must never happen silently.
	if info, statErr := os.Stat(packCfg.Dir); statErr != nil || !info.IsDir() {
		if statErr != nil {
			w.l.Warn("guard pack directory is not accessible — running with built-in guard hooks only", "dir", packCfg.Dir, "reason", statErr.Error())
		} else {
			w.l.Warn("guard pack path is not a directory — running with built-in guard hooks only", "dir", packCfg.Dir)
		}
		return nil
	}
	activeMode := mode
	switch strings.ToLower(packCfg.Mode) {
	case "":
	case "shadow":
		activeMode = guardhooks.ModeLog
	default:
		return fmt.Errorf("startup refused (guard pack): invalid YABANIN_GUARD_PACK_MODE %q (expected empty or shadow)", packCfg.Mode)
	}
	sources := make([]guardhooks.PackSource, 0, len(packCfg.ActivePacks))
	seen := make(map[string]struct{}, len(packCfg.ActivePacks))
	for _, packID := range packCfg.ActivePacks {
		if filepath.Base(packID) != packID || packID == "." || packID == ".." {
			return fmt.Errorf("startup refused (guard pack): invalid active pack ID %q", packID)
		}
		if _, exists := seen[packID]; exists {
			return fmt.Errorf("startup refused (guard pack): duplicate active pack ID %q", packID)
		}
		seen[packID] = struct{}{}
		manifestPath := packCfg.GuardPackManifestPath(packID)
		manifest, err := os.ReadFile(manifestPath) // #nosec G304 -- packID must be a single path component and root is operator-configured.
		if err != nil {
			return fmt.Errorf("startup refused (guard pack %q): read manifest: %w", packID, err)
		}
		sources = append(sources, guardhooks.PackSource{Root: filepath.Dir(manifestPath), Manifest: manifest})
	}
	// Guard-pack wiring: the coordination point is the durable
	// guard_pack_state row when a DB pool exists, so gateway startups and
	// admin-API activations converge (replicas adopt API activations; a lost
	// startup race adopts the durable winner). Without a pool the local
	// no-op store keeps the legacy env-based semantics bit-for-bit — no
	// coordination to fail, no behavior change for no-DB deployments
	// (see guardpack_durable.go for the shared reconciliation contract).
	lifecycle, err := reconcileGuardPackLifecycle(ctx, guardPackPolicyFor(w.pool), w.l, activeMode, packCfg.Dir, sources, verifier)
	if err != nil {
		return fmt.Errorf("startup refused (guard packs %v): %w", packCfg.ActivePacks, err)
	}
	gw.guardLifecycle = lifecycle
	if lifecycle != nil {
		gw.guardHooks = lifecycle.ActiveHook()
		// FIX-03 runtime adoption: with a durable coordination point, a
		// background watcher probes the guard_pack_state row on a jittered
		// interval and atomically swaps the enforced hook when the durable
		// version moves — already-running replicas adopt API activations
		// and rollbacks without a restart (convergence contract in
		// guardpack_watch.go). Without a pool there is nothing to adopt.
		// The watcher materializes under the SAME verifier the startup used.
		if w.pool != nil {
			gw.guardWatch = newGuardPackWatcher(guardPackPolicyFor(w.pool), w.l, activeMode, packCfg.Dir, lifecycle.ActiveHook(), verifier)
			go gw.guardWatch.Run(ctx)
		}
	}
	return nil
}

// additive pool surface (ListActiveOrgCredentials / ResolveKeyEntry /
// QuarantineOrgCredential). A nil store is feature-off: resolveUpstreamKey
// keeps the legacy newest-first ResolveKey path bit-for-bit.
func orgCredsPoolStore(s *adminstore.Store) (OrgCredsPoolStore, bool) {
	if s == nil {
		return nil, false
	}
	if cps, ok := interface{}(s).(OrgCredsPoolStore); ok {
		return cps, true
	}
	return nil, false
}

// orgKeyResolver reports whether the concrete adminstore carries the frozen
// W-BYOK-DB request-path surface. A nil store (no database configured) is
// feature-off, exactly like the other pool-gated facets.
func orgKeyResolver(s *adminstore.Store) (OrgKeyResolver, bool) {
	if s == nil {
		return nil, false
	}
	if ocs, ok := interface{}(s).(OrgKeyResolver); ok {
		return ocs, true
	}
	return nil, false
}

// buildGatewayAccounting wires the metering facet: the prepaid credits
// store, DB-backed pricing with reseller markup, budget enforcers, durable
// reservations, the semantic cache, whitelist access, opt-in key rate
// limits, and per-task/session token budgets. All of it requires the DB
// pool — without one the facet stays nil (historical gate) except the
// N12-P01-T02 history admission gate, which is deployment-level and works
// with Redis alone (history-only controller below).
func buildGatewayAccounting(ctx context.Context, w *gatewayWiring, gw *gateway) error {
	// N12-P01-T02 (owner decision 2026-11-04): durable request-history
	// admission (N10-P04-T03 machinery, I40/I44). Default OFF — the knob
	// pair YABANIN_HISTORY_ADMISSION / YABANIN_HISTORY_MODE arms the probe;
	// an enabled knob with a missing dependency aborts startup (fail-closed,
	// see buildHistoryAdmission).
	historyGate, err := buildHistoryAdmission(w.cfg, w.rdb, w.l)
	if err != nil {
		return err
	}
	gateMode := budget.ResolveMode(w.cfg.Reservations)

	if w.pool == nil {
		// Without a pool the metering facet stays nil (historical gate) —
		// but an armed history gate still needs its per-request consult
		// (reservationPlan runs whenever gw.admission is non-nil). A
		// history-only controller with the money leg off is safe by
		// construction: Plan consults the history gate and then
		// planAfterHistory early-returns on ModeOff; Start no-ops.
		if historyGate != nil {
			gw.admission = budget.NewAdmission(nil, budget.ScopedRateSource{}, w.l,
				reservationReplicaID(), budget.ModeOff, reservationOrgLoader(nil), budget.DefaultAdmissionConfig())
			gw.admission.SetHistoryAdmission(historyGate)
			gw.admission.Start(ctx)
			logHistoryAdmissionArmed(w, historyGate, budget.ModeOff)
		}
		return nil
	}

	// D2 bytea payloads, D4 billing through the admission pipeline — the
	// line runner rides gw.chatCompletions below). The executor is a
	// background worker like the cache cleaner; without a DB pool the
	// endpoints answer 503 and nothing is mounted.
	gw.batchStore = batchstore.NewStore(w.pool, w.l.With("component", "batchstore"))
	go batchstore.NewExecutor(gw.batchStore, gw.batchLineRunner, w.l.With("component", "batch-executor")).Start(ctx)
	w.l.Info("batch/files store + executor initialized",
		"max_file_bytes", batchstore.MaxFileSizeBytes, "max_batch_lines", batchstore.MaxBatchLines,
		"retention", batchstore.Retention.String())

	// Wire prepaid credits store for per-org balance management.
	storeCfg := credits.DefaultConfig()
	storeCfg.GracePeriodCents = w.cfg.CreditsGraceCents
	if ttl, err := time.ParseDuration(w.cfg.CreditsCacheTTL); err == nil && ttl > 0 {
		storeCfg.CacheTTL = ttl
	}
	gw.creditStore = credits.NewStoreWithConfig(w.pool, w.l.With("component", "credits"), storeCfg)
	w.l.Info("credits store initialized", "grace_cents", storeCfg.GracePeriodCents, "cache_ttl", storeCfg.CacheTTL)

	// Resale pricing (P6) + P6.10/G2 budget enforcers (same pool; nil-safe in
	// the handlers so deploys without the 0101 tables are fine).
	markupPricer := pricing.NewMarkupPricer(w.pool, w.dbPricer, w.l.With("component", "reseller-pricer"))
	gw.markupPricer = markupPricer
	w.l.Info("DB pricer + reseller markup wired — base cost from models_pricing, resale with markup")
	gw.budgetEnforcer = budget.NewEnforcer(w.pool, w.l)
	gw.agentEnforcer = budget.NewAgentEnforcer(w.pool, w.l)

	// T02: unit side-catalog for non-token metering (audio seconds /
	// characters / images). The default has no bundled unit rates; an
	// embedding application can install its validated operator-provided
	// snapshot with SetDefaultUnitPricer before startup.
	unitPricer := pricing.DefaultUnitPricer()
	gw.unitPricer = unitPricer
	w.l.Info("unit pricing catalog wired", "entries", unitPricer.Provenance().Entries)

	// NEXT-18c: durable budget reservations (ADR-0001 §5/§9). The env gate
	// (YABANIN_RESERVATIONS, default off) keeps the legacy admission path
	// bit-for-bit; shadow accounts without deciding; enforce denies service
	// at exhaustion. Per-org mode comes from organizations.reservations_mode
	// clamped to this gate. N12-P01-T02: an armed history gate runs through
	// the same controller even with reservations off — it is
	// deployment-level and Plan consults it before the §9 modes (an org
	// with reservations off still gets history-gated admission; the money
	// leg itself stays off for a history-only deployment).
	if gateMode != budget.ModeOff || historyGate != nil {
		historyOnly := gateMode == budget.ModeOff
		var resStore *budget.ReservationStore
		if !historyOnly {
			resStore = budget.NewReservationStoreWithConfig(w.pool, w.l.With("component", "budget-reservations"),
				budget.ReservationConfig{DefaultGraceFloorCents: w.cfg.CreditsGraceCents})
		}
		gw.admission = budget.NewAdmission(resStore,
			budget.ScopedRateSource{
				Base:   budget.BaseRateSource{Pricer: w.dbPricer, Units: gw.unitPricer},
				Resale: budget.ResaleRateSource{Markup: markupPricer},
			},
			w.l, reservationReplicaID(), gateMode, reservationOrgLoader(w.pool), budget.DefaultAdmissionConfig())
		if historyGate != nil {
			// Arm BEFORE Start: Plan reads the field without a lock, and
			// the armed gate owns the active history mode (N10-P04-T03
			// single-vocabulary-owner contract).
			gw.admission.SetHistoryAdmission(historyGate)
		}
		gw.admission.Start(ctx)
		if historyOnly {
			w.l.Info("reservations off — history-only admission controller (reservations money leg stays off)")
		} else {
			w.l.Info("budget reservations enabled", "gate", string(gateMode))
		}
	}
	if historyGate != nil {
		logHistoryAdmissionArmed(w, historyGate, gateMode)
	}

	// RATELIMIT-FALLBACK P3: opt-in per-replica fair admission (N09-P02
	// FairAdmission surface). Default OFF: nothing is constructed and the
	// request path stays bit-for-bit the legacy one — the same opt-in
	// posture as YABANIN_KEY_RATE_LIMITS and the reservations gate above.
	// A bound override of 0 keeps the library default so an operator can
	// enable the feature first and tune bounds one knob at a time. The
	// controller fails open internally on a misconfigured Capacity <= 0,
	// so a bad override can never become a self-inflicted outage.
	if w.cfg.FairAdmissionEnabled {
		faCfg := router.DefaultFairAdmissionConfig()
		if w.cfg.FairAdmissionCapacity > 0 {
			faCfg.Capacity = w.cfg.FairAdmissionCapacity
		}
		if w.cfg.FairAdmissionMaxPerTenant > 0 {
			faCfg.MaxPerTenant = w.cfg.FairAdmissionMaxPerTenant
		}
		if w.cfg.FairAdmissionQueueLimit > 0 {
			faCfg.QueueLimit = w.cfg.FairAdmissionQueueLimit
		}
		gw.fair = router.NewFairAdmission(faCfg)
		w.l.Info("fair admission enabled",
			"capacity", faCfg.Capacity,
			"max_per_tenant", faCfg.MaxPerTenant,
			"queue_limit", faCfg.QueueLimit,
			"wait_timeout", faCfg.WaitTimeout.String())
	}

	// P4: semantic cache (separate helper — this builder stays under the
	// aborts startup: return early — nothing after this point is wired.
	if err := wireCacheService(ctx, w, gw); err != nil {
		return err
	}

	// P1.1: whitelist enforcement loader — checks model access per API key / team.
	gw.wl = whitelist.NewLoader(w.adminStore, w.rdb, 60*time.Second, w.l)
	w.l.Info("whitelist loader initialized")

	// YABANIN_KEY_RATE_LIMITS (default OFF — no middleware, no Redis
	// calls, no extra headers). Requires both the DB (limits source,
	// migration 0027) and Redis (shared window state); without either
	// the feature stays off — the OD-07 fail-open at wiring granularity.
	if keyRateLimitsFlagEnabled() {
		if w.rdb == nil {
			w.l.Warn("YABANIN_KEY_RATE_LIMITS is on but no redis is configured — key rate limits disabled (fail-open)")
		} else {
			gw.rateLimits = newKeyRateLimiter(w.rdb, w.adminStore, w.l.With("component", "key-ratelimit"))
			w.l.Info("key rate limits enabled (rpm/tpm per key, team and org; 1m sliding window)")
		}
	}

	// W-CAPS: org-level beta caps (default 60 RPM / 200k TPM / $50 monthly
	// budget, per-org overrides via the admin caps endpoint). Off by default;
	// shadow measures, enforce denies — fail-closed on dependency errors.
	// Shares the rate-limiter middleware mount (caps windows ride the same
	// atomic admit/reconcile path), so it needs no separate r.Use.
	if capsMode := config.OrgCapsMode(); capsMode != config.OrgCapsOff {
		if w.rdb == nil {
			w.l.Warn("YABANIN_ORG_CAPS is on but no redis is configured — org caps disabled (fail-open)")
		} else {
			if gw.rateLimits == nil {
				gw.rateLimits = newKeyRateLimiter(w.rdb, w.adminStore, w.l.With("component", "key-ratelimit"))
			}
			gw.rateLimits.caps = newOrgCapsEnforcer(w.rdb, w.adminStore, capsMode, w.l.With("component", "org-caps"))
			w.l.Info("org caps enabled", "mode", capsMode,
				"defaults", "60 rpm / 200k tpm / $50 month (OP-19: input/output/per-key token caps off unless the org sets them)",
				"fair_share", "priority-scaled Retry-After (reject policy, not a scheduler)")
		}
	}

	// G3: per-task / per-session token budgets (opt-in; 0 = off). Built
	// whenever at least one cap is set, over a fixed 24h window.
	if w.cfg.TaskTokenBudget > 0 || w.cfg.SessionTokenBudget > 0 {
		gw.tokenBudget = NewTokenBudget(w.cfg.TaskTokenBudget, w.cfg.SessionTokenBudget, 24*time.Hour)
		w.l.Info("token budgets enabled",
			"task_tokens", w.cfg.TaskTokenBudget,
			"session_tokens", w.cfg.SessionTokenBudget)
	}
	return nil
}

// scoped to the DISTRIBUTION claim: when the embedder runs on the shipped
// default model (operator did NOT set YABANIN_EMBEDDER_MODEL), startup
// hard-refuses unless that model has a confirmed provenance manifest — the
// distribution gate stops being test-only. An explicitly configured external
// model is the operator's own supply chain: it boots with a provenance
// notice, never a refusal (integration wire tests and operator environments
// legitimately pin synthetic/external embedder ids).
func embedderProvenanceGate(cfg config.EmbedderConfig, l *slog.Logger) error {
	if !cfg.Enabled || cfg.BaseURL == "" || cfg.Model == "" {
		return nil // nothing enabled — nothing to gate
	}
	_, manifestErr := embeddings.ManifestFor(cfg.Model)
	if manifestErr == nil {
		return nil
	}
	if cfg.ModelExplicit {
		l.Info("embedder model is operator-supplied — provenance is the operator's supply chain (R003 D4 notice)",
			"model", cfg.Model, "manifest_reason", manifestErr.Error())
		return nil
	}
	return fmt.Errorf("startup refused (R003 D4): %w", manifestErr)
}

// wireCacheService wires the semantic cache when enabled (P4): the embedder,
// the cache service with its org-policy/embed/AB stores, and the periodic
// TTL cleaner. Returns the startup-refusal error from the provenance gate.
func wireCacheService(ctx context.Context, w *gatewayWiring, gw *gateway) error {
	if !w.cfg.CacheEnabled || w.pool == nil || w.rdb == nil {
		return nil
	}

	embCfg := w.cfg.Embedder()
	// versioned model pack (YABANIN_ML_PACK_DIR) is verified on disk before
	// anything is served from it — manifest provenance, weights presence and
	// sha256 digests; the manifest is unsigned by decision (perimeter model)
	// aborts startup; with no pack dir set nothing changes — minimal mode
	// stays NoopClient/rule-tier with zero download.
	if packDir := w.cfg.MLPack().Dir; packDir != "" {
		pack, err := mlpack.AttachDir(packDir)
		if err != nil {
			w.l.Error("model pack attach refused startup", "dir", packDir, "error", err.Error())
			return fmt.Errorf("startup refused (R058 model pack): %w", err)
		}
		if embCfg.Model != "" && embCfg.Model != pack.Manifest.ID {
			w.l.Warn("attached model pack does not match the configured embedder model — pack verified but not used by the embedder",
				"pack_id", pack.Manifest.ID, "pack_version", pack.Manifest.Version, "embedder_model", embCfg.Model)
		} else {
			w.l.Info("model pack attached — verified on disk, no download (R058; provenance is the operator's supply chain, R003 D4 notice)",
				"pack_id", pack.Manifest.ID, "pack_version", pack.Manifest.Version, "files", len(pack.Manifest.Files), "dir", pack.Dir)
		}
	}
	if err := embedderProvenanceGate(embCfg, w.l); err != nil {
		w.l.Error("embedder provenance gate refused startup", "model", embCfg.Model, "error", err.Error())
		return err
	}
	var emb embeddings.Client = &embeddings.NoopClient{}
	if embCfg.Enabled && embCfg.BaseURL != "" {
		emb = embeddings.NewHTTPClient(embeddings.Config{
			BaseURL:     embCfg.BaseURL,
			Model:       embCfg.Model,
			APIKey:      embCfg.APIKey,
			Timeout:     embCfg.Timeout,
			MaxChars:    embCfg.MaxChars,
			Endpoint:    embeddings.EndpointStyle(embCfg.Endpoint),
			QueryPrefix: embCfg.QueryPrefix,
		})
		w.l.Info("semantic cache enabled", "embedder_base_url", embCfg.BaseURL)
	} else {
		w.l.Info("cache enabled but no embedder configured — exact-Redis cache active")
	}

	gw.cacheSvc = cache.NewCacheService(ctx, w.pool, w.rdb, emb, w.l.With("component", "cache"), w.cfg.CachePGExactLookup)
	gw.cache = gw.cacheSvc

	// Wire DB-backed policy loader so Lookup/Write respect org-level cache_mode.
	dbLoader := cache.NewDBPolicyLoader(w.pool, w.l.With("component", "cache-policy-loader"))
	gw.cacheSvc.SetOrgPolicyLoader(dbLoader.Wrap())

	// N03-P02-T03/T04: bind the cache identity to the tenant policy regime —
	// lookups and writes compose the org's current policy fingerprint into
	// the route identity, so warm entries from an earlier policy snapshot
	// degrade to misses instead of replaying past a tightened policy. While
	// enforcement is off or unverifiable for an org (empty fingerprint:
	// unwired/unavailable runtime, policy mode off, failed snapshot load),
	// the cache performs no lookup and no write for the org at all. The
	// resolver reads gw.policyRuntime lazily, so boot order does not matter.
	gw.cacheSvc.SetPolicyRegimeResolver(gw.policyCacheRegime)

	// w23-06 (w22-06 review MEDIUM): with the effective policy mode off or
	// unset (ResolvePolicyMode defaults "" to off), the armed regime resolver
	// fail-safes to "" for every org — this freshly wired cache performs no
	// lookup and no write at all (every op ticks
	// CacheEnforcementOffSkippedTotal), so an operator enabling cache_enabled
	// would otherwise own a silently inert cache. One-shot at startup
	// (wireCacheService runs exactly once per boot from buildGatewayAccounting);
	// this only logs — the accepted N03-P02-T04 fail-safe semantics are
	// untouched, the gating stays exactly as it is.
	if w.policy.Mode == "" || w.policy.Mode == PolicyModeOff {
		w.l.Warn("cache enabled but the policy mode is off/unset — the cache is fully gated (no lookups, no writes) for every org; set YABANIN_POLICY_MODE=shadow or enforce to serve it",
			"policy_mode", string(w.policy.Mode))
	}

	// P4.15: EmbedCache in-memory LRU deduplicates embedding calls.
	gw.cacheSvc.SetEmbedCache(cache.NewEmbedCache(2048))
	w.l.Info("embed cache initialized (lru=2048)")

	// P4.14: A/B experiment store — control arm skips cache lookups.
	gw.cacheSvc.SetExperimentStore(cache.NewExperimentStore(w.pool))
	w.l.Info("cache experiment store initialized")

	gw.cleaner = cache.NewCleaner(gw.cacheSvc, 5*time.Minute, w.l.With("component", "cache-cleaner"))
	go gw.cleaner.Start(ctx) // goroutine for periodic TTL purge
	w.l.Info("cache service initialized")
	return nil
}

// buildGatewayRouting wires the model-selection facet: the model resolver
// (with alias book) and fallback executor, the classifier suite, the tier
// router, effort/session/time routing policies, the org routing-mode loader,
// the classifier A/B assigner, and the PB2 region router + failover
// evaluator. Returns the ML classifier (nil without a classifier service
// URL) for the observability facet's calibration refresher, and a
// attached pack that fails on-disk verification aborts startup). The resolver
// suite is wired inside the historical DB-pool gate; the A/B assigner and
func buildGatewayRouting(ctx context.Context, w *gatewayWiring, gw *gateway) (*classifier.MLClassifier, error) {
	var mlClassifier *classifier.MLClassifier
	if w.pool != nil {
		l2 := w.l.With("component", "model_resolver")
		// Interface-typed nil (never a typed-nil *Encryptor): NewResolver
		// honours decrypters[0] != nil, and a non-nil interface wrapping a
		// nil *encryption.Encryptor would flip decryption on with no key.
		var dec resolver.Decrypter
		if w.enc != nil {
			dec = w.enc
		}
		res := resolver.NewResolver(w.pool, w.cfg.FallbackModel, 5*time.Minute, l2, dec)
		res.UseAliases(resolver.NewAliasBook(0, func(ctx context.Context) (map[string]string, error) {
			return resolver.QueryAliases(ctx, w.pool)
		}, l2))
		// W-BYOK-CORE: org custom models resolve against the same pool (the
		// resolver pins the org-isolation GUC per lookup). Without this wire
		// org_custom_models entries silently never match (global fallback
		// substitution always stands).
		res.UseOrgModels(w.pool)
		gw.res = res

		var err error
		mlClassifier, err = wireClassifier(ctx, w, gw)
		if err != nil {
			return nil, err
		}

		dbLoader := router.NewDBModelLoader(w.pool, w.l.With("component", "tier-router"))
		gw.tierRouter = router.NewTierRouter(dbLoader, w.rdb)

		// (read-only adapter; only owner-approved snapshots surface). Unset
		// dir = quality routing unwired — off by default deployment-wide.
		if dir := w.cfg.QualityResultsDir; dir != "" {
			approvals := w.cfg.QualityApprovalsPath
			if approvals == "" {
				approvals = filepath.Join(dir, "approvals.json")
			}
			gw.qualitySource = results.NewSource(dir, approvals)
			w.l.Info("quality routing source wired (read-only, owner-approved snapshots only)",
				"runs_dir", dir, "approvals", approvals)
		}

		// version-key invalidation shares the gateway's Redis under
		// canarystore:ver:<orgID>; without Redis the resolver degrades to
		// its hard TTL. Unwired (no adminstore) keeps the feature off:
		// SelectModelForSession then behaves exactly like
		// SelectModelWithAffinity (the zero-overhead path).
		if w.adminStore != nil {
			loader := canarySnapshotLoader(w.adminStore)
			var canaryVersions router.CanaryVersionReader
			if w.rdb != nil {
				canaryVersions = adminstore.NewCanaryVersionCache(w.rdb, w.l.With("component", "canary-versions"))
			}
			gw.tierRouter.WithCanaryRollouts(router.NewCanaryRolloutCache(loader, canaryVersions, 0, w.l.With("component", "canary-rollouts")))
			w.l.Info("canary rollout resolver enabled", "version_key_invalidation", canaryVersions != nil)
		}

		// Reasoning-effort routing (v15 E1): lowercase fragment list from the
		// comma-separated env value (best-effort; empty list = no injection).
		if w.cfg.EffortModels != "" {
			for _, frag := range strings.Split(w.cfg.EffortModels, ",") {
				frag = strings.ToLower(strings.TrimSpace(frag))
				if frag != "" {
					gw.effortModels = append(gw.effortModels, frag)
				}
			}
		}

		// KV-cache-aware routing (v15 K2): sticky model per session.
		if w.cfg.SessionAffinityEnabled {
			ttl, err := time.ParseDuration(w.cfg.SessionAffinityTTL)
			if err != nil || ttl <= 0 {
				w.l.Warn("invalid session affinity TTL, using 10m default", "value", w.cfg.SessionAffinityTTL, "error", err)
				ttl = 10 * time.Minute
			}
			backend := w.cfg.SessionAffinityBackend
			if backend == "" {
				backend = "memory"
			}
			if backend == "redis" && w.rdb != nil {
				// ENT-04 HA: share stickiness across gateway replicas via Redis.
				gw.sessionAffinity = router.NewRedisSessionAffinity(w.rdb, ttl, int64(w.cfg.SessionAffinityMinCacheTokens), w.l)
				w.l.Info("session affinity (KV-cache-aware routing) enabled", "backend", "redis", "ttl", ttl.String(), "min_cache_tokens", w.cfg.SessionAffinityMinCacheTokens)
			} else {
				if backend == "redis" && w.rdb == nil {
					w.l.Warn("session affinity backend=redis but no Redis available; falling back to memory")
				}
				gw.sessionAffinity = router.NewSessionAffinity(ttl, int64(w.cfg.SessionAffinityMinCacheTokens), 0)
				w.l.Info("session affinity (KV-cache-aware routing) enabled", "backend", "memory", "ttl", ttl.String(), "min_cache_tokens", w.cfg.SessionAffinityMinCacheTokens)
			}
		}

		// R2: cheap-hours / batch tier downgrade (opt-in). A bad window string
		// disables the feature (fail-closed: never route on an ambiguous window).
		if w.cfg.TimeRoutingEnabled {
			if win, err := router.ParseTimeWindow(w.cfg.TimeCheapWindow); err == nil {
				gw.timeRoutingEnabled = true
				gw.timeCheapWindow = win
				w.l.Info("time-window routing enabled", "window", w.cfg.TimeCheapWindow)
			} else {
				w.l.Warn("time-window routing disabled: invalid window", "value", w.cfg.TimeCheapWindow, "error", err)
			}
		}

		// Per-org routing mode (auto/manual) from adminstore; lookup failures
		// default to auto.
		gw.routingModeLoader = func(ctx context.Context, orgID string) *adminstore.OrgRoutingSettings {
			rs, err := w.adminStore.GetOrgRoutingSettings(ctx, orgID)
			if err != nil {
				w.l.Debug("routing mode lookup failed, defaulting to auto", "org_id", orgID, "error", err)
				return &adminstore.OrgRoutingSettings{RoutingMode: adminstore.RoutingModeAuto}
			}
			return rs
		}

		w.l.Info("classifier + tier router initialized")
	}
	gw.fallback = router.NewFallbackExecutor(gw.res, 3, w.l.With("component", "fallback"))

	// P5.12: A/B assigner for classifier experiments (deterministic bucketing).
	if w.cfg.ClassifierABEnabled {
		gw.abAssigner = classifier.NewABAssigner(3600)
		w.l.Info("A/B assigner initialized", "experiment", "classifier-ab")
	}

	// PB2: region-aware org routing + failover evaluator.
	if w.pool != nil && w.rdb != nil && w.cfg.Region != "" && len(w.cfg.Regions) > 0 {
		pgStore := regionrouter.NewPGStore(w.pool)
		routerInst := regionrouter.NewWithRedis(pgStore, w.rdb)
		gw.regionRouter = routerInst

		healthChecker := regionrouter.NewHealthChecker(getPeerURLs(w.cfg.Regions))
		gw.failoverEvaluator = regionrouter.NewFailoverEvaluator(routerInst, healthChecker, w.cfg.Regions, w.cfg.Region, w.l)
		w.l.Info("region router + failover evaluator initialized", "region", w.cfg.Region, "regions", len(w.cfg.Regions))
	}

	return mlClassifier, nil
}

// canarySnapshotLoadFunc adapts a closure to router.CanaryRolloutLoader.
type canarySnapshotLoadFunc func(ctx context.Context, orgID string) ([]router.CanaryRollout, error)

func (f canarySnapshotLoadFunc) LoadCanaryRollouts(ctx context.Context, orgID string) ([]router.CanaryRollout, error) {
	return f(ctx, orgID)
}

// canarySnapshotLoader projects the adminstore canary snapshot onto the
// is present and consistent reach the split point — a disabled rollout (the
// manual rollback, D3) contributes nothing.
func canarySnapshotLoader(s *adminstore.Store) router.CanaryRolloutLoader {
	return canarySnapshotLoadFunc(func(ctx context.Context, orgID string) ([]router.CanaryRollout, error) {
		snap, err := s.LoadCanarySnapshot(ctx, orgID)
		if err != nil {
			return nil, err
		}
		out := make([]router.CanaryRollout, 0, len(snap.Rollouts))
		for _, r := range snap.Rollouts {
			v, ok := snap.Versions[r.ID]
			if !r.Enabled || !ok || r.CurrentVersion <= 0 || v.Version != r.CurrentVersion {
				continue
			}
			out = append(out, router.CanaryRollout{
				RolloutID:   r.ID,
				Name:        r.Name,
				Version:     v.Version,
				BaseModel:   v.BaseModel,
				CanaryModel: v.CanaryModel,
				Percent:     v.Percent,
			})
		}
		return out, nil
	})
}

// wireClassifier wires the P5 classifier suite: rule tier, the optional ML
// classifier behind a circuit breaker + health checker, the registry with
// its Redis/pgvector cache variants, and the PC3 drift detector. Requires a
// DB pool (the historical gate). Returns the ML classifier — nil when no
// classifier service URL is configured — and a startup-refusal error from
// enabled AND a pack dir is configured; without a service URL the behavior
// is unchanged).
func wireClassifier(ctx context.Context, w *gatewayWiring, gw *gateway) (*classifier.MLClassifier, error) {
	// P5: Classifier + tier router — smart model routing by prompt complexity.
	ruleTier := classifier.NewRuleTier()

	// P5.7/P5.14: ML classifier with circuit breaker and rule-tier fallback.
	var primaryClassifier classifier.Classifier = ruleTier
	var mlClassifier *classifier.MLClassifier
	if w.cfg.ClassifierServiceURL != "" {
		// before the ML classifier is enabled; a refusal aborts startup.
		if packDir := w.cfg.MLPack().Dir; packDir != "" {
			pack, err := mlpack.AttachDir(packDir)
			if err != nil {
				w.l.Error("classifier model pack attach refused startup", "dir", packDir, "error", err.Error())
				return nil, fmt.Errorf("startup refused (R058 model pack): %w", err)
			}
			w.l.Info("classifier head model pack attached — verified on disk, no download (R058)",
				"pack_id", pack.Manifest.ID, "pack_version", pack.Manifest.Version, "files", len(pack.Manifest.Files), "dir", pack.Dir)
		}
		mlClassifier = classifier.NewMLClassifier(w.cfg.ClassifierServiceURL, w.l.With("component", "ml-classifier"))

		// P5.14: Circuit breaker — 3 consecutive failures → 30s open (fast-fail to fallback).
		var cb *classifier.CircuitBreaker
		if w.cfg.ClassifierCircuitEnabled {
			openTimeout, _ := time.ParseDuration(w.cfg.ClassifierCircuitTimeout)
			cb = classifier.NewCircuitBreaker(
				w.cfg.ClassifierCircuitThreshold,
				openTimeout,
				1, // 1 success in half-open → closed
			)
		} else {
			cb = classifier.NewCircuitBreaker(w.cfg.ClassifierCircuitThreshold, 30*time.Second, 1)
		}

		wrappedML := classifier.NewCircuitBreakerClassifier(mlClassifier, cb)
		primaryClassifier = classifier.NewRegistryClassifier(classifier.NewRegistry(wrappedML, ruleTier))

		// Start health checker goroutine — calls ML health endpoint periodically.
		hc := classifier.NewCircuitHealthChecker(mlClassifier, cb, w.l)
		go hc.Start(ctx)

		w.l.Info("ML classifier v1 enabled with circuit breaker", "service_url", w.cfg.ClassifierServiceURL)
	} else {
		w.l.Info("ML classifier v1 disabled — using rule-tier V0 only")
	}

	classifierReg := classifier.NewRegistry(primaryClassifier)
	var cls *classifier.RegistryWithDBCache
	if w.rdb != nil && w.pool != nil {
		// P5.6: Redis + pgvector-backed classification cache (read-through).
		cls = classifier.NewRegistryWithDBCache(classifierReg, w.rdb, w.pool, w.l.With("component", "classifier-cache"))
		w.l.Info("classifier + tier router initialized (with redis + pgvector cache)")
	} else if w.rdb != nil {
		// Redis only — no DB pool for semantic cache.
		redisOnly := classifier.NewRegistryWithCache(classifierReg, w.rdb, w.l.With("component", "classifier-cache"))
		cls = classifier.NewRegistryWithDBCacheSilent(redisOnly, w.pool, w.l.With("component", "classifier-cache"))
		w.l.Info("classifier + tier router initialized (redis-only — no pgvector)")
	} else {
		noop := classifier.NewRegistryWithCacheNoop(classifierReg)
		cls = classifier.NewRegistryWithDBCacheSilent(noop, nil, w.l.With("component", "classifier-cache"))
		w.l.Info("classifier + tier router initialized (no cache — single binary mode)")
	}
	gw.classifier = cls

	// PC3: wire drift detector into ML classifier for data flywheel.
	// Feedback-driven retrain triggers live on the admin side; the gateway
	// only records predictions via events (→ loggerd → request_logs).
	if mlClassifier != nil {
		detector := classifier.NewDriftDetector()
		mlClassifier.WithDriftDetector(detector)
		gw.driftDetector = detector
		w.l.Info("drift detector initialized", "warning_threshold", 0.65, "critical_threshold", 0.45)
	}

	return mlClassifier, nil
}

// buildGatewayCompliance wires the governance facet: PC2 vertical packs, the
// ADL-01 CI task tag, PA.5 residency enforcement, and U1 pre-egress guard
// hooks (all historically inside the DB-pool gate — they read org data), and
// PB1 jurisdictional lineage attestation behind its own LineageEnabled gate.
func buildGatewayCompliance(ctx context.Context, w *gatewayWiring, gw *gateway) {
	if w.pool != nil {
		// PC2: register vertical compliance packs.
		vReg := verticals.NewRegistry()

		packs := []verticals.Vertical{
			halalpack.New(),
			carbonpack.New(),
			healthpack.New(),
			financepack.New(),
			defensepack.New(),
			educationpack.New(),
			legalpack.New(),
			retailpack.New(),
		}
		for _, p := range packs {
			if err := vReg.Register(p); err != nil {
				w.l.Warn("vertical pack registration failed", "id", p.ID(), "error", err)
			} else {
				w.l.Info("vertical pack registered", "id", p.ID())
			}
		}
		gw.verticalReg = vReg
		w.l.Info("vertical registry initialized", "packs", len(packs))

		// ADL-01: CI task tag (YABANIN_TASK). A value that does not match the
		// task-tag format is ignored (warn + off): the per-request header path
		// validates its own value, and a mistyped deployment-wide tag must not
		// 400 every request.
		if w.cfg.TaskTag != "" {
			if budget.ValidTaskID(w.cfg.TaskTag) {
				gw.taskTag = w.cfg.TaskTag
				w.l.Info("ci task tag enabled", "task", w.cfg.TaskTag)
			} else {
				w.l.Warn("YABANIN_TASK ignored: invalid task tag", "value", w.cfg.TaskTag)
			}
		}

		// PA.5: residency policy-packs + enforcer.
		policyReg := policy.NewRegistry()
		policyReg.Register(asiapacks.NewSingaporePack())
		policyReg.Register(asiapacks.NewIndiaPack())
		policyReg.Register(asiapacks.NewIndonesiaPack())
		policyReg.Register(asiapacks.NewJapanPack())
		gw.residencyEnforcer = policy.NewEnforcer(
			policyReg,
			func(ctx context.Context, orgID string) policy.Region {
				region, err := w.adminStore.GetOrgResidencyRegion(ctx, orgID)
				if err != nil {
					w.l.Debug("residency region lookup failed", "org_id", orgID, "error", err)
					return policy.RegionGlobal
				}
				return policy.Region(region)
			},
			nil, // remap pool: nil → deny-only for MVP (remap unit-tested in pkg/policy)
			w.l.With("component", "residency-enforcer"),
		)
		w.l.Info("residency policy-packs registered", "packs", "SG,IN,ID,JP")

		if h := gw.guardHook(); h != nil && h.Enabled() {
			w.l.Info("guard hooks enabled", "mode", string(h.Mode()))
		}

	}
	// OP-8: the policy-pipeline runtime (single gateway integration
	// point). Build helper lives in gateway_policy.go.
	buildPolicyRuntime(ctx, w, gw)

	// PB1: Jurisdictional lineage attestation (best-effort, never blocks request).
	if w.cfg.LineageEnabled && w.pool != nil {
		wireLineage(ctx, w, gw)
	}
}

// wireLineage wires PB1 jurisdictional lineage attestation: the key store
// (with its own encryptor — separate from the shared per-model decrypter),
// the key cache, the async ledger, and the region resolver.
func wireLineage(ctx context.Context, w *gatewayWiring, gw *gateway) {
	var enc *encryption.Encryptor
	if w.cfg.EncryptionKey != "" {
		e, err := encryption.New(w.cfg.EncryptionKey)
		if err == nil {
			enc = e
		} else {
			w.l.Warn("failed to create lineage encryptor, signing will use raw keys", "error", err)
		}
	}
	gw.lineageKeyStore = lineage.NewKeyStore(w.pool, enc)
	// org_lineage_keys.private_key rows. Idempotent; no-op without a key.
	if gw.lineageKeyStore != nil {
		if n, err := gw.lineageKeyStore.MigratePlaintextKeys(ctx); err != nil {
			w.l.Warn("plaintext lineage key migration failed; will retry on next start", "error", err)
		} else if n > 0 {
			w.l.Info("migrated plaintext lineage private keys to encrypted storage", "count", n)
		}
	}
	gw.lineageKeys = lineage.NewKeyCache(gw.lineageKeyStore, 0)
	gw.lineageLedgerStore = lineage.NewLedgerStore(w.pool)
	gw.lineageAsync = lineage.NewAsyncLedger(gw.lineageLedgerStore, w.l, ctx)
	gw.regionResolver = lineage.NewRegionResolver(provider.NewJurisdictionRegistry(w.pool, 0))

	w.l.Info("lineage attestation enabled", "signer", "Ed25519")
}

// buildGatewayObservability wires the telemetry facet: the P5.9 evalgate
// judge + verdict store (+ P5.10 calibration refresher when the routing
// facet wired an ML classifier) and the V9 shadow-mode dispatcher with its
// residency pin check.
func buildGatewayObservability(ctx context.Context, w *gatewayWiring, gw *gateway, mlClassifier *classifier.MLClassifier) {
	// P5.9: Evalgate judge — LLM-as-judge for quality feedback loop.
	if w.cfg.EvalgateURL != "" && w.pool != nil {
		judge := evalgate.NewJudge(w.cfg.EvalgateURL, w.l.With("component", "evalgate"))
		store := evalgate.NewStore(w.pool, w.l.With("component", "evalgate-store"))

		// Wire judge API key if configured.
		if w.cfg.EvalgateAPIKey != "" {
			judge.SetAPIKey(w.cfg.EvalgateAPIKey)
		}

		gw.judge = judge
		gw.evalStore = store
		w.l.Info("evalgate judge initialized", "url", w.cfg.EvalgateURL, "sample_rate", w.cfg.EvalgateSampleRate)

		// P5.10: Calibration refresher — periodically fits calibrator from evalgate verdicts.
		if mlClassifier != nil {
			refresher := classifier.NewCalibrationRefresher(store, mlClassifier, w.l)
			go refresher.Start(ctx)
			w.l.Info("calibration refresher started (interval=1h)")
		}
	}

	// V9: shadow-mode — mirror sampled non-streaming traffic to a candidate
	// model. Disabled by default; an invalid config degrades to disabled.
	// The pin check reuses the shared adminStore.
	if w.cfg.Shadow.Enabled {
		scfg := shadow.Config{
			Enabled:        true,
			Model:          w.cfg.Shadow.Model,
			UpstreamURL:    w.cfg.Shadow.UpstreamURL,
			APIKey:         w.cfg.Shadow.APIKey,
			SampleRate:     w.cfg.Shadow.SampleRate,
			Timeout:        w.cfg.Shadow.ShadowTimeout(),
			MaxConcurrent:  w.cfg.Shadow.MaxConcurrent,
			DailyBudgetUSD: w.cfg.Shadow.DailyBudgetUSD,
		}
		if vcfg, err := scfg.Validate(); err != nil {
			w.l.Warn("shadow-mode disabled: invalid configuration", "error", err)
		} else {
			gw.shadow = shadow.NewDispatcher(vcfg, w.l.With("component", "shadow"))
			// Residency-pinned orgs are never mirrored: their data may not
			// leave the pinned region, and the shadow provider is arbitrary.
			// Same adminStore lookup the residency enforcer uses (PA.5).
			gw.shadow.SetPinnedOrgFunc(func(ctx context.Context, orgID string) bool {
				if w.adminStore == nil {
					return false
				}
				region, rerr := w.adminStore.GetOrgResidencyRegion(ctx, orgID)
				if rerr != nil {
					// Fail-safe for shadow: unknown region ⇒ not pinned.
					// The residency enforcer itself is fail-closed at
					// request time and will deny if the org is regulated.
					return false
				}
				return region != "" && region != "global"
			})
			w.l.Info("shadow-mode initialized", "model", vcfg.Model, "sample_rate", vcfg.SampleRate,
				"timeout", vcfg.Timeout, "max_concurrent", vcfg.MaxConcurrent, "daily_budget_usd", vcfg.DailyBudgetUSD)
		}
	}
}

// reservationReplicaID names this gateway process instance for the
// reservation store: hostname + pid + start nanos — unique per boot so a
// crashed replica's allowances are never reused by the replacement.
func reservationReplicaID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "gateway"
	}
	return fmt.Sprintf("%s-%d-%d", host, os.Getpid(), time.Now().UnixNano())
}

// startGatewayServers runs the main and (optional) admin listeners and blocks
// until ctx cancellation, then drains gracefully (AF-17: server lifecycle
// lives here, separate from composition and from the routes). The drain
// sequence itself (readiness=false → bounded propagation → stop listeners →
// bounded in-flight drain → lease release) lives in drain_readiness.go
// (N12-P03-T03).
func startGatewayServers(gw *gateway, httpRouter chi.Router, cfg config.Gateway, l *slog.Logger, ctx context.Context) error {
	// N12-P03-T03: readiness knob parsed BEFORE any listener opens — an
	// invalid YABANIN_READINESS_DRAIN_DELAY fails startup (fail-closed knob
	// convention, same as YABANIN_HTTP_MAX_HEADER_BYTES / YABANIN_SHUTDOWN_GRACE).
	drain, err := NewDrainReadiness()
	if err != nil {
		return err
	}
	gw.drain = drain
	srv, err := newGatewayHTTPServer(cfg.ListenAddr, httpRouter)
	if err != nil {
		return err
	}
	var adminSrv *http.Server
	if cfg.AdminListen != "" {
		adminRouter := chi.NewRouter()
		adminRouter.Get("/debug/vars", gw.debugVars)
		if cfg.MetricsEnabled {
			gw.registerMetrics(adminRouter, l)
		}
		// V9: shadow-mode runtime kill-switch (fail-closed bearer auth).
		gw.registerShadowAdmin(adminRouter, l)
		if cfg.DebugPprof {
			gw.registerGatedPprof(adminRouter)
			l.Info("pprof endpoints enabled on admin server (gated like /debug/vars)")
		}
		readTimeout, _ := time.ParseDuration(cfg.ReadTimeout)
		writeTimeout, _ := time.ParseDuration(cfg.WriteTimeout)
		idleTimeout, _ := time.ParseDuration(cfg.IdleTimeout)
		if readTimeout == 0 {
			readTimeout = 15 * time.Second
		}
		if writeTimeout == 0 {
			writeTimeout = 15 * time.Second
		}
		if idleTimeout == 0 {
			idleTimeout = 60 * time.Second
		}
		adminSrv, err = newGatewayAdminServer(cfg.AdminListen, adminRouter, readTimeout, writeTimeout, idleTimeout)
		if err != nil {
			return err
		}
		l.Info("gateway admin starting", "addr", cfg.AdminListen)
		go func() {
			if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				l.Error("admin listen failed", "error", err)
			}
		}()
	}

	listenErr := make(chan error, 1)
	go func() {
		l.Info("gateway starting", "addr", cfg.ListenAddr, "build", buildVersion)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			l.Error("listen failed", "error", err)
			listenErr <- fmt.Errorf("gateway listen failed: %w", err)
		} else if len(listenErr) == 0 {
			// Server closed cleanly, signal success to any potential reader
			select {
			case listenErr <- nil:
			default:
			}
		}
	}()

	// Wait for context cancellation or immediate listen error
	select {
	case err := <-listenErr:
		if err != nil {
			return err
		}
	case <-ctx.Done():
	}
	// N12-P03-T03: readiness-first bounded drain (see drain_readiness.go).
	// The old inline sequence shut one shared 5s ctx across every stage, so a
	// saturated HTTP drain could starve the escrow-release budget; each stage
	// now has its own bound, and readiness flips false before anything closes.
	//nolint:contextcheck // the drain derives fresh bounded contexts after ctx cancellation; the shutdown sequence must outlive the cancelled request context
	gw.drainServers(srv, adminSrv, l)
	return nil
}

const defaultGatewayMaxHeaderBytes = 1 << 20
const maxGatewayMaxHeaderBytes = 16 << 20

// gatewayMaxHeaderBytes configures net/http's aggregate request-header limit.
// Invalid overrides fail startup rather than silently weakening configuration.
func gatewayMaxHeaderBytes() (int, error) {
	if raw := strings.TrimSpace(os.Getenv("YABANIN_HTTP_MAX_HEADER_BYTES")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("YABANIN_HTTP_MAX_HEADER_BYTES must be an integer: %w", err)
		}
		if n <= 0 || n > maxGatewayMaxHeaderBytes {
			return 0, fmt.Errorf("YABANIN_HTTP_MAX_HEADER_BYTES must be between 1 and %d bytes", maxGatewayMaxHeaderBytes)
		}
		return n, nil
	}
	return defaultGatewayMaxHeaderBytes, nil
}

func newGatewayHTTPServer(addr string, handler http.Handler) (*http.Server, error) {
	maxHeaderBytes, err := gatewayMaxHeaderBytes()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		// WriteTimeout=0 (no deadline) — streaming LLM responses routinely exceed
		// 15s. The per-request middleware timeout (default 60s) provides the actual
		// request-level deadline; http.Server.WriteTimeout should not truncate streams.
		WriteTimeout:   0,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: maxHeaderBytes,
	}, nil
}

// newGatewayAdminServer builds the in-process gateway admin listener
// (/debug/vars, /metrics, gated pprof) with the same server-level hardening
// as the main listener: the YABANIN_HTTP_MAX_HEADER_BYTES aggregate header
// cap plus the configured read/write/idle deadlines. Both gateway listeners
// must share the posture so an operator override (or a slow-header client)
// cannot leave the internal surface weaker than the public one. Unlike the
// main listener, WriteTimeout keeps the configured value: the admin surface
// never streams long LLM responses.
func newGatewayAdminServer(addr string, handler http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration) (*http.Server, error) {
	maxHeaderBytes, err := gatewayMaxHeaderBytes()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}, nil
}

// verdictStore is the evalgate persistence seam: sampled requests record
// judge verdicts through it. Production wires *evalgate.Store; tests observe
// InsertVerdict calls with a fake.
type verdictStore interface {
	InsertVerdict(ctx context.Context, orgID, requestID, prompt, cheapModel, premiumModel string, v *evalgate.Verdict, rawConfidence float64) error
}

// gatewayCore is the transport facet: config, logger, redis, DB/session
// handles, the auth middleware, the rule engine snapshot cache + rule store,
// the shared event publisher, and pipeline-wide defaults (retry policy,
// unknown-model policy, stream watchdog knobs, clock, label policy, model
// lister).
type gatewayCore struct {
	cfg            config.Gateway
	trustedProxies []string
	rdb            *redis.Client
	log            *slog.Logger
	auth           *AuthMiddleware
	ruleStore      *rulestore.Store
	eng            *evaluator.SnapshotCache
	publisher      *eventpub.RedisPublisher
	// eventNote, when set, observes events before they are published. Tests only.
	eventNote   func(*eventpub.Event)
	retryPolicy retry.Policy
	// unknownModelPolicy is "fallback" or "reject" (RM-09). Empty means fallback.
	unknownModelPolicy string
	// Stream idle watchdog: cancel the upstream body when no bytes arrive
	// for this long (0 = disabled; serveStream arms it per stream).
	streamIdleTimeout time.Duration
	// streamUsageProviders (RM-03) gates stream_options.include_usage
	// injection per provider name; nil = injection disabled (tests).
	streamUsageProviders map[string]bool
	dbPool               *pgxpool.Pool // DB pool for evalgate/feedback stores (P5.9+)
	// dbPricer (P6) is the per-gateway handle to the DB-backed pricer. The
	// request path's global default pricer is installed from it once at
	// server boot (RunGatewayServerWithJWT); composing a gateway never does.
	dbPricer  pricing.Pricer
	sessionDB sessionQuerier // AT-14 tests; production uses dbPool
	sessionKV sessionRedis   // AT-14 tests; production uses rdb
	// nowFn lets tests pin the clock (R2 window checks, budget days).
	nowFn func() time.Time
	// labelPolicy overrides the process-wide default. Tests use it for reject mode.
	labelPolicy     func(ctx context.Context, orgID string) *labels.Compiled
	labelPolicyOnce sync.Once
	labelsOrg       *orgLabelPolicies
	// GET /v1/models. Nil only before bindModelLister; handlers then return 503.
	models modelLister
	// P1.1: whitelist enforcement loader — model access per API key / team
	// (metering-adjacent; wired by the accounting facet builder).
	wl modelAccess
	// N12-P03-T03: drain/readiness gate. Nil until startGatewayServers wires
	// it (test compositions never start the server) — nil reports ready, so
	// /healthz keeps the pre-T03 shape there.
	drain *DrainReadiness
}

// gatewayEgress is the outbound facet: the upstream client pool, the circuit
// breaker, the MCP/A2A aggregator proxies, the tool policy engine + built-in
// executor, and the MCP agent-name resolver.
type gatewayEgress struct {
	pool     *upstream.Pool
	circuits *circuit.Map
	// circuitScope selects request-path gating granularity; meaningful only
	// when circuits != nil.
	circuitScope circuit.Scope

	// MCP-02: MCP aggregator proxy (nil when YABANIN_MCP_GATEWAY is not set
	// or no DB pool — the /api/mcp/invoke route group is not mounted).
	mcpProxy *mcpagg.Proxy
	// catalog reads through (same pool as the proxy; nil with the feature
	// off).
	mcpStore *mcpagg.Store
	// Wired with the proxy (it proxies into it); nil when the MCP feature
	// is off — the /mcp routes are then not mounted.
	mcpStreamable *mcpserver.Server
	// MC-3: the credential flow source (submit/begin/callback mechanics over
	// the adminstore + version store). Wired with the proxy; nil when the
	// MCP feature is off (the flow routes then 404).
	mcpCredsSrc *mcpCredsSource
	// A2A-01: external A2A agent proxy (nil when YABANIN_A2A_GATEWAY is not
	// set or no DB pool — the /api/a2a/send route group is then not mounted).
	a2aProxy *a2aagg.Proxy
	// TOOL-01/03: tool policy engine (nil without a DB pool; zero policies
	// = allow-all, no behavior change) and the built-in server-side tool
	// executor (web_fetch et al; nil without a DB pool).
	toolPolicies *toolpolicy.Engine
	toolExec     *toolexec.Executor

	// MCP-04: resolves an agent-principal ID to its display name so the
	// upstream MCP call carries X-Yabanin-Agent-Name. Returns "" when the
	// agent is unknown or no DB pool is available (the header is then simply
	// omitted — the name is an attribution aid, not an auth input).
	// Only wired when the MCP proxy is active (it requires a pool).
	mcpAgentName func(ctx context.Context, agentID string) string

	// W-BYOK-CORE: org credentials (BYOK). orgCreds is the request-path
	// ResolveKey surface of the frozen W-BYOK-DB adminstore contract (nil =
	// feature off — no org-key resolution, the pre-BYOK behavior); the
	// concrete *adminstore.Store satisfies it structurally once the
	// the (org, provider, endpoint) probes; orgCredsVersions is the shared
	// credentials CRUD (see OrgCredsVersionStore).
	orgCreds         OrgKeyResolver
	orgCredsProbe    *orgCredsProbe
	orgCredsVersions OrgCredsVersionStore
	// credentials: round-robin, version-scoped quarantine on 401/429 and
	// per-credential event attribution. nil = the store carries only the
	// frozen surface (legacy newest-first path) or BYOK is off.
	credPool *orgCredsPool
}

// gatewayRouting is the model-selection facet: the model resolver and
// fallback executor, the classifier suite, the tier router, session/effort/
// time routing policies, the classifier A/B assigner, and PB2 region
// routing + failover.
type gatewayRouting struct {
	res        modelResolver
	fallback   *router.FallbackExecutor
	classifier *classifier.RegistryWithDBCache
	tierRouter *router.TierRouter
	// Per-org routing mode (auto/manual) loader; lookup failures default to auto.
	routingModeLoader func(ctx context.Context, orgID string) *adminstore.OrgRoutingSettings
	// (nil = quality routing off everywhere; D2 owner-approved snapshots only).
	qualitySource router.QualitySource
	// KV-cache-aware routing (v15 K2): per-session sticky model (nil when
	// session affinity is disabled).
	sessionAffinity router.AffinityStore
	// Reasoning-effort routing (v15 E1): lowercase model-name fragments that
	// receive "reasoning_effort" injection (empty = no injection even when
	// enabled).
	effortModels       []string
	timeRoutingEnabled bool
	timeCheapWindow    router.TimeWindow
	// P5.12: A/B assigner for classifier experiments
	abAssigner *classifier.ABAssigner

	// PB2: region-aware routing and failover.
	regionRouter      *regionrouter.Router            // org_id → home_region (nil in single-region mode)
	failoverEvaluator *regionrouter.FailoverEvaluator // nil when single-region
}

// gatewayAccounting is the metering facet: the semantic cache, budget
// enforcers, prepaid credits, resale pricing, durable reservations, token
// budgets, and per-key rate limits.
type gatewayAccounting struct {
	// cache is the request-path cache surface (RT-02: interface so the warm
	// branch can be regression-tested without Redis). cacheSvc is the same
	// service as its concrete type for production wiring (policy/embed/AB
	// configuration and the cleaner).
	cache    responseCache
	cacheSvc *cache.CacheService
	cleaner  *cache.Cleaner
	// P6.10/G2: budget enforcers (nil-safe in the handlers so deploys without
	// the 0101 tables are fine).
	budgetEnforcer teamBudgetChecker
	agentEnforcer  agentBudgetChecker    // G2: per-agent daily budget (nil = not wired)
	creditStore    *credits.Store        // prepaid credits wallet per org (nil when no DB)
	markupPricer   *pricing.MarkupPricer // resale pricer with markup (nil when no DB)
	// NEXT-18c: durable budget reservations controller (ADR-0001 §5/§9).
	// nil = off — the legacy admission path runs untouched.
	admission *budget.Admission
	// T02: non-token unit rates (audio seconds / characters / images) from
	// the pinned side-catalog. nil in hand-built test gateways — unit
	// pricing off, the legacy fail-closed behavior stands.
	unitPricer pricing.UnitPricer
	// G3: per-task / per-session token budgets (nil when both caps are 0 /
	// off).
	tokenBudget *TokenBudget
	// YABANIN_KEY_RATE_LIMITS is off — the default — or no DB+Redis; nil
	// means the middleware is not mounted and behavior is unchanged).
	rateLimits *keyRateLimiter
	// RATELIMIT-FALLBACK P3: per-replica fair admission controller in
	// front of upstream dispatch (N09-P02 surface). nil = off — the
	// default; the request path is bit-for-bit the legacy one.
	fair *router.FairAdmission
	// and /v1/batches endpoints then answer 503 and the executor is not
	// started).
	batchStore *batchstore.Store
}

// gatewayCompliance is the governance facet: U1 pre-egress guard hooks, PA.5
// residency enforcement, PB1 jurisdictional lineage attestation, PC2
// vertical packs, and the ADL-01 CI task tag.
type gatewayCompliance struct {
	// U1: pre-egress guard hooks (deterministic PII/secrets/injection).
	// guardHooks is the construction-time built-in fallback (mode off / no
	// packs); the request path resolves the CURRENT hook per request via
	// guardHook (audit CA-02: never capture the startup hook for the
	// process lifetime).
	guardHooks     *guardhooks.Hook
	guardLifecycle *guardhooks.PackLifecycle
	// FIX-03: durable guard-pack runtime adoption for running replicas.
	// nil = off (no durable store / no pack root) — the lifecycle (or the
	// built-in fallback) alone serves requests.
	guardWatch *guardPackWatcher
	// PA.5: residency enforcement (nil when no DB pool is configured).
	residencyEnforcer residencyChecker

	// PB1: jurisdictional lineage attestation (nil when LineageEnabled=false).
	lineageKeyStore    *lineage.KeyStore
	lineageKeys        *lineage.KeyCache
	lineageLedgerStore *lineage.LedgerStore
	lineageAsync       *lineage.AsyncLedger
	// PB1.7: grades inference_region per request (endpoint_pinned vs provider_declared...).
	regionResolver *lineage.RegionResolver

	// PC2: vertical compliance packs registry.
	verticalReg *verticals.Registry

	// ADL-01: CI task tag (YABANIN_TASK). Valid at build time; applied to
	// requests that do not carry their own X-Yabanin-Task header.
	taskTag string

	// OP-8: the policy-pipeline runtime (nil = off — every hook is a
	// nil-check no-op and behavior is bit-for-bit pre-OP-8).
	policyRuntime *PolicyRuntime
}

// gatewayObservability is the telemetry facet: the P5.9 evalgate judge +
// verdict store, the PC3 classifier drift detector, and the V9 shadow-mode
// dispatcher.
type gatewayObservability struct {
	// P5.9: evalgate judge for LLM-as-judge quality feedback
	judge     *evalgate.Judge
	evalStore verdictStore
	// PC3: classifier drift detector for data flywheel.
	driftDetector *classifier.DriftDetector
	// V9: shadow-mode dispatcher (nil when shadow is disabled).
	shadow *shadow.Dispatcher
}

// gateway is the request-path service. Its dependencies are grouped into the
// embedded fields stay promoted, so gw.cfg, gw.pool, … keep working exactly
// as before the split.
type gateway struct {
	gatewayCore
	gatewayEgress
	gatewayRouting
	gatewayAccounting
	gatewayCompliance
	gatewayObservability
}

// decisionJSON renders the routing decision for the analytics event field
// when the event flag is enabled; empty string otherwise (the header is
// governed separately by DecisionHeaderEnabled).
// now returns the gateway clock (injectable for tests; defaults to time.Now).
func (gw *gateway) now() time.Time {
	if gw.nowFn != nil {
		return gw.nowFn()
	}
	return time.Now()
}

// ruleSnapshot returns the immutable compiled rule snapshot for orgID,
// served from the shared cache so an unchanged rule set is parsed once.
// Gateways built directly in tests may leave eng nil; they then compile a
// fresh snapshot per request — still immutable and org-scoped, just without
// caching.
func (gw *gateway) ruleSnapshot(orgID string, rules []evaluator.Rule) *evaluator.Snapshot {
	if gw.eng == nil {
		return evaluator.NewSnapshot(orgID, rules)
	}
	return gw.eng.Get(orgID, rules)
}

func (gw *gateway) decisionJSON(source string, d routingDecision) string {
	if !gw.cfg.DecisionEventEnabled || source == "" {
		return ""
	}
	d.Source = source
	b, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(b)
}

// effortForModel returns the reasoning_effort value that will be injected for
// the model ("" when effort routing is off or the model is not eligible).
// Mirrors the eligibility logic in maybeInjectEffort (v18 R1 decision fields).
func (gw *gateway) effortForModel(model string) string {
	if !gw.cfg.EffortRoutingEnabled || len(gw.effortModels) == 0 {
		return ""
	}
	lm := strings.ToLower(model)
	for _, frag := range gw.effortModels {
		if strings.Contains(lm, frag) {
			return "high"
		}
	}
	return ""
}

func (gw *gateway) routes(r chi.Router) {
	r.Head("/api/hello", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Route("/v1", func(v1 chi.Router) {
		v1.Group(func(r chi.Router) {
			gw.useInferenceMiddleware(r)
			r.Post("/chat/completions", gw.chatCompletions)
			r.Post("/responses", gw.responses)
			r.Post("/embeddings", gw.embeddings)
			r.Post("/images/generations", gw.imagesGenerations)
			r.Post("/completions", gw.completions)
			r.Post("/audio/speech", gw.audioSpeech)
			r.Post("/audio/transcriptions", gw.audioTranscriptions)
			// SSE-only; video is out of the first release.
			r.Post("/rerank", gw.rerank)
			r.Post("/moderations", gw.moderations)
			r.Post("/realtime", gw.realtime)
			r.Get("/models", gw.listModels)
			r.Get("/models/{id}", gw.getModel)
			// DB pool → the handlers answer 503).
			r.Post("/files", gw.filesUpload)
			r.Get("/files", gw.filesList)
			r.Get("/files/{id}", gw.filesGet)
			r.Get("/files/{id}/content", gw.filesContent)
			r.Delete("/files/{id}", gw.filesDelete)
			r.Post("/batches", gw.batchesCreate)
			r.Get("/batches", gw.batchesList)
			r.Get("/batches/{id}", gw.batchesGet)
			r.Post("/batches/{id}/cancel", gw.batchesCancel)
			r.Get("/batches/{id}/results", gw.batchesResults)
		})
		v1.Group(func(r chi.Router) {
			r.Use(anthropicErrorEnvelope)
			gw.useInferenceMiddleware(r)
			r.Post("/messages", gw.messages)
			r.Post("/messages/count_tokens", gw.countTokens)
		})
	})
	// AT-14: session keys. Auth only — label merge for mint is explicit.
	r.Route("/v1/yabanin", func(y chi.Router) {
		y.Use(gw.authMiddlewareFunc)
		y.Post("/session-keys", gw.mintSessionKey)
		y.Delete("/session-keys/{id}", gw.revokeSessionKey)
		y.Post("/session-keys/{id}/finish", gw.finishSessionKey)
		y.Get("/session-keys/{id}/usage", gw.sessionKeyUsage)
		y.Get("/usage", gw.ownUsage)
		y.Get("/label-policy", gw.sessionLabelPolicy)
	})

	// MCP-02: MCP aggregator invoke endpoint. Mounted ONLY when the proxy is
	// wired (YABANIN_MCP_GATEWAY=1 + DB pool) — default OFF, zero behavior
	// change otherwise. Agent-authenticated (same middleware as /v1): the
	// org comes from the resolved key; the MCP-03 card narrows this to yag_
	// agent keys + per-agent grants. Identity headers (X-Agent-Id, X-Team-Id)
	// are set by the auth middleware from the verified principal — client
	// copies are stripped there (R6).
	//
	// chi v5.4.0 note: this was Group()+Mount(); v5.4.0 (upstream #843)
	// panics on mounting a Group because an inline mux shares the parent's
	// routing tree. Route() mounts an independent subrouter. Auth is bound
	// per endpoint with With() — matching the previous inline-chain semantics
	// where middleware ran for matched routes only, so unknown subpaths stay
	// flat 404s (they never execute auth or a handler).
	if gw.mcpProxy != nil {
		r.Route("/api/mcp", func(r chi.Router) {
			r.With(gw.authMiddlewareFunc).Post("/invoke", gw.mcpInvoke)
			// TOOL-03: built-in executor discovery (agent-only; denied
			// tools are hidden per org policy).
			r.With(gw.authMiddlewareFunc).Get("/yabanin/tools", gw.builtinToolCatalog)
			// MC-3: per-user lazy authorization (agent-authenticated; the
			// grant on the server stays the ceiling).
			r.With(gw.authMiddlewareFunc).Post("/credentials/{server}", gw.mcpSubmitUserCredential)
			r.With(gw.authMiddlewareFunc).Post("/auth/{server}/begin", gw.mcpOAuthBegin)
		})
		// MC-3: the oauth callback is browser-driven (the IdP redirects the
		// human here — no agent key is present). Public on purpose; the flow
		// state nonce is the capability and the org query param is only a
		// routing hint (a wrong org finds no pending row).
		r.Get("/api/mcp/auth/{server}/callback", gw.mcpOAuthCallback)
	}

	// directly as to any MCP server (initialize/tools/list/tools/call over
	// JSON-RPC 2.0). Mounted ONLY when the proxy is wired (same gate as the
	// invoke group above). Agent auth is the same middleware as invoke; the
	// server-initiated SSE stream) and DELETE are served by the handler
	// itself (405 / 204) per the Streamable HTTP transport spec.
	if gw.mcpStreamable != nil {
		r.Group(func(r chi.Router) {
			r.Use(gw.authMiddlewareFunc)
			if gw.rateLimits != nil {
				r.Use(gw.rateLimits.middleware)
			}
			r.Post("/mcp", gw.mcpStreamable.ServeHTTP)
			r.Get("/mcp", gw.mcpStreamable.ServeHTTP)
			r.Delete("/mcp", gw.mcpStreamable.ServeHTTP)
		})
	}

	// A2A-01: agent-to-agent send endpoint. Mounted ONLY when the proxy is
	// wired (YABANIN_A2A_GATEWAY=1 + DB pool) — default OFF. Same middleware
	// and identity contract as /api/mcp/invoke (yag_ principals only).
	// Route()+With() for the same v5.4.0 and flat-404 reasons as /api/mcp.
	if gw.a2aProxy != nil {
		r.Route("/api/a2a", func(r chi.Router) {
			r.With(gw.authMiddlewareFunc).Post("/send", gw.a2aSend)
		})
	}
}

func (gw *gateway) useInferenceMiddleware(r chi.Router) {
	r.Use(gw.authMiddlewareFunc)
	// key/team/org RPM+TPM windows run right after auth (they key on
	// the resolved identity headers) and before any handler or cache branch.
	if gw.rateLimits != nil {
		r.Use(gw.rateLimits.middleware)
	}
	r.Use(gw.labelsMiddleware)
	if gw.creditStore != nil {
		r.Use(httpmw.CreditGuard(gw.creditStore))
	}
	if gw.failoverEvaluator != nil {
		r.Use(gw.failoverMiddlewareFunc)
	}
}

// mcpInvoke handles POST /api/mcp/invoke — one tool call on an org-registered
// external MCP server (MCP-02 core; MCP-03 adds agent-only + grants).
func (gw *gateway) mcpInvoke(w http.ResponseWriter, r *http.Request) {
	if gw.mcpProxy == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
			"org resolution failed")
		return
	}
	// MCP-03: tool-calls are agent-principal (yag_) only. The middleware sets
	// X-Agent-Id from the resolved principal and strips any client copy, so an
	// empty value means a regular api_key — rejected with 403 before the proxy.
	agentID := r.Header.Get("X-Agent-Id")
	if agentID == "" {
		apierrors.Write(w, http.StatusForbidden, "agent_only",
			"mcp tool-calls require an agent-principal (yag_) key")
		return
	}
	var req mcpagg.InvokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"malformed JSON body")
		return
	}
	// Per-request observability context for the audit trail (request_logs join
	// + task tagging). RequestID comes from the request context; TaskID is the
	// client's X-Yabanin-Task tag (validated by the gateway elsewhere; here it
	// is an attribution tag for the MCP call).
	id := mcpagg.Identity{
		AgentID:   agentID,
		TeamID:    r.Header.Get("X-Team-Id"),
		RequestID: logctx.RequestID(r.Context()),
		TaskID:    r.Header.Get("X-Yabanin-Task"),
	}
	// MCP-04: the agent display name rides upstream as X-Yabanin-Agent-Name.
	// It is an attribution aid (read by the upstream MCP server), not an auth
	// input — the agent ID is the auth fact. A lookup failure simply omits the
	// name header (mcpAgentName is nil when there is no DB pool, which cannot
	// happen here because the MCP proxy requires one).
	if gw.mcpAgentName != nil {
		id.AgentName = gw.mcpAgentName(r.Context(), agentID)
	}

	// TOOL-03: built-in server-side tools execute IN the gateway (the
	// "yabanin" virtual server): egress happens from the gateway's network
	// position, not the agent's machine.
	if req.Server == toolexec.BuiltinServerName {
		gw.builtinToolInvoke(w, r, orgID, id, req)
		return
	}

	// TOOL-01: org tool policy gates the call before the proxy egresses.
	if gw.policyDeniesTool(w, r, orgID, agentID, req.Tool) {
		return
	}

	result, err := gw.mcpProxy.Invoke(r.Context(), orgID, id, req)
	if err != nil {
		// MC-2: lazy authorization — no usable credential (or a terminally
		// rejected one) is a 401 carrying the flow pointer, not a generic
		// upstream failure: {"error":{"code":"mcp_auth_required","kind":
		// "oauth|headers","url":...}}.
		var authErr *mcpagg.AuthRequiredError
		if errors.As(err, &authErr) {
			writeMCPAuthRequired(w, authErr)
			return
		}
		var iErr *mcpagg.InvokeError
		if errors.As(err, &iErr) {
			status := http.StatusBadGateway
			switch iErr.Code {
			case mcpagg.ErrCodeAgentOnly:
				status = http.StatusForbidden
			case mcpagg.ErrCodeNotFound:
				status = http.StatusNotFound
			case mcpagg.ErrCodeSSRF:
				status = http.StatusBadRequest
			case mcpagg.ErrCodeDenied:
				status = http.StatusConflict
			case mcpagg.ErrCodeToolBlocked:
				status = http.StatusBadRequest
			case mcpagg.ErrCodeTimeout:
				status = http.StatusGatewayTimeout
			}
			apierrors.Write(w, status, iErr.Code, iErr.Message)
			return
		}
		gw.log.Error("mcp invoke failed", "org", orgID, "server", req.Server, "tool", req.Tool, "error", err)
		apierrors.Write(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	// The body is the upstream JSON-RPC result (application/json). gosec
	// G705's taint analysis flags w.Write(result) as a potential reflected
	// XSS; it is a false positive here: the response is JSON (not HTML), the
	// Content-Type is fixed, and the browser does not execute it as a script.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(result); err != nil { //nolint:gosec // G705: JSON body, not HTML
		gw.log.Warn("mcp invoke: writing response failed", "org", orgID, "error", err)
	}
}

// writeMCPAuthRequired renders the MC-2 lazy-authorization error. It is a
// dedicated shape (not the OpenAI envelope): the agent branches on code and
// surfaces kind + url to its human — the plan's contract for
// {"error":{"code":"mcp_auth_required","kind":...,"url":...}}. No secret
// material ever appears here; the URL is the MC-3 flow path on this origin.
func writeMCPAuthRequired(w http.ResponseWriter, authErr *mcpagg.AuthRequiredError) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    mcpagg.ErrCodeAuthRequired,
			"kind":    authErr.Kind,
			"url":     authErr.URL,
			"message": authErr.Message,
		},
	})
}

// failoverMiddlewareFunc checks if this gateway is the org's home region.
// Returns 307 redirect to peer or 503 for pinned orgs in a down region.
func (gw *gateway) failoverMiddlewareFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := r.Header.Get("X-Org-Id")
		if orgID != "" {
			if err := gw.failoverEvaluator.Decide(r.Context(), orgID); err != nil {
				gw.log.Warn("region failover", "org_id", orgID, "error", err)
				apierrors.Write(w, http.StatusServiceUnavailable, "region_unavailable",
					"service temporarily unavailable: "+err.Error())
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// getPeerURLs builds a list of PeerURL for all regions except the local one.
func getPeerURLs(regions config.RegionMap) []regionrouter.PeerURL {
	var peers []regionrouter.PeerURL
	for _, rc := range regions {
		if rc.GatewayURL != "" {
			peers = append(peers, regionrouter.PeerURL{Region: rc.Name, URL: rc.GatewayURL})
		}
	}
	return peers
}

// requireDebugAuth gates the debug surfaces (/debug/vars, /debug/pprof/*):
// only localhost callers presenting the configured Bearer key pass. On
// rejection it writes 403 itself and reports false.
func (gw *gateway) requireDebugAuth(w http.ResponseWriter, r *http.Request) bool {
	clientIP := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-Ip"), gw.trustedProxies)
	if !isLocalhost(clientIP) {
		apierrors.Write(w, http.StatusForbidden, apierrors.ErrorCodePermissionDenied, "forbidden")
		return false
	}
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth {
		token = strings.TrimPrefix(auth, "bearer ")
	}
	if gw.cfg.APIKey == "" || subtle.ConstantTimeCompare([]byte(token), []byte(gw.cfg.APIKey)) != 1 {
		apierrors.Write(w, http.StatusForbidden, apierrors.ErrorCodePermissionDenied, "forbidden")
		return false
	}
	return true
}

func (gw *gateway) debugVars(w http.ResponseWriter, r *http.Request) {
	if !gw.requireDebugAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data := map[string]interface{}{
		"config": map[string]string{
			"listen_addr":  gw.cfg.ListenAddr,
			"admin_listen": gw.cfg.AdminListen,
			"provider":     gw.cfg.Provider,
			"redis_addr":   gw.cfg.RedisAddr,
			"log_level":    gw.cfg.LogLevel,
			"auth_mode":    gw.cfg.AuthMode,
		},
	}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode debug vars response", "error", err)
	}
}

// registerMetrics mounts /metrics on the admin listener. When MetricsBearerKey is set,
// scrapes must present "Authorization: Bearer <key>" (constant-time compare); with an
// empty key the documented network-restriction-only behavior is preserved. No localhost
// check applies: Prometheus normally scrapes from outside the host/pod.
func (gw *gateway) registerMetrics(r chi.Router, l *slog.Logger) {
	handler := metrics.PrometheusHandler()
	if gw.cfg.MetricsBearerKey == "" {
		r.Handle("/metrics", handler)
		l.Info("metrics /metrics endpoint enabled on admin server")
		return
	}
	key := gw.cfg.MetricsBearerKey
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, req)
	})
	r.Handle("/metrics", wrapped)
	l.Info("metrics /metrics endpoint enabled on admin server (bearer auth required)")
}

// registerGatedPprof mounts /debug/pprof/* behind requireDebugAuth. The named
// profile endpoints (goroutine/heap/...) are not exposed on the admin server;
// profiles are captured via index + /profile and downloaded off-box.
func (gw *gateway) registerGatedPprof(r chi.Router) {
	r.Handle("/debug/pprof/", gw.gatedPprof("index"))
	r.Handle("/debug/pprof/cmdline", gw.gatedPprof("cmdline"))
	r.Handle("/debug/pprof/profile", gw.gatedPprof("profile"))
	r.Handle("/debug/pprof/symbol", gw.gatedPprof("symbol"))
	r.Handle("/debug/pprof/trace", gw.gatedPprof("trace"))
}

// gatedPprof wraps one std net/http/pprof endpoint with the debug-auth gate.
func (gw *gateway) gatedPprof(name string) http.HandlerFunc {
	var serve func(http.ResponseWriter, *http.Request)
	switch name {
	case "cmdline":
		serve = pprof.Cmdline
	case "profile":
		serve = pprof.Profile
	case "symbol":
		serve = pprof.Symbol
	case "trace":
		serve = pprof.Trace
	default:
		serve = pprof.Index
	}
	return func(w http.ResponseWriter, req *http.Request) {
		if !gw.requireDebugAuth(w, req) {
			return
		}
		serve(w, req)
	}
}

func isLocalhost(addr string) bool {
	host := addr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		host = addr[:idx]
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// buildVersion is the build marker for the gateway stand surface (incident
// 2026-11-01: the stand exposed no way to tell whether it ran pre-fix code).
// It is overridable at build time via
// -ldflags "-X github.com/reireirei/yabanin/pkg/gateway.buildVersion=<short-commit>"
// (the same vars-not-consts pattern services/admin/handlers uses for its
// authenticated /api/version; pkg/gateway carries the public probe value).
// The unstamped default is the honest "dev": a build without the marker says
// so instead of leaking nothing or inventing a version. The value must stay
// free of secrets, filesystem paths and topology details — it travels on the
// unauthenticated /healthz response, the X-Yabanin-Build header and the
// "gateway starting" log line.
var buildVersion = "dev"

func healthHandler(gw *gateway, r chi.Router, l *slog.Logger) {
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Yabanin-Build", buildVersion)

		// N12-P03-T03: during drain answer not-ready immediately — no redis
		// ping, no work — so load balancers and readiness probes stop routing
		// here BEFORE the listener closes (readiness managed before stop).
		if !gw.drain.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			if err := json.NewEncoder(w).Encode(map[string]string{"status": "draining"}); err != nil {
				l.Debug("health encode error", "error", err)
			}
			return
		}

		checks := make(map[string]string)
		statusCode := 200

		if gw.rdb != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
			defer cancel()
			if err := gw.rdb.Ping(ctx).Err(); err != nil {
				checks["redis"] = "down"
				statusCode = 503
				l.Error("health check redis ping failed", "error", err)
			} else {
				checks["redis"] = "up"
			}
		} else {
			checks["redis"] = "skipped"
		}

		result := map[string]any{"status": "ok", "build": buildVersion}
		for k, v := range checks {
			result[k] = v
		}

		if statusCode != 200 {
			result["status"] = "degraded"
		}

		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			l.Debug("health encode error", "error", err)
		}
	})
}
