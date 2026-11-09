package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
	"gopkg.in/yaml.v3"
)

// Gateway groups the historical flat field list into facets and embeds them into
// Gateway. Embedding preserves both wire compatibility and source
// compatibility: every facet is tagged yaml:",inline", so the YAML/env keys
// loading), and promoted fields keep every historical access path such as
// cfg.PGURI or cfg.KMSProvider compiling in packages outside pkg/config.
//
// Go composite literals are the one exception — promoted fields may not
// appear in a literal — so Gateway literals must now name their facet
// (config.Gateway{GatewayServer: GatewayServer{...}}).
type Gateway struct {
	GatewayServer        `yaml:",inline"`
	GatewayEgress        `yaml:",inline"`
	GatewayRouting       `yaml:",inline"`
	GatewayAccounting    `yaml:",inline"`
	GatewayCompliance    `yaml:",inline"`
	GatewayObservability `yaml:",inline"`

	// PB3: on-prem / air-gap toggles. Zero-value = SaaS defaults (back-compat).
	Onprem Onprem `yaml:"onprem"`

	// V9: shadow-mode — mirror a sampled fraction of non-streaming traffic to a
	// candidate model for real-cost/latency comparison. Disabled by default.
	Shadow Shadow `yaml:"shadow"`
}

// GatewayServer is the process/network facet: listener addresses, backing
// stores, auth identity, HTTP timeouts, and deployment posture.
type GatewayServer struct {
	ListenAddr  string `yaml:"listen_address"`
	AdminListen string `yaml:"admin_listen"`
	RedisAddr   string `yaml:"redis_addr"`
	PGURI       string `yaml:"pg_uri"`
	LogLevel    string `yaml:"log_level"`
	LogFormat   string `yaml:"log_format"`
	AuthMode    string `yaml:"auth_mode"`
	APIKey      string `yaml:"api_key"`
	// FallbackKey is the env YABANIN_FALLBACK_KEY (yaml fallback_api_key).
	// YABANIN_FALLBACK_API_KEY is NOT read — earlier docs mentioning it were
	// wrong; only _KEY is the live name.
	FallbackKey    string `yaml:"fallback_api_key"`
	EventStream    string `yaml:"event_stream"`
	ReadTimeout    string `yaml:"read_timeout"`
	WriteTimeout   string `yaml:"write_timeout"`
	IdleTimeout    string `yaml:"idle_timeout"`
	RequestTimeout string `yaml:"request_timeout"`
	// Streaming ceilings: StreamMaxDuration is the request-timeout override
	// for /v1/ routes (SSE streams run minutes); StreamIdleTimeout is the
	// upstream-silence watchdog serveStream arms on the body. Duration
	// strings; defaults 30m / 5m.
	StreamMaxDuration string `yaml:"stream_max_duration"` // env YABANIN_GATEWAY_STREAM_MAX_DURATION
	StreamIdleTimeout string `yaml:"stream_idle_timeout"` // env YABANIN_GATEWAY_STREAM_IDLE_TIMEOUT
	// StreamUsageProviders lists provider names for which serveStream
	// injects stream_options.include_usage on the upstream request. Comma-
	// separated via YABANIN_STREAM_USAGE_PROVIDERS; default covers all
	// OpenAI-compatible providers. Anthropic is intentionally absent (RM-04).
	StreamUsageProviders []string `yaml:"stream_usage_providers"` // env YABANIN_STREAM_USAGE_PROVIDERS
	TrustedProxies       []string `yaml:"trusted_proxies"`
	// AllowedOrigins configures CORS for the gateway. Empty = no CORS (default).
	AllowedOrigins []string `yaml:"allowed_origins"`
	// S02: org-resolver cache TTL in seconds. This is the key-revocation
	// propagation bound: a revoked api_key / agent_key can keep authenticating
	// for at most this long (the cached resolve result must expire before the
	// DB is consulted again). There is no push-based invalidation; tighten this
	// value to tighten the bound. Default 300s.
	OrgResolverTTL int64 `yaml:"org_resolver_ttl"`
	// PC1.0: deployment mode — "saas" (multi-tenant cloud) or "onprem" (single-tenant air-gap).
	// Env override: YABANIN_DEPLOY_MODE. Default: saas (back-compat).
	DeployMode string `yaml:"deploy_mode"`
}

// GatewayEgress is the outbound facet: which upstream this gateway fronts,
// the SSRF allow-lists, the proxy gateways, and the upstream circuit breaker.
type GatewayEgress struct {
	Provider         string   `yaml:"provider"`
	AllowedUpstreams []string `yaml:"allowed_upstreams"`
	// MCP-02: MCP aggregator (external MCP server proxy).
	//
	// MCPGatewayEnabled mounts the /api/mcp/invoke proxy route group on the
	// gateway data plane. Default false — a deployment that sets no new env
	// var behaves exactly as before (repo-wide invariant). The admin CRUD for
	// the mcp_servers registry is always available (root-only); the proxy is
	// what the flag gates.
	//
	// MCPAllowedUpstreams is the SSRF domain allow-list for registered MCP
	// server URLs (exact or *.suffix). Empty = no domain allowed (fail-
	// closed): the proxy and the registration guard reject every host.
	MCPGatewayEnabled   bool     `yaml:"mcp_gateway_enabled"`
	MCPAllowedUpstreams []string `yaml:"mcp_allowed_upstreams"`
	// A2A-01: A2A agent-to-agent gateway (external agent registry proxy).
	//
	// A2AGatewayEnabled mounts the /api/a2a/send proxy route group on the
	// gateway data plane. Default false — same opt-in invariant as the MCP
	// gateway. The admin CRUD for the a2a_agents registry is always
	// available; the proxy is what the flag gates.
	//
	// A2AAllowedUpstreams is the SSRF domain allow-list for registered A2A
	// agent URLs. Empty = no domain allowed (fail-closed).
	A2AGatewayEnabled   bool     `yaml:"a2a_gateway_enabled"`
	A2AAllowedUpstreams []string `yaml:"a2a_allowed_upstreams"`
	// Z.AI GLM Coding Plan. Off by default until the deployment is an
	// allowed Coding Plan client. When enabled, models with provider
	// "zai-coding" are pinned to the official endpoint (or ZAICodingBaseURL
	// for tests) and never fall back to PAYG.
	ZAICodingEnabled bool   `yaml:"zai_coding_enabled"`
	ZAICodingBaseURL string `yaml:"zai_coding_base_url"`
	// Upstream HTTP timeouts. Defaults preserve the historical behavior
	// (20s response-header, 60s non-stream call); raise both for upstreams
	// with multi-minute cold starts (e.g. NVIDIA NIM: first request to a
	// cold model can take 3-5 minutes before headers arrive).
	UpstreamResponseHeaderTimeout string `yaml:"upstream_response_header_timeout"`
	UpstreamNonStreamTimeout      string `yaml:"upstream_nonstream_timeout"`
	// Circuit breaker settings for upstream requests.
	CircuitEnabled          bool   `yaml:"circuit_enabled"`
	CircuitFailureThreshold int    `yaml:"circuit_failure_threshold"`
	CircuitSuccessThreshold int    `yaml:"circuit_success_threshold"`
	CircuitOpenTimeout      string `yaml:"circuit_open_timeout"`
	CircuitWindow           string `yaml:"circuit_window"`
}

// GatewayRouting is the model-selection facet: fallbacks, the ML classifier
// suite, KV/session/time/effort routing policies, decision explainability,
// and the PB2 region/failover topology.
type GatewayRouting struct {
	FallbackModel string `yaml:"fallback_model"`
	// UnknownModelPolicy is "fallback" (default: substitute FallbackModel and
	// advertise it) or "reject" (404 model_not_found). Unknown values become
	// fallback with a startup warning.
	UnknownModelPolicy string `yaml:"unknown_model_policy"` // env YABANIN_UNKNOWN_MODEL_POLICY
	// ResponsesNativeProviders lists providers whose POST /v1/responses is
	// forwarded unchanged. Other providers, and orgs with a deny tool policy,
	// stay on the chat translation. Env YABANIN_RESPONSES_NATIVE_PROVIDERS,
	// default openai.
	ResponsesNativeProviders []string `yaml:"responses_native_providers"`
	// P5.7: ML classifier v1 service URL (e.g., http://classifier:8080). Empty disables ML.
	ClassifierServiceURL string `yaml:"classifier_service_url"`
	// P5.14: Classifier circuit breaker settings.
	ClassifierCircuitEnabled   bool   `yaml:"classifier_circuit_enabled"`
	ClassifierCircuitThreshold int    `yaml:"classifier_circuit_threshold"` // consecutive failures before open
	ClassifierCircuitTimeout   string `yaml:"classifier_circuit_timeout"`   // duration to stay open (e.g., "30s")
	// P5.12: Classifier A/B experiment.
	ClassifierABEnabled bool `yaml:"classifier_ab_enabled"` // Enable classifier A/B test assignment
	// Reasoning-effort routing (v15 E1, opt-in): inject OpenAI
	// "reasoning_effort" into per-model request bodies based on the
	// classifier class. Off by default; EffortModels is a comma-separated
	// list of lowercase model-name fragments (e.g. "o3,o4-mini,gpt-5").
	EffortRoutingEnabled bool   `yaml:"effort_routing_enabled"`
	EffortModels         string `yaml:"effort_models"`
	// KV-cache-aware routing (v15 K2): prefer the model that recently got
	// cache-read hits for this session. On by default; TTL is a duration
	// string (e.g. "10m"), MinCacheTokens is the cache-read threshold that
	// marks a model "warm" for the session.
	SessionAffinityEnabled        bool   `yaml:"session_affinity_enabled"`
	SessionAffinityTTL            string `yaml:"session_affinity_ttl"`
	SessionAffinityMinCacheTokens int    `yaml:"session_affinity_min_cache_tokens"`
	// SessionAffinityBackend selects where the sticky model per session lives:
	// "memory" (default, single replica) or "redis" (shared across N gateway
	// replicas — ENT-04 HA). "redis" requires a configured Redis; if none is
	// available it falls back to "memory" so a misconfig never disables routing.
	SessionAffinityBackend string `yaml:"session_affinity_backend"`
	// R2: opt-in time-window / batch tier downgrade (cheap-hours routing).
	// When enabled, during the cheap window a non-high-priority request is
	// routed one tier down (Medium→easy; Hard stays hard). X-Yabanin-Batch:true
	// always downgrades. Off by default.
	TimeRoutingEnabled bool   `yaml:"time_routing_enabled"`
	TimeCheapWindow    string `yaml:"time_cheap_window"` // "HH:MM-HH:MM", e.g. "22:00-07:00"
	// Routing-decision explainability (v18 R1): machine-readable answer to
	// "why this model for this request". Header X-Yabanin-Decision on the
	// wire; routing_decision field on the analytics event. Both ON by
	// default (additive, no behavior change); disable via env for
	// compatibility-sensitive deployments.
	DecisionHeaderEnabled bool `yaml:"decision_header_enabled"`
	DecisionEventEnabled  bool `yaml:"decision_event_enabled"`
	// directory of versioned agenteval run results; QualityApprovalsPath at
	// the owner-approval registry (default <results_dir>/approvals.json).
	// Only orgs with routing_mode=quality route by measured quality, and
	// only against owner-approved snapshots. Empty dir (default) = the
	// quality source stays unwired — quality routing off everywhere.
	QualityResultsDir    string `yaml:"quality_results_dir"`
	QualityApprovalsPath string `yaml:"quality_approvals_path"`
	// PB2: home region country code stamped into lineage attestations.
	HomeRegion string `yaml:"home_region"`
	// PB2: this instance's region short-name. Must match a key in Regions.
	Region string `yaml:"region"`
	// PB2: all known regions for health-check + failover. Empty = single-region.
	Regions RegionMap `yaml:"regions"`
}

// GatewayAccounting is the metering facet: reseller markup, credits/grace,
// token budgets, and the semantic-cache feature flags.
type GatewayAccounting struct {
	// Reseller billing configuration (PR1). Empty = no billing enforcement.
	DefaultMarkupPct  float64 `yaml:"default_markup_pct"`  // default resale markup % (e.g., 15.0 = 15%)
	CreditsGraceCents int64   `yaml:"credits_grace_cents"` // max overdraft in cents (e.g., -100 = -$1.00)
	CreditsCacheTTL   string  `yaml:"credits_cache_ttl"`   // balance cache TTL duration string (e.g., "30s")
	// Reservations is the deployment-wide reservations gate (ADR-0001 §9,
	// NEXT-18c): "off" (default) keeps the legacy admission bit-for-bit,
	// "shadow" accounts reservations without applying decisions, "enforce"
	// denies service when a hard scope cannot fund a request bound. The
	// per-org organizations.reservations_mode refines the mode per org and
	// is clamped to this gate (off < shadow < enforce).
	Reservations string `yaml:"reservations"` // env YABANIN_RESERVATIONS
	// G3: per-task / per-session token budgets (opt-in). Each is a token cap
	// over the 24h window; 0 = that scope is OFF (the default). Recommended
	// starting values are 500000 (task) / 200000 (session). Exceeded → 429;
	// >=80% → X-Yabanin-Budget-Warning header.
	TaskTokenBudget    int64 `yaml:"task_token_budget"`
	SessionTokenBudget int64 `yaml:"session_token_budget"`
	// CacheConfig enables semantic cache integration when all fields are set.
	CacheEnabled bool `yaml:"cache_enabled"`
	// CachePGExactLookup enables the pgvector exact-match cache lookup on
	// every Redis miss. Disabled by default: Redis is the exact layer, and
	// the pg lookup only helps after Redis data loss at the cost of a
	// Postgres round-trip per miss.
	CachePGExactLookup bool `yaml:"cache_pg_exact_lookup"`
	// CacheHMACSecret signs cache/org-resolver/rulestore entries; required
	// whenever Redis is configured (see Validate).
	CacheHMACSecret string `yaml:"cache_hmac_secret"`
	// CacheStreamEnabled gates the streaming semantic-cache path
	// (cache_stream_enabled, env YABANIN_CACHE_STREAM_ENABLED). Default
	// false: streamed deltas are only replayable when the async write can
	// assemble a full completion document, so the feature ships dark until
	// explicitly enabled per deployment.
	CacheStreamEnabled bool `yaml:"cache_stream_enabled"`
	// RATELIMIT-FALLBACK P3: FairAdmission gates the per-replica fair
	// queue in front of upstream dispatch (N09-P02 surface). Default off:
	// the legacy admission path runs bit-for-bit — no admission object is
	// built and no request sees a queue or a shed decision. The bound
	// overrides of 0 keep the library defaults (capacity 256, per-tenant
	// 64, queue 32, 2s wait timeout), so an operator can enable the
	// feature and then tune one knob at a time.
	FairAdmissionEnabled      bool `yaml:"fair_admission_enabled"`        // env YABANIN_FAIR_ADMISSION
	FairAdmissionCapacity     int  `yaml:"fair_admission_capacity"`       // env YABANIN_FAIR_ADMISSION_CAPACITY
	FairAdmissionMaxPerTenant int  `yaml:"fair_admission_max_per_tenant"` // env YABANIN_FAIR_ADMISSION_MAX_PER_TENANT
	FairAdmissionQueueLimit   int  `yaml:"fair_admission_queue_limit"`    // env YABANIN_FAIR_ADMISSION_QUEUE_LIMIT
	// HistoryAdmissionEnabled arms the durable request-history admission
	// gate (N10-P04-T03 machinery, wired in N12-P01-T02, I40/I44): the
	// gateway probes loggerd's admission signal (Redis key
	// events:history:admission:<event_stream>) and, as a second line of
	// defense, the event stream depth directly; while the durable history
	// path cannot guarantee writes, Plan refuses new requests (default
	// "reject") or serves with the loss surfaced (explicit "allow_loss").
	// Default false: the request path stays bit-for-bit and the probe
	// wiring remains an explicit deployment step per the T01 contract —
	// arming costs 1–2 Redis round-trips per request and must never happen
	// by accident. Enabling requires Redis (see Validate) and a running
	// loggerd consuming the same stream.
	HistoryAdmissionEnabled bool `yaml:"history_admission_enabled"` // env YABANIN_HISTORY_ADMISSION
	// HistoryMode selects the outage policy when the history gate is
	// armed: "" (default) and "reject" refuse new requests while durable
	// history cannot guarantee writes (I40 fail-closed); "allow_loss"
	// explicitly serves through the outage with the loss surfaced in logs
	// and the admission decision (I44 opt-in). Validate fails startup on
	// any other value — a typo must be fixed, never silently resolved to
	// the deny-everything default.
	HistoryMode string `yaml:"history_mode"` // env YABANIN_HISTORY_MODE
	// HistoryProbeMaxEntries is the stream-depth bound (entries) for the
	// admission probe's direct XLen check: at or above it the stream counts
	// as saturated (buffer_full) even when loggerd's signal key is missing
	// or expired. The default matches the loggerd consumer's
	// DefaultHistoryBufferMaxEntries (see defaultHistoryProbeMaxEntries);
	// 0 disables the depth check (signal-only probing); negative values are
	// rejected by Validate.
	HistoryProbeMaxEntries int64 `yaml:"history_probe_max_entries"` // env YABANIN_HISTORY_PROBE_MAX_ENTRIES
}

// GatewayCompliance is the governance facet: guard mode, jurisdictional
// lineage, key management/encryption, and CI task attribution.
type GatewayCompliance struct {
	// U1: pre-egress guard hooks — deterministic PII/secrets/prompt-injection
	// detectors. Mode is off|log|redact|deny; default off. Invalid values
	// resolve to off with a Warn at config build.
	GuardMode string `yaml:"guard_mode"`
	// PB1: Jurisdictional lineage attestation (Ed25519 signing).
	LineageEnabled bool `yaml:"lineage_enabled"` // When true, gateway signs per-request attestations.
	// PB2: KMS provider selection. See pkg/kms (PB2.8).
	KMSProvider string `yaml:"kms_provider"`
	KMSKeyID    string `yaml:"kms_key_id"`
	// EncryptionKey enables per-model upstream_api_key decryption (P3.2).
	// Should match the key configured for the admin service so keys written
	// by admin can be decrypted by gateway. Empty disables per-model keys.
	EncryptionKey string `yaml:"encryption_key"`
	// ADL-01: CI task tag. When set (and valid), the gateway tags every
	// request that does NOT carry its own X-Yabanin-Task header with this
	// value. This lets an agent running inside CI attribute all of its model
	// calls to the current task (the same value a `Yabanin-Task:` commit
	// trailer carries, see docs/agent-governance.md) without the client
	// having to send the header per call. Default: empty = off (zero behavior
	// change). An invalid value is ignored (the gateway logs a warning at
	// startup and behaves as if unset — the per-request header path still
	// validates its own value).
	TaskTag string `yaml:"task_tag"`
}

// GatewayObservability is the telemetry facet: metrics, OTEL tracing,
// pprof, and the Evalgate LLM-as-judge sampling.
type GatewayObservability struct {
	// MetricsEnabled enables Prometheus metrics collection and the /metrics endpoint.
	MetricsEnabled bool `yaml:"metrics_enabled"`
	// MetricsBearerKey, when set, requires "Authorization: Bearer <key>" on
	// /metrics (constant-time compare). Empty keeps the network-restriction-only mode.
	MetricsBearerKey string `yaml:"metrics_bearer_key"`
	// OTEL tracing settings. Empty endpoint disables tracing (no-op).
	OTELTracingEndpoint string  `yaml:"otel_tracing_endpoint"`
	OTELTracingSample   float64 `yaml:"otel_tracing_sample_rate"`
	// P5.9+: Evalgate LLM-as-judge configuration.
	EvalgateURL        string  `yaml:"evalgate_url"`         // Judge endpoint (e.g., http://localhost:8080/v1)
	EvalgateAPIKey     string  `yaml:"evalgate_api_key"`     // API key for judge endpoint
	EvalgateModel      string  `yaml:"evalgate_model"`       // Model to use as judge (default gpt-4o-mini)
	EvalgateSampleRate float64 `yaml:"evalgate_sample_rate"` // Fraction of low-confidence medium requests to sample (0.05 = 5%)
	// DebugPprof enables Go pprof profiling endpoints on the admin server.
	// Gated behind trusted-proxies + auth in production. Default: false.
	DebugPprof bool `yaml:"debug_pprof"`
}

// Shadow holds v9 shadow-mode configuration. See pkg/shadow and
// docs/shadow-mode.md. Every field is optional; zero value = feature off.
type Shadow struct {
	Enabled        bool    `yaml:"enabled"`          // YABANIN_SHADOW_ENABLED
	Model          string  `yaml:"model"`            // YABANIN_SHADOW_MODEL
	UpstreamURL    string  `yaml:"upstream_url"`     // YABANIN_SHADOW_UPSTREAM_URL ("" = primary upstream)
	APIKey         string  `yaml:"api_key"`          // YABANIN_SHADOW_API_KEY ("" = gateway key)
	SampleRate     float64 `yaml:"sample_rate"`      // YABANIN_SHADOW_SAMPLE_RATE (default 0.10 when enabled)
	Timeout        string  `yaml:"timeout"`          // YABANIN_SHADOW_TIMEOUT (default 30s)
	MaxConcurrent  int     `yaml:"max_concurrent"`   // YABANIN_SHADOW_MAX_CONCURRENT (default 4)
	DailyBudgetUSD float64 `yaml:"daily_budget_usd"` // YABANIN_SHADOW_DAILY_BUDGET_USD (0 = unlimited)
}

// Deploy mode constants.
const (
	DeployModeSaaS   = "saas"   // Multi-tenant cloud deployment.
	DeployModeOnPrem = "onprem" // Single-tenant air-gap deployment.
)

// Shared defaults for fields that several services read from the same env
// byte-identical to the pre-consolidation literals.
const (
	defaultRedisAddr      = "localhost:6379"
	defaultLogFormat      = "text"
	defaultOTELSampleRate = 0.1
	// defaultHistoryProbeMaxEntries is the default history_probe_max_entries
	// bound for the gateway's durable-history admission probe (N12-P01-T02).
	// It must match services/loggerd/consumer.DefaultHistoryBufferMaxEntries
	// (the producer's own durable-buffer backpressure bound): by default the
	// admission probe declares the stream saturated at the same depth the
	// loggerd gate does, so both sides agree without extra coordination.
	// config_test pins the pairing.
	defaultHistoryProbeMaxEntries = 500_000
)

// IsOnprem returns true when deploy_mode is "onprem" or all signals point to on-prem:
// region=="onprem", kms_provider=="file", or no regions configured.
func (gw Gateway) IsOnprem() bool {
	if gw.DeployMode == DeployModeOnPrem {
		return true
	}
	// Auto-detect fallback for legacy configs that don't set deploy_mode explicitly.
	if gw.Region == "onprem" || gw.KMSProvider == "file" && len(gw.Regions) == 0 {
		return true
	}
	return false
}

// Embedder returns the resolved embedding service configuration from env vars.
func (gw Gateway) Embedder() EmbedderConfig {
	if !gw.CacheEnabled {
		return EmbedderConfig{}
	}
	cfg := NewEmbedderConfig()
	cfg.Enabled = gw.CacheEnabled
	return cfg
}

// DefaultGateway returns gateway config with sensible defaults. Malformed
// numeric env values warn with the variable name and keep the fallback;
// strict enforcement (YABANIN_CONFIG_STRICT=1) happens in Load.
func DefaultGateway() Gateway {
	return defaultGateway(&envDiag{})
}

func defaultGateway(d *envDiag) Gateway {
	return Gateway{
		GatewayServer: GatewayServer{
			ListenAddr:           env("YABANIN_GATEWAY_LISTEN", ":8082"),
			AdminListen:          env("YABANIN_GATEWAY_ADMIN", ":9090"),
			RedisAddr:            env("YABANIN_REDIS_ADDR", defaultRedisAddr),
			PGURI:                env("YABANIN_PG_URI", ""),
			LogLevel:             env("YABANIN_LOG_LEVEL", "info"),
			LogFormat:            env("LOG_FORMAT", defaultLogFormat),
			AuthMode:             env("YABANIN_AUTH_MODE", "header"),
			APIKey:               env("YABANIN_API_KEY", ""),
			FallbackKey:          env("YABANIN_FALLBACK_KEY", ""),
			EventStream:          env("YABANIN_EVENT_STREAM", "events:queue"),
			ReadTimeout:          env("YABANIN_GATEWAY_READ_TIMEOUT", "15s"),
			WriteTimeout:         env("YABANIN_GATEWAY_WRITE_TIMEOUT", "15s"),
			IdleTimeout:          env("YABANIN_GATEWAY_IDLE_TIMEOUT", "60s"),
			RequestTimeout:       env("YABANIN_GATEWAY_REQUEST_TIMEOUT", "60s"),
			StreamMaxDuration:    env("YABANIN_GATEWAY_STREAM_MAX_DURATION", "30m"),
			StreamIdleTimeout:    env("YABANIN_GATEWAY_STREAM_IDLE_TIMEOUT", "5m"),
			StreamUsageProviders: parseStreamUsageProviders(),
			TrustedProxies:       parseGatewayCIDRs(),
			AllowedOrigins:       nil, // default: no CORS
			OrgResolverTTL:       envInt64(d, "YABANIN_ORG_RESOLVER_TTL", 300),
			DeployMode:           env("YABANIN_DEPLOY_MODE", DeployModeSaaS),
		},
		GatewayEgress: GatewayEgress{
			Provider:                      env("YABANIN_PROVIDER_ADDR", "localhost:8081"),
			AllowedUpstreams:              nil,
			MCPGatewayEnabled:             envBool("YABANIN_MCP_GATEWAY", false),
			MCPAllowedUpstreams:           parseMCPAllowedUpstreams(),
			A2AGatewayEnabled:             envBool("YABANIN_A2A_GATEWAY", false),
			A2AAllowedUpstreams:           parseA2AAllowedUpstreams(),
			ZAICodingEnabled:              envBool("YABANIN_ZAI_CODING_ENABLED", false),
			ZAICodingBaseURL:              env("YABANIN_ZAI_CODING_BASE_URL", ""),
			CircuitEnabled:                envBool("YABANIN_CIRCUIT_ENABLED", false),
			CircuitFailureThreshold:       envInt(d, "YABANIN_CIRCUIT_FAILURE_THRESHOLD", 10),
			CircuitSuccessThreshold:       envInt(d, "YABANIN_CIRCUIT_SUCCESS_THRESHOLD", 2),
			UpstreamResponseHeaderTimeout: env("YABANIN_UPSTREAM_RESPONSE_HEADER_TIMEOUT", "20s"),
			UpstreamNonStreamTimeout:      env("YABANIN_UPSTREAM_NONSTREAM_TIMEOUT", "60s"),
			CircuitOpenTimeout:            env("YABANIN_CIRCUIT_OPEN_TIMEOUT", "30s"),
			CircuitWindow:                 env("YABANIN_CIRCUIT_WINDOW", "30s"),
		},
		GatewayRouting: GatewayRouting{
			FallbackModel:                 env("YABANIN_FALLBACK_MODEL", "smart"),
			UnknownModelPolicy:            parseUnknownModelPolicy(),
			ResponsesNativeProviders:      parseResponsesNativeProviders(),
			ClassifierServiceURL:          env("YABANIN_CLASSIFIER_SERVICE_URL", ""),
			ClassifierCircuitEnabled:      envBool("YABANIN_CLASSIFIER_CIRCUIT_ENABLED", true),
			ClassifierCircuitThreshold:    envInt(d, "YABANIN_CLASSIFIER_CIRCUIT_THRESHOLD", 3),
			ClassifierCircuitTimeout:      env("YABANIN_CLASSIFIER_CIRCUIT_TIMEOUT", "30s"),
			ClassifierABEnabled:           envBool("YABANIN_CLASSIFIER_AB_ENABLED", false),
			EffortRoutingEnabled:          envBool("YABANIN_EFFORT_ROUTING", false),
			EffortModels:                  env("YABANIN_EFFORT_MODELS", "o3,o4-mini,gpt-5"),
			SessionAffinityEnabled:        envBool("YABANIN_SESSION_AFFINITY", true),
			SessionAffinityTTL:            env("YABANIN_SESSION_AFFINITY_TTL", "10m"),
			SessionAffinityMinCacheTokens: envInt(d, "YABANIN_SESSION_AFFINITY_MIN_TOKENS", 512),
			SessionAffinityBackend:        env("YABANIN_SESSION_AFFINITY_BACKEND", "memory"),
			TimeRoutingEnabled:            envBool("YABANIN_TIME_ROUTING", false),
			TimeCheapWindow:               env("YABANIN_TIME_CHEAP_WINDOW", "22:00-07:00"),
			DecisionHeaderEnabled:         envBool("YABANIN_DECISION_HEADER", true),
			DecisionEventEnabled:          envBool("YABANIN_DECISION_EVENT", true),
			QualityResultsDir:             env("YABANIN_QUALITY_RESULTS_DIR", ""),
			QualityApprovalsPath:          env("YABANIN_QUALITY_APPROVALS", ""),
			HomeRegion:                    env("YABANIN_HOME_REGION", "SG"),
			Region:                        env("YABANIN_REGION", "sg"),
			Regions:                       nil,
		},
		GatewayAccounting: GatewayAccounting{
			DefaultMarkupPct:          envFloat64(d, "YABANIN_DEFAULT_MARKUP_PCT", 15.0),
			CreditsGraceCents:         envInt64(d, "YABANIN_CREDITS_GRACE_CENTS", -100),
			CreditsCacheTTL:           env("YABANIN_CREDITS_CACHE_TTL", "30s"),
			Reservations:              env("YABANIN_RESERVATIONS", "off"),
			TaskTokenBudget:           envInt64(d, "YABANIN_TASK_TOKEN_BUDGET", 0),
			SessionTokenBudget:        envInt64(d, "YABANIN_SESSION_TOKEN_BUDGET", 0),
			CacheEnabled:              false,
			CachePGExactLookup:        envBool("YABANIN_CACHE_PG_EXACT_LOOKUP", false),
			CacheHMACSecret:           env("YABANIN_CACHE_HMAC_SECRET", ""),
			CacheStreamEnabled:        envBool("YABANIN_CACHE_STREAM_ENABLED", false),
			FairAdmissionEnabled:      envBool("YABANIN_FAIR_ADMISSION", false),
			FairAdmissionCapacity:     envInt(d, "YABANIN_FAIR_ADMISSION_CAPACITY", 0),
			FairAdmissionMaxPerTenant: envInt(d, "YABANIN_FAIR_ADMISSION_MAX_PER_TENANT", 0),
			FairAdmissionQueueLimit:   envInt(d, "YABANIN_FAIR_ADMISSION_QUEUE_LIMIT", 0),
			// N12-P01-T02: durable request-history admission (I40/I44).
			// Default off / reject vocabulary / producer-matching depth
			// bound — see the field docs on GatewayAccounting.
			HistoryAdmissionEnabled: envBool("YABANIN_HISTORY_ADMISSION", false),
			HistoryMode:             env("YABANIN_HISTORY_MODE", ""),
			HistoryProbeMaxEntries:  envInt64(d, "YABANIN_HISTORY_PROBE_MAX_ENTRIES", defaultHistoryProbeMaxEntries),
		},
		GatewayCompliance: GatewayCompliance{
			GuardMode:      env("YABANIN_GUARD_MODE", "off"),
			LineageEnabled: envBool("YABANIN_LINEAGE_ENABLED", false),
			KMSProvider:    env("YABANIN_KMS_PROVIDER", "local"),
			KMSKeyID:       env("YABANIN_KMS_KEY_ID", ""),
			EncryptionKey:  env("YABANIN_ENCRYPTION_KEY", ""),
			TaskTag:        env("YABANIN_TASK", ""),
		},
		GatewayObservability: GatewayObservability{
			MetricsEnabled:      false,
			MetricsBearerKey:    env("YABANIN_METRICS_BEARER_KEY", ""),
			OTELTracingEndpoint: env("YABANIN_OTEL_ENDPOINT", ""),
			OTELTracingSample:   envFloat64(d, "YABANIN_OTEL_SAMPLE_RATE", defaultOTELSampleRate),
			EvalgateURL:         env("YABANIN_EVALGATE_URL", ""),
			EvalgateAPIKey:      env("YABANIN_EVALGATE_API_KEY", ""),
			EvalgateModel:       env("YABANIN_EVALGATE_MODEL", "gpt-4o-mini"),
			EvalgateSampleRate:  envFloat64(d, "YABANIN_EVALGATE_SAMPLE_RATE", 0.05),
			DebugPprof:          envBool("YABANIN_DEBUG_PPROF", false),
		},
		Shadow: Shadow{
			Enabled:        envBool("YABANIN_SHADOW_ENABLED", false),
			Model:          env("YABANIN_SHADOW_MODEL", ""),
			UpstreamURL:    env("YABANIN_SHADOW_UPSTREAM_URL", ""),
			APIKey:         env("YABANIN_SHADOW_API_KEY", ""),
			SampleRate:     envFloat64(d, "YABANIN_SHADOW_SAMPLE_RATE", 0.10),
			Timeout:        env("YABANIN_SHADOW_TIMEOUT", "30s"),
			MaxConcurrent:  envInt(d, "YABANIN_SHADOW_MAX_CONCURRENT", 4),
			DailyBudgetUSD: envFloat64(d, "YABANIN_SHADOW_DAILY_BUDGET_USD", 0),
		},
	}
}

// ShadowTimeout parses the shadow timeout string into a duration (fallback
// 30s on parse error — a mistyped value must not disable the feature).
func (s Shadow) ShadowTimeout() time.Duration {
	d, err := time.ParseDuration(s.Timeout)
	if err != nil || d <= 0 {
		return 30 * time.Second
	}
	return d
}

// Validate checks that the required configuration fields are set.
func (gw Gateway) Validate() error {
	if gw.ListenAddr == "" {
		return fmt.Errorf("listen_address is required")
	}
	if gw.Provider == "" {
		return fmt.Errorf("provider address is required")
	}
	switch gw.AuthMode {
	case "header", "strict":
	default:
		return fmt.Errorf("auth_mode must be 'header' or 'strict', got %q", gw.AuthMode)
	}
	if gw.EventStream == "" {
		return fmt.Errorf("event_stream is required")
	}
	if gw.PGURI == "" {
		return fmt.Errorf("pg_uri is required")
	}
	if gw.RedisAddr != "" && gw.CacheHMACSecret == "" {
		return fmt.Errorf("cache_hmac_secret is required when redis is configured")
	}
	// PB2: when Regions is configured, Region must be one of its keys.
	if len(gw.Regions) > 0 {
		if gw.Region == "" {
			return fmt.Errorf("region is required when regions map is configured")
		}
		if _, ok := gw.Regions[gw.Region]; !ok {
			return fmt.Errorf("region %q not found in regions map", gw.Region)
		}
	}
	// PC1.0: validate deploy_mode if set.
	if gw.DeployMode != "" && gw.DeployMode != DeployModeSaaS && gw.DeployMode != DeployModeOnPrem {
		return fmt.Errorf("deploy_mode must be %q or %q, got %q", DeployModeSaaS, DeployModeOnPrem, gw.DeployMode)
	}
	// N12-P01-T02: the durable-history admission vocabulary is validated at
	// startup so a typo fails deploy instead of silently resolving to the
	// deny-everything reject default (budget.ResolveHistoryMode's runtime
	// contract). The empty value is the documented default and stays legal.
	switch gw.HistoryMode {
	case "", "reject", "allow_loss":
	default:
		return fmt.Errorf("history_mode must be '', 'reject' or 'allow_loss' (env YABANIN_HISTORY_MODE), got %q", gw.HistoryMode)
	}
	// Arming the history gate without Redis would leave the I40 probe
	// unwireable — the gateway wiring refuses to start on that combination,
	// and Validate rejects it up front with the operator-facing knob name.
	if gw.HistoryAdmissionEnabled && gw.RedisAddr == "" {
		return fmt.Errorf("history_admission_enabled requires redis_addr (env YABANIN_HISTORY_ADMISSION needs Redis for the loggerd admission signal)")
	}
	if gw.HistoryProbeMaxEntries < 0 {
		return fmt.Errorf("history_probe_max_entries must be >= 0 (env YABANIN_HISTORY_PROBE_MAX_ENTRIES), got %d", gw.HistoryProbeMaxEntries)
	}
	// fail Validate (startup) instead of silently degrading at the usage
	// site — the usage sites apply zero-duration fallbacks with the parse
	// error discarded.
	durations := []struct{ field, envKey, value string }{
		{"read_timeout", "YABANIN_GATEWAY_READ_TIMEOUT", gw.ReadTimeout},
		{"write_timeout", "YABANIN_GATEWAY_WRITE_TIMEOUT", gw.WriteTimeout},
		{"idle_timeout", "YABANIN_GATEWAY_IDLE_TIMEOUT", gw.IdleTimeout},
		{"request_timeout", "YABANIN_GATEWAY_REQUEST_TIMEOUT", gw.RequestTimeout},
		{"stream_max_duration", "YABANIN_GATEWAY_STREAM_MAX_DURATION", gw.StreamMaxDuration},
		{"stream_idle_timeout", "YABANIN_GATEWAY_STREAM_IDLE_TIMEOUT", gw.StreamIdleTimeout},
		{"upstream_response_header_timeout", "YABANIN_UPSTREAM_RESPONSE_HEADER_TIMEOUT", gw.UpstreamResponseHeaderTimeout},
		{"upstream_nonstream_timeout", "YABANIN_UPSTREAM_NONSTREAM_TIMEOUT", gw.UpstreamNonStreamTimeout},
		{"circuit_open_timeout", "YABANIN_CIRCUIT_OPEN_TIMEOUT", gw.CircuitOpenTimeout},
		{"circuit_window", "YABANIN_CIRCUIT_WINDOW", gw.CircuitWindow},
		{"classifier_circuit_timeout", "YABANIN_CLASSIFIER_CIRCUIT_TIMEOUT", gw.ClassifierCircuitTimeout},
		{"credits_cache_ttl", "YABANIN_CREDITS_CACHE_TTL", gw.CreditsCacheTTL},
		{"session_affinity_ttl", "YABANIN_SESSION_AFFINITY_TTL", gw.SessionAffinityTTL},
		{"shadow.timeout", "YABANIN_SHADOW_TIMEOUT", gw.Shadow.Timeout},
	}
	for _, f := range durations {
		if err := validateDurationField(f.field, f.envKey, f.value); err != nil {
			return err
		}
	}
	return nil
}

// validateDurationField rejects non-empty values that time.ParseDuration
// cannot parse, naming the YAML field and its env override. Empty keeps the
// historical zero-value tolerance (defaults always populate these fields; an
// explicit empty override lands here and is handled by the usage sites).
func validateDurationField(field, envKey, value string) error {
	if value == "" {
		return nil
	}
	if _, err := time.ParseDuration(value); err != nil {
		return fmt.Errorf("%s (env %s): invalid duration %q: %w", field, envKey, value, err)
	}
	return nil
}

// Loggerd holds configuration for the logger daemon (consumer-only).
type Loggerd struct {
	ListenAddr          string  `yaml:"listen_address"`
	StreamName          string  `yaml:"stream_name"`
	RedisAddr           string  `yaml:"redis_addr"`
	PGURI               string  `yaml:"pg_uri"`
	LogLevel            string  `yaml:"log_level"`
	LogFormat           string  `yaml:"log_format"`
	OTELTracingEndpoint string  `yaml:"otel_tracing_endpoint"`
	OTELTracingSample   float64 `yaml:"otel_tracing_sample_rate"`

	// PB2.4: central analytics endpoint for cross-region rollup shipping.
	// Empty disables replication (single-region mode).
	ReplicationEndpoint string `yaml:"replication_endpoint"`

	// ENT-04 (HA): leader election for multi-replica loggerd. When true, N
	// loggerd replicas elect a single active node (Redis lock) and only the
	// leader runs the stream consumer; the leader's lock TTL is the failover
	// window. Default false = the historical single-node behavior (the consumer
	// runs directly), so an existing deployment is unaffected until opted in.
	LeaderElection bool   `yaml:"leader_election"`
	LeaderLockTTL  string `yaml:"leader_lock_ttl"`
}

// DefaultLoggerd returns the loggerd configuration with environment defaults.
// DefaultLoggerd.
func DefaultLoggerd() Loggerd {
	return defaultLoggerd(&envDiag{})
}

func defaultLoggerd(d *envDiag) Loggerd {
	return Loggerd{
		ListenAddr:          env("YABANIN_LOGGERD_LISTEN", ":8085"),
		StreamName:          env("YABANIN_LOGGERD_STREAM", "events:queue"),
		RedisAddr:           env("YABANIN_REDIS_ADDR", defaultRedisAddr),
		PGURI:               env("YABANIN_PG_URI", ""),
		LogLevel:            env("YABANIN_LOGGERD_LOG_LEVEL", "info"),
		LogFormat:           env("LOG_FORMAT", defaultLogFormat),
		OTELTracingEndpoint: env("YABANIN_OTEL_ENDPOINT", ""),
		OTELTracingSample:   envFloat64(d, "YABANIN_OTEL_SAMPLE_RATE", defaultOTELSampleRate),
		LeaderElection:      envBool("YABANIN_LOGGERD_LEADER_ELECTION", false),
		LeaderLockTTL:       env("YABANIN_LOGGERD_LEADER_TTL", "30s"),
	}
}

// Validate checks that the required configuration fields are set.
func (ld Loggerd) Validate() error {
	if ld.PGURI == "" {
		return fmt.Errorf("pg_uri is required")
	}
	if err := validateDurationField("leader_lock_ttl", "YABANIN_LOGGERD_LEADER_TTL", ld.LeaderLockTTL); err != nil {
		return err
	}
	return nil
}

// AdminAdmin holds configuration for the admin panel service.
type AdminAdmin struct {
	ListenAddr          string  `yaml:"listen_address"`
	PGURI               string  `yaml:"pg_uri"`
	LogLevel            string  `yaml:"log_level"`
	LogFormat           string  `yaml:"log_format"`
	SessionKey          string  `yaml:"session_key"`
	AdminDomain         string  `yaml:"admin_domain"`
	EncryptionKey       string  `yaml:"encryption_key"`
	OTELTracingEndpoint string  `yaml:"otel_tracing_endpoint"`
	OTELTracingSample   float64 `yaml:"otel_tracing_sample_rate"`

	// AllowedOrigins configures CORS for the admin panel. Empty = no CORS (default).
	AllowedOrigins []string `yaml:"allowed_origins"`

	// OIDC SSO (opt-in). All three fields must be set for the SSO routes to
	// mount; anything less keeps the console on the password flow only.
	OIDCIssuer       string `yaml:"oidc_issuer"`        // e.g. https://accounts.google.com
	OIDCClientID     string `yaml:"oidc_client_id"`     //
	OIDCClientSecret string `yaml:"oidc_client_secret"` //
	OIDCRedirectURL  string `yaml:"oidc_redirect_url"`  // e.g. https://admin.example.com/auth/oidc/callback

	// Developer portal (RM-43). Off unless YABANIN_PORTAL_ENABLED is set.
	// OIDC settings are separate from the admin console tuple.
	PortalEnabled         bool     `yaml:"portal_enabled"`
	PortalOIDCIssuer      string   `yaml:"portal_oidc_issuer"`
	PortalOIDCClientID    string   `yaml:"portal_oidc_client_id"`
	PortalOIDCSecret      string   `yaml:"portal_oidc_client_secret"`
	PortalOIDCRedirectURL string   `yaml:"portal_oidc_redirect_url"`
	PortalProvisioning    string   `yaml:"portal_provisioning"` // invite | domain
	PortalAllowedDomains  []string `yaml:"portal_allowed_domains"`
	PortalDefaultOrg      string   `yaml:"portal_default_org"`
	PortalDefaultTeam     string   `yaml:"portal_default_team"`
	PortalMaxKeys         int      `yaml:"portal_max_keys"`
	PortalKeyTTLDays      int      `yaml:"portal_key_ttl_days"`
	PortalGatewayURL      string   `yaml:"portal_gateway_url"`
}

// DefaultAdminConfig returns the admin panel configuration with environment defaults.
// DefaultAdminConfig.
func DefaultAdminConfig() AdminAdmin {
	return defaultAdminConfig(&envDiag{})
}

func defaultAdminConfig(d *envDiag) AdminAdmin {
	return AdminAdmin{
		ListenAddr:            env("YABANIN_ADMIN_LISTEN", ":8086"),
		PGURI:                 env("YABANIN_PG_URI", ""),
		LogLevel:              env("YABANIN_ADMIN_LOG_LEVEL", "info"),
		LogFormat:             env("LOG_FORMAT", defaultLogFormat),
		SessionKey:            adminSessionKeyFromEnv(),
		AdminDomain:           env("YABANIN_ADMIN_DOMAIN", "localhost"),
		EncryptionKey:         env("YABANIN_ENCRYPTION_KEY", ""),
		OTELTracingEndpoint:   env("YABANIN_OTEL_ENDPOINT", ""),
		OTELTracingSample:     envFloat64(d, "YABANIN_OTEL_SAMPLE_RATE", defaultOTELSampleRate),
		AllowedOrigins:        nil, // default: no CORS
		OIDCIssuer:            env("YABANIN_ADMIN_OIDC_ISSUER", ""),
		OIDCClientID:          env("YABANIN_ADMIN_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:      env("YABANIN_ADMIN_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:       env("YABANIN_ADMIN_OIDC_REDIRECT_URL", ""),
		PortalEnabled:         envBool("YABANIN_PORTAL_ENABLED", false),
		PortalOIDCIssuer:      env("YABANIN_PORTAL_OIDC_ISSUER", ""),
		PortalOIDCClientID:    env("YABANIN_PORTAL_OIDC_CLIENT_ID", ""),
		PortalOIDCSecret:      env("YABANIN_PORTAL_OIDC_CLIENT_SECRET", ""),
		PortalOIDCRedirectURL: env("YABANIN_PORTAL_OIDC_REDIRECT_URL", ""),
		PortalProvisioning:    portalProvisioning(env("YABANIN_PORTAL_PROVISIONING", "invite")),
		PortalAllowedDomains:  splitCSV(env("YABANIN_PORTAL_ALLOWED_DOMAINS", "")),
		PortalDefaultOrg:      env("YABANIN_PORTAL_DEFAULT_ORG", ""),
		PortalDefaultTeam:     env("YABANIN_PORTAL_DEFAULT_TEAM", ""),
		PortalMaxKeys:         envInt(d, "YABANIN_PORTAL_MAX_KEYS", 5),
		PortalKeyTTLDays:      envInt(d, "YABANIN_PORTAL_KEY_TTL_DAYS", 90),
		PortalGatewayURL:      env("YABANIN_PORTAL_GATEWAY_URL", ""),
	}
}

func portalProvisioning(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "domain":
		return "domain"
	default:
		return "invite"
	}
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate checks that the required configuration fields are set.
func (aa AdminAdmin) Validate() error {
	if aa.ListenAddr == "" {
		return fmt.Errorf("listen_address is required")
	}
	if aa.PGURI == "" {
		return fmt.Errorf("pg_uri is required")
	}
	if aa.SessionKey == "" {
		return fmt.Errorf("session_key is required for HMAC cookie signing")
	}
	return nil
}

// All holds config for every service.
type All struct {
	Gateway Gateway    `yaml:"gateway"`
	Loggerd Loggerd    `yaml:"loggerd"`
	Admin   AdminAdmin `yaml:"admin"`
}

// DefaultAll returns all services with default config.
func DefaultAll() All {
	return defaultAll(&envDiag{})
}

func defaultAll(d *envDiag) All {
	return All{
		Gateway: defaultGateway(d),
		Loggerd: defaultLoggerd(d),
		Admin:   defaultAdminConfig(d),
	}
}

// parseGatewayCIDRs parses the TrustedProxies config field into a map of
// trusted IP/CIDR strings. Env: YABANIN_GATEWAY_TRUSTED_PROXIES
// (comma-separated IPs or CIDRs; entries that are neither are warned about
// and kept — the caller decides trust).
func parseGatewayCIDRs() []string {
	val := os.Getenv("YABANIN_GATEWAY_TRUSTED_PROXIES")
	if val == "" {
		return nil
	}
	var proxies []string
	for _, p := range strings.Split(val, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			proxies = append(proxies, p)
		}
	}
	// Validate all entries are valid IP or CIDR
	for _, p := range proxies {
		if _, _, err := net.ParseCIDR(p); err != nil {
			ip := net.ParseIP(p)
			if ip == nil {
				fmt.Fprintf(os.Stderr, "warning: invalid trusted proxy %q, skipping\n", p)
			}
		}
	}
	return proxies
}

// parseMCPAllowedUpstreams parses the MCP-02 SSRF domain allow-list
// (YABANIN_MCP_ALLOWED_UPSTREAMS, comma-separated exact or *.suffix domains).
// Invalid entries are skipped with a warning (same posture as
// parseGatewayCIDRs); an all-invalid list yields nil = fail-closed.
func parseMCPAllowedUpstreams() []string {
	val := os.Getenv("YABANIN_MCP_ALLOWED_UPSTREAMS")
	if val == "" {
		return nil
	}
	var out []string
	for _, d := range strings.Split(val, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, err := ssrf.ParseDomain(d); err != nil {
			fmt.Fprintf(os.Stderr, "warning: invalid mcp allowed upstream %q, skipping\n", d)
			continue
		}
		out = append(out, d)
	}
	return out
}
func parseA2AAllowedUpstreams() []string {
	val := os.Getenv("YABANIN_A2A_ALLOWED_UPSTREAMS")
	if val == "" {
		return nil
	}
	var out []string
	for _, d := range strings.Split(val, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, err := ssrf.ParseDomain(d); err != nil {
			fmt.Fprintf(os.Stderr, "warning: invalid mcp allowed upstream %q, skipping\n", d)
			continue
		}
		out = append(out, d)
	}
	return out
}

// defaultStreamUsageProviders lists the providers whose upstreams accept
// stream_options.include_usage (OpenAI-compatible). Anthropic uses its own
// SSE dialect and always reports usage in message_delta — no injection there.
var defaultStreamUsageProviders = []string{
	"openai", "openai-compat", "vllm", "ollama", "llamacpp", "mistral", "zai-coding",
}

// parseStreamUsageProviders reads YABANIN_STREAM_USAGE_PROVIDERS (comma-
// separated provider names). Empty/blank entries are skipped; an unset or
// all-empty value falls back to the default provider list above (unlike the
// SSRF allow-lists, an empty list must not silently disable usage collection).
func parseStreamUsageProviders() []string {
	val := os.Getenv("YABANIN_STREAM_USAGE_PROVIDERS")
	if val == "" {
		return defaultStreamUsageProviders
	}
	return StreamUsageProvidersOrDefault(strings.Split(val, ","))
}

// StreamUsageProvidersOrDefault applies the documented stream-usage provider
// fallback to an already-parsed provider list (the Gateway.StreamUsageProviders
// field as decoded from yaml or set programmatically). Blank entries are
// skipped; an unset (nil) or all-empty list falls back to the default
// OpenAI-compatible provider set — the same contract as the
// YABANIN_STREAM_USAGE_PROVIDERS env parse: an empty list must not silently
// disable usage collection (RM-03). An explicit non-empty list wins verbatim.
//
// config.Load already applies this via parseStreamUsageProviders; boots that
// assemble a Gateway struct programmatically MUST apply it too — the gateway
// treats an empty provider set as "never inject stream_options.include_usage"
// and then strips nothing, so usage (tokens, cost, budgets) silently zeroes
// out on streamed hops (N07-P01-T06 defect 1, 2026-11-03 acceptance record).
// The returned slice aliases the package default when the fallback applies;
// treat it as read-only.
func StreamUsageProvidersOrDefault(providers []string) []string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaultStreamUsageProviders
	}
	return out
}

func parseResponsesNativeProviders() []string {
	val := env("YABANIN_RESPONSES_NATIVE_PROVIDERS", "openai")
	var out []string
	for _, p := range strings.Split(val, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseUnknownModelPolicy reads YABANIN_UNKNOWN_MODEL_POLICY.
// Empty and "fallback" keep the historical substitute-and-continue behaviour.
// "reject" fails the request. Any other value warns and falls back.
func parseUnknownModelPolicy() string {
	val := strings.ToLower(strings.TrimSpace(os.Getenv("YABANIN_UNKNOWN_MODEL_POLICY")))
	switch val {
	case "", "fallback":
		return "fallback"
	case "reject":
		return "reject"
	default:
		fmt.Fprintf(os.Stderr, "warning: unknown YABANIN_UNKNOWN_MODEL_POLICY %q, using fallback\n", val)
		return "fallback"
	}
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	// Support _FILE suffix for Docker secrets and Kubernetes secrets
	fileKey := key + "_FILE"
	if filePath, ok := os.LookupEnv(fileKey); ok && filePath != "" {
		//nolint:gosec // G304: path comes from the operator's own env (_FILE docker-secret convention)
		if data, err := os.ReadFile(filePath); err == nil {
			return string(bytes.TrimSpace(data))
		}
	}
	return fallback
}

func adminSessionKeyFromEnv() string {
	if key := os.Getenv("YABANIN_ADMIN_SESSION_SECRET"); key != "" {
		return key
	}
	return env("YABANIN_SESSION_KEY", "")
}

// envBool reads a boolean env variable. The truth table is a frozen
//
//	value              result
//	unset or ""        fallback
//	"1"                true
//	"true" (any case)  true — "true", "TRUE", "True", …
//	anything else      false — "0", "false", "yes", "no", " true", garbage
//
// Notably "0" and every other non-empty value resolve to false — not to
// the fallback — so a default of true is kept only by leaving the variable
// unset or empty. Values are not trimmed and there is no envDiag hook:
// envBool never warns and YABANIN_CONFIG_STRICT does not change this
// behavior; a mistyped boolean silently picks false.
func envBool(key string, fallback bool) bool {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	return strings.EqualFold(v, "true") || v == "1"
}

// envWarnf reports a malformed environment value on stderr. Package var so
// tests can capture warnings.
var envWarnf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// envDiag collects malformed environment values found while the default
// configuration is assembled. Non-strict mode warns (always naming the
// variable) and keeps the fallback. Strict mode — YABANIN_CONFIG_STRICT=1,
// intended for CI — records every finding; Load turns them into a load
// error so a mistyped value fails the boot instead of degrading silently.
type envDiag struct {
	strict   bool
	problems []string
}

// bad records a malformed value for key. kind names the expected shape
// ("integer", "float"). The variable name is part of the message in both
// modes.
func (d *envDiag) bad(key, value, kind string) {
	if d == nil {
		return
	}
	if !d.strict {
		envWarnf("warning: %s has invalid %s value %q; using default\n", key, kind, value)
		return
	}
	d.problems = append(d.problems, fmt.Sprintf("%s has invalid %s value %q", key, kind, value))
}

// err returns the strict-mode load error (nil otherwise).
func (d *envDiag) err() error {
	if d == nil || !d.strict || len(d.problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid environment configuration (YABANIN_CONFIG_STRICT=1): %s",
		strings.Join(d.problems, "; "))
}

// strictEnv reports whether YABANIN_CONFIG_STRICT=1 requests fail-closed
// parsing: malformed numeric env values fail Load instead of warning and
// keeping the default. Default (unset or not true/1) preserves the
// historical warn+default behavior.
func strictEnv() bool {
	v := strings.TrimSpace(env("YABANIN_CONFIG_STRICT", ""))
	return v == "1" || strings.EqualFold(v, "true")
}

func envInt(d *envDiag, key string, fallback int) int {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		d.bad(key, v, "integer")
		return fallback
	}
	return n
}

func envFloat64(d *envDiag, key string, fallback float64) float64 {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		d.bad(key, v, "float")
		return fallback
	}
	return f
}

func envInt64(d *envDiag, key string, fallback int64) int64 {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		d.bad(key, v, "integer")
		return fallback
	}
	return n
}

// TracingEnabled returns true when an OTEL endpoint has been configured.
// When false, tracing should be treated as no-op.
func (gw Gateway) TracingEnabled() bool { return gw.OTELTracingEndpoint != "" }

// TracingEnabled returns true when an OTEL endpoint has been configured.
// When false, tracing should be treated as no-op.
func (ld Loggerd) TracingEnabled() bool { return ld.OTELTracingEndpoint != "" }

// TracingEnabled returns true when an OTEL endpoint has been configured.
// When false, tracing should be treated as no-op.
func (aa AdminAdmin) TracingEnabled() bool { return aa.OTELTracingEndpoint != "" }

// Load reads a YAML config file and merges with defaults.
// If path is empty, returns DefaultAll().
// With YABANIN_CONFIG_STRICT=1 (CI), a malformed numeric env value fails the
// load instead of warning and keeping the default.
func Load(path string) (All, error) {
	d := &envDiag{strict: strictEnv()}
	cfg := defaultAll(d)
	if path == "" {
		if err := d.err(); err != nil {
			return All{}, err
		}
		return cfg, nil
	}

	//nolint:gosec // G304: path comes from the operator's config flag, not from request input
	data, err := os.ReadFile(path)
	if err != nil {
		return All{}, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return All{}, fmt.Errorf("parse config file: %w", err)
	}

	if err := d.err(); err != nil {
		return All{}, err
	}
	return cfg, nil
}
