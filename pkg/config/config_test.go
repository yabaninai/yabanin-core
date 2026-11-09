package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDefaultGateway(t *testing.T) {
	cfg := DefaultGateway()
	if cfg.ListenAddr != ":8082" {
		t.Errorf("expected default ListenAddr :8082, got %q", cfg.ListenAddr)
	}
	if cfg.AdminListen != ":9090" {
		t.Errorf("expected default AdminListen :9090, got %q", cfg.AdminListen)
	}
	if cfg.Provider != "localhost:8081" {
		t.Errorf("expected default Provider localhost:8081, got %q", cfg.Provider)
	}
	if cfg.RedisAddr != "localhost:6379" {
		t.Errorf("expected default RedisAddr localhost:6379, got %q", cfg.RedisAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel info, got %q", cfg.LogLevel)
	}
	if cfg.AuthMode != "header" {
		t.Errorf("expected default AuthMode header, got %q", cfg.AuthMode)
	}
	if cfg.ZAICodingEnabled {
		t.Error("Z.AI Coding Plan must be off by default")
	}
	if cfg.ZAICodingBaseURL != "" {
		t.Errorf("expected empty ZAICodingBaseURL, got %q", cfg.ZAICodingBaseURL)
	}
	if cfg.FallbackModel != "smart" {
		t.Errorf("expected default FallbackModel smart, got %q", cfg.FallbackModel)
	}
}

func TestGatewayRequestTimeout(t *testing.T) {
	// S02 stand run 2026-09-14: reasoning models legitimately exceed 60s;
	// the per-request LLM proxy timeout must be overridable without
	// changing the default for deployments that set nothing.
	cfg := DefaultGateway()
	if cfg.RequestTimeout != "60s" {
		t.Errorf("expected default RequestTimeout 60s, got %q", cfg.RequestTimeout)
	}
	t.Setenv("YABANIN_GATEWAY_REQUEST_TIMEOUT", "5m")
	cfg = DefaultGateway()
	if cfg.RequestTimeout != "5m" {
		t.Errorf("expected env override 5m, got %q", cfg.RequestTimeout)
	}
}

func TestGatewayStreamTimeouts(t *testing.T) {
	// Streaming ceilings: /v1/ streams outlive the 60s JSON default, so they
	// carry their own max-duration ceiling and an idle watchdog. Both must
	// default sanely and stay env-overridable.
	cfg := DefaultGateway()
	if cfg.StreamMaxDuration != "30m" {
		t.Errorf("expected default StreamMaxDuration 30m, got %q", cfg.StreamMaxDuration)
	}
	if cfg.StreamIdleTimeout != "5m" {
		t.Errorf("expected default StreamIdleTimeout 5m, got %q", cfg.StreamIdleTimeout)
	}
	t.Setenv("YABANIN_GATEWAY_STREAM_MAX_DURATION", "2h")
	t.Setenv("YABANIN_GATEWAY_STREAM_IDLE_TIMEOUT", "30s")
	cfg = DefaultGateway()
	if cfg.StreamMaxDuration != "2h" {
		t.Errorf("expected env override 2h, got %q", cfg.StreamMaxDuration)
	}
	if cfg.StreamIdleTimeout != "30s" {
		t.Errorf("expected env override 30s, got %q", cfg.StreamIdleTimeout)
	}
}

func TestGatewayStreamUsageProviders(t *testing.T) {
	// RM-03: default list covers every OpenAI-compatible provider; env
	// narrows it; an all-blank value falls back to the default (usage
	// collection must not be disabled by a typo).
	wantDefault := []string{"openai", "openai-compat", "vllm", "ollama", "llamacpp", "mistral", "zai-coding"}
	cfg := DefaultGateway()
	if !reflect.DeepEqual(cfg.StreamUsageProviders, wantDefault) {
		t.Errorf("expected default StreamUsageProviders %v, got %v", wantDefault, cfg.StreamUsageProviders)
	}

	t.Setenv("YABANIN_STREAM_USAGE_PROVIDERS", "openai, zai-coding")
	cfg = DefaultGateway()
	if !reflect.DeepEqual(cfg.StreamUsageProviders, []string{"openai", "zai-coding"}) {
		t.Errorf("expected env override [openai zai-coding], got %v", cfg.StreamUsageProviders)
	}

	t.Setenv("YABANIN_STREAM_USAGE_PROVIDERS", " , ")
	cfg = DefaultGateway()
	if !reflect.DeepEqual(cfg.StreamUsageProviders, wantDefault) {
		t.Errorf("all-blank value must fall back to defaults, got %v", cfg.StreamUsageProviders)
	}
}

// TestStreamUsageProvidersOrDefault pins the programmatic-config contract of
// StreamUsageProvidersOrDefault: an unset (nil) or all-empty provider list
// falls back to the default OpenAI-compatible set — the same documented
// unset-fallback the env parse applies — because the gateway treats an empty
// set as "never inject stream_options.include_usage", which silently zeroed
// usage on streamed hops for programmatically assembled boots (N07-P01-T06
// defect 1, RM-03, 2026-11-03 acceptance record). An explicit non-empty
// list wins verbatim (that is how an operator narrows the set).
func TestStreamUsageProvidersOrDefault(t *testing.T) {
	wantDefault := []string{"openai", "openai-compat", "vllm", "ollama", "llamacpp", "mistral", "zai-coding"}

	for name, in := range map[string][]string{
		"nil (programmatic unset)": nil,
		"empty slice":              {},
		"all-blank entries":        {"  ", ""},
	} {
		if got := StreamUsageProvidersOrDefault(in); !reflect.DeepEqual(got, wantDefault) {
			t.Errorf("%s: expected defaults %v, got %v", name, wantDefault, got)
		}
	}

	if got := StreamUsageProvidersOrDefault([]string{"openai", "  "}); !reflect.DeepEqual(got, []string{"openai"}) {
		t.Errorf("blank entries must be skipped, got %v", got)
	}
	if got := StreamUsageProvidersOrDefault([]string{"openai", "zai-coding"}); !reflect.DeepEqual(got, []string{"openai", "zai-coding"}) {
		t.Errorf("explicit non-empty list must win verbatim, got %v", got)
	}
}

func TestGatewayUnknownModelPolicy(t *testing.T) {
	t.Setenv("YABANIN_UNKNOWN_MODEL_POLICY", "")
	if got := DefaultGateway().UnknownModelPolicy; got != "fallback" {
		t.Fatalf("default policy %q", got)
	}
	t.Setenv("YABANIN_UNKNOWN_MODEL_POLICY", "reject")
	if got := DefaultGateway().UnknownModelPolicy; got != "reject" {
		t.Fatalf("reject policy %q", got)
	}
	t.Setenv("YABANIN_UNKNOWN_MODEL_POLICY", "nope")
	if got := DefaultGateway().UnknownModelPolicy; got != "fallback" {
		t.Fatalf("unknown policy %q", got)
	}
}

func TestGateway_Validate_Valid(t *testing.T) {
	cfg := DefaultGateway()
	cfg.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
	cfg.CacheHMACSecret = "test-secret"
	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected no error for valid config, got: %v", err)
	}
}

func TestGateway_Validate_MissingListenAddr(t *testing.T) {
	cfg := Gateway{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing ListenAddr, got nil")
	}
}

func TestGateway_Validate_MissingProvider(t *testing.T) {
	cfg := Gateway{ListenAddr: ":8082"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing Provider, got nil")
	}
}

func TestDefaultLoggerd(t *testing.T) {
	cfg := DefaultLoggerd()
	if cfg.ListenAddr != ":8085" {
		t.Errorf("expected default ListenAddr :8085, got %q", cfg.ListenAddr)
	}
	if cfg.StreamName != "events:queue" {
		t.Errorf("expected default StreamName events:queue, got %q", cfg.StreamName)
	}
}

func TestLoggerd_Validate_Valid(t *testing.T) {
	cfg := DefaultLoggerd()
	cfg.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected no error for valid config, got: %v", err)
	}
}

func TestDefaultAdminConfig(t *testing.T) {
	cfg := DefaultAdminConfig()
	if cfg.ListenAddr != ":8086" {
		t.Errorf("expected default ListenAddr :8086, got %q", cfg.ListenAddr)
	}
	if cfg.AdminDomain != "localhost" {
		t.Errorf("expected default AdminDomain localhost, got %q", cfg.AdminDomain)
	}
}

func TestAdminConfig_Validate_MissingListenAddr(t *testing.T) {
	cfg := AdminAdmin{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing ListenAddr, got nil")
	}
}

func TestAdminConfig_Validate_MissingSessionKey(t *testing.T) {
	cfg := AdminAdmin{ListenAddr: ":8086"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing SessionKey, got nil")
	}
}

func TestDefaultAll(t *testing.T) {
	all := DefaultAll()
	if all.Gateway.ListenAddr != ":8082" {
		t.Errorf("expected Gateway ListenAddr :8082, got %q", all.Gateway.ListenAddr)
	}
	if all.Loggerd.ListenAddr != ":8085" {
		t.Errorf("expected Loggerd ListenAddr :8085, got %q", all.Loggerd.ListenAddr)
	}
	if all.Admin.ListenAddr != ":8086" {
		t.Errorf("expected Admin ListenAddr :8086, got %q", all.Admin.ListenAddr)
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path should not error: %v", err)
	}
	if cfg.Gateway.ListenAddr != ":8082" {
		t.Errorf("expected default ListenAddr :8082, got %q", cfg.Gateway.ListenAddr)
	}
}

// builds its config with Load("") — env-only — and passes
// cfg.Gateway.MCPAllowedUpstreams to the MCP registry CRUD (services/run/
// admin.go SetMCPStore). The env var must therefore survive the empty-path
// load, and the SAME parsed list feeds the gateway proxy (one list on both
// paths); unset keeps it nil (fail-closed registration).
func TestLoad_EmptyPathMCPAllowedUpstreamsEnv(t *testing.T) {
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "github.com, *.example.com")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path should not error: %v", err)
	}
	want := []string{"github.com", "*.example.com"}
	if len(cfg.Gateway.MCPAllowedUpstreams) != len(want) {
		t.Fatalf("MCPAllowedUpstreams = %v, want %v", cfg.Gateway.MCPAllowedUpstreams, want)
	}
	for i := range want {
		if cfg.Gateway.MCPAllowedUpstreams[i] != want[i] {
			t.Fatalf("MCPAllowedUpstreams = %v, want %v", cfg.Gateway.MCPAllowedUpstreams, want)
		}
	}

	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load with empty path should not error: %v", err)
	}
	if cfg.Gateway.MCPAllowedUpstreams != nil {
		t.Errorf("MCPAllowedUpstreams = %v, want nil when env is empty (fail-closed)", cfg.Gateway.MCPAllowedUpstreams)
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(tmpFile, []byte("{{invalid yaml:::"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(tmpFile)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	yamlContent := `
gateway:
  listen_address: ":9999"
  provider: "custom-provider:5000"
  redis_addr: "redis://myredis:6379"
loggerd:
  stream_name: "custom:queue"
admin:
   listen_address: ":9997"
   session_key: "my-secret-key"
 `
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load should not error for valid YAML: %v", err)
	}
	if cfg.Gateway.ListenAddr != ":9999" {
		t.Errorf("expected Gateway ListenAddr :9999, got %q", cfg.Gateway.ListenAddr)
	}
	if cfg.Gateway.Provider != "custom-provider:5000" {
		t.Errorf("expected Gateway Provider custom-provider:5000, got %q", cfg.Gateway.Provider)
	}
	if cfg.Loggerd.StreamName != "custom:queue" {
		t.Errorf("expected Loggerd StreamName custom:queue, got %q", cfg.Loggerd.StreamName)
	}
	if cfg.Admin.ListenAddr != ":9997" {
		t.Errorf("expected Admin ListenAddr :9997, got %q", cfg.Admin.ListenAddr)
	}
	if cfg.Gateway.RedisAddr != "redis://myredis:6379" {
		t.Errorf("expected RedisAddr redis://myredis:6379, got %q", cfg.Gateway.RedisAddr)
	}
}

// facet structs (GatewayServer/Egress/Routing/Accounting/Compliance/
// every key at the flat gateway: level — must keep loading byte-for-byte.
// This test is the back-compatibility net for that regrouping: it exercises
// at least one key from every facet.
func TestLoad_LegacyFlatGatewayYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	// config.yaml). No nested groups under gateway:.
	yamlContent := `
gateway:
  # GatewayServer facet (process/network)
  listen_address: ":9100"
  admin_listen: ":9200"
  redis_addr: "legacy-redis:6379"
  pg_uri: "postgres://legacy:5432/db"
  log_level: "warn"
  log_format: "json"
  auth_mode: "strict"
  api_key: "legacy-api-key"
  fallback_api_key: "legacy-fallback-key"
  event_stream: "legacy:events"
  read_timeout: "16s"
  write_timeout: "17s"
  idle_timeout: "61s"
  request_timeout: "61s"
  stream_max_duration: "31m"
  stream_idle_timeout: "6m"
  stream_usage_providers: ["openai", "legacy-compat"]
  trusted_proxies: ["10.0.0.1"]
  allowed_origins: ["https://legacy.example.com"]
  org_resolver_ttl: 301
  deploy_mode: "saas"
  # GatewayEgress facet (outbound)
  provider: "legacy-provider:5000"
  allowed_upstreams: ["api.legacy.example.com"]
  mcp_gateway_enabled: true
  mcp_allowed_upstreams: ["mcp.legacy.example.com"]
  a2a_gateway_enabled: true
  a2a_allowed_upstreams: ["a2a.legacy.example.com"]
  zai_coding_enabled: true
  zai_coding_base_url: "https://zai.legacy.example.com"
  circuit_enabled: true
  circuit_failure_threshold: 11
  circuit_success_threshold: 3
  circuit_open_timeout: "31s"
  circuit_window: "31s"
  # GatewayRouting facet (model selection)
  fallback_model: "legacy-model"
  unknown_model_policy: "reject"
  responses_native_providers: ["legacy-native"]
  classifier_service_url: "http://legacy-classifier:8080"
  classifier_circuit_enabled: true
  classifier_circuit_threshold: 4
  classifier_circuit_timeout: "31s"
  classifier_ab_enabled: true
  effort_routing_enabled: true
  effort_models: "o3,o4-mini"
  session_affinity_enabled: true
  session_affinity_ttl: "11m"
  session_affinity_min_cache_tokens: 513
  session_affinity_backend: "redis"
  time_routing_enabled: true
  time_cheap_window: "23:00-06:00"
  decision_header_enabled: true
  decision_event_enabled: true
  home_region: "US"
  region: "us"
  # GatewayAccounting facet (metering)
  default_markup_pct: 16.5
  credits_grace_cents: -101
  credits_cache_ttl: "31s"
  reservations: "shadow"
  task_token_budget: 500000
  session_token_budget: 200000
  cache_enabled: true
  cache_pg_exact_lookup: true
  cache_hmac_secret: "legacy-hmac"
  # GatewayCompliance facet (governance)
  guard_mode: "log"
  lineage_enabled: true
  kms_provider: "awskms"
  kms_key_id: "legacy-key-id"
  encryption_key: "legacy-encryption-key"
  task_tag: "legacy-task"
  # GatewayObservability facet (telemetry)
  metrics_enabled: true
  metrics_bearer_key: "legacy-metrics-bearer"
  otel_tracing_endpoint: "localhost:4317"
  otel_tracing_sample_rate: 0.2
  evalgate_url: "http://legacy-evalgate:8080/v1"
  evalgate_api_key: "legacy-evalgate-key"
  evalgate_model: "legacy-judge"
  evalgate_sample_rate: 0.06
  debug_pprof: true
  shadow:
    enabled: true
    model: "legacy-shadow-model"
    upstream_url: "http://legacy-shadow:8080"
    api_key: "legacy-shadow-key"
    sample_rate: 0.2
    timeout: "20s"
    max_concurrent: 2
    daily_budget_usd: 5
`
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("legacy flat config.yaml must keep loading: %v", err)
	}
	gw := cfg.Gateway

	// GatewayServer
	if gw.ListenAddr != ":9100" || gw.AdminListen != ":9200" || gw.RedisAddr != "legacy-redis:6379" ||
		gw.PGURI != "postgres://legacy:5432/db" || gw.LogLevel != "warn" || gw.LogFormat != "json" ||
		gw.AuthMode != "strict" || gw.APIKey != "legacy-api-key" || gw.FallbackKey != "legacy-fallback-key" ||
		gw.EventStream != "legacy:events" || gw.ReadTimeout != "16s" || gw.WriteTimeout != "17s" ||
		gw.IdleTimeout != "61s" || gw.RequestTimeout != "61s" || gw.StreamMaxDuration != "31m" ||
		gw.StreamIdleTimeout != "6m" || gw.OrgResolverTTL != 301 || gw.DeployMode != "saas" {
		t.Fatalf("server facet keys lost: %+v", gw.GatewayServer)
	}
	if len(gw.StreamUsageProviders) != 2 || gw.StreamUsageProviders[1] != "legacy-compat" ||
		len(gw.TrustedProxies) != 1 || gw.TrustedProxies[0] != "10.0.0.1" ||
		len(gw.AllowedOrigins) != 1 || gw.AllowedOrigins[0] != "https://legacy.example.com" {
		t.Fatalf("server facet list keys lost: %+v", gw.GatewayServer)
	}
	// GatewayEgress
	if gw.Provider != "legacy-provider:5000" || !gw.MCPGatewayEnabled || !gw.A2AGatewayEnabled ||
		!gw.ZAICodingEnabled || gw.ZAICodingBaseURL != "https://zai.legacy.example.com" ||
		!gw.CircuitEnabled || gw.CircuitFailureThreshold != 11 || gw.CircuitSuccessThreshold != 3 ||
		gw.CircuitOpenTimeout != "31s" || gw.CircuitWindow != "31s" {
		t.Fatalf("egress facet keys lost: %+v", gw.GatewayEgress)
	}
	if len(gw.AllowedUpstreams) != 1 || gw.AllowedUpstreams[0] != "api.legacy.example.com" ||
		len(gw.MCPAllowedUpstreams) != 1 || gw.MCPAllowedUpstreams[0] != "mcp.legacy.example.com" ||
		len(gw.A2AAllowedUpstreams) != 1 || gw.A2AAllowedUpstreams[0] != "a2a.legacy.example.com" {
		t.Fatalf("egress facet list keys lost: %+v", gw.GatewayEgress)
	}
	// GatewayRouting
	if gw.FallbackModel != "legacy-model" || gw.UnknownModelPolicy != "reject" ||
		gw.ClassifierServiceURL != "http://legacy-classifier:8080" || !gw.ClassifierCircuitEnabled ||
		gw.ClassifierCircuitThreshold != 4 || gw.ClassifierCircuitTimeout != "31s" ||
		!gw.ClassifierABEnabled || !gw.EffortRoutingEnabled || gw.EffortModels != "o3,o4-mini" ||
		!gw.SessionAffinityEnabled || gw.SessionAffinityTTL != "11m" ||
		gw.SessionAffinityMinCacheTokens != 513 || gw.SessionAffinityBackend != "redis" ||
		!gw.TimeRoutingEnabled || gw.TimeCheapWindow != "23:00-06:00" ||
		!gw.DecisionHeaderEnabled || !gw.DecisionEventEnabled || gw.HomeRegion != "US" || gw.Region != "us" {
		t.Fatalf("routing facet keys lost: %+v", gw.GatewayRouting)
	}
	if len(gw.ResponsesNativeProviders) != 1 || gw.ResponsesNativeProviders[0] != "legacy-native" {
		t.Fatalf("routing facet list keys lost: %+v", gw.GatewayRouting)
	}
	// GatewayAccounting
	if gw.DefaultMarkupPct != 16.5 || gw.CreditsGraceCents != -101 || gw.CreditsCacheTTL != "31s" ||
		gw.Reservations != "shadow" || gw.TaskTokenBudget != 500000 || gw.SessionTokenBudget != 200000 ||
		!gw.CacheEnabled || !gw.CachePGExactLookup || gw.CacheHMACSecret != "legacy-hmac" {
		t.Fatalf("accounting facet keys lost: %+v", gw.GatewayAccounting)
	}
	// GatewayCompliance
	if gw.GuardMode != "log" || !gw.LineageEnabled || gw.KMSProvider != "awskms" ||
		gw.KMSKeyID != "legacy-key-id" || gw.EncryptionKey != "legacy-encryption-key" ||
		gw.TaskTag != "legacy-task" {
		t.Fatalf("compliance facet keys lost: %+v", gw.GatewayCompliance)
	}
	// GatewayObservability
	if !gw.MetricsEnabled || gw.MetricsBearerKey != "legacy-metrics-bearer" ||
		gw.OTELTracingEndpoint != "localhost:4317" || gw.OTELTracingSample != 0.2 ||
		gw.EvalgateURL != "http://legacy-evalgate:8080/v1" || gw.EvalgateAPIKey != "legacy-evalgate-key" ||
		gw.EvalgateModel != "legacy-judge" || gw.EvalgateSampleRate != 0.06 || !gw.DebugPprof {
		t.Fatalf("observability facet keys lost: %+v", gw.GatewayObservability)
	}
	if !gw.Shadow.Enabled || gw.Shadow.Model != "legacy-shadow-model" ||
		gw.Shadow.UpstreamURL != "http://legacy-shadow:8080" || gw.Shadow.APIKey != "legacy-shadow-key" ||
		gw.Shadow.SampleRate != 0.2 || gw.Shadow.Timeout != "20s" ||
		gw.Shadow.MaxConcurrent != 2 || gw.Shadow.DailyBudgetUSD != 5 {
		t.Fatalf("shadow section lost: %+v", gw.Shadow)
	}
}

// TestGatewayYAMLKeysRemainFlat guards the other half of the contract:
// marshaling a Gateway must emit the same flat top-level keys (no facet
// sub-objects), so a config written by a new build reads like an old one.
func TestGatewayYAMLKeysRemainFlat(t *testing.T) {
	g := DefaultGateway()
	g.ListenAddr = ":8099"
	g.AuthMode = "header"
	g.APIKey = "k"
	g.EventStream = "events:q"
	g.Provider = "p:8081"
	g.CachePGExactLookup = true
	g.MCPGatewayEnabled = true
	g.CircuitEnabled = true
	g.SessionAffinityEnabled = true
	g.DefaultMarkupPct = 15
	g.TaskTokenBudget = 10
	g.TaskTag = "t"
	g.GuardMode = "log"
	g.MetricsBearerKey = "m"
	g.ClassifierServiceURL = "http://c"
	g.EvalgateURL = "http://e"
	g.LineageEnabled = true
	g.HomeRegion = "SG"
	g.Region = "sg"
	g.DeployMode = "saas"
	g.A2AGatewayEnabled = true
	g.TimeRoutingEnabled = true
	g.EffortRoutingEnabled = true
	g.ZAICodingEnabled = true
	g.DecisionHeaderEnabled = true
	g.DecisionEventEnabled = true
	g.FallbackKey = "f"
	g.FallbackModel = "smart"
	g.OTELTracingEndpoint = "o:4317"
	out, err := yaml.Marshal(g)
	if err != nil {
		t.Fatalf("marshal Gateway: %v", err)
	}
	var probe map[string]any
	if err := yaml.Unmarshal(out, &probe); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	for _, key := range []string{
		"listen_address", "admin_listen", "provider", "redis_addr", "pg_uri",
		"log_level", "auth_mode", "api_key", "fallback_api_key", "fallback_model",
		"event_stream", "read_timeout", "write_timeout", "idle_timeout",
		"request_timeout", "stream_max_duration", "stream_idle_timeout",
		"cache_hmac_secret", "encryption_key", "circuit_enabled",
		"metrics_bearer_key", "otel_tracing_endpoint", "classifier_service_url",
		"evalgate_url", "lineage_enabled", "guard_mode", "home_region", "region",
		"kms_provider", "deploy_mode", "default_markup_pct", "credits_cache_ttl",
		"session_affinity_enabled", "task_token_budget", "task_tag",
		"time_routing_enabled", "org_resolver_ttl", "effort_routing_enabled",
		"zai_coding_enabled", "decision_header_enabled", "decision_event_enabled",
		"mcp_gateway_enabled", "a2a_gateway_enabled",
	} {
		if _, ok := probe[key]; !ok {
			t.Errorf("flat key %q missing from marshaled gateway section", key)
		}
	}
	for _, nested := range []string{
		"gatewayserver", "gatewayegress", "gatewayrouting", "gatewayaccounting",
		"gatewaycompliance", "gatewayobservability",
	} {
		if _, ok := probe[nested]; ok {
			t.Errorf("gateway section must stay flat: unexpected nested key %q (lost yaml inline?)", nested)
		}
	}
}

func TestLoad_AdminSessionKeyValidation(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	yamlContent := `
admin:
  listen_address: ":8086"
 `
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load should not error: %v", err)
	}
	err = cfg.Admin.Validate()
	if err == nil {
		t.Fatal("expected validation error for missing session_key")
	}
}

func TestEnv_FileFallback(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	if err := os.WriteFile(secretFile, []byte("  secret-from-file\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_SECRET_FILE", secretFile)

	result := env("TEST_SECRET", "fallback")
	if result != "secret-from-file" {
		t.Errorf("expected 'secret-from-file', got %q", result)
	}

	// Direct env var takes precedence over _FILE
	t.Setenv("TEST_SECRET", "direct-value")
	result = env("TEST_SECRET", "fallback")
	if result != "direct-value" {
		t.Errorf("expected 'direct-value' (direct env should take precedence), got %q", result)
	}

	// When neither exists, use fallback
	_ = os.Unsetenv("TEST_SECRET")
	_ = os.Unsetenv("TEST_SECRET_FILE")
	result = env("NONEXISTENT_TEST_VAR", "fallback-default")
	if result != "fallback-default" {
		t.Errorf("expected 'fallback-default', got %q", result)
	}

	// _FILE with unreadable path falls back to default
	t.Setenv("TEST_SECRET_FILE", "/nonexistent/path/secret")
	result = env("TEST_SECRET", "fallback-ok")
	if result != "fallback-ok" {
		t.Errorf("expected 'fallback-ok' when file is unreadable, got %q", result)
	}
}

func TestParseA2AAllowedUpstreams(t *testing.T) {
	t.Setenv("YABANIN_A2A_ALLOWED_UPSTREAMS", "a2a.example.com, *.partners.test, ")
	got := parseA2AAllowedUpstreams()
	// Empty entries are skipped (same posture as the MCP list); domain
	// VALIDITY itself is enforced by ssrf.ParseDomain at allow-list build
	// time, not by the parser.
	want := []string{"a2a.example.com", "*.partners.test"}
	if len(got) != len(want) {
		t.Fatalf("entries: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseA2AAllowedUpstreams_EmptyIsNil(t *testing.T) {
	t.Setenv("YABANIN_A2A_ALLOWED_UPSTREAMS", "")
	if got := parseA2AAllowedUpstreams(); got != nil {
		t.Fatalf("unset list must stay nil (fail-closed), got %v", got)
	}
}

func TestDefaultAdminConfig_OIDCFields(t *testing.T) {
	t.Setenv("YABANIN_ADMIN_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("YABANIN_ADMIN_OIDC_CLIENT_ID", "cid")
	t.Setenv("YABANIN_ADMIN_OIDC_CLIENT_SECRET", "sec")
	t.Setenv("YABANIN_ADMIN_OIDC_REDIRECT_URL", "https://adm/auth/oidc/callback")
	cfg := DefaultAdminConfig()
	if cfg.OIDCIssuer != "https://idp.example.com" || cfg.OIDCClientID != "cid" ||
		cfg.OIDCClientSecret != "sec" || cfg.OIDCRedirectURL != "https://adm/auth/oidc/callback" {
		t.Fatalf("oidc env wiring: %+v", cfg)
	}
	// Default (no env): all four empty → SSO stays off.
	t.Setenv("YABANIN_ADMIN_OIDC_ISSUER", "")
	t.Setenv("YABANIN_ADMIN_OIDC_CLIENT_ID", "")
	t.Setenv("YABANIN_ADMIN_OIDC_CLIENT_SECRET", "")
	t.Setenv("YABANIN_ADMIN_OIDC_REDIRECT_URL", "")
	cfg = DefaultAdminConfig()
	if cfg.OIDCIssuer != "" || cfg.OIDCClientID != "" || cfg.OIDCClientSecret != "" || cfg.OIDCRedirectURL != "" {
		t.Fatalf("oidc defaults must be empty: %+v", cfg)
	}
}

func TestDefaultAdminConfig_PortalDefaults(t *testing.T) {
	t.Setenv("YABANIN_PORTAL_ENABLED", "")
	t.Setenv("YABANIN_PORTAL_PROVISIONING", "")
	t.Setenv("YABANIN_PORTAL_MAX_KEYS", "")
	t.Setenv("YABANIN_PORTAL_KEY_TTL_DAYS", "")
	t.Setenv("YABANIN_PORTAL_ALLOWED_DOMAINS", "")
	cfg := DefaultAdminConfig()
	if cfg.PortalEnabled || cfg.PortalProvisioning != "invite" || cfg.PortalMaxKeys != 5 || cfg.PortalKeyTTLDays != 90 {
		t.Fatalf("portal defaults: %+v", cfg)
	}
	t.Setenv("YABANIN_PORTAL_ENABLED", "true")
	t.Setenv("YABANIN_PORTAL_PROVISIONING", "domain")
	t.Setenv("YABANIN_PORTAL_ALLOWED_DOMAINS", "Example.com, acme.test")
	t.Setenv("YABANIN_PORTAL_OIDC_ISSUER", "https://idp.example.com")
	cfg = DefaultAdminConfig()
	if !cfg.PortalEnabled || cfg.PortalProvisioning != "domain" || cfg.PortalOIDCIssuer != "https://idp.example.com" {
		t.Fatalf("portal env: %+v", cfg)
	}
	if len(cfg.PortalAllowedDomains) != 2 || cfg.PortalAllowedDomains[0] != "example.com" || cfg.PortalAllowedDomains[1] != "acme.test" {
		t.Fatalf("domains: %v", cfg.PortalAllowedDomains)
	}
}

// captureEnvWarnings redirects envWarnf into a slice for the duration of the
// test and restores it afterwards.
func captureEnvWarnings(t *testing.T) *[]string {
	t.Helper()
	var msgs []string
	prev := envWarnf
	envWarnf = func(format string, args ...any) {
		msgs = append(msgs, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { envWarnf = prev })
	return &msgs
}

// Default (non-strict) mode warns on stderr and keeps the fallback — the
// historical silent default is the defect this card closes.
func TestEnvInt_MalformedWarnsWithVarName(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "")
	t.Setenv("YABANIN_TEST_THRESHOLD", "abc")
	warnings := captureEnvWarnings(t)

	d := &envDiag{}
	if got := envInt(d, "YABANIN_TEST_THRESHOLD", 10); got != 10 {
		t.Fatalf("malformed int must keep fallback 10, got %d", got)
	}
	if len(*warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %v", *warnings)
	}
	if !strings.Contains((*warnings)[0], "YABANIN_TEST_THRESHOLD") {
		t.Fatalf("warning must name the variable, got %q", (*warnings)[0])
	}
	if !strings.Contains((*warnings)[0], "abc") {
		t.Fatalf("warning must quote the value, got %q", (*warnings)[0])
	}
}

// parsing rejects a trailing-garbage value instead of reading half of it.
func TestEnvInt_TrailingGarbageRejected(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "")
	t.Setenv("YABANIN_TEST_THRESHOLD", "5x")
	warnings := captureEnvWarnings(t)

	d := &envDiag{}
	if got := envInt(d, "YABANIN_TEST_THRESHOLD", 10); got != 10 {
		t.Fatalf(`"5x" must not parse as 5; got %d`, got)
	}
	if len(*warnings) != 1 {
		t.Fatalf("expected one warning for %q, got %v", "5x", *warnings)
	}
}

func TestEnvFloat64_MalformedWarnsWithVarName(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "")
	t.Setenv("YABANIN_TEST_RATE", "abc")
	warnings := captureEnvWarnings(t)

	d := &envDiag{}
	if got := envFloat64(d, "YABANIN_TEST_RATE", 0.1); got != 0.1 {
		t.Fatalf("malformed float must keep fallback 0.1, got %v", got)
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "YABANIN_TEST_RATE") {
		t.Fatalf("warning must name the variable, got %v", *warnings)
	}
}

func TestEnvInt64_MalformedWarnsWithVarName(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "")
	t.Setenv("YABANIN_TEST_BUDGET", "12.5")
	warnings := captureEnvWarnings(t)

	d := &envDiag{}
	if got := envInt64(d, "YABANIN_TEST_BUDGET", 7); got != 7 {
		t.Fatalf("malformed int64 must keep fallback 7, got %d", got)
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "YABANIN_TEST_BUDGET") {
		t.Fatalf("warning must name the variable, got %v", *warnings)
	}
}

// "1"/case-insensitive "true" are true, and every other non-empty value
// ("0", "false", "yes", "no", untrimmed, garbage) is false, never the
// fallback.
func TestEnvBool_Table(t *testing.T) {
	cases := []struct {
		name  string
		set   bool
		value string
		fb    bool
		want  bool
	}{
		{"unset falls back to true", false, "", true, true},
		{"unset falls back to false", false, "", false, false},
		{"empty falls back to true", true, "", true, true},
		{"empty falls back to false", true, "", false, false},
		{"1 is true despite false fallback", true, "1", false, true},
		{"lowercase true", true, "true", false, true},
		{"uppercase TRUE", true, "TRUE", false, true},
		{"mixed-case True", true, "True", false, true},
		{"0 is false despite true fallback", true, "0", true, false},
		{"lowercase false", true, "false", true, false},
		{"yes is not true", true, "yes", true, false},
		{"no is false despite true fallback", true, "no", true, false},
		{"garbage is false despite true fallback", true, "garbage", true, false},
		{"untrimmed leading space is garbage", true, " true", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("YABANIN_TEST_BOOL", tc.value)
			} else {
				unsetEnv(t, "YABANIN_TEST_BOOL")
			}

			if got := envBool("YABANIN_TEST_BOOL", tc.fb); got != tc.want {
				t.Fatalf("envBool(key, %v) with value %q (set=%v) must be %v, got %v",
					tc.fb, tc.value, tc.set, tc.want, got)
			}
		})
	}
}

// resolves silently to false and never warns.
func TestEnvBool_StrictModeUninvolved(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "1")
	t.Setenv("YABANIN_TEST_BOOL", "yes")
	warnings := captureEnvWarnings(t)

	if envBool("YABANIN_TEST_BOOL", true) {
		t.Fatal(`"yes" must be false in strict mode too`)
	}
	if len(*warnings) != 0 {
		t.Fatalf("envBool must never warn, got %v", *warnings)
	}
}

// load error that names the variable — CI fails closed.
func TestLoad_StrictMalformedIntFails(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "1")
	t.Setenv("YABANIN_CIRCUIT_FAILURE_THRESHOLD", "abc")
	warnings := captureEnvWarnings(t)

	_, err := Load("")
	if err == nil {
		t.Fatal("strict mode must fail the load on a malformed int")
	}
	if !strings.Contains(err.Error(), "YABANIN_CIRCUIT_FAILURE_THRESHOLD") {
		t.Fatalf("error must name the variable, got %q", err.Error())
	}
	if len(*warnings) != 0 {
		t.Fatalf("strict mode must not warn, got %v", *warnings)
	}
}

func TestLoad_StrictMalformedFloatFails(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "1")
	t.Setenv("YABANIN_OTEL_SAMPLE_RATE", "abc")

	_, err := Load("")
	if err == nil {
		t.Fatal("strict mode must fail the load on a malformed float")
	}
	if !strings.Contains(err.Error(), "YABANIN_OTEL_SAMPLE_RATE") {
		t.Fatalf("error must name the variable, got %q", err.Error())
	}
}

// succeeds, fallback value is used, warning names the variable.
func TestLoad_NonStrictWarnsAndDefaults(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "0")
	t.Setenv("YABANIN_CIRCUIT_FAILURE_THRESHOLD", "abc")
	warnings := captureEnvWarnings(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("non-strict load must succeed, got %v", err)
	}
	if cfg.Gateway.CircuitFailureThreshold != 10 {
		t.Fatalf("non-strict mode must keep default 10, got %d", cfg.Gateway.CircuitFailureThreshold)
	}
	found := false
	for _, w := range *warnings {
		if strings.Contains(w, "YABANIN_CIRCUIT_FAILURE_THRESHOLD") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warning must name the variable, got %v", *warnings)
	}
}

// valid configs keep loading.
func TestLoad_StrictValidEnvPasses(t *testing.T) {
	t.Setenv("YABANIN_CONFIG_STRICT", "1")
	t.Setenv("YABANIN_CIRCUIT_FAILURE_THRESHOLD", "20")
	t.Setenv("YABANIN_OTEL_SAMPLE_RATE", "0.5")
	t.Setenv("YABANIN_CREDITS_GRACE_CENTS", "-100")

	if _, err := Load(""); err != nil {
		t.Fatalf("strict load must pass on valid env, got %v", err)
	}
}

// Validate with the field (and env var) named instead of silently degrading
// to a zero duration at the usage site.
func TestGateway_Validate_DurationGarbage(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Gateway)
		field  string
	}{
		{"read_timeout", func(g *Gateway) { g.ReadTimeout = "abc" }, "read_timeout"},
		{"write_timeout", func(g *Gateway) { g.WriteTimeout = "15sec" }, "write_timeout"},
		{"idle_timeout", func(g *Gateway) { g.IdleTimeout = "soon" }, "idle_timeout"},
		{"request_timeout", func(g *Gateway) { g.RequestTimeout = "abc" }, "request_timeout"},
		{"stream_max_duration", func(g *Gateway) { g.StreamMaxDuration = "30min" }, "stream_max_duration"},
		{"stream_idle_timeout", func(g *Gateway) { g.StreamIdleTimeout = "5" }, "stream_idle_timeout"},
		{"circuit_open_timeout", func(g *Gateway) { g.CircuitOpenTimeout = "abc" }, "circuit_open_timeout"},
		{"circuit_window", func(g *Gateway) { g.CircuitWindow = "abc" }, "circuit_window"},
		{"classifier_circuit_timeout", func(g *Gateway) { g.ClassifierCircuitTimeout = "abc" }, "classifier_circuit_timeout"},
		{"credits_cache_ttl", func(g *Gateway) { g.CreditsCacheTTL = "abc" }, "credits_cache_ttl"},
		{"session_affinity_ttl", func(g *Gateway) { g.SessionAffinityTTL = "ten minutes" }, "session_affinity_ttl"},
		{"shadow.timeout", func(g *Gateway) { g.Shadow.Timeout = "abc" }, "shadow.timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := DefaultGateway()
			g.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
			g.CacheHMACSecret = "test-secret"
			tc.mutate(&g)
			err := g.Validate()
			if err == nil {
				t.Fatalf("%s=%q must fail Validate", tc.field, "garbage")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error must name the field %s, got %q", tc.field, err.Error())
			}
		})
	}
}

func TestGateway_Validate_DurationValid(t *testing.T) {
	g := DefaultGateway()
	g.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
	g.CacheHMACSecret = "test-secret"
	if err := g.Validate(); err != nil {
		t.Fatalf("default durations must validate, got %v", err)
	}
	g.Shadow.Timeout = "45s"
	g.SessionAffinityTTL = "2h"
	if err := g.Validate(); err != nil {
		t.Fatalf("valid custom durations must validate, got %v", err)
	}
}

func TestLoggerd_Validate_LeaderTTLGarbage(t *testing.T) {
	ld := DefaultLoggerd()
	ld.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
	if err := ld.Validate(); err != nil {
		t.Fatalf("default loggerd config must validate, got %v", err)
	}
	ld.LeaderLockTTL = "abc"
	err := ld.Validate()
	if err == nil {
		t.Fatal("garbage leader_lock_ttl must fail Validate")
	}
	if !strings.Contains(err.Error(), "leader_lock_ttl") || !strings.Contains(err.Error(), "YABANIN_LOGGERD_LEADER_TTL") {
		t.Fatalf("error must name field and env var, got %q", err.Error())
	}
}

func TestGatewayIsOnprem(t *testing.T) {
	cases := []struct {
		name string
		gw   Gateway
		want bool
	}{
		{"deploy_mode onprem", Gateway{DeployMode: DeployModeOnPrem}, true},
		{"region onprem", Gateway{Region: "onprem"}, true},
		{"file kms without regions", Gateway{KMSProvider: "file"}, true},
		{"file kms with regions", Gateway{KMSProvider: "file", Regions: RegionMap{"eu": {}}}, false},
		{"cloud", Gateway{DeployMode: DeployModeSaaS, Region: "eu", KMSProvider: "gcp", Regions: RegionMap{"eu": {}}}, false},
		{"empty", Gateway{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.gw.IsOnprem(); got != tc.want {
				t.Errorf("IsOnprem() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGatewayEmbedder(t *testing.T) {
	t.Run("cache disabled returns zero config", func(t *testing.T) {
		resetEmbedderEnv(t)
		gw := Gateway{CacheEnabled: false}
		if got := gw.Embedder(); got != (EmbedderConfig{}) {
			t.Errorf("Embedder() = %+v, want zero config", got)
		}
	})
	t.Run("cache enabled reads env", func(t *testing.T) {
		resetEmbedderEnv(t)
		t.Setenv("YABANIN_EMBEDDER_BASE_URL", "http://bge:6006")
		t.Setenv("YABANIN_EMBEDDER_TIMEOUT", "45")
		got := Gateway{CacheEnabled: true}.Embedder()
		if !got.Enabled {
			t.Error("Enabled = false, want true when CacheEnabled")
		}
		if got.BaseURL != "http://bge:6006" || got.Timeout != 45 || got.Endpoint != "openai" {
			t.Errorf("Embedder() = %+v", got)
		}
	})
}

func TestShadowTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout string
		want    time.Duration
	}{
		{"valid", "45s", 45 * time.Second},
		{"unset keeps default", "", 30 * time.Second},
		{"garbage falls back", "soon", 30 * time.Second},
		{"non-positive falls back", "0", 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Shadow{Timeout: tc.timeout}).ShadowTimeout(); got != tc.want {
				t.Errorf("ShadowTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTracingEnabled(t *testing.T) {
	if (Gateway{OTELTracingEndpoint: "http://otel:4317"}).TracingEnabled() != true {
		t.Error("Gateway.TracingEnabled() = false with endpoint, want true")
	}
	if (Gateway{}).TracingEnabled() != false {
		t.Error("Gateway.TracingEnabled() = true without endpoint, want false")
	}
	if (Loggerd{OTELTracingEndpoint: "http://otel:4317"}).TracingEnabled() != true {
		t.Error("Loggerd.TracingEnabled() = false with endpoint, want true")
	}
	if (Loggerd{}).TracingEnabled() != false {
		t.Error("Loggerd.TracingEnabled() = true without endpoint, want false")
	}
	if (AdminAdmin{OTELTracingEndpoint: "http://otel:4317"}).TracingEnabled() != true {
		t.Error("AdminAdmin.TracingEnabled() = false with endpoint, want true")
	}
	if (AdminAdmin{}).TracingEnabled() != false {
		t.Error("AdminAdmin.TracingEnabled() = true without endpoint, want false")
	}
}

func TestParseGatewayCIDRs(t *testing.T) {
	unset(t, "YABANIN_GATEWAY_TRUSTED_PROXIES")
	if got := parseGatewayCIDRs(); got != nil {
		t.Errorf("parseGatewayCIDRs() = %v, want nil when unset", got)
	}
	t.Setenv("YABANIN_GATEWAY_TRUSTED_PROXIES", " 10.0.0.1 , 192.168.0.0/16 , not-an-ip ,, ")
	got := parseGatewayCIDRs()
	want := []string{"10.0.0.1", "192.168.0.0/16", "not-an-ip"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseGatewayCIDRs() = %v, want %v (invalid entries kept, caller decides)", got, want)
	}
}

func TestParseMCPAllowedUpstreams(t *testing.T) {
	unset(t, "YABANIN_MCP_ALLOWED_UPSTREAMS")
	if got := parseMCPAllowedUpstreams(); got != nil {
		t.Errorf("parseMCPAllowedUpstreams() = %v, want nil when unset", got)
	}
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", " api.example.com , *.partners.test , bad_*entry ,, ")
	got := parseMCPAllowedUpstreams()
	want := []string{"api.example.com", "*.partners.test"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseMCPAllowedUpstreams() = %v, want %v (invalid skipped)", got, want)
	}
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", " no*such*domain ")
	if got := parseMCPAllowedUpstreams(); got != nil {
		t.Errorf("parseMCPAllowedUpstreams() = %v, want nil when all invalid (fail closed)", got)
	}
}

// cache.stream_enabled (W-STCACHE) ships dark: unset keeps the streaming
// cache write path off, YABANIN_CACHE_STREAM_ENABLED=true opts a deployment in.
func TestCacheStreamEnabledKillSwitch(t *testing.T) {
	unset(t, "YABANIN_CACHE_STREAM_ENABLED")
	if DefaultGateway().CacheStreamEnabled {
		t.Error("CacheStreamEnabled = true by default, want false")
	}

	t.Setenv("YABANIN_CACHE_STREAM_ENABLED", "true")
	if !DefaultGateway().CacheStreamEnabled {
		t.Error("CacheStreamEnabled = false with YABANIN_CACHE_STREAM_ENABLED=true, want true")
	}

	t.Setenv("YABANIN_CACHE_STREAM_ENABLED", "0")
	if DefaultGateway().CacheStreamEnabled {
		t.Error("CacheStreamEnabled = true with YABANIN_CACHE_STREAM_ENABLED=0, want false")
	}
}

// YABANIN_PROVIDER_ADDR / Gateway.Provider is validated for presence only at
// the config boundary. No scheme/URL parsing happens here: the shipped
// default is schemeless ("localhost:8081"), full URLs are equally accepted,
// and a syntactically malformed URL passes Validate and surfaces later at
// upstream-client construction ("upstream config: invalid provider URL",
// pkg/upstream). The owner ratified the as-is posture (no boot-time scheme
// enforcement), so these tests pin the decided contract and catch any
// silent change of it.
func TestGatewayValidate_ProviderAddrAsIsBoundary(t *testing.T) {
	valid := func(providerAddr string) Gateway {
		g := DefaultGateway()
		g.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
		g.CacheHMACSecret = "test-secret"
		g.Provider = providerAddr
		return g
	}

	t.Run("shipped default is schemeless and accepted", func(t *testing.T) {
		t.Setenv("YABANIN_PROVIDER_ADDR", "localhost:8081")
		g := DefaultGateway()
		g.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
		g.CacheHMACSecret = "test-secret"
		if g.Provider != "localhost:8081" {
			t.Fatalf("expected the shipped default provider addr, got %q", g.Provider)
		}
		if err := g.Validate(); err != nil {
			t.Fatalf("the schemeless shipped default must keep validating (as-is per owner decision 2026-10-13): %v", err)
		}
	})

	t.Run("empty provider address is refused", func(t *testing.T) {
		err := valid("").Validate()
		if err == nil {
			t.Fatal("empty provider address must fail Validate")
		}
		if !strings.Contains(err.Error(), "provider address is required") {
			t.Fatalf("refusal must name the missing field, got %q", err.Error())
		}
	})

	t.Run("full URL accepted", func(t *testing.T) {
		if err := valid("http://127.0.0.1:8081").Validate(); err != nil {
			t.Fatalf("a scheme'd local URL must validate: %v", err)
		}
	})

	t.Run("malformed URL passes config validation (surfaces at client construction)", func(t *testing.T) {
		if err := valid("http://[::bad").Validate(); err != nil {
			t.Fatalf("as-is, Validate does not parse the provider URL (D-2 resolved as-is); unexpected error: %v", err)
		}
	})
}

// TestFairAdmissionConfig pins the RATELIMIT-FALLBACK P3 gate: the fair
// admission queue ships OFF, and the bound overrides default to 0 (= the
// library defaults) so an operator can enable the feature first and tune
// one knob at a time.
func TestFairAdmissionConfig(t *testing.T) {
	cfg := DefaultGateway()
	if cfg.FairAdmissionEnabled {
		t.Error("fair admission must be off by default")
	}
	if cfg.FairAdmissionCapacity != 0 || cfg.FairAdmissionMaxPerTenant != 0 || cfg.FairAdmissionQueueLimit != 0 {
		t.Error("bound overrides must default to 0 (= library defaults)")
	}

	t.Setenv("YABANIN_FAIR_ADMISSION", "true")
	t.Setenv("YABANIN_FAIR_ADMISSION_CAPACITY", "8")
	t.Setenv("YABANIN_FAIR_ADMISSION_MAX_PER_TENANT", "2")
	t.Setenv("YABANIN_FAIR_ADMISSION_QUEUE_LIMIT", "4")
	cfg = DefaultGateway()
	if !cfg.FairAdmissionEnabled {
		t.Error("YABANIN_FAIR_ADMISSION=true must enable the gate")
	}
	if cfg.FairAdmissionCapacity != 8 {
		t.Errorf("capacity override: got %d, want 8", cfg.FairAdmissionCapacity)
	}
	if cfg.FairAdmissionMaxPerTenant != 2 {
		t.Errorf("max-per-tenant override: got %d, want 2", cfg.FairAdmissionMaxPerTenant)
	}
	if cfg.FairAdmissionQueueLimit != 4 {
		t.Errorf("queue-limit override: got %d, want 4", cfg.FairAdmissionQueueLimit)
	}

	t.Setenv("YABANIN_FAIR_ADMISSION", "0")
	if DefaultGateway().FairAdmissionEnabled {
		t.Error("YABANIN_FAIR_ADMISSION=0 must keep the gate off")
	}
}

// TestGatewayHistoryAdmissionDefaults pins the N12-P01-T02 knob defaults
// (I40/I44): arming is an explicit deployment step (off by default), the
// empty mode resolves to reject, and the probe depth bound matches the
// loggerd producer bound (pairing pinned cross-package in the external
// test file history_probe_pairing_ext_test.go).
func TestGatewayHistoryAdmissionDefaults(t *testing.T) {
	cfg := DefaultGateway()
	if cfg.HistoryAdmissionEnabled {
		t.Error("history admission must be off by default (arming is an explicit deployment step)")
	}
	if cfg.HistoryMode != "" {
		t.Errorf("expected empty default HistoryMode (resolves to reject), got %q", cfg.HistoryMode)
	}
	if cfg.HistoryProbeMaxEntries != 500000 {
		t.Errorf("expected default HistoryProbeMaxEntries 500000 (loggerd pairing), got %d", cfg.HistoryProbeMaxEntries)
	}

	t.Setenv("YABANIN_HISTORY_ADMISSION", "true")
	t.Setenv("YABANIN_HISTORY_MODE", "allow_loss")
	t.Setenv("YABANIN_HISTORY_PROBE_MAX_ENTRIES", "12345")
	cfg = DefaultGateway()
	if !cfg.HistoryAdmissionEnabled {
		t.Error("YABANIN_HISTORY_ADMISSION=true must arm the knob")
	}
	if cfg.HistoryMode != "allow_loss" {
		t.Errorf("expected env override allow_loss, got %q", cfg.HistoryMode)
	}
	if cfg.HistoryProbeMaxEntries != 12345 {
		t.Errorf("expected env override 12345, got %d", cfg.HistoryProbeMaxEntries)
	}

	t.Setenv("YABANIN_HISTORY_ADMISSION", "0")
	if DefaultGateway().HistoryAdmissionEnabled {
		t.Error("YABANIN_HISTORY_ADMISSION=0 must keep the gate off")
	}
}

// TestGatewayValidate_HistoryAdmission pins the startup validation: a
// mistyped mode must fail deploy (not silently resolve to the
// deny-everything default), a negative depth bound is a mistake, and arming
// without Redis is unwireable — all three abort startup.
func TestGatewayValidate_HistoryAdmission(t *testing.T) {
	valid := func() Gateway {
		cfg := DefaultGateway()
		cfg.PGURI = "postgres://user:pass@localhost/db?sslmode=require"
		cfg.CacheHMACSecret = "test-secret"
		return cfg
	}

	cases := []struct {
		name    string
		mutate  func(*Gateway)
		wantErr string
	}{
		{"default off passes", func(*Gateway) {}, ""},
		{"armed with redis and reject passes", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.HistoryMode = "reject"
		}, ""},
		{"armed allow_loss passes", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.HistoryMode = "allow_loss"
		}, ""},
		{"signal-only bound 0 passes", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.HistoryProbeMaxEntries = 0
		}, ""},
		{"hyphen typo mode fails startup", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.HistoryMode = "allow-loss"
		}, "history_mode"},
		{"unknown mode value fails startup", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.HistoryMode = "enforce"
		}, "history_mode"},
		{"negative depth bound fails startup", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.HistoryProbeMaxEntries = -1
		}, "history_probe_max_entries"},
		{"armed without redis fails startup", func(g *Gateway) {
			g.HistoryAdmissionEnabled = true
			g.RedisAddr = ""
		}, "redis_addr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
