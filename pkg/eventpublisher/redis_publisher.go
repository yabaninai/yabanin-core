package eventpublisher

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/events"
	"github.com/reireirei/yabanin/pkg/redact"
)

var piiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(api[_-]?key|access[_-]?token|secret|authorization)"\s*:\s*"(?:[^"\\]|\\.)*(?:"|\))`),
	regexp.MustCompile(`(?i)(?:bearer|basic)\s+[A-Za-z0-9+/=]{16,}`),
	regexp.MustCompile(`(?i)"(sk|rk|pk)_(live|test|prod)_[A-Za-z0-9]{20,}"`),
	regexp.MustCompile(`(?i)"api_key"\s*:\s*"(?:[^"\\]|\\.)*"`),
	regexp.MustCompile(`(?i)"access_token"\s*:\s*"(?:[^"\\]|\\.)*"`),
}

func redactPII(s string) string {
	if s == "" {
		return s
	}
	result := s
	for _, p := range piiPatterns {
		result = p.ReplaceAllString(result, "REDACTED")
	}
	return result
}

// RedisPublisher publishes events to a Redis stream.
type RedisPublisher struct {
	RDB    *redis.Client
	Stream string

	// retention is the N02-P06 org original-retention source for the
	// PRODUCER boundary (nil = fail-closed: every org resolves OFF and the
	// upstream captures are stripped pre-XADD). Guarded by retentionMu; the
	// shared resolver semantic lives in original_retention.go — the same
	// one semantic the loggerd consumer uses at the durable-history
	// boundary.
	retentionMu sync.Mutex
	retention   *OriginalRetentionResolver
	// retentionPolicy is the N02-P06 T04 Enterprise separation seam (nil =
	// the FREE-core BooleanRetentionPolicy over `retention` governs). First
	// install wins; the boolean store wiring below never clobbers it.
	retentionPolicy RetentionPolicyResolver
}

// NewRedisPublisher publishes request-completion events to a Redis stream.
// NewRedisPublisher.
func NewRedisPublisher(rdb *redis.Client, stream string) *RedisPublisher {
	return &RedisPublisher{RDB: rdb, Stream: stream}
}

// SetOriginalRetentionStore wires the org-toggle source (N02-P06 T03/T06
// producer boundary). Optional; nil (the default) keeps every org on the
// fail-closed processed-only wire. Idempotent first-wins: re-wiring would
// silently drop the warm per-org cache, so only the first wiring sticks.
// The gateway calls this per request completion — a runtime re-wire is a
// no-op by design and can never displace an installed retention policy
// (SetRetentionPolicy, N02-P06 T04).
func (r *RedisPublisher) SetOriginalRetentionStore(s OriginalRetentionStore) {
	r.retentionMu.Lock()
	defer r.retentionMu.Unlock()
	if r.retention != nil {
		return
	}
	r.retention = NewOriginalRetentionResolver(s)
}

// SetRetentionPolicy installs a RetentionPolicyResolver (N02-P06 T04
// Enterprise separation seam). Optional — core ships none and works without
// one. While installed, the policy answers every producer-side retention
// resolution in place of the boolean toggle; first install wins (a re-install
// is a no-op, mirroring the store setter: retention semantics must never
// swap mid-flight), and a nil install is a no-op. The strict content-profile
// contract still wins over any policy: it drops captures before this
// decision is consulted.
func (r *RedisPublisher) SetRetentionPolicy(p RetentionPolicyResolver) {
	if p == nil {
		return
	}
	r.retentionMu.Lock()
	defer r.retentionMu.Unlock()
	if r.retentionPolicy != nil {
		return
	}
	r.retentionPolicy = p
}

// OriginalRetention exposes the wired boolean resolver for in-process
// producers that must apply the SAME retention resolution outside the wire
// path (the gateway's evalgate prompt persistence). Nil publisher or
// unwired store returns nil — callers must fail closed. NOTE (T04 seam):
// this is the boolean view only; when an Enterprise policy is installed the
// wire path resolves through RetentionPolicy(), and this getter keeps
// serving the boolean resolver until the in-process call sites migrate to
// the policy seam (recorded remainder).
func (r *RedisPublisher) OriginalRetention() *OriginalRetentionResolver {
	if r == nil {
		return nil
	}
	r.retentionMu.Lock()
	defer r.retentionMu.Unlock()
	return r.retention
}

// RetentionPolicy exposes the effective producer-side policy (N02-P06 T04):
// the installed resolver when one is wired, else the FREE-core boolean
// default wrapping the wired toggle store (which fails closed when the
// store is unwired). Nil-safe; never returns nil.
func (r *RedisPublisher) RetentionPolicy() RetentionPolicyResolver {
	if r == nil {
		return BooleanRetentionPolicy{}
	}
	r.retentionMu.Lock()
	policy, boolean := r.retentionPolicy, r.retention
	r.retentionMu.Unlock()
	if policy != nil {
		return policy
	}
	return BooleanRetentionPolicy{Resolver: boolean}
}

// originalRetentionEnabled resolves the toggle once per Publish through the
// retention-policy seam (installed Enterprise policy first, else the
// fail-closed boolean default). The typed event attributes ride for the
// policy (publishTS is the effective producer timestamp — the event's own
// stamp or the publish-time fallback); the boolean default ignores
// everything but the org, so the default path stays byte-identical.
// Fail-closed matrix (nil resolver, nil store, empty org, lookup error) →
// false.
func (r *RedisPublisher) originalRetentionEnabled(ctx context.Context, event *Event, publishTS time.Time) bool {
	r.retentionMu.Lock()
	policy, boolean := r.retentionPolicy, r.retention
	r.retentionMu.Unlock()
	req := RetentionPolicyRequest{OrgID: event.OrgID, EventType: event.EventType, EventTS: publishTS}
	return ResolveOriginalRetention(ctx, policy, boolean, req)
}

// Publish appends the event to the configured Redis stream. It is also the
// producer that declares the metadata-only profile (Event.ContentProfile)
// must never reach the wire with content captures, even when an upstream
// layer failed to sanitize — the captures are dropped here and the error text
// is replaced by the fixed redaction notice. Legacy events (empty or
// "legacy" declaration) publish exactly as before.
//
// N02-P06 T03/T06 producer boundary: Publish is also retention-keyed. The
// org original-retention toggle (fail-closed OFF, shared resolver in
// original_retention.go) is applied BEFORE the XADD — the durable buffer —
// so under retention OFF the raw upstream captures (upstream_payload /
// upstream_response) never enter the buffer, whatever an upstream layer
// attached to the event. ON publishes the captures byte-identically; the
// strict profile behavior is unchanged (metadata-only regardless of
// retention).
func (r *RedisPublisher) Publish(ctx context.Context, event *Event) error {
	if event == nil {
		return fmt.Errorf("eventpublisher: cannot publish nil event")
	}

	strict := StrictContentProfile(event.ContentProfile)

	// The first durable boundary is the Redis stream itself: the shared
	// structured scrubber runs before XADD so a secret never lands in Redis,
	// then the legacy regex pass covers any remaining shapes.
	payload := redactPII(redact.ScrubSecrets(event.Payload))
	errorText := redact.ScrubSecrets(event.Error)
	promptHash := event.PromptHash
	if strict {
		// The digest is computed from the raw body BEFORE the captures are
		// dropped, so both profiles hash the same request content.
		promptHash = ResolvePromptHash(event.PromptHash, event.Payload)
		payload = ""
		errorText = ""
		if event.Error != "" {
			errorText = ContentProfileRedactedError
		}
	}
	upstreamURL := redactSensitiveURL(event.UpstreamURL)

	// Producer timestamp: the gateway normally stamps the event itself; a
	// zero TS (field added after legacy producers) falls back to the publish
	// time so the consumer always receives a usable event clock.
	ts := event.TS
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}

	values := map[string]interface{}{
		"event_type":              event.EventType,
		"source":                  event.Source,
		"ts":                      ts,
		"request_id":              event.RequestID,
		"session_id":              event.SessionID,
		"payload":                 payload,
		"org_id":                  event.OrgID,
		"model_requested":         event.ModelRequested,
		"model_used":              event.ModelUsed,
		"upstream_url":            upstreamURL,
		"status_code":             event.StatusCode,
		"duration_ms":             event.DurationMs,
		"tokens_in":               event.TokensIn,
		"tokens_out":              event.TokensOut,
		"method":                  event.Method,
		"error":                   errorText,
		"cache_hit_type":          event.CacheHitType,
		"cache_similarity":        event.CacheSimilarity,
		"counterfactual_cost_usd": event.CounterfactualCostUSD,
		"estimated_cost_usd":      event.EstimatedCostUSD,
		"resale_cost_usd":         event.ResaleCostUSD,
		"tier_used":               event.TierUsed,
		"classifier_class":        event.ClassifierClass,
		"classifier_confidence":   event.ClassifierConfidence,
		"classifier_source":       event.ClassifierSource,
		"cache_read_tokens":       event.CacheReadTokens,
		"cache_creation_tokens":   event.CacheCreationTokens,
		"endpoint":                event.Endpoint,
		"usage_source":            event.UsageSource,
		"cost_status":             event.CostStatus,
		"evalgate_sampled":        event.EvalgateSampled,
		"evalgate_should_upgrade": event.EvalgateShouldUpgrade,
		"ab_group":                event.ABGroup,
		"team_id":                 event.TeamID,
		"routing_decision":        event.RoutingDecision,
		"upstream_payload":        event.UpstreamPayload,
		"upstream_response":       event.UpstreamResponse,
		// FIX-20: processed, client-facing response envelope. PROCESSED
		// content class — kept under retention OFF, dropped when strict.
		"processed_response":                   event.ProcessedResponse,
		"agent_id":                             event.AgentID,
		"task_id":                              event.TaskID,
		"reservations":                         event.Reservations,
		"termination":                          event.Termination,
		"labels":                               labelsValue(event.Labels),
		events.FieldInferenceRegion:            event.InferenceRegion,
		events.FieldRegionEvidence:             event.RegionEvidence,
		events.FieldModelOriginCountry:         event.ModelOriginCountry,
		events.FieldLogStorageRegion:           event.LogStorageRegion,
		events.FieldProviderEntityJurisdiction: event.ProviderEntityJurisdiction,
		events.FieldAttestationHash:            event.AttestationHash,
		events.FieldAttestationSignature:       event.AttestationSignature,
		events.FieldAttestationKeyID:           event.AttestationKeyID,
		"first_token_ms":                       event.FirstTokenMs,
		"attempt_count":                        event.AttemptCount,
		"retry_count":                          event.RetryCount,
		// W-BYOK-CORE: BYOK attribution (bool → "true"/"" for the string
		// stream wire, matching the omitempty JSON contract).
		"used_org_key": boolStreamValue(event.UsedOrgKey),
		// OP-8: policy-pipeline decision record (JSON array contract on
		// the Event struct).
		"policy": event.Policy,
	}
	if strict {
		// profile and the correlation digest ride instead.
		delete(values, "payload")
		delete(values, "upstream_payload")
		delete(values, "upstream_response")
		delete(values, "processed_response")
		values["content_profile"] = event.ContentProfile
		values["prompt_hash"] = promptHash
	} else if !r.originalRetentionEnabled(ctx, event, time.UnixMilli(ts)) {
		// Retention OFF (the fail-closed default: unwired store, empty org
		// or lookup error included) — the ORIGINAL captures are withheld
		// before the durable buffer write. Payload, error, digest and every
		// metadata column keep flowing; an explicit org opt-in skips this
		// branch entirely, keeping the captures byte-identical.
		// FIX-20: processed_response stays — it is the PROCESSED,
		// client-facing response class, the same retention tier as payload.
		delete(values, "upstream_payload")
		delete(values, "upstream_response")
	}

	cmd := r.RDB.XAdd(ctx, &redis.XAddArgs{
		Stream: r.Stream,
		MaxLen: 1_000_000,
		Approx: true,
		Values: values,
	})
	return cmd.Err()
}

// boolStreamValue renders a bool for the string-only Redis stream wire:
// "true" when set, "" (omitted-equivalent) when not.
func boolStreamValue(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func labelsValue(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	body, _ := json.Marshal(labels)
	return string(body)
}

// redactSensitiveURL removes credentials from URLs and redacts PII in path segments.
func redactSensitiveURL(url string) string {
	if url == "" {
		return url
	}
	// Find scheme boundary (e.g., "https://")
	schemeEnd := strings.Index(url, "://")
	if schemeEnd == -1 {
		return url
	}

	// Check for credentials in authority section
	rest := url[schemeEnd+3:]
	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		// Has credentials: keep scheme://, redact everything up to @
		beforeAt := url[:schemeEnd+3] // e.g. "https://"
		afterAt := rest[atIdx:]       // e.g. "@api.openai.com/v1"
		return beforeAt + "***REDACTED***" + afterAt
	}

	// No credentials — just strip PII from path if present
	pathStart := schemeEnd + 3
	slashInRest := strings.Index(rest, "/")
	if slashInRest == -1 {
		return url // no path to redact
	}

	path := rest[slashInRest:]
	base := url[:pathStart+slashInRest]

	for _, p := range piiPatterns {
		path = p.ReplaceAllString(path, "REDACTED")
	}

	return base + path
}
