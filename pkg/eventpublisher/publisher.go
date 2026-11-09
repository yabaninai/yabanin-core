package eventpublisher

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/config"
)

// Event represents a routing event to be published to the central stream.
type Event struct {
	EventType string `json:"event_type"`
	Source    string `json:"source"`
	// TS is the event timestamp in milliseconds since the Unix epoch,
	// captured by the PRODUCER (gateway) at request completion. The consumer
	// persists it as request_logs.created_at and uses it for period
	// attribution (team_month buckets), so delayed delivery (loggerd outage,
	// DLQ replay) cannot shift billing into the wrong period. Zero means the
	// producer did not set it — Publish stamps the publish time so every
	// event still carries a usable timestamp. Serialized as "ts".
	TS             int64  `json:"ts,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	SessionID      string `json:"session_id"`
	Payload        string `json:"payload"`
	OrgID          string `json:"org_id"`
	ModelRequested string `json:"model_requested"`
	ModelUsed      string `json:"model_used"`
	UpstreamURL    string `json:"upstream_url"`
	StatusCode     int64  `json:"status_code"`
	DurationMs     int64  `json:"duration_ms"`
	TokensIn       int64  `json:"tokens_in"`
	TokensOut      int64  `json:"tokens_out"`
	// CacheReadTokens and CacheCreationTokens come from the provider's
	// usage payload (Anthropic cache_read_input_tokens / cache_creation_input_tokens,
	// OpenAI prompt_tokens_details.cached_tokens). Zero when the provider
	// didn't report them. Populated since P3.11.
	CacheReadTokens     int64 `json:"cache_read_tokens,omitempty"`
	CacheCreationTokens int64 `json:"cache_creation_tokens,omitempty"`
	// Endpoint is the gateway route that served the request (chat.completions, ...).
	Endpoint string `json:"endpoint,omitempty"`
	// UsageSource is provider, estimated, or none.
	UsageSource string `json:"usage_source,omitempty"`
	// CostStatus is priced, unknown_price, no_usage, cache_hit, or legacy.
	CostStatus string `json:"cost_status,omitempty"`
	// EstimatedCostUSD is computed by provider.ComputeCost from the token
	// counts above and the pkg/pricing table. Zero when the model isn't in
	// the table — downstream billing MUST distinguish $0-unknown from
	// $0-free using pricing.IsKnown. Populated since P3.11.
	EstimatedCostUSD float64 `json:"estimated_cost_usd,omitempty"`
	// ResaleCostUSD is the resale price with markup applied (for reseller billing).
	// Zero when markupPricer is not wired or model is unknown.
	ResaleCostUSD float64 `json:"resale_cost_usd,omitempty" p1:"true"`
	Method        string  `json:"method"`
	Error         string  `json:"error,omitempty"`
	// CacheHitType indicates which cache layer served this request:
	// "exact" (Redis exact-key), "semantic" (pgvector ANN), or empty for misses.
	CacheHitType string `json:"cache_hit_type,omitempty" p4:"true"`
	// CacheSimilarity is the cosine similarity score on semantic hits (0..1).
	CacheSimilarity float32 `json:"cache_similarity,omitempty" p4:"true"`
	// CounterfactualCostUSD estimates what this request would have cost
	// without any cache — used for savings_usd analytics.
	CounterfactualCostUSD float64 `json:"counterfactual_cost_usd,omitempty" p4:"true"`

	// P5 classifier fields: track model routing decisions by complexity class.
	TierUsed             string  `json:"tier_used,omitempty"`             // e.g. "cheap", "smart", "turbo" from tier router
	ClassifierClass      string  `json:"classifier_class,omitempty"`      // "easy", "medium", "hard"
	ClassifierConfidence float64 `json:"classifier_confidence,omitempty"` // [0, 1] confidence of classification
	ClassifierSource     string  `json:"classifier_source,omitempty"`     // "rule_tier", "ml_v1", "cache_hit", "default"

	// v18 R1: machine-readable routing decision (compact JSON of
	// pkg/gateway.routingDecision — source, class, confidence, affinity,
	// from/to, effort, reason). Mirrors the X-Yabanin-Decision response
	// header. Populated when DecisionEventEnabled=true (default on).
	RoutingDecision string `json:"routing_decision,omitempty"`
	// UpstreamPayload is the request body ACTUALLY sent to the provider:
	// after adapter translation, model override (tier routing) and effort
	// injection. The client's original body stays in Payload, so a reviewer
	// can see exactly what changed in flight (user finding 2026-09-15).
	UpstreamPayload string `json:"upstream_payload,omitempty"`
	// UpstreamResponse is a bounded sample of the provider's response body
	// (non-stream: full translated body; stream: first bytes of the SSE
	// stream). Same PH.1 truncation policy as Payload at storage time.
	UpstreamResponse string `json:"upstream_response,omitempty"`
	// ProcessedResponse is the PROCESSED, client-facing model response
	// (FIX-20): the full text/tool-call payload exactly as the client
	// received it — post tool gate and policy, never the raw provider body
	// (that stays in UpstreamResponse). A self-describing JSON envelope
	// ({v, kind:"model_response", status, content, ...}); see
	// pkg/gateway/response_history.go. PROCESSED content class: it survives
	// original-retention OFF (like Payload, unlike the upstream captures)
	// and is dropped under the metadata-only profile.
	ProcessedResponse string `json:"processed_response,omitempty"`
	// v18 G1: agent principal that issued the request (agent_keys table),
	// empty for ordinary api_keys. Populated by the resolver (G1).
	AgentID string `json:"agent_id,omitempty"`
	// UserID is the developer who owns the personal key (RM-44). Empty for
	// org and agent keys. Never taken from a client header.
	UserID string `json:"user_id,omitempty"`
	// APIKeyID is the trusted parent key (X-API-Key-Id). For a session key
	// this is the parent, so spend stays on the key that minted the session.
	APIKeyID string `json:"api_key_id,omitempty"`
	// SessionKeyID is the trusted ybs_ id (X-Session-Key-Id). Empty for a
	// request that authenticated with the parent key itself.
	SessionKeyID string `json:"session_key_id,omitempty"`
	// v18 G2: client-supplied task tag (X-Yabanin-Task, [A-Za-z0-9._:-]{1,128}),
	// used for per-task cost analytics.
	TaskID string `json:"task_id,omitempty"`
	// Reservations carries the reserve tuples of a reservation-backed
	// request (ADR-0001 §5.3 Finalize, NEXT-18c): a JSON array of
	// {scope_kind, scope_key, period, allowance_id, bound_micro_usd}. Empty
	// for legacy (off-mode) events — the consumer treats absent as legacy.
	Reservations string `json:"reservations,omitempty"`
	// Termination is how a reserved request ended (§5.3 Finalize): one of
	// completed, client_cancel, idle_timeout, upstream_error, policy_denied.
	// Empty for legacy events.
	Termination string `json:"termination,omitempty"`
	// Labels is the effective attribution set. Empty is omitted.
	Labels map[string]string `json:"labels,omitempty"`

	// P5 evalgate fields: whether this request was sampled for LLM-as-judge.
	EvalgateSampled       bool `json:"evalgate_sampled,omitempty"`
	EvalgateShouldUpgrade bool `json:"evalgate_should_upgrade,omitempty"` // Reserved for future verdict propagation

	// P5 A/B fields: classifier experiment group assignment.
	ABGroup string `json:"ab_group,omitempty"` // "test" or "control"

	// P6.10: Team ID for team-level budget attribution.
	TeamID string `json:"team_id,omitempty"`

	// PA.5: Residency enforcement outcome for this request.
	ResidencyRegion string `json:"residency_region,omitempty"`
	ResidencyPack   string `json:"residency_pack,omitempty"`
	ResidencyRemap  string `json:"residency_remap,omitempty"`

	// PB1: Jurisdictional lineage attestation fields. Populated by
	// gateway.attachLineage (PB1.6) when LineageEnabled=true. JSON tags
	// MUST mirror pkg/events/lineage.go field-name constants.
	InferenceRegion            string `json:"inference_region,omitempty"`
	RegionEvidence             string `json:"region_evidence,omitempty"`
	ModelOriginCountry         string `json:"model_origin_country,omitempty"`
	LogStorageRegion           string `json:"log_storage_region,omitempty"`
	ProviderEntityJurisdiction string `json:"provider_entity_jurisdiction,omitempty"`
	AttestationHash            string `json:"attestation_hash,omitempty"`
	AttestationSignature       string `json:"attestation_signature,omitempty"`
	AttestationKeyID           string `json:"attestation_key_id,omitempty"`

	// Observability parity fields (Bifrost-style request tracing).
	// FirstTokenMs is the time-to-first-token for streaming responses,
	// measured from request start to the first upstream SSE byte reaching
	// this process. Zero for non-streaming requests and streams that died
	// before producing a token.
	FirstTokenMs int64 `json:"first_token_ms,omitempty"`
	// AttemptCount is the number of fallback-chain hops tried for this
	// request (1 = primary only). Repeats the chain, not intra-model
	// retries — Bifrost's attempt_trail length equivalent.
	AttemptCount int `json:"attempt_count,omitempty"`
	// RetryCount is the total number of intra-model retries (transport /
	// 429 / 5xx) consumed across all chain hops. Zero when every hop
	// succeeded on the first try.
	RetryCount int `json:"retry_count,omitempty"`
	// UsedOrgKey (W-BYOK-CORE) reports that the winning upstream hop
	// authenticated with an org credential (BYOK) rather than a per-model or
	// global gateway key. Attribution only — the event never carries the
	// credential itself. Omitted when false.
	UsedOrgKey bool `json:"used_org_key,omitempty"`
	// of the winning hop: "<first 8 chars of the credential id>:<key last-4
	// mask>", e.g. "3f2ac1b2:9c11". Empty when the hop used a per-model or
	// global key (or BYOK served via the legacy newest-first path, which has
	// no credential identity). Attribution only — never key material;
	// and ignores unknown JSON) byte-compatible.
	OrgCredentialRef string `json:"org_credential_ref,omitempty"`

	// Policy (OP-8) is the policy-pipeline decision record for this request:
	// a JSON ARRAY of decision objects, one per executed policy, in
	// execution (attachment-priority) order:
	//
	//	[{"policy_id":"<uuid>","name":"sovereign-default","version":2,
	//	  "mode":"enforce|shadow","verdict":"deny|mask|flag|allow",
	//	  "findings":[{"step":"scan.pii","category":"innsnils",
	//	               "severity":"high","action":"deny"}],
	//	  "duration_ms":3}]
	//
	// THE CONTRACT (OP-9 decisions table): parse as a JSON array; absent or
	// empty = the pipeline did not evaluate this request (kill-switch off,
	// no matching policy, or a pre-OP-8 event). Findings carry categories,
	// severities and actions only — NEVER payload content.
	//
	// CORE-TRACE-05 (additive, envelope v1): each decision object may carry
	// the evaluation envelope — envelope_version, hook, rule_namespace,
	// matched, effective_action, applied_action, steps[] (bounded, with
	// skip reasons), steps_total/steps_truncated, findings_total/
	// findings_truncated and trace_completeness (full|partial|absent).
	// Readers MUST stay tolerant: envelope fields are optional on every
	// object (pre-envelope producers never emit them), and the findings
	// array keeps the exact legacy element contract. Object fields carry
	// categories/severities/actions only — still never payload content.
	Policy string `json:"policy,omitempty"`

	// that governed this event on the producer side: "metadata-only" when
	// strict filtering applied, "legacy" when full captures rode the event.
	// carried verbatim; a PRESENT but unrecognized value fails closed to
	// strict filtering downstream (config.EffectiveLogContentProfile).
	ContentProfile string `json:"content_profile,omitempty"`
	// SHA-256 of strings.TrimSpace(Event.Payload), lower-case hex (see
	// PromptDigest). Computed from the raw body BEFORE sanitization so the
	// same request hashes identically in both profiles. Omitted when there
	// is no body and no valid producer-supplied digest.
	PromptHash string `json:"prompt_hash,omitempty"`
}

// ContentProfileRedactedError is the fixed text that replaces a failed
// request's error string under the metadata-only profile: it carries the
// failure semantics without any upstream error body content.
const ContentProfileRedactedError = "request failed; details omitted by content profile"

// PromptDigest computes the prompt digest: SHA-256 over the trimmed
// payload, lower-case hex. A blank or whitespace-only payload has no
// digest — it returns "".
func PromptDigest(payload string) string {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

// isValidPromptHash reports whether v is exactly the digest shape the wire
// contract allows: 64 lower-case hex characters (the PromptDigest output
// form). Anything else is recomputed from the body or dropped — never
// forwarded, so the wire hash stays canonically formatted.
func isValidPromptHash(v string) bool {
	if len(v) != sha256.Size*2 || v != strings.ToLower(v) {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

// ResolvePromptHash applies the digest rule for strict events: a valid
// producer-supplied digest is preserved byte-for-byte; otherwise the digest
// is computed from the event payload. No body and no valid supplied digest →
// "" (the hash is omitted on the wire).
func ResolvePromptHash(supplied, payload string) string {
	if isValidPromptHash(supplied) {
		return supplied
	}
	return PromptDigest(payload)
}

// StrictContentProfile reports whether the declared wire profile requires
// metadata-only filtering. Empty and "legacy" keep the permissive legacy
// behavior; "metadata-only" and every unrecognized value fail closed to
// strict — only an exact known declaration may widen retention.
func StrictContentProfile(profile string) bool {
	return profile != "" && profile != string(config.LogContentProfileLegacy)
}

// ComputeDurationMs returns the duration between start and end in milliseconds.
func ComputeDurationMs(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}
