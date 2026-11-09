package events

// Payload is a plain struct equivalent to gen.EventPayload (protobuf).
// It replaces the proto-generated type for consumer deserialization of
// request-completed events from Redis streams.
type Payload struct {
	EventType      string `json:"event_type"`
	Source         string `json:"source"`
	RequestID      string `json:"request_id,omitempty"`
	SessionID      string `json:"session_id"`
	Payload        string `json:"payload,omitempty"`
	OrgID          string `json:"org_id"`
	ModelRequested string `json:"model_requested"`
	ModelUsed      string `json:"model_used"`
	UpstreamURL    string `json:"upstream_url"`
	StatusCode     int64  `json:"status_code,omitempty"`
	DurationMs     int64  `json:"duration_ms"`
	TokensIn       int64  `json:"tokens_in"`
	TokensOut      int64  `json:"tokens_out"`
	Method         string `json:"method"`
	Error          string `json:"error"`
	// Cache fields (P4)
	CacheHitType          string  `json:"cache_hit_type,omitempty"`
	CacheSimilarity       float32 `json:"cache_similarity,omitempty"`
	CounterfactualCostUSD float64 `json:"counterfactual_cost_usd,omitempty"`
	EstimatedCostUSD      float64 `json:"estimated_cost_usd,omitempty"`
	CacheReadTokens       int64   `json:"cache_read_tokens,omitempty"`
	CacheCreationTokens   int64   `json:"cache_creation_tokens,omitempty"`
	// P5 classifier fields
	TierUsed             string  `json:"tier_used,omitempty"`
	ClassifierClass      string  `json:"classifier_class,omitempty"`
	ClassifierConfidence float64 `json:"classifier_confidence,omitempty"`
	ClassifierSource     string  `json:"classifier_source,omitempty"`
	// P5 evalgate fields
	EvalgateSampled       bool `json:"evalgate_sampled,omitempty"`
	EvalgateShouldUpgrade bool `json:"evalgate_should_upgrade,omitempty"`
	// P5 A/B fields
	ABGroup string `json:"ab_group,omitempty"`
	// PA.5: residency enforcement outcome
	ResidencyRegion string `json:"residency_region,omitempty"`
	ResidencyPack   string `json:"residency_pack,omitempty"`
	ResidencyRemap  string `json:"residency_remap,omitempty"`

	// PB1 jurisdictional lineage fields (mirror eventpub.Event json tags).
	InferenceRegion            string `json:"inference_region,omitempty"`
	RegionEvidence             string `json:"region_evidence,omitempty"`
	ModelOriginCountry         string `json:"model_origin_country,omitempty"`
	LogStorageRegion           string `json:"log_storage_region,omitempty"`
	ProviderEntityJurisdiction string `json:"provider_entity_jurisdiction,omitempty"`
	AttestationHash            string `json:"attestation_hash,omitempty"`
	AttestationSignature       string `json:"attestation_signature,omitempty"`
	AttestationKeyID           string `json:"attestation_key_id,omitempty"`

	// Observability parity fields (Bifrost-style request tracing).
	// FirstTokenMs: time-to-first-token for streaming responses (0 when the
	// request was non-streaming or died before the first token).
	FirstTokenMs int64 `json:"first_token_ms,omitempty"`
	// AttemptCount: number of fallback-chain hops (1 = primary only).
	AttemptCount int `json:"attempt_count,omitempty"`
	// RetryCount: intra-model retries (transport/429/5xx) across all hops.
	RetryCount int `json:"retry_count,omitempty"`
}

// GetEventType returns the requested eventtype record.
func (p *Payload) GetEventType() string {
	if p == nil {
		return ""
	}
	return p.EventType
}

// GetSource returns the requested source record.
func (p *Payload) GetSource() string {
	if p == nil {
		return ""
	}
	return p.Source
}

// GetSessionID returns the requested sessionid record.
func (p *Payload) GetSessionID() string {
	if p == nil {
		return ""
	}
	return p.SessionID
}

// GetPayload returns the raw event payload bytes as a string.
func (p *Payload) GetPayload() string {
	if p == nil {
		return ""
	}
	return p.Payload
}

// GetOrgID returns the requested orgid record.
func (p *Payload) GetOrgID() string {
	if p == nil {
		return ""
	}
	return p.OrgID
}

// GetModelRequested returns the requested modelrequested record.
func (p *Payload) GetModelRequested() string {
	if p == nil {
		return ""
	}
	return p.ModelRequested
}

// GetModelUsed returns the requested modelused record.
func (p *Payload) GetModelUsed() string {
	if p == nil {
		return ""
	}
	return p.ModelUsed
}

// GetUpstreamURL returns the requested upstreamurl record.
func (p *Payload) GetUpstreamURL() string {
	if p == nil {
		return ""
	}
	return p.UpstreamURL
}

// GetStatusCode returns the HTTP status code from the response.
func (p *Payload) GetStatusCode() int64 {
	if p == nil {
		return 0
	}
	return p.StatusCode
}

// GetRequestID returns the unique request identifier for tracing and deduplication.
func (p *Payload) GetRequestID() string {
	if p == nil {
		return ""
	}
	return p.RequestID
}

// GetDurationMs returns the requested durationms record.
func (p *Payload) GetDurationMs() int64 {
	if p == nil {
		return 0
	}
	return p.DurationMs
}

// GetTokensIn returns the requested tokensin record.
func (p *Payload) GetTokensIn() int64 {
	if p == nil {
		return 0
	}
	return p.TokensIn
}

// GetTokensOut returns the requested tokensout record.
func (p *Payload) GetTokensOut() int64 {
	if p == nil {
		return 0
	}
	return p.TokensOut
}

// GetMethod returns the requested method record.
func (p *Payload) GetMethod() string {
	if p == nil {
		return ""
	}
	return p.Method
}

// GetError returns the requested error record.
func (p *Payload) GetError() string {
	if p == nil {
		return ""
	}
	return p.Error
}

// GetCacheHitType returns the cache layer that served this request.
func (p *Payload) GetCacheHitType() string {
	if p == nil {
		return ""
	}
	return p.CacheHitType
}

// GetCacheSimilarity returns the cosine similarity on semantic hits.
func (p *Payload) GetCacheSimilarity() float32 {
	if p == nil {
		return 0
	}
	return p.CacheSimilarity
}

// GetCounterfactualCostUSD estimates cost without cache.
func (p *Payload) GetCounterfactualCostUSD() float64 {
	if p == nil {
		return 0
	}
	return p.CounterfactualCostUSD
}

// GetEstimatedCostUSD returns the estimated cost in USD.
func (p *Payload) GetEstimatedCostUSD() float64 {
	if p == nil {
		return 0
	}
	return p.EstimatedCostUSD
}

// GetCacheReadTokens returns cache-read token count from provider usage.
func (p *Payload) GetCacheReadTokens() int64 {
	if p == nil {
		return 0
	}
	return p.CacheReadTokens
}

// GetCacheCreationTokens returns cache-creation token count from provider usage.
func (p *Payload) GetCacheCreationTokens() int64 {
	if p == nil {
		return 0
	}
	return p.CacheCreationTokens
}

// GetTierUsed returns the model name selected by the tier router.
func (p *Payload) GetTierUsed() string {
	if p == nil {
		return ""
	}
	return p.TierUsed
}

// GetClassifierClass returns the complexity class (easy/medium/hard).
func (p *Payload) GetClassifierClass() string {
	if p == nil {
		return ""
	}
	return p.ClassifierClass
}

// GetClassifierConfidence returns the classification confidence score [0, 1].
func (p *Payload) GetClassifierConfidence() float64 {
	if p == nil {
		return 0
	}
	return p.ClassifierConfidence
}

// GetClassifierSource returns which classifier produced the result.
func (p *Payload) GetClassifierSource() string {
	if p == nil {
		return ""
	}
	return p.ClassifierSource
}

// GetEvalgateSampled returns whether this request was sampled by evalgate.
func (p *Payload) GetEvalgateSampled() bool {
	if p == nil {
		return false
	}
	return p.EvalgateSampled
}

// GetEvalgateShouldUpgrade returns the judge verdict for this request.
func (p *Payload) GetEvalgateShouldUpgrade() bool {
	if p == nil {
		return false
	}
	return p.EvalgateShouldUpgrade
}

// GetABGroup returns the A/B test group ("test" or "control").
func (p *Payload) GetABGroup() string {
	if p == nil {
		return ""
	}
	return p.ABGroup
}

// --- PB1 lineage getters ---

// GetInferenceRegion returns the ISO-3166-1 alpha-2 country where inference ran.
func (p *Payload) GetInferenceRegion() string {
	if p == nil {
		return ""
	}
	return p.InferenceRegion
}

// GetRegionEvidence returns the evidence tier of the inference_region claim:
// "provider_attested" | "endpoint_pinned" | "header_observed" |
// "provider_declared". Empty on legacy events recorded before the field.
func (p *Payload) GetRegionEvidence() string {
	if p == nil {
		return ""
	}
	return p.RegionEvidence
}

// GetModelOriginCountry returns the upstream model vendor's corp-HQ country.
func (p *Payload) GetModelOriginCountry() string {
	if p == nil {
		return ""
	}
	return p.ModelOriginCountry
}

// GetLogStorageRegion returns the home region of this deployment.
func (p *Payload) GetLogStorageRegion() string {
	if p == nil {
		return ""
	}
	return p.LogStorageRegion
}

// GetProviderEntityJurisdiction returns the legal-entity country of the provider.
func (p *Payload) GetProviderEntityJurisdiction() string {
	if p == nil {
		return ""
	}
	return p.ProviderEntityJurisdiction
}

// GetAttestationHash returns the hex SHA-256 of the canonical attestation JSON.
func (p *Payload) GetAttestationHash() string {
	if p == nil {
		return ""
	}
	return p.AttestationHash
}

// GetAttestationSignature returns the base64 Ed25519 signature over the hash.
func (p *Payload) GetAttestationSignature() string {
	if p == nil {
		return ""
	}
	return p.AttestationSignature
}

// GetAttestationKeyID returns the signing key identifier ("org:<uuid>:v<n>").
func (p *Payload) GetAttestationKeyID() string {
	if p == nil {
		return ""
	}
	return p.AttestationKeyID
}

// GetFirstTokenMs returns the time-to-first-token for streaming responses.
func (p *Payload) GetFirstTokenMs() int64 {
	if p == nil {
		return 0
	}
	return p.FirstTokenMs
}

// GetAttemptCount returns the number of fallback-chain hops for the request.
func (p *Payload) GetAttemptCount() int {
	if p == nil {
		return 0
	}
	return p.AttemptCount
}

// GetRetryCount returns the intra-model retry count across all chain hops.
func (p *Payload) GetRetryCount() int {
	if p == nil {
		return 0
	}
	return p.RetryCount
}
