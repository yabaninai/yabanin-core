package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Google Vertex AI adapter (owner decisions I49/I50/I51/I61).
//
// Native auth posture: APPLICATION DEFAULT CREDENTIALS (ADC), the Google
// analog of the AWS default chain — the gateway process resolves ambient
// workload credentials (GOOGLE_APPLICATION_CREDENTIALS service-account key,
// gcloud user ADC well-known file, then the GCE metadata server). The
// per-org credential blob (org_provider_credentials.api_key_ct for provider
// rows with provider='vertex') is therefore NOT a secret: it carries only
// the ROUTING identity — {"project":…,"location":…} — which is baked into
// the endpoint URL
// ({location}-aiplatform.googleapis.com)/v1/projects/{project}/locations/{location}/…
// exactly as Vertex requires. No static API key and no per-org secret key
// is parsed anywhere in this file (packet negative: a project/audience
// mismatch must never fall back to someone else's credentials — the token
// cache in vertex_adc.go is keyed by source identity AND project/location).
//
// Stateful like AzureOpenAI: the upstream Pool shares one *Vertex per
// (provider, URL) across all orgs, while apiKey (the org's project/location
// config) still arrives per request. The ADC token cache is keyed by
// (credential source identity, project, location) so two orgs never ride
// each other's token even when the ambient credential is the same.
//
// Payload flow: TranslateRequest (vertex_translate.go) folds the OpenAI
// chat body into the adapter-internal {"model","gemini"} envelope;
// PrepareRequest resolves the envelope model against the capability matrix
// (vertex_capabilities.go), authenticates, and sends ONLY the inner
// generateContent payload; TranslateResponse maps the Gemini body back to
// the OpenAI shape. Streaming rides the same envelope with the ?alt=sse
// endpoint and the translating SSE handler (vertex_stream.go). Every
// unmappable feature fails closed with a precise reason (I51) instead of a
// silent downgrade.

const (
	// vertexDefaultScheme is the endpoint scheme when models_registry
	// leaves upstream_url empty: Vertex serves HTTPS only.
	vertexDefaultScheme = "https"
	// vertexTokenSkew refreshes the ADC access token 5 min before expiry
	// (azure precedent).
	vertexTokenSkew = 5 * time.Minute
	// vertexTokenRefreshTimeout bounds one ADC token acquisition. The
	// refresh runs on a detached, self-bounded context so one caller's
	// disconnect cannot abort the shared exchange (sber/azure precedent).
	vertexTokenRefreshTimeout = 10 * time.Second
	// vertexTokenDefaultTTL is the defensive cache TTL when a token
	// response omits expires_in (Google access tokens live ~1h).
	vertexTokenDefaultTTL = 25 * time.Minute
	// vertexRateLimitCooldownBase/Max mirror the azure rate-limit
	// cooldown contract for the shared token endpoints (oauth2 endpoint,
	// metadata server): a 429 never sleeps in the request path; it fails
	// closed with a bounded cooldown (Retry-After delta clamped to 60s).
	vertexRateLimitCooldownBase = 1 * time.Second
	vertexRateLimitCooldownMax  = 60 * time.Second
	// vertexMetadataDialTimeout / vertexMetadataTimeout bound the
	// metadata-server probe on hosts that are not on GCP (link-local has
	// no ARP → typically hangs until timeout). Fail closed fast.
	vertexMetadataDialTimeout = 2 * time.Second
	vertexMetadataTimeout     = 5 * time.Second
)

// vertexProjectRe matches Google project IDs: 6–30 chars, lowercase
// letters/digits/hyphens, starting with a letter. This is also the
// fail-closed guard against URL path injection via the credentials blob
// (no slashes, dots, or percent-escapes can survive this class).
var vertexProjectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// vertexLocationRe matches Vertex location tokens (us-central1,
// europe-west4, asia-southeast1, northamerica-northeast1, global, us,
// eu): lowercase letters, digits and hyphens, 2–30 chars, starting with
// a letter. The 30-char cap covers Google's longest multi-word regions
// (northamerica-northeast1 is 23) — the capability matrix ships them, so
// the syntax gate must accept every location the matrix serves. Same
// fail-closed/injection argument as the project pattern: the strict
// charset keeps the location safe for URL-path interpolation.
var vertexLocationRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,29}$`)

// VertexCredentials is the per-org routing config stored in the credential
// slot for vertex rows. Deliberately secret-free: ADC supplies the
// credentials, this blob only says WHERE to call.
type VertexCredentials struct {
	Project  string `json:"project"`
	Location string `json:"location"`
}

// ParseVertexCredentials decodes and validates the JSON config blob. The
// returned errors name the offending FIELD and the required shape — never
// the configured values (they are tenant-identifying), and invalid input
// fails closed before any network or token work happens.
func ParseVertexCredentials(blob string) (VertexCredentials, error) {
	var c VertexCredentials
	if err := json.Unmarshal([]byte(blob), &c); err != nil {
		return VertexCredentials{}, errors.New("vertex: credentials must be JSON {project,location}")
	}
	switch {
	case c.Project == "":
		return VertexCredentials{}, errors.New("vertex: credentials missing project")
	case c.Location == "":
		return VertexCredentials{}, errors.New("vertex: credentials missing location")
	case !vertexProjectRe.MatchString(c.Project):
		return VertexCredentials{}, errors.New("vertex: credentials project is not a valid Google project ID (6-30 chars, lowercase letters/digits/hyphens, starts with a letter)")
	case !vertexLocationRe.MatchString(c.Location):
		return VertexCredentials{}, errors.New("vertex: credentials location is not a valid Vertex location (lowercase letters/digits/hyphens)")
	}
	return c, nil
}

// Vertex is the native Google Vertex AI adapter.
//
// The zero value is NOT usable; construct via NewVertex (production, real
// ADC chain) or NewVertexWithSource (tests inject a token source; see
// vertexTokenSource).
type Vertex struct {
	// adc is the resolved-credential machinery: chain resolution, token
	// cache, singleflight and rate-limit cooldown. Shared across all
	// requests; internally synchronized.
	adc *vertexADC
}

// NewVertex constructs the production adapter: ADC chain
// (GOOGLE_APPLICATION_CREDENTIALS → gcloud well-known file → GCE metadata
// server) with every token exchange on the SSRF-guarded transport. The
// metadata-server probe dials the documented literal 169.254.169.254 — the
// one exact-literal pin (D-4 posture), because the metadata endpoint is a
// Google-owned fixed address and is otherwise a reserved-range refusal.
func NewVertex() *Vertex {
	return &Vertex{adc: newVertexADC(nil)}
}

// NewVertexWithSource is the test hook: inject the ADC machinery (tests
// override the token-endpoint host / metadata URL / env reads on the
// returned *vertexADC). Production code uses NewVertex.
func NewVertexWithSource(adc *vertexADC) *Vertex {
	if adc == nil {
		adc = newVertexADC(nil)
	}
	return &Vertex{adc: adc}
}

// Name returns the canonical provider identifier.
func (*Vertex) Name() string { return "vertex" }

// Path returns the endpoint path TEMPLATE. The real path is built per
// request in PrepareRequest (project, location and model are per-request
// values); the template documents the shape and is not directly usable as
// a URL (azure precedent).
func (*Vertex) Path(_ bool) string {
	return "/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:{generateContent|streamGenerateContent}"
}

// PrepareRequest builds the native Vertex request from the adapter-internal
// envelope: capability-gated (model+region matrix plus per-family streaming
// and tool gates, precise rejection), ADC-authenticated (Bearer) and
// project/location-qualified URL per the Vertex AI endpoint contract. The
// wire body is ONLY the inner generateContent payload — the envelope model
// exists solely for the matrix lookup and the URL path. apiKey must be the
// JSON routing config parsed by ParseVertexCredentials.
func (v *Vertex) PrepareRequest(ctx context.Context, baseURL, _ string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	creds, err := ParseVertexCredentials(apiKey)
	if err != nil {
		return nil, err
	}
	env, err := parseVertexEnvelope(body)
	if err != nil {
		return nil, err
	}
	// Capability gate: model must be a known family AND the location must
	// serve it. Unknown pairs fail closed with the precise matrix reason
	// (I51) BEFORE any credential or network work.
	caps, err := VertexLookup(env.Model, creds.Location)
	if err != nil {
		return nil, err
	}
	var wire struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(env.Gemini, &wire); err != nil {
		return nil, errors.New("vertex: gemini payload is not a JSON object")
	}
	if err := vertexCapabilityGate(env.Model, caps, stream, len(wire.Tools) > 0); err != nil {
		return nil, err
	}
	// ADC token for exactly this (source, project, location). A mismatched
	// project/location never reuses another entry's token (negative
	// acceptance): the cache key binds all three, resolution failures do
	// not fall back to a different credential source.
	token, err := v.adc.token(creds) //nolint:contextcheck // the shared token refresh deliberately runs detached (sber/azure precedent): one caller’s request ctx must not own the shared token exchange
	if err != nil {
		return nil, err
	}
	full, err := vertexUpstreamURL(baseURL, creds.Location, VertexEndpoint(creds.Project, creds.Location, env.Model, stream))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full, bytes.NewReader(env.Gemini))
	if err != nil {
		return nil, fmt.Errorf("build vertex request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// vertexCapabilityGate enforces the per-family request gates on top of the
// matrix lookup: a stream request against a non-streaming family and a
// tool-bearing request against a family without tool support are rejected
// with the precise reason (I51) before any credential or network work.
// The refusals are typed *CapabilityError values so the gateway renders
// them as client-shaped 400 capability_not_supported responses instead of
// fabricated upstream failures. Shipped families all support both; the
// gates are matrix-driven so new families fail closed instead of
// inheriting the current rows' abilities.
func vertexCapabilityGate(model string, caps VertexCapabilities, stream, hasTools bool) error {
	if stream && !caps.Streaming {
		return &CapabilityError{
			Provider:   "vertex",
			Capability: CapabilityStreaming,
			Model:      model,
			Detail:     fmt.Sprintf("vertex: model %q does not support streaming in the capability matrix; request rejected, not downgraded", model),
		}
	}
	if hasTools && !caps.Tools {
		return &CapabilityError{
			Provider:   "vertex",
			Capability: CapabilityTools,
			Model:      model,
			Detail:     fmt.Sprintf("vertex: model %q does not support tool calling in the capability matrix; request rejected, not downgraded", model),
		}
	}
	return nil
}

// vertexUpstreamURL joins the endpoint host and path. Empty baseURL uses
// the canonical location-derived host (production form:
// https://{location}-aiplatform.googleapis.com, "global" →
// aiplatform.googleapis.com). A configured baseURL (models_registry
// upstream_url, test rigs, private/regional gateways) is used verbatim and
// must parse as an absolute http(s) URL — malformed values fail closed.
// The upstream client re-validates the final URL against the SSRF
// allow-list before dialing (defense in depth, not a substitute).
func vertexUpstreamURL(baseURL, location, path string) (string, error) {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return vertexDefaultScheme + "://" + vertexHostForLocation(location) + path, nil
	}
	if !strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("vertex: base URL must be absolute http(s) URL, got a scheme-less value")
	}
	scheme, host, ok := strings.Cut(strings.TrimRight(trimmed, "/"), "://")
	if !ok || host == "" || (scheme != "http" && scheme != "https") {
		return "", fmt.Errorf("vertex: base URL must be an absolute http(s) URL")
	}
	return scheme + "://" + host + path, nil
}

// ParseUsage extracts token usage from a response body, shape-sniffing
// pointer-wise exactly like the bedrock adapter: native Gemini bodies carry
// usageMetadata (camelCase), while the gateway parses usage from the
// TRANSLATED chat.completion body — prompt_tokens/completion_tokens plus
// prompt_tokens_details (whose cached_tokens must survive the translation
// round-trip for cache billing). A body with neither shape means the
// provider reported nothing — UsageSourceNone, not provider-reported zeros.
func (*Vertex) ParseUsage(respBody []byte) Usage {
	var native struct {
		UsageMetadata *vertexUsageMetadata `json:"usageMetadata"`
	}
	if err := json.Unmarshal(respBody, &native); err == nil && native.UsageMetadata != nil {
		return native.UsageMetadata.toUsage()
	}
	var translated struct {
		Usage *struct {
			PromptTokens     *int64 `json:"prompt_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
			OpenAITotal      *int64 `json:"total_tokens"`
			Details          *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &translated); err != nil || translated.Usage == nil || translated.Usage.PromptTokens == nil {
		return Usage{Source: UsageSourceNone}
	}
	u := translated.Usage
	prompt := *u.PromptTokens
	completion := int64(0)
	if u.CompletionTokens != nil {
		completion = *u.CompletionTokens
	}
	total := prompt + completion
	if u.OpenAITotal != nil {
		total = *u.OpenAITotal
	}
	usage := Usage{
		PromptTokens:     prompt,
		CompletionTokens: completion,
		TotalTokens:      total,
		Source:           UsageSourceProvider,
	}
	if u.Details != nil {
		usage.CacheReadTokens = u.Details.CachedTokens
	}
	return usage
}
