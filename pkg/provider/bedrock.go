// Package provider — native Amazon Bedrock adapter (N08-P02, I49).
//
// Bedrock speaks the Converse / ConverseStream REST APIs, authenticated with
// SigV4 computed locally from the AWS SDK DefaultChain credential chain
// (env → shared config/credentials → IMDS / web identity / SSO). There is no
// API-key blob and no token exchange: unlike the Azure adapter there is no
// auth endpoint to hammer, so there is deliberately no cooldown cache. Non-200
// upstream answers (AWS throttling 429 + ThrottlingException, credential
// failures, denied-region refusals) flow to the gateway through the standard
// upstream.Error{Status,Body} path with the provider's precise refusal text
// unrewritten (I51); connection-phase retry classification is the shared
// status-based retry classifier's job, so the adapter defines no error parser
// of its own.
//
// Security invariants:
//   - the adapter never holds or logs secret material; error strings carry
//     SDK diagnostic text and service messages only;
//   - the apiKey parameter is intentionally unused — Bedrock identity is
//     ambient (DefaultChain); per-org credential blobs would need an
//     adminstore-side schema decision (follow-up);
//   - endpoint formation goes through the SDK rule set (or an operator-
//     configured baseURL that the upstream SSRF allowlist still validates);
//     the modelId is percent-escaped into the URL path.
package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	bedrockruntime "github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

const (
	// bedrockSigningName is the SigV4 service name for the Bedrock runtime
	// surface. It is pinned from the SDK's own generated metadata
	// (bedrockruntime endpoints.go: model default signing name, identical in
	// v1.56.0 and v1.63.8). Pinned in a const block (review
	// addendum: the dispatch-#2 comment said "var"); a live-smoke correction
	// is a one-line value change.
	bedrockSigningName = "amazonbedrockfrontendservice"

	// bedrockConverseSuffix / bedrockConverseStreamSuffix are the fixed
	// Converse REST path suffixes; the escaped modelId is inserted before
	// them (Converse carries modelId only as a URL path segment).
	bedrockConverseSuffix       = "/converse"
	bedrockConverseStreamSuffix = "/converse-stream"
)

// Bedrock is the native Amazon Bedrock adapter (N08-P02). Stateful like
// AzureOpenAI/Sber: the upstream Pool shares one instance per
// (provider, URL); the AWS DefaultChain config is resolved lazily once and
// cached, while credentials keep resolving per request with SDK-side caching
// and automatic refresh.
type Bedrock struct {
	mu     sync.Mutex
	cfg    *aws.Config
	cfgErr error
	loaded bool
}

// NewBedrock constructs the production adapter. The AWS DefaultChain config
// (region + credential chain) is loaded lazily on the first request so that
// process-start does not pay IMDS/shared-config cost and containers can set
// env after start.
func NewBedrock() *Bedrock { return &Bedrock{} }

// NewBedrockWithConfig is the injection hook for tests and future explicit
// configuration: callers supply a resolved aws.Config (e.g. with a custom
// Credentials provider or region). Production code uses NewBedrock.
func NewBedrockWithConfig(cfg aws.Config) *Bedrock {
	return &Bedrock{cfg: &cfg, loaded: true}
}

// Name returns the canonical provider identifier.
func (*Bedrock) Name() string { return "bedrock" }

// Path returns the Converse path TEMPLATE for documentation/dispatch. The
// real path (with the escaped modelId) is built per request in
// PrepareRequest because the modelId lives in the translated body.
func (b *Bedrock) Path(stream bool) string {
	if stream {
		return "/model/{model}" + bedrockConverseStreamSuffix
	}
	return "/model/{model}" + bedrockConverseSuffix
}

// ParseUsage extracts token counts from a non-streaming ConverseOutput body.
func (*Bedrock) ParseUsage(respBody []byte) Usage {
	return bedrockParseUsage(respBody)
}

// PrepareRequest builds the SigV4-signed Converse/ConverseStream request.
// The body is the adapter-internal envelope {"model":…,"converse":{…}}
// produced by TranslateRequest; the converse payload is forwarded as the
// request body while the modelId becomes the escaped path segment. The
// apiKey parameter is deliberately unused (DefaultChain identity — see the
// package comment). baseURL, when non-empty, overrides the SDK-resolved
// regional endpoint (operator-configured endpoints and test rigs); the
// upstream client still validates the final URL against its SSRF allowlist.
func (b *Bedrock) PrepareRequest(ctx context.Context, baseURL, _ string, body []byte, _ string, stream bool) (*http.Request, error) {
	env, err := parseBedrockEnvelope(body)
	if err != nil {
		return nil, err
	}
	cfg, err := b.awsConfig(ctx)
	if err != nil {
		return nil, err
	}
	region := cfg.Region
	if strings.TrimSpace(region) == "" {
		return nil, errors.New("bedrock: AWS region is not configured (set AWS_REGION/AWS_DEFAULT_REGION or a shared-config region, or configure models_registry.upstream_url)")
	}
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base, err = bedrockEndpoint(ctx, region)
		if err != nil {
			return nil, err
		}
	}
	creds, err := b.credentials(ctx)
	if err != nil {
		return nil, err
	}

	suffix := bedrockConverseSuffix
	if stream {
		suffix = bedrockConverseStreamSuffix
	}
	full := base + "/model/" + sigv4EscapePath(env.Model) + suffix
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full, bytes.NewReader(env.Converse))
	if err != nil {
		return nil, fmt.Errorf("bedrock: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "application/vnd.amazon.eventstream")
	}

	// SignHTTP expects the hex SHA-256 of the exact wire body; the body is
	// fully in memory here (env.Converse), so compute it directly.
	bodySum := sha256.Sum256(env.Converse)
	payloadHash := hex.EncodeToString(bodySum[:])
	// DisableURIPathEscaping: the path is already escaped exactly once by
	// sigv4EscapePath (SigV4-safe, unreserved-only), so the canonical URI
	// must equal the wire URI byte-for-byte.
	signOpts := func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, payloadHash,
		bedrockSigningName, region, time.Now(), signOpts); err != nil {
		return nil, fmt.Errorf("bedrock: sign request: %w", err)
	}
	return req, nil
}

// awsConfig resolves (once) and caches the AWS DefaultChain config:
// region + credential chain from env → shared config → IMDS/web identity/SSO.
// Load failures are cached too so a broken environment fails fast on every
// request instead of re-probing (e.g. a disabled metadata service) per hop.
func (b *Bedrock) awsConfig(ctx context.Context) (aws.Config, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded {
		cfg, err := config.LoadDefaultConfig(ctx)
		b.cfg, b.cfgErr, b.loaded = &cfg, err, true
	}
	if b.cfgErr != nil {
		return aws.Config{}, fmt.Errorf("bedrock: load AWS config (DefaultChain): %w", b.cfgErr)
	}
	if b.cfg == nil {
		return aws.Config{}, errors.New("bedrock: AWS config unavailable")
	}
	return *b.cfg, nil
}

// credentials resolves the request's credentials from the DefaultChain. The
// SDK cache refreshes expiring credentials automatically; resolution errors
// fail closed and carry SDK diagnostics only (no secret material exists in
// adapter state).
func (b *Bedrock) credentials(ctx context.Context) (aws.Credentials, error) {
	cfg, err := b.awsConfig(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	if cfg.Credentials == nil {
		return aws.Credentials{}, errors.New("bedrock: no AWS credentials resolved by the DefaultChain (env / shared config / IMDS / web identity / SSO)")
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("bedrock: resolve AWS credentials: %w", err)
	}
	if creds.AccessKeyID == "" && creds.SessionToken == "" {
		return aws.Credentials{}, errors.New("bedrock: resolved AWS credentials are empty")
	}
	return creds, nil
}

// bedrockEndpoint resolves the regional runtime endpoint strictly through
// the SDK endpoint rule set (honors dual-stack/FIPS region rules and
// AWS-standard partition metadata).
func bedrockEndpoint(ctx context.Context, region string) (string, error) {
	useStd := false
	ep, err := bedrockruntime.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx,
		bedrockruntime.EndpointParameters{
			Region:       aws.String(region),
			UseDualStack: &useStd,
			UseFIPS:      &useStd,
		})
	if err != nil {
		return "", fmt.Errorf("bedrock: resolve endpoint: %w", err)
	}
	u := strings.TrimRight(ep.URI.String(), "/")
	if u == "" {
		return "", errors.New("bedrock: SDK endpoint resolver returned an empty URI")
	}
	return u, nil
}

// sigv4EscapePath percent-escapes a single URL path segment using the SigV4
// unreserved set (A-Z a-z 0-9 '-' '_' '.' '~'); everything else becomes
// uppercase %XX. Bedrock modelIds contain '.' and ':' (e.g.
// "anthropic.claude-3-5-sonnet-20241022-v2:0"), so the colon MUST be escaped
// for the canonical request URI to match the wire URI.
func sigv4EscapePath(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
