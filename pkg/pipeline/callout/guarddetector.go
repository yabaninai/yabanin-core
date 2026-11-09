package callout

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// GuardDetector is the approved remote guard detector adapter
// (N02-P04-T03/T04): a guardhooks.VersionedDetector that speaks the versioned
// guardrails.http.v1 protocol through the Runtime's shared one-shot callout
// path, so a pack-declared HTTP detector inherits exactly the OP-2 bounds —
//
//   - compile-time egress allow-list (construction refuses any host outside
//     Deps.AllowHosts; a policy or pack can never widen egress),
//   - dial-time SSRF guard (reserved addresses refuse the connection; the
//     DNS-rebinding TOCTOU window is closed),
//   - no redirects, no retries (one upstream attempt per call; degradation is
//     the caller's FailureMode, never a silent resend),
//   - per-URL circuit breaker (post-threshold calls shed with a breaker
//     error instead of hammering a dead endpoint),
//   - singleflight dedup of concurrent identical (endpoint, content) calls,
//   - bounded payloads: MaxRequestBytes caps the outgoing projection and
//     maxReply caps the response body,
//   - per-attempt timeout: Deps.Timeout on the transport, the caller's
//     context deadline on the step.
//
// The wire contract itself (schema version, span validation, metadata-only
// findings) is owned by guardhooks' shared codec — see
// guardhooks.EncodeDetectorRequest / guardhooks.DecodeDetectorResponse.
// Findings are metadata+offsets; hit accounting applies the shared
// confidence threshold (guardhooks scanConfidence), so a detector reporting
// an unconfirmed (sub-threshold) finding can widen audit, never enforcement.
type GuardDetector struct {
	rt         *Runtime
	identity   guardhooks.RuleVersion
	cfg        stepConfig // endpoint key + response cap; the step fields beyond endpoint/maxReply are unused here
	maxRequest int64      // outgoing payload cap
}

// GuardDetectorConfig describes one approved remote guard detector endpoint.
type GuardDetectorConfig struct {
	// Identity is the versioned pack/rule identity reported by the adapter
	// (required complete, like every VersionedDetector).
	Identity guardhooks.RuleVersion

	// Endpoint is the detector URL (scheme http/https, no userinfo, no
	// fragment; query is dropped by the endpoint key). The host must be in
	// the operator allow-list.
	Endpoint string

	// MaxRequestBytes caps the outgoing payload (default
	// guardhooks.DefaultHTTPDetectorMaxBytes). A larger invocation is a
	// detection error before anything is sent.
	MaxRequestBytes int64

	// MaxResponseBytes caps the response body (default Deps.MaxResponseBytes).
	MaxResponseBytes int64
}

// NewGuardDetector validates the config against the Runtime's allow-list and
// builds the adapter. Construction-time rejection is the rights boundary:
// an endpoint that is not explicitly approved can never acquire a detector.
func (r *Runtime) NewGuardDetector(cfg GuardDetectorConfig) (*GuardDetector, error) {
	id := cfg.Identity
	if id.PackID == "" || id.PackVersion == "" || id.RuleID == "" || id.RuleVersion == "" {
		return nil, errors.New("callout guard detector: complete versioned identity required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("callout guard detector: parse endpoint: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		// https is the production requirement for a remote guard detector
		// (N02-P08 https posture): inspected content must not travel in
		// cleartext. A cleartext endpoint for a NON-loopback host is not a
		// construction error — the operator allow-list and the dial-time
		// reserved-IP guard remain the controls — but it is announced loudly
		// so the convention ("http is for loopback/test rigs") can never be
		// drifted out of silently. The pack-facing standalone adapter
		// (guardhooks.NewHTTPDetector) is stricter and refuses cleartext
		// unconditionally; a future pack-declared HTTP-detector wiring must
		// either use that adapter or gate cleartext endpoints behind an
		// explicit config flag (default strict).
		if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			slog.Warn("callout guard detector: cleartext http endpoint for a non-loopback host — https is the production requirement; http is reserved for loopback/test rigs by convention",
				"host", u.Hostname(), "pack", id.PackID, "rule", id.RuleID)
		}
	default:
		return nil, fmt.Errorf("callout guard detector: scheme must be http or https, got %q", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("callout guard detector: userinfo is not allowed (credentials never travel in detector URLs)")
	}
	if u.Host == "" {
		return nil, errors.New("callout guard detector: host is required")
	}
	if u.Fragment != "" {
		return nil, errors.New("callout guard detector: fragment is not allowed")
	}
	if !r.hostAllowed(u.Hostname()) {
		return nil, fmt.Errorf("callout guard detector: host %q is not in the callout egress allow-list (packs cannot widen egress)", u.Hostname())
	}
	maxRequest := cfg.MaxRequestBytes
	if maxRequest <= 0 {
		maxRequest = guardhooks.DefaultHTTPDetectorMaxBytes
	}
	maxReply := cfg.MaxResponseBytes
	if maxReply <= 0 {
		maxReply = r.deps.MaxResponseBytes
	}
	return &GuardDetector{
		rt:         r,
		identity:   id,
		cfg:        stepConfig{endpoint: endpointKey(u), maxReply: maxReply},
		maxRequest: maxRequest,
	}, nil
}

// isLoopbackHost reports whether the endpoint host is the loopback
// convention (literal loopback IP or "localhost"): the only tolerated
// cleartext shape for a guard detector endpoint.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Identity returns the configured versioned pack/rule identity.
func (d *GuardDetector) Identity() guardhooks.RuleVersion { return d.identity }

// Detect sends one bounded, deduplicated, breaker-admitted invocation to the
// approved endpoint and validates the versioned response. A probe failure
// (network, non-2xx, wrong content-type, oversized/malformed/out-of-version
// body, breaker rejection) is always an error — the caller's FailureOutcome
// decides enforce vs shadow, so a probe failure can never pose as an allow.
func (d *GuardDetector) Detect(in guardhooks.Invocation) ([]guardhooks.Finding, error) {
	if in.Context == nil {
		return nil, errors.New("callout guard detector: nil context")
	}
	text, err := in.Content()
	if err != nil {
		return nil, err // unsupported invocation version / phase / kind: loud
	}
	if int64(len(text)) > d.maxRequest {
		return nil, fmt.Errorf("callout guard detector: input exceeds %d bytes", d.maxRequest)
	}
	payload, err := guardhooks.EncodeDetectorRequest(in.Phase, in.Kind, text)
	if err != nil {
		return nil, err
	}
	resp, err := d.rt.call(in.Context, d.cfg, payload)
	if err != nil {
		return nil, err
	}
	// Spans are validated against the exact projection the endpoint saw, so
	// a hostile reply can never point redaction outside the scanned text.
	return guardhooks.DecodeDetectorResponse(resp.body, len(text))
}

// compile-time assertion: the adapter satisfies the guard detector SPI.
var _ interface {
	Identity() guardhooks.RuleVersion
	Detect(guardhooks.Invocation) ([]guardhooks.Finding, error)
} = (*GuardDetector)(nil)
