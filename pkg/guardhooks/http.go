package guardhooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// HTTPDetectorRequestVersion identifies the versioned remote detector JSON
	// protocol. Both envelopes carry it verbatim; a peer answering with any
	// other version is refused loudly — a consumer must never parse a payload
	// under mismatched schema assumptions (N02-P04-T02).
	HTTPDetectorRequestVersion = "guardrails.http.v1"
	// DefaultHTTPDetectorMaxBytes is the default payload cap shared by the
	// adapters that speak this protocol (request and response direction).
	DefaultHTTPDetectorMaxBytes = 1 << 20
)

// HTTPDetectorRequest is the versioned request envelope of the remote
// detector protocol. It carries exactly one invocation projection: the
// protocol version, the phase/kind labels and the selected content — never
// org, key, model or routing metadata.
type HTTPDetectorRequest struct {
	Version string      `json:"version"`
	Phase   Phase       `json:"phase"`
	Kind    ContentKind `json:"kind"`
	Text    string      `json:"text"`
}

// HTTPDetectorResponse is the versioned response envelope. Findings are
// offsets/metadata only; a service that echoes matched content violates the
// contract and its findings still carry no copied content field.
type HTTPDetectorResponse struct {
	Version  string    `json:"version"`
	Findings []Finding `json:"findings"`
}

// EncodeDetectorRequest renders the versioned request envelope for one
// invocation projection. Shared by every adapter that speaks the protocol so
// the wire shape cannot drift between them.
func EncodeDetectorRequest(phase Phase, kind ContentKind, text string) ([]byte, error) {
	payload, err := json.Marshal(HTTPDetectorRequest{Version: HTTPDetectorRequestVersion, Phase: phase, Kind: kind, Text: text})
	if err != nil {
		return nil, fmt.Errorf("guardrails http detector: encode request: %w", err)
	}
	return payload, nil
}

// DecodeDetectorResponse validates and decodes one response body against the
// shared protocol contract: the exact protocol version (loud refusal of
// unknown versions in both directions — the old-consumer tolerance rule is an
// explicit error, never a silent misparse), valid finding spans for the
// scanned text length, and a detector id on every finding.
func DecodeDetectorResponse(body []byte, textLen int) ([]Finding, error) {
	var result HTTPDetectorResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("guardrails http detector: malformed response: %w", err)
	}
	if result.Version != HTTPDetectorRequestVersion {
		return nil, fmt.Errorf("guardrails http detector: unsupported response version %q", result.Version)
	}
	for _, f := range result.Findings {
		if f.Start < 0 || f.End < f.Start || f.End > textLen {
			return nil, errors.New("guardrails http detector: response contains invalid finding span")
		}
		if f.Detector == "" {
			return nil, errors.New("guardrails http detector: response finding has no detector id")
		}
	}
	return result.Findings, nil
}

// HTTPDetectorConfig describes an explicitly approved remote detector. Only
// HTTPS endpoints and exact host allow-list entries are accepted.
type HTTPDetectorConfig struct {
	Identity RuleVersion
	Endpoint string
	Hosts    []string
	Timeout  time.Duration
	MaxBytes int64
	Client   *http.Client
}

// HTTPDetector is a VersionedDetector backed by an approved HTTP service. Its
// versioned JSON protocol sends only the selected invocation content and
// receives offsets/metadata, never copied matched content.
type HTTPDetector struct {
	identity RuleVersion
	endpoint string
	maxBytes int64
	client   *http.Client
}

// NewHTTPDetector validates the endpoint and builds a bounded, no-redirect
// adapter. Callers must explicitly approve the endpoint host.
func NewHTTPDetector(cfg HTTPDetectorConfig) (*HTTPDetector, error) {
	if cfg.Identity.PackID == "" || cfg.Identity.PackVersion == "" || cfg.Identity.RuleID == "" || cfg.Identity.RuleVersion == "" {
		return nil, errors.New("guardrails http detector: complete versioned identity required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("guardrails http detector: endpoint must be an https URL without userinfo or fragment")
	}
	approved := false
	for _, host := range cfg.Hosts {
		if strings.EqualFold(strings.TrimSpace(host), u.Hostname()) {
			approved = true
			break
		}
	}
	if !approved {
		return nil, fmt.Errorf("guardrails http detector: endpoint host %q is not approved", u.Hostname())
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultHTTPDetectorMaxBytes
	}
	client := cfg.Client
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	// Never permit a redirect to forward inspected content to another host.
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPDetector{identity: cfg.Identity, endpoint: u.String(), maxBytes: maxBytes, client: &clientCopy}, nil
}

// Identity returns the stable pack/rule identity configured for this adapter.
func (d *HTTPDetector) Identity() RuleVersion { return d.identity }

// Detect sends one bounded invocation to the approved service and validates
// the returned protocol version and finding spans.
func (d *HTTPDetector) Detect(in Invocation) ([]Finding, error) {
	if in.Context == nil {
		return nil, errors.New("guardrails http detector: nil context")
	}
	text, err := in.Content()
	if err != nil {
		return nil, err
	}
	if int64(len(text)) > d.maxBytes {
		return nil, fmt.Errorf("guardrails http detector: input exceeds %d bytes", d.maxBytes)
	}
	payload, err := EncodeDetectorRequest(in.Phase, in.Kind, text)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(in.Context, http.MethodPost, d.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("guardrails http detector: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardrails http detector: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardrails http detector: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, d.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("guardrails http detector: read response: %w", err)
	}
	if int64(len(body)) > d.maxBytes {
		return nil, fmt.Errorf("guardrails http detector: response exceeds %d bytes", d.maxBytes)
	}
	findings, err := DecodeDetectorResponse(body, len(text))
	if err != nil {
		return nil, err
	}
	return findings, nil
}
