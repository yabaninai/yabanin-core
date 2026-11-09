package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// DefaultNonStreamTimeout is the per-call deadline for non-streaming upstream
// requests when no explicit timeout is configured. Streaming requests do not
// apply an internal timeout — they rely on the caller's context.
const DefaultNonStreamTimeout = 60 * time.Second

// Options configures an upstream Client. Zero values fall back to sane
// defaults applied in NewClientWithOptions.
type Options struct {
	BaseURL               string
	Timeout               time.Duration // per-call deadline for non-streaming ForwardJSON
	DialTimeout           time.Duration // TCP connect timeout
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	MaxIdleConns          int
	MaxIdlePerHost        int
	IdleTimeout           time.Duration
	// AllowedUpstreams is required. The BaseURL host MUST appear in this list;
	// an empty list is a configuration error and never disables egress checks.
	AllowedUpstreams []string
	// ProxyURL optionally configures an explicit HTTP(S) proxy. Its hostname
	// and scheme must also be present in AllowedUpstreams; environment proxy
	// variables are never consulted by guarded upstream clients.
	ProxyURL string
	// ProviderName selects the request/response adapter. Empty defaults to
	// "openai" (also covers openai-compat upstreams). Use "anthropic" for
	// the native Anthropic Messages API.
	ProviderName string
}

// Client performs upstream HTTP calls with SSRF-aware URL validation.
type Client struct {
	baseURL        string
	adapter        provider.Provider
	client         *http.Client
	ssrfAllowList  ssrf.AllowList
	allowedSchemes map[string]map[string]struct{}
	defaultTimeout time.Duration
}

// NewClientWithAdapter is the canonical constructor: it builds the HTTP
// plumbing from Options and binds a provider adapter. Returned clients are
// safe for concurrent use.
func NewClientWithAdapter(opts Options) (*Client, error) {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultNonStreamTimeout
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.TLSHandshakeTimeout == 0 {
		opts.TLSHandshakeTimeout = 5 * time.Second
	}
	if opts.ResponseHeaderTimeout == 0 {
		opts.ResponseHeaderTimeout = 20 * time.Second
	}
	if opts.MaxIdleConns == 0 {
		opts.MaxIdleConns = 100
	}
	if opts.MaxIdlePerHost == 0 {
		opts.MaxIdlePerHost = 100
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 90 * time.Second
	}

	adapter, err := provider.New(opts.ProviderName)
	if err != nil {
		return nil, err
	}

	if len(opts.AllowedUpstreams) == 0 {
		return nil, errors.New("upstream config: AllowedUpstreams must contain at least one explicitly approved provider URL")
	}
	if err := ValidateBaseURL(opts.BaseURL); err != nil {
		return nil, fmt.Errorf("upstream config: %w", err)
	}
	parsed, err := url.Parse(strings.TrimRight(opts.BaseURL, "/"))
	if err != nil {
		// Defensive: ValidateBaseURL parsed this exact string above, so the
		// parse cannot fail here.
		return nil, fmt.Errorf("upstream config: invalid provider URL %q", opts.BaseURL)
	}

	var domains []string
	allowedSchemes := make(map[string]map[string]struct{})
	for _, u := range opts.AllowedUpstreams {
		p, parseErr := url.Parse(strings.TrimRight(u, "/"))
		if parseErr != nil || !isHTTPURL(p) {
			return nil, fmt.Errorf("upstream allowlist: invalid allowed URL %q", u)
		}
		domains = append(domains, p.Hostname())
		host := strings.ToLower(p.Hostname())
		if allowedSchemes[host] == nil {
			allowedSchemes[host] = make(map[string]struct{})
		}
		allowedSchemes[host][p.Scheme] = struct{}{}
	}

	al, err := ssrf.NewAllowListTrustingExactPins(domains)
	if err != nil {
		return nil, fmt.Errorf("upstream allowlist: %w", err)
	}

	if err := checkAllowedURL(al, allowedSchemes, parsed); err != nil {
		return nil, fmt.Errorf("upstream allowlist: provider %q is not in the allowed list: %v", opts.BaseURL, opts.AllowedUpstreams)
	}
	var proxyFunc func(*http.Request) (*url.URL, error)
	if opts.ProxyURL != "" {
		proxyURL, parseErr := url.Parse(opts.ProxyURL)
		if parseErr != nil || !isHTTPURL(proxyURL) {
			return nil, fmt.Errorf("upstream config: invalid proxy URL %q", opts.ProxyURL)
		}
		if err := checkAllowedURL(al, allowedSchemes, proxyURL); err != nil {
			return nil, fmt.Errorf("upstream proxy rejected: %w", err)
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	// D-4: both guard layers decide identically — exact allow-list entries
	// are operator pins whose reserved-range verdict is waived at validate
	trustedExactHosts := al.TrustsExactPin
	transport := ssrf.NewTransport(ssrf.TransportOptions{
		Proxy:                 proxyFunc,
		DialTimeout:           opts.DialTimeout,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		IdleConnTimeout:       opts.IdleTimeout,
		MaxIdleConns:          opts.MaxIdleConns,
		MaxIdleConnsPerHost:   opts.MaxIdlePerHost,
		ForceAttemptHTTP2:     true,
		GuardDialedIP:         true,
		TrustedExactHosts:     trustedExactHosts,
	})
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("upstream redirect: stopped after 10 redirects")
			}
			if err := checkAllowedURL(al, allowedSchemes, req.URL); err != nil {
				return fmt.Errorf("upstream redirect rejected: %w", err)
			}
			return nil
		},
	}

	// W-PROV: adapters that need custom TLS (Sber mTLS) hand over ONLY the
	// *tls.Config via TLSConfigProvider; it is composed ON TOP of the shared
	// transport above, so the dial-time SSRF guard stays active.
	if tp, ok := adapter.(provider.TLSConfigProvider); ok {
		if cfg := tp.TLSConfig(); cfg != nil {
			transport.TLSClientConfig = cfg
		}
	}

	return &Client{
		baseURL:        strings.TrimRight(opts.BaseURL, "/"),
		adapter:        adapter,
		ssrfAllowList:  al,
		allowedSchemes: allowedSchemes,
		defaultTimeout: opts.Timeout,
		client:         client,
	}, nil
}

// NewClient is a backward-compatible constructor using OpenAI defaults.
// Equivalent to NewClientWithAdapter with the same SSRF allowlist behaviour.
// It returns an error instead of panicking on adapter or SSRF-allowlist
//
// Deprecated: prefer NewClientWithAdapter so the provider type is explicit.
func NewClient(providerURL string, allowedUpstreams []string) (*Client, error) {
	return NewClientWithAdapter(Options{
		BaseURL:          providerURL,
		Timeout:          DefaultNonStreamTimeout,
		AllowedUpstreams: allowedUpstreams,
	})
}

// BaseURL returns the configured upstream base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// Adapter returns the bound provider adapter.
func (c *Client) Adapter() provider.Provider { return c.adapter }

// ForwardJSONWithHeaders is ForwardJSONWithTimeout that also returns the
// upstream response headers (cloned). The lineage resolver uses them for the
// header_observed / provider_attested evidence tiers; Clone detaches the
// headers from resp's lifetime (the body is closed before return).
func (c *Client) ForwardJSONWithHeaders(ctx context.Context, body []byte, model string, apiKey string, timeout time.Duration) (http.Header, []byte, error) {
	hdr, respBody, _, err := c.forward(ctx, body, model, apiKey, timeout, false)
	return hdr, respBody, err
}

// ForwardJSONCapturing additionally returns the exact request body sent
// upstream AFTER adapter translation and model override — the "what actually
// went to the model" evidence the request explorer shows next to the
// client's original payload (tier routing / effort injection visible).
func (c *Client) ForwardJSONCapturing(ctx context.Context, body []byte, model string, apiKey string, timeout time.Duration) (http.Header, []byte, []byte, error) {
	return c.forward(ctx, body, model, apiKey, timeout, true)
}

func (c *Client) forward(ctx context.Context, body []byte, model string, apiKey string, timeout time.Duration, capture bool) (http.Header, []byte, []byte, error) {
	if err := c.checkSSRF(); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
		return nil, nil, nil, err
	}

	reqBody, err := c.adapter.TranslateRequest(body)
	if err != nil {
		// Typed not-sent proof (N07-P01-T05): a translate refusal happens
		// before any transport activity, so the retry classifier, the
		// fallback chain and the gateway render can act on the fact instead
		// of guessing from an untyped error. The adapter's exact reason
		// stays in the message (I51).
		return nil, nil, nil, fmt.Errorf("translate request: %w", &retry.RequestNotSentError{Err: err})
	}
	if model != "" {
		// OverrideModelRaw patches only the model key; the map[string]interface{}
		// round-trip of the legacy overrideModel re-encodes every other field
		// through float64 and silently corrupts extension integers beyond 2^53
		// (N07-P01-T04 explicit pass-through). Native passthrough endpoints
		// already use the raw variant for the same reason.
		reqBody = OverrideModelRaw(reqBody, model)
	}
	// Post-override hook (W-PROV): adapters that must pin a canonical
	// served-model name re-assert it after the gateway's override, which
	// would otherwise clobber the TranslateRequest-time rewrite.
	if fin, ok := c.adapter.(provider.ModelFinalizer); ok {
		reqBody = fin.FinalizeModel(reqBody, model)
	}
	var sent []byte
	if capture {
		sent = append([]byte(nil), reqBody...)
	}

	t := timeout
	if t <= 0 {
		t = c.defaultTimeout
	}
	if t <= 0 {
		t = DefaultNonStreamTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()

	req, err := c.adapter.PrepareRequest(ctx, c.baseURL, c.adapter.Path(false), reqBody, apiKey, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create request: %w", err)
	}
	if err := c.checkRequestURL(req.URL); err != nil {
		return nil, nil, nil, err
	}
	if id := requestid.FromContext(ctx); id != "" {
		req.Header.Set(requestid.RequestIDHeader, string(id))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, nil, errors.New("upstream request timeout")
		}
		if errors.Is(err, context.Canceled) {
			return nil, nil, nil, errors.New("upstream request cancelled")
		}
		return nil, nil, nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyRead, _ := io.ReadAll(resp.Body)
		return nil, nil, sent, &Error{Status: resp.StatusCode, Body: string(bodyRead), Header: resp.Header.Clone()}
	}

	hdrs := resp.Header.Clone()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, sent, fmt.Errorf("failed to read response body: %w", err)
	}

	translated, terr := c.adapter.TranslateResponse(respBody)
	if terr != nil {
		// W-PROV: a provider-native body that cannot be converted into the
		// OpenAI response contract must NOT be passed through — an OpenAI
		// client would receive a foreign schema (e.g. raw Anthropic
		// Messages JSON). Surface a typed 502-mappable failure instead.
		return nil, nil, sent, &TranslateError{Provider: c.adapter.Name(), Err: terr}
	}
	return hdrs, translated, sent, nil
}

// ForwardJSONWithTimeout is like ForwardJSON but uses an explicit timeout
// instead of the client's defaultTimeout. Used for per-model timeout overrides
// (P3.12). When timeout is zero or negative it falls back to c.defaultTimeout.
func (c *Client) ForwardJSONWithTimeout(ctx context.Context, body []byte, model string, apiKey string, timeout time.Duration) ([]byte, error) {
	_, b, err := c.ForwardJSONWithHeaders(ctx, body, model, apiKey, timeout)
	return b, err
}

// ForwardJSON sends a non-streaming request to the upstream and returns the
// translated (OpenAI-shape) response body. The caller's context is wrapped in
// defaultTimeout to bound total round-trip time. Streaming requests should
// call Stream instead.
func (c *Client) ForwardJSON(ctx context.Context, body []byte, model string, apiKey string) ([]byte, error) {
	_, b, err := c.ForwardJSONWithHeaders(ctx, body, model, apiKey, 0)
	return b, err
}

// Stream returns the upstream response body for SSE streaming. The caller
// controls the lifetime of the request via ctx: a deadline on ctx bounds total
// stream time, ctx cancellation propagates to upstream on client disconnect.
// No internal timeout is applied so long token generations are not truncated.
//
// For OpenAI-compat upstreams the body is forwarded verbatim. For Anthropic
// the caller is responsible for translating events via the provider's
// stream translator (P3.13 wires this in serveStream).
func (c *Client) Stream(ctx context.Context, data []byte, apiKey string) (*http.Response, error) {
	if err := c.checkSSRF(); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
		return nil, err
	}

	reqBody, err := c.adapter.TranslateRequest(data)
	if err != nil {
		// Typed not-sent proof (N07-P01-T05) — same contract as forward():
		// the refusal is structural proof nothing was sent, with the exact
		// adapter reason preserved.
		return nil, fmt.Errorf("translate stream request: %w", &retry.RequestNotSentError{Err: err})
	}
	// Post-override hook (W-PROV): keep the canonical served-model invariant
	// on the streaming path too (the gateway overrides before Stream).
	if fin, ok := c.adapter.(provider.ModelFinalizer); ok {
		reqBody = fin.FinalizeModel(reqBody, "")
	}

	req, err := c.adapter.PrepareRequest(ctx, c.baseURL, c.adapter.Path(true), reqBody, apiKey, true)
	if err != nil {
		return nil, fmt.Errorf("create stream request: %w", err)
	}
	if err := c.checkRequestURL(req.URL); err != nil {
		return nil, err
	}
	if id := requestid.FromContext(ctx); id != "" {
		req.Header.Set(requestid.RequestIDHeader, string(id))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("upstream stream deadline exceeded")
		}
		if errors.Is(err, context.Canceled) {
			return nil, errors.New("client disconnected")
		}
		return nil, fmt.Errorf("upstream stream failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyRead, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close() // error path: body already discarded
		if err != nil {
			return nil, &Error{Status: resp.StatusCode, Body: "failed to read body", Header: resp.Header.Clone()}
		}
		return nil, &Error{Status: resp.StatusCode, Body: string(bodyRead), Header: resp.Header.Clone()}
	}

	return resp, nil
}

// OverrideModel replaces the model field in a JSON body with the given model
// name. It is exported so gateway-level callers (serveStream, chatCompletions)
// can apply the same per-hop model rewriting that ForwardJSON uses internally,
// while preserving every other field the client sent (temperature, tools,
// response_format, ...) instead of rebuilding the body from a narrow struct.
//
// Returns the input body unchanged when it isn't valid JSON; the caller is
// expected to have already validated request shape before invoking this.
func OverrideModel(body []byte, model string) []byte {
	return overrideModel(body, model)
}

// overrideModel replaces the model field in a JSON body with the given model name.
func overrideModel(body []byte, model string) []byte {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	raw["model"] = model
	result, _ := json.Marshal(raw)
	return result
}

// Do sends body to path on the upstream using the bound adapter's auth and
// headers, without chat schema translation. Any HTTP status is returned as a
// response; the caller owns and must close resp.Body. extra headers are
// applied after the adapter's: a key with an empty value deletes the header.
func (c *Client) Do(ctx context.Context, path string, body []byte, apiKey string, stream bool, extra http.Header) (*http.Response, error) {
	if err := c.checkSSRF(); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
		return nil, err
	}
	req, err := c.adapter.PrepareRequest(ctx, c.baseURL, path, body, apiKey, stream)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if err := c.checkRequestURL(req.URL); err != nil {
		return nil, err
	}
	if id := requestid.FromContext(ctx); id != "" {
		req.Header.Set(requestid.RequestIDHeader, string(id))
	}
	applyExtraHeaders(req, extra)
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("upstream request timeout")
		}
		if errors.Is(err, context.Canceled) {
			return nil, errors.New("upstream request cancelled")
		}
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	return resp, nil
}

// applyExtraHeaders overlays extra onto req. An empty value removes the header.
func applyExtraHeaders(req *http.Request, extra http.Header) {
	for key, values := range extra {
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			req.Header.Del(key)
			continue
		}
		req.Header.Del(key)
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
}

// OverrideModelRaw replaces the model field without decoding numbers into float64,
// so large integers survive a native passthrough. Invalid JSON is returned unchanged.
// The previous OverrideModel stays on map[string]interface{} for existing callers.
func OverrideModelRaw(body []byte, model string) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return body
	}
	raw["model"] = encoded
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// ValidateBaseURL validates an operator-configured custom base URL — the
// origin a local/self-hosted model endpoint (or any provider adapter) will
// be dialed on — and refuses everything that is not a clean http(s) origin,
// each refusal with a precise, operator-actionable reason (N08-P04-T04).
//
// The refusals are the custom-base-URL boundary in one place:
//
//   - empty (or whitespace-only): no origin to dial;
//   - unparseable / malformed (bad IPv6 literal, missing scheme, ...);
//   - embedded credentials (a userinfo part): the URL is surfaced verbatim
//     in model status rows, probe reasons and error reports, so a
//     URL-embedded secret would leak — keys belong in the provider
//     credential, never in the URL. The reason names the host but never
//     echoes the credential;
//   - non-http(s) schemes (file:, ftp:, ws:, ...): no filesystem or exotic
//     protocol hop from provider configuration;
//   - missing host;
//   - a query string or fragment: adapters join the serving path by string
//     concatenation, so a trailing "?a=b" or "#f" would corrupt every
//     request URL built from this base.
//
// Surrounding whitespace is tolerated (trimmed) as a copy-paste artifact;
// internal whitespace stays refused via the parse error. Request-time and
// redirect-time egress policy (allowlist, reserved-range and dial-time IP
// pinning) is enforced separately per request — this function only decides
// whether the configured origin is a well-formed, credential-free http(s)
// origin at all.
func ValidateBaseURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("custom base URL is empty: configure the endpoint origin, e.g. http://127.0.0.1:8080")
	}
	parsed, err := url.Parse(strings.TrimRight(trimmed, "/"))
	if err != nil {
		return fmt.Errorf("invalid provider URL %q: %v", raw, err)
	}
	if parsed.User != nil {
		// Deliberately no echo of the raw URL here: it contains the secret.
		// The host alone is enough for an operator to recognize the entry.
		return fmt.Errorf("base URL for host %q embeds credentials (a userinfo part before the host): configure the key as the provider credential instead — the URL is surfaced verbatim in model status, probe reasons and error reports, so URL-embedded credentials would leak",
			parsed.Hostname())
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("base URL scheme %q is not allowed: only http and https are admitted (plain http only for loopback or operator-private local endpoints)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("base URL %q has no host: configure the endpoint origin as scheme://host:port", raw)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("base URL %q carries a query string: the serving path is appended after it, which corrupts every request URL built from this base — remove the query or move it into the endpoint path configuration", raw)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("base URL %q carries a fragment: it and everything appended after it never reach the endpoint — remove the fragment", raw)
	}
	return nil
}

// checkSSRF validates the configured upstream against the mandatory policy.
func (c *Client) checkSSRF() error {
	// c.baseURL is a full URL ("https://api.openai.com" or "http://127.0.0.1:53265").
	// Extract the hostname before handing off to the allow-list, which compares
	// against bare hostnames ("api.openai.com", "127.0.0.1") — using SplitHostPort
	// here used to leak the scheme into the comparison and break every request.
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("ssrf: invalid baseURL %q: %w", c.baseURL, err)
	}
	return validateURL(c.ssrfAllowList, c.allowedSchemes, parsed)
}

func (c *Client) checkRequestURL(target *url.URL) error {
	if err := checkAllowedURL(c.ssrfAllowList, c.allowedSchemes, target); err != nil {
		return fmt.Errorf("upstream egress policy rejected request: %w", err)
	}
	return nil
}

// checkAllowedURL applies the hostname portion of egress policy. DNS/IP
// validation is performed by ValidateUpstream before the first request and,
// critically, by the guarded dialer on the exact address connected for every
// hop (including redirects).
func checkAllowedURL(allowList ssrf.AllowList, allowedSchemes map[string]map[string]struct{}, target *url.URL) error {
	if !isHTTPURL(target) {
		return errors.New("ssrf: invalid upstream URL")
	}
	if !allowList.Contains(target.Hostname()) {
		return fmt.Errorf("ssrf: host %q is not in the allowed domains list", target.Hostname())
	}
	if _, ok := allowedSchemes[strings.ToLower(target.Hostname())][target.Scheme]; !ok {
		return fmt.Errorf("ssrf: scheme %q is not allowed for host %q", target.Scheme, target.Hostname())
	}
	return nil
}

func isHTTPURL(target *url.URL) bool {
	return target != nil && (target.Scheme == "http" || target.Scheme == "https") && target.Hostname() != "" && target.User == nil
}

func validateURL(allowList ssrf.AllowList, allowedSchemes map[string]map[string]struct{}, target *url.URL) error {
	if err := checkAllowedURL(allowList, allowedSchemes, target); err != nil {
		return err
	}
	return allowList.ValidateUpstream(target.Hostname())
}
