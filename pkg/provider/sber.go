package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"golang.org/x/sync/singleflight"
)

const (
	sberBaseURL  = "https://gigachat.devices.sberbank.ru"
	sberTokenURL = sberBaseURL + "/api/v1/oauth"
	sberChatPath = "/api/v1/chat/completions"
	// sberTokenSkew refreshes the access token 5 min before its real expiry
	// to avoid a 401 mid-request.
	sberTokenSkew = 5 * time.Minute
	// sberTokenRefreshTimeout bounds one OAuth token exchange. It replaces
	// the former http.Client.Timeout, which also covered response-body reads
	// and therefore killed streaming responses; per-call liveness is bounded
	// by context deadlines instead, never by a client-wide timeout.
	sberTokenRefreshTimeout = 10 * time.Second
)

// Sber adapter for Sber GigaChat (HQ Moscow, RU). Most complex sovereign
// adapter because of:
//  1. Mutual-TLS: client certificate required on every call (incl. token
//     exchange). The cert/key are loaded once at construction and handed to
//     the upstream pool via TLSConfigProvider, so the pool composes mTLS ON
//     TOP of its SSRF-guarded transport instead of dropping the guard.
//  2. OAuth2 client-credentials flow: short-lived access token (~30 min),
//     refreshed transparently and deduplicated by singleflight, on a detached
//     context so one caller's disconnect cannot abort the shared refresh.
//
// Construction requires the cert/key paths. The factory NewSber() reads
// SBER_CLIENT_CERT / SBER_CLIENT_KEY env vars; if absent it returns a
// best-effort adapter with a plain (non-mTLS) client (good for tests against
// a plain httptest server; production MUST set the env vars).
//
// Sovereignty tier: full (RU jurisdiction).
type Sber struct {
	// httpClient performs the OAuth token exchange; in production it carries
	// the mTLS transport, built on the shared SSRF transport constructor.
	httpClient *http.Client
	// tlsConfig is the mTLS keypair exposed to the upstream pool via
	// TLSConfigProvider. Nil in the dev/test (no-cert) mode.
	tlsConfig *tls.Config
	// poolClient, when non-nil, replaces the upstream pool's HTTP client
	// entirely (ClientProvider). Only NewSberWithClient (test hook) sets it;
	// production Sber leaves it nil so the pool's SSRF guard survives.
	poolClient *http.Client
	// refreshGroup deduplicates concurrent token refreshes so N cold callers
	// trigger exactly one exchange.
	refreshGroup singleflight.Group
	mu           sync.Mutex
	accessToken  string
	tokenExp     time.Time
	// pinMu guards pinnedTokenHosts: the D-4 exact literal-IP pins recorded
	// from operator-configured token endpoints. The token client's guarded
	// dialer waives the reserved-range verdict for exactly these addresses
	// (ssrf.AllowList.TrustsExactPin parity); hostnames are never recorded.
	pinMu            sync.Mutex
	pinnedTokenHosts map[string]struct{}
}

// ClientProvider is the OPTIONAL interface an adapter implements when it
// needs to replace the upstream pool's *http.Client wholesale. Because the
// replacement discards the pool's SSRF-guarded transport, production adapters
// should prefer TLSConfigProvider; ClientProvider remains for test injections.
type ClientProvider interface {
	HTTPClient() *http.Client
}

// TLSConfigProvider is the OPTIONAL interface for adapters that need custom
// TLS (e.g. Sber mTLS). The upstream pool composes the returned *tls.Config
// ON TOP of its SSRF-guarded transport, keeping dial-time guards active.
type TLSConfigProvider interface {
	TLSConfig() *tls.Config
}

// TLSConfig returns the mTLS keypair for the upstream pool, or nil when the
// adapter runs without client certificates (dev/test mode).
func (s *Sber) TLSConfig() *tls.Config { return s.tlsConfig }

// HTTPClient implements ClientProvider. It returns non-nil only for a
// test-injected client (NewSberWithClient); production Sber returns nil so
// the pool keeps its own SSRF-guarded transport with the mTLS TLS config
// composed on top.
func (s *Sber) HTTPClient() *http.Client { return s.poolClient }

// NewSber constructs a Sber adapter. Reads SBER_CLIENT_CERT / SBER_CLIENT_KEY
// for the mTLS keypair; if both are set, builds a TLS-configured client. If
// absent, returns a default-client adapter (test/development only).
func NewSber() (*Sber, error) {
	certPath := getenv("SBER_CLIENT_CERT")
	keyPath := getenv("SBER_CLIENT_KEY")
	s := &Sber{pinnedTokenHosts: map[string]struct{}{}}
	if certPath == "" || keyPath == "" {
		s.httpClient = newSberHTTPClient(nil, s.trustedTokenHost)
		return s, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("sber: load mTLS keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	s.tlsConfig = cfg
	s.httpClient = newSberHTTPClient(cfg, s.trustedTokenHost)
	return s, nil
}

// newSberHTTPClient builds the OAuth token-exchange client. N01-P07: the
// transport previously ran in the legacy/dev mode (GuardDialedIP unset), so
// the token URL bypassed both the allowlist and the dial-time guard that
// protect the chat path (pkg/upstream). The guarded dialer is now mandatory
// and the only waiver is the D-4 exact literal-IP pin recorded from the
// operator-configured base URL (see recordTokenHost).
//
// Proxy stays nil: pkg/ssrf forbids environment proxy settings as a
// substitute for an allow-list-checked URL; an explicit validated proxy can
// be introduced later (upstream.Options.ProxyURL pattern).
//
// No http.Client.Timeout: a client-wide timeout bounds response-body reads
// and would truncate streams; lifetimes are bounded per call via contexts.
func newSberHTTPClient(tlsCfg *tls.Config, trustedExactHosts func(host string) bool) *http.Client {
	tr := ssrf.NewTransport(ssrf.TransportOptions{
		DialTimeout:           10 * time.Second,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		GuardDialedIP:         true,
		TrustedExactHosts:     trustedExactHosts,
	})
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{Transport: tr}
}

// NewSberWithClient is the test hook: inject a pre-configured client
// (httptest, custom CA, etc.). The injected client also replaces the
// upstream pool's client via ClientProvider, which is acceptable for tests
// only — production must use NewSber.
func NewSberWithClient(c *http.Client) *Sber {
	if c == nil {
		c = newSberHTTPClient(nil, nil)
	}
	return &Sber{httpClient: c, poolClient: c, pinnedTokenHosts: map[string]struct{}{}}
}

func (*Sber) Name() string { return "sber" }

func (*Sber) Path(_ bool) string { return sberChatPath }

func (s *Sber) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	// apiKey is the OAuth2 client_secret (Basic-auth user; password empty).
	//nolint:contextcheck // the refresh deliberately runs on a detached, self-bounded context (W-PROV) — the first caller's request ctx must not own the shared token exchange
	if err := s.ensureToken(baseURL, apiKey); err != nil {
		return nil, fmt.Errorf("sber: ensure token: %w", err)
	}
	if baseURL == "" {
		baseURL = sberBaseURL
	}
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build sber request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

// ensureToken returns quickly when the cached token is still fresh; otherwise
// it joins a singleflight refresh so N concurrent cold callers share exactly
// one exchange. The refresh itself never runs under the first caller's
// request context.
func (s *Sber) ensureToken(baseURL, clientSecret string) error {
	if s.tokenFresh() {
		return nil
	}
	_, err, _ := s.refreshGroup.Do(sberRefreshKey(baseURL, clientSecret), func() (any, error) {
		// Double-check: a waiter that joined after the winner's refresh
		// completed must not exchange again while the token is FRESH — an
		// expired-but-present token must still trigger a real refresh.
		if s.tokenFresh() {
			return struct{}{}, nil
		}
		if err := s.refreshToken(baseURL, clientSecret); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	})
	return err
}

// sberRefreshKey scopes one singleflight refresh to a token URL + secret pair
// so callers hitting different base URLs never share a wrong token.
func sberRefreshKey(baseURL, clientSecret string) string {
	return strings.TrimRight(baseURL, "/") + "|" + clientSecret
}

// tokenFresh reports whether the cached token is present and outside the
// refresh skew window.
func (s *Sber) tokenFresh() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accessToken != "" && time.Now().Before(s.tokenExp.Add(-sberTokenSkew))
}

// refreshToken performs the OAuth client-credentials exchange on a detached,
// self-bounded context: it must not inherit the first caller's request
// lifetime, because that caller disconnecting would abort the shared refresh
// every concurrent waiter depends on. Results are stored under s.mu.
func (s *Sber) refreshToken(baseURL, clientSecret string) error {
	tokenURL := sberTokenURL
	if baseURL != "" {
		tokenURL = strings.TrimRight(baseURL, "/") + "/api/v1/oauth"
	}
	s.recordTokenHost(tokenURL)
	refreshCtx, cancel := context.WithTimeout(context.Background(), sberTokenRefreshTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, tokenURL, nil)
	if err != nil {
		return err
	}
	basic := base64.StdEncoding.EncodeToString([]byte(clientSecret + ":"))
	req.Header.Set("Authorization", "Basic "+basic)
	req.Header.Set("RqUID", uuid.NewString())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token exchange HTTP %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"` // epoch millis
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("empty access_token in response")
	}
	s.mu.Lock()
	s.accessToken = tok.AccessToken
	if tok.ExpiresAt > 0 {
		s.tokenExp = time.UnixMilli(tok.ExpiresAt)
	} else {
		// Defensive default if upstream omits expires_at.
		s.tokenExp = time.Now().Add(25 * time.Minute)
	}
	s.mu.Unlock()
	return nil
}

func (*Sber) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (*Sber) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (*Sber) TranslateResponse(b []byte) ([]byte, error) { return b, nil }

// recordTokenHost pins the D-4 exact literal-IP form of the operator-
// configured token endpoint host so the token client's guarded dialer
// waives the reserved-range verdict for exactly that address. Hostnames are
// deliberately not recorded: their DNS answers are not operator-controlled,
// so the rebinding-window check stays active for them
// (ssrf.AllowList.TrustsExactPin parity).
func (s *Sber) recordTokenHost(tokenURL string) {
	parsed, err := url.Parse(tokenURL)
	if err != nil {
		return
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || net.ParseIP(host) == nil {
		return
	}
	s.pinMu.Lock()
	defer s.pinMu.Unlock()
	if s.pinnedTokenHosts == nil {
		s.pinnedTokenHosts = map[string]struct{}{}
	}
	s.pinnedTokenHosts[host] = struct{}{}
}

// trustedTokenHost is the TransportOptions.TrustedExactHosts predicate for
// the token-exchange client: true only for recorded literal-IP pins.
func (s *Sber) trustedTokenHost(host string) bool {
	s.pinMu.Lock()
	defer s.pinMu.Unlock()
	_, ok := s.pinnedTokenHosts[strings.ToLower(host)]
	return ok
}

// getenv returns os.Getenv; factored out for testability.
func getenv(key string) string { return osGetenv(key) }
