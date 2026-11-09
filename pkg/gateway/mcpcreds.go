package cli

// MC-2 (MCP-CREDENTIALS-PLAN-2026-10-05): the gateway-side credential source
// the MCP proxy calls per invoke. Resolution order: the agent's per-user
// credential (active) → the server-level credential (enabled) → none (the
// legacy unauthenticated posture).
//
// Cache mechanics (OrgCredsVersionStore parity, upstream.go): the probe
// caches the secret-free DECISION per (org, server, agent) — does a usable
// credential exist, at which level, of which kind. Positives are reused
// while the org's Redis version (mcpcreds:ver:<orgID>, bumped by the admin
// CRUD) is unchanged; negatives and version-less entries re-probe at the
// TTL. The PLAINTEXT is never cached: every apply decrypts per request via
// the store (the same discipline as the BYOK org-key chain), and the store
// read stays authoritative (a row that went needs_reauth/orphaned misses and
// the entry self-corrects).
//
// On an upstream 401/403 the source runs the single force-refresh round for
// per-user oauth credentials: the token endpoint (validated against the same
// SSRF allow-list as the server URL) is called with the server-level client
// configuration and the stored refresh token. A terminally dead token is
// marked needs_reauth (sticky — only an explicit re-submit/re-auth returns
// the row to active) and audited.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// MCPCredsVersionStore is the org-level cache-invalidation contract for the
// MCP credential cache (the MCPCredsVersionBumper twin in the admin
// handlers). Redis key "mcpcreds:ver:<orgID>", decimal int64, 7-day TTL —
// the OrgCredsVersionStore mechanics verbatim.
type MCPCredsVersionStore interface {
	GetMCPCredsVersion(ctx context.Context, orgID string) (int64, error)
	SetMCPCredsVersion(ctx context.Context, orgID string, version int64) error
}

// mcpCredsVersionKeyPrefix is the Redis key namespace of the contract above.
//
//nolint:gosec // false positive: a Redis key namespace (an invalidation version), not a credential
const mcpCredsVersionKeyPrefix = "mcpcreds:ver:"

// mcpCredsVersionTTL bounds the Redis retention of one org's version key;
// every Set refreshes it. Expiry is harmless: a missing key reads as 0 and a
// 0 != cached-version comparison only forces a re-probe.
const mcpCredsVersionTTL = 7 * 24 * time.Hour

// mcpCredsProbeTTL is the hard staleness bound of the negative (and, without
// a reachable version store, positive) probe decisions.
const mcpCredsProbeTTL = 30 * time.Second

// redisMCPCredsVersions is the production MCPCredsVersionStore over the same
// OrgCredsRedis surface as the BYOK version store.
type redisMCPCredsVersions struct {
	rdb OrgCredsRedis
	log *slog.Logger
}

// NewMCPCredsVersionStore builds the Redis-backed MCP credential version
// for the gateway probe.
func NewMCPCredsVersionStore(rdb OrgCredsRedis, l *slog.Logger) MCPCredsVersionStore {
	return &redisMCPCredsVersions{rdb: rdb, log: l}
}

func (s *redisMCPCredsVersions) key(orgID string) string {
	return mcpCredsVersionKeyPrefix + orgID
}

// GetMCPCredsVersion reads the org's current MCP credential version. A
// missing key is version 0, not an error (fresh org / expired key).
func (s *redisMCPCredsVersions) GetMCPCredsVersion(ctx context.Context, orgID string) (int64, error) {
	v, err := s.rdb.Get(ctx, s.key(orgID)).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read mcp creds version: %w", err)
	}
	return parseVersion(v)
}

// SetMCPCredsVersion records a new MCP credential version for the org.
func (s *redisMCPCredsVersions) SetMCPCredsVersion(ctx context.Context, orgID string, version int64) error {
	if err := s.rdb.Set(ctx, s.key(orgID), formatVersion(version), mcpCredsVersionTTL).Err(); err != nil {
		return fmt.Errorf("write mcp creds version: %w", err)
	}
	return nil
}

func parseVersion(v string) (int64, error) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse mcp creds version %q: %w", v, err)
	}
	return n, nil
}

func formatVersion(v int64) string { return strconv.FormatInt(v, 10) }

// MCPCredsStore is the request-path slice of the adminstore the source
// consumes (frozen MC-1 methods plus the migration-0016 mode lookup; the
// *adminstore.Store compile pin below enforces the implementation).
// Resolve* are the only plaintext egress points.
type MCPCredsStore interface {
	ResolveMCPUserSecret(ctx context.Context, orgID, serverName, agentKeyID string) (secret, kind string, version int64, ok bool, err error)
	ResolveMCPServerSecret(ctx context.Context, orgID, serverName string) (secret, kind string, version int64, ok bool, err error)
	// MCPServerCredentialMode reads the connection configuration's
	// credential mode (N05-P02-T02, I54): auto = legacy chain, service =
	// service credential only, delegated = user credential only (never a
	// silent escalation). ok=false when the server row is absent.
	MCPServerCredentialMode(ctx context.Context, orgID, serverName string) (mode string, configVersion int64, ok bool, err error)
	// StoreMCPUserCredVerifier persists the encrypted PKCE code_verifier on
	// the agent's row (N05-P02-T03, RFC 7636).
	StoreMCPUserCredVerifier(ctx context.Context, orgID, serverName, agentKeyID, verifier string) error
	// ConsumeMCPUserCredVerifier reads and clears the pending verifier
	// (single use). ok=false: no pending verifier — exchange without
	// code_verifier (pre-0017 rows).
	ConsumeMCPUserCredVerifier(ctx context.Context, orgID, serverName, agentKeyID string) (verifier string, ok bool, err error)
	GetMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID string) (adminstore.MCPUserCredential, error)
	UpsertMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID, kind, plaintextSecret string, expiresAt *time.Time) (adminstore.MCPUserCredential, error)
	DeleteMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID string) error
	CreatePendingMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID, state string) (adminstore.MCPUserCredential, error)
	FindMCPUserCredentialByState(ctx context.Context, orgID, state string) (adminstore.MCPUserCredential, error)
	UpdateMCPUserOAuthTokens(ctx context.Context, orgID, serverName, agentKeyID, tokenJSON string, expiresAt *time.Time) (adminstore.MCPUserCredential, error)
	SetMCPUserCredentialStatus(ctx context.Context, orgID, serverName, agentKeyID, status string) error
	InsertAuditLogEntry(ctx context.Context, rec adminstore.AuditLogEntryRecord) error
}

// compile pins: the production store implements the narrow surfaces.
var (
	_ MCPCredsStore        = (*adminstore.Store)(nil)
	_ mcpagg.CredSource    = (*mcpCredsSource)(nil)
	_ MCPCredsVersionStore = (*redisMCPCredsVersions)(nil)
)

// probe levels.
const (
	mcpCredLevelUser   = "user"
	mcpCredLevelServer = "server"
)

// oauth refresh bounds.
const (
	mcpRefreshTimeout   = 5 * time.Second
	mcpRefreshDialBound = 5 * time.Second
	mcpRefreshMaxBody   = 64 * 1024
	mcpRefreshClientCap = 4
)

// mcpCredsProbeEntry is one cached decision: does (org, server, agent) have
// a usable credential, at which level and kind. No secret material.
type mcpCredsProbeEntry struct {
	version  int64 // the org version at load (0 = unknown)
	haveVer  bool
	ok       bool
	level    string
	kind     string
	loadedAt time.Time
}

// mcpCredsSource implements mcpagg.CredSource over the adminstore.
type mcpCredsSource struct {
	store    MCPCredsStore
	versions MCPCredsVersionStore // nil = TTL-only invalidation
	allow    urlGuard             // SSRF guard for oauth token endpoints
	ttl      time.Duration
	log      *slog.Logger

	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*mcpCredsProbeEntry
}

// urlGuard validates one URL against the MCP egress allow-list (the same
// guard as the server URL — a credential never widens the surface).
type urlGuard func(ctx context.Context, rawURL string) error

// mcpTokenURLGuard binds the MCP SSRF allow-list into the source's URL
// guard: an oauth token endpoint must pass the SAME https-only + domain
// allow-list + reserved-IP checks as the server URLs it authorizes — a
// credential never widens the egress surface.
func mcpTokenURLGuard(allow ssrf.AllowList) urlGuard {
	return func(_ context.Context, rawURL string) error {
		return mcpagg.ValidateURLAtInvoke(rawURL, allow, false) //nolint:contextcheck // bounded ssrf check — same call shape as mcpagg.Invoke (QG2-D3)
	}
}

// mcpCredsSourceConfig wires the source. allow is the SSRF allow-list the
// server URLs already pass (token endpoints are held to the same list).
type mcpCredsSourceConfig struct {
	Store    MCPCredsStore
	Versions MCPCredsVersionStore // nil = TTL-only
	Allow    urlGuard             // nil = refresh refuses every token endpoint (fail-closed)
	TTL      time.Duration
	Log      *slog.Logger
	// HTTPClient overrides the refresh client (hermetic tests only; nil
	// builds the bounded production client).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// newMCPCredsSource builds the credential source. A nil store makes every
// call fail closed — the source is only wired when a DB pool exists.
func newMCPCredsSource(cfg mcpCredsSourceConfig) *mcpCredsSource {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = mcpCredsProbeTTL
	}
	client := cfg.HTTPClient
	if client == nil {
		// The production OAuth egress client (A01): the token/revocation
		// bodies carry client_secret + refresh_token, so the connection
		// needs the SAME protection as the MCP proxy invokes — dial-time
		// reserved-IP verification (a DNS rebinding between the URL
		// allow-check and the connect is refused at dial time) and an
		// explicit proxy policy. Redirects are refused outright
		// (http.ErrUseLastResponse): a 307/308 would otherwise re-send the
		// secret-bearing body to whatever Location names — token endpoints
		// don't legitimately redirect, so refusal is the safer contract
		// (pkg/mcpagg/config.go Client() is the precedent). Hermetic tests
		// override HTTPClient with a plain loopback client.
		transport := ssrf.NewTransport(ssrf.TransportOptions{
			Proxy:                 http.ProxyFromEnvironment,
			DialTimeout:           mcpRefreshDialBound,
			TLSHandshakeTimeout:   mcpRefreshDialBound,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          mcpRefreshClientCap,
			IdleConnTimeout:       30 * time.Second,
			GuardDialedIP:         true,
		})
		client = &http.Client{
			Transport: transport,
			Timeout:   mcpRefreshTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &mcpCredsSource{
		store:    cfg.Store,
		versions: cfg.Versions,
		allow:    cfg.Allow,
		ttl:      ttl,
		log:      cfg.Log,
		client:   client,
		now:      now,
		entries:  make(map[string]*mcpCredsProbeEntry),
	}
}

// probeKey is the cache map key.
func probeKey(orgID, serverName, agentID string) string {
	return orgID + "\x00" + serverName + "\x00" + agentID
}

// orgVersion reads the org's Redis version (0 when the store is nil or
// errors — TTL-only degradation, orgCredsProbe parity).
func (s *mcpCredsSource) orgVersion(ctx context.Context, orgID string) (int64, bool) {
	if s.versions == nil {
		return 0, false
	}
	v, err := s.versions.GetMCPCredsVersion(ctx, orgID)
	if err != nil {
		if s.log != nil {
			s.log.Warn("mcp creds version read failed; probe degrades to TTL", "org_id", orgID, "error", err.Error())
		}
		return 0, false
	}
	return v, true
}

// cachedDecision returns the cached entry when it is still fresh: positives
// while the org version is unchanged (or unknown — TTL bound; the admin CRUD
// bump clears a positive immediately); negatives only within the TTL (a
// stale negative would silently keep a new credential unused, so it never
// outlives the TTL — negatives never take the version fast path, the
// orgCredsProbe polarity policy).
func (s *mcpCredsSource) cachedDecision(ctx context.Context, orgID, serverName, agentID string) (*mcpCredsProbeEntry, bool) {
	key := probeKey(orgID, serverName, agentID)
	now := s.now()
	s.mu.Lock()
	entry, ok := s.entries[key]
	s.mu.Unlock()
	if !ok || entry == nil || now.Sub(entry.loadedAt) >= s.ttl {
		return nil, false
	}
	if !entry.ok {
		return entry, true // negative: load-shed within the TTL
	}
	if version, haveVer := s.orgVersion(ctx, orgID); haveVer && entry.haveVer && version != entry.version {
		return nil, false // the org's credentials changed — re-probe
	}
	return entry, true
}

// storeDecision caches one resolution outcome.
func (s *mcpCredsSource) storeDecision(orgID, serverName, agentID string, e *mcpCredsProbeEntry) {
	key := probeKey(orgID, serverName, agentID)
	e.loadedAt = s.now()
	s.mu.Lock()
	s.entries[key] = e
	s.mu.Unlock()
}

// resolveFresh runs the authoritative per-request resolution (user →
// server), returning the decrypted secret with its level and kind, or
// ok=false when the org holds no USABLE credential. A server-level oauth
// credential that is client-configuration only (no access_token) is not
// usable on the request path — it feeds the MC-3 flows, not direct calls.
func (s *mcpCredsSource) resolveFresh(ctx context.Context, orgID, serverName, agentID string) (secret, kind, level string, ok bool, err error) {
	// The connection configuration's credential mode gates which layer may
	// authorize this invoke (N05-P02-T02, I54). A lookup failure is
	// fail-closed (returned as an infrastructure error — the proxy refuses
	// to egress rather than guess the mode).
	mode, _, err := s.serverCredMode(ctx, orgID, serverName)
	if err != nil {
		return "", "", "", false, err
	}
	// service: the org/project service credential only — the user layer is
	// never consulted, so a partial user state cannot change the outcome.
	if mode == mcpagg.CredModeService {
		plain, kind, _, ok, err := s.store.ResolveMCPServerSecret(ctx, orgID, serverName)
		if err != nil || !ok || !credApplicable(kind, plain) {
			return "", "", "", false, err
		}
		return plain, kind, mcpCredLevelServer, true, nil
	}
	// delegated: the user credential only. A missing/unusable user
	// credential NEVER falls back to the more privileged service credential
	// (I54 negative) — the invoke misses and the lazy-authorization flow
	// takes over.
	if mode == mcpagg.CredModeDelegated {
		if plain, kind, _, ok, err := s.store.ResolveMCPUserSecret(ctx, orgID, serverName, agentID); err != nil {
			return "", "", "", false, err
		} else if ok && credApplicable(kind, plain) {
			return plain, kind, mcpCredLevelUser, true, nil
		}
		return "", "", "", false, nil
	}
	// auto (default): the legacy chain — per-user active → server-level
	// enabled → none, byte-for-byte the pre-0016 behavior.
	if plain, kind, _, ok, err := s.store.ResolveMCPUserSecret(ctx, orgID, serverName, agentID); err != nil {
		return "", "", "", false, err
	} else if ok && credApplicable(kind, plain) {
		return plain, kind, mcpCredLevelUser, true, nil
	}
	plain, kind, _, ok, err := s.store.ResolveMCPServerSecret(ctx, orgID, serverName)
	if err != nil || !ok || !credApplicable(kind, plain) {
		return "", "", "", false, err
	}
	return plain, kind, mcpCredLevelServer, true, nil
}

// serverCredMode reads the server's credential mode ("" → auto: rows read
// outside a migrated schema keep the legacy chain).
func (s *mcpCredsSource) serverCredMode(ctx context.Context, orgID, serverName string) (string, int64, error) {
	mode, version, _, err := s.store.MCPServerCredentialMode(ctx, orgID, serverName)
	if err != nil {
		return "", 0, fmt.Errorf("read mcp server credential mode: %w", err)
	}
	if mode == "" {
		mode = mcpagg.CredModeAuto
	}
	return mode, version, nil
}

// credApplicable reports whether a decrypted payload can authorize a call:
// headers always (store-validated), oauth only with token material.
func credApplicable(kind, plain string) bool {
	if kind != mcpagg.CredKindOAuth {
		return true
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(plain), &tok); err != nil {
		return false
	}
	return tok.AccessToken != ""
}

// AuthHeaders implements mcpagg.CredSource. (nil, "", nil) = no usable
// credential — the proxy proceeds unauthenticated and the upstream verdict
// decides.
func (s *mcpCredsSource) AuthHeaders(ctx context.Context, orgID, serverName, agentID string) (map[string][]string, string, error) {
	if s.store == nil {
		return nil, mcpagg.CredKindNone, fmt.Errorf("mcp credential store is not available")
	}
	if entry, ok := s.cachedDecision(ctx, orgID, serverName, agentID); ok && !entry.ok {
		// Negative decision (fresh within the TTL): no usable credential.
		return nil, mcpagg.CredKindNone, nil
	}
	// The store read stays authoritative on every request (the plaintext is
	// never cached): a row that lost its usable status misses here even when
	// the probe still holds a positive decision.
	plain, kind, level, ok, err := s.resolveFresh(ctx, orgID, serverName, agentID)
	if err != nil {
		return nil, mcpagg.CredKindNone, err
	}
	if !ok {
		s.storeDecision(orgID, serverName, agentID, &mcpCredsProbeEntry{ok: false})
		return nil, mcpagg.CredKindNone, nil
	}
	version, haveVer := s.orgVersion(ctx, orgID)
	s.storeDecision(orgID, serverName, agentID, &mcpCredsProbeEntry{
		version: version, haveVer: haveVer, ok: true, level: level, kind: kind,
	})
	headers, err := buildAuthHeaders(kind, plain)
	if err != nil {
		return nil, kind, err
	}
	return headers, kind, nil
}

// OnUpstreamUnauthorized implements mcpagg.CredSource: the single 401/403
// recovery round. Server-level credentials do not self-refresh (the operator
// rotates them; a per-user credential can overlay a working value). Per-user
// oauth force-refreshes once; per-user headers and terminally rejected
// tokens are marked needs_reauth (sticky) and audited.
func (s *mcpCredsSource) OnUpstreamUnauthorized(ctx context.Context, orgID, serverName, agentID, kind string) (map[string][]string, bool, error) {
	if s.store == nil {
		return nil, false, fmt.Errorf("mcp credential store is not available")
	}
	entry, cached := s.cachedDecision(ctx, orgID, serverName, agentID)
	level := mcpCredLevelUser
	if cached && entry.level != "" {
		level = entry.level
	}
	if level == mcpCredLevelServer {
		return nil, false, nil
	}
	if kind != mcpagg.CredKindOAuth {
		// Headers credentials carry no refresh mechanics: the stored value
		// was rejected → needs_reauth until the agent re-submits.
		if err := s.markNeedsReauth(ctx, orgID, serverName, agentID, kind, "upstream rejected the stored credential"); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	return s.refreshUserOAuth(ctx, orgID, serverName, agentID)
}

// refreshUserOAuth runs the oauth force-refresh: the server-level credential
// carries the client configuration (client_id, client_secret, token_url),
// the user row carries the refresh_token. On success the row is rotated
// (active, version bump) and the retry proceeds with the new token; on a
// terminal rejection the row is marked needs_reauth (sticky) and audited.
func (s *mcpCredsSource) refreshUserOAuth(ctx context.Context, orgID, serverName, agentID string) (map[string][]string, bool, error) {
	row, err := s.store.GetMCPUserCredential(ctx, orgID, serverName, agentID)
	if err != nil {
		if adminstore.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("load mcp user credential: %w", err)
	}
	userPlain, _, _, ok, err := s.store.ResolveMCPUserSecret(ctx, orgID, serverName, agentID)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	var userTok struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal([]byte(userPlain), &userTok)

	var srvCfg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		TokenURL     string `json:"token_url"`
	}
	srvPlain, _, _, ok, err := s.store.ResolveMCPServerSecret(ctx, orgID, serverName)
	if err != nil {
		return nil, false, err
	}
	if ok {
		_ = json.Unmarshal([]byte(srvPlain), &srvCfg)
	}

	refreshToken := userTok.RefreshToken
	if refreshToken == "" || srvCfg.TokenURL == "" || srvCfg.ClientID == "" {
		if err := s.markNeedsReauth(ctx, orgID, serverName, agentID, mcpagg.CredKindOAuth, "oauth refresh is not possible (missing refresh token or server client configuration)"); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}

	newTokens, permanent, err := s.postTokenRefresh(ctx, oauthClientConfig{
		ClientID:     srvCfg.ClientID,
		ClientSecret: srvCfg.ClientSecret,
		TokenURL:     srvCfg.TokenURL,
	}, refreshToken)
	if err != nil {
		// Typed failures leave the stored grant byte-identical: no token
		// overwrite, no needs_reauth. Transient ones (5xx/429/connection)
		// wait on the existing bounded policy — one force-refresh per
		// upstream 401/403, never a retry loop here; a refused redirect
		// (F2, permanent misconfiguration) surfaces as an error instead.
		if isTransientTokenEndpointError(err) && s.log != nil {
			s.log.Warn("mcp oauth refresh deferred: token endpoint transient failure",
				"server", serverName, "error", err.Error())
		}
		return nil, false, err
	}
	if permanent {
		if err := s.markNeedsReauth(ctx, orgID, serverName, agentID, mcpagg.CredKindOAuth, "the oauth provider rejected the refresh token"); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if newTokens.AccessToken == "" {
		// Contract invariant: postTokenForm returns success only with token
		// material. Belt and braces (A02): refuse to persist an
		// access-token-less payload over a live credential.
		return nil, false, fmt.Errorf("refreshed mcp oauth payload carries no access token; stored credential left untouched")
	}
	if newTokens.RefreshToken == "" {
		// RFC 6749 §6: a refresh response MAY omit refresh_token — the
		// presented one stays valid (A03). Preserve it so the NEXT refresh
		// still works; when the provider rotates, the new value is
		// accepted as-is (it is already in newTokens).
		newTokens.RefreshToken = refreshToken
	}

	payload, _ := json.Marshal(newTokens) //nolint:gosec // G117: this IS the at-rest token write path (enc: envelope applied by the store)
	var expiresAt *time.Time
	if newTokens.ExpiresIn > 0 {
		t := s.now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)
		expiresAt = &t
	}
	if _, err := s.store.UpdateMCPUserOAuthTokens(ctx, orgID, serverName, agentID, string(payload), expiresAt); err != nil {
		return nil, false, fmt.Errorf("store refreshed mcp oauth tokens: %w", err)
	}
	s.audit(ctx, orgID, serverName, agentID, "mcp_user_credential_refresh",
		fmt.Sprintf("server=%s,agent=%s,kind=oauth,last4=%s", serverName, agentID, row.SecretLast4))
	headers, err := buildAuthHeaders(mcpagg.CredKindOAuth, string(payload))
	if err != nil {
		return nil, false, err
	}
	return headers, true, nil
}

// refreshedTokens is the token-endpoint response subset the source keeps.
type refreshedTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

// oauthClientConfig is the server-level oauth client configuration the
// refresh grant needs.
type oauthClientConfig struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
}

// postTokenRefresh POSTs the refresh grant. permanent=true means the grant
// is dead at the provider (invalid_grant / 4xx, nil error) or the token URL
// itself redirects (3xx, typed *tokenEndpointRedirectError — F2); transport
// errors are infrastructure (false, err).
func (s *mcpCredsSource) postTokenRefresh(ctx context.Context, cfg oauthClientConfig, refreshToken string) (tokens refreshedTokens, permanent bool, err error) {
	if s.allow != nil {
		// A disallowed token endpoint can never work — treat as terminal
		// misconfiguration (nilerr: the refusal is the intended outcome).
		if gErr := s.allow(ctx, cfg.TokenURL); gErr != nil {
			return refreshedTokens{}, true, nil //nolint:nilerr // intentional: terminal refusal, not an error
		}
	} else {
		return refreshedTokens{}, true, nil // no guard wired: fail closed
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	return s.postTokenForm(ctx, cfg, form)
}

// tokenEndpointError marks a TRANSIENT token-endpoint failure (A02): a 5xx
// provider-side failure, 429 backpressure, or a connection/read/decode
// error. The grant itself is not dead — the caller must leave the stored
// credential untouched (no overwrite, no needs_reauth); a 4xx grant
// rejection is NOT transient (permanent=true, nil error), and a 3xx refused
// redirect is permanent WITH a typed error (*tokenEndpointRedirectError,
// F2) — neither is this type.
type tokenEndpointError struct {
	status int   // HTTP status when the endpoint answered; 0 = transport/read/decode
	cause  error // wrapped cause (url.Error, body read, json decode)
}

func (e *tokenEndpointError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("oauth token endpoint transient failure (status %d)", e.status)
	}
	if e.cause != nil {
		return fmt.Sprintf("oauth token endpoint unreachable (transient): %v", e.cause)
	}
	return "oauth token endpoint unreachable (transient)"
}

func (e *tokenEndpointError) Unwrap() error { return e.cause }

// isTransientTokenEndpointError reports whether err is (or wraps) a typed
// transient token-endpoint failure.
func isTransientTokenEndpointError(err error) bool {
	var tee *tokenEndpointError
	return errors.As(err, &tee)
}

// tokenEndpointRedirectError marks a REFUSED-REDIRECT outcome (F2, R1-sec
// 2026-11-01): the token endpoint answered 3xx. The egress client refuses
// every redirect hop (http.ErrUseLastResponse), so a 3xx can only mean the
// configured token URL itself points at a redirector — a permanent
// misconfiguration no retry can fix, hence permanent=true WITH a typed
// error (never *tokenEndpointError transient). The message names the status
// only; Location is never echoed (attacker-chosen material, never
// contacted).
type tokenEndpointRedirectError struct {
	status int
}

func (e *tokenEndpointRedirectError) Error() string {
	return fmt.Sprintf("oauth token endpoint redirect refused (status %d): token endpoints must answer directly; check the configured token url", e.status)
}

// postTokenForm POSTs one token-endpoint grant form. Outcome contract:
//   - 2xx with an access token → (tokens, false, nil);
//   - 4xx (the grant itself rejected, invalid_grant family) and 2xx without
//     token material → (zero, true, nil) — terminal, the caller pins
//     needs_reauth;
//   - 3xx (refused redirect: the token URL itself points at a redirector)
//     → (zero, true, *tokenEndpointRedirectError) — PERMANENT
//     misconfiguration with a typed, status-naming error; callers surface
//     the error and leave the stored credential untouched;
//   - 5xx, 429, transport/read/decode failures → (zero, false,
//     *tokenEndpointError) — TRANSIENT: the stored credential must not be
//     modified, and the message carries status/driver text only, never form
//     or token material.
func (s *mcpCredsSource) postTokenForm(ctx context.Context, cfg oauthClientConfig, form url.Values) (tokens refreshedTokens, permanent bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return refreshedTokens{}, true, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return refreshedTokens{}, false, &tokenEndpointError{cause: fmt.Errorf("oauth token refresh: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, mcpRefreshMaxBody))
	if err != nil {
		return refreshedTokens{}, false, &tokenEndpointError{cause: fmt.Errorf("read oauth token response: %w", err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// 429 is backpressure, not a grant verdict — transient with the
		// other 5xx-family failures. Other 4xx = the grant itself is
		// rejected (invalid_grant family) — terminal.
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return refreshedTokens{}, false, &tokenEndpointError{status: resp.StatusCode}
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// F2: redirects are refused outright (http.ErrUseLastResponse),
			// so a 3xx here means the token URL itself redirects — a
			// permanent misconfiguration, typed and terminal, never an
			// empty-success fall-through.
			return refreshedTokens{}, true, &tokenEndpointRedirectError{status: resp.StatusCode}
		}
		return refreshedTokens{}, resp.StatusCode >= 400 && resp.StatusCode < 500, nil
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return refreshedTokens{}, false, &tokenEndpointError{cause: fmt.Errorf("decode oauth token response: %w", err)}
	}
	if tokens.AccessToken == "" {
		return refreshedTokens{}, true, nil
	}
	if tokens.TokenType == "" {
		tokens.TokenType = "Bearer"
	}
	return tokens, false, nil
}

// markNeedsReauth flips the agent's row to needs_reauth (sticky) and writes
// the hash-chained audit record. A failed audit is logged, never fatal — the
// status flip is the security-relevant fact.
func (s *mcpCredsSource) markNeedsReauth(ctx context.Context, orgID, serverName, agentID, kind, reason string) error {
	if err := s.store.SetMCPUserCredentialStatus(ctx, orgID, serverName, agentID, adminstore.MCPUserCredStatusNeedsReauth); err != nil {
		if adminstore.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("mark mcp credential needs_reauth: %w", err)
	}
	s.audit(ctx, orgID, serverName, agentID, "mcp_user_credential_needs_reauth",
		fmt.Sprintf("server=%s,agent=%s,kind=%s,reason=%s", serverName, agentID, kind, reason))
	return nil
}

// audit writes one hash-chained journal record (the admin audit protocol);
// failures degrade to a log line.
func (s *mcpCredsSource) audit(ctx context.Context, orgID, serverName, agentID, action, details string) {
	s.auditReason(ctx, orgID, serverName, agentID, action, details, "")
}

// auditReason is audit with the operator reason (the gateway flows accept
// X-Audit-Reason like the admin surface). The row ID is generated here (the
// shared append protocol inserts it verbatim — an empty ID would collide on
// the primary key with every second row).
func (s *mcpCredsSource) auditReason(ctx context.Context, orgID, serverName, agentID, action, details, reason string) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		if s.log != nil {
			s.log.Warn("mcp credential audit id generation failed; row dropped", "org_id", orgID, "action", action, "error", err.Error())
		}
		return
	}
	err := s.store.InsertAuditLogEntry(ctx, adminstore.AuditLogEntryRecord{
		ID:       hex.EncodeToString(id),
		Action:   action,
		Resource: "mcp_user_credential",
		Details:  details + ",org=" + orgID,
		AdminID:  agentID,
		Reason:   reason,
	})
	if err != nil && s.log != nil {
		s.log.Warn("mcp credential audit write failed", "org_id", orgID, "action", action, "error", err.Error())
	}
}

// buildAuthHeaders converts a decrypted credential payload into outbound
// headers. headers kind: a JSON object of header names to string values;
// oauth kind: {access_token, token_type} → the Authorization header. The
// payload is store-validated at write time; parsing here is fail-closed.
func buildAuthHeaders(kind, secretJSON string) (map[string][]string, error) {
	switch kind {
	case mcpagg.CredKindHeaders:
		var raw map[string]any
		if err := json.Unmarshal([]byte(secretJSON), &raw); err != nil {
			return nil, fmt.Errorf("decode mcp headers credential: %w", err)
		}
		headers := make(map[string][]string, len(raw))
		for name, v := range raw {
			switch val := v.(type) {
			case string:
				if val != "" {
					headers[name] = []string{val}
				}
			case []any:
				vals := make([]string, 0, len(val))
				for _, item := range val {
					if s, ok := item.(string); ok && s != "" {
						vals = append(vals, s)
					}
				}
				if len(vals) > 0 {
					headers[name] = vals
				}
			}
		}
		if len(headers) == 0 {
			return nil, fmt.Errorf("mcp headers credential carries no usable values")
		}
		return headers, nil
	case mcpagg.CredKindOAuth:
		var tok struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		if err := json.Unmarshal([]byte(secretJSON), &tok); err != nil {
			return nil, fmt.Errorf("decode mcp oauth credential: %w", err)
		}
		if tok.AccessToken == "" {
			return nil, fmt.Errorf("mcp oauth credential carries no access token")
		}
		scheme := tok.TokenType
		if scheme == "" {
			scheme = "Bearer"
		}
		return map[string][]string{"Authorization": {scheme + " " + tok.AccessToken}}, nil
	default:
		return nil, fmt.Errorf("unknown mcp credential kind %q", kind)
	}
}

// ---------------------------------------------------------------------------
// MC-3: the lazy-authorization flow mechanics (submit / begin / callback).
// The HTTP handlers live in mcpcredflow.go; the source owns the store
// discipline (grant ceiling, state capability, audit) so every entry point
// shares it.
// ---------------------------------------------------------------------------

// flowStateBytes is the OAuth flow-state nonce size (32 hex chars).
const flowStateBytes = 16

// SubmitUserHeaders stores (or rotates) the agent's headers-kind credential
// for the server. The grant ceiling is enforced by the store (ErrNotFound);
// the org version bumps so the gateway's negative probe clears immediately,
// and the CRUD lands in the hash-chained audit journal with the operator
// reason (X-Audit-Reason, optional).
func (s *mcpCredsSource) SubmitUserHeaders(ctx context.Context, orgID, serverName, agentID, headersJSON, reason string) (adminstore.MCPUserCredential, error) {
	row, err := s.store.UpsertMCPUserCredential(ctx, orgID, serverName, agentID, mcpagg.CredKindHeaders, headersJSON, nil)
	if err != nil {
		return adminstore.MCPUserCredential{}, err
	}
	s.bumpOrgVersion(ctx, orgID)
	s.auditReason(ctx, orgID, serverName, agentID, "mcp_user_credential_upsert",
		fmt.Sprintf("server=%s,agent=%s,kind=headers,last4=%s", serverName, agentID, row.SecretLast4), reason)
	return row, nil
}

// DeleteUserCredential revokes the agent's credential on the server (audit
// + version bump parity with SubmitUserHeaders). The local delete is the
// authoritative access stop; the provider-side RFC 7009 revocation is
// best-effort afterwards — a dead/absent revocation endpoint must never
// keep the stored credential alive or fail the delete (the outcome is
// audited either way). The grant-lifecycle orphan path (OrphanMCPUser-
// Credentials) deliberately does NOT revoke — the restore path must keep
// working.
func (s *mcpCredsSource) DeleteUserCredential(ctx context.Context, orgID, serverName, agentID, reason string) error {
	plan, skip := s.planUserCredRevocation(ctx, orgID, serverName, agentID)
	if err := s.store.DeleteMCPUserCredential(ctx, orgID, serverName, agentID); err != nil {
		return err
	}
	s.bumpOrgVersion(ctx, orgID)
	outcome := "ok"
	switch {
	case plan == nil:
		outcome = "skipped(" + skip + ")"
	case !s.revokeUserCredAtProvider(ctx, *plan):
		outcome = "failed"
	}
	s.auditReason(ctx, orgID, serverName, agentID, "mcp_user_credential_delete",
		fmt.Sprintf("server=%s,agent=%s,revocation=%s", serverName, agentID, outcome), reason)
	return nil
}

// mcpRevocationPlan is the pre-captured material for one RFC 7009 revocation
// (RFC 7009 §2.1: the token plus the client's own authentication).
type mcpRevocationPlan struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Token        string
}

// planUserCredRevocation reads the (client config, token) pair a delete may
// revoke provider-side, BEFORE the local row disappears. A nil plan (with
// the skip reason) is returned when there is nothing to revoke: no enabled
// oauth client configuration, no revocation endpoint, an unreadable or
// non-oauth row, or a guard refusal — revocation never widens the egress
// surface.
func (s *mcpCredsSource) planUserCredRevocation(ctx context.Context, orgID, serverName, agentID string) (*mcpRevocationPlan, string) {
	cfg, complete, err := s.serverOAuthConfig(ctx, orgID, serverName)
	if err != nil || !complete || cfg.RevocationEndpoint == "" {
		return nil, "no-endpoint"
	}
	plain, kind, _, ok, err := s.store.ResolveMCPUserSecret(ctx, orgID, serverName, agentID)
	if err != nil || !ok || kind != mcpagg.CredKindOAuth {
		return nil, "no-token"
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(plain), &tok); err != nil || tok.AccessToken == "" {
		return nil, "no-token"
	}
	if s.allow != nil {
		if err := s.allow(ctx, cfg.RevocationEndpoint); err != nil {
			return nil, "guard-refused"
		}
	}
	return &mcpRevocationPlan{
		Endpoint:     cfg.RevocationEndpoint,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Token:        tok.AccessToken,
	}, ""
}

// revokeUserCredAtProvider POSTs the RFC 7009 revocation (token + hint +
// client auth) through the same guarded, redirect-refusing client as the
// token endpoint. Best-effort by contract: the boolean is the audited
// outcome, errors are logged with status-only detail (never body/secret
// material). Hint=access_token: RFC 7009 §2.1 allows the server to revoke
// the whole grant when tokens are linked.
func (s *mcpCredsSource) revokeUserCredAtProvider(ctx context.Context, plan mcpRevocationPlan) bool {
	form := url.Values{}
	form.Set("token", plan.Token)
	form.Set("token_type_hint", "access_token")
	form.Set("client_id", plan.ClientID)
	if plan.ClientSecret != "" {
		form.Set("client_secret", plan.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, plan.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		if s.log != nil {
			s.log.Warn("mcp credential provider revocation unreachable; local delete stands", "error", err.Error())
		}
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, mcpRefreshMaxBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if s.log != nil {
			s.log.Warn("mcp credential provider revocation refused", "status", resp.StatusCode)
		}
		return false
	}
	return true
}

// oauthServerConfig is the server-level oauth client configuration the flows
// need (client credentials + endpoints). redirectURI may carry an operator
// override; otherwise the handler derives it from the request origin.
type oauthServerConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       string
	RedirectURI  string
	// RevocationEndpoint is the RFC 7009 endpoint (optional — providers
	// without one simply skip the provider-side revoke; the local delete
	// stays the authoritative access stop).
	RevocationEndpoint string
}

// serverOAuthConfig loads and validates the org's server-level oauth
// credential. ok=false when the server has no ENABLED oauth credential.
func (s *mcpCredsSource) serverOAuthConfig(ctx context.Context, orgID, serverName string) (oauthServerConfig, bool, error) {
	plain, kind, _, ok, err := s.store.ResolveMCPServerSecret(ctx, orgID, serverName)
	if err != nil || !ok {
		return oauthServerConfig{}, false, err
	}
	if kind != mcpagg.CredKindOAuth {
		return oauthServerConfig{}, false, nil
	}
	var raw struct {
		ClientID           string `json:"client_id"`
		ClientSecret       string `json:"client_secret"`
		AuthURL            string `json:"auth_url"`
		TokenURL           string `json:"token_url"`
		Scopes             string `json:"scopes"`
		RedirectURI        string `json:"redirect_uri"`
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := json.Unmarshal([]byte(plain), &raw); err != nil {
		return oauthServerConfig{}, false, fmt.Errorf("decode mcp oauth server credential: %w", err)
	}
	return oauthServerConfig{
		ClientID: raw.ClientID, ClientSecret: raw.ClientSecret,
		AuthURL: raw.AuthURL, TokenURL: raw.TokenURL,
		Scopes: raw.Scopes, RedirectURI: raw.RedirectURI,
		RevocationEndpoint: raw.RevocationEndpoint,
	}, raw.AuthURL != "" && raw.TokenURL != "" && raw.ClientID != "", nil
}

// newPKCEVerifier returns an RFC 7636 code_verifier: 32 random bytes
// base64url-encoded (43 chars over the unreserved alphabet by construction).
func newPKCEVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate pkce code_verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// pkceChallengeS256 derives the S256 code_challenge:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), padding stripped.
func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// BeginUserOAuth plants the pending flow row and builds the consent URL the
// human opens. The grant ceiling is enforced by the store; the state nonce
// is the callback capability. The exchange is PKCE-protected (RFC 7636,
// S256): the gateway — the confidential client — generates the verifier,
// stores it encrypted on the pending row, and sends only the S256 challenge
// in the authorize URL; the verifier joins the token exchange at the callback
// and is consumed once.
func (s *mcpCredsSource) BeginUserOAuth(ctx context.Context, orgID, serverName, agentID, redirectURI string) (authorizeURL, state string, err error) {
	cfg, complete, err := s.serverOAuthConfig(ctx, orgID, serverName)
	if err != nil {
		return "", "", err
	}
	if !complete {
		return "", "", errMCPNoOAuthConfig
	}
	state, err = newFlowState()
	if err != nil {
		return "", "", err
	}
	verifier, err := newPKCEVerifier()
	if err != nil {
		return "", "", err
	}
	if _, err := s.store.CreatePendingMCPUserCredential(ctx, orgID, serverName, agentID, state); err != nil {
		return "", "", err
	}
	if err := s.store.StoreMCPUserCredVerifier(ctx, orgID, serverName, agentID, verifier); err != nil {
		return "", "", fmt.Errorf("store pkce verifier: %w", err)
	}
	if cfg.RedirectURI != "" {
		redirectURI = cfg.RedirectURI
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", pkceChallengeS256(verifier))
	q.Set("code_challenge_method", "S256")
	if cfg.Scopes != "" {
		q.Set("scope", cfg.Scopes)
	}
	sep := "?"
	if strings.Contains(cfg.AuthURL, "?") {
		sep = "&"
	}
	s.auditReason(ctx, orgID, serverName, agentID, "mcp_user_credential_begin",
		fmt.Sprintf("server=%s,agent=%s,kind=oauth", serverName, agentID), "")
	return cfg.AuthURL + sep + q.Encode(), state, nil
}

// CompleteUserOAuth exchanges the authorization code at the token endpoint
// and activates the agent's credential. The pending row (located by the
// state capability) pins the (server, agent) pair; the token endpoint is
// held to the same SSRF guard as the server URLs; the store re-checks the
// grant ceiling on the token write.
func (s *mcpCredsSource) CompleteUserOAuth(ctx context.Context, orgID, serverName, code, state string) (adminstore.MCPUserCredential, error) {
	pending, err := s.store.FindMCPUserCredentialByState(ctx, orgID, state)
	if err != nil {
		return adminstore.MCPUserCredential{}, err
	}
	if pending.ServerName != serverName {
		return adminstore.MCPUserCredential{}, adminstore.ErrNotFound
	}
	cfg, complete, err := s.serverOAuthConfig(ctx, orgID, serverName)
	if err != nil {
		return adminstore.MCPUserCredential{}, err
	}
	if !complete {
		return adminstore.MCPUserCredential{}, errMCPNoOAuthConfig
	}
	if s.allow != nil {
		if err := s.allow(ctx, cfg.TokenURL); err != nil {
			return adminstore.MCPUserCredential{}, fmt.Errorf("mcp oauth token endpoint refused by the egress guard: %w", err)
		}
	} else {
		return adminstore.MCPUserCredential{}, fmt.Errorf("mcp oauth token endpoint guard is not wired")
	}

	// PKCE (RFC 7636): consume the verifier planted at flow start (single
	// use — read and cleared in one statement). ok=false for pre-0017 rows
	// (no verifier stored): the exchange then runs without code_verifier,
	// byte-compatible with the pre-PKCE behavior.
	verifier, hasVerifier, err := s.store.ConsumeMCPUserCredVerifier(ctx, orgID, serverName, pending.AgentKeyID)
	if err != nil {
		// The code was issued against the S256 challenge: exchanging it
		// without the verifier would fail at the token endpoint anyway —
		// fail here with the clearer infrastructure reason.
		return adminstore.MCPUserCredential{}, fmt.Errorf("consume pkce verifier: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if cfg.RedirectURI != "" {
		form.Set("redirect_uri", cfg.RedirectURI)
	}
	if hasVerifier {
		form.Set("code_verifier", verifier)
	}
	tokens, _, err := s.postTokenForm(ctx, oauthClientConfig{TokenURL: cfg.TokenURL}, form)
	if err != nil {
		return adminstore.MCPUserCredential{}, err
	}
	if tokens.AccessToken == "" {
		return adminstore.MCPUserCredential{}, fmt.Errorf("mcp oauth token exchange returned no access token")
	}
	payload, err := json.Marshal(tokens) //nolint:gosec // G117: this IS the at-rest token write path (enc: envelope applied by the store)
	if err != nil {
		return adminstore.MCPUserCredential{}, err
	}
	var expiresAt *time.Time
	if tokens.ExpiresIn > 0 {
		t := s.now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
		expiresAt = &t
	}
	row, err := s.store.UpdateMCPUserOAuthTokens(ctx, orgID, serverName, pending.AgentKeyID, string(payload), expiresAt)
	if err != nil {
		return adminstore.MCPUserCredential{}, err
	}
	s.bumpOrgVersion(ctx, orgID)
	s.auditReason(ctx, orgID, serverName, pending.AgentKeyID, "mcp_user_credential_authorized",
		fmt.Sprintf("server=%s,agent=%s,kind=oauth,last4=%s", serverName, pending.AgentKeyID, row.SecretLast4), "")
	return row, nil
}

// bumpOrgVersion refreshes the org's MCP credential version (the admin CRUD
// bumper twin on the data plane); failures degrade to a log line — the TTL
// bounds the staleness either way.
func (s *mcpCredsSource) bumpOrgVersion(ctx context.Context, orgID string) {
	if s.versions == nil {
		return
	}
	if err := s.versions.SetMCPCredsVersion(ctx, orgID, s.now().UnixNano()); err != nil && s.log != nil {
		s.log.Warn("mcp credential version bump failed; probe expires via TTL", "org_id", orgID, "error", err.Error())
	}
}

// newFlowState generates the URL-safe state nonce.
func newFlowState() (string, error) {
	b := make([]byte, flowStateBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate mcp flow state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// errMCPNoOAuthConfig marks a server without a usable ENABLED oauth
// credential (the caller renders it 409/409-style, never 500).
var errMCPNoOAuthConfig = errors.New("mcp server has no enabled oauth credential")
