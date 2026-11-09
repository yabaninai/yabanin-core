package cli

// MC-2 tests for the gateway credential source: header building, the
// resolution order + probe cache polarity, the oauth force-refresh round
// against a mock token endpoint, the sticky needs_reauth marking, the
// server-level no-refresh posture, and the Redis version store.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// fakeMCPCredsStore is the MCPCredsStore double.
type fakeMCPCredsStore struct {
	mu             sync.Mutex
	userSecret     string
	userKind       string
	userOK         bool
	srvSecret      string
	srvKind        string
	srvOK          bool
	srvMode        string // credential_mode of the server row ("" = unmigrated → auto)
	modeErr        error  // simulates a mode-lookup failure (fail-closed path)
	userRow        adminstore.MCPUserCredential
	tokensSet      string
	updateErr      error // simulated token-write failure (concurrent grant revocation)
	statuses       []string
	auditRows      []adminstore.AuditLogEntryRecord
	pendingState   string
	verifierStored string // pending PKCE verifier ("" = none/consumed)
}

func (f *fakeMCPCredsStore) MCPServerCredentialMode(context.Context, string, string) (string, int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modeErr != nil {
		return "", 0, false, f.modeErr
	}
	return f.srvMode, 1, true, nil
}

func (f *fakeMCPCredsStore) ResolveMCPUserSecret(context.Context, string, string, string) (string, string, int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.userSecret, f.userKind, 1, f.userOK, nil
}

func (f *fakeMCPCredsStore) ResolveMCPServerSecret(context.Context, string, string) (string, string, int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.srvSecret, f.srvKind, 1, f.srvOK, nil
}

func (f *fakeMCPCredsStore) GetMCPUserCredential(context.Context, string, string, string) (adminstore.MCPUserCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.userRow, nil
}

func (f *fakeMCPCredsStore) UpdateMCPUserOAuthTokens(_ context.Context, _, _, _, tokenJSON string, _ *time.Time) (adminstore.MCPUserCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return adminstore.MCPUserCredential{}, f.updateErr
	}
	f.tokensSet = tokenJSON
	return f.userRow, nil
}

func (f *fakeMCPCredsStore) UpsertMCPUserCredential(_ context.Context, _, _, _, kind, secret string, _ *time.Time) (adminstore.MCPUserCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userSecret, f.userKind, f.userOK = secret, kind, true
	return f.userRow, nil
}

func (f *fakeMCPCredsStore) DeleteMCPUserCredential(context.Context, string, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userOK = false
	return nil
}

func (f *fakeMCPCredsStore) CreatePendingMCPUserCredential(_ context.Context, _, _, _, state string) (adminstore.MCPUserCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pendingState = state
	return f.userRow, nil
}

func (f *fakeMCPCredsStore) FindMCPUserCredentialByState(_ context.Context, _, state string) (adminstore.MCPUserCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingState == "" || f.pendingState != state {
		return adminstore.MCPUserCredential{}, adminstore.ErrNotFound
	}
	return f.userRow, nil
}

func (f *fakeMCPCredsStore) StoreMCPUserCredVerifier(_ context.Context, _, _, _, verifier string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifierStored = verifier
	return nil
}

func (f *fakeMCPCredsStore) ConsumeMCPUserCredVerifier(_ context.Context, _, _, _ string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.verifierStored
	f.verifierStored = ""
	return v, v != "", nil
}

func (f *fakeMCPCredsStore) SetMCPUserCredentialStatus(_ context.Context, _, _, _ string, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, status)
	return nil
}

func (f *fakeMCPCredsStore) InsertAuditLogEntry(_ context.Context, rec adminstore.AuditLogEntryRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auditRows = append(f.auditRows, rec)
	return nil
}

func (f *fakeMCPCredsStore) statusCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.statuses)
}

// stubMCPRedis is the OrgCredsRedis double over a map.
type stubMCPRedis struct {
	mu     sync.Mutex
	values map[string]string
}

func (s *stubMCPRedis) Get(_ context.Context, key string) *redis.StringCmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := redis.NewStringResult(s.values[key], nil)
	if s.values[key] == "" {
		cmd = redis.NewStringResult("", redis.Nil)
	}
	return cmd
}

func (s *stubMCPRedis) Set(_ context.Context, key string, value interface{}, _ time.Duration) *redis.StatusCmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value.(string)
	return redis.NewStatusResult("OK", nil)
}

func TestBuildAuthHeaders_Kinds(t *testing.T) {
	h, err := buildAuthHeaders(mcpagg.CredKindHeaders, `{"Authorization":"Bearer abc","X-Multi":["1","2"]}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer abc"}, h["Authorization"])
	assert.Equal(t, []string{"1", "2"}, h["X-Multi"])

	h, err = buildAuthHeaders(mcpagg.CredKindOAuth, `{"access_token":"at-1","token_type":"Bearer"}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer at-1"}, h["Authorization"])

	// Defaults + errors.
	h, err = buildAuthHeaders(mcpagg.CredKindOAuth, `{"access_token":"at-1"}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer at-1"}, h["Authorization"])
	_, err = buildAuthHeaders(mcpagg.CredKindOAuth, `{"refresh_token":"rt"}`)
	require.Error(t, err, "an oauth credential without an access token is not applicable")
	_, err = buildAuthHeaders(mcpagg.CredKindHeaders, `{}`)
	require.Error(t, err)
	_, err = buildAuthHeaders("basic", `{}`)
	require.Error(t, err)
}

func TestMCPCredsSource_AuthHeaders_OrderAndCache(t *testing.T) {
	store := &fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer user-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
		srvSecret: `{"Authorization":"Bearer srv-tok"}`, srvKind: mcpagg.CredKindHeaders, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second, Now: func() time.Time { return time.Unix(0, 0) }})

	// Per-user wins over server-level.
	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer user-tok"}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// The positive decision is cached; the plaintext read stays authoritative.
	store.userSecret = `{"Authorization":"Bearer user-rotated"}`
	h, _, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer user-rotated"}, h["Authorization"], "the fresh plaintext must be served")

	// After the TTL lapse the decision re-probes: user lost active status →
	// the server-level credential takes over.
	store.userOK = false
	src.now = func() time.Time { return time.Unix(10, 0) }
	h, kind, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer srv-tok"}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// No credential anywhere: miss, cached within the TTL.
	store.srvOK = false
	src.now = func() time.Time { return time.Unix(20, 0) }
	h, kind, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// The negative is load-shed within the TTL (no store change observable —
	// flip the store back and confirm the cached negative still answers).
	store.srvOK = true
	h, _, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Nil(t, h, "a fresh negative decision must not re-resolve")

	// Past the TTL the negative re-probes (negatives never take the version
	// fast path — the orgCredsProbe polarity): the re-probe serves the
	// restored store credential and pins the org version for the positive
	// fast path.
	src.now = func() time.Time { return time.Unix(21, 0) }
	src.versions = &stubMCPCredsVersions{versions: map[string]int64{"org-1": 7}}
	h, _, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.NotNil(t, h, "the negative must re-probe at the TTL lapse")
}

// stubMCPCredsVersions is a memory MCPCredsVersionStore.
type stubMCPCredsVersions struct {
	mu       sync.Mutex
	versions map[string]int64
}

func (s *stubMCPCredsVersions) GetMCPCredsVersion(_ context.Context, orgID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.versions[orgID], nil
}

func (s *stubMCPCredsVersions) SetMCPCredsVersion(_ context.Context, orgID string, v int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[orgID] = v
	return nil
}

func TestMCPCredsSource_RefreshOAuth_Success(t *testing.T) {
	var refreshAuth string
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		refreshAuth = r.Header.Get("Authorization")
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "rt-1", r.FormValue("refresh_token"))
		assert.Equal(t, "cid", r.FormValue("client_id"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-new","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"refresh_token":"rt-1","access_token":"at-expired"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","client_secret":"csec","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, raw string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	require.True(t, retry)
	assert.Equal(t, []string{"Bearer at-new"}, h["Authorization"])
	assert.Contains(t, store.tokensSet, "at-new")
	assert.Empty(t, store.statuses, "a successful refresh must not flip the status")
	require.Len(t, store.auditRows, 1)
	assert.Equal(t, "mcp_user_credential_refresh", store.auditRows[0].Action)
	_ = refreshAuth
}

func TestMCPCredsSource_RefreshOAuth_PermanentRejection(t *testing.T) {
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"refresh_token":"rt-1"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, _ string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	assert.False(t, retry)
	assert.Nil(t, h)
	assert.Equal(t, []string{adminstore.MCPUserCredStatusNeedsReauth}, store.statuses, "needs_reauth is sticky")
	require.Len(t, store.auditRows, 1)
	assert.Equal(t, "mcp_user_credential_needs_reauth", store.auditRows[0].Action)
}

func TestMCPCredsSource_RefreshRefused_FailClosedWithoutGuard(t *testing.T) {
	// No URL guard wired: the refresh must refuse EVERY token endpoint (fail
	// closed) rather than POSTing credentials to an unguarded host.
	store := &fakeMCPCredsStore{ //nolint:gosec // G101: synthetic fixture, no real credentials
		userSecret: `{"refresh_token":"rt-1"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","token_url":"https://idp.example.test/token"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})

	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	assert.False(t, retry)
	assert.Nil(t, h)
	assert.Equal(t, []string{adminstore.MCPUserCredStatusNeedsReauth}, store.statuses)
}

func TestMCPCredsSource_HeadersKind_NeedsReauth(t *testing.T) {
	store := &fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer dead"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})

	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindHeaders)
	require.NoError(t, err)
	assert.False(t, retry)
	assert.Nil(t, h)
	assert.Equal(t, []string{adminstore.MCPUserCredStatusNeedsReauth}, store.statuses)
}

func TestMCPCredsSource_ServerLevel_NoRefresh(t *testing.T) {
	store := &fakeMCPCredsStore{
		srvSecret: `{"Authorization":"Bearer srv"}`, srvKind: mcpagg.CredKindHeaders, srvOK: true,
		userOK: false,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})

	// Prime the probe: server-level hit.
	_, _, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)

	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindHeaders)
	require.NoError(t, err)
	assert.False(t, retry)
	assert.Nil(t, h)
	assert.Zero(t, store.statusCalls(), "server-level credentials are operator-rotated, never self-marked")
}

func TestMCPCredsSource_GuardHoldsTokenEndpointToAllowList(t *testing.T) {
	// The same guard as the server URLs: a token endpoint outside the MCP
	// allow-list makes the refresh terminal, never a request.
	store := &fakeMCPCredsStore{ //nolint:gosec // G101: synthetic fixture, no real credentials
		userSecret: `{"refresh_token":"rt-1"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","token_url":"https://evil.example.test/token"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow: func(_ context.Context, raw string) error {
			if strings.Contains(raw, "evil.example.test") {
				return errors.New("host not allowed")
			}
			return nil
		},
	})

	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	assert.False(t, retry)
	assert.Nil(t, h)
	assert.Equal(t, []string{adminstore.MCPUserCredStatusNeedsReauth}, store.statuses)
}

func TestMCPCredsVersionStore_Redis(t *testing.T) {
	rdb := &stubMCPRedis{values: map[string]string{}}
	vs := NewMCPCredsVersionStore(rdb, nil)

	v, err := vs.GetMCPCredsVersion(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Zero(t, v, "a missing key is version 0")

	require.NoError(t, vs.SetMCPCredsVersion(context.Background(), "org-1", 42))
	v, err = vs.GetMCPCredsVersion(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, int64(42), v)
}

// loopbackClient is the hermetic-test HTTP client: httptest stubs live on
// the loopback, which the PRODUCTION guarded client refuses by design
// (GuardDialedIP) — every test that actually talks to a stub injects this
// via mcpCredsSourceConfig.HTTPClient.
func loopbackClient() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

// ---------------------------------------------------------------------------
// N05-P02-T03: PKCE (RFC 7636) + provider-side revocation (RFC 7009).
// ---------------------------------------------------------------------------

func TestPKCEChallengeS256_RFC7636Vector(t *testing.T) {
	// The exact Appendix B vector of RFC 7636.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", pkceChallengeS256(verifier))
}

func TestPKCEVerifier_Generated(t *testing.T) {
	v, err := newPKCEVerifier()
	require.NoError(t, err)
	assert.Len(t, v, 43, "32 bytes base64url = 43 chars (RFC 7636 §4.1 length floor)")
	assert.Regexp(t, `^[A-Za-z0-9\-_]+$`, v, "unreserved alphabet only")
	other, err := newPKCEVerifier()
	require.NoError(t, err)
	assert.NotEqual(t, v, other, "verifiers are per-flow random")
}

func TestMCPBeginOAuth_PKCEChallengeMatchesStoredVerifier(t *testing.T) {
	store := &fakeMCPCredsStore{ //nolint:gosec // G101: synthetic fixture, no real credentials
		srvSecret: `{"client_id":"cid","client_secret":"csec","auth_url":"https://idp.example.test/authorize","token_url":"https://idp.example.test/token"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})

	authURL, state, err := src.BeginUserOAuth(context.Background(), "org-1", "srv", "ag-1", "https://gw.example.test/cb")
	require.NoError(t, err)
	assert.NotEmpty(t, state)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	verifier := store.verifierStored
	require.NotEmpty(t, verifier, "begin must plant the encrypted verifier")
	assert.Equal(t, pkceChallengeS256(verifier), q.Get("code_challenge"),
		"the authorize URL carries S256(verifier) — never the verifier itself")
	assert.NotContains(t, authURL, verifier)
}

func TestMCPCompleteOAuth_PKCEVerifierJoinsExchange(t *testing.T) {
	var gotForm url.Values
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-pkce","token_type":"Bearer","expires_in":600}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		srvSecret: `{"client_id":"cid","auth_url":"https://idp.example.test/authorize","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		userRow: adminstore.MCPUserCredential{ServerName: "srv", AgentKeyID: "ag-1"},
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, raw string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	_, state, err := src.BeginUserOAuth(context.Background(), "org-1", "srv", "ag-1", "https://gw.example.test/cb")
	require.NoError(t, err)
	planted := store.verifierStored

	_, err = src.CompleteUserOAuth(context.Background(), "org-1", "srv", "auth-code-1", state)
	require.NoError(t, err)
	assert.Equal(t, planted, gotForm.Get("code_verifier"),
		"the token exchange must present the exact planted verifier")
	assert.Equal(t, "authorization_code", gotForm.Get("grant_type"))
	assert.Empty(t, store.verifierStored, "the verifier is single-use: consumed by the exchange")
}

func TestMCPCompleteOAuth_PrePKCERowExchangesWithoutVerifier(t *testing.T) {
	// A pending row created before migration 0017 carries no verifier: the
	// exchange must stay byte-compatible (no code_verifier form field).
	var gotForm url.Values
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-legacy"}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		srvSecret: `{"client_id":"cid","auth_url":"https://idp.example.test/authorize","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		pendingState: "legacy-state-00001",
		userRow:      adminstore.MCPUserCredential{ServerName: "srv", AgentKeyID: "ag-1"},
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, raw string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	_, err := src.CompleteUserOAuth(context.Background(), "org-1", "srv", "auth-code-1", "legacy-state-00001")
	require.NoError(t, err)
	assert.Empty(t, gotForm.Get("code_verifier"), "pre-0017 rows exchange without code_verifier")
}

func TestMCPDelete_Rfc7009RevocationCalled(t *testing.T) {
	var mu sync.Mutex
	var revForm url.Values
	var revCalls int
	revSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		revCalls++
		_ = r.ParseForm()
		revForm = r.PostForm
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(revSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"access_token":"at-del","refresh_token":"rt-del"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","client_secret":"csec","auth_url":"https://idp.example.test/authorize","token_url":"https://idp.example.test/token","revocation_endpoint":"` + revSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, raw string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	require.NoError(t, src.DeleteUserCredential(context.Background(), "org-1", "srv", "ag-1", "cleanup"))
	assert.False(t, store.userOK, "the local delete is the authoritative stop")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, revCalls, "the delete must attempt the provider-side revoke")
	assert.Equal(t, "at-del", revForm.Get("token"))
	assert.Equal(t, "access_token", revForm.Get("token_type_hint"))
	assert.Equal(t, "cid", revForm.Get("client_id"))
	assert.Equal(t, "csec", revForm.Get("client_secret"))
	require.Len(t, store.auditRows, 1)
	assert.Equal(t, "mcp_user_credential_delete", store.auditRows[0].Action)
	assert.Contains(t, store.auditRows[0].Details, "revocation=ok")
}

func TestMCPDelete_RevocationFailureDoesNotBreakDelete(t *testing.T) {
	revSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(revSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"access_token":"at-del"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","auth_url":"https://idp.example.test/authorize","token_url":"https://idp.example.test/token","revocation_endpoint":"` + revSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, raw string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	require.NoError(t, src.DeleteUserCredential(context.Background(), "org-1", "srv", "ag-1", "cleanup"),
		"a failing revocation must never fail the local delete")
	assert.False(t, store.userOK)
	require.Len(t, store.auditRows, 1)
	assert.Contains(t, store.auditRows[0].Details, "revocation=failed")
}

func TestMCPDelete_RevocationSkipped_NoEndpoint(t *testing.T) {
	var calls int
	var mu sync.Mutex
	revSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(revSrv.Close)

	store := &fakeMCPCredsStore{ //nolint:gosec // G101: synthetic fixture, no real credentials
		userSecret: `{"access_token":"at-del"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","token_url":"https://idp.example.test/token"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow: func(_ context.Context, raw string) error { return nil },
	})

	require.NoError(t, src.DeleteUserCredential(context.Background(), "org-1", "srv", "ag-1", "cleanup"))
	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, calls, "no revocation endpoint → no HTTP call")
	require.Len(t, store.auditRows, 1)
	assert.Contains(t, store.auditRows[0].Details, "revocation=skipped(no-endpoint)")
}

func TestMCPDelete_RevocationSkipped_GuardRefusedOrNonOAuth(t *testing.T) {
	revSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(revSrv.Close)

	newSrc := func(store *fakeMCPCredsStore, allow urlGuard) *mcpCredsSource {
		return newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second, Allow: allow})
	}
	allowNone := func(_ context.Context, _ string) error { return errors.New("refused") }

	// Guard refusal: revocation never widens the egress surface.
	store := &fakeMCPCredsStore{
		userSecret: `{"access_token":"at-del"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","auth_url":"https://idp.example.test/authorize","token_url":"https://tok.example.test","revocation_endpoint":"` + revSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	require.NoError(t, newSrc(store, allowNone).DeleteUserCredential(context.Background(), "org-1", "srv", "ag-1", "cleanup"))
	require.Len(t, store.auditRows, 1)
	assert.Contains(t, store.auditRows[0].Details, "revocation=skipped(guard-refused)")

	// Headers-kind row: nothing to revoke at the provider.
	store2 := &fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer h"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
		srvSecret: `{"client_id":"cid","auth_url":"https://idp.example.test/authorize","token_url":"https://tok.example.test","revocation_endpoint":"` + revSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
	}
	require.NoError(t, newSrc(store2, func(_ context.Context, _ string) error { return nil }).
		DeleteUserCredential(context.Background(), "org-1", "srv", "ag-1", "cleanup"))
	require.Len(t, store2.auditRows, 1)
	assert.Contains(t, store2.auditRows[0].Details, "revocation=skipped(no-token)")
}

// ---------------------------------------------------------------------------
// A01: the OAuth egress client is guarded — dial-time reserved-IP check and
// outright redirect refusal (pkg/mcpagg/config.go Client() parity). The
// token/revocation bodies carry client_secret + refresh_token: a redirect
// would re-send them to whatever Location names, and a DNS rebinding
// between the URL allow-check and the connect must die at dial time.
// ---------------------------------------------------------------------------

func TestMCPOAuthEgress_RedirectContract_RefusedOutright(t *testing.T) {
	// Every local test address is reserved (the dial test below proves the
	// guard refuses them), so the redirect refusal is pinned at the client
	// contract: CheckRedirect returns http.ErrUseLastResponse for ANY hop —
	// Go's client then surfaces the 3xx to the caller without contacting
	// Location and without re-sending the secret-bearing body. Token
	// endpoints don't legitimately redirect.
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: &fakeMCPCredsStore{}, TTL: time.Second,
		Allow: func(_ context.Context, _ string) error { return nil },
	})
	require.NotNil(t, src.client.CheckRedirect, "the production client must pin a redirect policy")

	first, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://token.example.test/token", nil)
	require.NoError(t, err)
	via := []*http.Request{first}
	for _, target := range []string{
		"https://elsewhere.example.test/redirected",
		"http://169.254.169.254/latest/meta-data",
		"https://token.example.test/token?again=1",
	} {
		redir, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		require.NoError(t, err)
		err = src.client.CheckRedirect(redir, via)
		assert.ErrorIs(t, err, http.ErrUseLastResponse,
			"redirect to %s must be refused outright, got: %v", target, err)
	}
}

func TestMCPOAuthEgress_RefusesReservedDialAtDialTime(t *testing.T) {
	var hits int
	var mu sync.Mutex
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(stub.Close)

	// No HTTPClient override → the production guarded client. The httptest
	// listener is on the loopback — exactly the reserved target a rebinding
	// (or a moved token_url) would land on; the URL allow-check stub above
	// passes everything, so the refusal must come from the dial itself.
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: &fakeMCPCredsStore{}, TTL: time.Second,
		Allow: func(_ context.Context, _ string) error { return nil },
	})

	form := url.Values{"refresh_token": {"rt-egress-test"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		stub.URL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := src.client.Do(req)
	require.Error(t, err, "the guarded dialer must refuse the reserved target")
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	require.ErrorIs(t, err, ssrf.ErrReservedTarget, "dial-time reserved-IP refusal, got: %v", err)
	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, hits, "no request may reach the reserved target")
}

// ---------------------------------------------------------------------------
// A02: transient token-endpoint failures (5xx/429/connection) must leave the
// STORED credential untouched — no overwrite with an empty payload, no
// needs_reauth (429 is backpressure, not a grant verdict) — and failure
// paths stay key-free in the logs.
// ---------------------------------------------------------------------------

// captureLog is a slog handler over an in-memory buffer.
type captureLog struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (c *captureLog) Enabled(context.Context, slog.Level) bool { return true }

func (c *captureLog) WithAttrs([]slog.Attr) slog.Handler { return c }

func (c *captureLog) WithGroup(string) slog.Handler { return c }

func (c *captureLog) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf.WriteString(r.Message)
	c.buf.WriteString(" | ")
	r.Attrs(func(a slog.Attr) bool {
		c.buf.WriteString(a.Key)
		c.buf.WriteString("=")
		c.buf.WriteString(a.Value.String())
		c.buf.WriteString(" | ")
		return true
	})
	c.buf.WriteString("\n")
	return nil
}

func (c *captureLog) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func TestMCPCredsSource_RefreshTransientFailure_RowUntouched(t *testing.T) {
	const userSecret = `{"refresh_token":"rt-refresh-secret","access_token":"at-stored-secret"}`
	cases := []struct {
		name   string
		status int // 0 = the endpoint is unreachable (closed server)
	}{
		{"500", http.StatusInternalServerError},
		{"503", http.StatusServiceUnavailable},
		{"429", http.StatusTooManyRequests},
		{"connection refused", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logc := &captureLog{}
			var tokSrv *httptest.Server
			if tc.status != 0 {
				tokSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.status)
				}))
				t.Cleanup(tokSrv.Close)
			} else {
				tokSrv = httptest.NewServer(http.NotFoundHandler())
				tokSrv.Close() // dead listener → dial error
			}

			store := &fakeMCPCredsStore{
				userSecret: userSecret, userKind: mcpagg.CredKindOAuth, userOK: true,
				srvSecret: `{"client_id":"cid","client_secret":"csec","token_url":"` + tokSrv.URL + `"}`,
				srvKind:   mcpagg.CredKindOAuth, srvOK: true,
				userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
			}
			src := newMCPCredsSource(mcpCredsSourceConfig{
				Store: store, TTL: time.Second,
				Allow:      func(_ context.Context, _ string) error { return nil },
				HTTPClient: loopbackClient(),
				Log:        slog.New(logc),
			})

			h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
			require.Error(t, err, "a transient failure must surface, not silently blank the credential")
			assert.True(t, isTransientTokenEndpointError(err), "typed transient outcome, got: %v", err)
			assert.Nil(t, h)
			assert.False(t, retry)
			// The STORED row is untouched — the actual A02 regression pin
			// (not just the returned error): no token overwrite, no
			// needs_reauth flip, no audit write.
			assert.Empty(t, store.tokensSet, "the stored payload must not be overwritten")
			assert.Zero(t, store.statusCalls(), "a transient failure must not set needs_reauth")
			assert.Empty(t, store.auditRows, "no audit record for an untouched credential")
			// Logs stay key-free.
			logs := logc.String()
			assert.NotContains(t, logs, "rt-refresh-secret")
			assert.NotContains(t, logs, "at-stored-secret")
			assert.NotContains(t, logs, "csec")
		})
	}
}

func TestMCPCredsSource_RefreshRedirectPermanentTyped_RowUntouched(t *testing.T) {
	// F2 (R1-sec 2026-11-01): a token endpoint answering 3xx is a PERMANENT
	// misconfiguration (the egress client refuses every redirect hop), and
	// the typed refusal must surface — never be absorbed as transient and
	// never ride the empty-access-token belt-and-suspenders. The stored row
	// stays untouched: no token overwrite, no needs_reauth flip, no audit.
	const userSecret = `{"refresh_token":"rt-refresh-secret","access_token":"at-stored-secret"}`
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		t.Run(fmt.Sprintf("%d", status), func(t *testing.T) {
			// Location-less 3xx: Go's client returns it as-is, so the stub
			// verdict reaches postTokenForm directly over the plain loopback
			// client (a live-Location follow test is impossible here — the
			// loopback client has no redirect policy; hopping itself is
			// pinned by A01 against the production client).
			tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			t.Cleanup(tokSrv.Close)

			store := &fakeMCPCredsStore{
				userSecret: userSecret, userKind: mcpagg.CredKindOAuth, userOK: true,
				srvSecret: `{"client_id":"cid","client_secret":"csec","token_url":"` + tokSrv.URL + `"}`,
				srvKind:   mcpagg.CredKindOAuth, srvOK: true,
				userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
			}
			src := newMCPCredsSource(mcpCredsSourceConfig{
				Store: store, TTL: time.Second,
				Allow:      func(_ context.Context, _ string) error { return nil },
				HTTPClient: loopbackClient(),
			})

			h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
			require.Error(t, err, "a refused redirect must surface, not silently blank the credential")
			var re *tokenEndpointRedirectError
			require.ErrorAs(t, err, &re, "typed redirect refusal")
			assert.Equal(t, status, re.status)
			assert.Contains(t, err.Error(), fmt.Sprintf("status %d", status), "the error must name the status")
			assert.False(t, isTransientTokenEndpointError(err), "a redirect refusal is permanent, never transient")
			assert.Nil(t, h)
			assert.False(t, retry)
			// The STORED row is untouched: no token overwrite, no
			// needs_reauth flip, no audit write.
			assert.Empty(t, store.tokensSet, "the stored payload must not be overwritten")
			assert.Zero(t, store.statusCalls(), "a redirect refusal must not set needs_reauth")
			assert.Empty(t, store.auditRows, "no audit record for an untouched credential")
			// No secret material in the surfaced error.
			assert.NotContains(t, err.Error(), "rt-refresh-secret")
			assert.NotContains(t, err.Error(), "csec")
		})
	}
}

func TestMCPOAuthEgress_TokenFormOutcomeContract(t *testing.T) {
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: &fakeMCPCredsStore{}, TTL: time.Second,
		Allow:      func(_ context.Context, _ string) error { return nil },
		HTTPClient: loopbackClient(),
	})
	form := url.Values{"refresh_token": {"rt-x"}}
	stub := func(status int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
	}

	cases := []struct {
		name      string
		status    int
		body      string
		permanent bool
		transient bool
		redirect  bool // F2: typed redirect refusal — permanent AND err non-nil
		wantToken string
	}{
		{"success", http.StatusOK, `{"access_token":"at-new","expires_in":60}`, false, false, false, "at-new"},
		{"invalid_grant 400 terminal", http.StatusBadRequest, `{"error":"invalid_grant"}`, true, false, false, ""},
		{"401 terminal", http.StatusUnauthorized, ``, true, false, false, ""},
		{"2xx without token terminal", http.StatusOK, `{}`, true, false, false, ""},
		{"302 redirect permanent-typed", http.StatusFound, ``, true, false, true, ""},
		{"307 redirect permanent-typed", http.StatusTemporaryRedirect, ``, true, false, true, ""},
		{"500 transient", http.StatusInternalServerError, `oops`, false, true, false, ""},
		{"429 transient", http.StatusTooManyRequests, `{"error":"slow_down"}`, false, true, false, ""},
		{"malformed json transient", http.StatusOK, `not-json`, false, true, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := stub(tc.status, tc.body)
			t.Cleanup(srv.Close)
			tokens, permanent, err := src.postTokenForm(context.Background(), oauthClientConfig{TokenURL: srv.URL}, form)
			assert.Equal(t, tc.permanent, permanent)
			assert.Equal(t, tc.transient || tc.redirect, err != nil)
			if tc.transient {
				assert.True(t, isTransientTokenEndpointError(err))
			}
			if tc.redirect {
				// The stub sends no Location: Go's client returns a
				// Location-less 3xx as-is, so the classification branch sees
				// the verdict directly (hopping itself is A01's pin).
				var re *tokenEndpointRedirectError
				require.ErrorAs(t, err, &re, "typed redirect refusal")
				assert.Equal(t, tc.status, re.status)
				assert.Contains(t, err.Error(), fmt.Sprintf("status %d", tc.status),
					"the error must name the offending status")
				assert.False(t, isTransientTokenEndpointError(err),
					"a redirect refusal is permanent, never transient")
			}
			assert.Equal(t, tc.wantToken, tokens.AccessToken)
		})
	}

	// Dead endpoint → typed transient too.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	_, permanent, err := src.postTokenForm(context.Background(), oauthClientConfig{TokenURL: dead.URL}, form)
	require.Error(t, err)
	assert.True(t, isTransientTokenEndpointError(err))
	assert.False(t, permanent)
}

// ---------------------------------------------------------------------------
// A03: a refresh response without a new refresh_token (RFC 6749 §6 allows)
// must preserve the old one; rotation is accepted; a concurrent grant
// revocation between read and write must not resurrect the credential.
// ---------------------------------------------------------------------------

func TestMCPCredsSource_RefreshOAuth_PreservesRefreshTokenAcrossRefreshes(t *testing.T) {
	var mu sync.Mutex
	var exchanges int
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		exchanges++
		mu.Unlock()
		// The provider never rotates: every response omits refresh_token.
		_, _ = w.Write([]byte(`{"access_token":"at-gen-` + r.FormValue("refresh_token") + `","token_type":"Bearer","expires_in":600}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"refresh_token":"rt-original","access_token":"at-old"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","client_secret":"csec","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, _ string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	// First refresh: the response omits refresh_token → the original must
	// survive in the stored payload.
	h, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	require.True(t, retry)
	assert.Contains(t, store.tokensSet, "at-gen-rt-original")
	assert.Contains(t, store.tokensSet, "rt-original", "the omitted refresh_token must be preserved")
	require.Len(t, h["Authorization"], 1)

	// Second sequential refresh: the preserved token is presented and
	// preserved again — the chain survives.
	store.mu.Lock()
	store.userSecret = store.tokensSet
	store.mu.Unlock()
	_, retry, err = src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	require.True(t, retry)
	assert.Contains(t, store.tokensSet, "at-gen-rt-original")
	assert.Contains(t, store.tokensSet, "rt-original", "two sequential refreshes must survive")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, exchanges)
}

func TestMCPCredsSource_RefreshOAuth_AcceptsRotatedRefreshToken(t *testing.T) {
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at-rotated","refresh_token":"rt-rotated"}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"refresh_token":"rt-old","access_token":"at-old"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, _ string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	_, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.NoError(t, err)
	require.True(t, retry)
	assert.Contains(t, store.tokensSet, "rt-rotated", "rotation is accepted")
	assert.NotContains(t, store.tokensSet, "rt-old", "the rotated-out token must not survive")
}

func TestMCPCredsSource_RefreshOAuth_ConcurrentRevoke_DoesNotResurrect(t *testing.T) {
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at-after-revoke","refresh_token":"rt-new"}`))
	}))
	t.Cleanup(tokSrv.Close)

	store := &fakeMCPCredsStore{
		userSecret: `{"refresh_token":"rt-1","access_token":"at-old"}`, userKind: mcpagg.CredKindOAuth, userOK: true,
		srvSecret: `{"client_id":"cid","token_url":"` + tokSrv.URL + `"}`,
		srvKind:   mcpagg.CredKindOAuth, srvOK: true,
		userRow: adminstore.MCPUserCredential{SecretLast4: "-1"},
		// The grant is revoked between the token read and the write — the
		// real store enforces the ENABLED-grant ceiling on every token
		// write (ErrNotFound), pinned in adminstore integration tests.
		updateErr: adminstore.ErrNotFound,
	}
	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow:      func(_ context.Context, _ string) error { return nil },
		HTTPClient: loopbackClient(),
	})

	_, _, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindOAuth)
	require.Error(t, err, "the failed write must surface")
	assert.True(t, adminstore.IsNotFound(err))
	assert.Empty(t, store.tokensSet, "a revoked grant must not be overwritten back to active (no resurrection)")
	assert.Zero(t, store.statusCalls(), "no needs_reauth flip on a store-refused write")
}
