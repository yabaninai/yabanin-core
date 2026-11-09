//go:build integration

package mcpagg

// entry point (Proxy.Invoke) with the REAL credential boundary: disposable
// migrated Postgres (testdb.Postgres), the production adminstore (real
// AES-GCM at-rest encryption, org-scoped resolution, the active/expiry SQL
// filter), and the production mcpagg registry (real server + grant rows;
// the https:// CHECK is satisfied with a TLS httptest upstream injected via
// This file covers the middle: the store resolution chain (the exported
// ResolveMCPUserSecret → ResolveMCPServerSecret egress) feeding Proxy.Invoke
// through a minimal source adapter that mirrors the documented gateway
// discipline (user → server level, headers rejection goes sticky
// needs_reauth, server-level credentials never self-refresh).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// lifecycleIntRequireAuthRequired pins the structured lazy-authorization
// failure for this server: kind, the flow URL, a diagnosable message, and no
// credential material in the JSON shape.
func lifecycleIntRequireAuthRequired(t *testing.T, err error, wantKind string) {
	t.Helper()
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("want %s, got %v", ErrCodeAuthRequired, err)
	}
	if authErr.Kind != wantKind {
		t.Errorf("auth-required kind = %q, want %q", authErr.Kind, wantKind)
	}
	wantURL := "/api/mcp/credentials/" + lifecycleIntServerName
	if wantKind == CredKindOAuth {
		wantURL = "/api/mcp/auth/" + lifecycleIntServerName + "/begin"
	}
	if authErr.URL != wantURL {
		t.Errorf("auth-required url = %q, want %q", authErr.URL, wantURL)
	}
	if authErr.Message == "" {
		t.Error("the auth-required error must stay diagnosable (non-empty message)")
	}
	shape, mErr := json.Marshal(authErr)
	if mErr != nil {
		t.Fatalf("marshal AuthRequiredError: %v", mErr)
	}
	if len(strings.Split(string(shape), ":")) != 4 {
		t.Errorf("the structured 401 body must carry kind+url+message only, got %s", shape)
	}
	for _, material := range []string{"Bearer sk-", "Bearer oauth-"} {
		if strings.Contains(string(shape), material) {
			t.Errorf("the structured 401 body carried credential material: %s", shape)
		}
	}
}

const lifecycleIntServerName = "int-lifecycle-srv"

// lifecycleIntUpstream is the bearer-checking TLS upstream: it records every
// Authorization value, reflects it into the JSON-RPC result text (the leak
// vector), and answers 401 with a hostile echo body when rejectAll is set or
// the request arrived unauthenticated.
type lifecycleIntUpstream struct {
	srv       *httptest.Server
	rejectAll atomic.Bool
	mu        sync.Mutex
	seen      map[string]int
}

func newLifecycleIntUpstream(t *testing.T) *lifecycleIntUpstream {
	t.Helper()
	u := &lifecycleIntUpstream{seen: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		u.mu.Lock()
		u.seen[auth]++
		u.mu.Unlock()
		if auth == "" || u.rejectAll.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			//nolint:gosec // G705: the mock upstream deliberately echoes the credential it received — the test proves the proxy redacts it
			_, _ = w.Write([]byte(`{"error":"rejected credential: ` + auth + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G705: the mock upstream deliberately reflects the credential — the test proves where it may and may not surface
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"saw ` + auth + `"}]}}`))
	})
	u.srv = httptest.NewTLSServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

func (u *lifecycleIntUpstream) snapshot() map[string]int {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make(map[string]int, len(u.seen))
	for k, v := range u.seen {
		out[k] = v
	}
	return out
}

// cpIntDelta returns the count increase for one upstream-seen value between
// two snapshots.
func cpIntDelta(before, after map[string]int, key string) int {
	return after[key] - before[key]
}

// lifecycleIntSource is the store-backed CredSource adapter: the resolution
// chain runs entirely through the exported adminstore boundary (the only
// plaintext egress), and the failure discipline mirrors the documented
// gateway source (level sticky per probe, headers rejection → needs_reauth,
// server-level never self-refreshes).
type lifecycleIntSource struct {
	store *adminstore.Store
	mu    sync.Mutex
	level map[string]string
}

func newLifecycleIntSource(store *adminstore.Store) *lifecycleIntSource {
	return &lifecycleIntSource{store: store, level: map[string]string{}}
}

func lifecycleIntKey(orgID, serverName, agentID string) string {
	return orgID + "\x00" + serverName + "\x00" + agentID
}

// lifecycleIntPayloadApplicable mirrors the gateway applicability rule:
// headers always, oauth only with token material.
func lifecycleIntPayloadApplicable(kind, plain string) bool {
	if kind != CredKindOAuth {
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

// lifecycleIntAuthHeaders maps the decrypted payload to outbound headers
// (the same two documented shapes as the gateway source).
func lifecycleIntAuthHeaders(kind, plain string) (map[string][]string, error) {
	switch kind {
	case CredKindHeaders:
		var raw map[string]any
		if err := json.Unmarshal([]byte(plain), &raw); err != nil {
			return nil, fmt.Errorf("decode mcp headers credential: %w", err)
		}
		headers := make(map[string][]string, len(raw))
		for name, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				headers[name] = []string{s}
			}
		}
		if len(headers) == 0 {
			return nil, fmt.Errorf("mcp headers credential carries no usable values")
		}
		return headers, nil
	case CredKindOAuth:
		var tok struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		if err := json.Unmarshal([]byte(plain), &tok); err != nil {
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

func (s *lifecycleIntSource) AuthHeaders(ctx context.Context, orgID, serverName, agentID string) (map[string][]string, string, error) {
	plain, kind, _, ok, err := s.store.ResolveMCPUserSecret(ctx, orgID, serverName, agentID)
	if err != nil {
		return nil, CredKindNone, err
	}
	level := "user"
	if !ok || !lifecycleIntPayloadApplicable(kind, plain) {
		plain, kind, _, ok, err = s.store.ResolveMCPServerSecret(ctx, orgID, serverName)
		if err != nil {
			return nil, CredKindNone, err
		}
		if !ok || !lifecycleIntPayloadApplicable(kind, plain) {
			return nil, CredKindNone, nil
		}
		level = "server"
	}
	headers, err := lifecycleIntAuthHeaders(kind, plain)
	if err != nil {
		return nil, kind, err
	}
	s.mu.Lock()
	s.level[lifecycleIntKey(orgID, serverName, agentID)] = level
	s.mu.Unlock()
	return headers, kind, nil
}

func (s *lifecycleIntSource) OnUpstreamUnauthorized(ctx context.Context, orgID, serverName, agentID, kind string) (map[string][]string, bool, error) {
	s.mu.Lock()
	level := s.level[lifecycleIntKey(orgID, serverName, agentID)]
	s.mu.Unlock()
	if level == "server" || kind != CredKindHeaders {
		// Server-level credentials do not self-refresh (the operator
		// rotates); a per-user oauth credential has no refresh
		// configuration on this stand — both are terminal.
		return nil, false, nil
	}
	// The stored headers credential was rejected: sticky needs_reauth —
	// the active filter stops resolving it until a re-submit.
	if err := s.store.SetMCPUserCredentialStatus(ctx, orgID, serverName, agentID, adminstore.MCPUserCredStatusNeedsReauth); err != nil {
		if adminstore.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return nil, false, nil
}

// lifecycleIntOrg creates an isolated org and registers its cleanup.
func lifecycleIntOrg(t *testing.T, pool *pgxpool.Pool, store *adminstore.Store, name string) string {
	t.Helper()
	org, err := store.CreateOrganization(context.Background(), name, name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
	})
	return org.ID
}

// lifecycleIntAgent seeds the agent principal row (the mcpagg registry
// references it by id; credentials resolve per agent_key_id).
func lifecycleIntAgent(t *testing.T, pool *pgxpool.Pool, orgID string) string {
	t.Helper()
	var agentID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		orgID, "r034-intlc-agent", "hash-"+orgID).Scan(&agentID))
	return agentID
}

// TestProxy_Invoke_StoreBackedCredentialLifecycle_Integration walks the full
// credential lifecycle through Proxy.Invoke against the real store boundary:
// create → rotate → revoke, server-level fallback and disable, scheduled
// (expires_at) revocation, sticky rejection revocation, foreign-tenant
// isolation, and non-visibility of the token material everywhere except the
// single outbound header per invoke.
func TestProxy_Invoke_StoreBackedCredentialLifecycle_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	registry := NewStore(pool)
	ctx := context.Background()

	const (
		v1       = "sk-intlc-v1-aaaa"           //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		v2       = "sk-intlc-v2-bbbb"           //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		v3       = "sk-intlc-v3-cccc"           //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		srvTok1  = "sk-intlc-srv1-dddddddddddd" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		srvTok2  = "sk-intlc-srv2-eeeeeeeeeeee" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		oauthTok = "oauth-intlc-ffff"           //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	)
	allTokens := []string{v1, v2, v3, srvTok1, srvTok2, oauthTok}

	up := newLifecycleIntUpstream(t)
	orgA := lifecycleIntOrg(t, pool, store, "r034-intlc-a")
	orgB := lifecycleIntOrg(t, pool, store, "r034-intlc-b")
	agentA := lifecycleIntAgent(t, pool, orgA)
	agentB := lifecycleIntAgent(t, pool, orgB)
	for _, member := range []struct {
		org, agent string
	}{{orgA, agentA}, {orgB, agentB}} {
		_, err := registry.Create(ctx, CreateParams{
			OrgID: member.org, Name: lifecycleIntServerName, URL: up.srv.URL, Enabled: true,
		})
		require.NoError(t, err)
		_, err = registry.CreateGrant(ctx, GrantCreateParams{
			OrgID: member.org, AgentID: member.agent, ServerName: lifecycleIntServerName, Enabled: true,
		})
		require.NoError(t, err)
	}

	cfg := testConfig()
	cfg.HTTP = up.srv.Client() // trust the TLS httptest upstream
	var auditEvents []AuditEvent
	p := NewProxy(registry, cfg, loopbackAllow(t), nil, &recordingAudit{events: &auditEvents}).
		WithCredsSource(newLifecycleIntSource(store))
	invoke := func(orgID, agentID string) (json.RawMessage, error) {
		return p.Invoke(ctx, orgID, Identity{AgentID: agentID},
			InvokeRequest{Server: lifecycleIntServerName, Tool: "search", Params: json.RawMessage(`{}`)})
	}
	headersJSON := func(tok string) string {
		return fmt.Sprintf(`{"Authorization":"Bearer %s"}`, tok)
	}

	// Leg 0 — no credential anywhere: the unauthenticated call is rejected
	// by the upstream and surfaces as the lazy-authorization error.
	_, err := invoke(orgA, agentA)
	lifecycleIntRequireAuthRequired(t, err, CredKindHeaders)
	assert.Equal(t, 1, up.snapshot()[""], "leg 0 must reach the upstream unauthenticated exactly once")

	// Leg 1 — create: the masked readback never carries the token, the
	// ciphertext at rest never carries it, and the very next invoke serves
	// it to the upstream (and only there).
	row, err := store.UpsertMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA, CredKindHeaders, headersJSON(v1), nil)
	require.NoError(t, err)
	assert.True(t, row.HasSecret)
	assert.Equal(t, v1[len(v1)-4:], row.SecretLast4)
	masked, mErr := json.Marshal(row)
	require.NoError(t, mErr)
	assert.NotContains(t, string(masked), v1, "the masked row must not carry the token")
	var kindCol, statusCol, ctCol string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT kind, status, secret_ct FROM mcp_user_credentials WHERE agent_key_id = $1::uuid`, agentA,
	).Scan(&kindCol, &statusCol, &ctCol))
	assert.Equal(t, CredKindHeaders, kindCol)
	assert.Equal(t, adminstore.MCPUserCredStatusActive, statusCol)
	assert.NotContains(t, ctCol, v1, "the at-rest ciphertext must not carry the plaintext")
	res, err := invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+v1)

	// Leg 2 — rotation: the next invoke serves v2; v1 is never re-sent.
	rotated, err := store.UpsertMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA, CredKindHeaders, headersJSON(v2), nil)
	require.NoError(t, err)
	assert.Greater(t, rotated.Version, row.Version, "rotation must bump the row version")
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+v2)
	assert.NotContains(t, string(res), v1)
	assert.Equal(t, 1, up.snapshot()["Bearer "+v1], "the old version must not be re-sent after rotation")

	// Leg 3 — explicit revoke: the next invoke fails closed, repeatedly,
	// and the revoked row is gone from the store.
	require.NoError(t, store.DeleteMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA))
	_, err = store.GetMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA)
	assert.True(t, adminstore.IsNotFound(err), "the revoked row must be gone")
	_, err = invoke(orgA, agentA)
	lifecycleIntRequireAuthRequired(t, err, CredKindHeaders)
	_, err = invoke(orgA, agentA)
	lifecycleIntRequireAuthRequired(t, err, CredKindHeaders)

	// Leg 4 — server-level fallback + rotation at that level: the deleted
	// user row falls through to the server credential, which the operator
	// rotates in place.
	_, err = store.UpsertMCPServerCredential(ctx, orgA, lifecycleIntServerName, CredKindHeaders, headersJSON(srvTok1))
	require.NoError(t, err)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+srvTok1)
	_, err = store.UpsertMCPServerCredential(ctx, orgA, lifecycleIntServerName, CredKindHeaders, headersJSON(srvTok2))
	require.NoError(t, err)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+srvTok2)
	assert.Equal(t, 1, up.snapshot()["Bearer "+srvTok1], "the old server-level version must not be re-sent")

	// Leg 5 — server-level disable acts as revocation (routing miss, not an
	// error), and re-enable restores service.
	_, err = store.SetMCPServerCredentialEnabled(ctx, orgA, lifecycleIntServerName, false)
	require.NoError(t, err)
	_, err = invoke(orgA, agentA)
	lifecycleIntRequireAuthRequired(t, err, CredKindHeaders)
	_, err = store.SetMCPServerCredentialEnabled(ctx, orgA, lifecycleIntServerName, true)
	require.NoError(t, err)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+srvTok2)

	// Leg 6 — scheduled revocation: an oauth credential inside its expiry
	// window serves; the same row past expires_at misses on the next invoke
	// (the lazy-expiry filter = revocation on schedule) and falls through to
	// the server level; re-activation returns it to service.
	future := time.Now().Add(time.Hour)
	_, err = store.UpsertMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA, CredKindOAuth,
		fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","refresh_token":"r034-intlc-refresh"}`, oauthTok), &future)
	require.NoError(t, err)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+oauthTok)
	expired := time.Now().Add(-time.Minute)
	_, err = store.UpdateMCPUserOAuthTokens(ctx, orgA, lifecycleIntServerName, agentA,
		fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer"}`, oauthTok), &expired)
	require.NoError(t, err)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+srvTok2, "the expired row must fall through to the server level")
	assert.NotContains(t, string(res), oauthTok, "the expired token must not resolve")
	_, err = store.UpdateMCPUserOAuthTokens(ctx, orgA, lifecycleIntServerName, agentA,
		fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer"}`, oauthTok), nil)
	require.NoError(t, err)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+oauthTok)

	// Leg 7 — upstream rejection is sticky revocation for a per-user
	// headers credential: the flagged row stops resolving through the real
	// active filter, and no later invoke replays the rejected value.
	up.rejectAll.Store(true)
	_, err = store.UpsertMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA, CredKindHeaders, headersJSON(v3), nil)
	require.NoError(t, err)
	_, err = invoke(orgA, agentA)
	lifecycleIntRequireAuthRequired(t, err, CredKindHeaders)
	flagged, gErr := store.GetMCPUserCredential(ctx, orgA, lifecycleIntServerName, agentA)
	require.NoError(t, gErr)
	assert.Equal(t, adminstore.MCPUserCredStatusNeedsReauth, flagged.Status, "the rejection must go sticky needs_reauth")
	up.rejectAll.Store(false)
	res, err = invoke(orgA, agentA)
	require.NoError(t, err)
	assert.Contains(t, string(res), "saw Bearer "+srvTok2, "the flagged row must fall through to the server level")
	assert.NotContains(t, string(res), v3, "the rejected value must not resolve again")

	// Leg 8 — foreign tenant: org B holds the same server name under its
	// own pin; none of org A's credential material ever resolves or egresses
	// on org B's invokes (the only new egress is the unauthenticated one).
	beforeB := up.snapshot()
	_, err = invoke(orgB, agentB)
	lifecycleIntRequireAuthRequired(t, err, CredKindHeaders)
	afterB := up.snapshot()
	assert.Equal(t, beforeB[""]+1, afterB[""], "org B's invoke must go out unauthenticated exactly once")
	assert.Len(t, afterB, len(beforeB), "org B's invoke must add no credential-bearing egress")
	for _, leak := range allTokens {
		assert.NotContains(t, err.Error(), leak)
		assert.Zero(t, cpIntDelta(beforeB, afterB, "Bearer "+leak), "org A material must never egress on org B's calls")
	}

	// Non-visibility across the whole flow: no token material anywhere in
	// the audit trail, and the hostile echo body never surfaces.
	assertNoMaterial(t, allTokens, err, auditEvents)
	for _, ev := range auditEvents {
		assert.NotContains(t, ev.ErrorMessage, "rejected credential",
			"the hostile echo body must never surface in the audit trail")
		assert.NotContains(t, string(ev.ParamsRedacted), "sk-intlc")
	}
	seen := up.snapshot()
	// Every version egresses a bounded number of times: the user tokens
	// exactly once (rotation/revoke replaces them before the next invoke),
	// the oauth token once per activation, and the surviving server-level
	// token once per resolve that falls through to it.
	assert.Equal(t, 1, seen["Bearer "+v1])
	assert.Equal(t, 1, seen["Bearer "+v2])
	assert.Equal(t, 1, seen["Bearer "+v3])
	assert.Equal(t, 1, seen["Bearer "+srvTok1])
	assert.Equal(t, 2, seen["Bearer "+oauthTok], "one per activation, never after expiry")
	assert.Equal(t, 4, seen["Bearer "+srvTok2], "fallback resolves after each user-level miss")
	assert.False(t, strings.Contains(fmt.Sprint(seen), "r034-intlc-refresh"), "the refresh token must never egress")
}
