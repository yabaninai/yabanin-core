package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
)

// mockRowForGateway implements pgx.Row for gateway tests.
type mockRowForGateway struct {
	err       error
	orgID     string
	userID    string
	expiresAt *time.Time
}

func (m *mockRowForGateway) Scan(dest ...interface{}) error {
	if m.err != nil {
		return m.err
	}
	n := 0
	for _, d := range dest {
		switch p := d.(type) {
		case *string:
			// api_keys scan order: id, org, team, user.
			if n == 3 {
				*p = m.userID
			} else {
				*p = m.orgID
			}
			n++
		case **time.Time:
			if m.expiresAt != nil {
				*p = m.expiresAt
			}
		}
	}
	return nil
}

// mockDBForGateway implements auth.DBPool.
type mockDBForGateway struct {
	queryRowFn func(ctx context.Context, query string, args ...interface{}) pgx.Row
}

func (m *mockDBForGateway) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, query, args...)
	}
	return &mockRowForGateway{err: pgx.ErrNoRows}
}

// mockRedisForGateway implements auth.RedisClient.
type mockRedisForGateway struct {
	getFn func(ctx context.Context, key string) *redis.StringCmd
	setFn func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

func (m *mockRedisForGateway) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.getFn != nil {
		return m.getFn(ctx, key)
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(redis.Nil)
	return cmd
}

func (m *mockRedisForGateway) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if m.setFn != nil {
		return m.setFn(ctx, key, value, expiration)
	}
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func newGatewayConfig(authMode, apiKey, fallbackKey string) config.Gateway {
	return config.Gateway{
		ListenAddr:    ":8082",
		Provider:      "localhost:8081",
		AuthMode:      authMode,
		APIKey:        apiKey,
		FallbackKey:   fallbackKey,
		FallbackModel: "smart",
	}
}

func newTestResolver(orgID string, err error) *auth.Resolver {
	pool := &mockDBForGateway{
		queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRowForGateway{orgID: orgID, err: err}
		},
	}
	rdb := &mockRedisForGateway{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			cmd := redis.NewStringCmd(ctx)
			cmd.SetErr(redis.Nil)
			return cmd
		},
	}
	return auth.NewResolver(pool, rdb, 300, nil)
}

func newCachedResolver(orgID string) *auth.Resolver {
	pool := &mockDBForGateway{
		queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRowForGateway{err: errors.New("should not be called on cache hit")}
		},
	}
	rdb := &mockRedisForGateway{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal(orgID + "|cached-key-id|")
			return cmd
		},
	}
	return auth.NewResolver(pool, rdb, 300, nil)
}

func newTestAuthMiddleware(cfg config.Gateway, resolver *auth.Resolver) *AuthMiddleware {
	return NewAuthMiddleware(cfg, resolver)
}

// --- X-Org-Id sanitization tests ---

func TestGatewayAuthMiddleware_XOrgIdDeletedAtEntry(t *testing.T) {
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Set("X-Org-Id", "org-hacker-123")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Org-Id"); got != "" {
			t.Errorf("expected X-Org-Id to be deleted at entry, got: %q", got)
		}
	})

	mw.ServeHTTP(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_XOrgIdNotInjectedWhenNoResolver(t *testing.T) {
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Org-Id"); got != "" {
			t.Errorf("expected X-Org-Id to be empty without resolver, got: %q", got)
		}
	})

	mw.ServeHTTP(handler).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_XOrgIdInjectedOnResolverSuccess(t *testing.T) {
	resolver := newTestResolver("org-resolved-abc", nil)
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, resolver)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Org-Id")
		assert.Equal(t, "org-resolved-abc", got)
	})

	mw.ServeHTTP(handler).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_XOrgIdInjectedFromCache(t *testing.T) {
	resolver := newCachedResolver("org-cached-xyz")
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, resolver)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Org-Id")
		assert.Equal(t, "org-cached-xyz", got)
	})

	mw.ServeHTTP(handler).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_XOrgIdSpoofingPrevented(t *testing.T) {
	resolver := newTestResolver("org-trusted-123", nil)
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, resolver)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Set("X-Org-Id", "org-spoofed-bad")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Org-Id")
		assert.Equal(t, "org-trusted-123", got, "spoofed X-Org-Id should be replaced by resolver")
	})

	mw.ServeHTTP(handler).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_MultipleOrgIdHeadersSanitized(t *testing.T) {
	resolver := newTestResolver("org-single", nil)
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, resolver)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Add("X-Org-Id", "org-first")
	req.Header.Add("X-Org-Id", "org-second")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header["X-Org-Id"]
		assert.Equal(t, []string{"org-single"}, got)
	})

	mw.ServeHTTP(handler).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- Token validation tests (timing-safe comparison verification) ---

func TestGatewayAuthMiddleware_HeaderMode_ValidKey(t *testing.T) {
	cfg := newGatewayConfig("header", "my-api-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer my-api-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_HeaderMode_FallbackKeyMatches(t *testing.T) {
	cfg := newGatewayConfig("header", "primary-key", "fallback-key")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer fallback-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_HeaderMode_BothKeysRejected(t *testing.T) {
	cfg := newGatewayConfig("header", "primary-key", "fallback-key")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer neither-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid key")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_BearerPrefixVariants(t *testing.T) {
	cfg := newGatewayConfig("header", "my-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	validCases := []string{"Bearer my-key", "bearer my-key"}
	invalidCases := []string{"BEARER my-key", "beArEr my-key"}

	for _, tc := range validCases {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		req.Header.Set("Authorization", tc)

		rec := httptest.NewRecorder()
		mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "for auth %q: expected 200", tc)
	}

	for _, tc := range invalidCases {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		req.Header.Set("Authorization", tc)

		rec := httptest.NewRecorder()
		mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("handler should not be called for auth %q", tc)
		})).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "for auth %q: expected 401", tc)
	}
}

func TestGatewayAuthMiddleware_DefaultMode_ValidKey(t *testing.T) {
	cfg := newGatewayConfig("", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_InvalidKey_Rejected(t *testing.T) {
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid key")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_XAPIKeyAuthenticates(t *testing.T) {
	cfg := newGatewayConfig("strict", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/messages", nil)
	req.Header.Set("x-api-key", "valid-key")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer valid-key", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("x-api-key"))
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_AuthorizationWinsOverXAPIKey(t *testing.T) {
	cfg := newGatewayConfig("strict", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Set("x-api-key", "wrong-key")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer valid-key", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("x-api-key"))
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_MissingAuthHeader(t *testing.T) {
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without Authorization header")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_EmptyToken(t *testing.T) {
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer ")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with empty token")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_BasicSchemeRejected(t *testing.T) {
	cfg := newGatewayConfig("header", "valid-key", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with Basic auth scheme")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_StaticKeyTimingSafe_PrefixMatch_Fail(t *testing.T) {
	cfg := newGatewayConfig("header", "abcdefghijklmnop", "")
	mw := newTestAuthMiddleware(cfg, nil)

	testCases := []string{
		"abcdefghijklmno",
		"abcdefghijklmnopq",
		"ABCDEFGHIJKLMNOP",
		"abcdegfghijklmnop",
	}

	for _, tc := range testCases {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+tc)

		rec := httptest.NewRecorder()
		mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("handler should not be called for key %q", tc)
		})).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "for key %q: expected 401", tc)
	}
}

func TestGatewayAuthMiddleware_FallbackKeyTimingSafe_PrefixMatch_Fail(t *testing.T) {
	cfg := newGatewayConfig("header", "primary-key", "fallback-12345")
	mw := newTestAuthMiddleware(cfg, nil)

	testCases := []string{
		"fallback-1234",
		"fallback-123456",
		"FALLBACK-12345",
	}

	for _, tc := range testCases {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+tc)

		rec := httptest.NewRecorder()
		mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("handler should not be called for key %q", tc)
		})).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "for key %q: expected 401", tc)
	}
}

func TestGatewayAuthMiddleware_NoResolverNoStaticKey_Rejected(t *testing.T) {
	cfg := newGatewayConfig("header", "", "")
	mw := newTestAuthMiddleware(cfg, nil)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer any-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without any configured key")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_HeaderMode_ResolverFail_Rejected(t *testing.T) {
	resolver := newTestResolver("", errors.New("not found"))
	cfg := newGatewayConfig("header", "", "")
	mw := newTestAuthMiddleware(cfg, resolver)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called in header mode when resolver fails")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_ExpiredPersonalKey_Unauthorized(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	pool := &mockDBForGateway{
		queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			if strings.Contains(query, "agent_keys") {
				return &mockRowForGateway{err: errors.New("no rows")}
			}
			return &mockRowForGateway{orgID: "org-1", expiresAt: &past}
		},
	}
	rdb := &mockRedisForGateway{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			cmd := redis.NewStringCmd(ctx)
			cmd.SetErr(redis.Nil)
			return cmd
		},
	}
	mw := newTestAuthMiddleware(newGatewayConfig("header", "", ""), auth.NewResolver(pool, rdb, 300, nil))
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer yb_expired")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("expired key must not reach the handler")
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGatewayAuthMiddleware_ClientUserIDDoesNotSurvive(t *testing.T) {
	const user = "11111111-1111-4111-8111-111111111111"
	pool := &mockDBForGateway{
		queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRowForGateway{orgID: "org-1", userID: user}
		},
	}
	rdb := &mockRedisForGateway{
		getFn: func(ctx context.Context, key string) *redis.StringCmd {
			cmd := redis.NewStringCmd(ctx)
			cmd.SetErr(redis.Nil)
			return cmd
		},
	}
	mw := newTestAuthMiddleware(newGatewayConfig("header", "", ""), auth.NewResolver(pool, rdb, 300, nil))
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer yb_personal")
	req.Header.Set("X-User-Id", "forged-user")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, user, r.Header.Get("X-User-Id"))
		assert.NotEqual(t, "forged-user", r.Header.Get("X-User-Id"))
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGatewayAuthMiddleware_NoResolverDropsClientUserID(t *testing.T) {
	mw := newTestAuthMiddleware(newGatewayConfig("header", "valid-key", ""), nil)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer valid-key")
	req.Header.Set("X-User-Id", "forged-user")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("X-User-Id"))
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- P0.2 Debug vars auth bypass regression tests ---

func TestDebugVars_LocalhostWithValidKey(t *testing.T) {
	cfg := newGatewayConfig("header", "admin-key", "")
	gw := &gateway{cfg: cfg}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/vars", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer admin-key")

	rec := httptest.NewRecorder()
	gw.debugVars(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDebugVars_LocalhostWithoutApiKey_Rejected(t *testing.T) {
	cfg := newGatewayConfig("header", "admin-key", "")
	gw := &gateway{cfg: cfg}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/vars", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	gw.debugVars(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDebugVars_LocalhostWithWrongKey_Rejected(t *testing.T) {
	cfg := newGatewayConfig("header", "admin-key", "")
	gw := &gateway{cfg: cfg}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/vars", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer wrong-key")

	rec := httptest.NewRecorder()
	gw.debugVars(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDebugVars_RemoteIP_RejectedEvenWithValidKey(t *testing.T) {
	cfg := newGatewayConfig("header", "admin-key", "")
	gw := &gateway{cfg: cfg}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/vars", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("Authorization", "Bearer admin-key")

	rec := httptest.NewRecorder()
	gw.debugVars(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDebugVars_XForwardedForCannotBypassLocalhostCheck(t *testing.T) {
	cfg := newGatewayConfig("header", "admin-key", "")
	gw := &gateway{cfg: cfg}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/vars", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Authorization", "Bearer admin-key")

	rec := httptest.NewRecorder()
	gw.debugVars(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDebugVars_EmptyAPIKeyConfig_AnyTokenRejected(t *testing.T) {
	cfg := newGatewayConfig("header", "", "")
	gw := &gateway{cfg: cfg}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/debug/vars", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	gw.debugVars(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
