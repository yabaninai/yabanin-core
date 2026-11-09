//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/gateway"
	"github.com/stretchr/testify/assert"
)

// mockRow implements pgx.Row interface
type mockRow struct {
	scanErr  error
	orgID    string
	apiKeyID string
	teamID   string
}

func (m *mockRow) Scan(dest ...interface{}) error {
	if m.scanErr != nil {
		return m.scanErr
	}
	for i, d := range dest {
		if i >= 3 {
			break
		}
		switch v := d.(type) {
		case *string:
			if i == 0 {
				*v = m.apiKeyID
			} else if i == 1 {
				*v = m.orgID
			} else if i == 2 {
				*v = m.teamID
			}
		case *bool:
			*v = true
		case *int64:
			*v = 123
		}
	}
	return nil
}

// mockPool implements auth.DBPool interface
type mockPool struct {
	QueryRowFunc func(ctx context.Context, query string, args ...interface{}) pgx.Row
}

func (m *mockPool) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	if m.QueryRowFunc != nil {
		return m.QueryRowFunc(ctx, query, args...)
	}
	return &mockRow{scanErr: errors.New("no rows")}
}

// mockRedisClient implements auth.RedisClient interface
type mockRedisClient struct {
	getFunc  func(ctx context.Context, key string) (string, error)
	setFunc  func(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	setCalls []string
}

func (m *mockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.getFunc != nil {
		val, err := m.getFunc(ctx, key)
		return redis.NewStringResult(val, err)
	}
	return redis.NewStringResult("", errors.New("not found"))
}

func (m *mockRedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	m.setCalls = append(m.setCalls, key)
	if m.setFunc != nil {
		err := m.setFunc(ctx, key, value, ttl)
		return redis.NewStatusResult("", err)
	}
	return redis.NewStatusResult("", nil)
}

func TestAuthMiddleware_MissingAuth(t *testing.T) {
	mw := cli.NewAuthMiddleware(config.Gateway{
		AuthMode:    "header",
		APIKey:      "test-key",
		FallbackKey: os.Getenv("YABANIN_FALLBACK_API_KEY"),
	}, nil)

	handler := mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "http://test/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing auth: expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ValidAPIKey(t *testing.T) {
	mw := cli.NewAuthMiddleware(config.Gateway{
		AuthMode:    "header",
		APIKey:      "test-key",
		FallbackKey: os.Getenv("YABANIN_FALLBACK_API_KEY"),
	}, nil)

	handler := mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest(http.MethodGet, "http://test/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("valid auth: expected 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidAPIKey(t *testing.T) {
	mw := cli.NewAuthMiddleware(config.Gateway{
		AuthMode:    "header",
		APIKey:      "test-key",
		FallbackKey: os.Getenv("YABANIN_FALLBACK_API_KEY"),
	}, nil)

	handler := mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest(http.MethodGet, "http://test/", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid auth: expected 401, got %d", rec.Code)
	}
}

func TestConfigLoad(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
gateway:
  listen_address: :9090
  auth_mode: strict
  api_key: my-secret-key
`), 0600)
	assert.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	assert.NoError(t, err)
	assert.Equal(t, ":9090", cfg.Gateway.ListenAddr)
	assert.Equal(t, "strict", cfg.Gateway.AuthMode)
	assert.Equal(t, "my-secret-key", cfg.Gateway.APIKey)
}

func TestAuthMiddleware_WithResolver(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRow{apiKeyID: "key-123", orgID: "org-resolved-123", teamID: "team-general"}
		},
	}
	rdb := &mockRedisClient{
		getFunc: func(ctx context.Context, key string) (string, error) {
			return "", errors.New("cache miss")
		},
	}

	mw := cli.NewAuthMiddleware(config.Gateway{
		AuthMode: "strict",
		APIKey:   "test-key",
	}, auth.NewResolver(pool, rdb, 300, nil))

	handler := mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest(http.MethodGet, "http://test/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if got := req.Header.Get("X-Org-Id"); got != "org-resolved-123" {
		t.Errorf("expected X-Org-Id 'org-resolved-123', got '%s'", got)
	}
}

func TestAuthMiddleware_ResolverFailOpen(t *testing.T) {
	pool := &mockPool{
		QueryRowFunc: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRow{scanErr: errors.New("db error")}
		},
	}

	resolver := auth.NewResolver(pool, nil, 300, nil)
	_, _ = resolver.Resolve(context.Background(), "test-key")

	mw := cli.NewAuthMiddleware(config.Gateway{
		AuthMode: "strict",
		APIKey:   "",
	}, resolver)

	handler := mw.ServeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest(http.MethodGet, "http://test/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("resolver failure in strict mode: expected 401, got %d", rec.Code)
	}
}

// Note: the old TestAuthMiddleware_ResolverFailOpen_FailOpenMode was removed —
// it asserted a `fail-open` auth mode that the implementation intentionally
// rejects. `config.Gateway.Validate` only allows `header`|`strict` (plan I2.3),
// and `AuthMiddleware` fails closed (401) on org-resolution error for both. The
// fail-closed contract is covered by TestAuthMiddleware_ResolverFailOpen above.
