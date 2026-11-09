package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/errors"
)

// Every write also signals writtenCh (non-blocking), so tests can synchronize
// on the async tracker write instead of polling.
type expiryExecStore struct {
	mu        sync.Mutex
	batch     [][]string
	writtenCh chan struct{}
}

func (s *expiryExecStore) Exec(_ context.Context, _ string, args ...interface{}) (pgconn.CommandTag, error) {
	ids, _ := args[0].([]string)
	s.mu.Lock()
	s.batch = append(s.batch, ids)
	s.mu.Unlock()
	select {
	case s.writtenCh <- struct{}{}:
	default:
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (s *expiryExecStore) written() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, b := range s.batch {
		ids = append(ids, b...)
	}
	return ids
}

// waitWritten waits (bounded) for the tracker's first async UPDATE.
func (s *expiryExecStore) waitWritten(t *testing.T) {
	t.Helper()
	select {
	case <-s.writtenCh:
	case <-time.After(2 * time.Second):
		t.Fatal("the last-used tracker never flushed an UPDATE")
	}
}

func expiryResolver(expiresAt *time.Time) *auth.Resolver {
	pool := &mockDBForGateway{
		queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			return &mockRowForGateway{orgID: "org-imp81", expiresAt: expiresAt}
		},
	}
	rdb := &mockRedisForGateway{}
	return auth.NewResolver(pool, rdb, 300, nil)
}

func doAuthRequest(t *testing.T, mw *AuthMiddleware, next http.Handler, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(next).ServeHTTP(rec, req)
	return rec
}

// "key_expired" — distinguishable from an unknown-key 401.
func TestAuthMiddleware_ExpiredKey_401WithKeyExpiredCode(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	mw := newTestAuthMiddleware(newGatewayConfig("header", "", ""), expiryResolver(&past))

	rec := doAuthRequest(t, mw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not run for an expired key")
	}), "sk_expired")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	var doc struct {
		Error struct {
			Type    string  `json:"type"`
			Code    *string `json:"code"`
			Message string  `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, errors.ErrorCodeAuthentication, doc.Error.Type)
	require.NotNil(t, doc.Error.Code)
	assert.Equal(t, errors.CodeKeyExpired, *doc.Error.Code)
	assert.Contains(t, strings.ToLower(doc.Error.Message), "expire")
}

// A key with a future expiry and a never-expiring key both pass through.
func TestAuthMiddleware_FutureAndNoExpiry_Resolve(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	for name, exp := range map[string]*time.Time{"future": &future, "never": nil} {
		t.Run(name, func(t *testing.T) {
			mw := newTestAuthMiddleware(newGatewayConfig("header", "", ""), expiryResolver(exp))
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "org-imp81", r.Header.Get("X-Org-Id"))
				w.WriteHeader(http.StatusOK)
			})
			rec := doAuthRequest(t, mw, next, "sk_valid")
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

// enqueue at most one last_used_at UPDATE per key, and none of them waits on
// the DB write.
func TestAuthMiddleware_LastUsedThrottledAsync(t *testing.T) {
	store := &expiryExecStore{writtenCh: make(chan struct{}, 1)}
	tr := auth.NewLastUsedTracker(context.Background(), store, 128, 1, time.Minute)
	defer tr.Close()

	mw := newTestAuthMiddleware(newGatewayConfig("header", "", ""), expiryResolver(nil))
	mw.SetLastUsedTracker(tr)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 1000; i++ {
		rec := doAuthRequest(t, mw, next, "sk_hot")
		require.Equal(t, http.StatusOK, rec.Code)
	}

	// The tracker signals through the store double when the async UPDATE
	// lands — no polling.
	store.waitWritten(t)
	ids := store.written()
	require.Len(t, ids, 1, "1000 requests within a minute must record at most one last_used_at write")
	assert.Equal(t, "org-imp81", ids[0], "the mock row resolves api key id = org id")
}
