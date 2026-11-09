package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/labels"
)

type memSessionKV struct {
	mu   sync.Mutex
	n    map[string]int64
	dels []string
}

func (m *memSessionKV) Get(_ context.Context, key string) *redis.StringCmd {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.n[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(strconv.FormatInt(v, 10), nil)
}

func (m *memSessionKV) Incr(ctx context.Context, key string) *redis.IntCmd {
	return m.IncrBy(ctx, key, 1)
}

func (m *memSessionKV) IncrBy(_ context.Context, key string, value int64) *redis.IntCmd {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n == nil {
		m.n = map[string]int64{}
	}
	m.n[key] += value
	return redis.NewIntResult(m.n[key], nil)
}

func (m *memSessionKV) Expire(context.Context, string, time.Duration) *redis.BoolCmd {
	return redis.NewBoolResult(true, nil)
}

func (m *memSessionKV) Del(_ context.Context, keys ...string) *redis.IntCmd {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dels = append(m.dels, keys...)
	return redis.NewIntResult(int64(len(keys)), nil)
}

type scriptDB struct {
	inserts [][]any
	loads   map[string]sessionRow
	usage   []any
}

func (s *scriptDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "INSERT INTO session_keys"):
		s.inserts = append(s.inserts, args)
		return scanRow{vals: []any{"sess-new"}}
	case strings.Contains(sql, "FROM session_keys WHERE id"):
		id, _ := args[0].(string)
		row, ok := s.loads[id]
		if !ok {
			return scanRow{err: errors.New("no row")}
		}
		return scanRow{vals: []any{row.id, row.parentID, row.keyHash, row.orgID, row.revokedAt, row.finishedAt}}
	case strings.Contains(sql, "count(*)"):
		if s.usage == nil {
			s.usage = []any{int64(2), int64(10), int64(4), int64(1), 0.5, int64(0)}
		}
		return scanRow{vals: s.usage}
	default:
		return scanRow{err: errors.New("no row")}
	}
}

func (s *scriptDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("no model rows")
}

func (s *scriptDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	id, _ := args[0].(string)
	row := s.loads[id]
	now := time.Now()
	row.revokedAt = &now
	if strings.Contains(sql, "finished_at") && row.finishedAt == nil {
		row.finishedAt = &now
	}
	s.loads[id] = row
	if strings.Contains(sql, "finished_at IS NULL") && row.finishedAt != nil && !row.finishedAt.Equal(now) {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

type scanRow struct {
	vals []any
	err  error
}

func (r scanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		if i >= len(r.vals) || r.vals[i] == nil {
			continue
		}
		switch d := d.(type) {
		case *string:
			*d = r.vals[i].(string)
		case *int64:
			*d = r.vals[i].(int64)
		case *float64:
			*d = r.vals[i].(float64)
		case **time.Time:
			switch v := r.vals[i].(type) {
			case *time.Time:
				*d = v
			case time.Time:
				copied := v
				*d = &copied
			}
		default:
			return errors.New("unsupported scan dest")
		}
	}
	return nil
}

func mintGW(db *scriptDB, kv sessionRedis, logs *bytes.Buffer) *gateway {
	gw := &gateway{sessionDB: db, sessionKV: kv, log: slog.New(slog.DiscardHandler)}
	if logs != nil {
		gw.log = slog.New(slog.NewTextHandler(logs, nil))
	}
	return gw
}

func mintReq(t *testing.T, p principal, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/yabanin/session-keys", strings.NewReader(body))
	ctx := withPrincipal(req.Context(), p)
	ctx = withPrincipalLabelSources(ctx, []labels.Source{{Name: "key", Labels: labels.Set{"team": "payments"}, Locked: true}})
	req = req.WithContext(ctx)
	req.Header.Set("X-Org-Id", "org-1")
	return req
}

func TestMintSessionKey_Matrix(t *testing.T) {
	parent := principal{APIKeyID: "parent-1", CanMintSessions: true}
	db := &scriptDB{}
	var logs bytes.Buffer
	gw := mintGW(db, &memSessionKV{}, &logs)

	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, principal{APIKeyID: "parent-1"}, `{}`))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, principal{APIKeyID: "parent-1", AgentID: "agent-1", CanMintSessions: true}, `{}`))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, principal{APIKeyID: "parent-1", SessionKeyID: "sess", CanMintSessions: true}, `{}`))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, parent, `{"ttl_seconds":10}`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_ttl")

	rec = httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, parent, `{"name":"bad name!"}`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_name")

	rec = httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, parent, `{"labels":{"yabanin.secret":"1","team":"other"},"ttl_seconds":60}`))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ybs_")
	assert.Contains(t, rec.Body.String(), "reserved")
	assert.NotContains(t, logs.String(), "ybs_")
	require.NotEmpty(t, db.inserts)
	raw, _ := db.inserts[len(db.inserts)-1][4].([]byte)
	assert.NotContains(t, string(raw), "yabanin")
	assert.NotContains(t, string(raw), "payments")

	kv := &memSessionKV{n: map[string]int64{}}
	gw.sessionKV = kv
	kv.n["yb:skey:mint:parent-1:"+strconv.FormatInt(time.Now().Unix()/60, 10)] = 60
	rec = httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, parent, `{}`))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "rate_limited")
}

func TestSessionKey_RevokeFinishUsageAndForeignID(t *testing.T) {
	db := &scriptDB{loads: map[string]sessionRow{
		"sess-1": {id: "sess-1", parentID: "parent-1", keyHash: "hash-1", orgID: "org-1"},
		"sess-2": {id: "sess-2", parentID: "parent-1", keyHash: "hash-2", orgID: "org-1"},
	}}
	kv := &memSessionKV{}
	gw := mintGW(db, kv, nil)
	r := chi.NewRouter()
	r.Delete("/session-keys/{id}", gw.revokeSessionKey)
	r.Post("/session-keys/{id}/finish", gw.finishSessionKey)
	r.Get("/session-keys/{id}/usage", gw.sessionKeyUsage)

	call := func(method, path string, p principal, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req = req.WithContext(withPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	assert.Equal(t, http.StatusNotFound, call(http.MethodDelete, "/session-keys/sess-1", principal{APIKeyID: "other"}, "").Code)
	assert.Equal(t, http.StatusNoContent, call(http.MethodDelete, "/session-keys/sess-1", principal{APIKeyID: "parent-1"}, "").Code)
	assert.Contains(t, kv.dels, "org:resolve:hash-1")
	assert.Equal(t, http.StatusNoContent, call(http.MethodDelete, "/session-keys/sess-1", principal{APIKeyID: "parent-1"}, "").Code)

	assert.Equal(t, http.StatusNoContent, call(http.MethodPost, "/session-keys/sess-2/finish", principal{SessionKeyID: "sess-2"}, `{"status":"success","exit_code":0,"duration_ms":5}`).Code)
	assert.NotNil(t, db.loads["sess-2"].finishedAt)
	assert.Equal(t, http.StatusNoContent, call(http.MethodPost, "/session-keys/sess-2/finish", principal{SessionKeyID: "sess-2"}, `{"status":"failed"}`).Code)

	usage := call(http.MethodGet, "/session-keys/sess-1/usage", principal{APIKeyID: "parent-1"}, "")
	assert.Equal(t, http.StatusOK, usage.Code)
	assert.Contains(t, usage.Body.String(), `"requests":2`)
	assert.Equal(t, http.StatusNotFound, call(http.MethodGet, "/session-keys/sess-1/usage", principal{APIKeyID: "nope"}, "").Code)
}

func TestOwnUsage_RequiresFlag(t *testing.T) {
	gw := mintGW(&scriptDB{}, nil, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage", nil)
	req = req.WithContext(withPrincipal(req.Context(), principal{APIKeyID: "parent-1"}))
	req.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	gw.ownUsage(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/yabanin/usage", nil)
	req = req.WithContext(withPrincipal(req.Context(), principal{APIKeyID: "parent-1", CanReadUsage: true}))
	req.Header.Set("X-Org-Id", "org-1")
	rec = httptest.NewRecorder()
	gw.ownUsage(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestSessionBudget_ExceededAndRecord(t *testing.T) {
	max := int64(10)
	kv := &memSessionKV{n: map[string]int64{"yb:skey:sess-1:tok": 10}}
	gw := &gateway{sessionKV: kv, log: slog.New(slog.DiscardHandler)}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)
	req = req.WithContext(withPrincipal(req.Context(), principal{SessionKeyID: "sess-1", SessionMaxTokens: &max}))
	rec := httptest.NewRecorder()
	assert.False(t, gw.checkSessionBudget(rec, req))
	assert.Equal(t, "false", rec.Header().Get("x-should-retry"))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	gw.sessionKV = &memSessionKV{}
	rec = httptest.NewRecorder()
	gw.recordSessionSpend(req.Context(), rec, 3, 0, false)
	assert.Equal(t, "unpriced_requests", rec.Header().Get("X-Yabanin-Budget-Warning"))
	assert.Equal(t, int64(3), gw.sessionKV.(*memSessionKV).n["yb:skey:sess-1:tok"])
}

func TestSessionLabels_LockedNotOverridden(t *testing.T) {
	key, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	expires := time.Now().Add(time.Hour).UTC().Unix()
	raw := `v2:{"org":"org-1","key":"parent-1","team":"team-1","labels":{"team":"payments"},"locked":true,"session":"sess-1","slabels":{"job":"lint"},"slocked":true,"sexp":` + strconv.FormatInt(expires, 10) + `}`
	pool := &mockDBForGateway{queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		t.Fatal("cache hit should not query")
		return nil
	}}
	rdb := &mockRedisForGateway{getFn: func(ctx context.Context, key string) *redis.StringCmd {
		return redis.NewStringResult(raw, nil)
	}}
	resolver := auth.NewResolver(pool, rdb, 300, nil)
	gw := &gateway{}
	var got map[string]string
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Yabanin-Labels", "job=other,team=other")
	NewAuthMiddleware(newGatewayConfig("header", "", ""), resolver).ServeHTTP(gw.labelsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = map[string]string{}
		for k, v := range labelsFrom(r.Context()) {
			got[k] = v
		}
		if r.Header.Get("X-API-Key-Id") != "parent-1" {
			t.Fatalf("parent id %s", r.Header.Get("X-API-Key-Id"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	assert.Equal(t, "payments", got["team"])
	assert.Equal(t, "lint", got["job"])
	assert.Contains(t, rec.Header().Get("X-Yabanin-Labels-Dropped"), "locked")
}

func TestSessionsUnavailableWithoutDB(t *testing.T) {
	gw := &gateway{log: slog.New(slog.DiscardHandler)}
	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/yabanin/session-keys", nil))
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "session_keys_unavailable")
}

// AUTH-03: a minted session must never outlive its parent API key. A TTL
// longer than the parent's remaining lifetime is capped at the parent's
// expiry; the stored row and the response both carry the capped instant.
func TestMintSessionKey_CapsAtParentKeyExpiry(t *testing.T) {
	parentExpires := time.Now().UTC().Add(45 * time.Minute)
	db := &scriptDB{}
	gw := mintGW(db, &memSessionKV{}, nil)

	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, mintReq(t, principal{
		APIKeyID: "parent-1", CanMintSessions: true, KeyExpiresAt: parentExpires,
	}, `{"ttl_seconds":7200}`))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var body struct {
		ExpiresAt string `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	expires, err := time.Parse(time.RFC3339, body.ExpiresAt)
	require.NoError(t, err)
	assert.False(t, expires.After(parentExpires),
		"session expires %s must be capped at parent expiry %s", expires, parentExpires)

	// The stored row carries the same capped instant (arg 9 of the INSERT).
	require.Len(t, db.inserts, 1)
	stored, ok := db.inserts[0][8].(time.Time)
	require.True(t, ok, "expires_at insert arg = %T", db.inserts[0][8])
	assert.False(t, stored.After(parentExpires))
}
