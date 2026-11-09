package handlers

// HOT-PATCH inside SetupRouter's protected group (router.go is a hot file),
// so these tests mount the exact same chain locally (session revalidation +
// CSRF, GET exempt) to prove the session gate and the payload contract.
// The migration-version acceptance runs against the real, fully migrated
// disposable Postgres (testdb.Postgres): the reported version must equal
// SELECT MAX(version) FROM schema_migrations on the same pool.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// versionTestSecret is the test-only HMAC key for session cookies.
const versionTestSecret = "version-handler-test-secret" // #nosec G101 -- test-only HMAC key

// versionStubStore is a StoreInterface whose only live surfaces are the
// session revalidation lookup and a nil DB() capability (→ migration 0).
type versionStubStore struct {
	StoreInterface
}

func (s *versionStubStore) GetAdminUserByID(_ context.Context, id string) (*adminstore.AdminUser, error) {
	return &adminstore.AdminUser{
		ID: id, Email: id + "@x.test", DisplayName: "Version Stub",
		IsRoot: id == "test-root", Active: true,
	}, nil
}

func (s *versionStubStore) DB() *pgxpool.Pool { return nil }

// versionTestRouter mirrors the protected-group registration the HOT-PATCH
// applies in SetupRouter: same middlewares, same order (session revalidation
// then CSRF; GET is CSRF-exempt like every /api read).
func versionTestRouter(h *AdminHandlers) http.Handler {
	r := chi.NewRouter()
	r.Use(adminauth.ChiAuthMiddleware(versionTestSecret, h.adminSessionRevalidate))
	r.Use(adminauth.CSRFValidation())
	r.Get("/api/version", h.Version())
	return r
}

// versionSessionCookie builds a signed admin session cookie (same attributes
// as the production cookie).
func versionSessionCookie(t *testing.T, userID string, isRoot bool) *http.Cookie {
	t.Helper()
	c, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    userID,
		Email:     userID + "@x.test",
		IsRoot:    isRoot,
		SessionID: "version-test-session",
		ExpiresAt: time.Now().Add(time.Hour),
	}, versionTestSecret)
	require.NoError(t, err)
	return &http.Cookie{Name: c.Name, Value: c.Value, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func getVersion(t *testing.T, router http.Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/version", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func biWithRev(rev, modified string) *debug.BuildInfo {
	return &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: rev},
		{Key: "vcs.modified", Value: modified},
	}}
}

func TestBuildIdentity(t *testing.T) {
	bi := &debug.BuildInfo{}
	cases := []struct {
		name              string
		ldVersion, ldCo   string
		buildInfo         *debug.BuildInfo
		wantV, wantCommit string
	}{
		{"ldflags overrides win", "v9.9.9", "abc1234", biWithRev("feedc0de", "true"), "v9.9.9", "abc1234"},
		{"vcs fallback dirty", "", "", biWithRev("feedc0de", "true"), "dev", "feedc0de-dirty"},
		{"vcs fallback clean", "", "", biWithRev("feedc0de", "false"), "dev", "feedc0de"},
		{"no info", "", "", nil, "dev", "unknown"},
		{"empty build info", "", "", bi, "dev", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, c := buildIdentity(tc.ldVersion, tc.ldCo, tc.buildInfo)
			assert.Equal(t, tc.wantV, v)
			assert.Equal(t, tc.wantCommit, c)
		})
	}
}

// pin it so an accidental change is a deliberate, reviewed act.
func TestVersion_APILevelStartsAtOne(t *testing.T) {
	assert.Equal(t, 1, AdminAPILevel)
}

// versionFakeRow returns a canned Scan outcome.
type versionFakeRow struct {
	scan func(dest ...any) error
}

func (r versionFakeRow) Scan(dest ...any) error { return r.scan(dest...) }

// versionFakeQuerier records the SQL it was asked to run.
type versionFakeQuerier struct {
	sql string
	row pgx.Row
}

func (q *versionFakeQuerier) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	q.sql = sql
	return q.row
}

// The migration version must come from the same state pkg/migrate maintains
// (schema_migrations), never from a second source.
func TestReadSchemaVersion_UsesMigrateState(t *testing.T) {
	q := &versionFakeQuerier{row: versionFakeRow{scan: func(dest ...any) error {
		*(dest[0].(*int64)) = 42
		return nil
	}}}
	version, err := readSchemaVersion(t.Context(), q)
	require.NoError(t, err)
	assert.Equal(t, int64(42), version)
	assert.Contains(t, q.sql, "schema_migrations")
	assert.Contains(t, q.sql, "MAX(version)")
}

func TestReadSchemaVersion_ReadFailureDegrades(t *testing.T) {
	q := &versionFakeQuerier{row: versionFakeRow{scan: func(_ ...any) error {
		return errors.New("no rows / NULL / table missing")
	}}}
	version, err := readSchemaVersion(t.Context(), q)
	require.Error(t, err)
	assert.Equal(t, int64(0), version)
}

func TestVersion_Unauthenticated(t *testing.T) {
	h := New(&versionStubStore{}, versionTestSecret, "localhost", nil)
	router := versionTestRouter(h)

	w := getVersion(t, router, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "error")

	// A garbage cookie must not pass either.
	w = getVersion(t, router, &http.Cookie{Name: "yabanin_admin_session", Value: "forged", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// The handler itself fails closed when it ever runs without the session
	// context (route left the protected group).
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/version", nil)
	rw := httptest.NewRecorder()
	h.Version()(rw, req)
	assert.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.Contains(t, rw.Body.String(), "unauthorized")
}

// The payload contract: exactly version/commit/api_level/migration, all
// present, typed, non-empty where a string is promised, and free of secrets
// or machine paths. Numbers decode as json.Number and must parse as exact
// integers — a float or a string in their place fails the handshake test.
func TestVersion_PayloadTypedAndSecretFree(t *testing.T) {
	h := New(&versionStubStore{}, versionTestSecret, "localhost", nil)
	router := versionTestRouter(h)

	w := getVersion(t, router, versionSessionCookie(t, "test-root", true))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var payload struct {
		Version   string      `json:"version"`
		Commit    string      `json:"commit"`
		APILevel  json.Number `json:"api_level"`
		Migration json.Number `json:"migration"`
	}
	dec := json.NewDecoder(strings.NewReader(w.Body.String()))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&payload), "body: %s", w.Body.String())

	assert.NotEmpty(t, payload.Version, "version must be a non-empty string")
	assert.NotEmpty(t, payload.Commit, "commit must be a non-empty string")

	apiLevel, err := payload.APILevel.Int64()
	require.NoError(t, err, "api_level must be an integer, got %q", payload.APILevel.String())
	assert.Equal(t, AdminAPILevel, int(apiLevel))

	migration, err := payload.Migration.Int64()
	require.NoError(t, err, "migration must be an integer, got %q", payload.Migration.String())
	assert.GreaterOrEqual(t, migration, int64(0))

	// No secrets, no paths: build facts only.
	for _, banned := range []string{versionTestSecret, "postgres://", "password", "/Users/", "/home/", "sqlserver"} {
		assert.NotContains(t, w.Body.String(), banned)
	}
}

// Acceptance: the reported migration version equals the latest applied
// migration recorded in the migrate state (schema_migrations — the same
// table pkg/migrate reads and the runbooks repair), and the whole payload
// stays typed behind a real session.
func TestVersion_MigrationMatchesAppliedSchema(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	store := adminstore.New(pool, slog.Default(), nil)
	h := New(store, versionTestSecret, "localhost", nil)

	// Unique per run so -count>1 and -shuffle stay repeatable on the shared stand.
	email := fmt.Sprintf("version-int-%d@x.test", time.Now().UnixNano())
	user, err := store.CreateAdminUser(ctx, email, "Version Int", "version-int-test-hash", true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, user.ID) })

	// The test stand applies migrations without golang-migrate's bookkeeping
	// (pkg/testdb runs the .up.sql files directly). Record the exact migrate
	// state a real deployment has — the table definition pkg/migrate's own
	// canary test uses — with two applied versions; the handler must report
	// the latest one.
	_, err = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint NOT NULL, dirty boolean NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS schema_migrations`) })
	_, err = pool.Exec(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES ($1, false), ($2, false)`, 18, 37)
	require.NoError(t, err)

	router := versionTestRouter(h)
	w := getVersion(t, router, versionSessionCookie(t, user.ID, true))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp versionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, AdminAPILevel, resp.APILevel)
	assert.NotEmpty(t, resp.Version)
	assert.NotEmpty(t, resp.Commit)
	assert.Equal(t, int64(37), resp.Migration, "must report the latest applied migration (MAX(version))")

	for _, banned := range []string{versionTestSecret, "postgres://", "yabanin", "sslmode"} {
		assert.NotContains(t, w.Body.String(), banned)
	}
}

// A store without the DB() capability degrades to migration 0 but keeps the
// endpoint answerable (the dashboard still learns the API level).
func TestVersion_StoreWithoutCapabilityReportsZero(t *testing.T) {
	h := New(&versionStubStore{}, versionTestSecret, "localhost", nil)
	router := versionTestRouter(h)

	w := getVersion(t, router, versionSessionCookie(t, "test-admin", false))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), `"migration":0`)
	assert.NotContains(t, w.Body.String(), "SQLSTATE", "no storage errors may leak")
}
