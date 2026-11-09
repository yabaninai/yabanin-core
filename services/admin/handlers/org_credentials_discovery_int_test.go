//go:build integration

package handlers_test

// suite replayed through the REAL production boundaries, not the in-memory
// stubs — the card requires the actual consumer entry point, so every probe
// here runs through:
//
//   - the FULL SetupRouter (session HMAC + TP-02 revalidation + CSRF +
//     RequireOrgPermissionKeysManage over real SQL memberships),
//   - the real *adminstore.Store on a disposable, fully migrated Postgres
//     (org_provider_credentials RLS/GUC scoping, AES-GCM encryption at rest,
//     ResolveKey's enabled=true filter and /v1 normalization),
//   - the real SSRF-guarded production client where the scenario refuses
//     before dialing (loopback seed), the documented OrgCredentialHandlerOptions.
//     HTTPClient test seam only where a live upstream must answer,
//   - the real models_registry table for the display-only and manual-entry
//     fallback pins.
//
// The wire assertions pin the EXACT JSON key sets of both response states —
// the contract the dashboard client consumes (web/dashboard
// ProviderModelCatalog → catalogStateFromResult, pinned on the TS side by
// providerKeysHelpers.test.ts / providerKeysRegression.test.ts against these
// same shapes). Package criterion «Fallback ручного ввода; discovery не
// означает verified usability»; negative scenario «List API отсутствует, ключ
// без list permission, revoked key» (plus the real-store enabled-filter
// key_unavailable and the D-4 shared probe budget). Synthetic data only,
// disposable container, never the live stand.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
	"github.com/stretchr/testify/require"
)

const (
	// Integration-only stored plaintexts, distinct from every stub-based
	// fixture: a leak of the RESOLVED key cannot hide behind another file's
	// constants. #nosec G101 -- test-only fake values.
	r067IntStoredKey  = "sk-r067-integration-stored-0607"
	r067IntRotatedKey = "sk-r067-integration-rotated-0809"

	r067IntSessionSecret = "r067-int-session-key" // #nosec G101 -- test-only HMAC key
	r067IntUpstreamError = `{"error":{"message":"r067 upstream secret detail"}}`
)

// r067IntEnv is one wired scenario: a fresh router (fresh throttle) over the
// shared real store, its own version bumper and the shared log capture.
type r067IntEnv struct {
	router http.Handler
	bumper *credBumper
}

// newR067IntStore builds the production store over the disposable Postgres
// with a REAL encryptor (fail-closed posture, enc:-prefixed rows). The store
// logger shares the caller's capture buffer so the zero-log-leak assertion
// covers the store too.
func newR067IntStore(t *testing.T, pool *pgxpool.Pool, logs *bytes.Buffer) *adminstore.Store {
	t.Helper()
	return adminstore.New(pool, slog.New(slog.NewTextHandler(logs, nil)), encryption.MustNew(encryption.EncodeKey()))
}

// newR067IntRouter wires the full SetupRouter over store with the credential
// handlers attached (opts carries the HTTPClient seam when the scenario needs
// a live upstream; the zero value keeps the guarded production client).
func newR067IntRouter(t *testing.T, store *adminstore.Store, opts handlers.OrgCredentialHandlerOptions, logs *bytes.Buffer) *r067IntEnv {
	t.Helper()
	bumper := &credBumper{}
	opts.VersionBumper = bumper
	h := handlers.New(store, r067IntSessionSecret, "r067int.test", []string{})
	h.SetOrgCredentialHandlers(handlers.NewOrgCredentialHandlers(store, opts, slog.New(slog.NewTextHandler(logs, nil))))
	t.Cleanup(h.Stop)
	return &r067IntEnv{router: h.SetupRouter(), bumper: bumper}
}

// r067IntSessionCookieValue signs a session cookie for a seeded user (the
// exported adminauth contract; TP-02 revalidation resolves the user over real
// SQL on every probe).
func r067IntSessionCookieValue(t *testing.T, userID string, isRoot bool) string {
	t.Helper()
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    userID,
		Email:     userID + "@r067int.test",
		IsRoot:    isRoot,
		SessionID: "r067-" + userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}, r067IntSessionSecret)
	require.NoError(t, err, "sign session cookie for %s", userID)
	return cookie.Value
}

// r067IntIdentity seeds one org plus one org-admin member through the real
// store and returns the org id and the member's signed session cookie value.
func r067IntIdentity(t *testing.T, store *adminstore.Store, run, tag string) (string, string) {
	t.Helper()
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, "r067 int "+tag+" "+run, "r067-int-"+tag+"-"+run)
	require.NoError(t, err, "seed org %s", tag)
	t.Cleanup(func() { _ = store.DeleteOrganization(ctx, org.ID) })
	user, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("r067-%s-%s@sweep.test", tag, run), "r067 "+tag, "integration-hash-not-used-for-login", false)
	require.NoError(t, err, "seed admin user %s", tag)
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, user.ID) })
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{UserID: user.ID, OrgID: org.ID, Role: adminstore.RoleOrgAdmin})
	require.NoError(t, err, "seed membership %s", tag)
	return org.ID, r067IntSessionCookieValue(t, user.ID, false)
}

// r067IntRoot seeds one root identity (the manual-entry fallback surface is
// root-only) and returns the signed session cookie value.
func r067IntRoot(t *testing.T, store *adminstore.Store, run string) string {
	t.Helper()
	ctx := context.Background()
	user, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("r067-root-%s@sweep.test", run), "r067 root", "integration-hash-not-used-for-login", true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteAdminUser(ctx, user.ID) })
	return r067IntSessionCookieValue(t, user.ID, true)
}

// r067IntCredPath builds the credential-surface path for a real org id.
func r067IntCredPath(orgID, suffix string) string {
	return fmt.Sprintf("/api/orgs/%s/provider-credentials%s", orgID, suffix)
}

// r067NoKeyMaterial extends the stub-suite leak pin to the integration
// plaintexts: neither key may appear in any response body, response header or
// captured log line (store logger included).
func r067NoKeyMaterial(t *testing.T, w *httptest.ResponseRecorder, logs *bytes.Buffer) {
	t.Helper()
	for _, key := range []string{r067IntStoredKey, r067IntRotatedKey} {
		if strings.Contains(w.Body.String(), key) {
			t.Fatalf("response body leaks key material: %s", w.Body.String())
		}
		for name, values := range w.Header() {
			for _, v := range values {
				if strings.Contains(v, key) {
					t.Fatalf("response header %q leaks key material: %s", name, v)
				}
			}
		}
		if logs != nil && strings.Contains(logs.String(), key) {
			t.Fatalf("log output leaks key material: %s", logs.String())
		}
	}
}

// r067JSONKeys decodes a response body and returns the sorted top-level JSON
// key set — the exact wire shape the dashboard client maps on.
func r067JSONKeys(t *testing.T, body []byte) []string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m), "body: %s", body)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// r067CredRow reads the credential row the way the store persisted it:
// enabled flag, key_version and the at-rest ciphertext.
func r067CredRow(t *testing.T, pool *pgxpool.Pool, credID string) (enabled bool, keyVersion int, apikeyCT string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT enabled, key_version, api_key_ct FROM org_provider_credentials WHERE id = $1::uuid`,
		credID).Scan(&enabled, &keyVersion, &apikeyCT))
	return enabled, keyVersion, apikeyCT
}

// r067RegistryCount counts models_registry rows carrying any of the given
// names — the display-only / fallback pin over the real registry table.
func r067RegistryCount(t *testing.T, pool *pgxpool.Pool, names []string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM models_registry WHERE model_name = ANY($1)`, names).Scan(&n))
	return n
}

// r067IntCatalog builds the OpenAI-compat list body with run-unique model ids
// so the display-only pin can count exact rows in the shared registry table.
func r067IntCatalog(run string) string {
	return fmt.Sprintf(`{"object":"list","data":[{"id":"int-large-%s","object":"model"},{"id":"int-mini-%s","object":"model"}]}`, run, run)
}

// TestR067Discovery_RealStore_WorkingInput pins contract Example A through
// the real boundaries: credential created over the public POST contract lands
// ENCRYPTED at rest; discovery resolves the decrypted stored key over real
// SQL and answers the parsed display-only snapshot (discovered=true with an
// explicit verified=false) after exactly one upstream call; the /models and
// /test surfaces share the one 1/min/org probe budget (D-4); nothing reaches
// models_registry while the manual-entry fallback registers the only row.
func TestR067Discovery_RealStore_WorkingInput(t *testing.T) {
	pool := testdb.Postgres(t)
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	logs := new(bytes.Buffer) // one capture for the store AND the handlers
	store := newR067IntStore(t, pool, logs)

	upstream := newCatalogUpstream(t, http.StatusOK, r067IntCatalog(run))
	env := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
	orgID, member := r067IntIdentity(t, store, run, "working")
	root := r067IntRoot(t, store, run)

	// The credential is stored through the public POST contract: 201 with the
	// last-4 mask only, and the at-rest row carries enc: ciphertext.
	w := credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, ""), member,
		credCreateBody("openai-compat", upstream.srv.URL+"/v1", r067IntStoredKey))
	require.Equal(t, http.StatusCreated, w.Code, "create: %s", w.Body.String())
	r067NoKeyMaterial(t, w, logs)
	var cred handlers.OrgCredential
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cred))
	require.Equal(t, "0607", cred.KeyLast4)
	require.True(t, cred.Enabled)
	require.Equal(t, 1, cred.KeyVersion)
	enabled, version, ct := r067CredRow(t, pool, cred.ID)
	require.True(t, enabled)
	require.Equal(t, 1, version)
	require.True(t, strings.HasPrefix(ct, "enc:"), "key must be encrypted at rest, got %.20s", ct)
	require.NotContains(t, ct, r067IntStoredKey, "ciphertext must not contain the plaintext")

	// POST /test spends the shared probe budget first (D-4: one 1/min/org
	// counter across both surfaces) and resolves the same stored key.
	w = credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/test"), member, "")
	require.Equal(t, http.StatusOK, w.Code, "test: %s", w.Body.String())
	r067NoKeyMaterial(t, w, logs)
	var testRes struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &testRes))
	require.True(t, testRes.OK, "connection test must succeed against the live upstream")
	require.Equal(t, 1, upstream.hitCount())
	require.Equal(t, "Bearer "+r067IntStoredKey, upstream.gotAuth())

	// The immediate /models repeat shares the spent budget: diagnosable 429,
	// no catalog payload, zero extra upstream dials.
	w = credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "throttled repeat: %s", w.Body.String())
	r067NoKeyMaterial(t, w, logs)
	require.Contains(t, w.Body.String(), "rate limit")
	require.NotContains(t, w.Body.String(), "discovered")
	require.NotContains(t, w.Body.String(), `"data"`)
	require.Equal(t, 1, upstream.hitCount(), "the throttled call never dials")

	// A fresh router (fresh throttle) over the SAME store discovers: the
	// snapshot is the display-only wire shape, keyed by the STORED key
	// resolved through real SQL decryption.
	env2 := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
	w = credRequest(t, env2.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
	require.Equal(t, http.StatusOK, w.Code, "models: %s", w.Body.String())
	r067NoKeyMaterial(t, w, logs)
	require.Equal(t, []string{"base_url", "count", "data", "discovered", "provider", "verified"}, r067JSONKeys(t, w.Body.Bytes()),
		"snapshot wire shape must match the dashboard ProviderModelCatalog contract")
	var snap struct {
		Provider   string   `json:"provider"`
		BaseURL    string   `json:"base_url"`
		Count      int      `json:"count"`
		Data       []string `json:"data"`
		Discovered bool     `json:"discovered"`
		Verified   *bool    `json:"verified"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &snap))
	require.True(t, snap.Discovered)
	require.NotNil(t, snap.Verified)
	require.False(t, *snap.Verified, "discovery is not verified usability")
	require.Equal(t, []string{"int-large-" + run, "int-mini-" + run}, snap.Data)
	require.Equal(t, 2, snap.Count)
	require.Equal(t, "openai-compat", snap.Provider)
	require.Equal(t, upstream.srv.URL+"/v1", snap.BaseURL)
	require.Equal(t, 2, upstream.hitCount(), "exactly one discovery dial after the throttled repeat")
	require.Equal(t, "Bearer "+r067IntStoredKey, upstream.gotAuth())
	require.Empty(t, env2.bumper.bumped(), "discovery is not a CRUD — no cache bump of its own")

	// Display-only over the REAL registry: the catalog ids and the manual
	// entry name start absent; only the root manual entry ever lands.
	require.Zero(t, r067RegistryCount(t, pool, []string{"int-large-" + run, "int-mini-" + run}),
		"discovery must never write the registry (D-3)")
	modelName := "int-manual-" + run
	w = credRequest(t, env2.router, http.MethodPost, "/api/models", root,
		fmt.Sprintf(`{"model_name":%q,"display_name":"R067 int manual","tier":"standard"}`, modelName))
	require.Equal(t, http.StatusCreated, w.Code, "manual entry: %s", w.Body.String())
	r067NoKeyMaterial(t, w, logs)
	require.Equal(t, 1, r067RegistryCount(t, pool, []string{modelName}),
		"the manual-entry fallback registers through the real store")
}

// TestR067Discovery_RealStore_Refusals pins the negative scenario through the
// real store: each upstream refusal stays an honest, diagnosable,
// non-echoing 200 snapshot with the exact refusal wire shape, the credential
// row stays enabled in the SQL table, and nothing reaches the registry.
func TestR067Discovery_RealStore_Refusals(t *testing.T) {
	pool := testdb.Postgres(t)
	cases := []struct {
		name       string
		status     int
		wantReason string
	}{
		{"list API absent (404)", http.StatusNotFound, "models_list_unavailable"},
		{"key without list permission (403)", http.StatusForbidden, "key_forbidden"},
		{"revoked key (401)", http.StatusUnauthorized, "key_unauthorized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := fmt.Sprintf("%d", time.Now().UnixNano())
			logs := new(bytes.Buffer)
			store := newR067IntStore(t, pool, logs)
			upstream := newCatalogUpstream(t, tc.status, r067IntUpstreamError)
			env := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
			orgID, member := r067IntIdentity(t, store, run, "refusal")

			w := credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, ""), member,
				credCreateBody("openai-compat", upstream.srv.URL+"/v1", r067IntStoredKey))
			require.Equal(t, http.StatusCreated, w.Code, "create: %s", w.Body.String())
			var cred handlers.OrgCredential
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cred))

			w = credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
			require.Equal(t, http.StatusOK, w.Code, "a refusal is a state, not a failed call: %s", w.Body.String())
			r067NoKeyMaterial(t, w, logs)
			require.Equal(t, []string{"count", "provider", "reason", "status"}, r067JSONKeys(t, w.Body.Bytes()),
				"refusal wire shape must match the dashboard ProviderModelCatalog contract")
			var res struct {
				Provider string `json:"provider"`
				Reason   string `json:"reason"`
				Status   int    `json:"status"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
			require.Equal(t, tc.wantReason, res.Reason)
			require.Equal(t, tc.status, res.Status)
			require.Equal(t, "openai-compat", res.Provider)
			require.NotContains(t, w.Body.String(), "r067 upstream secret detail",
				"the refusal never echoes the upstream body")
			require.Equal(t, 1, upstream.hitCount(), "diagnosable, bounded: exactly one probe")

			// Real-SQL posture: the listing refusal does NOT break the
			// credential (still enabled) and writes nothing to the registry.
			enabled, version, _ := r067CredRow(t, pool, cred.ID)
			require.True(t, enabled, "a listing refusal is not a broken credential")
			require.Equal(t, 1, version, "no discovery outcome rotates anything")
			require.Zero(t, r067RegistryCount(t, pool, []string{"int-large-" + run, "int-mini-" + run}))
		})
	}

	// key_unavailable is a REAL-store behavior the stub could not express:
	// ResolveKey filters enabled=true, so disabling the credential through
	// the public PUT must yield the refusal with ZERO upstream dials.
	t.Run("disabled credential: key_unavailable with zero upstream dials", func(t *testing.T) {
		run := fmt.Sprintf("%d", time.Now().UnixNano())
		logs := new(bytes.Buffer)
		store := newR067IntStore(t, pool, logs)
		upstream := newCatalogUpstream(t, http.StatusOK, r067IntCatalog(run))
		env := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
		orgID, member := r067IntIdentity(t, store, run, "disabled")

		w := credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, ""), member,
			credCreateBody("openai-compat", upstream.srv.URL+"/v1", r067IntStoredKey))
		require.Equal(t, http.StatusCreated, w.Code, "create: %s", w.Body.String())
		var cred handlers.OrgCredential
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cred))

		w = credRequest(t, env.router, http.MethodPut, r067IntCredPath(orgID, "/"+cred.ID), member, `{"enabled":false}`)
		require.Equal(t, http.StatusOK, w.Code, "disable: %s", w.Body.String())
		enabled, _, _ := r067CredRow(t, pool, cred.ID)
		require.False(t, enabled, "the PUT must persist enabled=false")

		env2 := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
		w = credRequest(t, env2.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
		require.Equal(t, http.StatusOK, w.Code, "refusal: %s", w.Body.String())
		r067NoKeyMaterial(t, w, logs)
		require.Equal(t, []string{"count", "provider", "reason"}, r067JSONKeys(t, w.Body.Bytes()),
			"key_unavailable carries no upstream status — the probe never ran")
		require.Contains(t, w.Body.String(), "key_unavailable")
		require.Zero(t, upstream.hitCount(), "a disabled credential must not be probed")
	})

	// Revoked key repaired by the existing PUT rotation contract: key_version
	// bumps in the real row and the NEXT discovery follows the rotated stored
	// key upstream.
	t.Run("revoked key: refusal then rotation, discovery follows the new stored key", func(t *testing.T) {
		run := fmt.Sprintf("%d", time.Now().UnixNano())
		logs := new(bytes.Buffer)
		store := newR067IntStore(t, pool, logs)
		upstream := newCatalogUpstream(t, http.StatusUnauthorized, r067IntUpstreamError)
		env := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
		orgID, member := r067IntIdentity(t, store, run, "rotation")

		w := credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, ""), member,
			credCreateBody("openai-compat", upstream.srv.URL+"/v1", r067IntStoredKey))
		require.Equal(t, http.StatusCreated, w.Code, "create: %s", w.Body.String())
		var cred handlers.OrgCredential
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cred))

		w = credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "key_unauthorized")

		w = credRequest(t, env.router, http.MethodPut, r067IntCredPath(orgID, "/"+cred.ID), member,
			fmt.Sprintf(`{"api_key":%q}`, r067IntRotatedKey))
		require.Equal(t, http.StatusOK, w.Code, "rotation: %s", w.Body.String())
		r067NoKeyMaterial(t, w, logs)
		_, version, ct := r067CredRow(t, pool, cred.ID)
		require.Equal(t, 2, version, "rotation bumps key_version")
		require.True(t, strings.HasPrefix(ct, "enc:") && !strings.Contains(ct, r067IntRotatedKey),
			"the rotated key is encrypted at rest too")

		env2 := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}, logs)
		upstream.serve(http.StatusOK, r067IntCatalog(run))
		w = credRequest(t, env2.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
		require.Equal(t, http.StatusOK, w.Code, "post-rotation discovery: %s", w.Body.String())
		r067NoKeyMaterial(t, w, logs)
		require.Contains(t, w.Body.String(), `"discovered":true`)
		require.Equal(t, 2, upstream.hitCount(), "refusal + post-rotation discovery")
		require.Equal(t, "Bearer "+r067IntRotatedKey, upstream.gotAuth(),
			"discovery must follow the rotated stored key through real SQL ResolveKey")
	})
}

// TestR067Discovery_RealStore_ForeignAndGuarded pins the boundary scenarios
// that need no live upstream: a foreign tenant's credential id is a 404 with
// zero upstream dials (org-scoped visibility over the real store), and a
// loopback base_url is refused by the PRODUCTION guarded client before any
// bytes — and before the key — leave, as an honest transport_error.
func TestR067Discovery_RealStore_ForeignAndGuarded(t *testing.T) {
	pool := testdb.Postgres(t)

	t.Run("foreign tenant credential id: 404, zero upstream dials", func(t *testing.T) {
		run := fmt.Sprintf("%d", time.Now().UnixNano())
		logs := new(bytes.Buffer)
		store := newR067IntStore(t, pool, logs)
		upstream := newCatalogUpstream(t, http.StatusOK, r067IntCatalog(run))
		opts := handlers.OrgCredentialHandlerOptions{HTTPClient: upstream.srv.Client()}
		env := newR067IntRouter(t, store, opts, logs)
		orgB, memberB := r067IntIdentity(t, store, run, "tenantb")
		orgA, memberA := r067IntIdentity(t, store, run, "tenanta")

		// The credential belongs to org B, stored through org B's own admin.
		w := credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgB, ""), memberB,
			credCreateBody("openai-compat", upstream.srv.URL+"/v1", r067IntStoredKey))
		require.Equal(t, http.StatusCreated, w.Code, "orgB create: %s", w.Body.String())
		var cred handlers.OrgCredential
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &cred))

		// Org A's admin probes org B's credential id on org A's path: the
		// org-scoped real-SQL list never sees it — 404, no echo, no dial.
		w = credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgA, "/"+cred.ID+"/models"), memberA, "")
		require.Equal(t, http.StatusNotFound, w.Code, "cross-org resource id must stay invisible: %s", w.Body.String())
		r067NoKeyMaterial(t, w, logs)
		require.NotContains(t, w.Body.String(), "openai-compat", "the 404 must not describe the hidden credential")
		require.Zero(t, upstream.hitCount(), "a foreign-tenant probe must never dial")
	})

	t.Run("loopback base_url: production guarded client refuses before dialing", func(t *testing.T) {
		run := fmt.Sprintf("%d", time.Now().UnixNano())
		logs := new(bytes.Buffer)
		store := newR067IntStore(t, pool, logs)
		upstream := newCatalogUpstream(t, http.StatusOK, r067IntCatalog(run))
		// No HTTPClient seam: the production SSRF-guarded client runs.
		env := newR067IntRouter(t, store, handlers.OrgCredentialHandlerOptions{}, logs)
		orgID, member := r067IntIdentity(t, store, run, "loopback")

		// Seeded directly (like the on-prem flow the validation gate allows
		// operators to type): the loopback TLS upstream URL.
		cred, err := store.Create(context.Background(), orgID, "r067 loopback", "openai-compat", upstream.srv.URL, r067IntStoredKey)
		require.NoError(t, err, "seed loopback credential")

		w := credRequest(t, env.router, http.MethodPost, r067IntCredPath(orgID, "/"+cred.ID+"/models"), member, "")
		require.Equal(t, http.StatusOK, w.Code, "refusal: %s", w.Body.String())
		r067NoKeyMaterial(t, w, logs)
		require.Contains(t, w.Body.String(), "transport_error", "an honest state, not a fake empty success")
		var res struct {
			Error      string `json:"error"`
			Discovered bool   `json:"discovered"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		require.False(t, res.Discovered)
		require.NotEmpty(t, res.Error)
		require.NotContains(t, res.Error, r067IntStoredKey, "the transport text never carries the key")
		require.Zero(t, upstream.hitCount(), "the guarded client refused before dialing")
		require.Zero(t, r067RegistryCount(t, pool, []string{"int-large-" + run, "int-mini-" + run}))
	})
}
