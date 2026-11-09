package handlers

// a parameter-type drift in adminstore.RemoveScimMemberRole (orgID/scimUserID
// typed OrgRole instead of string), which made *adminstore.Store stop
// satisfying handlers.ScimStore. The lazy type-assertion in scimStore() then
// returned nil and the whole /scim/v2 surface answered 501/503 while the
// fake-store unit tests in scim_test.go stayed green.
//
// These tests drive the REAL wiring end to end on the disposable stand:
// the real *adminstore.Store is wired through New() with NO SetScimStore
// override, a token is minted through the admin API handler (the deploy
// entry point for "mint token"), and the SCIM provisioning surface is
// exercised over the full SetupRouter HTTP mount. If the F4 signature
// drift ever returns, scimStore() resolves nil here and the 201 expectation
// fails with the deployed 501/503 behavior instead.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oktaDeployCreateUser is the Okta push profile body (same shape the Okta
// contract test pins) with a per-run unique userName.
func oktaDeployCreateUser(suffix int64) string {
	userName := fmt.Sprintf("scim-deploy-%d@example.com", suffix)
	return fmt.Sprintf(`{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": %q,
		"name": {"givenName": "Deploy", "familyName": "Smoke"},
		"emails": [{"value": %q, "primary": true}],
		"displayName": "Deploy Smoke",
		"externalId": "00udeploy%d",
		"active": true
	}`, userName, userName, suffix)
}

// override — mint token (admin API) → POST /scim/v2/Users → 201, the created
// identity lands in the token's org, and a foreign-org token cannot see the
// resource (org predicate through the HTTP deploy path).
func TestSCIMDeployPath_TokenMintToCreateUser201(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	h := New(store, "test-session-key", "scim.deploy", nil)
	t.Cleanup(h.Stop)

	// The runtime half of the compile-time pin (var _ ScimStore in scim.go):
	// the real store must satisfy the capability without any override.
	require.NotNil(t, h.scimStore(), "real *adminstore.Store must satisfy handlers.ScimStore (OP-25 F-4)")

	ctx := context.Background()
	suffix := time.Now().UnixNano()

	// scim_tokens.created_by is a real FK: the deploy path mints tokens in the
	// name of an authenticated admin user.
	var creatorID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, active)
		 VALUES ($1, '', 'SCIM Deploy Creator', true) RETURNING id::text`,
		fmt.Sprintf("scim-deploy-creator-%d@example.com", suffix)).Scan(&creatorID))
	orgA, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-deploy-a-%d", suffix), fmt.Sprintf("scim-deploy-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-deploy-b-%d", suffix), fmt.Sprintf("scim-deploy-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		// Memberships, identities and tokens cascade with the org rows; the
		// SCIM-provisioned admin users have no org FK (same cleanup contract
		// as pkg/adminstore/scim_int_test.go).
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE 'scim-deploy-%'`)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA.ID, orgB.ID})
	})

	// mintToken drives the real CreateScimToken admin-API handler as a root
	// session acting for the creator (the /api/organizations/{id}/scim/tokens
	// deploy entry point), not a direct store call.
	mintToken := func(t *testing.T, orgID string) string {
		t.Helper()
		r := chi.NewRouter()
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				c := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, creatorID)
				c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, true)
				next.ServeHTTP(w, req.WithContext(c))
			})
		})
		r.Post("/api/organizations/{id}/scim/tokens", h.CreateScimToken())
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/organizations/"+orgID+"/scim/tokens",
			strings.NewReader(`{"label":"deploy-smoke"}`)))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var res struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
		require.True(t, strings.HasPrefix(res.Token, adminstore.ScimTokenPrefix))
		return res.Token
	}

	tokenA := mintToken(t, orgA.ID)
	tokenB := mintToken(t, orgB.ID)

	// scimServe pushes the request through the full SetupRouter — the same
	// public-router mount deployments serve (/scim/v2 is bearer-only there).
	scimServe := func(t *testing.T, method, path, bearer string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		var reader io.Reader = strings.NewReader("")
		if body != nil {
			reader = strings.NewReader(string(body))
		}
		req := httptest.NewRequestWithContext(t.Context(), method, path, reader)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/scim+json")
		}
		rec := httptest.NewRecorder()
		h.SetupRouter().ServeHTTP(rec, req)
		return rec
	}

	body := oktaDeployCreateUser(suffix)
	rec := scimServe(t, http.MethodPost, scimBasePath+"/Users", tokenA, []byte(body))
	require.Equal(t, http.StatusCreated, rec.Code,
		"deploy-path provisioning must create the user: %s", rec.Body.String())

	var created struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
		Active   bool   `json:"active"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	assert.Equal(t, fmt.Sprintf("scim-deploy-%d@example.com", suffix), created.UserName)
	assert.True(t, created.Active)
	assert.Equal(t, scimBasePath+"/Users/"+created.ID, rec.Header().Get("Location"))

	// The provisioned user holds the default reader membership in the TOKEN's
	// org (SCIM works for the correct org).
	members, err := store.ListScimRoleMembers(ctx, orgA.ID, adminstore.RoleReader)
	require.NoError(t, err)
	require.Len(t, members, 1)

	// The token's org can read the resource back over HTTP.
	rec = scimServe(t, http.MethodGet, scimBasePath+"/Users/"+created.ID, tokenA, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Negative (failure scenario: wrong org / foreign tenant): org B's token
	// must not see org A's SCIM resource — the org predicate holds through the
	// HTTP deploy path, not just at the store layer.
	rec = scimServe(t, http.MethodGet, scimBasePath+"/Users/"+created.ID, tokenB, nil)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}
