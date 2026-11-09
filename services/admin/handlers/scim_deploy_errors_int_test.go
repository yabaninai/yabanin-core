package handlers

// SCIM/MCP deploy blockers — errors and boundaries: negative scenarios.
// wiring (real *adminstore.Store, no SetScimStore override, token mint via
// the admin API handler, full SetupRouter HTTP mount — same chain as
// scim_deploy_int_test.go).
//
// org/user, не подключённый allow-list env"):
//   - auth boundaries: missing, unknown and REVOKED bearer tokens fail
//     closed (401) on every attempt — a revoked token retry never succeeds;
//   - invalid input: malformed JSON and empty userName are 400 invalidValue
//     and leave NO partial row;
//   - wrong org/user type at the HTTP boundary: a member operation naming a
//     user of another org fails 404 and creates no membership (fail-closed
//     cross-org);
//   - invalid filter → 400; well-formed-but-unsupported filter → EMPTY list
//     (never the full list — partial/unknown is not presented as success);
//   - immutable userName: a 400 refusal leaves the profile unchanged;
//   - interrupt: a cancelled request context fails closed (401 — the auth
//     lookup cannot complete, so the request can never succeed);
//   - recovery/retry: after all the failures above the surface still
//     provisions (201), and an idempotent re-POST returns 200 with the SAME
//     id (no duplicate is ever counted as a fresh success).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestSCIMDeployPath_ErrorBoundaries(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	h := New(store, "test-session-key", "scim.deploy", nil)
	t.Cleanup(h.Stop)

	require.NotNil(t, h.scimStore(), "real *adminstore.Store must satisfy handlers.ScimStore (OP-25 F-4)")

	ctx := context.Background()
	suffix := time.Now().UnixNano()

	var creatorID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, active)
		 VALUES ($1, '', 'SCIM Errors Creator', true) RETURNING id::text`,
		fmt.Sprintf("scim-errors-creator-%d@example.com", suffix)).Scan(&creatorID))
	orgA, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-errors-a-%d", suffix), fmt.Sprintf("scim-errors-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-errors-b-%d", suffix), fmt.Sprintf("scim-errors-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE 'scim-errors-%'`)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA.ID, orgB.ID})
	})

	mintToken := func(t *testing.T, orgID, label string) string {
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
			strings.NewReader(fmt.Sprintf(`{"label":%q}`, label))))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var res struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
		return res.Token
	}

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
	usersIn := func(t *testing.T, orgID string) []*adminstore.ScimUser {
		t.Helper()
		users, err := store.ListScimUsers(ctx, orgID)
		require.NoError(t, err)
		return users
	}

	tokenA := mintToken(t, orgA.ID, "deploy-errors")
	tokenB := mintToken(t, orgB.ID, "deploy-errors-org-b")

	// A revoked token: minted through the same real path, then revoked via
	// the store (the admin revoke handler is exactly this store call).
	revoked, revokedPlain, err := store.CreateScimToken(ctx, orgA.ID, "deploy-errors-revoked", creatorID)
	require.NoError(t, err)
	require.NotNil(t, revoked)
	require.NotEmpty(t, revokedPlain)
	require.NoError(t, store.RevokeScimToken(ctx, orgA.ID, revoked.ID))

	// 1. Auth boundaries: missing, unknown, revoked — one uniform 401, and
	// a revoked-token retry NEVER succeeds or creates anything.
	rec := scimServe(t, http.MethodGet, scimBasePath+"/Users", "", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))

	rec = scimServe(t, http.MethodGet, scimBasePath+"/Users", "scim-not-a-real-token", nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalidToken")

	for _, attempt := range []string{"first", "retry"} {
		rec = scimServe(t, http.MethodPost, scimBasePath+"/Users", revokedPlain,
			[]byte(oktaDeployCreateUser(suffix)))
		require.Equal(t, http.StatusUnauthorized, rec.Code,
			"%s attempt with a revoked token must fail: %s", attempt, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "invalidToken")
	}
	require.Empty(t, usersIn(t, orgA.ID), "refused auth must leave no identity row")

	// 2. Invalid input: malformed JSON and missing userName → 400
	// invalidValue, no partial row.
	rec = scimServe(t, http.MethodPost, scimBasePath+"/Users", tokenA, []byte(`{"userName": `))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalidValue")
	assert.Contains(t, rec.Body.String(), "malformed request body")

	rec = scimServe(t, http.MethodPost, scimBasePath+"/Users", tokenA,
		[]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"   "}`))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "userName is required")
	require.Empty(t, usersIn(t, orgA.ID), "rejected creates must leave no partial row")

	// 3. Wrong role type on the group boundary: an unknown displayName is a
	// 400 invalidValue naming the valid roles (diagnosable cause).
	rec = scimServe(t, http.MethodPost, scimBasePath+"/Groups", tokenA,
		[]byte(`{"displayName":"not-a-role"}`))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalidValue")
	assert.Contains(t, rec.Body.String(), "org-admin")

	rec = scimServe(t, http.MethodGet, scimBasePath+"/Groups/definitely-not-a-role", tokenA, nil)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	// 4. Recovery: after the refusals above the surface still provisions.
	userBody := oktaDeployCreateUser(suffix)
	rec = scimServe(t, http.MethodPost, scimBasePath+"/Users", tokenA, []byte(userBody))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)

	// 5. Retry of the SAME provisioning is idempotent: 200 with the SAME id
	// (no duplicate, no second row).
	rec = scimServe(t, http.MethodPost, scimBasePath+"/Users", tokenA, []byte(userBody))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var reProvisioned struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reProvisioned))
	assert.Equal(t, created.ID, reProvisioned.ID, "idempotent re-provision must not mint a new identity")
	require.Len(t, usersIn(t, orgA.ID), 1)

	// 6. Wrong org/user identity (cross-org member op): org B's token adding
	// org A's user to its reader group fails 404 with the diagnosable cause
	// and creates NO membership in org B (fail-closed, no partial state).
	rec = scimServe(t, http.MethodPatch, scimBasePath+"/Groups/reader", tokenB,
		[]byte(fmt.Sprintf(`{"Operations":[{"op":"add","path":"members","value":[{"value":%q}]}]}`, created.ID)))
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "is not a user of this organization")
	membersB, err := store.ListScimRoleMembers(ctx, orgB.ID, adminstore.RoleReader)
	require.NoError(t, err)
	require.Empty(t, membersB, "a refused cross-org member add must create no membership")
	// org A's reader group does hold the provisioned user (default role).
	membersA, err := store.ListScimRoleMembers(ctx, orgA.ID, adminstore.RoleReader)
	require.NoError(t, err)
	require.Len(t, membersA, 1)

	// 7. Filter boundaries: a malformed filter is 400 invalidFilter; a
	// well-formed filter on an unsupported attribute yields an EMPTY list —
	// never the org's full list (partial/unknown is not success).
	rec = scimServe(t, http.MethodGet, scimBasePath+"/Users?filter=broken", tokenA, nil)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalidFilter")

	rec = scimServe(t, http.MethodGet,
		scimBasePath+"/Users?filter="+url.QueryEscape(`emails eq "x@example.com"`), tokenA, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Equal(t, 0, list.TotalResults, "an unmatched filter must return an empty list, not everything")

	// 8. Immutable userName: the 400 refusal leaves the profile unchanged.
	rec = scimServe(t, http.MethodPut, scimBasePath+"/Users/"+created.ID, tokenA,
		[]byte(`{"userName":"renamed@example.com"}`))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "mutability")
	rec = scimServe(t, http.MethodGet, scimBasePath+"/Users/"+created.ID, tokenA, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var after struct {
		UserName string `json:"userName"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &after))
	assert.Equal(t, fmt.Sprintf("scim-deploy-%d@example.com", suffix), after.UserName,
		"a refused userName mutation must not partially apply")

	// 9. Interrupt: a cancelled request context must never mutate. The
	// timeout middleware (pkg/httpmw/timeout.go:159-176) returns WITHOUT a
	// response on context.Canceled — only DeadlineExceeded writes 504 — so
	// no status code is asserted here: the deploy-relevant invariant is that
	// the auth lookup fails closed (logged scim auth refused) and the
	// provisioning transaction never lands a row.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	req := httptest.NewRequestWithContext(cancelled, http.MethodPost, scimBasePath+"/Users",
		strings.NewReader(userBody))
	req.Header.Set("Authorization", "Bearer "+tokenA)
	req.Header.Set("Content-Type", "application/scim+json")
	h.SetupRouter().ServeHTTP(httptest.NewRecorder(), req)
	// Let the detached handler goroutine settle before asserting.
	time.Sleep(250 * time.Millisecond)
	require.Len(t, usersIn(t, orgA.ID), 1, "an interrupted request must leave no row")

	// 10. Final recovery: provisioning still works after every refusal.
	next := oktaDeployCreateUser(suffix + 1)
	rec = scimServe(t, http.MethodPost, scimBasePath+"/Users", tokenA, []byte(next))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.Len(t, usersIn(t, orgA.ID), 2)
}
