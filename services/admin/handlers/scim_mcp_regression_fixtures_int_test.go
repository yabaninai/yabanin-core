package handlers

// (SCIM/MCP deploy blockers — regression fixtures): named contract
// deploy wiring on the disposable stand — the same chains as
// scim_deploy_int_test.go (F-4: real *adminstore.Store, no SetScimStore
// override, token mint via the admin-API handler, full SetupRouter mount)
// and mcp_allowlist_deploy_int_test.go (F-5: env knob → config.Load("") →
// SetMCPStore → CreateMCPServer → real mcpagg store, deterministic DNS seam
// QG2-D3).
//
// The negative partner of each pair reproduces the HISTORICAL BROKEN wiring
// (the deployed failure mode the fix removed) and asserts it fails with its
// real observable — never a skip, never a green mock:
//   - F-4 broken: the SCIM capability is missing (nil store → the lazy
//     type-assertion in scimStore() resolves nil, exactly what the
//     parameter-type drift produced at request time) → the whole /scim/v2
//     surface answers 503 "SCIM provisioning is not available". The FIXED
//     wiring answers 201 to the byte-identical request. The check therefore
//     distinguishes broken from fixed by response, not by construction.
//   - F-5 broken: the allow-list env knob is unconnected (absent or
//     all-invalid → config.Load("") yields a nil list) → every registration,
//     including a perfectly valid listed host, fails closed 400 "not in the
//     allowed" with no row. The FIXED wiring registers the same host 201 and
//     still rejects unlisted ones.
//
// The compile-time half of the F-4 guard (var _ ScimStore =
// (*adminstore.Store)(nil) in scim.go) is exercised by `go build ./...`; its
// red proof against the drifted signature is recorded with exact exit codes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegressionFixtures_SCIMDeployBlocker — F-4 fixture pair for «SCIM
// работает для правильного org» vs «Неверный тип org/user» (capability
// drift / wrong org identity), through the real deploy wiring.
func TestRegressionFixtures_SCIMDeployBlocker(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	h := New(store, "test-session-key", "scim.deploy", nil)
	t.Cleanup(h.Stop)

	ctx := context.Background()
	suffix := time.Now().UnixNano()

	var creatorID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, active)
		 VALUES ($1, '', 'SCIM Regression Creator', true) RETURNING id::text`,
		fmt.Sprintf("scim-regression-creator-%d@example.com", suffix)).Scan(&creatorID))
	orgA, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-regression-a-%d", suffix), fmt.Sprintf("scim-regression-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-regression-b-%d", suffix), fmt.Sprintf("scim-regression-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		// Only this run's rows: the creator/inserts carry the run suffix
		// (the provisioned identity reuses the Okta fixture's email shape).
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE 'scim-regression-%' OR email LIKE $1`,
			fmt.Sprintf("scim-deploy-%d%%", suffix))
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA.ID, orgB.ID})
	})

	// The token-mint fixture: the real CreateScimToken admin-API handler as a
	// root session acting for the creator (the deploy entry point).
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
			strings.NewReader(`{"label":"regression-fixture"}`)))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var res struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
		return res.Token
	}

	// The HTTP fixture: the request goes through the given handler's full
	// SetupRouter mount (the same public-router surface deployments serve).
	scimServe := func(t *testing.T, h *AdminHandlers, method, path, bearer string, body []byte) *httptest.ResponseRecorder {
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

	tokenA := mintToken(t, orgA.ID)
	tokenB := mintToken(t, orgB.ID)
	body := []byte(oktaDeployCreateUser(suffix))

	// The BROKEN wiring: no SCIM capability on the handler — the lazy
	// type-assertion resolves nil, byte-for-byte the runtime state the F-4
	// parameter-type drift left in deployments.
	hBroken := New(nil, "test-session-key", "scim.deploy", nil)
	t.Cleanup(hBroken.Stop)
	require.Nil(t, hBroken.scimStore(),
		"fixture setup: the broken handler must have NO scim capability (the F-4 request-time state)")

	t.Run("f4_negative_capability_drift_503", func(t *testing.T) {
		rec := scimServe(t, hBroken, http.MethodPost, scimBasePath+"/Users", tokenA, body)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code,
			"the broken wiring must fail with the deployed 503, not succeed: %s", rec.Body.String())
		assert.Contains(t, rec.Body.String(), "SCIM provisioning is not available")
	})

	var createdID string
	t.Run("f4_positive_correct_org_201", func(t *testing.T) {
		require.NotNil(t, h.scimStore(),
			"the fixed wiring must resolve the capability from the real store (runtime half of the compile pin)")
		rec := scimServe(t, h, http.MethodPost, scimBasePath+"/Users", tokenA, body)
		require.Equal(t, http.StatusCreated, rec.Code,
			"the byte-identical request must succeed on the fixed wiring: %s", rec.Body.String())

		var created struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
			Active   bool   `json:"active"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		createdID = created.ID
		require.NotEmpty(t, createdID)
		assert.Equal(t, fmt.Sprintf("scim-deploy-%d@example.com", suffix), created.UserName)
		assert.True(t, created.Active)
		assert.Equal(t, scimBasePath+"/Users/"+createdID, rec.Header().Get("Location"))

		members, err := store.ListScimRoleMembers(ctx, orgA.ID, adminstore.RoleReader)
		require.NoError(t, err)
		require.Len(t, members, 1, "SCIM works for the correct org: the provisioned user joins the token org")

		rec = scimServe(t, h, http.MethodGet, scimBasePath+"/Users/"+createdID, tokenA, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("f4_negative_wrong_org_404", func(t *testing.T) {
		require.NotEmpty(t, createdID, "the positive fixture must have provisioned the identity")
		rec := scimServe(t, h, http.MethodGet, scimBasePath+"/Users/"+createdID, tokenB, nil)
		require.Equal(t, http.StatusNotFound, rec.Code,
			"a foreign-org token must not see the resource (wrong org identity fails closed): %s", rec.Body.String())
		membersB, err := store.ListScimRoleMembers(ctx, orgB.ID, adminstore.RoleReader)
		require.NoError(t, err)
		require.Empty(t, membersB, "the wrong-org refusal must leave no membership in the foreign org")
	})
}

// TestRegressionFixtures_MCPAllowListDeployBlocker — F-5 fixture pair for
// «MCP deployment соблюдает список» vs «не подключённый allow-list env»,
// through the real env → Load("") → SetMCPStore → registration chain.
func TestRegressionFixtures_MCPAllowListDeployBlocker(t *testing.T) {
	pool := testdb.Postgres(t)
	orgStore := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	mcpStore := mcpagg.NewStore(pool)

	ctx := context.Background()
	suffix := time.Now().UnixNano()
	org, err := orgStore.CreateOrganization(ctx,
		fmt.Sprintf("mcp-regression-%d", suffix), fmt.Sprintf("mcp-regression-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _ = orgStore.DeleteOrganization(context.Background(), org.ID) })

	register := func(t *testing.T, h *AdminHandlers, name, url string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"org_id":%q,"name":%q,"url":%q,"enabled":true}`, org.ID, name, url)
		req := rootRequest("POST", "/api/organizations/"+org.ID+"/mcp/servers", body)
		w := httptest.NewRecorder()
		h.CreateMCPServer()(w, req)
		return w
	}
	noRow := func(t *testing.T, name string) {
		t.Helper()
		_, err := mcpStore.Get(ctx, org.ID, name)
		require.ErrorIs(t, err, mcpagg.ErrNotFound, "a refused registration must leave no row")
	}

	// The BROKEN knob state: YABANIN_MCP_ALLOWED_UPSTREAMS never reaches
	// config.Load("") (the pre-F-5 deployment) — the list parses to nil.
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "")
	cfgBroken, err := config.Load("")
	require.NoError(t, err)
	require.Nil(t, cfgBroken.Gateway.MCPAllowedUpstreams,
		"fixture setup: the unconnected knob must parse to a nil (fail-closed) list")

	hBroken := New(nil, "", "", []string{})
	hBroken.SetMCPStore(mcpStore, cfgBroken.Gateway.MCPAllowedUpstreams)
	hBroken.mcp.dnsResolver = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.3")}, nil // public, non-reserved
	}

	t.Run("f5_negative_unconnected_env_400", func(t *testing.T) {
		name := fmt.Sprintf("unconnected%d", suffix)
		w := register(t, hBroken, name, "https://mcp.example.com/mcp")
		require.Equal(t, http.StatusBadRequest, w.Code,
			"the broken wiring must reject even a perfectly valid listed host: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "not in the allowed")
		noRow(t, name)
	})

	// The FIXED knob state: the env knob survives the admin boot path
	// (services/run/admin.go) and the resulting list — nothing else —
	// governs the registry.
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "mcp.example.com, *.corp.example")
	cfgFixed, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, []string{"mcp.example.com", "*.corp.example"}, cfgFixed.Gateway.MCPAllowedUpstreams,
		`the fixed wiring must carry YABANIN_MCP_ALLOWED_UPSTREAMS through Load("")`)

	hFixed := New(nil, "", "", []string{})
	hFixed.SetMCPStore(mcpStore, cfgFixed.Gateway.MCPAllowedUpstreams)
	hFixed.mcp.dnsResolver = hBroken.mcp.dnsResolver

	t.Run("f5_positive_connected_env_201", func(t *testing.T) {
		name := fmt.Sprintf("exact%d", suffix)
		w := register(t, hFixed, name, "https://mcp.example.com/mcp")
		require.Equal(t, http.StatusCreated, w.Code,
			"the identical request that the broken wiring refused must register: %s", w.Body.String())
		var srv mcpagg.Server
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &srv))
		assert.Equal(t, org.ID, srv.OrgID)
		got, err := mcpStore.Get(ctx, org.ID, name)
		require.NoError(t, err, "the registration must persist through the real store")
		assert.Equal(t, srv.ID, got.ID)
		require.NoError(t, mcpStore.Delete(ctx, org.ID, name))

		wild := fmt.Sprintf("wild%d", suffix)
		w = register(t, hFixed, wild, "https://api.corp.example/v1")
		require.Equal(t, http.StatusCreated, w.Code,
			"a *.suffix entry must admit subdomains: %s", w.Body.String())
		require.NoError(t, mcpStore.Delete(ctx, org.ID, wild))
	})

	t.Run("f5_negative_unlisted_host_400", func(t *testing.T) {
		name := fmt.Sprintf("unlisted%d", suffix)
		w := register(t, hFixed, name, "https://evil.example.com/mcp")
		require.Equal(t, http.StatusBadRequest, w.Code,
			"the fixed wiring must still enforce the list: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "not in the allowed")
		noRow(t, name)
	})

	t.Run("f5_negative_all_invalid_env_400", func(t *testing.T) {
		t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "bad_*entry, no*such*domain")
		cfgInvalid, err := config.Load("")
		require.NoError(t, err)
		require.Nil(t, cfgInvalid.Gateway.MCPAllowedUpstreams,
			"an all-invalid knob must parse to a nil (fail-closed) list, never permissive")

		hInvalid := New(nil, "", "", []string{})
		hInvalid.SetMCPStore(mcpStore, cfgInvalid.Gateway.MCPAllowedUpstreams)
		hInvalid.mcp.dnsResolver = hBroken.mcp.dnsResolver
		name := fmt.Sprintf("allinvalid%d", suffix)
		w := register(t, hInvalid, name, "https://mcp.example.com/mcp")
		require.Equal(t, http.StatusBadRequest, w.Code,
			"a garbage knob must fail closed exactly like a missing one: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "not in the allowed")
		noRow(t, name)
	})
}
