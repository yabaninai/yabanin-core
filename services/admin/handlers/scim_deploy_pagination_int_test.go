package handlers

// through the REAL store (disposable Postgres, no SetScimStore override —
// SetupRouter served by httptest, driven by an http.Client). This is the
// consumer boundary of the contract: GET /scim/v2/Users with
// startIndex/count windows against rows that live in Postgres, and group
// member lists that exclude SCIM-deactivated members through the real
// admin_users join.

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

// real HTTP — windows paginate live rows (disjoint, totalResults full),
// edges clamp per contract, malformed values are 400s, and a SCIM DELETE
// makes the member vanish from GET /Groups/reader through the real
// admin_users.active join.
func TestSCIMDeployPath_PaginationRealStore_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	h := New(store, "test-session-key", "scim.deploy", nil)
	t.Cleanup(h.Stop)
	require.NotNil(t, h.scimStore(), "real store must satisfy the SCIM capability")

	ctx := context.Background()
	suffix := time.Now().UnixNano()

	var creatorID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, active)
		 VALUES ($1, '', 'SCIM Page Creator', true) RETURNING id::text`,
		fmt.Sprintf("scim-page-creator-%d@example.com", suffix)).Scan(&creatorID))
	org, err := store.CreateOrganization(ctx,
		fmt.Sprintf("scim-page-a-%d", suffix), fmt.Sprintf("scim-page-a-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE 'scim-page-%'`)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM organizations WHERE id::text = $1`, org.ID)
	})

	// Mint the org token through the admin-API deploy entry point.
	mint := chi.NewRouter()
	mint.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			c := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, creatorID)
			c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, true)
			next.ServeHTTP(w, req.WithContext(c))
		})
	})
	mint.Post("/api/organizations/{id}/scim/tokens", h.CreateScimToken())
	rec := httptest.NewRecorder()
	mint.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/organizations/"+org.ID+"/scim/tokens",
		strings.NewReader(`{"label":"pagination-int"}`)))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var minted struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &minted))
	token := minted.Token

	// The SCIM surface over a real HTTP server (the public-router mount).
	srv := httptest.NewServer(h.SetupRouter())
	t.Cleanup(srv.Close)
	do := func(method, path, contentType string, body string) (int, string) {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, reader)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(raw)
	}

	// Provision 7 users over real HTTP; provisioning order is the stable
	// listing order (created_at, id).
	const total = 7
	provision := func(i int) string {
		t.Helper()
		payload := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":"scim-page-%d-%d@example.com","name":{"givenName":"Page","familyName":"User"},
			"active":true}`, suffix, i)
		code, body := do(http.MethodPost, "/scim/v2/Users", scimContentType, payload)
		require.Equal(t, http.StatusCreated, code, body)
		var res struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &res))
		require.NotEmpty(t, res.ID)
		return res.ID
	}
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		ids = append(ids, provision(i))
	}

	// Windows against live rows: page 1 (startIndex=3, count=2), disjoint
	// page 2, the 1-row tail, past-the-end empty; totalResults always 7.
	list := func(query string) scimListBodyInt {
		t.Helper()
		code, body := do(http.MethodGet, "/scim/v2/Users"+query, "", "")
		require.Equal(t, http.StatusOK, code, body)
		var page scimListBodyInt
		require.NoError(t, json.Unmarshal([]byte(body), &page))
		return page
	}
	p1 := list("?startIndex=3&count=2")
	require.Equal(t, total, p1.TotalResults)
	require.Len(t, p1.Resources, 2)
	assert.Equal(t, 3, p1.StartIndex)
	p2 := list("?startIndex=5&count=2")
	require.Len(t, p2.Resources, 2)
	seen := map[string]bool{}
	for _, page := range []scimListBodyInt{p1, p2} {
		for _, r := range page.Resources {
			id, _ := r["id"].(string)
			require.False(t, seen[id], "real-store pages must not overlap: %s", id)
			seen[id] = true
		}
	}
	tail := list("?startIndex=7&count=5")
	require.Len(t, tail.Resources, 1)
	past := list("?startIndex=99")
	assert.Empty(t, past.Resources)
	assert.Equal(t, total, past.TotalResults)

	// Edges over the real boundary: zero startIndex clamps to the first
	// window, oversized count clamps to the 200 ceiling (7 < 200 → all
	// rows), malformed is a 400 invalidValue.
	c0 := list("?startIndex=0")
	assert.Equal(t, 1, c0.StartIndex)
	assert.Len(t, c0.Resources, 7)
	big := list("?count=9999")
	assert.Len(t, big.Resources, 7)
	code, body := do(http.MethodGet, "/scim/v2/Users?count=abc", "", "")
	require.Equal(t, http.StatusBadRequest, code, body)
	assert.Contains(t, body, "invalidValue", body)

	// Deactivated members are excluded through the real admin_users join:
	// DELETE one member over HTTP, then the group list drops them while the
	// other six stay.
	code, body = do(http.MethodDelete, "/scim/v2/Users/"+ids[0], "", "")
	require.Equal(t, http.StatusNoContent, code, body)
	code, body = do(http.MethodGet, "/scim/v2/Groups/reader", "", "")
	require.Equal(t, http.StatusOK, code, body)
	var group struct {
		Members []struct {
			Value string `json:"value"`
		} `json:"members"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &group))
	memberIDs := make([]string, 0, len(group.Members))
	for _, m := range group.Members {
		memberIDs = append(memberIDs, m.Value)
	}
	assert.NotContains(t, memberIDs, ids[0], "deactivated member must be absent from the real-store group list")
	assert.Len(t, memberIDs, total-1, "the remaining members stay listed")
}

// scimListBodyInt is the ListResponse envelope for the integration test.
type scimListBodyInt struct {
	TotalResults int              `json:"totalResults"`
	ItemsPerPage int              `json:"itemsPerPage"`
	StartIndex   int              `json:"startIndex"`
	Resources    []map[string]any `json:"Resources"`
}
