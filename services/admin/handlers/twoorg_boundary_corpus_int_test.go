//go:build integration

package handlers

// N01-P02 T07 — boundary corpus for the two-org isolation matrix, over the
// REAL store (disposable, fully migrated Postgres): org-id edge cases, IDOR
// guesses on every explorer surface, and ownership-transfer attempts. Each
// case pins the OBSERVABLE error and the previous behavior; nothing here
// leaks data or org existence (the packet's negative result: «угаданный ID
// чужой org не раскрывает данные или existence»).
//
// Documented previous behavior (intentional, pinned — not defects):
//   - a member probing an org id they hold no membership for gets exactly
//     403, byte-shape equal for existing-foreign, malformed, numeric and
//     case-variant ids — no org existence oracle;
//   - a privileged root reaching the store with a NON-uuid org id gets a
//     generic 500 (the invalid uuid hits the SQL cast; the response body is
//     the generic "internal server error", the value is never echoed);
//   - membership matching is text-exact: a case-variant of the org uuid is
//     denied for members (PG uuid equality is case-insensitive, so root
//     resolves it — both shapes are non-leaking).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTwoOrg_BoundaryCorpus(t *testing.T) {
	pool := testdb.Postgres(t)
	h, store := dbRBACRouter(t, pool)
	router := h.SetupRouter()
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	orgA, err := store.CreateOrganization(ctx, "twoorg corpus A "+run, "twoorg-corpus-a-"+run)
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, "twoorg corpus B "+run, "twoorg-corpus-b-"+run)
	require.NoError(t, err)

	// memberA: org-admin of A (and nothing else); foreignMember: org-admin
	// of B; root: the operator (any org by design).
	memberA, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("twoorg-corpus-a-%s@sweep.test", run), "corpus member A", "integration-hash-not-used-for-login", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: memberA.ID, OrgID: orgA.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	memberACookie := sweepSessionCookie(t, "test-session-key", memberA.ID)

	rootUser, err := store.CreateAdminUser(ctx,
		fmt.Sprintf("twoorg-corpus-root-%s@sweep.test", run), "corpus root", "integration-hash-not-used-for-login", true)
	require.NoError(t, err)
	rootCookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: rootUser.ID, Email: rootUser.Email, IsRoot: true,
		SessionID: "twoorg-corpus-root", ExpiresAt: time.Now().Add(time.Hour),
	}, "test-session-key")
	require.NoError(t, err)

	// One request row per org, each carrying an org-exclusive marker, so a
	// single string search proves any leak. (testdb.Postgres has no region
	// GUC: home_region is set explicitly.)
	reqA, reqB := "req-twoorg-corpus-a", "req-twoorg-corpus-b"
	markerA, markerB := "TWOORG-A CORPUS MARKER", "TWOORG-B CORPUS MARKER"
	_, err = pool.Exec(ctx, `
		INSERT INTO request_logs
			(org_id, request_id, model_requested, model_used, status_code, duration_ms,
			 tokens_in, tokens_out, cost_in_usd, error, response, home_region)
		VALUES
			($1, $3, 'corpus-model', 'corpus-model', 200, 10, 100, 50, 1.25,
			 $5, $7::jsonb, 'e2e'),
			($2, $4, 'corpus-model', 'corpus-model', 200, 10, 200, 70, 2.50,
			 $6, $8::jsonb, 'e2e')`,
		orgA.ID, orgB.ID, reqA, reqB, markerA+" ERROR", markerB+" ERROR",
		fmt.Sprintf(`{"marker":%q}`, markerA), fmt.Sprintf(`{"marker":%q}`, markerB))
	require.NoError(t, err)

	// callFull is the probe primitive; it also returns the response header
	// map so the no-oracle subtest can pin the 404 header maps too (a
	// distinguishing header would be the same oracle over a side channel).
	callFull := func(method, path, body string, cookie *http.Cookie) (int, string, http.Header) {
		t.Helper()
		var rd *strings.Reader
		if body == "" {
			rd = strings.NewReader("")
		} else {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequestWithContext(ctx, method, path, rd)
		req.Host = "dbint.test"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String(), w.Header()
	}
	call := func(method, path, body string, cookie *http.Cookie) (int, string) {
		code, bodyText, _ := callFull(method, path, body, cookie)
		return code, bodyText
	}

	// callMutating adds the matching CSRF cookie + header so a mutating verb
	// probe passes the CSRF wall and reaches the ROUTER's method decision —
	// the corpus pins route absence (405), not the CSRF gate.
	callMutating := func(method, path, body string, cookie *http.Cookie) (int, string) {
		t.Helper()
		const csrf = "twoorg-corpus-csrf"
		var rd *strings.Reader
		if body == "" {
			rd = strings.NewReader("")
		} else {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequestWithContext(ctx, method, path, rd)
		req.Host = "dbint.test"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		req.Header.Set("X-CSRF-Token", csrf)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	// ── Aspect 1: org-id edge cases (empty, malformed uuid, numeric, case).
	t.Run("org_id_edges", func(t *testing.T) {
		t.Run("empty org id segment fails closed without data", func(t *testing.T) {
			// Previous behavior: the gate resolves no org target from the
			// empty segment and answers 400 "org target required" — no data,
			// no existence hint.
			code, body := call(http.MethodGet, "/api/organizations//requests", "", memberACookie)
			assert.Equal(t, http.StatusBadRequest, code, "body: %s", body)
			assert.Contains(t, body, "org target required")
			assert.NotContains(t, body, markerA)
			assert.NotContains(t, body, markerB)
		})

		t.Run("malformed uuid equals a nonexistent org for a member (no oracle)", func(t *testing.T) {
			codeMalformed, bodyMalformed := call(http.MethodGet, "/api/organizations/not-a-uuid/requests", "", memberACookie)
			codeRandom, _ := call(http.MethodGet,
				"/api/organizations/"+uuid.NewString()+"/requests", "", memberACookie)
			assert.Equal(t, http.StatusForbidden, codeMalformed, "body: %s", bodyMalformed)
			assert.Equal(t, http.StatusForbidden, codeRandom)
			assert.NotContains(t, bodyMalformed, markerA)
			assert.NotContains(t, bodyMalformed, markerB)
		})

		t.Run("numeric-string org id equals a nonexistent org for a member", func(t *testing.T) {
			code, body := call(http.MethodGet, "/api/organizations/12345/requests", "", memberACookie)
			assert.Equal(t, http.StatusForbidden, code, "body: %s", body)
			assert.NotContains(t, body, markerA)
		})

		t.Run("case-variant org id is denied for a member like an unknown org", func(t *testing.T) {
			// Membership lookup is text-exact; the uppercase spelling of A's
			// own uuid is not the membership key. Fail-closed, no data.
			code, body := call(http.MethodGet,
				"/api/organizations/"+strings.ToUpper(orgA.ID)+"/requests", "", memberACookie)
			assert.Equal(t, http.StatusForbidden, code, "body: %s", body)
			assert.NotContains(t, body, markerA)
		})

		t.Run("uuid case-equivalence holds at the store predicate", func(t *testing.T) {
			// The API gate is text-exact (a case-variant is 403 for members
			// above). Past the gate, the SQL org predicate compares uuids, so
			// the case-variant spelling resolves to the same org's row —
			// pinned at the store level.
			rows, total, err := store.ListRequests(ctx, adminstore.RequestListFilters{
				OrgID: strings.ToUpper(orgA.ID), PayloadAuthorizationSet: true,
			})
			require.NoError(t, err)
			assert.EqualValues(t, 1, total, "PG uuid equality is case-insensitive")
			require.Len(t, rows, 1)
			assert.Equal(t, reqA, rows[0].RequestID)
			assert.Equal(t, orgA.ID, rows[0].OrgID, "the canonical org id comes back")
		})

		t.Run("root on a malformed org gets a generic 500 without an echo", func(t *testing.T) {
			// Previous behavior: the invalid uuid reaches the SQL cast; the
			// body is the generic 5xx message (the value is never echoed).
			code, body := call(http.MethodGet, "/api/organizations/not-a-uuid/requests", "", rootCookie)
			assert.Equal(t, http.StatusInternalServerError, code, "body: %s", body)
			assert.NotContains(t, body, "not-a-uuid")
			assert.NotContains(t, body, markerA)
			assert.NotContains(t, body, markerB)
		})

		t.Run("detail route shows the same edge shapes", func(t *testing.T) {
			code, _ := call(http.MethodGet, "/api/organizations/12345/requests/"+reqA, "", memberACookie)
			assert.Equal(t, http.StatusForbidden, code)
			code, _ = call(http.MethodGet, "/api/organizations/a%20b/requests/"+reqA, "", memberACookie)
			assert.NotEqual(t, http.StatusOK, code, "a whitespace org id must never resolve")
		})
	})

	// ── Aspect 2: IDOR guesses (foreign org in path/query/body). ─────────
	t.Run("idor_guesses", func(t *testing.T) {
		foreignRoutes := []struct{ name, path string }{
			{"list", "/api/organizations/" + orgB.ID + "/requests"},
			{"detail", "/api/organizations/" + orgB.ID + "/requests/" + reqB},
			{"detail guessed id", "/api/organizations/" + orgB.ID + "/requests/" + reqA},
			{"export", "/api/organizations/" + orgB.ID + "/requests/export"},
			{"archive-search", "/api/organizations/" + orgB.ID + "/requests/archive-search"},
			{"stats", "/api/organizations/" + orgB.ID + "/requests/stats"},
		}
		for _, tc := range foreignRoutes {
			t.Run("path "+tc.name+" is 403 without data", func(t *testing.T) {
				code, body := call(http.MethodGet, tc.path, "", memberACookie)
				require.Equal(t, http.StatusForbidden, code, "body: %s", body)
				assert.NotContains(t, body, reqB)
				assert.NotContains(t, body, reqA)
				assert.NotContains(t, body, markerA)
				assert.NotContains(t, body, markerB)
			})
		}

		t.Run("foreign request id via query filter on the own org is absent", func(t *testing.T) {
			code, body := call(http.MethodGet,
				"/api/organizations/"+orgA.ID+"/requests?request_id="+reqB, "", memberACookie)
			require.Equal(t, http.StatusOK, code)
			assert.NotContains(t, body, reqB, "the org predicate outranks the guessed id")
			assert.NotContains(t, body, markerB)
		})

		t.Run("foreign content via q search on the own org is absent", func(t *testing.T) {
			code, body := call(http.MethodGet,
				"/api/organizations/"+orgA.ID+"/requests?q="+strings.ReplaceAll(markerB, " ", "+"), "", memberACookie)
			require.Equal(t, http.StatusOK, code)
			assert.NotContains(t, body, markerB, "content search stays subject-scoped")
		})

		t.Run("foreign org in a GET body is inert (scope comes from the path)", func(t *testing.T) {
			code, body := call(http.MethodGet, "/api/organizations/"+orgA.ID+"/requests",
				fmt.Sprintf(`{"org_id":%q}`, orgB.ID), memberACookie)
			require.Equal(t, http.StatusOK, code)
			assert.Contains(t, body, reqA)
			assert.NotContains(t, body, reqB)
			assert.NotContains(t, body, markerB)
		})

		t.Run("foreign org in the query string is inert on org-scoped routes", func(t *testing.T) {
			code, body := call(http.MethodGet,
				"/api/organizations/"+orgA.ID+"/requests?org_id="+orgB.ID, "", memberACookie)
			require.Equal(t, http.StatusOK, code)
			assert.Contains(t, body, reqA)
			assert.NotContains(t, body, reqB)
		})

		t.Run("existence oracle absent on the own-org detail path", func(t *testing.T) {
			codeReal, bodyReal, hdrReal := callFull(http.MethodGet,
				"/api/organizations/"+orgA.ID+"/requests/"+reqB, "", memberACookie)
			codeFake, bodyFake, hdrFake := callFull(http.MethodGet,
				"/api/organizations/"+orgA.ID+"/requests/req-twoorg-corpus-fake", "", memberACookie)
			require.Equal(t, http.StatusNotFound, codeReal)
			require.Equal(t, http.StatusNotFound, codeFake)
			assert.Equal(t, bodyFake, bodyReal, "a real foreign id must look exactly like a fake id")
			assert.Equal(t, hdrFake, hdrReal, "the 404 header map must not distinguish a real foreign id from a fake one")
		})

		t.Run("own-org stats totals never include the foreign org", func(t *testing.T) {
			code, body := call(http.MethodGet,
				"/api/organizations/"+orgA.ID+"/requests/stats", "", memberACookie)
			require.Equal(t, http.StatusOK, code)
			var stats struct {
				TotalRequests int64   `json:"total_requests"`
				TotalTokensIn int64   `json:"total_tokens_in"`
				TotalCostUSD  float64 `json:"total_cost_usd"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &stats))
			assert.Equal(t, int64(1), stats.TotalRequests, "A's aggregate counts A's row only")
			assert.Equal(t, int64(100), stats.TotalTokensIn)
			assert.InDelta(t, 1.25, stats.TotalCostUSD, 0.0001)
		})
	})

	// ── Aspect 3: ownership-transfer attempts (move request between orgs).
	t.Run("ownership_transfer_attempts", func(t *testing.T) {
		// No mutating verb exists on the explorer surface: with the CSRF
		// wall passed, every transfer attempt dies at the router with 405
		// before any handler, and the row stays in its org.
		detail := "/api/organizations/" + orgA.ID + "/requests/" + reqA
		transferBody := fmt.Sprintf(`{"org_id":%q}`, orgB.ID)
		for _, tc := range []struct{ name, method, path string }{
			{"PATCH detail", http.MethodPatch, detail},
			{"PUT detail", http.MethodPut, detail},
			{"DELETE detail", http.MethodDelete, detail},
			{"POST detail", http.MethodPost, detail},
			{"POST collection", http.MethodPost, "/api/organizations/" + orgA.ID + "/requests"},
		} {
			t.Run(tc.name+" is not a route", func(t *testing.T) {
				code, body := callMutating(tc.method, tc.path, transferBody, memberACookie)
				assert.Equal(t, http.StatusMethodNotAllowed, code,
					"transfer verbs must not exist on the explorer surface; body: %s", body)
				assert.NotContains(t, body, markerA)
				assert.NotContains(t, body, orgB.ID)
			})
		}
		// Root (the operator) hits the same wall: no route exists to move a
		// request between orgs through the API.
		code, _ := callMutating(http.MethodPatch, detail, transferBody, rootCookie)
		assert.Equal(t, http.StatusMethodNotAllowed, code)

		// The row is untouched after every attempt.
		var stillOrgA string
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT org_id::text FROM request_logs WHERE request_id = $1", reqA).Scan(&stillOrgA))
		assert.Equal(t, orgA.ID, stillOrgA, "no transfer path may move the row")

		var duplicates int64
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT count(*) FROM request_logs WHERE request_id = $1", reqA).Scan(&duplicates))
		assert.Equal(t, int64(1), duplicates, "no transfer path may duplicate the row into org B")
	})
}
