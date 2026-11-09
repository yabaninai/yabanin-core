package handlers

// N04-P05.listguard (RV-n04p5t7 F2) — real-SQL end-to-end pin: a
// verdict-denied agent key (authenticated, marked subject, NO live
// delegation) gets an EMPTY list and a ZERO stats block over the real
// request_logs table, while a human org member on the same org sees the
// same rows. The emptiness is enforced by the shared requestListWhere
// predicate (PayloadDenied without a subject scope ⇒ FALSE); this suite
// proves the handler→store wiring end to end, mirroring the deny-before-
// grant baseline style of delegations_int_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

func TestVerdictDeniedAgentListStatsEmpty_Int(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.Default(), nil)
	h := New(store, "", "", []string{})
	t.Cleanup(h.Stop)
	ctx := context.Background()
	token := fmt.Sprintf("lg%d", time.Now().UnixNano())

	org, err := store.CreateOrganization(ctx, "listguard org "+token, "listguard-"+token)
	require.NoError(t, err)
	adminUser, err := store.CreateAdminUser(ctx, token+"-admin@example.com", "listguard admin", "hash", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: adminUser.ID, OrgID: org.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	keyA, err := store.CreateAgentKey(ctx, "hash-"+token+"-a", "listguard subject", org.ID)
	require.NoError(t, err)

	agentRowID := token + "-agent-row"
	humanRowID := token + "-human-row"
	_, err = pool.Exec(ctx, `
		INSERT INTO request_logs (
			org_id, agent_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, error, request_id, prompt_hash, home_region)
		VALUES ($1::uuid, $2::uuid, 'lg-model', 'lg-model', 200, 5, 1, 2, 'lg-agent-error', $3, 'ph-lg', 'GLOBAL')`,
		org.ID, keyA.ID, agentRowID)
	require.NoError(t, err, "seed agent-attributed request_logs row")
	_, err = pool.Exec(ctx, `
		INSERT INTO request_logs (
			org_id, user_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, error, request_id, prompt_hash, home_region)
		VALUES ($1::uuid, $2::uuid, 'lg-model', 'lg-model', 200, 7, 3, 4, 'lg-human-error', $3, 'ph-lg', 'GLOBAL')`,
		org.ID, adminUser.ID, humanRowID)
	require.NoError(t, err, "seed human-attributed request_logs row")

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM request_logs WHERE org_id = $1`,
			`DELETE FROM admin_users WHERE id::text = ANY($1)`,
		} {
			_, _ = pool.Exec(cleanupCtx, q, org.ID)
		}
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM organizations WHERE id::text = ANY($1)`,
			[]string{org.ID})
	})

	// --- verdict-denied agent: marked subject, no delegation exists ---
	deniedAgent := func(target string) *http.Request {
		c := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, keyA.ID)
		c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, false)
		req := httptest.NewRequestWithContext(c, http.MethodGet, target, nil)
		return req.WithContext(adminstore.WithRequestPayloadSubject(req.Context(), adminstore.RequestPayloadSubject{
			Type: adminstore.RequestPayloadAgent, AgentID: keyA.ID,
		}))
	}

	t.Run("list is the empty page shape", func(t *testing.T) {
		rec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgRequests(), "/api/organizations/{id}/requests")(
			rec, deniedAgent("/api/organizations/"+org.ID+"/requests"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var page sortPage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
		var rows []map[string]any
		require.NoError(t, json.Unmarshal(page.Data, &rows))
		require.Empty(t, rows, "a verdict-denied agent must see no rows over real SQL")
		require.Equal(t, int64(0), page.Pagination.Total)
		require.NotContains(t, rec.Body.String(), agentRowID)
		require.NotContains(t, rec.Body.String(), humanRowID)
		require.NotContains(t, rec.Body.String(), "lg-agent-error")
		require.NotContains(t, rec.Body.String(), "lg-human-error")
	})

	t.Run("stats is the zero block shape", func(t *testing.T) {
		rec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgRequestStats(), "/api/organizations/{id}/requests/stats")(
			rec, deniedAgent("/api/organizations/"+org.ID+"/requests/stats"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var stats adminstore.RequestListStats
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &stats))
		require.Equal(t, adminstore.RequestListStats{}, stats,
			"aggregates over a verdict-denied agent must be all zero")
	})

	// --- control: a human org member on the SAME store sees the rows ---
	humanMember := func(target string) *http.Request {
		c := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, adminUser.ID)
		c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, false)
		return httptest.NewRequestWithContext(c, http.MethodGet, target, nil)
	}

	t.Run("human member control sees both rows", func(t *testing.T) {
		rec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgRequests(), "/api/organizations/{id}/requests")(
			rec, humanMember("/api/organizations/"+org.ID+"/requests"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var page sortPage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
		require.Equal(t, int64(2), page.Pagination.Total)
		require.True(t, strings.Contains(string(page.Data), agentRowID) &&
			strings.Contains(string(page.Data), humanRowID),
			"the control must see both org rows: %s", page.Data)

		srec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgRequestStats(), "/api/organizations/{id}/requests/stats")(
			srec, humanMember("/api/organizations/"+org.ID+"/requests/stats"))
		require.Equal(t, http.StatusOK, srec.Code, srec.Body.String())
		var stats adminstore.RequestListStats
		require.NoError(t, json.Unmarshal(srec.Body.Bytes(), &stats))
		require.Equal(t, int64(2), stats.TotalRequests)
	})
}
