package handlers

// N04-P05-T07 (RV-n04p5c must-track): the delegated-ALLOW path had no
// end-to-end coverage — the existing suite runs on mirror fakes, so "a
// delegated subject actually sees its own rows with payload columns" was
// never exercised over real SQL. This suite drives the full handler stack
// (real chi params, real pipeline evaluator, real audit seam) over the real
// store on the disposable migrated Postgres (testdb.Postgres):
//
//	issue (admin grantor + root grantor, over HTTP)
//	  → delegated list pins rows to the subject's own attribution
//	  → delegated detail serves payload columns, never originals
//	  → delegated export streams the scoped rows
//	  → revoking the payload delegation narrows to metadata-only
//	  → revoking the read delegation closes the surface again.
//
// The deny-before-grant baseline (creation is inert) is asserted first so a
// green allow below can only come from the delegation rows.

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

func TestDelegatedSubjectAllowPathEndToEnd_Int(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.Default(), nil)
	h := New(store, "", "", []string{})
	t.Cleanup(h.Stop)
	ctx := context.Background()
	token := fmt.Sprintf("de2e%x", time.Now().UnixNano())

	org, err := store.CreateOrganization(ctx, "de2e org "+token, "de2e-"+token)
	require.NoError(t, err)
	rootUser, err := store.CreateAdminUser(ctx, token+"-root@example.com", "de2e root", "hash", true)
	require.NoError(t, err)
	adminUser, err := store.CreateAdminUser(ctx, token+"-admin@example.com", "de2e admin", "hash", false)
	require.NoError(t, err)
	_, err = store.CreateOrgMembership(ctx, adminstore.OrgMembership{
		UserID: adminUser.ID, OrgID: org.ID, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)
	keyA, err := store.CreateAgentKey(ctx, "hash-"+token+"-a", "de2e subject", org.ID)
	require.NoError(t, err)
	keyB, err := store.CreateAgentKey(ctx, "hash-"+token+"-b", "de2e other", org.ID)
	require.NoError(t, err)

	var sessionA string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO sessions (org_id, client_session, home_region)
		VALUES ($1::uuid, $2, 'GLOBAL') RETURNING id::text`,
		org.ID, token+"-sess-a").Scan(&sessionA), "seed session")

	seedRequest := func(requestID string, agentKey *adminstore.AgentKey, withSession bool) {
		t.Helper()
		var sessionID any
		if withSession {
			sessionID = sessionA
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (
				org_id, session_id, agent_id, model_requested, model_used, status_code, duration_ms,
				tokens_in, tokens_out, error, request_id, prompt_hash, response,
				upstream_request, upstream_response, home_region)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'de2e-model', 'de2e-model', 200, 5,
			        1, 2, 'boom', $4, 'ph-hash', '{"answer":"payload-canary"}'::jsonb,
			        '{"body":"originals-request-canary"}'::jsonb, '{"raw":"originals-response-canary"}'::jsonb,
			        'GLOBAL')`,
			org.ID, sessionID, agentKey.ID, requestID)
		require.NoError(t, err, "seed request_logs row for %s", requestID)
	}
	ownRequestID, otherRequestID := token+"-own", token+"-other"
	seedRequest(ownRequestID, keyA, true)
	seedRequest(otherRequestID, keyB, false)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM principal_delegations WHERE org_id = $1`,
			`DELETE FROM request_logs WHERE org_id = $1`,
			`DELETE FROM sessions WHERE org_id = $1`,
		} {
			_, _ = pool.Exec(cleanupCtx, q, org.ID)
		}
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM admin_users WHERE id::text = ANY($1)`,
			[]string{adminUser.ID, rootUser.ID})
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM organizations WHERE id::text = ANY($1)`, []string{org.ID})
	})

	// --- request builders (what ChiAuthMiddleware/the ingress would stamp) ---
	dintRoot := func(method, target, body string) *http.Request {
		c := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, rootUser.ID)
		c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, true)
		return httptest.NewRequestWithContext(c, method, target, strings.NewReader(body))
	}
	dintAdmin := func(method, target, body string) *http.Request {
		c := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, adminUser.ID)
		c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, false)
		c = context.WithValue(c, ctxKeyOrgScope{}, org.ID)
		return httptest.NewRequestWithContext(c, method, target, strings.NewReader(body))
	}
	dintAgent := func(method, target string) *http.Request {
		c := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, keyA.ID)
		c = context.WithValue(c, adminauth.ContextKeyIsRoot{}, false)
		req := httptest.NewRequestWithContext(c, method, target, nil)
		return req.WithContext(adminstore.WithRequestPayloadSubject(req.Context(), adminstore.RequestPayloadSubject{
			Type: adminstore.RequestPayloadAgent, AgentID: keyA.ID,
		}))
	}

	// --- baseline: creation is inert, nothing is visible without a row ---
	detail := func(requestID string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(
			rec, dintAgent(http.MethodGet, "/api/organizations/"+org.ID+"/requests/"+requestID))
		var body map[string]any
		if rec.Code == http.StatusOK {
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		}
		return rec.Code, body
	}
	code, _ := detail(ownRequestID)
	require.Equal(t, http.StatusNotFound, code, "no delegation yet: the subject must not see its own row")
	code, _ = detail(otherRequestID)
	require.Equal(t, http.StatusNotFound, code, "no delegation yet: the subject must not see any row")

	recExport := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
		recExport, dintAgent(http.MethodGet, "/api/organizations/"+org.ID+"/requests/export"))
	require.Equal(t, http.StatusForbidden, recExport.Code,
		"no delegation yet: export must deny loudly (zero access, not degraded access)")

	// --- issue over HTTP: the org admin delegates metadata read, root adds payloads ---
	issue := func(buildReq func(method, target, body string) *http.Request, perms string) *adminstore.PrincipalDelegation {
		t.Helper()
		rec := httptest.NewRecorder()
		wrapWithParams(h.IssuePrincipalDelegation(), "/api/agent-keys/{id}/delegations")(
			rec, buildReq(http.MethodPost, "/api/agent-keys/"+keyA.ID+"/delegations",
				fmt.Sprintf(`{"org_id":%q,"permissions":%s,"ttl_seconds":3600}`, org.ID, perms)))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var d adminstore.PrincipalDelegation
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &d))
		return &d
	}
	readDelegation := issue(dintAdmin, `["requests.read"]`)
	require.Equal(t, adminstore.PrincipalDelegationGrantorAdmin, readDelegation.GrantorType)
	require.Equal(t, keyA.ID, readDelegation.SubjectID)
	payloadDelegation := issue(dintRoot, `["requests.read","requests.read_payloads"]`)
	require.Equal(t, adminstore.PrincipalDelegationGrantorRoot, payloadDelegation.GrantorType)

	// The provenance rows are really there (list endpoint, real SQL).
	recListKeys := httptest.NewRecorder()
	wrapWithParams(h.ListPrincipalDelegations(), "/api/agent-keys/{id}/delegations")(
		recListKeys, dintAdmin(http.MethodGet, "/api/agent-keys/"+keyA.ID+"/delegations?org_id="+org.ID, ""))
	require.Equal(t, http.StatusOK, recListKeys.Code, recListKeys.Body.String())
	var listed struct {
		Data []adminstore.PrincipalDelegation `json:"data"`
	}
	require.NoError(t, json.Unmarshal(recListKeys.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 2, "both issued delegations must be persisted and listed")

	// --- delegated list: pinned to the subject's own attribution ---
	rec := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequests(), "/api/organizations/{id}/requests")(
		rec, dintAgent(http.MethodGet, "/api/organizations/"+org.ID+"/requests"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page sortPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(page.Data, &rows))
	require.Len(t, rows, 1, "the delegated subject must see exactly its own attributed row")
	require.Equal(t, ownRequestID, rows[0]["request_id"])
	require.NotContains(t, string(page.Data), otherRequestID, "the other agent's row must be absent")
	require.Equal(t, "boom", rows[0]["error"],
		"delegated payload scope keeps the row's payload content on the list")

	// --- delegated detail: payload columns served, originals never ---
	code, body := detail(ownRequestID)
	require.Equal(t, http.StatusOK, code)
	require.JSONEq(t, `{"answer":"payload-canary"}`, string(mustRawJSON(t, body["response"])),
		"the delegated payload scope must serve the response column")
	require.Equal(t, "boom", body["error"])
	require.Equal(t, keyA.ID, body["agent_id"])
	require.NotContains(t, body, "upstream_request", "originals are never delegatable")
	require.NotContains(t, body, "upstream_response", "originals are never delegatable")

	code, _ = detail(otherRequestID)
	require.Equal(t, http.StatusNotFound, code,
		"the delegated subject can never address another subject's row (scope pin)")

	// --- delegated export: streams exactly the scoped rows with payload ---
	recExport = httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
		recExport, dintAgent(http.MethodGet, "/api/organizations/"+org.ID+"/requests/export"))
	require.Equal(t, http.StatusOK, recExport.Code, recExport.Body.String())
	require.Equal(t, "application/x-ndjson", recExport.Header().Get("Content-Type"))
	exportLines := nonEmptyLines(recExport.Body.String())
	require.Len(t, exportLines, 1, "the export must stream exactly the subject's own row")
	var exportRow map[string]any
	require.NoError(t, json.Unmarshal([]byte(exportLines[0]), &exportRow))
	require.Equal(t, ownRequestID, exportRow["request_id"])
	require.JSONEq(t, `{"answer":"payload-canary"}`, string(mustRawJSON(t, exportRow["response"])),
		"export under a delegated scope carries payload content")
	require.NotContains(t, exportRow, "upstream_request", "export originals stay closed")
	require.NotContains(t, exportRow, "upstream_response", "export originals stay closed")

	// --- revoking the payload delegation narrows to metadata-only ---
	revoke := func(buildReq func(method, target, body string) *http.Request, delegationID string) {
		t.Helper()
		rec := httptest.NewRecorder()
		wrapWithParams(h.RevokePrincipalDelegation(), "/api/agent-keys/{id}/delegations/{delegationID}/revoke")(
			rec, buildReq(http.MethodPost,
				"/api/agent-keys/"+keyA.ID+"/delegations/"+delegationID+"/revoke?org_id="+org.ID, ""))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	}
	revoke(dintRoot, payloadDelegation.ID)

	code, body = detail(ownRequestID)
	require.Equal(t, http.StatusOK, code, "the metadata delegation is still live")
	require.Nil(t, body["response"],
		"payload columns close with the payload delegation (SQL coalesces to JSON null)")
	require.Empty(t, body["error"], "payload-gated columns are redacted, not zeroed")

	// --- revoking the read delegation closes the surface entirely ---
	revoke(dintAdmin, readDelegation.ID)
	code, _ = detail(ownRequestID)
	require.Equal(t, http.StatusNotFound, code, "with no live delegation the row is invisible again")
	recExport = httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
		recExport, dintAgent(http.MethodGet, "/api/organizations/"+org.ID+"/requests/export"))
	require.Equal(t, http.StatusForbidden, recExport.Code, "export denies again after revocation")
}

// mustRawJSON re-marshals a decoded JSON value so assertions can compare
// payload columns byte-semantically without re-decoding struct trees.
func mustRawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
