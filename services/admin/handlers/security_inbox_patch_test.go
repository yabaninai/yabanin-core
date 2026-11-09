package handlers

// E06-P01 W04-C02: the operator PATCH endpoint. Arms drive the REAL router
// (session + CSRF + org permission middleware) exactly like production:
//
//	rights matrix   org_admin 200; security_auditor/operator/none 403;
//	               anonymous 401; root 200 — and denials journal nothing
//	no-op law       same-state / equal-assignee PATCH: 200, outcome noop,
//	               exactly one audit row, row untouched
//	conflict        illegal transition: 409, outcome conflict, row frozen
//	not-found       unknown and foreign-org incidents are the same 404
//	validation      malformed body, empty patch, unknown status word, bad
//	               assignee, bad ids: 400 without journaling
//	capability      a read-capable store without the patch capability keeps
//	               reads (200) and degrades the write to 503

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/inbox"
)

// ApplyOperatorPatch gives the fixture the W04-C01 write capability by
// mirroring the store's law in memory (same transition table, same no-op
// semantics, updated_at moves only on an effective patch).
func (f *securityInboxFixture) ApplyOperatorPatch(_ context.Context, orgID, incidentID uuid.UUID, patch inbox.OperatorPatch) (inbox.Incident, bool, error) {
	inc, ok := f.incidents[incidentID]
	if !ok || inc.OrgID != orgID {
		return inbox.Incident{}, false, nil
	}
	if patch.Status != nil {
		if err := inbox.ValidateTransition(inc.Status, *patch.Status); err != nil {
			return inbox.Incident{}, false, err
		}
	}
	statusChanged := patch.Status != nil && *patch.Status != inc.Status
	assigneeChanged := patch.AssigneeSet && !sameWireAssignee(inc.Assignee, patch.Assignee)
	if !statusChanged && !assigneeChanged {
		return inc, true, nil
	}
	if statusChanged {
		inc.Status = *patch.Status
	}
	if assigneeChanged {
		if patch.Assignee == uuid.Nil {
			inc.Assignee = nil
		} else {
			a := patch.Assignee
			inc.Assignee = &a
		}
	}
	inc.UpdatedAt = inc.UpdatedAt.Add(time.Minute) // visible movement marker
	f.incidents[incidentID] = inc
	return inc, true, nil
}

// siServePatch builds the real router and returns a request helper that
// carries the session cookie plus the double-submit CSRF pair for
// state-changing methods (production chain: session + CSRF validation).
func siServePatch(t *testing.T, f *securityInboxFixture) func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	h := New(f, siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)
	return func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if method != http.MethodGet && method != http.MethodHead {
			req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "test-csrf-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			req.Header.Set("X-CSRF-Token", "test-csrf-token")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
}

// siPatchFixture seeds one new incident for orgA and returns the fixture,
// orgA and the incident.
func siPatchFixture(t *testing.T) (*securityInboxFixture, uuid.UUID, inbox.Incident) {
	t.Helper()
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	inc := siIncident(t, orgA, "evt-patch-1", time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC))
	f.rows[orgA] = []inbox.Incident{inc}
	f.incidents[inc.ID] = inc
	return f, orgA, inc
}

func siPatchPath(orgID, incidentID uuid.UUID) string {
	return fmt.Sprintf("/api/organizations/%s/security-inbox/%s", orgID, incidentID)
}

// siAudit asserts the last audit row is a security_inbox.patch journal
// entry with the given outcome for the incident, and returns it.
func siAudit(t *testing.T, f *securityInboxFixture, incidentID uuid.UUID, outcome string) adminstore.AuditLogEntryRecord {
	t.Helper()
	rec := f.lastAuditRecord(t)
	require.Equal(t, "security_inbox.patch", rec.Action)
	require.True(t, strings.HasPrefix(rec.Resource, "organization:"), "resource %q", rec.Resource)
	var detail struct {
		OrgID      string `json:"org_id"`
		IncidentID string `json:"incident_id"`
		Outcome    string `json:"outcome"`
	}
	require.NoError(t, json.Unmarshal([]byte(rec.Details), &detail))
	assert.Equal(t, incidentID.String(), detail.IncidentID)
	assert.Equal(t, outcome, detail.Outcome)
	return rec
}

func TestSecurityInboxPatchRightsMatrix(t *testing.T) {
	f, orgA, inc := siPatchFixture(t)
	do := siServePatch(t, f)
	body := `{"status":"acknowledged"}`

	t.Run("org_admin may patch", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), body, siSessionCookie(t, "admin-1", false))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Equal(t, 1, f.auditRecordCount(), "one journal row per applied request")
	})

	t.Run("security_auditor is read-only", func(t *testing.T) {
		before := f.auditRecordCount()
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), body, siSessionCookie(t, "admin-2", false))
		require.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, before, f.auditRecordCount(), "middleware denials are unjournaled")
		assert.Equal(t, inbox.StatusAcknowledged, f.incidents[inc.ID].Status, "denial changed nothing")
	})

	t.Run("operator is denied", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), body, siSessionCookie(t, "admin-4", false))
		require.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("non-member is denied", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), body, siSessionCookie(t, "admin-3", false))
		require.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("anonymous is rejected", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), body, nil)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("missing CSRF pair is rejected", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, siPatchPath(orgA, inc.ID), strings.NewReader(body))
		req.AddCookie(siSessionCookie(t, "admin-1", false))
		w := httptest.NewRecorder()
		h := New(f, siSessionKey(), "", []string{})
		router := h.SetupRouter()
		t.Cleanup(h.Stop)
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})

	t.Run("root may patch", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), body, siSessionCookie(t, "admin-root", true))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}

func TestSecurityInboxPatchApplies(t *testing.T) {
	f, orgA, inc := siPatchFixture(t)
	do := siServePatch(t, f)
	admin := siSessionCookie(t, "admin-1", false)

	t.Run("status transition is applied, echoed and journaled", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), `{"status":"acknowledged"}`, admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp struct {
			Data securityIncidentJSON `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, inbox.StatusAcknowledged, resp.Data.Status)
		assert.Equal(t, inbox.StatusAcknowledged, f.incidents[inc.ID].Status)
		require.Equal(t, 1, f.auditRecordCount())
		rec := siAudit(t, f, inc.ID, "patched")
		assert.Contains(t, rec.Resource, orgA.String())
	})

	t.Run("assignee set, then cleared by null", func(t *testing.T) {
		member := uuid.New()
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), fmt.Sprintf(`{"assignee":%q}`, member), admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp struct {
			Data securityIncidentJSON `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NotNil(t, resp.Data.Assignee)
		assert.Equal(t, member, *resp.Data.Assignee)
		siAudit(t, f, inc.ID, "patched")

		w = do(http.MethodPatch, siPatchPath(orgA, inc.ID), `{"assignee":null}`, admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		// Fresh decode: an omitted field must not inherit the previous
		// response's value.
		var resp2 struct {
			Data securityIncidentJSON `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp2))
		assert.Nil(t, resp2.Data.Assignee, "explicit null clears the assignee")
		siAudit(t, f, inc.ID, "patched")
	})

	t.Run("status and assignee in one request", func(t *testing.T) {
		member := uuid.New()
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID),
			fmt.Sprintf(`{"status":"in_progress","assignee":%q}`, member), admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, inbox.StatusInProgress, f.incidents[inc.ID].Status)
		require.NotNil(t, f.incidents[inc.ID].Assignee)
	})

	t.Run("reads still work through the same router", func(t *testing.T) {
		w := do(http.MethodGet, "/api/organizations/"+orgA.String()+"/security-inbox", "", admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}

func TestSecurityInboxPatchNoop(t *testing.T) {
	f, orgA, inc := siPatchFixture(t)
	do := siServePatch(t, f)
	admin := siSessionCookie(t, "admin-1", false)

	t.Run("same-state status is a journaled no-op", func(t *testing.T) {
		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), `{"status":"new"}`, admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Equal(t, 1, f.auditRecordCount(), "exactly one row")
		siAudit(t, f, inc.ID, "noop")
		assert.Equal(t, inbox.StatusNew, f.incidents[inc.ID].Status)
	})

	t.Run("equal assignee re-set is a no-op", func(t *testing.T) {
		member := uuid.New()
		_, _, err := f.ApplyOperatorPatch(context.Background(), orgA, inc.ID,
			inbox.OperatorPatch{Assignee: member, AssigneeSet: true})
		require.NoError(t, err)

		w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), fmt.Sprintf(`{"assignee":%q}`, member), admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		siAudit(t, f, inc.ID, "noop")
		require.NotNil(t, f.incidents[inc.ID].Assignee, "no-op kept the assignee")
	})
}

func TestSecurityInboxPatchConflict(t *testing.T) {
	f, orgA, inc := siPatchFixture(t)
	do := siServePatch(t, f)
	admin := siSessionCookie(t, "admin-1", false)

	// new → resolved is not an edge of the W04-C01 table.
	w := do(http.MethodPatch, siPatchPath(orgA, inc.ID), `{"status":"resolved"}`, admin)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Equal(t, 1, f.auditRecordCount())
	siAudit(t, f, inc.ID, "conflict")
	assert.Equal(t, inbox.StatusNew, f.incidents[inc.ID].Status, "conflict changed nothing")

	// The incident is still operable afterwards.
	w = do(http.MethodPatch, siPatchPath(orgA, inc.ID), `{"status":"acknowledged"}`, admin)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestSecurityInboxPatchNotFound(t *testing.T) {
	f, orgA, inc := siPatchFixture(t)
	do := siServePatch(t, f)
	admin := siSessionCookie(t, "admin-1", false)

	t.Run("unknown incident id", func(t *testing.T) {
		missing := uuid.New()
		w := do(http.MethodPatch, siPatchPath(orgA, missing), `{"status":"acknowledged"}`, admin)
		require.Equal(t, http.StatusNotFound, w.Code)
		siAudit(t, f, missing, "not_found")
	})

	t.Run("foreign-org incident is indistinguishable", func(t *testing.T) {
		orgB := uuid.New()
		other := siIncident(t, orgB, "evt-foreign", time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC))
		f.incidents[other.ID] = other // exists, but belongs to orgB

		w := do(http.MethodPatch, siPatchPath(orgA, other.ID), `{"status":"acknowledged"}`, admin)
		require.Equal(t, http.StatusNotFound, w.Code, "no existence leak")
		assert.Equal(t, inbox.StatusNew, other.Status, "foreign row untouched")
		require.Equal(t, inc.OrgID, orgA) // silence unused-var lint on inc
	})
}

func TestSecurityInboxPatchValidation(t *testing.T) {
	f, orgA, inc := siPatchFixture(t)
	do := siServePatch(t, f)
	admin := siSessionCookie(t, "admin-1", false)

	cases := []struct {
		name string
		path string
		body string
	}{
		{"malformed JSON", siPatchPath(orgA, inc.ID), `{"status":`},
		{"empty patch", siPatchPath(orgA, inc.ID), `{}`},
		{"unknown status word", siPatchPath(orgA, inc.ID), `{"status":"teleported"}`},
		{"status not a string", siPatchPath(orgA, inc.ID), `{"status":5}`},
		{"assignee not a uuid", siPatchPath(orgA, inc.ID), `{"assignee":"not-a-uuid"}`},
		{"assignee nil uuid", siPatchPath(orgA, inc.ID), `{"assignee":"00000000-0000-0000-0000-000000000000"}`},
		{"invalid incident id", fmt.Sprintf("/api/organizations/%s/security-inbox/nope", orgA), `{"status":"new"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := f.auditRecordCount()
			w := do(http.MethodPatch, tc.path, tc.body, admin)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, before, f.auditRecordCount(), "validation failures are unjournaled")
		})
	}

	t.Run("invalid org id is a middleware denial, not a handler 400", func(t *testing.T) {
		before := f.auditRecordCount()
		w := do(http.MethodPatch, "/api/organizations/nope/security-inbox/"+inc.ID.String(), `{"status":"new"}`, admin)
		require.Equal(t, http.StatusForbidden, w.Code, "org resolution happens in RequireOrgPermission before the handler")
		assert.Equal(t, before, f.auditRecordCount())
	})

	assert.Equal(t, inbox.StatusNew, f.incidents[inc.ID].Status, "nothing applied")
}

// siPatchlessFixture reproduces the batch-A store shape: the READ
// capability (List/Get) without the write — embedding would promote the
// patch method too, so the read surface is re-declared on the shared
// mockStore. Reads must keep working while PATCH degrades to 503.
type siPatchlessFixture struct {
	*mockStore
	rows      map[uuid.UUID][]inbox.Incident
	incidents map[uuid.UUID]inbox.Incident
}

func (f *siPatchlessFixture) List(_ context.Context, orgID uuid.UUID) ([]inbox.Incident, error) {
	return append([]inbox.Incident{}, f.rows[orgID]...), nil
}

func (f *siPatchlessFixture) Get(_ context.Context, orgID, incidentID uuid.UUID) (inbox.Incident, bool, error) {
	inc, ok := f.incidents[incidentID]
	if !ok || inc.OrgID != orgID {
		return inbox.Incident{}, false, nil
	}
	return inc, true, nil
}

// ApplyOperatorPatch is deliberately NOT defined: the capability assertion
// fails and the route answers 503.

func TestSecurityInboxPatchUnavailable(t *testing.T) {
	orgA := uuid.New()
	f := &siPatchlessFixture{
		mockStore: newMockStore(),
		rows:      map[uuid.UUID][]inbox.Incident{},
		incidents: map[uuid.UUID]inbox.Incident{},
	}
	// Same membership shape as siSeed, without the fixture type.
	for _, id := range []string{"admin-2", "admin-3", "admin-4"} {
		f.adminUsers[id] = &adminstore.AdminUser{ID: id, Email: id + "@example.com", DisplayName: id, IsRoot: false, Active: true}
	}
	if _, err := f.SetOrgMembership(t.Context(), "admin-1", orgA.String(), adminstore.RoleOrgAdmin); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	inc := siIncident(t, orgA, "evt-patchless", time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC))
	f.rows[orgA] = []inbox.Incident{inc}
	f.incidents[inc.ID] = inc

	h := New(f, siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, siPatchPath(orgA, inc.ID),
		strings.NewReader(`{"status":"acknowledged"}`))
	req.AddCookie(siSessionCookie(t, "admin-1", false))
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "test-csrf-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	req.Header.Set("X-CSRF-Token", "test-csrf-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())

	// Reads on the same degraded store still answer.
	getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/organizations/"+orgA.String()+"/security-inbox", nil)
	getReq.AddCookie(siSessionCookie(t, "admin-1", false))
	wGet := httptest.NewRecorder()
	router.ServeHTTP(wGet, getReq)
	require.Equal(t, http.StatusOK, wGet.Code, wGet.Body.String())
}
