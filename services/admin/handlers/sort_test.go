package handlers

// AUX-02: the audit-logs list is served from the in-memory buffer, so its
// sorting contract lives entirely in the handler: sort=<allowlisted column>
// &dir=<asc|desc>, unknown column or direction → 400 invalid_sort, ties keep
// the buffer (insertion) order so pagination stays stable.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// appendAuditEntries appends entries with actions in a deliberately
// non-alphabetical insertion order so a no-op "sort" cannot pass.
func appendAuditEntries(t *testing.T, h *AdminHandlers) {
	t.Helper()
	seed := []struct{ action, resource, name, ip string }{
		{"update", "api_key", "carol", "10.0.0.3"},
		{"create", "organization", "alice", "10.0.0.1"},
		{"delete", "routing_rule", "bob", "10.0.0.2"},
	}
	for _, s := range seed {
		ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, s.name+"-id")
		ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, s.name)
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/x", nil)
		r.RemoteAddr = s.ip + ":1234"
		h.auditLogActionWithCtx(context.Background(), r, s.action, s.resource, "details")
	}
}

func listAuditLogsWithQuery(t *testing.T, h *AdminHandlers, query string) (int, []AuditLogEntry) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/audit-logs"+query, nil)
	rw := httptest.NewRecorder()
	h.ListAuditLogs()(rw, req)
	require.Equal(t, http.StatusOK, rw.Code, "body: %s", rw.Body.String())
	var resp struct {
		AuditLogs []AuditLogEntry `json:"audit_logs"`
	}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
	return rw.Code, resp.AuditLogs
}

func TestListAuditLogs_SortActionBothDirections(t *testing.T) {
	h := New(nil, "", "", []string{})
	appendAuditEntries(t, h)

	_, entries := listAuditLogsWithQuery(t, h, "?sort=action&dir=asc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"create", "delete", "update"},
		[]string{entries[0].Action, entries[1].Action, entries[2].Action})

	_, entries = listAuditLogsWithQuery(t, h, "?sort=action&dir=desc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"update", "delete", "create"},
		[]string{entries[0].Action, entries[1].Action, entries[2].Action})
}

func TestListAuditLogs_SortAdminNameBothDirections(t *testing.T) {
	h := New(nil, "", "", []string{})
	appendAuditEntries(t, h)

	_, entries := listAuditLogsWithQuery(t, h, "?sort=admin_name&dir=asc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"alice", "bob", "carol"},
		[]string{entries[0].AdminName, entries[1].AdminName, entries[2].AdminName})

	_, entries = listAuditLogsWithQuery(t, h, "?sort=admin_name&dir=desc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"carol", "bob", "alice"},
		[]string{entries[0].AdminName, entries[1].AdminName, entries[2].AdminName})
}

func TestListAuditLogs_DefaultKeepsInsertionOrder(t *testing.T) {
	h := New(nil, "", "", []string{})
	appendAuditEntries(t, h)

	_, entries := listAuditLogsWithQuery(t, h, "")
	require.Len(t, entries, 3)
	// Current behavior: the buffer is returned in insertion order.
	assert.Equal(t, []string{"update", "create", "delete"},
		[]string{entries[0].Action, entries[1].Action, entries[2].Action})
}

func TestListAuditLogs_UnknownColumnAndInjectionRejected(t *testing.T) {
	h := New(nil, "", "", []string{})
	appendAuditEntries(t, h)

	for _, query := range []string{
		"?sort=__bogus__",
		"?sort=action&dir=sideways",
		"?sort=action;DROP%20TABLE%20admin_audit_logs",
		"?sort=1%3D1",
		"?sort=action%27",
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/audit-logs"+query, nil)
		rw := httptest.NewRecorder()
		h.ListAuditLogs()(rw, req)
		assert.Equal(t, http.StatusBadRequest, rw.Code, "query %s must be rejected, body: %s", query, rw.Body.String())
		if rw.Code == http.StatusBadRequest {
			var resp apiError
			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))
			assert.Equal(t, "invalid_sort", resp.Error, "query %s", query)
		}
	}
}

func TestListAuditLogs_TiesKeepInsertionOrder(t *testing.T) {
	h := New(nil, "", "", []string{})
	// Same action for all entries → sorting by action must not shuffle ties
	// between pages; the insertion order is the deterministic tie-breaker.
	for _, res := range []string{"r1", "r2", "r3"} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
		h.auditLogActionWithCtx(context.Background(), r, "create", res, "")
	}

	_, entries := listAuditLogsWithQuery(t, h, "?sort=action&dir=asc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"r1", "r2", "r3"},
		[]string{entries[0].Resource, entries[1].Resource, entries[2].Resource})
}

// TestListAuditLogs_SortTimestampSubSecondPrecision pins the timestamp sort
// key: it must compare chronologically even when some entries carry no
// sub-second part (RFC3339Nano strips trailing zeros and would place
// 10:00:01Z after 10:00:01.5Z).
func TestListAuditLogs_SortTimestampSubSecondPrecision(t *testing.T) {
	h := New(nil, "", "", []string{})
	base := time.Date(2026, 9, 30, 10, 0, 1, 0, time.UTC)
	h.auditMu.Lock()
	h.auditLogBuffer = []AuditLogEntry{
		{ID: "whole", Action: "create", Resource: "r-whole", Timestamp: base},
		{ID: "half", Action: "create", Resource: "r-half", Timestamp: base.Add(500 * time.Millisecond)},
		{ID: "quarter", Action: "create", Resource: "r-quarter", Timestamp: base.Add(250 * time.Millisecond)},
	}
	h.auditMu.Unlock()

	resources := func(entries []AuditLogEntry) []string {
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.Resource)
		}
		return out
	}

	_, entries := listAuditLogsWithQuery(t, h, "?sort=timestamp&dir=asc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"r-whole", "r-quarter", "r-half"}, resources(entries), "timestamp asc")

	_, entries = listAuditLogsWithQuery(t, h, "?sort=timestamp&dir=desc")
	require.Len(t, entries, 3)
	assert.Equal(t, []string{"r-half", "r-quarter", "r-whole"}, resources(entries), "timestamp desc")
}

func TestParseSortParams(t *testing.T) {
	allowed := func(s string) bool {
		return s == "name" || s == "created_at"
	}
	cases := []struct {
		name     string
		rawQuery string
		wantCol  string
		wantDesc bool
		wantSet  bool
		wantOK   bool
	}{
		{"absent", "", "", false, false, true},
		{"column only", "sort=name", "name", false, true, true},
		{"column and dir", "sort=name&dir=desc", "name", true, true, true},
		{"dir only applies to default", "dir=desc", "", true, false, true},
		{"empty values", "sort=&dir=", "", false, false, true},
		{"unknown column", "sort=bogus", "", false, false, false},
		{"bad dir", "sort=name&dir=sideways", "", false, false, false},
		{"semicolon smuggle", "sort=name;DROP%20TABLE%20x", "", false, false, false},
		{"injection equality", "sort=1%3D1", "", false, false, false},
		{"quoted smuggle", "sort=name%27--", "", false, false, false},
		{"bad percent encoding", "sort=%ZZ", "", false, false, false},
		{"valueless param", "sort", "", false, false, true},
		{"second occurrence invalid", "sort=name&sort=bogus", "", false, false, false},
	}
	for _, tc := range cases {
		col, desc, set, ok := parseSortParams(tc.rawQuery, allowed)
		assert.Equal(t, tc.wantOK, ok, tc.name)
		if tc.wantOK {
			assert.Equal(t, tc.wantCol, col, tc.name)
			assert.Equal(t, tc.wantDesc, desc, tc.name)
			assert.Equal(t, tc.wantSet, set, tc.name)
		}
	}
}
