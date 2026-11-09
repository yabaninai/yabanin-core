package handlers

// N04-P05.listguard (RV-n04p5t7 F2) — handler-level shape pins for the
// verdict-deny path of the request explorer list/stats endpoints.
//
// Inventory outcome (see artifacts/fix/listguard/record.md): export and
// archive-search consult the authorizeRequestList boolean directly (403 on
// false); list/stats intentionally do NOT — they must stay 200 with the
// SAME envelope shape, merely empty. With the real store the emptiness is
// enforced by the shared requestListWhere predicate (pinned in
// pkg/adminstore/request_list_guard_test.go and over real SQL in
// request_list_guard_int_test.go), NOT by the handler: the existing pin
// TestAgentKeyDoesNotInheritHumanHistory requires the store to stay
// consulted with the verdict-derived flags, and honoring the boolean
// blanket-style would change pinned behavior for sessionless and
// root-without-grant callers. These tests therefore pin the wire contract:
// a verdict-denied agent gets exactly the empty-page/zero-stats shapes a
// legitimate empty result has, while a human member on the same store still
// sees the rows.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listGuardStore mirrors the real adminstore contract for the verdict-deny
// shapes — requestListWhere appends FALSE when PayloadDenied is set without
// a PayloadUserID/DelegateAgentID scope (agent shapes) — and serves canned
// rows for every other filter shape. The emptiness contract itself is held
// by the adminstore predicate pins and the real-SQL integration pin; this
// fake exists so the handler's response SHAPE is observable in a unit test.
type listGuardStore struct {
	*mockStore
	rows  []adminstore.RequestListRow
	total int
}

func (s *listGuardStore) denied(f adminstore.RequestListFilters) bool {
	return f.PayloadAuthorizationSet && f.PayloadDenied &&
		f.PayloadUserID == "" && f.DelegateAgentID == ""
}

func (s *listGuardStore) ListRequests(_ context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	s.lastRequestFilters = f
	if s.denied(f) {
		return []adminstore.RequestListRow{}, 0, nil
	}
	return s.rows, s.total, nil
}

func (s *listGuardStore) RequestStats(_ context.Context, f adminstore.RequestListFilters) (*adminstore.RequestListStats, error) {
	if s.denied(f) {
		return &adminstore.RequestListStats{}, nil
	}
	return &adminstore.RequestListStats{
		TotalRequests: int64(s.total), SuccessRate: 1, AvgLatencyMs: 42, P95LatencyMs: 42,
		TotalTokensIn: 100, TotalTokensOut: 50, TotalCostUSD: 0.002,
	}, nil
}

func listGuardAgentRequest(target string) *http.Request {
	// Same stamping as TestAgentKeyDoesNotInheritHumanHistory: an
	// authenticated subject marked as an agent key, no live delegation (the
	// mock store implements no delegation seam, which fails closed).
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")
	ctx = adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadAgent, AgentID: "agent-1", APIKeyID: "key-1",
	})
	return httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
}

func TestVerdictDeniedAgentListAndStatsAreEmptyShapes(t *testing.T) {
	store := &listGuardStore{
		mockStore: newMockStore(),
		rows: []adminstore.RequestListRow{{
			RequestID: "req-guard-1", OrgID: "org-1", ModelUsed: "gpt-4o-mini",
			StatusCode: 200, CreatedAt: time.Now(),
		}},
		total: 1,
	}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	t.Run("verdict-denied agent list is the empty page shape", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.apiOrgRequests()(w, listGuardAgentRequest("/api/organizations/org-1/requests"))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		// Byte-for-byte the envelope writePaginated emits for a legitimate
		// empty page — data is [] (never null), total 0, no row content.
		require.JSONEq(t,
			`{"data":[],"pagination":{"page":1,"page_size":50,"total":0,"total_pages":0}}`,
			w.Body.String())
		f := store.lastRequestFilters
		assert.True(t, f.PayloadAuthorizationSet)
		assert.True(t, f.PayloadDenied, "the verdict gate must deny a delegation-less agent")
		assert.Empty(t, f.PayloadUserID, "an agent principal must not be scoped to the human session owner")
		assert.Empty(t, f.DelegateAgentID)
		assert.False(t, f.PayloadGrant)
		assert.False(t, f.PayloadSearchAllowed)
	})

	t.Run("verdict-denied agent stats is the zero block shape", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.apiOrgRequestStats()(w, listGuardAgentRequest("/api/organizations/org-1/requests/stats"))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		// Exactly what RequestStats returns for zero matching rows — the
		// aggregate never discloses that org rows exist.
		require.JSONEq(t,
			`{"total_requests":0,"success_rate":0,"average_latency_ms":0,`+
				`"p95_latency_ms":0,"total_tokens_in":0,"total_tokens_out":0,"total_cost_usd":0}`,
			w.Body.String())
		f := store.lastRequestFilters
		assert.True(t, f.PayloadAuthorizationSet)
		assert.True(t, f.PayloadDenied)
		assert.Empty(t, f.PayloadUserID)
		assert.Empty(t, f.DelegateAgentID)
	})

	t.Run("human member on the same store still sees the rows", func(t *testing.T) {
		// Control: the emptiness above is deny-driven, not fixture-driven.
		store.orgMembers["human-owner/org-1"] = &adminstore.OrgMembership{
			UserID: "human-owner", OrgID: "org-1", Role: adminstore.RoleOrgAdmin,
		}
		ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests", nil)
		h.apiOrgRequests()(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var page struct {
			Data []adminstore.RequestListRow `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
		require.Len(t, page.Data, 1)
		assert.Equal(t, "req-guard-1", page.Data[0].RequestID)

		sw := httptest.NewRecorder()
		sreq := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/stats", nil)
		h.apiOrgRequestStats()(sw, sreq)
		require.Equal(t, http.StatusOK, sw.Code, sw.Body.String())
		var stats adminstore.RequestListStats
		require.NoError(t, json.Unmarshal(sw.Body.Bytes(), &stats))
		assert.Equal(t, int64(1), stats.TotalRequests)
	})
}
