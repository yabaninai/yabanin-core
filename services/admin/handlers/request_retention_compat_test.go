package handlers

// N02-P06-T09 — the original-retention compatibility matrix, read side.
//
// One table-driven walkthrough of the supported retention CONFIGURATIONS ×
// the real supported history CONSUMERS. Configurations:
//
//	pre-toggle   — an organizations row predating migration 0008 (no
//	               retain_original_text value): the NULL override inherits
//	               adminstore.OriginalRetentionPlatformDefault (OFF, fail-closed)
//	explicit-off — an explicit false override (the opt-out)
//	explicit-on  — an explicit true override (the opt-in)
//
// Consumers: history list, history detail, history export (read + originals
// scopes) and archive search. The durable-history writer (loggerd) and the
// Redis publisher are the write-side consumers; their matrix lives with the
// boundary implementations (services/loggerd/consumer/original_retention_test.go,
// retention_joint_integration_test.go, pkg/eventpublisher/original_retention_test.go,
// publisher_test.go) and is cross-referenced in docs/compatibility.md.
//
// Unsupported cases must fail loudly, never degrade to an implicit allow:
// malformed/unknown retention values are 400s (org_original_retention_test.go
// pins the PATCH surface), a retention store error is a 503 with the
// retention_unavailable audit outcome, and an unknown export scope is a 400.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// retentionCompatStore is the matrix fake: it mirrors the adminstore
// tri-state (NULL override inherits OriginalRetentionPlatformDefault) so the
// pre-toggle era is representable, and it captures the payload access the
// detail consumer actually passed into the store.
type retentionCompatStore struct {
	*mockStore
	// retain is the stored column value; nil = pre-toggle NULL (inherit).
	retain       *bool
	retentionErr error
	access       adminstore.RequestPayloadAccess
}

func (s *retentionCompatStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	if s.retentionErr != nil {
		return nil, s.retentionErr
	}
	setting := &adminstore.OrgOriginalRetention{OrgID: orgID, Enabled: s.retain}
	if s.retain == nil {
		setting.Inherited = true
		setting.Effective = adminstore.OriginalRetentionPlatformDefault
	} else {
		setting.Effective = *s.retain
	}
	return setting, nil
}

func (s *retentionCompatStore) UpdateOrgOriginalRetention(_ context.Context, _ string, enabled *bool) error {
	s.retain = enabled
	return nil
}

func (s *retentionCompatStore) GetRequestDetail(ctx context.Context, orgID, requestID string) (*adminstore.RequestDetail, error) {
	s.access, _ = adminstore.RequestPayloadAccessFromContext(ctx)
	return s.mockStore.GetRequestDetail(ctx, orgID, requestID)
}

func (s *retentionCompatStore) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	return s.mockStore.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope, now)
}

func retentionMatrixConfigs() map[string]*bool {
	return map[string]*bool{
		"pre-toggle (NULL override inherits platform default)": nil,
		"explicit-off": ptrBool(false),
		"explicit-on":  ptrBool(true),
	}
}

func ptrBool(b bool) *bool { return &b }

func TestOriginalRetentionCompatibilityMatrix(t *testing.T) {
	configs := retentionMatrixConfigs()
	names := []string{
		"pre-toggle (NULL override inherits platform default)",
		"explicit-off",
		"explicit-on",
	}

	for _, configName := range names {
		config := configs[configName]
		t.Run(configName, func(t *testing.T) {
			store := &retentionCompatStore{mockStore: newMockStore(), retain: config}
			h := New(store, "", "", nil)
			t.Cleanup(h.Stop)
			// The detail consumer consumes a redeemable originals grant on
			// success, so the export row needs its own grant.
			originalsDetail := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)
			originalsExport := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)
			read := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read"}`)

			t.Run("history list: 200, payload fields follow the authz matrix (retention-independent)", func(t *testing.T) {
				rec := httptest.NewRecorder()
				wrapWithParams(h.apiOrgRequests(), "/api/organizations/{id}/requests")(
					rec, rootPayloadRequest(http.MethodGet, "/api/organizations/org-1/requests", ""))
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.True(t, store.lastRequestFilters.PayloadAuthorizationSet)
				require.False(t, store.lastRequestFilters.PayloadDenied)
				require.NotContains(t, rec.Body.String(), "upstream_request", "the list never carries originals in any configuration")
			})

			t.Run("history detail: originals grant honored only under effective retention", func(t *testing.T) {
				rec := httptest.NewRecorder()
				url := "/api/organizations/org-1/requests/req-1?payload_grant=" + originalsDetail + "&scope=payload.read_originals"
				wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(
					rec, rootPayloadRequest(http.MethodGet, url, ""))
				if config != nil && *config {
					require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
					require.True(t, store.access.Originals, "explicit opt-in must carry originals into the store")
					require.Contains(t, rec.Body.String(), `"upstream_request":{"messages":[{"content":"source"}]}`)
					return
				}
				// FIX-08 detail symmetry: non-effective retention fails loudly
				// BEFORE the consume — the same contract as the export
				// endpoint — instead of degrading to a metadata-only 200.
				require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
				require.Contains(t, rec.Body.String(), "original payload retention is disabled")
				require.NotContains(t, rec.Body.String(), "upstream_request", "fail-closed OFF must hide originals")
				require.True(t, grantAlive(store.mockStore, originalsDetail),
					"a retention denial must not consume the grant")
				found := false
				for _, r := range store.auditRecords {
					if r.Action == "request_detail.denied" && contains(r.Details, `"outcome":"original_retention_disabled"`) {
						found = true
					}
				}
				require.True(t, found, "the detail retention denial must be journalled with its reason")
			})

			t.Run("history export read scope: processed payload, never originals (retention-independent)", func(t *testing.T) {
				rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+read)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.Contains(t, rec.Body.String(), `"arguments"`)
				require.NotContains(t, rec.Body.String(), "upstream_request", "payload.read never unlocks originals in any configuration")
			})

			t.Run("history export originals scope: explicit-on streams, every other configuration denies loudly", func(t *testing.T) {
				before := len(store.auditRecords)
				rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+originalsExport+"&scope=payload.read_originals")
				if config != nil && *config {
					require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
					require.Contains(t, rec.Body.String(), `"upstream_request":{"messages":[{"content":"source"}]}`)
					return
				}
				require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
				require.Contains(t, rec.Body.String(), "original payload retention is disabled")
				require.True(t, grantAlive(store.mockStore, originalsExport), "a retention denial must not consume the grant")
				found := false
				for _, r := range store.auditRecords[before:] {
					if r.Action == "request_export.denied" && contains(r.Details, `"outcome":"original_retention_disabled"`) {
						found = true
					}
				}
				require.True(t, found, "the retention denial must be journalled with its reason")
			})

			t.Run("archive search: shared hot-source search, metadata only (retention-independent)", func(t *testing.T) {
				rec := httptest.NewRecorder()
				wrapWithParams(h.apiOrgArchiveSearch(), "/api/organizations/{id}/requests/archive-search")(
					rec, rootPayloadRequest(http.MethodGet, "/api/organizations/org-1/requests/archive-search?q=secret", ""))
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.Contains(t, rec.Body.String(), `"source":"hot"`)
				require.True(t, store.lastRequestFilters.PayloadAuthorizationSet)
				require.NotContains(t, rec.Body.String(), "upstream_request")
			})
		})
	}
}

// Unsupported cases must fail loudly: an unknown export scope is a 400, a
// retention store error is a 503 fail-closed with the retention_unavailable
// audit outcome and a NOT-consumed grant, and a malformed retention PATCH
// never reaches the store.
func TestOriginalRetentionUnsupportedCasesFailLoudly(t *testing.T) {
	t.Run("unknown export scope is rejected", func(t *testing.T) {
		store := &retentionCompatStore{mockStore: newMockStore(), retain: ptrBool(true)}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token+"&scope=payload.everything")
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	t.Run("retention store error is a 503 with an audit reason and no grant burn", func(t *testing.T) {
		store := &retentionCompatStore{mockStore: newMockStore(), retain: ptrBool(true), retentionErr: fmt.Errorf("retention read failed")}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)
		before := len(store.auditRecords)
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token+"&scope=payload.read_originals")
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		require.True(t, grantAlive(store.mockStore, token))
		found := false
		for _, r := range store.auditRecords[before:] {
			if r.Action == "request_export.denied" && contains(r.Details, `"outcome":"retention_unavailable"`) {
				found = true
			}
		}
		require.True(t, found, "the unavailable retention lookup must be journalled with its reason")
	})

	t.Run("malformed retention PATCH bodies never reach the store", func(t *testing.T) {
		store := &retentionCompatStore{mockStore: newMockStore(), retain: nil}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		for name, body := range map[string]string{
			"missing enabled":  `{}`,
			"unknown value":    `{"enabled":"yes"}`,
			"not json":         `not-json`,
			"non-bool enabled": `{"enabled":1}`,
		} {
			t.Run(name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				wrapWithParams(h.UpdateOrgOriginalRetention(), "/api/organizations/{id}/original-retention")(
					rec, rootRequest(http.MethodPatch, "/api/organizations/org-1/original-retention", body))
				require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
				require.Nil(t, store.retain, "a rejected body must not mutate the stored value")
			})
		}
	})
}
