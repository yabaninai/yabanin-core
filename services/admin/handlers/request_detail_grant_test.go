package handlers

// FIX-08 detail symmetry (owner decision 2026-10-24, wave-10 gate): the
// request DETAIL endpoint must follow the same one-time grant refusal/replay
// contract as the export endpoint (option (a+)): every non-disclosing
// precheck (scope validation, grant usability, retention, the row read used
// to decide 404/500) runs BEFORE the atomic consume; the consume is the last
// step before the payload write; a replay answers the same generic 403 as an
// unknown grant (no oracle); post-disclosure failures are final (no refund);
// the metadata-only path (no token) never consumes.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

// detailSeamStore records the handler seam order and can fail each phase on
// command: the pre-consume row read and the grant consume. Delegate calls are
// serialized so concurrent redemptions stay race-free while the consume keeps
// the mock's own atomic guard.
type detailSeamStore struct {
	*mockStore
	mu       sync.Mutex
	calls    []string
	rowGone  bool // the row vanished: the pre-consume read answers 404
	failRead bool // the pre-consume read fails with a store error
	badBody  bool // the read succeeds but the payload cannot be encoded
}

func (s *detailSeamStore) record(stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, stage)
}

func (s *detailSeamStore) callsSoFar() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *detailSeamStore) GetRequestDetail(ctx context.Context, orgID, requestID string) (*adminstore.RequestDetail, error) {
	s.record("read")
	s.mu.Lock()
	rowGone, failRead, badBody := s.rowGone, s.failRead, s.badBody
	s.mu.Unlock()
	switch {
	case rowGone:
		return nil, adminstore.ErrNotFound
	case failRead:
		return nil, context.DeadlineExceeded
	}
	d, err := s.mockStore.GetRequestDetail(ctx, orgID, requestID)
	if badBody && err == nil {
		// Invalid raw JSON forces the writeJSON encode to fail AFTER the 200
		// header is committed (the post-disclosure failure shape).
		d.Response = json.RawMessage(`{"truncated`)
	}
	return d, err
}

func (s *detailSeamStore) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	s.record("consume")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mockStore.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope, now)
}

// runRootDetail invokes the detail handler as root with a concrete target.
func runRootDetail(h *AdminHandlers, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(
		rec, rootPayloadRequest(http.MethodGet, target, ""))
	return rec
}

// detailAuditRecord returns the latest journalled request_detail[.denied]
// record carrying the given outcome, or nil.
func detailAuditRecord(store *mockStore, denied bool, outcome string) *adminstore.AuditLogEntryRecord {
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	action := "request_detail"
	if denied {
		action = "request_detail.denied"
	}
	needle := `"outcome":"` + outcome + `"`
	for i := len(store.auditRecords) - 1; i >= 0; i-- {
		r := &store.auditRecords[i]
		if r.Action == action && strings.Contains(r.Details, needle) {
			return r
		}
	}
	return nil
}

// Failing-before probe: a redemption whose row vanished used to burn the
// one-time grant (consume at the top of the handler, 404 from the row read
// afterwards) — the caller paid the token and received nothing. After the
// reorder the 404 is decided pre-consume and the grant stays redeemable.
func TestDetailGrantRowMissingDoesNotBurnGrant(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore(), rowGone: true}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	require.Equal(t, []string{"read"}, store.callsSoFar(),
		"the row read decides the 404 before the consume seam")
	require.True(t, grantAlive(store.mockStore, token),
		"a 404 decided before the consume must not burn the one-time grant")
	require.NotContains(t, rec.Body.String(), "arguments", "a 404 denial must not disclose payload bytes")
	require.NotNil(t, detailAuditRecord(store.mockStore, true, "row_not_found"),
		"the pre-consume 404 denial must be journalled")
}

// Failing-before probe: a store-side failure on the row read used to be
// answered 500 AFTER the grant consume had committed. After the reorder the
// read runs before the consume, so the 500 leaves the grant redeemable.
func TestDetailGrantStoreErrorDoesNotBurnGrant(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore(), failRead: true}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	require.Equal(t, []string{"read"}, store.callsSoFar(),
		"a failing read must stop before the consume seam")
	require.True(t, grantAlive(store.mockStore, token),
		"a pre-consume 500 must not burn the grant; the redemption may be retried once the store recovers")
	require.NotContains(t, rec.Body.String(), "arguments", "a store failure must not disclose payload bytes")
	require.NotNil(t, detailAuditRecord(store.mockStore, true, "store_error"),
		"the pre-consume store failure must be journalled")
}

// The happy path reads the row first and consumes strictly last before the
// payload write; the grant is consumed exactly once and the payload is
// disclosed once. Before the reorder the seam order was [consume, read].
func TestDetailGrantHappyPathReadsBeforeConsume(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, []string{"read", "consume"}, store.callsSoFar(),
		"prechecks and the row read must run before the atomic consume; the consume stays the last step before disclosure")
	require.Contains(t, rec.Body.String(), `"arguments"`)
	require.False(t, grantAlive(store.mockStore, token), "the happy path consumes the grant exactly once")
	require.NotNil(t, detailAuditRecord(store.mockStore, false, "completed"),
		"the allowed redemption must be journalled")
}

// Replaying a consumed grant (and every other failed consume: invalid,
// expired, revoked, wrong scope, grant-store failure) answers the same
// generic 403 with zero row bytes — the pre-consume read is discarded, so
// invalid and replayed grants stay indistinguishable (anti-oracle).
func TestDetailGrantReplayIsGenericForbidden(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	first := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), `"arguments"`)

	replay := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusForbidden, replay.Code, replay.Body.String())
	require.Contains(t, replay.Body.String(), "request payload grant is invalid or unavailable")
	require.NotContains(t, replay.Body.String(), "arguments")
	require.NotContains(t, replay.Body.String(), "choices", "a failed consume must not fall back to a metadata read")

	expired := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
	mockPayloadGrantMu.Lock()
	g := mockPayloadGrants[store.mockStore][expired]
	g.ExpiresAt = time.Now().UTC().Add(-time.Second)
	mockPayloadGrants[store.mockStore][expired] = g
	mockPayloadGrantMu.Unlock()
	denied := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+expired)
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
	require.Equal(t, replay.Body.String(), denied.Body.String(),
		"invalid and replayed grants must be indistinguishable (same generic body, no oracle)")
	require.NotNil(t, detailAuditRecord(store.mockStore, true, "grant_invalid_or_unavailable"))
}

// A grant presented by a caller who cannot use it (not root, deny-own-history
// policy, or no grant capability) is a loud fail-closed 403 — never a silent
// degrade to a metadata read, and never a consume.
func TestDetailGrantUnusableDeniedWithoutConsumeOrRead(t *testing.T) {
	t.Run("non-root caller", func(t *testing.T) {
		store := &detailSeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet,
			"/api/organizations/org-1/requests/req-1?payload_grant="+token, nil)
		wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "request payload grant cannot be used")
		require.Empty(t, store.callsSoFar(), "an unusable grant must stop before the read and consume seams")
		require.True(t, grantAlive(store.mockStore, token), "a policy refusal must not burn the grant")
		require.NotNil(t, detailAuditRecord(store.mockStore, true, "grant_unusable"))
	})

	t.Run("deny-own-history policy", func(t *testing.T) {
		store := &detailSeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		ctx := adminstore.WithRequestPayloadDenyOwnHistory(context.Background(), true)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet,
			"/api/organizations/org-1/requests/req-1?payload_grant="+token, nil)
		wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(rec, req)

		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Empty(t, store.callsSoFar(), "an explicit policy deny must stop before the read and consume seams")
		require.True(t, grantAlive(store.mockStore, token), "an explicit policy deny must not consume the grant")
	})
}

// Originals scope is gated by effective retention BEFORE the consume, exactly
// like the export endpoint: a disabled setting is a loud 403 and a retention
// lookup error is a fail-closed 503 — both with the grant still redeemable.
func TestDetailGrantRetentionFailsClosedBeforeConsume(t *testing.T) {
	newRetentionStore := func(err error, enabled bool) *retentionCompatStore {
		return &retentionCompatStore{mockStore: newMockStore(), retain: ptrBool(enabled), retentionErr: err}
	}

	t.Run("retention disabled", func(t *testing.T) {
		store := newRetentionStore(nil, false)
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)

		rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token+"&scope=payload.read_originals")

		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "original payload retention is disabled")
		require.NotContains(t, rec.Body.String(), "upstream_request")
		require.True(t, grantAlive(store.mockStore, token), "a retention denial must not consume the grant")
		require.NotNil(t, detailAuditRecord(store.mockStore, true, "original_retention_disabled"))
	})

	t.Run("retention lookup error", func(t *testing.T) {
		store := newRetentionStore(context.DeadlineExceeded, true)
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)

		rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token+"&scope=payload.read_originals")

		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		require.True(t, grantAlive(store.mockStore, token), "fail-closed retention must not consume the grant")
		require.NotNil(t, detailAuditRecord(store.mockStore, true, "retention_unavailable"))
	})
}

// An unknown scope on a grant redemption is a 400 validation refusal with the
// grant untouched (mirrors the export contract); without a token the scope
// parameter stays irrelevant to the metadata-only read.
func TestDetailGrantInvalidScopeRejectedWithoutConsume(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token+"&scope=payload.everything")

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Empty(t, store.callsSoFar(), "scope validation is a precheck — no read, no consume")
	require.True(t, grantAlive(store.mockStore, token), "an invalid scope must not consume the grant")
}

// Two concurrent redemptions of one grant must produce at most one payload:
// the winner's 200 carries the payload, every loser is denied with the
// generic 403 and zero payload bytes (the store's conditional consume stays
// the single authority).
func TestDetailGrantConcurrentRedemptionsDiscloseAtMostOnePayload(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	const redemptions = 8
	type redemption struct {
		status int
		body   string
	}
	results := make([]redemption, redemptions)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < redemptions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)
			results[i] = redemption{status: rec.Code, body: rec.Body.String()}
		}(i)
	}
	close(start)
	wg.Wait()

	allowed := 0
	for _, r := range results {
		if r.status == http.StatusOK {
			allowed++
			require.Contains(t, r.body, `"arguments"`, "the winning redemption must disclose the payload")
		} else {
			require.Equal(t, http.StatusForbidden, r.status, r.body)
			require.NotContains(t, r.body, "arguments", "a losing redemption must never disclose payload bytes")
			require.NotContains(t, r.body, "choices", "a losing redemption must never fall back to a metadata read")
		}
	}
	require.Equal(t, 1, allowed, "exactly one concurrent redemption may disclose the payload")
	require.False(t, grantAlive(store.mockStore, token), "the grant is consumed exactly once")
}

// The metadata-only path (no bearer token) never touches the consume seam —
// role-based and own-history reads keep working without grant side effects.
func TestDetailMetadataOnlyNeverConsumes(t *testing.T) {
	t.Run("root without grant", func(t *testing.T) {
		store := &detailSeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)

		rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1")

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "arguments", "root has no payload scope without a self-grant")
		require.Equal(t, []string{"read"}, store.callsSoFar(), "the metadata-only path must never consume")
	})

	t.Run("own payload without grant", func(t *testing.T) {
		store := &detailSeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)

		ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "subject-a")
		ctx = WithOrgRole(ctx, "org-1", adminstore.RoleReader)
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/req-1", nil)
		wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), `"arguments"`, "own-history payload access needs no grant")
		require.Equal(t, []string{"read"}, store.callsSoFar(), "the metadata-only path must never consume")
	})
}

// Post-disclosure finality: once the consume succeeded and the 200 write
// began, the attempt is final even when the payload encoding fails midway —
// the token stays consumed, there is no refund and no re-serve; the journal
// never carries the bearer token.
func TestDetailGrantPostDisclosureFailureIsFinal(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore(), badBody: true}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)

	require.Equal(t, http.StatusOK, rec.Code, "the 200 is committed before the encode runs")
	require.Equal(t, []string{"read", "consume"}, store.callsSoFar())
	require.False(t, grantAlive(store.mockStore, token),
		"a post-disclosure failure is final: the token stays consumed (never refunded)")

	journalled := detailAuditRecord(store.mockStore, false, "completed")
	require.NotNil(t, journalled, "the attempt must be journalled")
	require.NotContains(t, journalled.Details, token, "the bearer grant token must never reach the journal")

	replay := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusForbidden, replay.Code, replay.Body.String())
}

// Every journalled detail decision carries identifiers and flags only, and
// the details are valid JSON even for a hostile (control-character) request
// id — the request_id is path-controlled.
func TestDetailGrantAuditIsValidJSONForHostileRequestID(t *testing.T) {
	store := &detailSeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootDetail(h, "/api/organizations/org-1/requests/req-1?payload_grant="+token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	missing := runRootDetail(h, "/api/organizations/org-1/requests/req%01%1b%FF?payload_grant="+token)
	require.Equal(t, http.StatusNotFound, missing.Code)

	for _, r := range store.auditRecords {
		if !strings.HasPrefix(r.Action, "request_detail") {
			continue
		}
		require.True(t, json.Valid([]byte(r.Details)),
			"journal details must be valid JSON for a hostile request_id, got %q", r.Details)
		require.NotContains(t, r.Details, token, "the bearer grant token must never reach the journal")
	}
}
