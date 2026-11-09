package handlers

// FIX-08 (OBS-01): the one-time payload-grant refusal/replay contract on the
// export endpoint. Phase order must be prechecks → atomic consume →
// disclosure: every read-only precheck (export-capability assertion, the
// pre-flight row count and its 413 cap) runs BEFORE the grant consume, so a
// pre-stream failure (500/413/503) denies with the token still redeemable and
// is journalled; the consume stays the last step before the 200 commit, and
// any failure after disclosure starts (X-Export-Error trailers) leaves the
// token consumed — never refunded, never re-served.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

// fix08SeamStore records the handler seam order and can fail each phase on
// command: the pre-flight list, the grant consume, and the disclosure stream.
// Its delegate calls are serialized so concurrent redemptions stay race-free
// while the consume itself keeps the mock's own atomic guard.
type fix08SeamStore struct {
	*mockStore
	mu               sync.Mutex
	calls            []string
	failPreflight    bool
	overCap          bool
	failMidStream    bool
	streaming        bool
	preflightFilters *adminstore.RequestListFilters
}

func (s *fix08SeamStore) record(stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, stage)
}

func (s *fix08SeamStore) callsSoFar() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fix08SeamStore) ListRequests(ctx context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	s.mu.Lock()
	streaming := s.streaming
	if !streaming {
		copied := f
		s.preflightFilters = &copied
	}
	s.mu.Unlock()
	if streaming {
		s.record("stream-list")
	} else {
		s.record("preflight")
		if s.failPreflight {
			return nil, 0, errors.New("database unavailable")
		}
		if s.overCap {
			return nil, maxRequestExportRows + 1, nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mockStore.ListRequests(ctx, f)
}

func (s *fix08SeamStore) preflightFiltersSeen() *adminstore.RequestListFilters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preflightFilters
}

func (s *fix08SeamStore) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	s.record("consume")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mockStore.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope, now)
}

func (s *fix08SeamStore) StreamRequestExport(ctx context.Context, filters adminstore.RequestListFilters, access adminstore.RequestPayloadAccess, maxRows int, emit func(*adminstore.RequestDetail) error) (int, error) {
	s.record("stream")
	s.mu.Lock()
	s.streaming = true
	s.mu.Unlock()
	rows, total, err := s.ListRequests(ctx, filters)
	if err != nil || total > maxRows {
		return total, err
	}
	emitted := 0
	for _, row := range rows {
		detailCtx := adminstore.WithRequestPayloadAccess(ctx, access)
		s.mu.Lock()
		d, err := s.GetRequestDetail(detailCtx, filters.OrgID, row.RequestID)
		s.mu.Unlock()
		if err != nil {
			if adminstore.IsNotFound(err) {
				continue
			}
			return total, err
		}
		if err := emit(d); err != nil {
			return total, err
		}
		emitted++
	}
	if s.failMidStream && emitted > 0 {
		// Disclosure has already happened: rows are on the wire when the
		// store walk fails mid-stream.
		return total, errors.New("database unavailable mid-stream")
	}
	return total, nil
}

// fix08PreflightFailStore is the ported REPRO-3 fixture: a healthy mock store
// whose ListRequests always fails (a stand-in for any store-side DB failure).
type fix08PreflightFailStore struct {
	*mockStore
}

func (s *fix08PreflightFailStore) ListRequests(context.Context, adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	return nil, 0, errors.New("database unavailable")
}

// fix08NoExportStore satisfies StoreInterface and the grant capability but
// deliberately lacks StreamRequestExport, so the export-capability type
// assertion fails while everything else behaves like the mock.
type fix08NoExportStore struct {
	StoreInterface
	base *mockStore
}

func newFix08NoExportStore() (*fix08NoExportStore, *mockStore) {
	base := newMockStore()
	return &fix08NoExportStore{StoreInterface: base, base: base}, base
}

func (s *fix08NoExportStore) CreateRequestPayloadGrant(orgID, requestID, rootID string, ttl time.Duration, now time.Time) (adminstore.RequestPayloadGrant, error) {
	return s.base.CreateRequestPayloadGrant(orgID, requestID, rootID, ttl, now)
}

func (s *fix08NoExportStore) CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope string, ttl time.Duration, now time.Time) (adminstore.RequestPayloadGrant, error) {
	return s.base.CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope, ttl, now)
}

func (s *fix08NoExportStore) ConsumeRequestPayloadGrant(token, orgID, requestID, rootID string, now time.Time) bool {
	return s.base.ConsumeRequestPayloadGrant(token, orgID, requestID, rootID, now)
}

func (s *fix08NoExportStore) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	return s.base.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope, now)
}

func (s *fix08NoExportStore) RevokeRequestPayloadGrant(token, rootID string) error {
	return s.base.RevokeRequestPayloadGrant(token, rootID)
}

func (s *fix08NoExportStore) ListRequestPayloadGrants(ctx context.Context, rootID string) ([]adminstore.RequestPayloadGrant, error) {
	return s.base.ListRequestPayloadGrants(ctx, rootID)
}

func (s *fix08NoExportStore) InsertAuditLogEntry(ctx context.Context, rec adminstore.AuditLogEntryRecord) error {
	return s.base.InsertAuditLogEntry(ctx, rec)
}

func (s *fix08NoExportStore) ListAuditLogEntries(ctx context.Context, q adminstore.AuditLogQuery) ([]adminstore.AuditLogEntry, int64, int64, error) {
	return s.base.ListAuditLogEntries(ctx, q)
}

func (s *fix08NoExportStore) EnqueueAuditOutbox(ctx context.Context, rec adminstore.AuditLogEntryRecord) error {
	return s.base.EnqueueAuditOutbox(ctx, rec)
}

func (s *fix08NoExportStore) DrainAuditOutbox(ctx context.Context, limit int) (int, error) {
	return s.base.DrainAuditOutbox(ctx, limit)
}

// fix08AuditDeniedOutcome returns the latest journalled request_export.denied
// record carrying the given outcome, or nil.
func fix08AuditDeniedOutcome(store *mockStore, outcome string) *adminstore.AuditLogEntryRecord {
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	needle := `"outcome":"` + outcome + `"`
	for i := range store.auditRecords {
		r := &store.auditRecords[i]
		if r.Action == "request_export.denied" && strings.Contains(r.Details, needle) {
			return r
		}
	}
	return nil
}

// Failing-before (OBS-01 repro, ported from REPRO-3): a store-side pre-flight
// failure used to be answered 500 AFTER the grant consume had already
// committed — the caller paid the one-time token and received nothing. After
// the FIX-08 reorder the pre-flight count runs before the consume, so the 500
// leaves the grant redeemable and is journalled as a denial.
func TestAuditExportStoreFailureDoesNotBurnGrant(t *testing.T) {
	base := newMockStore()
	store := &fix08PreflightFailStore{base}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "arguments", "a pre-stream failure must not disclose payload bytes")
	require.True(t, grantAlive(base, token),
		"request export failed before any payload, but one-time grant was consumed")
	require.NotNil(t, fix08AuditDeniedOutcome(base, "store_error"),
		"a pre-stream store failure must be journalled as a denied export")
}

// Phase-order probe (adapted REPRO-3 W1): the recorded seam order must be
// preflight → consume → stream, and a pre-flight failure must stop before the
// consume seam with the token intact. Before FIX-08 the order was
// [consume, preflight] with the token burned on the 500.
func TestFIX08PrechecksRunBeforeGrantConsume(t *testing.T) {
	t.Run("healthy run", func(t *testing.T) {
		store := &fix08SeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, []string{"preflight", "consume", "stream", "stream-list"}, store.callsSoFar(),
			"prechecks must run before the atomic consume; the consume stays the last step before disclosure")
		require.Contains(t, rec.Body.String(), `"arguments"`)
		require.False(t, grantAlive(store.mockStore, token), "the happy path consumes the grant exactly once")
	})

	t.Run("preflight failure stops before consume", func(t *testing.T) {
		store := &fix08SeamStore{mockStore: newMockStore(), failPreflight: true}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

		require.Equal(t, []string{"preflight"}, store.callsSoFar(),
			"a pre-flight failure must stop before the consume seam")
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		require.True(t, grantAlive(store.mockStore, token), "a pre-stream 500 must not burn the grant")
	})

	t.Run("preflight count uses grant-hypothetical widening for a discarded read", func(t *testing.T) {
		store := &fix08SeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		preflight := store.preflightFiltersSeen()
		require.NotNil(t, preflight)
		require.True(t, preflight.PayloadGrant && preflight.OrgWideMetadata && preflight.OwnerUserID == "",
			"the row cap is only exact if the pre-flight count runs under the grant-hypothetical widening")
	})
}

// W2 adapted (expired grant × failing pre-flight): both outcomes stay
// fail-closed — after the reorder the pre-flight 500 wins and the expired
// token is never consumed; with a healthy store the expired grant still stops
// at the consume seam with the generic 403 and zero disclosure.
func TestFIX08ExpiredGrantWithDBErrorFailsClosed(t *testing.T) {
	expire := func(store *fix08SeamStore, token string) {
		mockPayloadGrantMu.Lock()
		g := mockPayloadGrants[store.mockStore][token]
		g.ExpiresAt = time.Now().UTC().Add(-time.Second)
		mockPayloadGrants[store.mockStore][token] = g
		mockPayloadGrantMu.Unlock()
	}

	t.Run("expired grant, failing preflight", func(t *testing.T) {
		store := &fix08SeamStore{mockStore: newMockStore(), failPreflight: true}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		expire(store, token)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		require.Equal(t, []string{"preflight"}, store.callsSoFar())
		require.True(t, grantAlive(store.mockStore, token),
			"the expired token was never consumed — the pre-flight failure must not burn it either")
	})

	t.Run("expired grant, healthy store", func(t *testing.T) {
		store := &fix08SeamStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		expire(store, token)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "arguments")
		require.Equal(t, []string{"preflight", "consume"}, store.callsSoFar(),
			"the expired grant must stop at the consume seam after the prechecks")
		require.True(t, grantAlive(store.mockStore, token),
			"a failed consume must not delete the grant record (it stays expired, not burned)")
	})
}

// W3 adapted (consume-side store error, healthy list): the pre-flight read
// runs first, the consume fails closed with the generic 403, and the grant
// record survives — only the window after a SUCCESSFUL consume is final.
func TestFIX08GrantStoreErrorFailsClosed(t *testing.T) {
	base := newMockStore()
	store := &exportRetentionStore{mockStore: base, consumeErr: adminstore.ErrRequestPayloadGrantUnavailable}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "arguments")
	require.True(t, grantAlive(base, token), "a failed consume never burns the grant")
	require.NotNil(t, fix08AuditDeniedOutcome(base, "grant_invalid_or_unavailable"),
		"a consume-side failure must be journalled as a denied export")
}

// Pre-stream 413 (row-cap denial on the pre-flight count) must keep the grant
// redeemable and be journalled; the mid-stream byte/row caps are trailers on
// the committed 200 and are a different, final outcome.
func TestFIX08PreStreamRowCapDenialDoesNotBurnGrant(t *testing.T) {
	store := &fix08SeamStore{mockStore: newMockStore(), overCap: true}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "arguments", "a 413 denial must not disclose rows")
	require.Equal(t, []string{"preflight"}, store.callsSoFar(),
		"the cap check is a precheck — the consume seam must never run")
	require.True(t, grantAlive(store.mockStore, token), "a pre-stream 413 must not burn the grant")
	require.NotNil(t, fix08AuditDeniedOutcome(store.mockStore, "row_limit"),
		"a pre-stream 413 must be journalled as a denied export")
}

// Pre-stream 503 (store lacks the export capability) must keep the grant
// redeemable and be journalled.
func TestFIX08ExportUnavailableDenialDoesNotBurnGrant(t *testing.T) {
	store, base := newFix08NoExportStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "arguments")
	require.True(t, grantAlive(base, token), "a pre-stream 503 must not burn the grant")
	require.NotNil(t, fix08AuditDeniedOutcome(base, "export_unavailable"),
		"a pre-stream 503 must be journalled as a denied export")
}

// After the 200 stream is committed the attempt is final (documented
// contract): a mid-stream store failure delivers a partial JSONL prefix plus
// the X-Export-Error: store_error trailer, leaves the token consumed, and is
// journalled as an allowed attempt with outcome=store_error. No refund exists;
// the replay gets the same generic 403 as an unknown grant (anti-oracle).
func TestFIX08MidStreamStoreFailureBurnsGrantAndIsJournalled(t *testing.T) {
	store := &fix08SeamStore{mockStore: newMockStore(), failMidStream: true}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)

	require.Equal(t, http.StatusOK, rec.Code, "the 200 was already committed when the stream failed")
	require.Contains(t, rec.Body.String(), `"arguments"`, "partial data was disclosed before the failure")
	require.Equal(t, "store_error", rec.Header().Get("X-Export-Error"))
	require.False(t, grantAlive(store.mockStore, token),
		"a post-disclosure failure is final: the token stays consumed (never refunded)")

	store.auditMu.Lock()
	var journalled *adminstore.AuditLogEntryRecord
	for i := range store.auditRecords {
		if store.auditRecords[i].Action == "request_export" {
			journalled = &store.auditRecords[i]
		}
	}
	store.auditMu.Unlock()
	require.NotNil(t, journalled, "the allowed stream attempt must be journalled")
	require.Contains(t, journalled.Details, `"outcome":"store_error"`)
	require.Contains(t, journalled.Details, `"rows":1`)

	replay := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
	require.Equal(t, http.StatusForbidden, replay.Code, replay.Body.String())
	require.NotContains(t, replay.Body.String(), "arguments")
}

// Two concurrent redemptions of one grant must produce at most one payload:
// the winner's 200 streams the row, every loser is denied with the generic
// 403 and zero payload bytes. The store's conditional consume stays the
// single authority (handler order: no byte before a successful consume).
func TestFIX08ConcurrentRedemptionsDiscloseAtMostOnePayload(t *testing.T) {
	store := &fix08SeamStore{mockStore: newMockStore()}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	const redemptions = 8
	type redemption struct {
		status  int
		body    string
		trailer string
	}
	results := make([]redemption, redemptions)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < redemptions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
			results[i] = redemption{status: rec.Code, body: rec.Body.String(), trailer: rec.Header().Get("X-Export-Error")}
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
			require.Empty(t, r.trailer, "a denied redemption never opens a stream, so no trailer exists")
		}
	}
	require.Equal(t, 1, allowed, "exactly one concurrent redemption may disclose the payload")
	require.False(t, grantAlive(store.mockStore, token), "the grant is consumed exactly once")
}
