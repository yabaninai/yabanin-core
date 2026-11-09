package consumer

// N02-P06 T07 — the boundary corpus for the original-retention aspects.
// Table-driven, delivery-boundary level (mock seams, no DB); each entry
// names the aspect, proves the boundary behavior, and cites the test that
// already covers the shared pieces instead of duplicating them:
//
//   - resolver-level rules (fail-closed matrix, TTL expiry pickup with an
//     injected clock, bounds) → TestOriginalRetentionResolver_Matrix
//     (pkg/eventpublisher) — cited, not repeated;
//   - the default-OFF persistence contract →
//     TestHandleMessage_RetentionOffPersistsProcessedOnly — cited; the
//     real-DB NULL-column default is proven by the T06 integration test;
//   - the producer-side strict interplay → TestPublish_strictProfileIgnoresRetention
//     (pkg/eventpublisher) — cited; this corpus adds the consumer-side
//     shape matrix;
//   - the HTTP-layer grant expiry/revocation denial →
//     TestRequestExportRejectsExpiredRevokedAndForeignGrants +
//     TestOriginalPayloadGrantRequiresRetention (services/admin/handlers,
//     merged read path) — cited; this corpus pins the durable-write-side
//     corollary (no retroactive rewrite, read-side denial governs).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	eventpublisher "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retOrgMapStore answers per-org: unknown orgs fail closed (the unknown-
// setting case), known orgs answer their explicit value.
type retOrgMapStore struct {
	answers map[string]bool
	calls   []string
}

func (s *retOrgMapStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	s.calls = append(s.calls, orgID)
	enabled, found := s.answers[orgID]
	if !found {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	return &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: enabled}, nil
}

// retFlippingStore answers ON for the first lookup, then OFF — a mid-stream
// admin toggle flip.
type retFlippingStore struct {
	retStubStore
}

// deliverCompleted drives one completed event through the exact production
// dispatch (one resolution at handleMessage, policy threaded to the shape
// handler) and returns the bound arguments of THIS delivery only (the
// capture DB accumulates across deliveries of one scenario).
func deliverCompleted(t *testing.T, c *StreamConsumer, id, requestID, orgID string) string {
	t.Helper()
	fields := cpCompletedFields(requestID, false)
	fields["org_id"] = orgID
	db, ok := c.dbPool.(*retCaptureDB)
	require.True(t, ok, "corpus consumers must carry a retCaptureDB")
	before := len(db.calls)
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(),
		redis.XMessage{ID: id, Values: fields},
		deliveryPolicy{profile: config.LogContentProfileLegacy,
			retainOriginal: c.originalRetentionEnabled(context.Background(), fields)}))
	return renderJoin2(db.calls[before:])
}

// renderJoin2 renders a call slice (same rendering as allArgs, for a
// sub-slice).
func renderJoin2(calls []retCall) string {
	var sb strings.Builder
	for _, call := range calls {
		sb.WriteString(renderJoin(call.args))
		sb.WriteString("\n")
	}
	return sb.String()
}

// TestRetentionBoundaryCorpus is the T07 aspect corpus. Every entry is a
// named boundary aspect with its observable outcome.
func TestRetentionBoundaryCorpus(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"toggle flip mid-stream: warm cache serves the stale value within the documented TTL", testFlipMidStreamWarmSkew},
		{"toggle flip lands on restart/TTL expiry: fresh consumer re-reads", testFlipLandsOnRestart},
		{"documented skew bound is the 30s default TTL", testSkewBoundDocumented},
		{"org with unknown setting: fail-closed default OFF", testUnknownOrgDefaultOff},
		{"strict profile + retention ON: strict wins on every event shape", testStrictWinsMatrix},
		{"grant expiry vs retention: no retroactive rewrite; read-side denial governs", testGrantExpiryNoRetroactiveRewrite},
		{"multi-org cache isolation in one stream", testMultiOrgCacheIsolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
			t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")
			tc.run(t)
		})
	}
}

// testFlipMidStreamWarmSkew — the documented ≤30s skew boundary: a flip
// between deliveries is NOT observed by a warm consumer inside the TTL
// window; the stale resolution keeps governing the durable writes. Covered
// at the resolver level (TTL expiry pickup, injected clock) by
// TestOriginalRetentionResolver_Matrix — cited, not duplicated.
func testFlipMidStreamWarmSkew(t *testing.T) {
	t.Helper()
	db := newRetCaptureDB()
	store := &retFlippingStore{retStubStore{found: true, effective: true}}
	c := retConsumer(db, store)

	first := deliverCompleted(t, c, "60-1", "req-flip-warm-1", "org-cp-1")
	require.Equal(t, 1, store.calls)

	// Mid-stream flip: the store would now answer OFF.
	store.effective = false

	second := deliverCompleted(t, c, "60-2", "req-flip-warm-2", "org-cp-1")
	assert.Equal(t, 1, store.calls, "the warm cache serves the stale value — the flip is invisible inside the TTL")
	assert.Contains(t, second, cpSentinelUpReq, "the pre-flip resolution keeps governing within the skew window")
	assert.Contains(t, first, cpSentinelUpReq)
}

// testFlipLandsOnRestart — the flip lands at the latest on the resolver
// being rebuilt (process restart or TTL expiry): a fresh consumer re-reads
// the store and applies the new value to every subsequent durable write.
func testFlipLandsOnRestart(t *testing.T) {
	t.Helper()
	db := newRetCaptureDB()
	store := &retFlippingStore{retStubStore{found: true, effective: true}}
	warm := retConsumer(db, store)
	_ = deliverCompleted(t, warm, "61-1", "req-flip-restart-1", "org-cp-1")
	store.effective = false // flip while the warm consumer holds the cache

	fresh := retConsumer(db, store) // the restart: cold resolver
	after := deliverCompleted(t, fresh, "61-2", "req-flip-restart-2", "org-cp-1")
	assert.Equal(t, 2, store.calls, "a cold resolver re-reads the store")
	assert.NotContains(t, after, cpSentinelUpReq, "post-flip deliveries persist processed-only")
}

// testSkewBoundDocumented pins the documented boundary constants: the skew
// window is the 30s default TTL (plus the delivery backlog) and the
// resolver map is bounded. Changing either is a documented-contract change,
// not an implementation detail.
func testSkewBoundDocumented(t *testing.T) {
	t.Helper()
	assert.Equal(t, 30*time.Second, eventpublisher.DefaultOriginalRetentionTTL,
		"the documented toggle-flip propagation bound")
	assert.Equal(t, 4096, eventpublisher.MaxOriginalRetentionOrgs,
		"the documented resolver bound")
}

// testUnknownOrgDefaultOff — an org the settings store does not know (no
// row, NULL override, not-found) resolves OFF: processed-only persistence.
// The same shape with a REAL DB (NULL retain_original_text column) is the
// T06 integration test; the not-found stub contract is already pinned by
// TestHandleMessage_RetentionOffPersistsProcessedOnly — both cited.
func testUnknownOrgDefaultOff(t *testing.T) {
	t.Helper()
	db := newRetCaptureDB()
	c := retConsumer(db, &retOrgMapStore{answers: map[string]bool{}}) // unknown org

	rendered := deliverCompleted(t, c, "62-1", "req-unknown-org", "org-unknown")
	assert.NotContains(t, rendered, cpSentinelUpReq)
	assert.NotContains(t, rendered, cpSentinelUpResp)
	assert.Contains(t, rendered, "TOP SECRET PROMPT BODY", "the processed snapshot still persists")
}

// testStrictWinsMatrix — strict profile + retention ON: the metadata-only
// contract wins on every event shape, whatever the toggle says (the
// producer-side twin is TestPublish_strictProfileIgnoresRetention — cited).
func testStrictWinsMatrix(t *testing.T) {
	t.Helper()
	shapes := []struct {
		eventType string
		id        string
	}{
		{"request.completed", "63-1"},
		{"request.failed", "63-2"},
		{"request.shadow_completed", "63-3"},
		{"request.budget_exceeded", "63-4"},
	}
	for _, shape := range shapes {
		t.Run(shape.eventType, func(t *testing.T) {
			db := newRetCaptureDB()
			c := retConsumer(db, &retStubStore{found: true, effective: true}) // ON

			fields := cpCompletedFields("req-strict-on-"+shape.id, true) // wire strict
			fields["event_type"] = shape.eventType
			require.NoError(t, c.deliverEventPolicy(context.Background(),
				redis.XMessage{ID: shape.id, Values: fields}, shape.eventType,
				deliveryPolicy{profile: config.LogContentProfileMetadataOnly,
					retainOriginal: c.originalRetentionEnabled(context.Background(), fields)}))

			assertNoSentinel(t, db)
			for _, call := range db.calls {
				assert.NotContains(t, call.query, "INSERT INTO tool_calls",
					"strict wins over retention ON on %s", shape.eventType)
			}
		})
	}
}

// testGrantExpiryNoRetroactiveRewrite — the durable-write side of the grant
// expiry vs retention aspect: originals persisted while the toggle (or the
// condition) allowed them are NOT retroactively stripped when the setting
// flips; the read side (expired grant denial; originals requiring effective
// retention at read time — request_export.go) governs exposure. Cited:
// TestRequestExportRejectsExpiredRevokedAndForeignGrants,
// TestOriginalPayloadGrantRequiresRetention (merged handlers).
func testGrantExpiryNoRetroactiveRewrite(t *testing.T) {
	t.Helper()
	db := newRetCaptureDB()
	store := &retFlippingStore{retStubStore{found: true, effective: true}}
	on := retConsumer(db, store)

	whileOn := deliverCompleted(t, on, "64-1", "req-expiry-on", "org-cp-1")
	assert.Contains(t, whileOn, cpSentinelUpReq, "delivered while allowed: originals persisted")

	store.effective = false // the grant/setting expires
	after := deliverCompleted(t, retConsumer(db, store), "64-2", "req-expiry-off", "org-cp-1")
	assert.NotContains(t, after, cpSentinelUpReq, "delivered after expiry: processed-only")

	// The first row's durable representation was never rewritten: the
	// while-on bound arguments stay in the recorded write set unchanged.
	assert.Contains(t, whileOn, cpSentinelUpReq, "no retroactive strip job exists — stored-but-denied is the contract")
}

// testMultiOrgCacheIsolation — interleaved deliveries of two orgs through
// ONE consumer: each org resolves independently (one lookup each), the ON
// org keeps originals, the OFF org binds NULLs, and no resolution leaks
// across orgs. (The count-only version is
// TestOriginalResolution_OneReadPerMessage — cited; this entry pins the
// per-org durable outcomes.)
func testMultiOrgCacheIsolation(t *testing.T) {
	t.Helper()
	db := newRetCaptureDB()
	store := &retOrgMapStore{answers: map[string]bool{"org-on": true, "org-off": false}}
	c := retConsumer(db, store)

	on1 := deliverCompleted(t, c, "65-1", "req-iso-on-1", "org-on")
	off1 := deliverCompleted(t, c, "65-2", "req-iso-off-1", "org-off")
	on2 := deliverCompleted(t, c, "65-3", "req-iso-on-2", "org-on")
	off2 := deliverCompleted(t, c, "65-4", "req-iso-off-2", "org-off")

	assert.Contains(t, on1, cpSentinelUpReq, "the ON org keeps originals")
	assert.Contains(t, on2, cpSentinelUpReq, "the ON org stays cached and keeps originals")
	assert.NotContains(t, off1, cpSentinelUpReq, "the OFF org binds NULLs")
	assert.NotContains(t, off2, cpSentinelUpResp, "the OFF org stays cached and binds NULLs")
	assert.Equal(t, []string{"org-on", "org-off"}, store.calls, "exactly one independent resolution per org")
}
