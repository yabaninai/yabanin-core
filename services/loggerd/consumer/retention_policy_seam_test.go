package consumer

// N02-P06 T04 — the Enterprise separation seam, durable-history side. The
// FREE core installs only the boolean toggle resolver; these tests prove
// that (1) the default path is byte-identical to the pre-seam behavior and
// (2) a test double implementing conditional retention semantics drives the
// delivery boundary through the seam — exactly the integration an
// Enterprise Expr-based module would use. No Enterprise code ships in core.

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seamConditionalPolicy is the consumer-side test double: it retains the
// originals of exactly one org's request.completed events and records the
// requests it saw (the typed attributes the seam hands to a policy).
type seamConditionalPolicy struct {
	org       string
	eventType string
	calls     []RetentionPolicyRequest
}

func (p *seamConditionalPolicy) RetainOriginal(_ context.Context, req RetentionPolicyRequest) bool {
	p.calls = append(p.calls, req)
	return req.OrgID == p.org && req.EventType == p.eventType
}

// TestRetentionPolicySeam_DefaultPathByteIdentical proves direction 1: with
// only the boolean store wired and NO policy installed, the delivery
// resolution is exactly the pre-seam behavior — the store answers, the
// resolver caches, the outcome matches Enabled directly.
func TestRetentionPolicySeam_DefaultPathByteIdentical(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	db := newRetCaptureDB()
	store := &retStubStore{found: true, effective: true}
	c := retConsumer(db, store)
	require.Nil(t, c.retentionPolicy, "core ships no policy")

	msg := redis.XMessage{ID: "50-1", Values: cpCompletedFields("req-seam-default", false)}
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy,
			retainOriginal: c.originalRetentionEnabled(context.Background(), msg.Values)}))

	assert.Equal(t, 1, store.calls, "one resolution, unchanged by the seam")
	assert.Equal(t, "org-cp-1", store.lastOrgID)
	assert.Contains(t, db.allArgs(), cpSentinelUpReq, "default path keeps the opt-in captures byte-identical")

	// The seam routing helper itself is the shared precedence rule.
	ctx := context.Background()
	assert.True(t, c.originalRetentionEnabled(ctx, msg.Values), "warm cache answer")
	assert.Equal(t, 1, store.calls, "still cached — the default added no lookups")
}

// TestRetentionPolicySeam_ConditionalDoubleGatesDelivery proves direction 2
// on the durable-history boundary: the installed double retains exactly the
// conditioned org+event-shape and withholds everything else, with the
// boolean store never consulted.
func TestRetentionPolicySeam_ConditionalDoubleGatesDelivery(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	cases := []struct {
		name      string
		orgID     string
		eventType string
		wantKept  bool
	}{
		{"conditioned org+shape keeps originals", "org-cp-1", "request.completed", true},
		{"other org, same shape strips", "org-other", "request.completed", false},
		{"same org, failed shape strips", "org-cp-1", "request.failed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newRetCaptureDB()
			store := &retStubStore{found: true, effective: true}
			c := retConsumer(db, store)
			policy := &seamConditionalPolicy{org: "org-cp-1", eventType: "request.completed"}
			c.SetRetentionPolicy(policy)

			fields := cpCompletedFields("req-seam-cond", false)
			fields["event_type"] = tc.eventType
			fields["org_id"] = tc.orgID
			require.NoError(t, c.handleRequestCompleteProfile(context.Background(),
				redis.XMessage{ID: "51-1", Values: fields},
				deliveryPolicy{profile: config.LogContentProfileLegacy,
					retainOriginal: c.originalRetentionEnabled(context.Background(), fields)}))

			assert.Equal(t, 0, store.calls, "an installed policy replaces the boolean resolution entirely")
			require.Len(t, policy.calls, 1)
			assert.Equal(t, tc.orgID, policy.calls[0].OrgID)
			assert.Equal(t, tc.eventType, policy.calls[0].EventType)
			assert.False(t, policy.calls[0].EventTS.IsZero(), "the wire event time rides the seam")

			joined := db.allArgs()
			if tc.wantKept {
				assert.Contains(t, joined, cpSentinelUpReq)
				assert.Contains(t, joined, cpSentinelUpResp)
			} else {
				assert.NotContains(t, joined, cpSentinelUpReq)
				assert.NotContains(t, joined, cpSentinelUpResp)
			}
		})
	}
}

// TestRetentionPolicySeam_StrictWinsOverConsumerPolicy: the strict profile
// drops captures upstream of the seam — a permissive-all policy cannot push
// content into a metadata-only delivery.
func TestRetentionPolicySeam_StrictWinsOverConsumerPolicy(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	db := newRetCaptureDB()
	c := retConsumer(db, nil)
	c.SetRetentionPolicy(seamPermissivePolicy{})

	msg := redis.XMessage{ID: "52-1", Values: cpCompletedFields("req-seam-strict", true)}
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileMetadataOnly,
			retainOriginal: c.originalRetentionEnabled(context.Background(), msg.Values)}))

	assertNoSentinel(t, db)
}

// TestRetentionPolicySeam_InstallRules: nil and re-installs are no-ops
// (first non-nil install wins), and SetOriginalRetentionStore can never
// displace an installed policy.
func TestRetentionPolicySeam_InstallRules(t *testing.T) {
	c := New(&mockRedis{}, newRetCaptureDB(), "events:queue", silentLogger())

	c.SetRetentionPolicy(nil)
	assert.Nil(t, c.retentionPolicy, "nil install is a no-op")

	first := &seamConditionalPolicy{org: "org-a", eventType: "request.completed"}
	c.SetRetentionPolicy(first)
	c.SetRetentionPolicy(&seamConditionalPolicy{org: "org-b", eventType: "request.completed"})
	c.SetRetentionPolicy(nil)
	c.SetOriginalRetentionStore(&retStubStore{found: true, effective: true})

	assert.Empty(t, first.calls, "sanity: nothing resolved yet")
	ctx := context.Background()
	assert.True(t, c.originalRetentionEnabled(ctx, map[string]interface{}{
		"org_id": "org-a", "event_type": "request.completed"}), "the first policy stays installed")
	assert.False(t, c.originalRetentionEnabled(ctx, map[string]interface{}{
		"org_id": "org-b", "event_type": "request.completed"}), "the re-install never displaced it")
	assert.Len(t, first.calls, 2, "both resolutions went through the first policy")
}

// TestRetentionPolicySeam_PolicyFailureFailsClosedByContract documents the
// boundary of the seam's own guarantees: the core never swallows a policy
// error (the interface has none) and never softens a false — the fail-closed
// matrix belongs to the boolean default and to each licensed policy's own
// contract. A double that answers false strips, deterministically.
func TestRetentionPolicySeam_PolicyFailureFailsClosedByContract(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	db := newRetCaptureDB()
	c := retConsumer(db, nil)
	c.SetRetentionPolicy(denyAllPolicy{})

	msg := redis.XMessage{ID: "53-1", Values: cpCompletedFields("req-seam-deny", false)}
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy,
			retainOriginal: c.originalRetentionEnabled(context.Background(), msg.Values)}))
	assertNoSentinel(t, db)
}

// denyAllPolicy is the always-withhold double (the safe extreme of a
// conditional policy).
type denyAllPolicy struct{}

func (denyAllPolicy) RetainOriginal(context.Context, RetentionPolicyRequest) bool { return false }

// seamPermissivePolicy is the maximally permissive double, used to prove
// the strict profile wins structurally over ANY policy.
type seamPermissivePolicy struct{}

func (seamPermissivePolicy) RetainOriginal(context.Context, RetentionPolicyRequest) bool { return true }
