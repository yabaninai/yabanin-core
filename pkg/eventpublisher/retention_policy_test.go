package eventpublisher

// N02-P06 T04 — the Enterprise separation seam, producer side. The FREE
// core installs only the boolean default; these tests prove both directions
// the card requires:
//
//  1. the DEFAULT path (no policy installed) is byte-identical to the
//     pre-seam behavior — same resolver, one resolution per Publish, the
//     same strip/keep outcome on the real wire;
//  2. a TEST DOUBLE implementing conditional semantics (the stand-in for an
//     Enterprise Expr policy) drives the producer boundary through the seam
//     — while the strict content-profile contract keeps winning over ANY
//     policy.

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retConditionalPolicy is the test double: conditional retention semantics
// a licensed Enterprise module could implement with Expr. It retains the
// originals of exactly one org's request.completed events — everything else
// is withheld.
type retConditionalPolicy struct {
	org       string
	eventType string
	calls     []RetentionPolicyRequest
}

func (p *retConditionalPolicy) RetainOriginal(_ context.Context, req RetentionPolicyRequest) bool {
	p.calls = append(p.calls, req)
	return req.OrgID == p.org && req.EventType == p.eventType
}

// TestBooleanRetentionPolicy_DefaultMatrix: the core default is exactly the
// shared boolean resolver — same answers, same single resolution per call,
// nil fail-closed.
func TestBooleanRetentionPolicy_DefaultMatrix(t *testing.T) {
	ctx := context.Background()
	store := &retResolverStubStore{found: true, effective: true}
	resolver := NewOriginalRetentionResolver(store)
	policy := BooleanRetentionPolicy{Resolver: resolver}

	req := RetentionPolicyRequest{OrgID: "org-on", EventType: "request.completed"}
	assert.True(t, policy.RetainOriginal(ctx, req))
	assert.True(t, policy.RetainOriginal(ctx, req))
	assert.Equal(t, 1, store.calls, "the default policy delegates to the TTL-cached resolver")
	assert.Equal(t, "org-on", store.lastOrgID, "only the org attribute reaches the store")

	store.effective = false
	assert.False(t, policy.RetainOriginal(ctx, RetentionPolicyRequest{OrgID: "org-off"}))

	// Nil-backed and nil-receiver policies fail closed, exactly like the
	// pre-seam unwired boundaries.
	assert.False(t, BooleanRetentionPolicy{}.RetainOriginal(ctx, req))
	var nilPolicy BooleanRetentionPolicy
	assert.False(t, nilPolicy.RetainOriginal(ctx, req))
}

// TestResolveOriginalRetention_Precedence: installed policy wins; otherwise
// the boolean default answers; both nil fail closed.
func TestResolveOriginalRetention_Precedence(t *testing.T) {
	ctx := context.Background()
	double := &retConditionalPolicy{org: "org-a", eventType: "request.completed"}
	resolver := NewOriginalRetentionResolver(&retResolverStubStore{found: true, effective: true})

	req := RetentionPolicyRequest{OrgID: "org-a", EventType: "request.completed"}
	assert.True(t, ResolveOriginalRetention(ctx, double, nil, req), "an installed policy wins over no resolver")
	assert.False(t, ResolveOriginalRetention(ctx, double, resolver,
		RetentionPolicyRequest{OrgID: "org-b", EventType: "request.completed"}),
		"an installed policy wins over a wired boolean store too")
	assert.True(t, ResolveOriginalRetention(ctx, nil, resolver, req), "no policy: the boolean default answers")
	assert.False(t, ResolveOriginalRetention(ctx, nil, nil, req), "both absent: fail closed")
}

// TestPublish_RetentionPolicySeam_DefaultPathByteIdentical proves seam
// direction 1: with only the boolean store wired (the FREE-core install),
// the wire outcome and the resolution count are exactly the pre-seam
// contract — the seam adds no lookups, no fields, no rewrites.
func TestPublish_RetentionPolicySeam_DefaultPathByteIdentical(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-seam-default-stream")
	store := &retPubStubStore{found: true, effective: true}
	p.SetOriginalRetentionStore(store)

	require.NotNil(t, p.RetentionPolicy(), "the effective policy is never nil")
	ev := retPublishEvent()
	require.NoError(t, p.Publish(testCtx, ev))
	require.Equal(t, 1, store.calls, "one resolution per Publish — unchanged by the seam")

	vals, err := rdb.XRange(testCtx, "eventpublisher-seam-default-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	assert.Equal(t, ev.UpstreamPayload, entry["upstream_payload"], "opt-in wire outcome byte-identical")
	assert.Equal(t, ev.UpstreamResponse, entry["upstream_response"])

	// The boolean view getter still exposes the same resolver for the
	// in-process call sites — and shares its TTL cache (no second store
	// read for the same org inside the window).
	require.NotNil(t, p.OriginalRetention())
	assert.True(t, p.OriginalRetention().Enabled(testCtx, "org-ret"))
	assert.Equal(t, 1, store.calls, "the getter path shares the warm per-org cache")
}

// TestPublish_RetentionPolicySeam_ConditionalDouble is seam direction 2: a
// test double implementing conditional semantics drives the producer
// boundary. Only the matching org+event-type keeps its captures; every
// other publish strips them — without any boolean store wired at all.
func TestPublish_RetentionPolicySeam_ConditionalDouble(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-seam-conditional-stream")
	policy := &retConditionalPolicy{org: "org-ret", eventType: "request.completed"}
	p.SetRetentionPolicy(policy)

	publish := func(eventType, orgID string) map[string]interface{} {
		ev := retPublishEvent()
		ev.EventType, ev.OrgID = eventType, orgID
		require.NoError(t, p.Publish(testCtx, ev))
		vals, err := rdb.XRange(testCtx, "eventpublisher-seam-conditional-stream", "-", "+").Result()
		require.NoError(t, err)
		require.NotEmpty(t, vals)
		last := vals[len(vals)-1].Values
		return map[string]interface{}{"upstream_payload": last["upstream_payload"], "upstream_response": last["upstream_response"]}
	}

	kept := publish("request.completed", "org-ret")
	assert.NotEmpty(t, kept["upstream_payload"], "the conditioned org+shape keeps its captures")
	assert.NotEmpty(t, kept["upstream_response"])

	for _, tc := range []struct{ name, eventType, orgID string }{
		{"other org, same shape", "request.completed", "org-other"},
		{"same org, other shape", "request.failed", "org-ret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stripped := publish(tc.eventType, tc.orgID)
			assert.Empty(t, stripped["upstream_payload"], "captures withheld outside the condition")
			assert.Empty(t, stripped["upstream_response"])
		})
	}

	require.NotEmpty(t, policy.calls)
	assert.Equal(t, "request.completed", policy.calls[0].EventType, "the policy receives the typed event attributes")
	assert.False(t, policy.calls[0].EventTS.IsZero(), "the producer stamps the event time")
}

// TestPublish_RetentionPolicySeam_InstallRules pins the install contract:
// nil is a no-op, first install wins, and a later boolean store wiring can
// never displace an installed policy (the gateway re-wires the store per
// request completion at runtime).
func TestPublish_RetentionPolicySeam_InstallRules(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-seam-install-stream")
	p.SetRetentionPolicy(nil)
	assert.NotNil(t, p.RetentionPolicy(), "nil install keeps the boolean default")

	first := &retConditionalPolicy{org: "org-ret", eventType: "request.completed"}
	p.SetRetentionPolicy(first)
	p.SetRetentionPolicy(&retConditionalPolicy{org: "org-other", eventType: "request.completed"})
	assert.Empty(t, first.calls, "sanity: no resolution before a publish")

	// The runtime store re-wire (per request completion) must be a no-op
	// behind the installed policy.
	store := &retPubStubStore{found: true, effective: true}
	p.SetOriginalRetentionStore(store)

	require.NoError(t, p.Publish(testCtx, retPublishEvent())) // org-ret + completed → keep
	require.NoError(t, p.Publish(testCtx, func() *Event {     // org-other → strip
		ev := retPublishEvent()
		ev.OrgID = "org-other"
		return ev
	}()))
	assert.Equal(t, 0, store.calls, "the boolean store is never consulted behind an installed policy")
	assert.Len(t, first.calls, 2, "the first policy stays installed")

	vals, err := rdb.XRange(testCtx, "eventpublisher-seam-install-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 2)
	assert.NotEmpty(t, vals[0].Values["upstream_payload"], "first publish keeps captures under the installed policy")
	_, has := vals[1].Values["upstream_payload"]
	assert.False(t, has, "second publish strips under the same installed policy")
}

// TestPublish_RetentionPolicySeam_StrictWinsOverAnyPolicy: the content-
// profile contract is upstream of the seam — a policy that answers true for
// everything still cannot push captures through a strict event.
func TestPublish_RetentionPolicySeam_StrictWinsOverAnyPolicy(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-seam-strict-stream")
	p.SetRetentionPolicy(retainAllPolicy{})

	body := `{"messages":[{"role":"user","content":"secret-seam-body"}]}`
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:        "request.completed",
		OrgID:            "org-seam-strict",
		ContentProfile:   "metadata-only",
		Payload:          body,
		UpstreamPayload:  body,
		UpstreamResponse: `{"completion":"secret-seam-response"}`,
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-seam-strict-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	for _, key := range []string{"upstream_payload", "upstream_response", "payload"} {
		_, has := vals[0].Values[key]
		assert.False(t, has, "%s must stay stripped under strict regardless of the installed policy", key)
	}
	assert.Equal(t, "metadata-only", vals[0].Values["content_profile"])
}

// retainAllPolicy is the maximally permissive double used to prove the
// strict profile wins structurally, over ANY policy.
type retainAllPolicy struct{}

func (retainAllPolicy) RetainOriginal(context.Context, RetentionPolicyRequest) bool { return true }
