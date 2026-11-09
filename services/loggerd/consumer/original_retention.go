package consumer

// N02-P06 T03 (core): the org original-text retention toggle, applied at the
// history-writer boundary BEFORE the durable request_logs write.
//
// Contract (N02-P06 contract.md + PRODUCT-CONTRACT §5):
//   - default OFF (fail closed): history persists processed text only. The
//     processed `response` snapshot, the prompt digest and every metadata
//     column keep flowing; the full-fidelity ORIGINAL captures
//     (upstream_request / upstream_response / tool-call arguments) bind SQL
//     NULL until the org explicitly opts in.
//   - One source of truth: the effective value is resolved ONCE per message
//     at handleMessage (the same boundary that computes the effective
//     content profile) and threaded explicitly into every event-shape
//     handler — buffered and streamed shapes share the identical gate, so
//     the persisted representation never drifts between paths.
//   - Lookup errors, an unwired store and an empty org all resolve to OFF —
//     the same fail-closed default as adminstore.OriginalRetentionPlatformDefault.
//     Lookup errors are NOT cached, so a transient DB blip cannot pin the
//     fail-closed answer for a full TTL window.
//
// The resolver itself lives in pkg/eventpublisher (original_retention.go) —
// ONE semantic, two call sites: this durable-history boundary and the
// RedisPublisher.Publish pre-XADD capture strip (N02-P06 T03/T06 producer
// boundary, "retention применяется до записи в buffer/storage"). The names
// below are aliases so the consumer surface (and the production wiring in
// services/run/loggerd.go) is unchanged.

import (
	"context"

	"github.com/reireirei/yabanin/pkg/config"
	eventpublisher "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// deliveryPolicy is the per-message delivery decision computed ONCE at the
// handleMessage boundary: the effective content profile and the org
// original-retention resolution. Every event-shape handler receives the
// same value — buffered and streamed shapes share the identical gate.
type deliveryPolicy struct {
	profile config.LogContentProfile
	// retainOriginal reports the org's effective original-text retention.
	// false (the fail-closed default) persists processed text only.
	retainOriginal bool
}

// legacyDeliveryPolicy is the permissive seam for callers predating the
// content-profile/retention boundary (tests, tooling): legacy profile,
// originals retained — byte-for-byte the pre-toggle behavior.
func legacyDeliveryPolicy() deliveryPolicy {
	return deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}
}

// OriginalRetentionStore is the resolution surface of the org toggle
// (shared definition in pkg/eventpublisher).
type OriginalRetentionStore = eventpublisher.OriginalRetentionStore

// AdminOriginalRetentionStore adapts *adminstore.Store to the consumer
// surface (shared definition in pkg/eventpublisher).
type AdminOriginalRetentionStore = eventpublisher.AdminOriginalRetentionStore

// RetentionPolicyResolver is the N02-P06 T04 Enterprise separation seam
// (shared definition in pkg/eventpublisher): the hook an Enterprise module
// implements to govern original persistence with complex (Expr-based)
// conditions. Core ships none — the boolean toggle default below is the
// FREE path and is byte-identical to the pre-seam behavior.
type RetentionPolicyResolver = eventpublisher.RetentionPolicyResolver

// RetentionPolicyRequest is the typed decision input of the seam (shared
// definition in pkg/eventpublisher).
type RetentionPolicyRequest = eventpublisher.RetentionPolicyRequest

// originalRetentionResolver is the shared per-process resolver (pkg/
// eventpublisher): TTL-cached, fail-closed, bounded.
type originalRetentionResolver = eventpublisher.OriginalRetentionResolver

// newOriginalRetentionResolver builds the shared resolver; a nil store keeps
// the fail-closed all-OFF behavior (production wires the adminstore adapter).
func newOriginalRetentionResolver(store OriginalRetentionStore) *originalRetentionResolver {
	return eventpublisher.NewOriginalRetentionResolver(store)
}

// SetOriginalRetentionStore wires the org-toggle source (N02-P06 T03).
// Optional; nil (the default) keeps every org on the fail-closed
// processed-only persistence. Production passes AdminOriginalRetentionStore.
// An installed retention policy (SetRetentionPolicy) is never displaced by
// this call.
func (c *StreamConsumer) SetOriginalRetentionStore(s OriginalRetentionStore) {
	c.originalRetention = newOriginalRetentionResolver(s)
}

// SetRetentionPolicy installs a RetentionPolicyResolver (N02-P06 T04
// Enterprise separation seam) for the durable-history/DLQ boundary.
// Optional — core ships none. While installed (non-nil), the policy answers
// every per-message retention resolution in place of the boolean toggle;
// first non-nil install wins, later installs and nil are no-ops, and
// SetOriginalRetentionStore cannot displace it. Wire before Start, like the
// other optional seams. The content-profile contract is upstream of this
// decision and keeps winning: the strict profile drops captures before any
// policy is consulted.
func (c *StreamConsumer) SetRetentionPolicy(p RetentionPolicyResolver) {
	if p == nil {
		return
	}
	if c.retentionPolicy != nil {
		return
	}
	c.retentionPolicy = p
}

// originalRetentionEnabled resolves the toggle once per message at the
// handleMessage boundary. It is the single read of the toggle on the
// delivery path: the resolved bool is threaded into the event-shape
// handlers, never re-read per handler or per column. The resolution routes
// through the T04 seam — an installed Enterprise policy wins; the default
// path is the shared boolean resolver with its fail-closed matrix (nil
// resolver, nil store, empty org, lookup error → false) and is byte-
// identical to the pre-seam behavior.
func (c *StreamConsumer) originalRetentionEnabled(ctx context.Context, fields map[string]interface{}) bool {
	req := eventpublisher.RetentionPolicyRequest{
		OrgID:     eventString(fields, "org_id"),
		EventType: eventString(fields, "event_type"),
		EventTS:   eventCreatedAt(fields),
	}
	return eventpublisher.ResolveOriginalRetention(ctx, c.retentionPolicy, c.originalRetention, req)
}

// originalCaptureFieldKeys are the wire fields that carry full-fidelity
// ORIGINAL captures. Under retention OFF they must never reach a durable
// write — the producer (RedisPublisher.Publish) withholds them pre-XADD;
// this consumer-side strip covers entries already in flight from a producer
// predating that gate, so the DLQ envelope can never re-introduce them.
var originalCaptureFieldKeys = map[string]struct{}{
	"upstream_payload":  {},
	"upstream_response": {},
}

// retentionStrippedValues rebuilds stream values without the original
// capture fields. Every other field (metadata, processed payload, digest)
// passes through verbatim.
func retentionStrippedValues(values map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(values))
	for k, v := range values {
		if _, capture := originalCaptureFieldKeys[k]; capture {
			continue
		}
		out[k] = v
	}
	return out
}
