package eventpublisher

// N02-P06 T04 — the Enterprise separation seam for original-text retention.
//
// PRODUCT-CONTRACT («сложные условия хранения отделены от бесплатных общих
// политик»; owner answers I26/I63): the FREE core ships the simple boolean
// org toggle (original_retention.go — fail-closed OFF, adminstore-backed);
// COMPLEX retention CONDITIONS (Expr-based, e.g. per-event-type or time-
// windowed rules) belong to the separately-licensed Enterprise edition.
//
// This file is the SEAM only — no Enterprise code ships in core:
//
//   - RetentionPolicyResolver is the hook an Enterprise module implements.
//   - BooleanRetentionPolicy is the core-installed default: it delegates to
//     the shared OriginalRetentionResolver, so the unwired core path is
//     byte-identical to the pre-seam behavior (same resolver, same cache,
//     same fail-closed matrix, one resolution per boundary call).
//   - The boundaries (RedisPublisher.Publish and the loggerd durable-history
//     writer) resolve through the installed policy when one is present and
//     through the boolean default otherwise. Core keeps working with zero
//     Enterprise code; installing a policy is the only integration an
//     Enterprise module needs.
//
// Boundaries of the seam itself:
//
//   - The policy answers "may the ORIGINAL captures of this event be
//     durably persisted?". It never widens the content-profile contract:
//     the strict (metadata-only) profile drops captures before this
//     decision on every boundary, for any policy, installed or not.
//   - Fail-closed ownership: the CORE default (nil policy, nil resolver,
//     empty org, store error) resolves OFF. An installed policy owns its
//     own fail-closed behavior — a broken Enterprise module that answers
//     true is a licensed-module contract violation, and the core treats an
//     installed non-nil policy as authoritative (first-wins install, no
//     runtime swaps).
//   - Caching: the boolean default caches per org (TTL 30s). A custom
//     policy is resolved on every boundary call and owns any caching of
//     its own.

import (
	"context"
	"time"
)

// RetentionPolicyRequest carries the event facts a retention decision may
// condition on. The field set is deliberately small and closed for the core;
// an Enterprise Expr policy evaluates these typed attributes (plus its own
// licensed configuration) — never arbitrary event content, which must not
// leak into a policy decision path.
type RetentionPolicyRequest struct {
	// OrgID is the tenant the event belongs to ("" never retains: the
	// boolean default fails closed on it).
	OrgID string
	// EventType is the wire event_type ("request.completed", …).
	EventType string
	// EventTS is the producer event time (zero when the wire carried none).
	EventTS time.Time
}

// RetentionPolicyResolver decides whether the original captures of one event
// may be durably persisted (the buffer XADD, the history row, the DLQ
// envelope). Implementations must be safe for concurrent use and must not
// retain the request.
type RetentionPolicyResolver interface {
	RetainOriginal(ctx context.Context, req RetentionPolicyRequest) bool
}

// BooleanRetentionPolicy is the FREE-core policy: the org boolean toggle
// resolved through OriginalRetentionResolver. A nil Resolver (and a nil
// *OriginalRetentionResolver receiver) fails closed to OFF — the identical
// matrix the unwired boundaries have always had.
type BooleanRetentionPolicy struct {
	Resolver *OriginalRetentionResolver
}

// RetainOriginal delegates to the shared boolean resolver; one resolution
// per call (cache-hit within the TTL), exactly the pre-seam call shape.
func (p BooleanRetentionPolicy) RetainOriginal(ctx context.Context, req RetentionPolicyRequest) bool {
	return p.Resolver.Enabled(ctx, req.OrgID) // nil-receiver safe: false
}

// ResolveOriginalRetention is the single routing rule shared by every
// retention boundary (the RedisPublisher producer pre-XADD strip and the
// loggerd durable-history/DLQ writer): an installed policy wins; otherwise
// the FREE-core boolean default answers. Exported so the producer and the
// consumer cannot drift apart on the precedence.
func ResolveOriginalRetention(ctx context.Context, policy RetentionPolicyResolver, boolean *OriginalRetentionResolver, req RetentionPolicyRequest) bool {
	if policy != nil {
		return policy.RetainOriginal(ctx, req)
	}
	return boolean.Enabled(ctx, req.OrgID) // nil-receiver safe: false
}
