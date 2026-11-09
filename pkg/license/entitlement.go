package license

// EntitlementSource is the extension interface a future closed-source
// enterprise module implements from outside the Apache core.
//
// Boundary rules:
//   - The implementation lives outside core (under a designated enterprise
//     path such as "enterprise/", see scripts/quality/license-policy.json).
//     An enterprise module depends on core, never the reverse: core code
//     must never import an enterprise path.
//   - Wiring is opt-in at the consumer point. A nil EntitlementSource means
//     "not in enforcement mode": current core behavior is unchanged, and
//     consumers must not treat the absence of a source as a failure.
//   - No business defaults: features or activity are never granted without
//     an external source. An error from OrgFeatures propagates to the
//     caller; callers must not fall back to any implicit feature set.
type EntitlementSource interface {
	// OrgFeatures returns the entitlement features granted to orgID.
	OrgFeatures(orgID string) ([]string, error)
	// Active reports whether the external entitlement source is active.
	Active() bool
}
