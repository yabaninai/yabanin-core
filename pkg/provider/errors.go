package provider

import "errors"

// UnsupportedFeatureError is a deterministic request-shape rejection an
// adapter raises BEFORE any byte leaves the gateway: the requested feature
// (image/audio input, an unmapped content-part type, ...) has no mapping for
// this provider adapter (I51/I61 — explicit reject instead of a silent
// downgrade). The gateway maps the type to an explicit
// 400 invalid_request_error / unsupported_feature answer carrying the
// adapter's own reason text, classifies the outcome as not-executed (no
// breaker penalty, no retry on the same candidate), and lets failover
// chains advance to a media-capable fallback instead of answering an
// opaque upstream_outcome_unknown 502 (N07-P05-T02).
type UnsupportedFeatureError struct {
	// Provider is the canonical adapter identifier (Name(), e.g. "bedrock").
	Provider string
	// Reason is the adapter's exact reject reason (same text as the
	// non-typed rejections kept for wire compatibility).
	Reason string
}

func (e *UnsupportedFeatureError) Error() string {
	if e.Provider != "" {
		return e.Provider + " adapter: " + e.Reason
	}
	return e.Reason
}

// IsUnsupportedFeature reports whether err (or anything it wraps) is a
// deterministic pre-flight feature rejection by a provider adapter.
func IsUnsupportedFeature(err error) bool {
	var ufe *UnsupportedFeatureError
	return errors.As(err, &ufe)
}
