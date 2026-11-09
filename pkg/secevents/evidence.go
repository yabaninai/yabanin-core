// Redacted evidence references (E01-P03-W03).
//
// A security event never carries content: the evidence lives in the
// store that produced the event (request logs, policy decision records,
// attestations), and the event carries only typed references to it. This
// is the security-event generalization of two landed core rules:
//
//   - the digest-reference rule: PromptHash (pkg/eventpublisher) and the
//     PB1 attestation hash reference evidence by SHA-256, never inline;
//   - the media-hygiene rule (I62): captures must never indirectly retain
//     media bytes — a Location that would smuggle a data URL is rejected.
//
// The redaction is by construction: EvidenceRef has no field that could
// hold evidence content — only a kind, a digest of the redacted artifact,
// and an optional storage location.

package secevents

import (
	"fmt"
	"regexp"
	"strings"
)

// EvidenceKind values for the core adapter. The kind namespace is open
// (lowercase slug) so enterprise integrations can add their own without a
// schema bump; the core-derivable kinds are named for consistency.
const (
	EvidencePayloadDigest  = "payload_digest"  // digest of the request capture (PromptHash rule)
	EvidencePolicyDecision = "policy_decision" // digest of the OP-8/OP-9 policy decision record
)

var (
	digestShape = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dataURLLeak = regexp.MustCompile(`(?i)data:`)
)

// EvidenceRef references one redacted evidence artifact.
type EvidenceRef struct {
	// Kind names the evidence class (e.g. "payload_digest"). Lowercase
	// slug, open namespace.
	Kind string `json:"kind"`
	// Digest is the lower-case hex SHA-256 of the redacted evidence
	// artifact — the same reference form as eventpublisher.PromptDigest.
	Digest string `json:"digest"`
	// Location is an optional storage pointer (where the artifact lives),
	// e.g. "request_logs:payload:<request_id>". It is a pointer, never a
	// capture: content-bearing strings (any case-insensitive data: URL,
	// base64 or not) are rejected.
	Location string `json:"location,omitempty"`
}

func (r EvidenceRef) validate() error {
	if !validSlug(r.Kind) {
		return fmt.Errorf("%w: evidence[%s]: kind %q", ErrInvalidEvent, r.Digest, r.Kind)
	}
	if !digestShape.MatchString(r.Digest) {
		return fmt.Errorf("%w: evidence kind %s: digest must be 64 lower-case hex chars", ErrInvalidEvent, r.Kind)
	}
	if len(r.Location) > 256 {
		return fmt.Errorf("%w: evidence kind %s: location too long", ErrInvalidEvent, r.Kind)
	}
	if dataURLLeak.MatchString(r.Location) {
		return fmt.Errorf("%w: evidence kind %s: location must not carry data URLs (I62 media hygiene)", ErrInvalidEvent, r.Kind)
	}
	for _, s := range []string{r.Kind, r.Location} {
		if strings.ContainsAny(s, " \t\r\n") {
			return fmt.Errorf("%w: evidence kind %s: whitespace in %q", ErrInvalidEvent, r.Kind, s)
		}
	}
	return nil
}
