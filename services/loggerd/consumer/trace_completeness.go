package consumer

// Producer-side trace-completeness stamp validation for request_rows.labels
// (G4 owner decision 2026-11-04; CORE-TRACE-05). The envelope shape and
// vocabulary are duplicated from pkg/gateway by design — the consumer accepts
// only what it can interpret, and a producer change arrives with a bumped
// envelope version that this side strips until taught (the same
// identical-caps discipline as the policy-decision envelope). The stamp is
// content-free telemetry: a grammar-bounded JSON envelope, never request
// content. An uninterpretable stamp is stripped and counted via
// gateway_silent_failures_total{place="audit_ingest_trace_completeness"};
// the request row itself still lands.

import (
	"encoding/json"
	"regexp"
)

const (
	// traceStampLabelKey is the reserved producer label key (pkg/gateway
	// traceStampLabelKey — duplicated, not imported: the consumer must keep
	// validating its own copy of the contract).
	traceStampLabelKey = "trace_completeness"

	// traceStampVersion is the only envelope version this consumer
	// interprets (producer traceStampVersion).
	traceStampVersion = 1

	// traceStampMaxReasons matches the producer's bounded reason list (3
	// real reasons + the overflow marker).
	traceStampMaxReasons = 4
)

// traceStampVocabulary is the owner-binding completeness vocabulary
// (full|partial|absent|unknown). Anything else is a contract violation.
var traceStampVocabulary = map[string]struct{}{
	"full":    {},
	"partial": {},
	"absent":  {},
	"unknown": {},
}

// traceStampReasonPattern bounds producer reason codes: colon-separated
// lowercase slugs, printable ASCII, no request content. The closed producer
// enum satisfies the grammar; a future producer reason outside the grammar
// can only arrive with a version bump (rejected above), so the grammar is a
// defense-in-depth bound on the tag surface, not the primary contract check.
var traceStampReasonPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}(:[a-z0-9_]{1,32}){0,2}$`)

// traceStampEnvelope mirrors the producer payload (pkg/gateway
// traceCompletenessEnvelope v1).
type traceStampEnvelope struct {
	Version      int      `json:"v"`
	Completeness string   `json:"c"`
	Reasons      []string `json:"r"`
}

// traceCompletenessLabel validates the producer stamp inside the raw labels
// map. It returns the canonical value to store, whether it is acceptable,
// and the silent-failure reason when it is not (empty when the label is
// simply absent — legacy rows without a stamp are the normal case).
func traceCompletenessLabel(raw map[string]string) (value string, ok bool, failure string) {
	rawValue, present := raw[traceStampLabelKey]
	if !present {
		return "", false, ""
	}
	var env traceStampEnvelope
	if err := json.Unmarshal([]byte(rawValue), &env); err != nil {
		return "", false, "invalid_value"
	}
	if env.Version != traceStampVersion {
		// Producer envelope newer than this consumer: strip rather than
		// store a marker nothing downstream can interpret (same discipline
		// as the policy-decision envelope's unknown-version handling).
		return "", false, "unknown_version"
	}
	if _, known := traceStampVocabulary[env.Completeness]; !known {
		return "", false, "invalid_value"
	}
	if len(env.Reasons) > traceStampMaxReasons {
		return "", false, "invalid_value"
	}
	for _, reason := range env.Reasons {
		if !traceStampReasonPattern.MatchString(reason) {
			return "", false, "invalid_value"
		}
	}
	return rawValue, true, ""
}
