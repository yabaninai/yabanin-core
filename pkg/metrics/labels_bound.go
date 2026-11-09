// Bounded-label boundary for metric emitters (N13-P02-T03).
//
// Prometheus label values multiply: one new value per distinct tuple mints a
// permanent new time series in every scraper's TSDB. Any emitter that feeds
// a raw, tenant-controlled string into a label explodes series cardinality
// without bound — the same failure mode as an unbounded telemetry-attribute
// domain.
//
// The policy mirrors pkg/tracing's genai.system allowlist: known upstream
// hosts map to their canonical provider bucket, unknown hosts collapse into
// the fixed "other" bucket, unusable input degrades to "unknown". The value
// set is CLOSED: {allowlist systems} ∪ {suffix-rule systems} ∪ {"other",
// "unknown"} — never the raw host, never free text.
//
// Consumers: gateway_upstream_health_state (pkg/metrics/upstream.go) MUST
// take its label from BoundUpstreamHostLabel. Any future metric labeled by
// upstream must do the same; request identifiers (request.id, org.id,
// session ids) are high-cardinality log attributes by design and must never
// become metric labels.

package metrics

import "github.com/reireirei/yabanin/pkg/tracing"

// boundHostUnknown is the fixed bucket for a URL that yields no system
// value at all (empty or unusable input): it is distinct from "other"
// (a KNOWN-unbounded but parseable host) so an operator can tell
// "weird tenant URL" from "broken input" on the dashboard.
const boundHostUnknown = "unknown"

// BoundUpstreamHostLabel derives a bounded Prometheus label value from a raw
// upstream URL. Known hosts map to their canonical provider system (e.g.
// "openai", "aws.bedrock"), unknown hosts bucket to "other", empty or
// unusable input yields "unknown". The value set is closed regardless of how
// many tenant base URLs exist; the raw URL never surfaces as a label.
func BoundUpstreamHostLabel(rawURL string) string {
	if s := tracing.SystemFromUpstreamURL(rawURL); s != "" {
		return s
	}
	return boundHostUnknown
}
