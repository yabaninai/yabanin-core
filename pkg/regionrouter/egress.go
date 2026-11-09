package regionrouter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/sovereign"
)

// ResidencyDisclosure is the mandatory non-claim wording that accompanies
// every routing surface which names a country-bound endpoint (N09-P05
// negative criterion): a country endpoint is a technical policy control.
// It MUST NOT be presented — in APIs, admin UIs, redirects or errors — as
// a legal guarantee of data residency. Legal residency commitments are
// contractual matters; this package only enforces routing constraints.
//
// The canonical wording lives in pkg/sovereign (N09-P05-T04) so the
// region and provider exclusion surfaces render the same sentence from one
// source of truth; this alias keeps every regionrouter reference stable.
const ResidencyDisclosure = sovereign.ResidencyDisclosure

// DataClass is the routing-level data category a request path carries.
// N09-P05-T03 requires routing decisions to account for detectors,
// embeddings, logs and tools in addition to inference — each class maps to
// the closed set of sovereign egress kinds (pkg/sovereign) whose country
// profiles must permit a region before the class may route there.
//
// The set of classes is closed; an unknown class denies every region
// (fail-closed), so a newly introduced category can never silently bypass
// the org's egress policy.
type DataClass string

const (
	// ClassInference is prompt/completion model serving traffic.
	ClassInference DataClass = "inference"
	// ClassDetectors is PII/classification detector traffic. It is a
	// COMPOUND class: detector payloads are derived from request/response
	// content (inference-class data) and detector findings are retained and
	// shipped in the logs/audit plane (logs-class data). A region may carry
	// detectors only when BOTH the inference and the logs profiles permit
	// it — the stricter of the two wins, fail-closed.
	ClassDetectors DataClass = "detectors"
	// ClassEmbeddings is text/vector representation data sent to embedding
	// endpoints or vector stores.
	ClassEmbeddings DataClass = "embeddings"
	// ClassLogs is request/response logging, tracing and audit data.
	ClassLogs DataClass = "logs"
	// ClassTools is tool/MCP call payloads and results leaving the boundary.
	ClassTools DataClass = "tools"
	// ClassExport is dataset/admin export out of the home region.
	ClassExport DataClass = "export"
)

// DataClasses is the closed, canonical set of routing data classes.
var DataClasses = []DataClass{ClassInference, ClassDetectors, ClassEmbeddings, ClassLogs, ClassTools, ClassExport}

// Valid reports whether c is one of the six defined data classes.
func (c DataClass) Valid() bool {
	for _, v := range DataClasses {
		if c == v {
			return true
		}
	}
	return false
}

// Kinds returns the sovereign egress kinds whose country profiles must ALL
// permit a region for the class (fixed order → deterministic denials).
// Every kind is a valid sovereign.EgressKind; the mapping is total over
// sovereign.EgressKinds (see DataClassForKind) so no policy dimension is
// unreachable from routing.
func (c DataClass) Kinds() []sovereign.EgressKind {
	switch c {
	case ClassInference:
		return []sovereign.EgressKind{sovereign.EgressInference}
	case ClassDetectors:
		return []sovereign.EgressKind{sovereign.EgressInference, sovereign.EgressLogs}
	case ClassEmbeddings:
		return []sovereign.EgressKind{sovereign.EgressEmbeddings}
	case ClassLogs:
		return []sovereign.EgressKind{sovereign.EgressLogs}
	case ClassTools:
		return []sovereign.EgressKind{sovereign.EgressTools}
	case ClassExport:
		return []sovereign.EgressKind{sovereign.EgressExport}
	default:
		// Unknown class: empty kind set — callers must treat this as
		// deny-all (CheckClass returns true vacuously, so guard with
		// Valid() before trusting an allow result).
		return nil
	}
}

// DataClassForKind maps a sovereign egress kind to its routing class.
// ok=false for kinds outside the closed sovereign set.
func DataClassForKind(k sovereign.EgressKind) (DataClass, bool) {
	switch k {
	case sovereign.EgressInference:
		return ClassInference, true
	case sovereign.EgressEmbeddings:
		return ClassEmbeddings, true
	case sovereign.EgressLogs:
		return ClassLogs, true
	case sovereign.EgressExport:
		return ClassExport, true
	case sovereign.EgressTools:
		return ClassTools, true
	default:
		return "", false
	}
}

// CheckClass evaluates whether data of the class may go to `country` under
// the policy: EVERY kind of the class must be permitted by Policy.CheckEgress.
// The first denial in the class's fixed kind order wins (deterministic).
// An empty/unknown country never satisfies a non-empty allowlist (the
// sovereign check is fail-closed). For an invalid class Kinds() is empty and
// the check would vacuously allow — callers MUST reject invalid classes
// before calling (Valid gate); this mirrors EgressKind handling upstream.
func CheckClass(pol sovereign.Policy, class DataClass, country string) (bool, sovereign.EgressKind, sovereign.DenialReason) {
	if !class.Valid() {
		return false, "", ""
	}
	for _, k := range class.Kinds() {
		if ok, reason := pol.CheckEgress(k, country); !ok {
			return false, k, reason
		}
	}
	return true, "", ""
}

// EgressDenial records one policy denial (or a permission with empty
// Kind/Rule) for explanation surfaces: logs, admin APIs, metrics labels.
// A denial is always explainable — region, country, which kind of data and
// which rule denied it (N09-P05 facet "explanation of the exclusion
// reason"; provider-exclusion explanations in admin surfaces are T04).
type EgressDenial struct {
	Region  string
	Country string
	// Kind is the sovereign egress kind whose profile denied. Empty only
	// for invalid-class or permission results.
	Kind sovereign.EgressKind
	// Rule is the matched denial rule (kind_excluded / kind_not_allowed /
	// org_excluded). Empty only for invalid-class or permission results.
	Rule sovereign.DenialReason
}

// FallbackHop is one policy-permitted, currently-healthy failover target.
type FallbackHop struct {
	Region     string
	Country    string
	GatewayURL string
	Priority   int
}

// FallbackPlan is the residency-safe route chain for one org and data
// class: the home region (policy permission only — home health is the
// local monitor's concern) followed by healthy, policy-permitted peers
// ordered by priority (ties broken by region name → deterministic).
//
// Invariants:
//   - A peer denied by policy appears ONLY in Denied, never in Route():
//     health never resurrects a denied region (N09-P05 acceptance: a denied
//     region is not used even when the primary route is down).
//   - Pinned orgs never fail over: Fallbacks is empty for them.
//   - Planning is read-only: it does not mutate assignments, health state
//     or metrics (denial counters increment on the serving decision path).
type FallbackPlan struct {
	OrgID       string
	Class       DataClass
	Home        string
	HomeCountry string
	HomeAllowed bool
	// HomeDenial explains why the home region may not carry the class
	// (nil when HomeAllowed).
	HomeDenial *EgressDenial
	Fallbacks  []FallbackHop
	// Denied lists every candidate peer excluded by policy, with the kind
	// and rule that denied it. Sorted by region name (deterministic).
	Denied []EgressDenial
}

// Route returns the ordered routing chain: the home region first (when the
// class is permitted there), then the permitted fallback hops. Consumers
// walk the chain in order; attempt-level retry decisions (unknown outcome
// handling) are governed by N09-P01 semantics, not by this plan.
func (p FallbackPlan) Route() []string {
	out := make([]string, 0, len(p.Fallbacks)+1)
	if p.HomeAllowed {
		out = append(out, p.Home)
	}
	for _, h := range p.Fallbacks {
		out = append(out, h.Region)
	}
	return out
}

// Disclosure returns the mandatory non-legal-guarantee wording that must
// accompany any presentation of this plan's endpoints.
func (p FallbackPlan) Disclosure() string { return ResidencyDisclosure }

// Err returns *ErrNoPermittedRegion when the plan offers no usable route
// (home denied AND no permitted healthy fallback). This is the 503-shaped
// outcome: the routing layer refuses to fall back into a denied region.
func (p FallbackPlan) Err() error {
	if p.HomeAllowed || len(p.Fallbacks) > 0 {
		return nil
	}
	return &ErrNoPermittedRegion{OrgID: p.OrgID, Class: p.Class, Home: p.Home, Denied: p.Denied}
}

// ErrNoPermittedRegion reports that no policy-permitted region exists for
// an org's data class: every candidate was denied by the org's egress
// policy (or no peer is healthy). It carries the per-peer denials so logs
// and admin surfaces can explain the refusal instead of a bare 503.
type ErrNoPermittedRegion struct {
	OrgID  string
	Class  DataClass
	Home   string
	Denied []EgressDenial
}

func (e *ErrNoPermittedRegion) Error() string {
	denied := "none"
	if len(e.Denied) > 0 {
		parts := make([]string, 0, len(e.Denied))
		for _, d := range e.Denied {
			parts = append(parts, fmt.Sprintf("%s=%s/%s/%s", d.Region, d.Country, d.Kind, d.Rule))
		}
		denied = strings.Join(parts, ",")
	}
	return fmt.Sprintf("regionrouter: no policy-permitted region for org=%s class=%s home=%s denied=[%s]: %s",
		e.OrgID, e.Class, e.Home, denied, ResidencyDisclosure)
}

// ErrFailoverPeersDenied is the serving-path refusal raised by
// FailoverEvaluator.Decide when EVERY healthy failover peer was denied by
// the org's egress policy: instead of serving — or, worse, serving from a
// denied region — the request is refused 503-shaped with one structured
// record per denied peer (region, country, kind, rule), so the refusal is
// explainable rather than a bare error (N09-P05-T04). The message keeps the
// historical "denied by egress policy" anchor and always carries the
// residency disclosure.
type ErrFailoverPeersDenied struct {
	OrgID string
	Home  string
	// Kind is the egress kind whose profile denied the peers.
	Kind sovereign.EgressKind
	// Denied lists the per-peer denials (region order follows the health
	// snapshot; the plan path sorts its own copy by region).
	Denied []EgressDenial
}

func (e *ErrFailoverPeersDenied) Error() string {
	denied := "none"
	if len(e.Denied) > 0 {
		parts := make([]string, 0, len(e.Denied))
		for _, d := range e.Denied {
			parts = append(parts, fmt.Sprintf("%s=%s/%s/%s", d.Region, d.Country, d.Kind, d.Rule))
		}
		denied = strings.Join(parts, ",")
	}
	return fmt.Sprintf("regionrouter: failover peers for home region %s denied by egress policy (org=%s kind=%s) denied=[%s]: %s",
		e.Home, e.OrgID, e.Kind, denied, ResidencyDisclosure)
}

// countryLabel canonicalizes a country code for metric labels: trim+upper,
// empty stays empty (bounded by the deployment's configured regions).
func countryLabel(c string) string {
	return strings.ToUpper(strings.TrimSpace(c))
}

// sortDenialsByRegion orders denials deterministically by region name.
func sortDenialsByRegion(d []EgressDenial) {
	sort.Slice(d, func(i, j int) bool { return d[i].Region < d[j].Region })
}
