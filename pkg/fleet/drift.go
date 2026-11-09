// Version and caps drift (E03-P01 card W04-C02, batch B): comparing what
// a deployment currently REPORTS against what the registry REMEMBERS,
// and making every difference VISIBLE. Drift is observability — it
// surfaces in the read API (W04-C03) and never refuses anything: only
// revocation blocks issuance (identity.go law), staleness and drift
// inform operators.
//
// Laws:
//   - nil-safe form (modelcatalog.go:374 precedent): a nil remembered
//     installation reports zero values, consistent with "nothing
//     remembered" — never a panic, never a fabricated baseline;
//   - «пустая версия = upstream-пустое»: an empty upstream version is
//     its own EXPLICIT verdict (upstream-empty), not a guess about
//     being behind or ahead;
//   - «N/A где несравнимо»: versions are ordered by the KNOWN matrix
//     (caps.go); an upstream token outside the matrix, or nothing
//     remembered, is honestly incomparable — visible as n/a, never
//     coerced into a fake ordering;
//   - caps vocabularies are compared only within the same format
//     version: comparing name sets across versions is meaningless (the
//     version verdict already tells that story), so caps drift is n/a
//     unless the versions are equal.
//
// Determinism: pure functions, injected inputs, no clock, no I/O.
package fleet

import (
	"sort"
	"strings"
)

// DriftVerdict is the version-comparison verdict.
type DriftVerdict string

const (
	// DriftSame means both sides report the same format version.
	DriftSame DriftVerdict = "same"
	// DriftOlder means the upstream report names an OLDER known version
	// than the registry remembers — the deployment lags the registry.
	DriftOlder DriftVerdict = "older"
	// DriftNewer means the upstream report names a NEWER known version
	// than the registry remembers — the registry lags the deployment.
	DriftNewer DriftVerdict = "newer"
	// DriftUpstreamEmpty means the upstream report names NO version —
	// the explicit upstream-empty verdict (its own fact, not a ranking).
	DriftUpstreamEmpty DriftVerdict = "upstream-empty"
	// DriftIncomparable means the comparison is meaningless — an
	// upstream token outside the known matrix, or nothing remembered to
	// compare against. Rendered as "n/a" («N/A где несравнимо»).
	DriftIncomparable DriftVerdict = "n/a"
)

// String renders the verdict; the read API serializes exactly this.
func (v DriftVerdict) String() string { return string(v) }

// RememberedVersion reports the format version the registry remembers
// for this installation. Nil-receiver safe (modelcatalog.go:374 form): a
// nil *StoredInstallation reports "" — "nothing remembered", consistent
// with no row installed.
func (s *StoredInstallation) RememberedVersion() string {
	if s == nil {
		return ""
	}
	return s.Caps.FormatVersion
}

// RememberedCaps reports the negotiated capability names the registry
// remembers. Nil-receiver safe: nil reports nil (no baseline).
func (s *StoredInstallation) RememberedCaps() []string {
	if s == nil {
		return nil
	}
	return s.Caps.Capabilities
}

// DriftReport is the visible difference between what the registry
// remembers and what the deployment reports. Zero-value semantics: an
// empty report means "nothing to say" (nothing remembered), not "no
// drift" — Comparable gates every field.
type DriftReport struct {
	// Comparable is false when the whole report is n/a: nothing is
	// remembered (unknown/absent installation) — every verdict below is
	// meaningless and must render as n/a.
	Comparable bool
	// Version is the version verdict (DriftSame/Older/Newer/
	// UpstreamEmpty/Incomparable). Remembered and Upstream carry the
	// raw tokens for operator visibility.
	Version    DriftVerdict
	Remembered string
	Upstream   string
	// CapsComparable is false unless both sides report the SAME format
	// version — vocabulary drift across versions is n/a by law.
	CapsComparable bool
	// CapsDrift is true when the negotiated name sets differ.
	CapsDrift bool
	// CapsAdded: names the upstream report negotiates that the registry
	// does not remember (sorted).
	CapsAdded []string
	// CapsRemoved: names the registry remembers that the upstream report
	// no longer negotiates (sorted).
	CapsRemoved []string
}

// compareCapsVersions orders two version tokens against an explicit
// known matrix (ascending, the caps.go matrix law). Pure: the matrix is
// a parameter so batteries can exercise ordering with synthetic
// matrices without touching the production vocabulary.
//
//	one empty, other not → DriftUpstreamEmpty (only when upstream side
//	    is the empty one; an empty remembered side is n/a — nothing to
//	    rank against)
//	both empty          → n/a (no version question exists)
//	equal tokens        → DriftSame
//	both in matrix      → DriftOlder / DriftNewer by matrix position
//	otherwise           → DriftIncomparable (unknown vocabulary is not
//	    coerced into an ordering)
func compareCapsVersions(remembered, upstream string, matrix []string) DriftVerdict {
	if upstream == "" {
		// «пустая версия = upstream-пустое»: an explicit verdict even
		// when nothing is remembered (the report itself is gated by
		// Comparable upstream).
		return DriftUpstreamEmpty
	}
	if remembered == "" {
		return DriftIncomparable
	}
	if remembered == upstream {
		return DriftSame
	}
	ri, rok := indexOfString(matrix, remembered)
	ui, uok := indexOfString(matrix, upstream)
	if !rok || !uok {
		return DriftIncomparable
	}
	if ui < ri {
		return DriftOlder
	}
	return DriftNewer
}

func indexOfString(haystack []string, needle string) (int, bool) {
	for i, s := range haystack {
		if s == needle {
			return i, true
		}
	}
	return 0, false
}

// AssessDrift compares the remembered installation against an
// upstream-reported negotiated document. Pure, total and nil-safe:
// remembered == nil yields the n/a report (Comparable false) — the
// honest answer for an installation the registry has no row for.
//
// The upstream document is taken as DATA, not re-validated: drift is a
// diagnostic seam (fail-open visibility); structural enforcement is the
// negotiation (caps.go) and persistence (caps_store.go) laws. Unknown
// upstream names are reported verbatim in CapsAdded — an operator
// looking for drift wants to SEE the oddity, not have it hidden by a
// validator.
func AssessDrift(remembered *StoredInstallation, upstream NegotiatedCaps) DriftReport {
	if remembered == nil {
		return DriftReport{
			Comparable: false,
			Version:    DriftIncomparable,
			Upstream:   upstream.FormatVersion,
		}
	}
	rep := DriftReport{
		Comparable: true,
		Version:    compareCapsVersions(remembered.RememberedVersion(), upstream.FormatVersion, capsMatrix),
		Remembered: remembered.RememberedVersion(),
		Upstream:   upstream.FormatVersion,
	}
	if rep.Version != DriftSame {
		// Vocabulary comparison across format versions is n/a by law.
		return rep
	}
	rep.CapsComparable = true
	rep.CapsAdded, rep.CapsRemoved = diffNameSets(remembered.RememberedCaps(), upstream.Capabilities)
	rep.CapsDrift = len(rep.CapsAdded) > 0 || len(rep.CapsRemoved) > 0
	return rep
}

// diffNameSets returns the sorted one-sided differences (added, removed)
// of upstream relative to remembered. Both inputs are treated as sets;
// duplicates (impossible in NegotiatedCaps by construction, tolerated
// here — diagnostic seam) collapse silently.
func diffNameSets(remembered, upstream []string) (added, removed []string) {
	rset := make(map[string]struct{}, len(remembered))
	uset := make(map[string]struct{}, len(upstream))
	for _, n := range remembered {
		rset[n] = struct{}{}
	}
	for _, n := range upstream {
		uset[n] = struct{}{}
	}
	for n := range uset {
		if _, ok := rset[n]; !ok {
			added = append(added, n)
		}
	}
	for n := range rset {
		if _, ok := uset[n]; !ok {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// Summary renders the one-line operator form the read API (W04-C03)
// surfaces: version verdict plus caps delta, or the honest n/a. Stable,
// deterministic, no secrets (identity-model §2 — only public
// coordinates and vocabularies ever appear).
func (r DriftReport) Summary() string {
	if !r.Comparable {
		return "n/a"
	}
	var b strings.Builder
	b.WriteString("version:")
	b.WriteString(string(r.Version))
	if r.CapsComparable {
		if r.CapsDrift {
			b.WriteString(" caps:+[")
			b.WriteString(strings.Join(r.CapsAdded, ","))
			b.WriteString("]-[")
			b.WriteString(strings.Join(r.CapsRemoved, ","))
			b.WriteString("]")
		} else {
			b.WriteString(" caps:same")
		}
	} else {
		b.WriteString(" caps:n/a")
	}
	return b.String()
}
