// Caps core (E03-P01, batch B, card W03-C01): versioned installation
// capability negotiation. The model document is
// artifacts/enterprise-beta/E03-P01/caps-matrix.md; this file is the
// contract.
//
// Laws (caps-matrix.md §2–§4, carried from the dispatch card):
//   - versioned caps: the declared set rides behind a completed E01-P05
//     handshake, with its OWN format version (a third vocabulary beside
//     HandshakeFormatVersion and ModuleEntitlementVersion —
//     pkg/license/handshake.go:41-46 documents that independence law);
//   - отказ silent downgrade: an offered format version outside the
//     supported matrix is REFUSED, never answered with a fallback — the
//     mcpserver echo-or-latest precedent (version.go:57) is deliberately
//     diverged from here, because a fallback would silently reinterpret a
//     declared set under a vocabulary it was not written against;
//   - the negotiated version is always one the core implements (matrix
//     membership), and always exactly what the module offered;
//   - empty declared set = upstream-empty («upstream-пустое»), a VALID
//     declaration — not an error; emptiness is observable, never
//     synthesized into a refusal;
//   - unknown NAMES are never silently dropped: they surface visibly in
//     NegotiatedCaps.Unsupported (the W04-C02 drift seam).
//
// Boundary posture (package law, identity.go): pure data + pure functions,
// no clock/randomness/environment/I/O, no pkg/license import — the
// handshake contract is consumed as documented plain-string vocabulary,
// keeping the R-1 license boundary (pkg/license stays test-only for fleet).
package fleet

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CapsFormatVersion is the caps vocabulary format version this core
// implements — the newest (and today the only) entry of capsMatrix. It
// versions the capability-name vocabulary and the negotiation semantics;
// a vocabulary change bumps the matrix as a one-point change
// (caps-matrix.md §5).
const CapsFormatVersion = "1"

// capsMatrix lists the supported caps format versions, newest first — the
// single source of truth for every caps-version decision (protocolMatrix
// shape, version.go:32). Negotiation echoes a matrix member and refuses
// everything else; the matrix only grows.
var capsMatrix = []string{CapsFormatVersion}

// capsToken limits (fail-closed shape checks, the handshake version-token
// discipline: a version is a short opaque token, never prose).
const (
	// capsVersionMaxBytes bounds the format-version token.
	capsVersionMaxBytes = 64
	// capsNameMaxBytes bounds one capability name (the coordinate-scale
	// bound of identity.go: generous for vendor vocabulary, small enough
	// to keep stored sets sane).
	capsNameMaxBytes = 128
)

// Caps errors. Sentinels so batteries and callers can errors.Is them;
// wrapped context is added at each site (identity.go:63 discipline).
var (
	// ErrUnknownCapsVersion: the offered caps format version is outside
	// the supported matrix — refused fail-closed (the «отказ silent
	// downgrade» law: unknown, older, newer and garbage are all refused;
	// never a fallback answer).
	ErrUnknownCapsVersion = errors.New("fleet: unknown caps format version")
	// ErrInvalidCaps: the caps declaration (or the core-side vocabulary
	// descriptor) fails STRUCTURAL validation — malformed version token,
	// malformed name, duplicates, oversized set.
	ErrInvalidCaps = errors.New("fleet: invalid caps declaration")
)

// capsMaxNames bounds one declared set (and the core vocabulary): large
// enough for any real feature surface, bounded so a hostile envelope
// cannot make negotiation or storage unbounded.
const capsMaxNames = 256

// validateCapsVersionToken applies the version-token shape law (the
// handshake discipline, handshake.go:134-154): non-empty, bounded, no
// leading/trailing whitespace, no control characters. It performs NO
// matrix policy — an unknown-but-well-formed token is refused by
// NegotiateCaps with ErrUnknownCapsVersion, not here.
func validateCapsVersionToken(field, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidCaps, field)
	}
	if len(v) > capsVersionMaxBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidCaps, field, capsVersionMaxBytes)
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("%w: %s must not have leading/trailing whitespace", ErrInvalidCaps, field)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidCaps, field)
		}
	}
	return nil
}

// validateCapsName applies the capability-name structural law
// (caps-matrix.md §3): an opaque vendor token — non-empty, valid UTF-8, no
// padding, no control characters, at most capsNameMaxBytes bytes. Exact
// strings; membership is all a consumer may rely on.
func validateCapsName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: capability name is empty", ErrInvalidCaps)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: capability name %q is not valid UTF-8", ErrInvalidCaps, name)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("%w: capability name %q must not have leading/trailing whitespace", ErrInvalidCaps, name)
	}
	if len(name) > capsNameMaxBytes {
		return fmt.Errorf("%w: capability name exceeds %d bytes", ErrInvalidCaps, capsNameMaxBytes)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: capability name %q must not contain control characters", ErrInvalidCaps, name)
		}
	}
	return nil
}

// capsNameSet validates a name slice and returns it sorted, rejecting
// duplicates and oversized sets (fail-closed: duplicates are a malformed
// declaration, not silently folded; the sorted form makes every later
// intersection/difference deterministic — package determinism law).
func capsNameSet(kind string, names []string) ([]string, error) {
	if len(names) > capsMaxNames {
		return nil, fmt.Errorf("%w: %s exceeds %d names", ErrInvalidCaps, kind, capsMaxNames)
	}
	for _, n := range names {
		if err := validateCapsName(n); err != nil {
			return nil, err
		}
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, fmt.Errorf("%w: %s contains duplicate name %q", ErrInvalidCaps, kind, sorted[i])
		}
	}
	return sorted, nil
}

// supportedCapsVersion reports whether v is one of the supported caps
// format versions (matrix membership; version.go:44 shape).
func supportedCapsVersion(v string) bool {
	for _, m := range capsMatrix {
		if v == m {
			return true
		}
	}
	return false
}

// CoreCaps is the core-side caps descriptor for one format version: the
// vocabulary of capability NAMES the core understands at that version.
// Built by NewCoreCaps, which enforces the descriptor's own laws (matrix
// membership + name structural law) so a malformed core side fails at
// construction, never mid-negotiation.
type CoreCaps struct {
	// FormatVersion is the vocabulary version this descriptor speaks
	// (must be a capsMatrix member).
	FormatVersion string
	// Vocabulary is the sorted, duplicate-free set of known capability
	// names at that version.
	Vocabulary []string
}

// NewCoreCaps builds a CoreCaps after validating the version token and
// every vocabulary name (fail-closed: no zero-value descriptor with an
// invalid vocabulary; an unknown version is refused here exactly as it is
// in negotiation — the core may not claim a vocabulary it does not
// implement).
func NewCoreCaps(formatVersion string, vocabulary []string) (CoreCaps, error) {
	if err := validateCapsVersionToken("core caps format_version", formatVersion); err != nil {
		return CoreCaps{}, err
	}
	if !supportedCapsVersion(formatVersion) {
		return CoreCaps{}, fmt.Errorf("%w: core descriptor %q is outside the supported matrix", ErrUnknownCapsVersion, formatVersion)
	}
	sorted, err := capsNameSet("core vocabulary", vocabulary)
	if err != nil {
		return CoreCaps{}, err
	}
	return CoreCaps{FormatVersion: formatVersion, Vocabulary: sorted}, nil
}

// CapsEnvelope is what one installation declares: the vocabulary version
// its set is described in, and the declared capability names. An EMPTY
// set is a valid declaration («upstream-пустое»): the module says it has
// no capabilities. The envelope carries no secrets (caps-matrix.md §1).
type CapsEnvelope struct {
	// FormatVersion is the caps vocabulary version the declaration is
	// written against (CapsFormatVersion vocabulary).
	FormatVersion string `json:"format_version"`
	// Capabilities is the declared set; order is irrelevant (negotiation
	// sorts), duplicates are refused.
	Capabilities []string `json:"capabilities"`
}

// NegotiatedCaps is the negotiation outcome. Capabilities and Unsupported
// are sorted and duplicate-free by construction: equal inputs always yield
// byte-equal results (determinism law, identity.go:12-14).
type NegotiatedCaps struct {
	// FormatVersion is the negotiated vocabulary version: always a
	// capsMatrix member and always EXACTLY the offered version — the
	// core never answers a version the module did not offer (no silent
	// downgrade, caps-matrix.md §2).
	FormatVersion string `json:"format_version"`
	// Capabilities is the intersection of the declared set with the core
	// vocabulary at the negotiated version — what the installation and
	// the core agree on.
	Capabilities []string `json:"capabilities"`
	// Unsupported lists declared names the core does not know at the
	// negotiated version: visible, never silently dropped (the W04-C02
	// drift seam). Empty when every declared name is known.
	Unsupported []string `json:"unsupported"`
}

// Empty reports whether the negotiated capability set is empty. It covers
// BOTH legal emptinesses (caps-matrix.md §4): upstream-empty (nothing
// declared) and empty intersection (everything declared is unknown —
// Unsupported is non-empty then); Unsupported disambiguates the two.
func (n NegotiatedCaps) Empty() bool { return len(n.Capabilities) == 0 }

// NegotiateCaps resolves the caps negotiation (caps-matrix.md §2–§4):
//
//   - structural validation first: the envelope's version token and names
//     must be well-formed (ErrInvalidCaps);
//   - version policy second: an offered version outside the matrix is
//     refused fail-closed (ErrUnknownCapsVersion) — unknown, older, newer
//     and garbage all refuse; there is NO fallback answer;
//   - on a supported version (exact echo), the result is the sorted
//     intersection with the core vocabulary plus the visibly-unsupported
//     remainder; empty results are legal outcomes, not errors.
//
// core must come from NewCoreCaps (its laws hold by construction); the
// offered version must equal the core descriptor's version — the core
// negotiates with the vocabulary it speaks.
func NegotiateCaps(core CoreCaps, offered CapsEnvelope) (NegotiatedCaps, error) {
	if err := validateCapsVersionToken("caps format_version", offered.FormatVersion); err != nil {
		return NegotiatedCaps{}, err
	}
	if !supportedCapsVersion(offered.FormatVersion) {
		return NegotiatedCaps{}, fmt.Errorf("%w: %q is outside the supported matrix (no fallback)", ErrUnknownCapsVersion, offered.FormatVersion)
	}
	if offered.FormatVersion != core.FormatVersion {
		return NegotiatedCaps{}, fmt.Errorf("%w: offered %q but the core speaks %q (no fallback)", ErrUnknownCapsVersion, offered.FormatVersion, core.FormatVersion)
	}
	declared, err := capsNameSet("declared capabilities", offered.Capabilities)
	if err != nil {
		return NegotiatedCaps{}, err
	}

	// Merge-walk of two sorted sets: intersection + offered-only remainder.
	n := NegotiatedCaps{FormatVersion: core.FormatVersion}
	i, j := 0, 0
	for i < len(declared) && j < len(core.Vocabulary) {
		switch {
		case declared[i] == core.Vocabulary[j]:
			n.Capabilities = append(n.Capabilities, declared[i])
			i++
			j++
		case declared[i] < core.Vocabulary[j]:
			n.Unsupported = append(n.Unsupported, declared[i])
			i++
		default:
			j++
		}
	}
	n.Unsupported = append(n.Unsupported, declared[i:]...)
	return n, nil
}
