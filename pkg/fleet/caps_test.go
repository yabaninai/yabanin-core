// Caps core battery (E03-P01 card W03-C01, batch B): the four card checks
// — negotiated caps (exact echo + visible Unsupported), unknown version
// refused, downgrade attempt fail-closed (no fallback answer), empty
// declared set = upstream-empty not an error — plus the structural law of
// envelopes and core descriptors. All inputs are fixed literals:
// deterministic by construction (no clock, no randomness, no environment).
//
// The pkg/license import below is TEST-ONLY (the package's R-1 boundary
// law, identity.go header): it pins the third-vocabulary layering of
// CapsFormatVersion on the E01-P05 handshake contract without the product
// code ever importing pkg/license.
package fleet

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	license "github.com/reireirei/yabanin/pkg/license"
)

// testCoreCapsV1 is the battery's standing core descriptor: the vocabulary
// names are opaque test tokens exercising the exact-string membership law.
func testCoreCapsV1(t *testing.T) CoreCaps {
	t.Helper()
	core, err := NewCoreCaps(CapsFormatVersion, []string{
		"caps.inventory.upload",
		"caps.inventory.export",
		"caps.secevents.publish",
		"caps.health.heartbeat",
	})
	require.NoError(t, err)
	return core
}

func TestCapsCore_Negotiated(t *testing.T) {
	core := testCoreCapsV1(t)

	// Full intersection: every declared name is known; the negotiated
	// version is the exact echo; output is sorted regardless of input
	// order (determinism law).
	got, err := NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.health.heartbeat", "caps.inventory.upload"},
	})
	require.NoError(t, err)
	assert.Equal(t, CapsFormatVersion, got.FormatVersion, "negotiated version must be the exact echo")
	assert.Equal(t, []string{"caps.health.heartbeat", "caps.inventory.upload"}, got.Capabilities)
	assert.Empty(t, got.Unsupported, "fully-known set has no unsupported remainder")
	assert.False(t, got.Empty())

	// Partial intersection: known names negotiate, unknown names stay
	// visible in Unsupported — never silently dropped (caps-matrix.md §3).
	got, err = NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.secevents.publish", "vendor.future.feature", "vendor.other.feature"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"caps.secevents.publish"}, got.Capabilities)
	assert.Equal(t, []string{"vendor.future.feature", "vendor.other.feature"}, got.Unsupported, "unknown names must surface, sorted")

	// Determinism: equal inputs yield byte-equal results on repeat.
	again, err := NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"vendor.other.feature", "caps.secevents.publish", "vendor.future.feature"},
	})
	require.NoError(t, err)
	assert.Equal(t, got, again, "negotiation must be order-insensitive and repeatable")
}

func TestCapsCore_UnknownVersionRefused(t *testing.T) {
	core := testCoreCapsV1(t)

	// Well-formed but unknown versions: the MATRIX policy refuses them
	// (unknown, older, newer, never-shipped shapes).
	for _, v := range []string{"2", "0", "1.5", "garbage"} {
		_, err := NegotiateCaps(core, CapsEnvelope{FormatVersion: v, Capabilities: []string{"caps.health.heartbeat"}})
		require.ErrorIs(t, err, ErrUnknownCapsVersion, "version %q", v)
	}

	// Malformed version tokens: the STRUCTURAL law refuses them before
	// any policy (the version-token discipline, handshake.go:134-154).
	for _, v := range []string{"", " 1", "1\x00", strings.Repeat("1", capsVersionMaxBytes+1)} {
		_, err := NegotiateCaps(core, CapsEnvelope{FormatVersion: v, Capabilities: []string{"caps.health.heartbeat"}})
		require.ErrorIs(t, err, ErrInvalidCaps, "version token %q", v)
	}
}

func TestCapsCore_DowngradeFailsClosed(t *testing.T) {
	core := testCoreCapsV1(t)

	// The «отказ silent downgrade» law: a module declaring a version the
	// core does not implement gets a REFUSAL, never the core's own
	// version as a fallback answer. Contrast the mcpserver precedent
	// (version.go:57 echo-or-latest): fleet caps must not reinterpret a
	// declared set under a vocabulary it was not written against.
	got, err := NegotiateCaps(core, CapsEnvelope{FormatVersion: "2", Capabilities: []string{"caps.health.heartbeat"}})
	require.ErrorIs(t, err, ErrUnknownCapsVersion)
	assert.Equal(t, NegotiatedCaps{}, got, "a refused negotiation returns no result — not a downgraded one")

	// The same law binds the core side: a descriptor claiming a version
	// outside the matrix cannot be constructed at all. (The offered-vs-
	// core version split inside NegotiateCaps is unreachable while the
	// matrix holds one version — both sides are matrix members, hence
	// equal; it exists for the future multi-version matrix, where it
	// keeps cross-version guessing refused.)
	_, err = NewCoreCaps("2", []string{"caps.health.heartbeat"})
	require.ErrorIs(t, err, ErrUnknownCapsVersion)
}

func TestCapsCore_EmptyUpstream(t *testing.T) {
	core := testCoreCapsV1(t)

	// «пустой набор caps = upstream-пустое, не ошибка»: an empty declared
	// set is a VALID declaration — the module says it has no capabilities.
	got, err := NegotiateCaps(core, CapsEnvelope{FormatVersion: CapsFormatVersion, Capabilities: nil})
	require.NoError(t, err)
	assert.Empty(t, got.Capabilities)
	assert.Empty(t, got.Unsupported)
	assert.True(t, got.Empty(), "upstream-empty negotiates to an explicit empty set")
	assert.Equal(t, CapsFormatVersion, got.FormatVersion, "the version is still negotiated")

	// The empty-set law is order-of-checks independent: an empty set with
	// an unknown version is still refused (version policy is not skipped
	// for trivial sets — fail-closed default).
	_, err = NegotiateCaps(core, CapsEnvelope{FormatVersion: "9", Capabilities: nil})
	require.ErrorIs(t, err, ErrUnknownCapsVersion)

	// Empty intersection (all declared names unknown) is observable
	// state, not failure: empty capabilities + visible Unsupported.
	got, err = NegotiateCaps(core, CapsEnvelope{FormatVersion: CapsFormatVersion, Capabilities: []string{"vendor.only.feature"}})
	require.NoError(t, err)
	assert.True(t, got.Empty())
	assert.Equal(t, []string{"vendor.only.feature"}, got.Unsupported, "Unsupported disambiguates empty-intersection from upstream-empty")
}

func TestCapsCore_StructuralLaw(t *testing.T) {
	core := testCoreCapsV1(t)

	// Malformed names: the opaque-token law (non-empty, no padding, no
	// control characters, bounded, valid UTF-8).
	for _, bad := range []string{
		"",
		" caps.health.heartbeat",
		"caps.health.heartbeat\n",
		"caps\u007fhealth",
		"caps\x00health",
		strings.Repeat("n", capsNameMaxBytes+1),
		"caps\xff\xfe",
	} {
		_, err := NegotiateCaps(core, CapsEnvelope{
			FormatVersion: CapsFormatVersion,
			Capabilities:  []string{bad},
		})
		require.ErrorIs(t, err, ErrInvalidCaps, "name %q", bad)
	}

	// Duplicates are a malformed declaration, not silently folded.
	_, err := NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.health.heartbeat", "caps.health.heartbeat"},
	})
	require.ErrorIs(t, err, ErrInvalidCaps)

	// Oversized sets are bounded (hostile-envelope containment); the
	// generated names are distinct, so the refusal is the SET bound, not
	// the duplicate law.
	many := make([]string, 0, capsMaxNames+1)
	for i := 0; i <= capsMaxNames; i++ {
		many = append(many, "vendor.cap."+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26)))
	}
	_, err = NegotiateCaps(core, CapsEnvelope{FormatVersion: CapsFormatVersion, Capabilities: many})
	require.ErrorIs(t, err, ErrInvalidCaps)

	// The same structural law binds the core descriptor vocabulary.
	_, err = NewCoreCaps(CapsFormatVersion, []string{"good.name", " bad.name"})
	require.ErrorIs(t, err, ErrInvalidCaps)
	_, err = NewCoreCaps(CapsFormatVersion, []string{"dup", "dup"})
	require.ErrorIs(t, err, ErrInvalidCaps)
	_, err = NewCoreCaps("", nil)
	require.ErrorIs(t, err, ErrInvalidCaps)

	// A valid descriptor's vocabulary is normalized to sorted form.
	cd, err := NewCoreCaps(CapsFormatVersion, []string{"b.name", "a.name"})
	require.NoError(t, err)
	assert.Equal(t, []string{"a.name", "b.name"}, cd.Vocabulary)
}

func TestCapsCore_ThirdVocabularyLayering(t *testing.T) {
	// The handshake layering law (caps-matrix.md §1): CapsFormatVersion
	// is a THIRD vocabulary, beside the E01-P05 handshake's own two —
	// it evolves on its own schedule, and a caps bump must never be
	// confused with a handshake or entitlement-document bump. Pinned
	// here against the license contract constants (test-only import).
	assert.Equal(t, "1", license.HandshakeFormatVersion)
	assert.Equal(t, "2", license.ModuleEntitlementVersion)
	assert.Equal(t, "1", CapsFormatVersion, "caps v1 today; independent of both license constants")

	// The matrix shape law (protocolMatrix discipline, version.go:32):
	// newest first, no duplicates, and the const names the newest edge.
	require.NotEmpty(t, capsMatrix)
	require.Equal(t, CapsFormatVersion, capsMatrix[0], "the const is the matrix head (newest)")
	for i := 1; i < len(capsMatrix); i++ {
		require.NotEqual(t, capsMatrix[i-1], capsMatrix[i], "duplicate matrix entry")
	}
	assert.True(t, supportedCapsVersion(CapsFormatVersion))
}
