// Caps battery (E03-P01 card W03-C02, batch B): the FULL intersection
// matrix of caps negotiation — every offered × known subset combination
// over a fixed three-name universe (the 8 × 8 cross product), plus the
// named card arms (partial intersection, empty) and the determinism law
// over every matrix cell. All inputs are fixed literals and exhaustive
// enumerations: deterministic by construction.
//
// N/A branches (in-file justification, per the card's «Обязательные
// варианты» rule): arms requiring a LIVE installation — a persisted caps
// set surviving a registry round-trip, cross-org isolation of stored caps,
// negotiation fed by a real module connection — need the W03-C03 store
// and the W05 integration cards; this battery pins the pure negotiation
// semantics they consume. No network, no clock, no environment by design.
package fleet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// batteryUniverse is the fixed three-name universe of the full matrix:
// every subset of it (8) is used both as the core vocabulary and as the
// offered set, giving the exhaustive 64-cell intersection matrix.
var batteryUniverse = []string{"alpha.feature", "beta.feature", "gamma.feature"}

// batterySubsets returns every subset of the universe, with the empty
// subset first, as sorted slices (the negotiation input shape). Order of
// the enumeration itself is fixed (mask order): deterministic.
func batterySubsets() [][]string {
	out := make([][]string, 0, 8)
	for mask := 0; mask < 8; mask++ {
		var s []string
		for i, name := range batteryUniverse {
			if mask&(1<<i) != 0 {
				s = append(s, name)
			}
		}
		out = append(out, s)
	}
	return out
}

func TestCapsBattery_FullIntersectionMatrix(t *testing.T) {
	subsets := batterySubsets()

	for vi, vocab := range subsets {
		core, err := NewCoreCaps(CapsFormatVersion, vocab)
		require.NoError(t, err, "vocab cell %d (%v)", vi, vocab)

		for oi, offered := range subsets {
			got, err := NegotiateCaps(core, CapsEnvelope{
				FormatVersion: CapsFormatVersion,
				Capabilities:  offered,
			})
			require.NoError(t, err,
				"matrix cell vocab=%v offered=%v: negotiation never errors on well-formed input", vocab, offered)

			// The negotiation contract is exactly set arithmetic:
			// intersection(vocab, offered) and offered \ vocab.
			wantCaps, wantUnsup := batterySetArithmetic(vocab, offered)
			assert.Equal(t, wantCaps, got.Capabilities,
				"cell v%d×o%d: capabilities = vocab ∩ offered", vi, oi)
			assert.Equal(t, wantUnsup, got.Unsupported,
				"cell v%d×o%d: unsupported = offered \\ vocab", vi, oi)
			assert.Equal(t, CapsFormatVersion, got.FormatVersion, "cell v%d×o%d: exact echo", vi, oi)

			// The matrix exposes the two legal emptinesses (§4): empty
			// capabilities comes from upstream-empty (offered == ∅) or
			// empty intersection (offered ∩ vocab == ∅); Unsupported
			// disambiguates.
			if len(got.Capabilities) == 0 {
				assert.True(t, got.Empty())
				if len(offered) == 0 {
					assert.Empty(t, got.Unsupported, "upstream-empty: nothing can be unsupported")
				}
			}

			// Determinism over every cell: a repeat negotiation is
			// byte-equal (order-insensitivity included via the shuffled
			// input form below).
			repeat, err := NegotiateCaps(core, CapsEnvelope{
				FormatVersion: CapsFormatVersion,
				Capabilities:  batteryReverse(offered),
			})
			require.NoError(t, err)
			assert.Equal(t, got, repeat, "cell v%d×o%d: deterministic under input reordering", vi, oi)
		}
	}
}

// batterySetArithmetic computes the expected intersection and remainder
// by brute force — an oracle INDEPENDENT of the merge-walk under test
// (a battery must not re-implement the algorithm it checks).
func batterySetArithmetic(vocab, offered []string) (intersection, remainder []string) {
	for _, o := range offered {
		known := false
		for _, v := range vocab {
			if v == o {
				known = true
				break
			}
		}
		if known {
			intersection = append(intersection, o)
		} else {
			remainder = append(remainder, o)
		}
	}
	// Both sides of the comparison are sorted by construction here:
	// subsets() enumerates in universe order (already sorted).
	return intersection, remainder
}

// batteryReverse returns a reversed copy (input-order insensitivity probe).
func batteryReverse(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

func TestCapsBattery_PartialIntersection(t *testing.T) {
	core, err := NewCoreCaps(CapsFormatVersion, []string{
		"caps.inventory.upload",
		"caps.inventory.export",
		"caps.secevents.publish",
	})
	require.NoError(t, err)

	// The named partial arm: part of the declaration negotiates, the
	// rest stays visible — neither dropped nor refused.
	got, err := NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.secevents.publish", "vendor.extra.one", "vendor.extra.two"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"caps.secevents.publish"}, got.Capabilities)
	assert.Equal(t, []string{"vendor.extra.one", "vendor.extra.two"}, got.Unsupported)
	assert.False(t, got.Empty())

	// One-known-of-many and many-known-of-one: the boundary shapes of
	// partial intersection (single-element overlap on either side).
	got, err = NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.inventory.upload", "x.unknown", "y.unknown", "z.unknown"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"caps.inventory.upload"}, got.Capabilities)
	assert.Len(t, got.Unsupported, 3)

	got, err = NegotiateCaps(core, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"only.unknown"},
	})
	require.NoError(t, err)
	assert.Empty(t, got.Capabilities)
	assert.Equal(t, []string{"only.unknown"}, got.Unsupported)
	assert.True(t, got.Empty(), "empty intersection is observable state, not failure")
}

func TestCapsBattery_EmptyArms(t *testing.T) {
	core, err := NewCoreCaps(CapsFormatVersion, []string{"caps.health.heartbeat"})
	require.NoError(t, err)

	// «пустое» arm, upstream side: the module declares nothing.
	got, err := NegotiateCaps(core, CapsEnvelope{FormatVersion: CapsFormatVersion})
	require.NoError(t, err)
	assert.True(t, got.Empty())
	assert.Empty(t, got.Unsupported)

	// «пустое» arm, core side: an empty vocabulary is a legal descriptor
	// (a core that understands no caps still negotiates — everything
	// offered lands in Unsupported, visibly).
	emptyCore, err := NewCoreCaps(CapsFormatVersion, nil)
	require.NoError(t, err)
	got, err = NegotiateCaps(emptyCore, CapsEnvelope{
		FormatVersion: CapsFormatVersion,
		Capabilities:  []string{"caps.health.heartbeat"},
	})
	require.NoError(t, err)
	assert.True(t, got.Empty())
	assert.Equal(t, []string{"caps.health.heartbeat"}, got.Unsupported)

	// Both empty: the fully-degenerate cell of the matrix, still a
	// successful, explicit, empty negotiation.
	got, err = NegotiateCaps(emptyCore, CapsEnvelope{FormatVersion: CapsFormatVersion})
	require.NoError(t, err)
	assert.True(t, got.Empty())
	assert.Empty(t, got.Unsupported)
}

func TestCapsBattery_UnknownAndDowngradeArms(t *testing.T) {
	core, err := NewCoreCaps(CapsFormatVersion, []string{"caps.health.heartbeat"})
	require.NoError(t, err)

	// The refusal law over the battery's own vocabulary: every
	// well-formed non-matrix version — older, newer, adjacent, garbage —
	// refuses with the same sentinel and returns no half-result.
	// (Malformed TOKENS are the structural law's table in caps_test.go.)
	for _, v := range []string{"0", "2", "1.0", "v1", "one", "-1"} {
		got, err := NegotiateCaps(core, CapsEnvelope{FormatVersion: v, Capabilities: []string{"caps.health.heartbeat"}})
		require.ErrorIs(t, err, ErrUnknownCapsVersion, "battery version %q", v)
		assert.Equal(t, NegotiatedCaps{}, got)
	}

	// Downgrade is refused even when the declared set WOULD intersect
	// fully: the version refusal precedes any set semantics — a fully-
	// known set under an unknown vocabulary is still not negotiable
	// (fail-closed ordering law, the no-silent-downgrade guarantee).
	_, err = NegotiateCaps(core, CapsEnvelope{
		FormatVersion: "0",
		Capabilities:  []string{"caps.health.heartbeat"},
	})
	require.ErrorIs(t, err, ErrUnknownCapsVersion)
}

func TestCapsBattery_MatrixWellFormed(t *testing.T) {
	// The matrix invariants over the battery's own package state
	// (protocolMatrix discipline): newest first, const == head, unique.
	require.Equal(t, CapsFormatVersion, capsMatrix[0])
	seen := map[string]bool{}
	for _, v := range capsMatrix {
		require.False(t, seen[v], "duplicate matrix entry %q", v)
		seen[v] = true
		require.True(t, supportedCapsVersion(v), "every matrix entry is supported")
	}
	// The known-edges property the whole battery relies on: today the
	// matrix is exactly ["1"]; a bump that changes this fact must
	// update the batteries together with the matrix (one-point change).
	require.Equal(t, []string{CapsFormatVersion}, capsMatrix,
		"matrix bump detected: caps_battery expectations must be revisited")
}
