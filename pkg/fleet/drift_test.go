// Drift battery (E03-P01 card W04-C02, batch B): the card's arms —
// versions equal; version drift VISIBLE; caps drift VISIBLE; empty
// upstream version = the explicit upstream-empty verdict; n/a where
// incomparable — plus the nil-safe accessor law (modelcatalog.go:374
// form) and the end-to-end matrix-bump arm.
package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func drCaps(t *testing.T, version string, names ...string) NegotiatedCaps {
	t.Helper()
	return NegotiatedCaps{FormatVersion: version, Capabilities: names}
}

func drStored(version string, names ...string) *StoredInstallation {
	return &StoredInstallation{
		Identity: Identity{OrgID: "drorg", DeploymentID: "deploy-dr"},
		State:    StateActive,
		Caps:     NegotiatedCaps{FormatVersion: version, Capabilities: names},
	}
}

func TestDrift_NilSafeAccessors(t *testing.T) {
	// The modelcatalog.go:374 form, verbatim discipline: a nil receiver
	// reports the zero value — "nothing remembered" — never a panic and
	// never a fabricated baseline.
	var absent *StoredInstallation
	assert.Empty(t, absent.RememberedVersion())
	assert.Nil(t, absent.RememberedCaps())

	// And the whole assessment on an absent row is the honest n/a.
	rep := AssessDrift(absent, drCaps(t, CapsFormatVersion, "caps.health.heartbeat"))
	assert.False(t, rep.Comparable)
	assert.Equal(t, DriftIncomparable, rep.Version)
	assert.Equal(t, CapsFormatVersion, rep.Upstream, "the upstream token stays visible even in n/a")
	assert.Equal(t, "n/a", rep.Summary())
}

func TestDrift_VersionsEqual(t *testing.T) {
	remembered := drStored(CapsFormatVersion, "caps.health.heartbeat", "caps.inventory.upload")
	rep := AssessDrift(remembered, drCaps(t, CapsFormatVersion, "caps.health.heartbeat", "caps.inventory.upload"))
	require.True(t, rep.Comparable)
	assert.Equal(t, DriftSame, rep.Version)
	assert.True(t, rep.CapsComparable)
	assert.False(t, rep.CapsDrift)
	assert.Empty(t, rep.CapsAdded)
	assert.Empty(t, rep.CapsRemoved)
	assert.Equal(t, "version:same caps:same", rep.Summary())

	// Equal but reordered name sets are the same set: drift is
	// order-blind by law (sorted-by-construction comparison).
	rep = AssessDrift(remembered, drCaps(t, CapsFormatVersion, "caps.inventory.upload", "caps.health.heartbeat"))
	assert.False(t, rep.CapsDrift, "reordering is not drift")
}

func TestDrift_VersionVerdictsAgainstMatrix(t *testing.T) {
	// Ordering battery against a synthetic matrix (the production matrix
	// is single-entry today; the ordering law must still be pinned —
	// compareCapsVersions takes the matrix explicitly for exactly this).
	synth := []string{"1", "2", "3"}

	assert.Equal(t, DriftSame, compareCapsVersions("2", "2", synth))
	assert.Equal(t, DriftOlder, compareCapsVersions("2", "1", synth), "upstream lags the registry")
	assert.Equal(t, DriftNewer, compareCapsVersions("1", "3", synth), "registry lags the upstream")
	// Unknown vocabulary is never coerced into an ordering.
	assert.Equal(t, DriftIncomparable, compareCapsVersions("2", "9", synth))
	assert.Equal(t, DriftIncomparable, compareCapsVersions("9", "2", synth))
	assert.Equal(t, DriftIncomparable, compareCapsVersions("9", "8", synth))
	// Empty sides: upstream-empty is its own verdict; an empty
	// remembered side cannot rank anything.
	assert.Equal(t, DriftUpstreamEmpty, compareCapsVersions("2", "", synth))
	assert.Equal(t, DriftUpstreamEmpty, compareCapsVersions("", "", synth))
	assert.Equal(t, DriftIncomparable, compareCapsVersions("", "2", synth))

	// Against the REAL matrix: any different token is n/a today (the
	// registry knows exactly one version), same is same.
	assert.Equal(t, DriftSame, compareCapsVersions(CapsFormatVersion, CapsFormatVersion, capsMatrix))
	assert.Equal(t, DriftIncomparable, compareCapsVersions(CapsFormatVersion, "2", capsMatrix))
}

func TestDrift_EndToEndMatrixBump(t *testing.T) {
	// When the matrix grows, the same inputs flip from n/a to a visible
	// verdict with NO drift-seam change — the one-point-change law.
	// Save/restore the production matrix (serial test; the battery pins
	// the seam, not the vocabulary).
	orig := capsMatrix
	defer func() { capsMatrix = orig }()
	capsMatrix = []string{"1", "2"}

	remembered := drStored("1", "caps.health.heartbeat")
	rep := AssessDrift(remembered, drCaps(t, "2", "caps.health.heartbeat"))
	require.True(t, rep.Comparable)
	assert.Equal(t, DriftNewer, rep.Version, "registry lags the deployment")
	assert.False(t, rep.CapsComparable, "vocabulary comparison across versions stays n/a")
	assert.Contains(t, rep.Summary(), "version:newer")
}

func TestDrift_CapsDriftVisible(t *testing.T) {
	remembered := drStored(CapsFormatVersion, "caps.health.heartbeat", "caps.inventory.upload")
	rep := AssessDrift(remembered, drCaps(t, CapsFormatVersion, "caps.inventory.upload", "vendor.extra.feature"))
	require.True(t, rep.Comparable)
	require.True(t, rep.CapsComparable)
	assert.True(t, rep.CapsDrift)
	// Sorted, one-sided, direction named: operators see WHAT appeared
	// and WHAT vanished — including names outside our vocabulary,
	// verbatim (diagnostic seam: visible, not validated away).
	assert.Equal(t, []string{"vendor.extra.feature"}, rep.CapsAdded)
	assert.Equal(t, []string{"caps.health.heartbeat"}, rep.CapsRemoved)
	assert.Equal(t, "version:same caps:+[vendor.extra.feature]-[caps.health.heartbeat]", rep.Summary())

	// Pure addition / pure removal arms.
	rep = AssessDrift(remembered, drCaps(t, CapsFormatVersion, "caps.health.heartbeat", "caps.inventory.upload", "caps.x"))
	assert.Equal(t, []string{"caps.x"}, rep.CapsAdded)
	assert.Empty(t, rep.CapsRemoved)
	rep = AssessDrift(remembered, drCaps(t, CapsFormatVersion, "caps.health.heartbeat"))
	assert.Empty(t, rep.CapsAdded)
	assert.Equal(t, []string{"caps.inventory.upload"}, rep.CapsRemoved)

	// Total disappearance is visible too (upstream negotiates nothing).
	rep = AssessDrift(remembered, drCaps(t, CapsFormatVersion))
	assert.True(t, rep.CapsDrift)
	assert.Len(t, rep.CapsRemoved, 2)

	// Duplicates in the upstream report (impossible by negotiation
	// construction, tolerated by the diagnostic) collapse, not explode:
	// the set arithmetic still holds — heartbeat matches, upload stays
	// removed, no phantom duplicate entries.
	rep = AssessDrift(remembered, drCaps(t, CapsFormatVersion, "caps.health.heartbeat", "caps.health.heartbeat"))
	assert.True(t, rep.CapsDrift)
	assert.Empty(t, rep.CapsAdded)
	assert.Equal(t, []string{"caps.inventory.upload"}, rep.CapsRemoved)
}

func TestDrift_UpstreamEmptyVersion(t *testing.T) {
	// «пустая версия = upstream-пустое»: the explicit verdict, and the
	// caps comparison is n/a — a document without a version cannot
	// claim a vocabulary.
	remembered := drStored(CapsFormatVersion, "caps.health.heartbeat")
	rep := AssessDrift(remembered, drCaps(t, ""))
	require.True(t, rep.Comparable)
	assert.Equal(t, DriftUpstreamEmpty, rep.Version)
	assert.False(t, rep.CapsComparable)
	assert.False(t, rep.CapsDrift)
	assert.Equal(t, "version:upstream-empty caps:n/a", rep.Summary())
}

func TestDrift_NAWhereIncomparable(t *testing.T) {
	// Upstream names a version outside the known matrix: honest n/a on
	// both version and caps; the tokens stay visible for the operator.
	remembered := drStored(CapsFormatVersion, "caps.health.heartbeat")
	rep := AssessDrift(remembered, drCaps(t, "2", "caps.health.heartbeat"))
	require.True(t, rep.Comparable)
	assert.Equal(t, DriftIncomparable, rep.Version)
	assert.False(t, rep.CapsComparable)
	assert.Equal(t, "version:n/a caps:n/a", rep.Summary())
	assert.Equal(t, CapsFormatVersion, rep.Remembered)
	assert.Equal(t, "2", rep.Upstream)
}

func TestDrift_ReportCarriesNoPunishment(t *testing.T) {
	// The seam is observability: the harshest drift report coexists
	// with issuance authorization. Staleness and drift inform; only
	// revocation refuses (AuthorizeSecretIssuance law, revoke.go).
	reg := NewRegistry()
	pub, priv, base := drKeys(t)
	tok, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID: "drorg", DeploymentID: "deploy-dr", Nonce: "dr-enroll-1",
	}, base)
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(tok, pub, "drorg", base, DefaultEnrollmentWindow)
	require.NoError(t, err)

	remembered := drStored(CapsFormatVersion, "caps.health.heartbeat")
	rep := AssessDrift(remembered, drCaps(t, CapsFormatVersion))
	require.True(t, rep.CapsDrift)
	require.NoError(t, reg.AuthorizeSecretIssuance("deploy-dr"),
		"drift must never become an issuance refusal")
}

// drKeys: deterministic-in-time helper for the one registry-backed arm
// (test-side keygen only; the package determinism law governs non-test
// code).
func drKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv, time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
}
