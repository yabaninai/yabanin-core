package license

// N04-P06 negative-scenario regression: the retired per-seat license model
// (owner answers I16–I20, cancelled by I22) must stay inert. Core has no
// account-count limit — the 101st and every later account are available
// without a license — so seat metadata on a legacy activation token is not
// a billing or enforcement unit, and no part of the verification path may
// resurrect the cancelled seat cap.

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSeatsMetadataIsInert_NoAccountLimit pins that tokens differing only in
// their seats value produce byte-identical activation semantics, including
// the extremes (0, negative, 10^9): activation never consults account
// counts, so nothing can derive a seat cap from the metadata.
func TestSeatsMetadataIsInert_NoAccountLimit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()

	expires := time.Now().Add(30 * 24 * time.Hour)
	issued := time.Now()

	stateFor := func(seats int) State {
		t.Helper()
		token := makeToken(t, priv, map[string]interface{}{
			"org_id":     "acme",
			"seats":      seats,
			"expires_at": expires.Format(time.RFC3339),
			"issued_at":  issued.Format(time.RFC3339),
		})
		claims, err := Verify(token)
		require.NoError(t, err, "verify seats=%d", seats)
		require.Equal(t, seats, claims.Seats, "seats must be copied through verbatim")
		return StateFromClaims(claims)
	}

	// Extremes around the retired 100-seat model: 0, negative, the legacy
	// cap region and 10^9 — every variant activates identically.
	extremes := []int{0, -7, 1, 100, 101, 1000000, 1000000000}
	baseline := stateFor(1)
	if !baseline.Active || baseline.Expired || baseline.HardExpired {
		t.Fatalf("unexpected activation state: %+v", baseline)
	}
	for _, seats := range extremes {
		state := stateFor(seats)
		// Seats is copied through verbatim (documented inert metadata); every
		// other activation field must be identical across all variants.
		state.Seats, baseline.Seats = 0, 0
		assert.True(t, reflect.DeepEqual(baseline, state),
			"seat metadata changed activation semantics: seats=%d → %+v, seats=1 → %+v", seats, state, baseline)
	}
}

// TestLicenseStateNeverHalfActivated pins the T08 interruption property:
// activation is a pure derivation with no persistent half-state. Every State
// lands in exactly one phase (active / expired-within-grace / hard-expired —
// never contradictory), and a corrupted or interrupted token leaves the
// previously verified state untouched (fail closed, nothing half-activated).
func TestLicenseStateNeverHalfActivated(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := VendorPublicKey
	VendorPublicKey = pub
	defer func() { VendorPublicKey = old }()

	now := time.Now()
	phases := []struct {
		name        string
		expiresAt   time.Time
		active      bool
		expired     bool
		hardExpired bool
		verifyOK    bool
	}{
		{"before expiry", now.Add(time.Hour), true, false, false, true},
		{"inside grace", now.Add(-time.Hour), true, true, false, true},
		{"past grace", now.Add(-8 * 24 * time.Hour), false, false, true, false},
	}
	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			token := makeToken(t, priv, map[string]interface{}{
				"org_id":     "acme",
				"expires_at": phase.expiresAt.Format(time.RFC3339),
				"issued_at":  now.Add(-24 * time.Hour).Format(time.RFC3339),
			})
			claims, err := Verify(token)
			if phase.verifyOK {
				require.NoError(t, err)
			} else {
				// Past-grace tokens fail closed at the entry point: an
				// interrupted/expired activation can never yield claims at all.
				require.Error(t, err)
			}
			state := StateFromClaims(claims)
			require.Equal(t, phase.active, state.Active, "Active phase")
			require.Equal(t, phase.expired, state.Expired, "Expired phase")
			require.Equal(t, phase.hardExpired, state.HardExpired, "HardExpired phase")
			// Coherence invariants: exactly one phase, never a half-activated
			// mixture (e.g. Active with HardExpired, or Expired without Active).
			require.False(t, state.HardExpired && (state.Active || state.Expired))
			require.False(t, state.Expired && !state.Active)
			// Purity: re-deriving from the same claims is byte-identical —
			// there is no mutable activation state to interrupt.
			require.True(t, reflect.DeepEqual(state, StateFromClaims(claims)))
		})
	}

	t.Run("interrupted token leaves state unchanged", func(t *testing.T) {
		good := makeToken(t, priv, map[string]interface{}{
			"org_id":     "acme",
			"expires_at": now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			"issued_at":  now.Format(time.RFC3339),
		})
		claims, err := Verify(good)
		require.NoError(t, err)
		before := StateFromClaims(claims)

		// An activation cut off mid-delivery: half the token is unusable.
		for _, interrupted := range []string{good[:len(good)/2], good + "truncated", "", "not-a-token"} {
			if interrupted == "" {
				continue
			}
			_, err := Verify(interrupted)
			require.Error(t, err, "interrupted token %q must not activate", interrupted)
		}
		// The interrupted attempts wrote nothing: the good token still
		// derives exactly the same state (no half-activated union state).
		claims, err = Verify(good)
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(before, StateFromClaims(claims)))
	})
}

// TestLicenseActivationSchemaUnreachable pins the inert-vocabulary probe:
// the dead `license_activation` schema (baseline migration 0001, including
// its seats column) has zero Go references. Nothing can read or revive it
// without touching this test first. SQL migrations are the only legitimate
// carriers of the name.
func TestLicenseActivationSchemaUnreachable(t *testing.T) {
	root := repoRoot(t)
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			switch name {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		// The path is synthesized by WalkDir from the repo root this test
		// resolved itself — no external input can enter it, and the file is
		// only read (never executed) to pin a vocabulary boundary.
		data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from WalkDir over the repo's own source
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "license_activation") {
			hits = append(hits, path)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, hits,
		"the dead license_activation schema must stay unreachable from Go; referenced by: %v", hits)
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "go.mod not found above %s", dir)
		dir = parent
	}
}
