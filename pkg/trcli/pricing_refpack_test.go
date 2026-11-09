package trcli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// refPackCLIFixture seals a minimal draft catalog and returns its JSON —
// the input material for the pack/verify/diff/chain CLI round-trip.
func refPackCLIFixture(t *testing.T, version, supersedes string, amt float64) []byte {
	t.Helper()
	cat := pricing.Catalog{
		SchemaVersion: pricing.RefSchemaVersion,
		Version:       version,
		GeneratedAt:   "2026-11-02",
		Source:        "trcli refpack test assembly (deterministic fixture)",
		ReviewSLADays: 90,
		Supersedes:    supersedes,
		Models: []pricing.RefModel{{
			Provider: "fprov", Model: "fixture-model",
			Currency: "USD", Status: pricing.RefStatusDraft,
			EffectiveFrom: "2026-11-01", VerifiedAt: "2026-11-02",
			Rates: []pricing.RefRate{{
				Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens, Amount: &amt,
			}},
			Reviewer: "fixture-reviewer",
		}},
	}
	sealed, err := pricing.SealCatalog(cat)
	require.NoError(t, err)
	// The operator's sealed body keeps its digest field; the pack command
	// re-canonicalizes internally and pins the digest into the envelope.
	body, err := json.Marshal(sealed)
	require.NoError(t, err)
	return body
}

// TestPricingRefPackCommands drives the offline pack/verify/diff/chain
// subcommands end-to-end: envelope build, tamper refusal with the
// expected-vs-actual digest, chain direction, canonical diff render and
// the committed v1 snapshot verify pin. Everything is local-file-only.
func TestPricingRefPackCommands(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name string, body []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, body, 0o600)) //nolint:gosec // G703: p is a t.TempDir() fixture path, not request input
		return p
	}
	run := func(t *testing.T, args ...string) (string, string, error) {
		t.Helper()
		root := RootCommand()
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		root.SetArgs(args)
		err := root.Execute()
		return stdout.String(), stderr.String(), err
	}

	packPath := func(t *testing.T, name, version, supersedes string, amt float64) string {
		t.Helper()
		catalog := writeFile(name+".catalog.json", refPackCLIFixture(t, version, supersedes, amt))
		out := filepath.Join(dir, name+".pack.json")
		_, stderr, err := run(t, "pricing", "pack", "--catalog", catalog, "--out", out, "--notice", "trcli test")
		require.NoError(t, err)
		require.Contains(t, stderr, "pack_sha256=")
		require.Contains(t, stderr, "catalog_digest=")
		return out
	}

	t.Run("pack verify diff chain round-trip", func(t *testing.T) {
		p1 := packPath(t, "p1", "0.1.0-cli", "", 2.0)
		stdout, stderr, err := run(t, "pricing", "verify", "--pack", p1)
		require.NoError(t, err)
		require.Empty(t, stderr)
		require.Contains(t, stdout, "yabanin-catalog@0.1.0-cli")
		require.Contains(t, stdout, "sha256:")
		require.Contains(t, stdout, "models: 1")

		// The successor must declare p1's digest for the chain to hold.
		d1 := mustDigestOf(t, p1)
		p2 := packPath(t, "p2", "0.2.0-cli", d1, 2.5)

		_, _, err = run(t, "pricing", "chain", "--prev", p1, "--next", p2)
		require.NoError(t, err, "a successor declaring the predecessor's digest must chain")
		_, _, err = run(t, "pricing", "chain", "--prev", p2, "--next", p1)
		require.Error(t, err, "reverse direction must be refused")

		stdout, _, err = run(t, "pricing", "diff", "--old", p1, "--new", p2)
		require.NoError(t, err)
		require.Contains(t, stdout, "ref-diff:")
		require.Contains(t, stdout, "CHANGED")
		require.Contains(t, stdout, "summary:")
	})

	t.Run("verify refuses a tampered pack", func(t *testing.T) {
		p1 := packPath(t, "tamper", "0.1.0-cli", "", 2.0)
		body, err := os.ReadFile(p1) //nolint:gosec // G304/G703: p1 is a t.TempDir() fixture path, not request input
		require.NoError(t, err)
		// Flip one character inside the catalog body: catalog_digest and
		// pack_sha256 must both break.
		flip := bytes.Index(body, []byte(`"fixture-model"`))
		require.Positive(t, flip)
		body[flip] = 'F'
		tampered := writeFile("tampered.pack.json", body)
		_, _, err = run(t, "pricing", "verify", "--pack", tampered)
		require.Error(t, err)
	})

	t.Run("committed v1 snapshot verifies offline", func(t *testing.T) {
		stdout, stderr, err := run(t, "pricing", "verify",
			"--pack", "../../pkg/pricing/snapshots/reference-pack-v1.json")
		require.NoError(t, err)
		require.Empty(t, stderr)
		require.Contains(t, stdout, "sha256:eeb4d7063d48b8bf7b5d4f4374278259cdff856792755f63d0a92c21f2f651c5",
			"the pinned REF-02 genesis digest must survive the pack envelope")
		require.Contains(t, stdout, "schema_version: 1")
	})
}

// mustDigestOf loads a pack and returns its catalog digest — used to link
// a successor catalog to its predecessor in the chain round-trip.
func mustDigestOf(t *testing.T, packPath string) string {
	t.Helper()
	body, err := os.ReadFile(packPath) //nolint:gosec // G304/G703: packPath is a t.TempDir() fixture path, not request input
	require.NoError(t, err)
	pack, _, err := pricing.LoadRefPack(body)
	require.NoError(t, err)
	return pack.CatalogDigest
}
