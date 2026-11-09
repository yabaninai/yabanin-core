package run

// N11-P05-T07 boundary corpus, wiring layer: the file-envelope boundary at
// the admin entry point. The corpus CONFIRMS the previously supported
// contract (shipped N11-P05-T03..T06 behavior) — every row documents
// behavior that already holds; zero production changes.
//
// Non-duplication contract: T06's wiring refusal rows cover absent file,
// garbage file, wrong contour, garbage deployment env and half-configured
// envs with non-whitespace values. The rows below are NEW boundary input
// shapes — padded-but-valid file envelopes (the T05 whitespace pin was the
// env VALUES, not the file content), inner whitespace inside the envelope
// and a directory path — none of which any existing wiring test feeds.
//
// Entry-point layer split: the wiring TRIMS the file content
// (operator-config noise) while the pkg verifier consumes exact bytes; both
// sides of that split are pinned here and in the pkg boundary corpus.

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boundaryIssueToken issues a token with the deterministic wiring keys and
// returns the TOKEN (not a path) — the envelope-shape rows need the exact
// token string to splice. Reachable only with the vendor private key, same
// as the shared writeEntitlementToken helper (which returns a path).
func boundaryIssueToken(t *testing.T, priv ed25519.PrivateKey, deployment string, modules []string, issued, me time.Time) string {
	t.Helper()
	token, err := fixtureSignedModuleEntitlement(priv, license.PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   deployment,
		Modules:        modules,
		IssuedAt:       issued,
		MaintenanceEnd: me,
		Nonce:          "wiring-boundary-0001",
	}, issued)
	require.NoError(t, err)
	return token
}

// TestModuleEntitlementBoundary_FileEnvelopePadding pins the file-envelope
// boundary at the entry point: operator-config padding around the token
// inside the document file is noise and must resolve to the IDENTICAL
// grant, while whitespace INSIDE the envelope (payload or before the
// separator) is envelope damage the verifier refuses — the entry point
// trims the outside, never repairs the inside.
func TestModuleEntitlementBoundary_FileEnvelopePadding(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	modules := []string{"protection-pack-av", "internal-loop"}
	token := boundaryIssueToken(t, priv, "prod-eu-1", modules, now.Add(-time.Hour), now.Add(365*day))
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	require.True(t, ok, "fixture precondition lost: token must be payload.signature")
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	writeBoundaryFile := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "ent.token")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	// Reference: the exact same token, unpadded.
	t.Setenv(licenseModuleEntitlementFileEnv, writeBoundaryFile(t, token))
	ref, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, ref)

	// Padded-but-valid envelopes: every padding variant resolves to the
	// byte-identical grant (deployment, modules, nonce, both instants).
	for _, pad := range []string{" ", "\t", "\n", "\r\n", "  \n\t"} {
		t.Setenv(licenseModuleEntitlementFileEnv, writeBoundaryFile(t, pad+token+pad))
		ent, err := resolveModuleEntitlement()
		require.NoError(t, err, "padding %q around the token is operator-config noise", pad)
		require.NotNil(t, ent)
		assert.Equal(t, ref.DeploymentID, ent.DeploymentID, "padding must not change the signed contour binding")
		assert.Equal(t, ref.Modules, ent.Modules, "padding must not change the signed module list")
		assert.Equal(t, ref.Nonce, ent.Nonce, "padding must not change the signed nonce")
		assert.True(t, ref.IssuedAt.Equal(ent.IssuedAt), "padding must not change the signed issue instant")
		assert.True(t, ref.MaintenanceEnd.Equal(ent.MaintenanceEnd), "padding must not change the signed term end")
		assert.Nil(t, ent.Signature, "transport metadata must stay nil on a decoded grant")
	}

	// Inner whitespace is envelope damage: the pkg verifier consumes exact
	// bytes and refuses through its decode-payload family — same refusal
	// shape at the entry point, nil grant.
	spliced := payloadB64[:len(payloadB64)/2] + " " + payloadB64[len(payloadB64)/2:] + "." + sigB64
	t.Setenv(licenseModuleEntitlementFileEnv, writeBoundaryFile(t, spliced))
	ent, err := resolveModuleEntitlement()
	require.Error(t, err, "whitespace inside the signed payload is not trimmable")
	assert.Contains(t, err.Error(), "verify module entitlement", "inner damage must surface through the verify refusal family")
	assert.Nil(t, ent)

	// Newline INSIDE the payload segment: the base64 decoder skips newline
	// characters, the decoded signed bytes are unchanged, so the document
	// still verifies to the identical grant — sound tolerance (whitespace
	// between the bytes is not part of the signed material).
	split := payloadB64[:len(payloadB64)/2] + "\n" + payloadB64[len(payloadB64)/2:] + "." + sigB64
	t.Setenv(licenseModuleEntitlementFileEnv, writeBoundaryFile(t, split))
	ent, err = resolveModuleEntitlement()
	require.NoError(t, err, "a newline inside the payload segment is decoder-skipped, not corruption")
	require.NotNil(t, ent)
	assert.Equal(t, ref.Nonce, ent.Nonce, "decoder-skipped whitespace must not change the decoded grant")

	// A character outside the base64url alphabet DOES change the decoded
	// bytes and refuses through the decode-payload family — same refusal
	// shape at the entry point, nil grant.
	foreign := payloadB64[:len(payloadB64)/2] + "+" + payloadB64[len(payloadB64)/2:] + "." + sigB64
	t.Setenv(licenseModuleEntitlementFileEnv, writeBoundaryFile(t, foreign))
	ent, err = resolveModuleEntitlement()
	require.Error(t, err, "a non-base64url character corrupts the payload segment")
	assert.Contains(t, err.Error(), "verify module entitlement", "inner damage must surface through the verify refusal family")
	assert.Nil(t, ent)
}

// TestModuleEntitlementBoundary_WhitespaceOnlyEnvValues pins the env-value
// boundary between "unconfigured" and "half-configured": whitespace-only env
// values are trimmed to empty, so a whitespace-only file env with no
// deployment env stays an unconfigured (enterprise-free) contour — while
// whitespace on either side of a SET pair is half-configuration and refuses
// startup naming the missing variable. Enforcement never half-starts.
func TestModuleEntitlementBoundary_WhitespaceOnlyEnvValues(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	modules := []string{"internal-loop"}

	// Both sides whitespace-only: the unconfigured contour (nil, nil) —
	// absence, not failure.
	t.Setenv(licenseModuleEntitlementFileEnv, "   ")
	ent, err := resolveModuleEntitlement()
	require.NoError(t, err, "whitespace-only values are unconfigured, not broken")
	assert.Nil(t, ent, "an unconfigured contour grants nothing and does not fail")

	// File env whitespace-only, deployment env set: half-configured — the
	// missing variable is named, fail-closed.
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	ent, err = resolveModuleEntitlement()
	require.Error(t, err, "a set deployment env with no document must refuse startup")
	assert.Contains(t, err.Error(), "env incomplete")
	assert.Contains(t, err.Error(), licenseModuleEntitlementFileEnv, "the refusal must name the missing variable")
	assert.Nil(t, ent)

	// Valid file, deployment env whitespace-only: half-configured from the
	// other side, still naming the missing variable.
	t.Setenv(licenseModuleEntitlementFileEnv,
		writeEntitlementToken(t, priv, modules, now.Add(-time.Hour), now.Add(365*24*time.Hour)))
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "  \t ")
	ent, err = resolveModuleEntitlement()
	require.Error(t, err, "a set file env with an empty running identity must refuse startup")
	assert.Contains(t, err.Error(), "env incomplete")
	assert.Contains(t, err.Error(), licenseModuleEntitlementDeploymentEnv, "the refusal must name the missing variable")
	assert.Nil(t, ent)
}

// TestModuleEntitlementBoundary_TokenFileIsDirectory pins the path-shape
// boundary: a directory path is an unreadable document, refused through the
// read-refusal family ("read module entitlement file") with a nil grant —
// startup refusal, not a silent skip and not a verify-family refusal.
func TestModuleEntitlementBoundary_TokenFileIsDirectory(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, _ := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	t.Setenv(licenseModuleEntitlementFileEnv, t.TempDir())
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	ent, err := resolveModuleEntitlement()
	require.Error(t, err, "a directory is not a readable entitlement document")
	assert.Contains(t, err.Error(), "read module entitlement file", "path-shape refusals stay in the read family")
	assert.Nil(t, ent)
}
