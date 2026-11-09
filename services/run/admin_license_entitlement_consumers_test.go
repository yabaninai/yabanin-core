package run

// N11-P05-T06 consumer-agreement pins at the admin entry point seam
// (adjacent tests-only card; T03/T04 helpers consumed, no fork, zero
// production changes). The card's integration items, pinned at the wiring:
//
//   1. consumers are consistent per DTO: resolveModuleEntitlement surfaces
//      EXACTLY what pkg/license verification returns for the same token —
//      module ORDER, release lines, times — for in-term AND past-maintenance
//      documents (a paid version continues without renewal, with no
//      renewal-time reinterpretation injected at the wiring);
//   2. refusals are one language family: every invalid document (tampered
//      payload, wrong signing key, wrong format version old/new, empty or
//      whitespace-only file) yields an error that names its cause and the
//      zero grant — never a partial entitlement;
//   3. no license → the core runs without any account limit (the
//      unconfigured state is stable and grants nothing); licensed contour
//      replicas resolving the same document never consume anything (five
//      resolves return identical full grants — no counter exists to move);
//      and no "edition" concept exists in the wiring source (I22).
//
// Day-scale margins follow the shipped wiring pattern; no wall-clock
// anchors, no external server.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/license"
)

// consumerAgreementModules is deliberately NOT alphabetical: the DTO-match
// pin below must fail if any layer reorders the grant.
var consumerAgreementModules = []string{
	"internal-loop",
	"protection-pack-av",
	"conditional-original-text-retention",
	"media-persistence",
}

// mintRawEntitlementToken marshals and signs a document as-is (no issue-time
// validation) so the refusal matrix can present old/new format versions —
// exactly what an attacker or a future vendor build would put on disk.
func mintRawEntitlementToken(t *testing.T, ent license.PaidModuleEntitlement, priv ed25519.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(ent)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

// TestModuleEntitlementConsumers_WiringDTOMatchesPkgVerify pins the consumer
// consistency agreement: the wiring is a thin offline pass-through. For the
// same token file, resolveModuleEntitlement must return EXACTLY what a
// direct license.VerifyPaidModuleEntitlement returns — byte-for-byte
// semantics including module ORDER, release lines and signed instants —
// both for an in-term document and for a document whose maintenance already
// ended (the paid version continues without renewal; the wiring adds no
// renewal-time interpretation, drops no history module, injects no default).
func TestModuleEntitlementConsumers_WiringDTOMatchesPkgVerify(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	cases := []struct {
		name           string
		maintenanceEnd time.Time
		trialEnd       time.Time
	}{
		{"in-term document", now.Add(365 * day), now.Add(30 * day)},
		{"past-maintenance document (paid version continues without renewal)", now.Add(-40 * day), now.Add(-10 * day)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := fixtureSignedModuleEntitlement(priv, license.PaidModuleEntitlement{
				CustomerID:     "cust_acme",
				DeploymentID:   "prod-eu-1",
				Modules:        consumerAgreementModules, // non-alphabetical: order is part of the agreement
				IssuedAt:       now.Add(-400 * day),
				MaintenanceEnd: tc.maintenanceEnd,
				TrialEnd:       tc.trialEnd,
				ReleaseLines: []license.ReleaseLine{
					{Line: "1.4", SupportEnd: now.Add(240 * day), CriticalFixes: true},
					{Line: "1.3", SupportEnd: now.Add(30 * day), CriticalFixes: false},
				},
				Nonce: "consumer-dto-0001",
			}, now.Add(-400*day))
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "module-entitlement.token")
			require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))

			direct, err := license.VerifyPaidModuleEntitlement(token, license.VendorPublicKey, "prod-eu-1")
			require.NoError(t, err)
			require.Len(t, direct.Modules, len(consumerAgreementModules))
			require.Equal(t, consumerAgreementModules[0], direct.Modules[0],
				"fixture must keep the non-alphabetical order — otherwise the order pin below is vacuous")

			t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
			t.Setenv(licenseModuleEntitlementFileEnv, path)

			wired, err := resolveModuleEntitlement()
			require.NoError(t, err, "a valid document must resolve offline at the wiring, identical to direct verification")
			require.NotNil(t, wired)
			require.Equal(t, direct, *wired,
				"the wiring must surface EXACTLY the pkg verification result — same module order, same release lines, same signed instants; no wiring-side reinterpretation")
			for _, m := range consumerAgreementModules {
				assert.Truef(t, wired.HasModule(m), "resolved grant includes %q (consumers consistent per rights)", m)
			}
		})
	}
}

// TestModuleEntitlementConsumers_RefusalMatrixConsistent pins the refusal
// agreement: every invalid document class produces an error that names its
// cause AND the zero grant — the same nil-ent-plus-cause family for tampered
// payloads, wrong signing keys, old and future format versions, and
// degenerate files. No invalid input may yield a partial entitlement.
func TestModuleEntitlementConsumers_RefusalMatrixConsistent(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	doc := license.PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        consumerAgreementModules,
		IssuedAt:       now.Add(-24 * time.Hour),
		MaintenanceEnd: now.Add(365 * day),
		Nonce:          "refusal-matrix-0001",
	}
	validToken, err := fixtureSignedModuleEntitlement(priv, doc, now.Add(-24*time.Hour))
	require.NoError(t, err)

	// Deterministically corrupt one base64url ALPHABET character in the
	// payload segment: decode still succeeds, bytes differ, signature fails.
	payloadB64, _, _ := strings.Cut(validToken, ".")
	corrupt := []byte(payloadB64)
	for i := len(corrupt) / 2; i < len(corrupt); i++ {
		if c := corrupt[i]; (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			corrupt[i] = 'A' + ((c - 'A' + 1) % 26) // deterministic alphabet step
			if corrupt[i] == c {
				corrupt[i] = 'B'
			}
			break
		}
	}
	tamperedToken := string(corrupt) + validToken[len(payloadB64):]

	wrongKey := ed25519.NewKeyFromSeed([]byte("yabanin-n11-p05-t06-wrong-key-01")) // exactly 32 bytes
	wrongKeyToken := mintRawEntitlementToken(t, doc, wrongKey)

	v1Doc := doc
	v1Doc.Version = "1"
	v1Doc.Nonce = "refusal-matrix-v1"
	v3Doc := doc
	v3Doc.Version = "3"
	v3Doc.Nonce = "refusal-matrix-v3"

	rows := []struct {
		name    string
		content string
		wantErr string
	}{
		{"tampered payload", tamperedToken, "invalid entitlement signature"},
		{"wrong signing key", wrongKeyToken, "invalid entitlement signature"},
		{"legacy format v1 (pre-I24 hard-expiry class)", mintRawEntitlementToken(t, v1Doc, priv), `unsupported version "1"`},
		{"future format v3", mintRawEntitlementToken(t, v3Doc, priv), `unsupported version "3"`},
		{"empty file", "", "invalid token format"},
		{"whitespace-only file", " \n\t\n", "invalid token format"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "module-entitlement.token")
			require.NoError(t, os.WriteFile(path, []byte(row.content), 0o600))
			t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
			t.Setenv(licenseModuleEntitlementFileEnv, path)

			ent, err := resolveModuleEntitlement()
			require.Errorf(t, err, "%s must be refused — a refusal may never degrade into a grant", row.name)
			assert.Containsf(t, err.Error(), row.wantErr,
				"%s must be refused with its named cause (consumer agreement: one refusal language family)", row.name)
			assert.Nilf(t, ent, "%s must yield the zero grant — never a partial entitlement", row.name)
		})
	}
}

// TestModuleEntitlementConsumers_UnlicensedUnlimited_LicensedReplicasNeverConsume
// pins the integration scenario's consumption semantics: the unlicensed core
// state is stable, error-free and grants nothing (no account limit input
// exists to consult), and licensed contour replicas resolving the SAME
// document five times get the identical full grant every time — resolution
// consumes nothing, because the grant surface has no counter to move (the
// structural no-limit pin lives in pkg; this is its runtime twin). Also: no
// "edition" concept anywhere in the wiring source (I22).
func TestModuleEntitlementConsumers_UnlicensedUnlimited_LicensedReplicasNeverConsume(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	// Unlicensed: repeated resolution stays (nil, nil) — the core keeps
	// running with no limit consulted and nothing consumed. (Both module
	// entitlement envs unset — the explicit unconfigured state; setting only
	// the deployment env would be the fail-closed half-configured class,
	// already pinned by T03.)
	for i := 0; i < 3; i++ {
		ent, err := resolveModuleEntitlement()
		require.NoErrorf(t, err, "unlicensed resolve %d must be the explicit non-error no-entitlement state (I22)", i)
		assert.Nilf(t, ent, "unlicensed resolve %d must grant nothing", i)
	}

	// Licensed replicas: five resolves of the same document — identical
	// full grants, no consumption, no degradation.
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementToken(t, priv, consumerAgreementModules,
		time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour)))

	var first *license.PaidModuleEntitlement
	for i := 0; i < 5; i++ {
		ent, err := resolveModuleEntitlement()
		require.NoErrorf(t, err, "replica resolve %d must succeed offline", i)
		require.NotNilf(t, ent, "replica resolve %d must yield the full grant", i)
		if first == nil {
			first = ent
		}
		assert.Equalf(t, first, ent,
			"replica resolve %d must return the identical grant — resolution consumes nothing (replicas never consume licenses)", i)
		for _, m := range consumerAgreementModules {
			assert.Truef(t, ent.HasModule(m), "replica resolve %d grants %q in full", i, m)
		}
	}

	// No edition concept in the wiring source: no identifier, no string
	// literal (error texts included) mentions an edition split (I22).
	f, err := parser.ParseFile(token.NewFileSet(), "admin_license_entitlement.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err, "the wiring source must parse — the audit must see the real file")
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			assert.NotContainsf(t, lower(node.Name), "edition",
				"wiring references an edition concept (%q) — the core has no edition split (I22)", node.Name)
		case *ast.BasicLit:
			assert.NotContainsf(t, lower(node.Value), "edition",
				"wiring carries an edition string literal (%q) — the core has no edition split (I22)", node.Value)
		}
		return true
	})
}

// lower is a tiny ASCII helper so the edition pins read without importing
// strings for one call site.
func lower(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c - 'A' + 'a'
		}
	}
	return string(out)
}
