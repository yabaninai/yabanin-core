// Offline proof battery (E01-P05 card W03-C03, batch B): the executable
// form of the packet criterion «верификация лицензии работает offline — нет
// обязательного внешнего license call» against the design
// artifacts/enterprise-beta/E01-P05/offline-verification-design.md §6.
//
// Three layers:
//
//  1. The chain plane (VerifyLicenseChain, verify.go:20) is proven with
//     witnesses made ONLY of local files and runtime-generated Ed25519
//     keys: the valid-chain vector passes, and every failure class of the
//     taxonomy (§3) fails closed — expired intermediate (F6), expired
//     token (F4), revoked intermediate (F9, with the CRL soft-skip
//     posture documented side by side), tampered token (F10), malformed
//     JSON (F3).
//
//  2. Fixed clocks (§4): the pure (document, now) predicates — the
//     maintenance gates and the trial state — are proven at fixed
//     past/present/future instants and at the EXACT boundary instants
//     (inclusive boundaries are part of the contract), with recomputation
//     idempotent: the verdict is a function of the inputs, never of the
//     wall clock or of evaluation order.
//
//  3. No network by construction: a source-level red pin — the offline
//     verify path must not gain an outbound-network capability. go/parser
//     walks the package's non-test sources: no file may import net/*
//     except server.go, whose net/http is the LOCAL /healthz serving
//     surface (an inbound handler, never an outbound license call). Any
//     new net import anywhere else turns this proof red.
//
// N/A network branches: there is no branch in the verification path where a
// network call could substitute for a local input — the witness set (§2 of
// the design) is files + embedded/parameter keys + clock, all local; the
// proofs below therefore have no offline/online fork to cover, which is the
// point being pinned.
package license

import (
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// offlineChain builds a complete local witness set in t.TempDir: root key,
// intermediate cert (validity may be negative — F6), license token, clean
// CRL. The intermediate env var is pinned via t.Setenv (resolution order:
// override → env → deploy default, verify.go:82–91 — the env pin is what a
// deployment must do to avoid the deploy/ default trap of design §3 F5).
func offlineChain(t *testing.T, interValidity, licenseExpiry time.Duration) (licensePath, rootPubHex, crlPath string, tok *Token) {
	t.Helper()
	rootPub, rootPriv, err := fixtureRootKeyPair()
	require.NoError(t, err)
	inter, interPriv, err := fixtureIntermediate(rootPriv, interValidity)
	require.NoError(t, err)
	tok, err = fixtureLicense(interPriv, inter.Serial, "offline-proof-customer", time.Now().Add(licenseExpiry))
	require.NoError(t, err)

	dir := t.TempDir()
	licensePath = filepath.Join(dir, "license.json")
	interPath := filepath.Join(dir, "intermediate.json")
	crlPath = filepath.Join(dir, "crl.json")

	writeJSON := func(path string, v any) {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, raw, 0o600))
	}
	writeJSON(licensePath, tok)
	writeJSON(interPath, inter)
	writeJSON(crlPath, CRL{RevokedSerials: []string{}, UpdatedAt: time.Now().UTC()})

	t.Setenv("YABANIN_LICENSE_INTERMEDIATE_CERT", interPath)
	return licensePath, hex.EncodeToString(rootPub), crlPath, tok
}

// TestOfflineProof_ChainVerifiesWithLocalInputsOnly is the packet
// criterion's positive proof: every input is a local file or a parameter
// key; no external license call exists to make.
func TestOfflineProof_ChainVerifiesWithLocalInputsOnly(t *testing.T) {
	licensePath, rootPubHex, crlPath, _ := offlineChain(t, 365*24*time.Hour, 90*24*time.Hour)
	require.NoError(t, VerifyLicenseChain(licensePath, rootPubHex, crlPath),
		"the full chain verifies with local files only")
}

// TestOfflineProof_ExpiredIntermediateFailsClosed pins F6: an expired
// intermediate kills every license under it, even an unexpired token.
func TestOfflineProof_ExpiredIntermediateFailsClosed(t *testing.T) {
	licensePath, rootPubHex, crlPath, _ := offlineChain(t, -time.Hour, 90*24*time.Hour)
	err := VerifyLicenseChain(licensePath, rootPubHex, crlPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "intermediate")
	assert.Contains(t, err.Error(), "expired")
}

// TestOfflineProof_ExpiredTokenFailsClosed pins F4: the chain plane has NO
// grace — a token past Expiry is rejected immediately (the 7d GracePeriod
// is activation-plane only, license.go:35).
func TestOfflineProof_ExpiredTokenFailsClosed(t *testing.T) {
	licensePath, rootPubHex, crlPath, _ := offlineChain(t, 365*24*time.Hour, -24*time.Hour)
	err := VerifyLicenseChain(licensePath, rootPubHex, crlPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "license expired")
}

// TestOfflineProof_RevokedIntermediateFailsClosed pins F9 and documents the
// CRL soft-skip posture side by side (design §3): with a CRL configured,
// the revoked serial fails verification; with crlPath empty the same
// revocation is INVISIBLE — revocation reach equals CRL configuration, a
// deployment posture the design records for the owner, not a verifier
// verdict.
func TestOfflineProof_RevokedIntermediateFailsClosed(t *testing.T) {
	licensePath, rootPubHex, crlPath, _ := offlineChain(t, 365*24*time.Hour, 90*24*time.Hour)

	// Discover the intermediate serial through the resolution the verifier
	// itself uses, then revoke it in the local CRL file.
	interPath := os.Getenv("YABANIN_LICENSE_INTERMEDIATE_CERT")
	raw, err := os.ReadFile(interPath) // #nosec G304,G703 -- test-set t.Setenv override, never operator input
	require.NoError(t, err)
	var inter IntermediateCert
	require.NoError(t, json.Unmarshal(raw, &inter))
	require.NoError(t, RevokeIntermediate(crlPath, inter.Serial))

	err = VerifyLicenseChain(licensePath, rootPubHex, crlPath)
	require.Error(t, err, "a configured CRL must enforce revocation offline")
	assert.Contains(t, err.Error(), "revoked")

	require.NoError(t, VerifyLicenseChain(licensePath, rootPubHex, ""),
		"POSTURE (design §3, documented, not a verdict): without a CRL configured the same revocation is invisible")
}

// TestOfflineProof_TamperedTokenFailsClosed pins F10: the signature covers
// Version|CustomerID|Serial|Expiry|Intermediate (pki.go:89–95) — flipping
// the customer id after issuance breaks verification.
func TestOfflineProof_TamperedTokenFailsClosed(t *testing.T) {
	licensePath, rootPubHex, crlPath, tok := offlineChain(t, 365*24*time.Hour, 90*24*time.Hour)
	tok.CustomerID = "offline-proof-attacker"
	raw, err := json.Marshal(tok)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(licensePath, raw, 0o600))

	err = VerifyLicenseChain(licensePath, rootPubHex, crlPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "license verification")
}

// TestOfflineProof_MalformedLicenseFailsClosed pins F3: a corrupt artifact
// fails closed at parse.
func TestOfflineProof_MalformedLicenseFailsClosed(t *testing.T) {
	licensePath, rootPubHex, crlPath, _ := offlineChain(t, 365*24*time.Hour, 90*24*time.Hour)
	require.NoError(t, os.WriteFile(licensePath, []byte(`{"v":"1","c":"trunca`), 0o600))

	err := VerifyLicenseChain(licensePath, rootPubHex, crlPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse license")
}

// offlineVerdicts evaluates every pure (document, now) predicate of one
// corpus state at one instant — the fixed-clock fingerprint.
func offlineVerdicts(ent PaidModuleEntitlement, now time.Time) [6]bool {
	return [6]bool{
		ent.MaintenanceEndedAt(now),
		ent.UpdatesEntitledAt(now),
		ent.CriticalFixEntitledAt("2026.1", now),
		ent.CriticalFixEntitledAt("2026.0", now),
		ent.CriticalFixEntitledAt("2027.0", now),
		ent.TrialActiveAt(now),
	}
}

// TestOfflineProof_FixedClocksPurePredicates pins clock independence on the
// pure plane: fixed past/present/future instants produce fixed verdicts,
// the EXACT boundary instants are inclusive (part of the contract, design
// §4), and recomputation is idempotent — verdicts are functions of
// (document, now), never of the wall clock or evaluation order.
func TestOfflineProof_FixedClocksPurePredicates(t *testing.T) {
	valid := loadCorpusEntitlement(t, "valid.json")
	ended := loadCorpusEntitlement(t, "maintenance_ended.json")
	critical := loadCorpusEntitlement(t, "critical_only.json")

	instants := map[string]time.Time{
		"past":    corpusAnchor.Add(-365 * 24 * time.Hour),
		"present": corpusAnchor,
		"future":  corpusAnchor.Add(365 * 24 * time.Hour),
	}

	// Fixed instants, recomputed twice: identical fingerprints.
	states := map[string]PaidModuleEntitlement{"valid": valid, "ended": ended, "critical": critical}
	for state, ent := range states {
		for label, at := range instants {
			first := offlineVerdicts(ent, at)
			assert.Equal(t, first, offlineVerdicts(ent, at),
				"%s@%s: recomputation must be idempotent", state, label)
		}
	}

	// Exact boundary instants are INCLUSIVE (strict-After semantics at
	// maintenance.go:34/:45/:60 and module_entitlement.go:345).
	assert.False(t, ended.MaintenanceEndedAt(ended.MaintenanceEnd),
		"the maintenance term is still running at the exact MaintenanceEnd instant")
	assert.True(t, ended.UpdatesEntitledAt(ended.MaintenanceEnd),
		"updates stay entitled at the exact MaintenanceEnd instant")
	assert.True(t, valid.UpdatesEntitledAt(valid.MaintenanceEnd))
	for _, rl := range critical.ReleaseLines {
		if rl.Line == "2026.1" {
			assert.True(t, critical.CriticalFixEntitledAt(rl.Line, rl.SupportEnd),
				"the I25 exception holds through the exact SupportEnd instant")
		}
	}
	trial := loadCorpusEntitlement(t, "updates_unentitled_trial.json")
	assert.True(t, trial.TrialActiveAt(trial.TrialEnd),
		"the trial is active through the exact TrialEnd instant")

	// Past vs future across the boundary flips exactly the term-gated
	// predicates; HasModule — the perpetual run right — never moves.
	day := 24 * time.Hour
	assert.True(t, ended.UpdatesEntitledAt(ended.MaintenanceEnd.Add(-day)))
	assert.False(t, ended.UpdatesEntitledAt(ended.MaintenanceEnd.Add(day)))
	assert.True(t, ended.HasModule("internal-loop"))
	assert.True(t, ended.HasModule("internal-loop"), // recomputed: clock-free by construction
		"HasModule reads no clock at all (I24)")
}

// TestOfflineProof_EntitlementVerifyClockFree pins the I24 API-shape law:
// VerifyPaidModuleEntitlement takes NO clock — its verdict is wall-time
// independent by construction. The behavioral proof: a maintenance-ENDED
// corpus document verifies today (the run right survives its term, already
// pinned per-state in the corpus battery), and the same token yields the
// identical document on every verification.
func TestOfflineProof_EntitlementVerifyClockFree(t *testing.T) {
	token, pub := issueCorpus(t, loadCorpusEntitlement(t, "maintenance_ended.json"))
	first, err := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
	require.NoError(t, err, "a maintenance-ended document verifies: no clock input exists to reject it")
	second, err := VerifyPaidModuleEntitlement(token, pub, corpusDeployment)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

// TestOfflineProof_NoNetworkByConstruction is the source-level red pin for
// the packet criterion: the offline verify path must not gain outbound
// network capability. Any non-test source of pkg/license importing net/*
// turns this red, except server.go (local /healthz serving — inbound
// handler, never an outbound license call).
func TestOfflineProof_NoNetworkByConstruction(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, err, "parse %s", name)
		checked++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path != "net" && !strings.HasPrefix(path, "net/") {
				continue
			}
			if name == "server.go" {
				continue // documented allowance: local /healthz serving, never outbound
			}
			t.Errorf("offline criterion red pin: %s imports %s — only server.go (local /healthz serving) may touch net/*", name, path)
		}
	}
	assert.Positive(t, checked, "the pin must have walked the package sources")
}
