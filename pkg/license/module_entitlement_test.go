package license

// Tests for the paid-module entitlement (N11-P05-T02 data layer, evolved to
// format "2" by N11-P05-T03): offline signature verification, the I23
// one-production-contour binding, the perpetual I24 run right (no clock
// input can reject a document) and the no-defaults module grant. All tests
// use a fixed-seed Ed25519 key and a fixed clock — fully deterministic, no
// global state is mutated.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// moduleEntitlementNow is the fixed test clock (never time.Now).
var moduleEntitlementNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// moduleEntitlementTestSeed is a fixed 32-byte seed for the deterministic
// test signing key. Test-only: never a production key.
var moduleEntitlementTestSeed = []byte("yabanin-n11-p05-t03-test-seed-01")

// moduleEntitlementTestKey derives the deterministic test keypair.
func moduleEntitlementTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(moduleEntitlementTestSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

func issueModuleToken(t *testing.T, deployID string, modules []string, issued, maintenanceEnd time.Time) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := moduleEntitlementTestKey()
	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   deployID,
		Modules:        modules,
		IssuedAt:       issued,
		MaintenanceEnd: maintenanceEnd,
		Nonce:          "issue-0001",
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return token, pub, priv
}

// TestPaidModuleEntitlement_RoundTrip_OfflineVerify: a valid entitlement for
// the running deployment verifies with no external server and grants exactly
// the signed module list.
func TestPaidModuleEntitlement_RoundTrip_OfflineVerify(t *testing.T) {
	modules := []string{"internal-loop", "media-persistence"}
	token, pub, _ := issueModuleToken(t, "prod-eu-1", modules, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))

	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ent.CustomerID != "cust_acme" || ent.DeploymentID != "prod-eu-1" || ent.Nonce != "issue-0001" {
		t.Fatalf("unexpected entitlement: %+v", ent)
	}
	for _, m := range modules {
		if !ent.HasModule(m) {
			t.Fatalf("granted module %q not reported by HasModule", m)
		}
	}
	if ent.Signature != nil {
		t.Fatalf("decoded entitlement carries transport Signature %v, want nil", ent.Signature)
	}
	if ent.Version != ModuleEntitlementVersion {
		t.Fatalf("version = %q, want %q", ent.Version, ModuleEntitlementVersion)
	}
}

// TestPaidModuleEntitlement_SameContourInstances: HA replica, DR and test
// instances of the SAME production contour are configured with the contour's
// DeploymentID, so the one entitlement covers them all (I23) — replica
// scaling and failover never consume an additional license.
func TestPaidModuleEntitlement_SameContourInstances(t *testing.T) {
	token, pub, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	// Contour members presenting the licensed identity: primary, HA replica,
	// DR failover and test environments all verify against the same grant.
	for _, role := range []string{"primary", "ha-replica", "dr-failover", "test"} {
		if _, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1"); err != nil {
			t.Fatalf("contour instance %s must verify against its own entitlement: %v", role, err)
		}
	}
}

// TestPaidModuleEntitlement_WrongDeployment_Rejected pins the I23 negative:
// an independent production contour cannot reuse another production's
// entitlement — it is licensed and paid for separately.
func TestPaidModuleEntitlement_WrongDeployment_Rejected(t *testing.T) {
	token, pub, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	_, err := VerifyPaidModuleEntitlement(token, pub, "prod-us-2")
	if err == nil {
		t.Fatal("independent production verified against another deployment's entitlement, want rejection")
	}
	if !strings.Contains(err.Error(), `licensed for deployment "prod-eu-1"`) || !strings.Contains(err.Error(), `running deployment is "prod-us-2"`) {
		t.Fatalf("error must name both deployment identities, got: %v", err)
	}
}

// TestPaidModuleEntitlement_UnconfiguredRunningDeployment_Rejected: an
// instance that cannot name its own deployment identity is never entitled.
func TestPaidModuleEntitlement_UnconfiguredRunningDeployment_Rejected(t *testing.T) {
	token, pub, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	if _, err := VerifyPaidModuleEntitlement(token, pub, ""); err == nil {
		t.Fatal("empty running deployment identity must not verify")
	}
}

// TestPaidModuleEntitlement_TamperRejected: any payload change (e.g. swapping
// the deployment identity inside the signed bytes) invalidates the signature.
func TestPaidModuleEntitlement_TamperRejected(t *testing.T) {
	token, pub, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))

	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatal("token has no separator")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	tampered := strings.Replace(string(payload), `"prod-eu-1"`, `"prod-us-2"`, 1)
	if tampered == string(payload) {
		t.Fatal("tamper substitution did not change the payload")
	}
	forged := base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + sigB64
	if _, err := VerifyPaidModuleEntitlement(forged, pub, "prod-us-2"); err == nil {
		t.Fatal("redeployment-forged entitlement verified, want signature rejection")
	}
}

// TestPaidModuleEntitlement_WrongKeyAndFormatRejected covers fail-closed
// parsing: wrong vendor key, truncated and garbage tokens never verify.
func TestPaidModuleEntitlement_WrongKeyAndFormatRejected(t *testing.T) {
	token, _, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	otherPub, _, _ := ed25519.GenerateKey(nil)

	for name, tc := range map[string]struct {
		key ed25519.PublicKey
		tok string
	}{
		"wrong key":    {otherPub, token},
		"truncated":    {otherPub, token[:len(token)/2]},
		"no separator": {otherPub, "not-a-token"},
		"empty":        {otherPub, ""},
	} {
		if _, err := VerifyPaidModuleEntitlement(tc.tok, tc.key, "prod-eu-1"); err == nil {
			t.Fatalf("%s: verification succeeded, want error", name)
		}
	}
}

// TestPaidModuleEntitlement_ModuleNotGranted: a module absent from the signed
// list has no entitlement — new packs get no rights without a grant.
func TestPaidModuleEntitlement_ModuleNotGranted(t *testing.T) {
	token, pub, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ent.HasModule("media-persistence") {
		t.Fatal("ungranted module reported as entitled")
	}
	if ent.HasModule("") {
		t.Fatal("empty module id reported as entitled")
	}
}

// TestPaidModuleEntitlement_ErrorCarriesZeroEntitlement pins fail-closed
// return semantics: a rejected document must never leak its signed grant
// list through the returned value, even though the payload was parseable.
func TestPaidModuleEntitlement_ErrorCarriesZeroEntitlement(t *testing.T) {
	token, pub, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop", "media-persistence"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))

	errCases := []struct {
		name string
		tok  string
		pub  ed25519.PublicKey
		run  string
	}{
		{"wrong deployment", token, pub, "prod-us-2"},
		{"unconfigured running deployment", token, pub, ""},
		{"wrong key", token, func() ed25519.PublicKey { k, _, _ := ed25519.GenerateKey(nil); return k }(), "prod-eu-1"},
		{"garbage token", "not-a-token", pub, "prod-eu-1"},
	}
	for _, tc := range errCases {
		ent, err := VerifyPaidModuleEntitlement(tc.tok, tc.pub, tc.run)
		if err == nil {
			t.Fatalf("%s: verification succeeded, want error", tc.name)
		}
		if ent.CustomerID != "" || ent.DeploymentID != "" || ent.Nonce != "" || len(ent.Modules) != 0 {
			t.Fatalf("%s: error returned populated entitlement %+v, want zero value", tc.name, ent)
		}
		if ent.HasModule("internal-loop") || ent.HasModule("media-persistence") {
			t.Fatalf("%s: error entitlement reports granted modules, want none", tc.name)
		}
	}

	// A v1-format document (N11-P05-T02 shape, no maintenance split) must
	// also fail closed with zero grants — the version pin rejects it before
	// any semantic is derived.
	v1Pub, v1Priv, _ := ed25519.GenerateKey(nil)
	v1Payload := []byte(`{"v":"1","c":"cust_acme","d":"prod-eu-1","m":["internal-loop"],"i":"2026-01-01T00:00:00Z","e":"2027-01-01T00:00:00Z","n":"legacy-0001"}`)
	v1Tok := base64.RawURLEncoding.EncodeToString(v1Payload) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(v1Priv, v1Payload))
	ent, err := VerifyPaidModuleEntitlement(v1Tok, v1Pub, "prod-eu-1")
	if err == nil {
		t.Fatal("v1-format entitlement verified, want version rejection")
	}
	if len(ent.Modules) != 0 || ent.HasModule("internal-loop") || ent.DeploymentID != "" {
		t.Fatalf("v1-format error returned entitlement with grants %+v, want zero value", ent)
	}

	// Signed-but-malformed payload (review finding 1): the JSON parse fails
	// after a valid signature — reachable only with the vendor key. The
	// stdlib keeps already-decoded fields on UnmarshalTypeError, so this
	// path must explicitly return the zero entitlement.
	malPub, malPriv := moduleEntitlementTestKey()
	malPayload := []byte(`{"v":"2","c":"cust_acme","d":"prod-eu-1","m":5,"i":"2026-01-01T00:00:00Z","me":"2027-01-01T00:00:00Z","n":"malformed-0001"}`)
	malSig := ed25519.Sign(malPriv, malPayload)
	malTok := base64.RawURLEncoding.EncodeToString(malPayload) + "." + base64.RawURLEncoding.EncodeToString(malSig)
	ent, err = VerifyPaidModuleEntitlement(malTok, malPub, "prod-eu-1")
	if err == nil {
		t.Fatal("signed-malformed verification succeeded, want parse error")
	}
	if ent.CustomerID != "" || ent.DeploymentID != "" || ent.Nonce != "" || len(ent.Modules) != 0 {
		t.Fatalf("signed-malformed error returned populated entitlement %+v, want zero value", ent)
	}
}

// TestPaidModuleEntitlement_SignedInvalidClaims verifies malformed grants
// even when their envelope carries a valid signature.
func TestPaidModuleEntitlement_SignedInvalidClaims(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	future := moduleEntitlementNow.Add(30 * 24 * time.Hour)
	base := PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		MaintenanceEnd: future,
		Nonce:          "n1",
	}

	cases := map[string]PaidModuleEntitlement{
		"no customer":         {DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"}, MaintenanceEnd: future, Nonce: "n1"},
		"no deployment":       {CustomerID: "cust_acme", Modules: []string{"internal-loop"}, MaintenanceEnd: future, Nonce: "n1"},
		"padded deployment":   {CustomerID: "cust_acme", DeploymentID: " prod-eu-1", Modules: []string{"internal-loop"}, MaintenanceEnd: future, Nonce: "n1"},
		"no modules":          {CustomerID: "cust_acme", DeploymentID: "prod-eu-1", MaintenanceEnd: future, Nonce: "n1"},
		"empty module entry":  {CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{""}, MaintenanceEnd: future, Nonce: "n1"},
		"blank module entry":  {CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"   "}, MaintenanceEnd: future, Nonce: "n1"},
		"padded module entry": {CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{" internal-loop"}, MaintenanceEnd: future, Nonce: "n1"},
		"no nonce":            {CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"}, MaintenanceEnd: future},
		"no maintenance end":  {CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"}, Nonce: "n1"},
		"maintenance before issued": {
			CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"},
			IssuedAt: moduleEntitlementNow, MaintenanceEnd: moduleEntitlementNow.Add(-time.Second), Nonce: "n1",
		},
		"maintenance equals issued": {
			CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"},
			IssuedAt: moduleEntitlementNow, MaintenanceEnd: moduleEntitlementNow, Nonce: "n1",
		},
		"unknown version": {
			Version: "3", CustomerID: "cust_acme", DeploymentID: "prod-eu-1",
			Modules: []string{"internal-loop"}, MaintenanceEnd: future, Nonce: "n1",
		},
		"empty release line": {
			CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"},
			MaintenanceEnd: future, Nonce: "n1",
			ReleaseLines: []ReleaseLine{{Line: "", SupportEnd: future, CriticalFixes: true}},
		},
		"padded release line": {
			CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"},
			MaintenanceEnd: future, Nonce: "n1",
			ReleaseLines: []ReleaseLine{{Line: " 1.4 ", SupportEnd: future}},
		},
		"release line without support end": {
			CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"},
			MaintenanceEnd: future, Nonce: "n1",
			ReleaseLines: []ReleaseLine{{Line: "1.4"}},
		},
		"duplicate release line": {
			CustomerID: "cust_acme", DeploymentID: "prod-eu-1", Modules: []string{"internal-loop"},
			MaintenanceEnd: future, Nonce: "n1",
			ReleaseLines: []ReleaseLine{
				{Line: "1.4", SupportEnd: future},
				{Line: "1.4", SupportEnd: future.Add(time.Hour)},
			},
		},
	}
	verifyRejected := func(name string, ent PaidModuleEntitlement) {
		t.Helper()
		raw, err := json.Marshal(ent)
		require.NoError(t, err)
		token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))
		rejected, err := VerifyPaidModuleEntitlement(token, pub, base.DeploymentID)
		require.Error(t, err, name)
		require.Zero(t, rejected, name)
	}
	for name, ent := range cases {
		if ent.Version == "" {
			ent.Version = ModuleEntitlementVersion
		}
		if ent.IssuedAt.IsZero() {
			ent.IssuedAt = moduleEntitlementNow
		}
		verifyRejected(name, ent)
	}
	base.Version = ModuleEntitlementVersion
	verifyRejected("zero issued time", base)
}

// TestPaidModuleEntitlement_VerifyStructuralValidation proves the verifier's
// own checks are independent of issuer-side validation: a correctly signed
// but structurally invalid document still fails closed.
func TestPaidModuleEntitlement_VerifyStructuralValidation(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()

	sign := func(t *testing.T, raw map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(payload) + "." +
			base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	}
	when := moduleEntitlementNow.Add(24 * time.Hour).Format(time.RFC3339)

	cases := map[string]map[string]any{
		"unknown version": {
			"v": "3", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "n1",
		},
		"legacy v1 document": {
			"v": "1", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "e": when, "n": "n1",
		},
		"no deployment": {
			"v": "2", "c": "cust_acme", "d": "", "m": []string{"internal-loop"}, "me": when, "n": "n1",
		},
		"no customer": {
			"v": "2", "c": "", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "n1",
		},
		"no modules": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{}, "me": when, "n": "n1",
		},
		"empty module entry": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{""}, "me": when, "n": "n1",
		},
		"blank module entry": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"   "}, "me": when, "n": "n1",
		},
		"padded module entry": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop "}, "me": when, "n": "n1",
		},
		"no maintenance end": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "n": "n1",
		},
		"no issued time": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "n1",
		},
		"no nonce": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "",
		},
		"maintenance end before issued": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"},
			"i":  moduleEntitlementNow.Add(48 * time.Hour).Format(time.RFC3339),
			"me": when, "n": "n1",
		},
		"empty release line": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "n1",
			"rl": []map[string]any{{"line": "", "se": when}},
		},
		"release line without support end": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "n1",
			"rl": []map[string]any{{"line": "1.4", "cf": true}},
		},
		"duplicate release line": {
			"v": "2", "c": "cust_acme", "d": "prod-eu-1", "m": []string{"internal-loop"}, "me": when, "n": "n1",
			"rl": []map[string]any{
				{"line": "1.4", "se": when},
				{"line": "1.4", "se": when},
			},
		},
	}
	for name, raw := range cases {
		token := sign(t, raw)
		if _, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1"); err == nil {
			t.Fatalf("%s: signed-but-invalid entitlement verified, want rejection", name)
		}
	}
}

// TestPaidModuleEntitlement_IssuanceDefaultsAndUTC: zero IssuedAt defaults to
// now, times are normalized to UTC, empty version is pinned to "2", and the
// resulting token round-trips.
func TestPaidModuleEntitlement_IssuanceDefaultsAndUTC(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()

	nonUTC := time.Date(2026, 10, 28, 15, 0, 0, 0, time.FixedZone("UTC+3", 3*3600))
	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		IssuedAt:       nonUTC,
		MaintenanceEnd: nonUTC.Add(24 * time.Hour),
		Nonce:          "n1",
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ent.Version != ModuleEntitlementVersion {
		t.Fatalf("version = %q, want %q", ent.Version, ModuleEntitlementVersion)
	}
	if got, want := ent.IssuedAt, nonUTC.UTC().Truncate(time.Second); !got.Equal(want) {
		t.Fatalf("issued = %v, want %v (UTC-normalized)", got, want)
	}
	if got, want := ent.MaintenanceEnd, nonUTC.Add(24*time.Hour).UTC().Truncate(time.Second); !got.Equal(want) {
		t.Fatalf("maintenance end = %v, want %v (UTC-normalized)", got, want)
	}
}

// TestPaidModuleEntitlement_ReleaseLinesRoundTrip: release-line metadata
// survives issue → verify byte-faithfully (I25 source of truth).
func TestPaidModuleEntitlement_ReleaseLinesRoundTrip(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		MaintenanceEnd: moduleEntitlementNow.Add(365 * 24 * time.Hour),
		Nonce:          "n1",
		ReleaseLines: []ReleaseLine{
			{Line: "1.4", SupportEnd: moduleEntitlementNow.Add(730 * 24 * time.Hour), CriticalFixes: true},
			{Line: "1.3", SupportEnd: moduleEntitlementNow.Add(30 * 24 * time.Hour)},
		},
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(ent.ReleaseLines) != 2 {
		t.Fatalf("release lines = %d, want 2", len(ent.ReleaseLines))
	}
	if ent.ReleaseLines[0].Line != "1.4" || !ent.ReleaseLines[0].CriticalFixes ||
		!ent.ReleaseLines[0].SupportEnd.Equal(moduleEntitlementNow.Add(730*24*time.Hour).UTC()) {
		t.Fatalf("release line[0] corrupted: %+v", ent.ReleaseLines[0])
	}
	if ent.ReleaseLines[1].CriticalFixes {
		t.Fatal("release line[1] must keep the critical-fix flag unset")
	}
}

// TestPaidModuleEntitlement_TrialRoundTrip: the optional signed TrialEnd
// survives issue → verify byte-faithfully (UTC-normalized like the other
// times), and absence stays absence (zero in, zero out — an old "2" document
// without the field still parses unchanged: the field is additive).
func TestPaidModuleEntitlement_TrialRoundTrip(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	nonUTC := time.Date(2026, 11, 15, 18, 0, 0, 0, time.FixedZone("UTC+3", 3*3600))

	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(365 * 24 * time.Hour),
		TrialEnd:       nonUTC,
		Nonce:          "trial-0001",
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got, want := ent.TrialEnd, nonUTC.UTC().Truncate(time.Second); !got.Equal(want) {
		t.Fatalf("trial end = %v, want %v (UTC-normalized)", got, want)
	}

	// A document issued without a trial must stay trial-free end to end —
	// the optional field must not conjure a default trial term.
	noTrial, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(365 * 24 * time.Hour),
		Nonce:          "trial-none",
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue no-trial: %v", err)
	}
	entNoTrial, err := VerifyPaidModuleEntitlement(noTrial, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify no-trial: %v", err)
	}
	if !entNoTrial.TrialEnd.IsZero() {
		t.Fatalf("trial end = %v, want zero (no trial issued)", entNoTrial.TrialEnd)
	}
}

// TestPaidModuleEntitlement_TrialExplicitEndState pins the explicit trial
// state machine: active through the exact TrialEnd instant (inclusive),
// explicitly ended one nanosecond later, and never active for a document
// without a trial (zero = definitive no-trial state, not open-ended).
func TestPaidModuleEntitlement_TrialExplicitEndState(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	trialEnd := moduleEntitlementNow.Add(14 * 24 * time.Hour)
	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(365 * 24 * time.Hour),
		TrialEnd:       trialEnd,
		Nonce:          "trial-0002",
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"at issue", moduleEntitlementNow, true},
		{"one ns before trial end", trialEnd.Add(-time.Nanosecond), true},
		{"at exact trial end", trialEnd, true},
		{"one ns after trial end", trialEnd.Add(time.Nanosecond), false},
		{"long after trial end", trialEnd.Add(10 * 365 * 24 * time.Hour), false},
	}
	for _, tc := range cases {
		if got := ent.TrialActiveAt(tc.now); got != tc.want {
			t.Fatalf("%s: TrialActiveAt = %v, want %v", tc.name, got, tc.want)
		}
	}

	// Zero-valued and no-trial entitlements: TrialActiveAt is false at every
	// instant — absence of a trial is an explicit state, never indefinite.
	var zero PaidModuleEntitlement
	if zero.TrialActiveAt(time.Now()) {
		t.Fatal("zero entitlement reports an active trial, want fail-closed")
	}
	if ent.TrialActiveAt(trialEnd.Add(-24*time.Hour)) != true {
		t.Fatal("fixture precondition lost: trial must be active inside its term")
	}
}

// TestPaidModuleEntitlement_TrialValidation checks that a signed trial term
// which does not start after IssuedAt fails verification.
func TestPaidModuleEntitlement_TrialValidation(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	base := PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop"},
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(365 * 24 * time.Hour),
		Nonce:          "trial-0003",
	}

	bad := []struct {
		name     string
		trialEnd time.Time
	}{
		{"trial end equals issued", moduleEntitlementNow},
		{"trial end before issued", moduleEntitlementNow.Add(-time.Second)},
	}
	for _, tc := range bad {
		// Sign invalid claims directly so verification cannot rely on
		// fixture-side validation.
		raw, err := json.Marshal(map[string]any{
			"v":  ModuleEntitlementVersion,
			"c":  base.CustomerID,
			"d":  base.DeploymentID,
			"m":  []string{"internal-loop"},
			"i":  base.IssuedAt.Format(time.RFC3339),
			"me": base.MaintenanceEnd.Format(time.RFC3339),
			"te": tc.trialEnd.Format(time.RFC3339),
			"n":  base.Nonce,
		})
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		tok := base64.RawURLEncoding.EncodeToString(raw) + "." +
			base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))
		entVerified, err := VerifyPaidModuleEntitlement(tok, pub, "prod-eu-1")
		if err == nil {
			t.Fatalf("%s: signed-but-invalid trial verified, want rejection", tc.name)
		}
		if entVerified.TrialEnd.Equal(tc.trialEnd) || !entVerified.TrialEnd.IsZero() {
			t.Fatalf("%s: error returned populated trial end %v, want zero value", tc.name, entVerified.TrialEnd)
		}
	}
}

// TestPaidModuleEntitlement_TrialExplicitStateIsolation is the safety core
// of the trial layer: the trial state — active, ended, or absent — never
// influences any other right. The perpetual paid run right (I24), the
// renewal-gated update term and the I25 critical-fix exception are identical
// while a trial runs and after it explicitly ends; a trial ending never
// disables previously paid modules.
func TestPaidModuleEntitlement_TrialExplicitStateIsolation(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	trialEnd := moduleEntitlementNow.Add(14 * 24 * time.Hour)
	maintenanceEnd := moduleEntitlementNow.Add(30 * 24 * time.Hour)
	lineSupportEnd := moduleEntitlementNow.Add(90 * 24 * time.Hour)

	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop", "media-persistence"},
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: maintenanceEnd,
		TrialEnd:       trialEnd,
		Nonce:          "trial-0004",
		ReleaseLines: []ReleaseLine{
			{Line: "1.4", SupportEnd: lineSupportEnd, CriticalFixes: true},
		},
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	points := []struct {
		name string
		now  time.Time
	}{
		{"trial active, inside maintenance", moduleEntitlementNow.Add(24 * time.Hour)},
		{"trial just ended, inside maintenance", trialEnd.Add(time.Nanosecond)},
		{"long after trial, past maintenance too", maintenanceEnd.Add(24 * time.Hour)},
	}
	for _, at := range points {
		for _, m := range []string{"internal-loop", "media-persistence"} {
			if !ent.HasModule(m) {
				t.Fatalf("%s: paid module %q lost — trial state must not affect the I24 run right", at.name, m)
			}
		}
		if ent.HasModule("protection-pack-nextgen") {
			t.Fatalf("%s: unsigned pack granted during trial — trial is not a grant", at.name)
		}
		if ent.TrialActiveAt(at.now) != (at.now.Before(trialEnd) || at.now.Equal(trialEnd)) {
			t.Fatalf("%s: trial state itself drifted", at.name)
		}
		if got, wantUpdate := ent.UpdatesEntitledAt(at.now), !at.now.After(maintenanceEnd); got != wantUpdate {
			t.Fatalf("%s: update right = %v, want %v — trial must not gate updates", at.name, got, wantUpdate)
		}
		if !ent.CriticalFixEntitledAt("1.4", at.now) {
			t.Fatalf("%s: I25 critical-fix right lost — trial must not gate it", at.name)
		}
	}
}
