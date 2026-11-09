package license

// N11-P05-T06 consumer-agreement pins, data layer (adjacent tests-only card;
// T03/T04 helpers and fixtures consumed, no fork, zero production changes).
// The card's integration scenario, pinned at the DTO boundary:
//
//   1. the wire format is a STABLE agreement: the issued payload JSON carries
//      exactly the shipped key set (additive-only evolution; sig never leaks
//      into a decoded grant);
//   2. issuance is deterministic — the same document under the same key
//      yields byte-identical tokens (reproducible offline audit trail), and
//      only real document changes (nonce, key) change the bytes;
//   3. the grant surface carries NO limit/count input and NO edition
//      concept: no numeric field can count consumption, verification takes
//      exactly (token, key, deployment) — no account/limit parameter — and
//      the entitlement path never mentions an "edition" (I22: core has no
//      edition split; the run right is the signed module list).
//
// Fixed anchors only (moduleEntitlementNow / maintenanceFixture). No wall
// clock; no external server — every pin runs pure-offline.

import (
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entitlementPayloadKeys decodes the payload segment of an issued token into
// a raw JSON map so the pin sees the WIRE, not the Go struct.
func entitlementPayloadKeys(t *testing.T, token string) map[string]any {
	t.Helper()
	payloadB64, _, ok := strings.Cut(token, ".")
	require.Truef(t, ok, "token must be payload.signature, got %q shape", token)
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err, "payload segment must decode as base64url")
	var raw map[string]any
	require.NoError(t, json.Unmarshal(payload, &raw), "payload segment must be a JSON object")
	return raw
}

// TestConsumerAgreement_WireFormatDTOStable pins the exact wire key set as a
// consumer agreement: the minimal (no-trial, no-lines) document carries
// exactly {v,c,d,m,i,me,n}; the full document adds exactly {te,rl}; the
// signature never appears inside a decoded payload (it is transport
// metadata); a release line is exactly {line,se,cf}. Any key removal or
// rename breaks shipped consumers and fails here; additive keys fail the
// exact-set pins below and must be an owner-visible format event, not a
// silent drift.
func TestConsumerAgreement_WireFormatDTOStable(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()

	base := PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   maintenanceFixture.deploy,
		Modules:        maintenanceFixture.modules,
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(30 * 24 * time.Hour),
		Nonce:          "consumer-agreement-min",
	}
	minToken, err := fixturePaidModuleEntitlement(priv, base, moduleEntitlementNow)
	require.NoError(t, err)

	// Wire reality (pinned, not assumed): omitempty never omits a zero
	// time.Time (struct kind), so the definitive no-trial state IS on the
	// wire as the zero instant — consumers must read it as "no trial"
	// (fail-closed), and rl/sig are omitted when unset (nil slice/bytes).
	wantMin := []string{"v", "c", "d", "m", "i", "me", "n", "te"}
	minKeys := entitlementPayloadKeys(t, minToken)
	require.Len(t, minKeys, len(wantMin), "the minimal document must carry exactly the agreed key set — nothing else on the wire")
	for _, k := range wantMin {
		assert.Containsf(t, minKeys, k, "agreed key %q missing from the minimal wire format", k)
	}
	assert.Equal(t, "0001-01-01T00:00:00Z", minKeys["te"],
		"the no-trial document must serialize TrialEnd as the zero instant — a definitive, fail-closed no-trial state on the wire, never a silent omission")
	for _, absent := range []string{"sig", "rl"} {
		assert.NotContainsf(t, minKeys, absent,
			"key %q must not appear on the wire when its field is nil — omission is part of the agreement", absent)
	}

	full := base
	full.TrialEnd = moduleEntitlementNow.Add(7 * 24 * time.Hour)
	full.ReleaseLines = []ReleaseLine{
		{Line: "1.4", SupportEnd: moduleEntitlementNow.Add(240 * 24 * time.Hour), CriticalFixes: true},
	}
	full.Nonce = "consumer-agreement-full"
	fullToken, err := fixturePaidModuleEntitlement(priv, full, moduleEntitlementNow)
	require.NoError(t, err)

	wantFull := append(wantMin, "rl")
	fullKeys := entitlementPayloadKeys(t, fullToken)
	require.Len(t, fullKeys, len(wantFull), "the full document must carry exactly the agreed key set — nothing else on the wire")
	for _, k := range wantFull {
		assert.Containsf(t, fullKeys, k, "agreed key %q missing from the full wire format", k)
	}
	assert.NotContains(t, fullKeys, "sig", "the signature is transport metadata and never part of the decoded grant")
	assert.NotEqual(t, "0001-01-01T00:00:00Z", fullKeys["te"],
		"a signed trial serializes its real end instant — distinct from the zero no-trial state")

	// The nested release-line object is its own agreement (I25): exactly
	// {line,se,cf}.
	lines, ok := fullKeys["rl"].([]any)
	require.True(t, ok, "rl must decode as a JSON array")
	require.Len(t, lines, 1)
	lineObj, ok := lines[0].(map[string]any)
	require.True(t, ok, "a release line must decode as a JSON object")
	assert.ElementsMatch(t, []string{"line", "se", "cf"}, mapKeys(lineObj),
		"release-line wire keys drifted — shipped consumers read exactly {line,se,cf}")

	// A decoded grant never carries signature bytes: verify output's
	// Signature is transport metadata, always nil.
	got, err := VerifyPaidModuleEntitlement(fullToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err)
	assert.Nil(t, got.Signature, "Signature must be nil on a verified grant — transport metadata never masquerades as grant data")
}

// mapKeys is a tiny helper for the release-line key-set pin above.
func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestConsumerAgreement_IssuanceDeterministic pins reproducible issuance:
// identical document + key → byte-identical token (the offline audit trail
// can be reproduced years later without server state); re-issuing the
// DECODED document reproduces the same bytes (verify strips only transport
// metadata); only real document changes (nonce) or key changes alter the
// bytes. Any nondeterminism (map iteration, local time, random padding)
// breaks byte reproducibility and fails here.
func TestConsumerAgreement_IssuanceDeterministic(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	doc := PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   maintenanceFixture.deploy,
		Modules:        maintenanceFixture.modules,
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(30 * 24 * time.Hour),
		ReleaseLines: []ReleaseLine{
			{Line: "1.4", SupportEnd: moduleEntitlementNow.Add(240 * 24 * time.Hour), CriticalFixes: true},
		},
		Nonce: "determinism-0001",
	}

	token1, err := fixturePaidModuleEntitlement(priv, doc, moduleEntitlementNow)
	require.NoError(t, err)
	token2, err := fixturePaidModuleEntitlement(priv, doc, moduleEntitlementNow)
	require.NoError(t, err)
	require.Equal(t, token1, token2,
		"issuance must be deterministic: identical document+key must produce byte-identical tokens (reproducible offline audit trail)")

	// Re-issue from the decoded document: verify output re-signs to the
	// same bytes — the decoded grant is the complete document (only
	// transport metadata was stripped).
	decoded, err := VerifyPaidModuleEntitlement(token1, pub, maintenanceFixture.deploy)
	require.NoError(t, err)
	reissue, err := fixturePaidModuleEntitlement(priv, decoded, moduleEntitlementNow)
	require.NoError(t, err)
	assert.Equal(t, token1, reissue,
		"re-issuing the decoded document must reproduce the exact token bytes — the decoded grant loses no signed content")

	// Only a real document change changes the bytes.
	nonceChanged := doc
	nonceChanged.Nonce = "determinism-0002"
	token3, err := fixturePaidModuleEntitlement(priv, nonceChanged, moduleEntitlementNow)
	require.NoError(t, err)
	assert.NotEqual(t, token1, token3,
		"a different nonce is a different document and must produce different bytes (issuer-side audit identity)")
}

// TestConsumerAgreement_GrantSurfaceCarriesNoLimitOrEditionInput pins the
// grant surface structurally: no field can hold a count (a consumption
// counter needs a numeric field — none exists in either DTO type, the
// module LIST is the whole grant), verification takes exactly
// (token, key, deploymentID) — no account/user/limit parameter — and no
// "edition" concept exists anywhere on the entitlement path (I22: the core
// defines no edition split; the packet's consistency item is satisfied by
// construction, pinned here so it stays that way). Complements T04's
// NoUserCap (vocabulary + method surface) without repeating it.
func TestConsumerAgreement_GrantSurfaceCarriesNoLimitOrEditionInput(t *testing.T) {
	numericKinds := map[reflect.Kind]bool{
		reflect.Int: true, reflect.Int8: true, reflect.Int16: true, reflect.Int32: true, reflect.Int64: true,
		reflect.Uint: true, reflect.Uint8: true, reflect.Uint16: true, reflect.Uint32: true, reflect.Uint64: true, reflect.Uintptr: true,
		reflect.Float32: true, reflect.Float64: true,
		reflect.Complex64: true, reflect.Complex128: true,
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(PaidModuleEntitlement{}),
		reflect.TypeOf(ReleaseLine{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			assert.Falsef(t, numericKinds[field.Type.Kind()],
				"%s.%s is numeric (%s) — a numeric grant field can only be a consumption counter; the grant is a module LIST (I22/no-cap)",
				typ.Name(), field.Name, field.Type.Kind())
			assert.NotContainsf(t, strings.ToLower(field.Name+field.Tag.Get("json")), "edition",
				"%s.%s carries an edition concept — the core has no edition split (I22)", typ.Name(), field.Name)
		}
	}

	verifyType := reflect.TypeOf(VerifyPaidModuleEntitlement)
	require.Equal(t, 3, verifyType.NumIn(),
		"verification must take exactly (token, key, deployment): no limit/account parameter may enter the verify surface")
	for i := 0; i < verifyType.NumIn(); i++ {
		assert.Falsef(t, numericKinds[verifyType.In(i).Kind()],
			"verify parameter %d is numeric — a count/limit input on the verify surface is a consumption meter (I22/no-cap)", i)
	}
	assert.False(t, verifyType.IsVariadic(), "verification must not be variadic — the offline surface is exactly three fixed inputs")

	// No "edition" anywhere on the entitlement path sources: not as an
	// identifier, not as a string literal (error texts included).
	for _, name := range []string{"module_entitlement.go", "maintenance.go"} {
		f := parsePackageFile(t, name)
		require.NotNil(t, f, "%s must parse — the audit must see the real file", name)
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Ident:
				assert.NotContainsf(t, strings.ToLower(node.Name), "edition",
					"%s references an edition concept (%q) — the core has no edition split (I22)", name, node.Name)
			case *ast.BasicLit:
				assert.NotContainsf(t, strings.ToLower(node.Value), "edition",
					"%s carries an edition string literal (%q) — the core has no edition split (I22)", name, node.Value)
			}
			return true
		})
	}
}
