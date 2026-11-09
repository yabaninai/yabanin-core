package license

// N11-P05-T07 boundary corpus, data layer: token-envelope shapes, signed
// payload JSON shapes, signed-instant zones/precision and the cross-right
// combination matrix at boundary instants. The corpus CONFIRMS the
// previously supported contract (shipped N11-P05-T03..T06 behavior) — every
// row documents behavior that already holds; zero production changes.
//
// Non-duplication contract: refusal-family rows here are NEW input shapes,
// not re-runs of covered ones — T03 pinned truncated/no-separator/empty
// (with a wrong key) and the semantic drift matrix; T06 pinned the issued
// wire key set and six wiring refusal rows. Every row below either uses the
// CORRECT vendor key (so the refusal cause is attributable to the shape, not
// to key mismatch) or pins a positive boundary no other test covers.
//
// Fixed anchors only (moduleEntitlementNow, moduleEntitlementTestKey): fully
// deterministic, offline, no wall clock.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// boundarySignRaw signs an arbitrary payload with the deterministic test key
// — exactly the shape a future vendor build (or an attacker who somehow
// obtained the vendor key) would put on disk. Reachable only with the vendor
// key; every negative row below must still return the zero grant.
func boundarySignRaw(t *testing.T, priv ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

// TestBoundary_TokenEnvelopeShapes pins the token ENVELOPE boundary of the
// verifier: the payload.signature split and the base64url alphabet are
// exact. Each malformed shape lands in its named shipped refusal family and
// leaks no grant — with the correct vendor key, so the cause attribution is
// precise. The surrounding-whitespace row pins the layer split: the pkg
// verifier consumes EXACT bytes and never trims (trimming is the wiring's
// explicit job, pinned at the entry point by the T07 wiring corpus).
func TestBoundary_TokenEnvelopeShapes(t *testing.T) {
	pub, _ := moduleEntitlementTestKey()
	token, _, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatal("fixture precondition lost: issued token must be payload.signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode fixture payload: %v", err)
	}
	// Same payload bytes under the standard alphabet: identical characters
	// plus '=' padding — '=' is outside the base64url alphabet, so the
	// RawURL decoder must refuse this envelope shape.
	stdPayload := base64.StdEncoding.EncodeToString(payloadBytes)
	if stdPayload == payloadB64 {
		t.Fatal("fixture precondition lost: standard alphabet must differ from raw-url encoding")
	}

	cases := []struct {
		name    string
		tok     string
		wantErr string
	}{
		{"trailing dot leaves an empty signature segment", payloadB64 + ".", "invalid entitlement signature"},
		{"leading dot leaves an empty payload segment", "." + sigB64, "invalid entitlement signature"},
		{"extra segment rides inside the signature part", token + ".extra", "decode sig"},
		{"standard-alphabet padding is outside base64url", stdPayload + "." + sigB64, "decode payload"},
		{"surrounding whitespace is not pkg-verified", "  " + token + "\t", "decode payload"},
	}
	for _, tc := range cases {
		ent, err := VerifyPaidModuleEntitlement(tc.tok, pub, "prod-eu-1")
		if err == nil {
			t.Fatalf("%s: verification succeeded, want refusal", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: error %q must name its refusal family (want %q)", tc.name, err, tc.wantErr)
		}
		if len(ent.Modules) != 0 || ent.DeploymentID != "" || ent.Nonce != "" {
			t.Fatalf("%s: refusal returned populated entitlement %+v, want zero grant", tc.name, ent)
		}
	}
}

// TestBoundary_SignedPayloadJSONShapes pins the signed-payload JSON boundary:
// degenerate documents and unusual-but-signed shapes decode exactly as
// shipped — the version pin is the first gate (and names the EMPTY version
// for null/empty documents), structurally wrong JSON refuses, unknown keys
// inside a signed v2 document are ignored (decode tolerance within the
// pinned version: the version string is the compatibility gate — issuance
// stays strict per the T06 exact wire key set), an embedded signature field
// is inert transport metadata, and duplicate JSON keys decode deterministically
// (stdlib last-key-wins over the signed bytes), so vendor audit and consumer
// decode agree on the same bytes.
func TestBoundary_SignedPayloadJSONShapes(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	sign := func(t *testing.T, payload []byte) string {
		t.Helper()
		return boundarySignRaw(t, priv, payload)
	}
	i := moduleEntitlementNow.Format(time.RFC3339)
	me := moduleEntitlementNow.Add(24 * time.Hour).Format(time.RFC3339)

	degenerate := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{"null document", []byte("null"), `unsupported version ""`},
		{"empty object document", []byte("{}"), `unsupported version ""`},
		{"array document", []byte("[]"), "parse entitlement"},
	}
	for _, tc := range degenerate {
		ent, err := VerifyPaidModuleEntitlement(sign(t, tc.payload), pub, "prod-eu-1")
		if err == nil {
			t.Fatalf("%s: verification succeeded, want refusal", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: error %q must name its refusal family (want %q)", tc.name, err, tc.wantErr)
		}
		if len(ent.Modules) != 0 || ent.DeploymentID != "" {
			t.Fatalf("%s: refusal returned populated entitlement %+v, want zero grant", tc.name, ent)
		}
	}

	validRaw := func(extra map[string]any) map[string]any {
		raw := map[string]any{
			"v": ModuleEntitlementVersion, "c": "cust_acme", "d": "prod-eu-1",
			"m": []string{"internal-loop"},
			"i": i, "me": me, "n": "boundary-shape-0001",
		}
		for k, v := range extra {
			raw[k] = v
		}
		return raw
	}
	marshal := func(raw map[string]any) []byte {
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	// Additive unknown field within the pinned version: verified, ignored,
	// grant intact — a future additive v2 revision never breaks deployed
	// verifiers; the version string, not the key set, is the decode gate.
	ent, err := VerifyPaidModuleEntitlement(sign(t, marshal(validRaw(map[string]any{
		"x_vendor_future": "opaque-additive-field",
	}))), pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("unknown-field document must verify (additive decode tolerance): %v", err)
	}
	if !ent.HasModule("internal-loop") || ent.DeploymentID != "prod-eu-1" || ent.Nonce != "boundary-shape-0001" {
		t.Fatalf("unknown-field document decoded wrong: %+v", ent)
	}

	// Embedded signature field inside a SIGNED payload: transport metadata
	// is inert even when an anomalous signed document carries it (complement
	// of the T06 wire pin, which pins the issued format's omission).
	ent, err = VerifyPaidModuleEntitlement(sign(t, marshal(validRaw(map[string]any{
		"sig": "AAECAw==",
	}))), pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("embedded-sig document must verify: %v", err)
	}
	if ent.Signature != nil {
		t.Fatalf("embedded signature leaked into the decoded grant: %v", ent.Signature)
	}

	// Duplicate JSON keys: the stdlib decode rule is last-key-wins over the
	// exact signed bytes — deterministic, so the same document always yields
	// the same grant.
	dup := []byte(`{"v":"2","c":"cust_acme","d":"prod-eu-1","m":["internal-loop"],` +
		`"m":["media-persistence"],"i":"` + i + `","me":"` + me + `","n":"dup-keys-0001"}`)
	ent, err = VerifyPaidModuleEntitlement(sign(t, dup), pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("duplicate-key document must verify deterministically: %v", err)
	}
	if len(ent.Modules) != 1 || ent.Modules[0] != "media-persistence" {
		t.Fatalf("duplicate module keys decoded %v, want the stdlib last-key-wins result [media-persistence]", ent.Modules)
	}
	entAgain, err := VerifyPaidModuleEntitlement(sign(t, dup), pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("repeat verify of duplicate-key document: %v", err)
	}
	if len(entAgain.Modules) != 1 || entAgain.Modules[0] != ent.Modules[0] || entAgain.Nonce != ent.Nonce {
		t.Fatalf("repeat verify drifted: %+v vs %+v — decode must be deterministic over signed bytes", entAgain, ent)
	}
}

// TestBoundary_SignedInstantZonesAndPrecision pins the signed-instant
// boundary: verification and every offline predicate compare INSTANTS, so a
// vendor-signed document expressed in a non-UTC offset is semantically
// identical to its UTC twin (issuance normalizes its own output to UTC, but
// the verifier must not depend on that), nanosecond precision survives the
// round trip and flips predicates exactly, the verify-side term boundary is
// inclusive-exclusive at the equality edge (me == i refuses; i + 1ns is the
// minimum legal term), independently of issuer validation.
func TestBoundary_SignedInstantZonesAndPrecision(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	zone := time.FixedZone("BOUNDARY+3", 3*3600)
	meUTC := moduleEntitlementNow.Add(48 * time.Hour)
	iZoneStr := moduleEntitlementNow.In(zone).Format(time.RFC3339Nano)
	meZoneStr := meUTC.In(zone).Format(time.RFC3339Nano)
	if !strings.Contains(iZoneStr, "+03:00") || !strings.Contains(meZoneStr, "+03:00") {
		t.Fatalf("fixture precondition lost: zone expressions must carry the offset (%q / %q)", iZoneStr, meZoneStr)
	}

	utcToken, _, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, meUTC)
	zoneToken := boundarySignRaw(t, priv, func() []byte {
		b, err := json.Marshal(map[string]any{
			"v": ModuleEntitlementVersion, "c": "cust_acme", "d": "prod-eu-1",
			"m": []string{"internal-loop"},
			"i": iZoneStr, "me": meZoneStr, "n": "zone-twin-0001",
		})
		if err != nil {
			t.Fatalf("marshal zone twin: %v", err)
		}
		return b
	}())

	entUTC, err := VerifyPaidModuleEntitlement(utcToken, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify UTC twin: %v", err)
	}
	entZone, err := VerifyPaidModuleEntitlement(zoneToken, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify zone twin: %v", err)
	}
	if !entUTC.IssuedAt.Equal(entZone.IssuedAt) || !entUTC.MaintenanceEnd.Equal(entZone.MaintenanceEnd) {
		t.Fatalf("zone twins decoded to different instants: %v/%v vs %v/%v",
			entUTC.IssuedAt, entUTC.MaintenanceEnd, entZone.IssuedAt, entZone.MaintenanceEnd)
	}
	for _, at := range []time.Time{
		moduleEntitlementNow.Add(24 * time.Hour), meUTC, meUTC.Add(time.Nanosecond),
	} {
		if entUTC.UpdatesEntitledAt(at) != entZone.UpdatesEntitledAt(at) ||
			entUTC.MaintenanceEndedAt(at) != entZone.MaintenanceEndedAt(at) {
			t.Fatalf("zone twins disagree at %v — predicates must compare instants, never representations", at)
		}
	}

	// Nanosecond precision: survives issue → verify byte-faithfully and the
	// renewal boundary flips exactly at the nanosecond.
	meNano := moduleEntitlementNow.Add(24 * time.Hour).Add(123456789 * time.Nanosecond)
	nanoToken, _, _ := issueModuleToken(t, "prod-eu-1", []string{"internal-loop"}, moduleEntitlementNow, meNano)
	entNano, err := VerifyPaidModuleEntitlement(nanoToken, pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("verify nano document: %v", err)
	}
	if !entNano.MaintenanceEnd.Equal(meNano) || entNano.MaintenanceEnd.Nanosecond() != 123456789 {
		t.Fatalf("nano precision lost: %v, want %v", entNano.MaintenanceEnd, meNano)
	}
	if !entNano.UpdatesEntitledAt(meNano) || entNano.UpdatesEntitledAt(meNano.Add(time.Nanosecond)) {
		t.Fatal("update boundary must flip exactly between me and me+1ns (inclusive end)")
	}
	if entNano.MaintenanceEndedAt(meNano) || !entNano.MaintenanceEndedAt(meNano.Add(time.Nanosecond)) {
		t.Fatal("maintenance-ended verdict must mirror the inclusive boundary")
	}

	// Verify-side equality edge: a signed me == i refuses independently of
	// issuer validation; i + 1ns is the minimum legal term and verifies.
	eqPayload, err := json.Marshal(map[string]any{
		"v": ModuleEntitlementVersion, "c": "cust_acme", "d": "prod-eu-1",
		"m":  []string{"internal-loop"},
		"i":  moduleEntitlementNow.Format(time.RFC3339),
		"me": moduleEntitlementNow.Format(time.RFC3339),
		"n":  "eq-edge-0001",
	})
	if err != nil {
		t.Fatalf("marshal equality edge: %v", err)
	}
	if _, err := VerifyPaidModuleEntitlement(boundarySignRaw(t, priv, eqPayload), pub, "prod-eu-1"); err == nil ||
		!strings.Contains(err.Error(), "must be after issued") {
		t.Fatalf("signed me == i must refuse naming the term edge, got: %v", err)
	}
	minPayload, err := json.Marshal(map[string]any{
		"v": ModuleEntitlementVersion, "c": "cust_acme", "d": "prod-eu-1",
		"m":  []string{"internal-loop"},
		"i":  moduleEntitlementNow.Format(time.RFC3339Nano),
		"me": moduleEntitlementNow.Add(time.Nanosecond).Format(time.RFC3339Nano),
		"n":  "min-term-0001",
	})
	if err != nil {
		t.Fatalf("marshal minimum term: %v", err)
	}
	if _, err := VerifyPaidModuleEntitlement(boundarySignRaw(t, priv, minPayload), pub, "prod-eu-1"); err != nil {
		t.Fatalf("minimum legal term (i+1ns) must verify: %v", err)
	}
}

// TestBoundary_CrossRightCombinationMatrix pins the combination boundaries
// between the three rights (run / updates / critical fixes) that the
// single-right tables leave uncovered:
//   - the MIRROR of the pinned after-maintenance case: a dead release line
//     stays dead even while the paid term runs (the I25 exception flows
//     forward only, never backwards);
//   - aligned inclusive boundaries: when a line's support end equals the
//     maintenance end, both rights are true AT the shared instant and both
//     flip 1ns later, in lockstep;
//   - per-line independence at one instant: supported+flag, expired+flag,
//     supported-but-unflagged and unknown lines get four independent
//     verdicts from one document;
//   - a historical support window (already over at issuance) is accepted in
//     the document (windows may be historical in vendor bytes) and grants
//     no fixes from the closure instant onward — fail-closed where it
//     matters, while a pure-instant query INSIDE the still-open window
//     still answers true (the predicate is a pure function of the query
//     instant, so historical queries are answered historically).
func TestBoundary_CrossRightCombinationMatrix(t *testing.T) {
	issueWith := func(t *testing.T, nonce string, me time.Time, lines []ReleaseLine) PaidModuleEntitlement {
		t.Helper()
		pub, priv := moduleEntitlementTestKey()
		token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
			CustomerID:     "cust_acme",
			DeploymentID:   "prod-eu-1",
			Modules:        []string{"protection-pack-av", "internal-loop"},
			IssuedAt:       moduleEntitlementNow,
			MaintenanceEnd: me,
			Nonce:          nonce,
			ReleaseLines:   lines,
		}, moduleEntitlementNow)
		if err != nil {
			t.Fatalf("issue %s: %v", nonce, err)
		}
		verified, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
		if err != nil {
			t.Fatalf("verify %s: %v", nonce, err)
		}
		return verified
	}

	// Mirror: paid term running, line already dead.
	mirror := issueWith(t, "cross-mirror-0001", moduleEntitlementNow.Add(90*24*time.Hour), []ReleaseLine{
		{Line: "1.3", SupportEnd: moduleEntitlementNow.Add(-24 * time.Hour), CriticalFixes: true},
	})
	if !mirror.UpdatesEntitledAt(moduleEntitlementNow) {
		t.Fatal("fixture precondition lost: the paid term must be running in the mirror row")
	}
	if mirror.CriticalFixEntitledAt("1.3", moduleEntitlementNow) {
		t.Fatal("a dead release line must stay dead inside a paid term — the I25 exception flows forward only")
	}
	if !mirror.HasModule("protection-pack-av") || !mirror.HasModule("internal-loop") {
		t.Fatal("the run right must be untouched by the dead line")
	}

	// Aligned inclusive boundaries: support end == maintenance end.
	edge := moduleEntitlementNow.Add(30 * 24 * time.Hour)
	aligned := issueWith(t, "cross-aligned-0001", edge, []ReleaseLine{
		{Line: "1.4", SupportEnd: edge, CriticalFixes: true},
	})
	if !aligned.UpdatesEntitledAt(edge) || !aligned.CriticalFixEntitledAt("1.4", edge) {
		t.Fatal("at the shared boundary instant both term rights must be included (inclusive)")
	}
	if aligned.UpdatesEntitledAt(edge.Add(time.Nanosecond)) || aligned.CriticalFixEntitledAt("1.4", edge.Add(time.Nanosecond)) {
		t.Fatal("past the shared boundary instant both term rights must end in lockstep")
	}

	// Per-line independence at one instant.
	multi := issueWith(t, "cross-multi-0001", moduleEntitlementNow.Add(365*24*time.Hour), []ReleaseLine{
		{Line: "1.5", SupportEnd: moduleEntitlementNow.Add(90 * 24 * time.Hour), CriticalFixes: true},
		{Line: "1.3", SupportEnd: moduleEntitlementNow.Add(-24 * time.Hour), CriticalFixes: true},
		{Line: "1.2", SupportEnd: moduleEntitlementNow.Add(90 * 24 * time.Hour), CriticalFixes: false},
	})
	at := moduleEntitlementNow.Add(24 * time.Hour)
	if !multi.CriticalFixEntitledAt("1.5", at) {
		t.Fatal("supported flagged line must be entitled to critical fixes")
	}
	if multi.CriticalFixEntitledAt("1.3", at) {
		t.Fatal("expired flagged line must fail closed at the same instant")
	}
	if multi.CriticalFixEntitledAt("1.2", at) {
		t.Fatal("supported but unflagged line must fail closed at the same instant")
	}
	if multi.CriticalFixEntitledAt("0.9", at) {
		t.Fatal("unknown line must fail closed at the same instant")
	}

	// Historical support window: document accepted; entitled through the
	// exact closure instant (inclusive, like every term boundary), then
	// fail-closed from closure+1ns onward — including at issuance and in the
	// future, where the window is already over.
	hist := issueWith(t, "cross-historical-0001", moduleEntitlementNow.Add(365*24*time.Hour), []ReleaseLine{
		{Line: "1.0", SupportEnd: moduleEntitlementNow.Add(-24 * time.Hour), CriticalFixes: true},
	})
	for _, at := range []time.Time{
		moduleEntitlementNow.Add(-25 * time.Hour), // inside the still-open window
		moduleEntitlementNow.Add(-24 * time.Hour), // closure instant: inclusive
	} {
		if !hist.CriticalFixEntitledAt("1.0", at) {
			t.Fatalf("historical window must stay entitled through %v (inclusive closure, pure instant predicate)", at)
		}
	}
	for _, at := range []time.Time{
		moduleEntitlementNow.Add(-24 * time.Hour).Add(time.Nanosecond),
		moduleEntitlementNow, // already over at issuance
		moduleEntitlementNow.Add(90 * 24 * time.Hour),
	} {
		if hist.CriticalFixEntitledAt("1.0", at) {
			t.Fatalf("historical line must grant no critical fixes at %v — fail-closed from closure+1ns onward", at)
		}
	}
}

// TestBoundary_DuplicateModuleEntriesAreInert pins the signed module-list
// boundary: a duplicate module id is legal-but-inert — it cannot enlarge the
// grant set, so membership stays exact-match and nothing ungranted appears.
// The contrast is deliberate and shipped: duplicate RELEASE LINES are
// structurally rejected (pinned by the T03 verify-structural table) because
// a duplicated line id could carry conflicting windows; a duplicated MODULE
// id cannot conflict, and the verifier does not pretend otherwise.
func TestBoundary_DuplicateModuleEntriesAreInert(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	payload, err := json.Marshal(map[string]any{
		"v": ModuleEntitlementVersion, "c": "cust_acme", "d": "prod-eu-1",
		"m":  []string{"internal-loop", "internal-loop"},
		"i":  moduleEntitlementNow.Format(time.RFC3339),
		"me": moduleEntitlementNow.Add(24 * time.Hour).Format(time.RFC3339),
		"n":  "dup-modules-0001",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ent, err := VerifyPaidModuleEntitlement(boundarySignRaw(t, priv, payload), pub, "prod-eu-1")
	if err != nil {
		t.Fatalf("duplicate module entry must verify (legal-but-inert): %v", err)
	}
	if len(ent.Modules) != 2 {
		t.Fatalf("signed list must round trip byte-faithfully: %v, want 2 entries", ent.Modules)
	}
	if !ent.HasModule("internal-loop") {
		t.Fatal("the duplicated module must be granted")
	}
	if ent.HasModule("media-persistence") || ent.HasModule("") {
		t.Fatal("duplicate entries must not widen the grant surface")
	}
}

// TestBoundary_VerifyRepeatableSameResult pins verification determinism
// under repetition at the data layer — the contract the recovery corpus
// (T08 wiring) relies on: the same token verifies to the same grant, again
// and again, forever. Verification is a pure function of its three inputs;
// nothing is consumed.
func TestBoundary_VerifyRepeatableSameResult(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop", "media-persistence"},
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(30 * 24 * time.Hour),
		TrialEnd:       moduleEntitlementNow.Add(7 * 24 * time.Hour),
		Nonce:          "repeat-0001",
		ReleaseLines: []ReleaseLine{
			{Line: "1.4", SupportEnd: moduleEntitlementNow.Add(240 * 24 * time.Hour), CriticalFixes: true},
		},
	}, moduleEntitlementNow)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var first PaidModuleEntitlement
	for i := 0; i < 3; i++ {
		ent, err := VerifyPaidModuleEntitlement(token, pub, "prod-eu-1")
		if err != nil {
			t.Fatalf("verify repetition %d: %v", i, err)
		}
		if i == 0 {
			first = ent
			continue
		}
		if ent.Nonce != first.Nonce || ent.DeploymentID != first.DeploymentID ||
			len(ent.Modules) != len(first.Modules) ||
			!ent.IssuedAt.Equal(first.IssuedAt) || !ent.MaintenanceEnd.Equal(first.MaintenanceEnd) ||
			!ent.TrialEnd.Equal(first.TrialEnd) ||
			len(ent.ReleaseLines) != len(first.ReleaseLines) ||
			ent.ReleaseLines[0].Line != first.ReleaseLines[0].Line ||
			!ent.ReleaseLines[0].SupportEnd.Equal(first.ReleaseLines[0].SupportEnd) {
			t.Fatalf("verify repetition %d drifted from the first result: %+v vs %+v", i, ent, first)
		}
		if ent.UpdatesEntitledAt(moduleEntitlementNow.Add(24*time.Hour)) != first.UpdatesEntitledAt(moduleEntitlementNow.Add(24*time.Hour)) ||
			ent.HasModule("internal-loop") != first.HasModule("internal-loop") ||
			ent.TrialActiveAt(moduleEntitlementNow.Add(time.Hour)) != first.TrialActiveAt(moduleEntitlementNow.Add(time.Hour)) {
			t.Fatalf("predicate repetition %d drifted — verification must be a pure function of its inputs", i)
		}
	}
}
