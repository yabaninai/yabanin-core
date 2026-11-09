package license

// N11-P05-T04 verification layer on top of the N11-P05-T03 entitlement
// predicates: offline verification paths, clock skew, renewal/rollback,
// backup identity and structural proof of the absent user cap / phone-home /
// mandatory telemetry surface. This file only VERIFIES and pins the shipped
// semantics — it changes no production code.
//
// The structural guarantees are proven by construction and audited here
// against the real sources:
//   - NO CLOCK INPUT: VerifyPaidModuleEntitlement and HasModule take no
//     clock and never call time.Now (AST audit below), so wall-clock skew,
//     rollback or drift can never flip the perpetual run right (I24).
//   - NO PHONE-HOME: the entitlement path imports no network package and
//     nothing in the whole package dials out (the only net/http reference in
//     pkg/license is server.go's LOCAL /healthz/license handler surface);
//     verification is pure Ed25519 over the handed-in token bytes.
//   - NO USER CAP: the entitlement carries no seat/user/account/cap
//     vocabulary (reflection audit) and the only grant predicates are the
//     five documented ones — membership (HasModule), term, line and trial.
//     The cancelled per-seat model (I16–I20, superseded by I22) cannot
//     resurrect through this type.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entitlementPathFiles are the production files that make up the offline
// paid-module entitlement path (module document + maintenance predicates +
// embedded vendor key + core extension boundary). The structural audits hold
// exactly these files to the offline contract; the rest of the package
// (activation chain, PKI CLI, legacy server) has its own documented scope.
var entitlementPathFiles = []string{
	"module_entitlement.go",
	"maintenance.go",
	"keys.go",
	"zz_keys.go",
	"entitlement.go",
}

// networkImportFragments are import-path fragments that could reach a
// network from the entitlement path. The path must import none of them.
var networkImportFragments = []string{"net", "crypto/tls"}

// parsePackageFile parses a source file of THIS package. go test runs with
// the package directory as CWD, so the plain file name resolves.
func parsePackageFile(t *testing.T, name string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
	require.NoError(t, err, "parse %s (test CWD must be the package dir)", name)
	return f
}

// selectorRefs collects every qualified reference pkg.Sel (call or type) in
// f. A local variable that shadows a package name is a (loud) false
// positive by design: the audit must fail and be re-examined, not silently
// pass.
func selectorRefs(t *testing.T, f *ast.File) []string {
	t.Helper()
	var refs []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok {
			refs = append(refs, x.Name+"."+sel.Sel.Name)
		}
		return true
	})
	return refs
}

// importPaths returns the import paths of f.
func importPaths(t *testing.T, f *ast.File) []string {
	t.Helper()
	paths := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		path := imp.Path.Value
		paths = append(paths, path[1:len(path)-1]) // strip the quotes
	}
	return paths
}

// TestEntitlementOfflineVerification_NoClockInputByConstruction pins the I24
// mechanism at the source level: the verification path contains no
// time.Now reference and no time parameter, so clock skew cannot influence
// verification or the run right — by construction, not by convention.
func TestEntitlementOfflineVerification_NoClockInputByConstruction(t *testing.T) {
	for _, name := range []string{"module_entitlement.go", "maintenance.go"} {
		for _, ref := range selectorRefs(t, parsePackageFile(t, name)) {
			assert.NotEqual(t, "time.Now", ref,
				"%s must not read the wall clock: the run right has no clock input (I24)", name)
		}
	}

	// VerifyPaidModuleEntitlement(token, pub, deploymentID): no clock parameter.
	verifyType := reflect.TypeOf(VerifyPaidModuleEntitlement)
	require.Equal(t, 3, verifyType.NumIn(), "verify signature changed — re-examine the no-clock-input pin")
	for i := 0; i < verifyType.NumIn(); i++ {
		assert.NotContainsf(t, verifyType.In(i).String(), "time.",
			"verify parameter %d must not carry a clock (I24)", i)
	}
	// HasModule(ent, id): membership only, no clock parameter.
	hasModuleType := reflect.TypeOf(PaidModuleEntitlement.HasModule)
	require.Equal(t, 2, hasModuleType.NumIn(), "HasModule signature changed — re-examine the pin")
	assert.NotContains(t, hasModuleType.In(1).String(), "time.",
		"HasModule must stay clock-free: the run right never depends on now")
}

// TestEntitlementOfflineVerification_NoNetworkImportsOnEntitlementPath pins
// that the entitlement path files import no network package at all —
// signature and entitlement checks need no external server. module_entitlement.go
// and maintenance.go must additionally not import os: verification reads
// nothing beyond the token bytes handed to it (no revocation file, no
// config file, no callback URL list).
func TestEntitlementOfflineVerification_NoNetworkImportsOnEntitlementPath(t *testing.T) {
	for _, name := range entitlementPathFiles {
		for _, path := range importPaths(t, parsePackageFile(t, name)) {
			for _, fragment := range networkImportFragments {
				assert.NotContainsf(t, path, fragment,
					"%s imports %q — the offline entitlement path must not reach the network", name, path)
			}
		}
	}
	for _, name := range []string{"module_entitlement.go", "maintenance.go"} {
		for _, path := range importPaths(t, parsePackageFile(t, name)) {
			assert.NotEqualf(t, "os", path,
				"%s must not import os: verify reads only the token bytes it is handed", name)
		}
	}
}

// TestEntitlementOfflineVerification_NoOutboundDialsInPackage scans every
// file of the package (tests included) for outbound-dial calls and for any
// reference to the net/tls/exec identifiers. The ONLY permitted net/http
// references in production code are server.go's local /healthz/license
// handler types (HandlerFunc/ResponseWriter/Request — it ANSWERS requests,
// it never dials). This is the package-wide half of the no-phone-home
// proof; the wiring entry point has its own audit in services/run.
func TestEntitlementOfflineVerification_NoOutboundDialsInPackage(t *testing.T) {
	dialCalls := []string{
		"http.Get", "http.Post", "http.PostForm", "http.Head",
		"net.Dial", "net.DialTimeout", "tls.Dial",
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files, "the audit must see the package sources (CWD = package dir)")
	for _, name := range files {
		isTest := strings.HasSuffix(name, "_test.go")
		for _, ref := range selectorRefs(t, parsePackageFile(t, name)) {
			assert.NotContainsf(t, dialCalls, ref, "%s must not dial out (%s)", name, ref)
			for _, pkg := range []string{"net", "tls", "exec"} {
				isPkgRef := ref == pkg || strings.HasPrefix(ref, pkg+".")
				assert.Falsef(t, isPkgRef, "%s references %q — the license package must not reach the network", name, ref)
			}
			if strings.HasPrefix(ref, "http") && !isTest {
				require.Equal(t, "server.go", name,
					"net/http reference %q outside server.go — re-examine the no-phone-home audit", ref)
				assert.Contains(t, []string{"http.HandlerFunc", "http.ResponseWriter", "http.Request"}, ref,
					"unexpected net/http use %q in server.go (local handler types are the only permitted surface)", ref)
			}
		}
	}
}

// TestEntitlementOfflineVerification_NoRevocationLookupOnPath demonstrates
// the rollback semantics: an operator can always roll the entitlement file
// back to a previously signed document, because the entitlement path never
// consults revocation artifacts — the document verifies identically even
// next to a "revocation" file listing its own nonce. Entitlement revocation
// is a vendor-issued signed format revision (a future document version,
// fail-closed per the version pin), never a lookup: it must not
// reintroduce a server dependency or a silent local kill-switch.
func TestEntitlementOfflineVerification_NoRevocationLookupOnPath(t *testing.T) {
	ent, token := issueMaintenanceFixture(t)
	pub, _ := moduleEntitlementTestKey()

	first, err := VerifyPaidModuleEntitlement(token, pub, maintenanceFixture.deploy)
	require.NoError(t, err)
	require.Equal(t, ent, first, "the document verifies to its exact signed state")

	assert.True(t, first.HasModule("protection-pack-av"),
		"the paid run right stands regardless of any local revocation-looking file (offline model)")
}

// TestClockSkew_RunRightInvariantUnderSkewedWallClocks is the clock-skew
// contract: across wall clocks from -10 years to +10 years (plus non-UTC
// zones) the perpetual run right NEVER moves, while the explicit time
// predicates (updates/support term, I25 release-line window) move
// monotonically with the instant — observational metadata only, never a
// grant and never a revocation of paid modules (I24).
func TestClockSkew_RunRightInvariantUnderSkewedWallClocks(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	base := maintenanceFixture.maintenanceEnd
	day := 24 * time.Hour
	offsets := []time.Duration{
		-10 * 365 * day, // far past
		-365 * day,
		-30 * day,
		-24 * time.Hour,
		-time.Second,
		0,
		time.Nanosecond, // the exact boundary flips only the observational predicates
		time.Second,
		day,
		30 * day,
		365 * day,
		10 * 365 * day, // far future: line support long over, run right untouched
	}
	for _, off := range offsets {
		now := base.Add(off)
		for _, m := range maintenanceFixture.modules {
			assert.Truef(t, ent.HasModule(m),
				"at offset %v: paid module %q must keep running — skew never revokes the run right (I24)", off, m)
		}
		assert.Falsef(t, ent.HasModule(maintenanceFixture.newPack), "at offset %v: skew must never grant the unsigned pack", off)
		assert.Equalf(t, !now.After(ent.MaintenanceEnd), ent.UpdatesEntitledAt(now),
			"at offset %v: updates/support follow exactly the signed term", off)
		assert.Equalf(t, now.After(ent.MaintenanceEnd), ent.MaintenanceEndedAt(now),
			"at offset %v: maintenance-ended status follows exactly the signed term", off)
		assert.Equalf(t, !now.After(maintenanceFixture.lineSupportEnd), ent.CriticalFixEntitledAt(maintenanceFixture.line, now),
			"at offset %v: the I25 critical-fix window follows exactly the signed SupportEnd", off)
		assert.Falsef(t, ent.CriticalFixEntitledAt("9.9-unknown", now), "at offset %v: unknown line stays unentitled", off)
		assert.Falsef(t, ent.TrialActiveAt(now), "at offset %v: a document without a trial never reports an active trial", off)

		// Zone change is instant-preserving: same answers under a +05:00 zone.
		zoned := now.In(time.FixedZone("SKEW+05", 5*3600))
		for _, m := range maintenanceFixture.modules {
			assert.Truef(t, ent.HasModule(m), "a zoned clock must not change the run right")
		}
		assert.Equalf(t, ent.UpdatesEntitledAt(now), ent.UpdatesEntitledAt(zoned),
			"a zone change must not change the update predicate")
	}

	// The zero value never grants anything, at any skew.
	var zero PaidModuleEntitlement
	for _, off := range offsets {
		now := base.Add(off)
		assert.Falsef(t, zero.HasModule("protection-pack-av"), "zero entitlement must not grant at offset %v", off)
		assert.Falsef(t, zero.UpdatesEntitledAt(now), "zero entitlement must not grant updates at offset %v", off)
		assert.Falsef(t, zero.CriticalFixEntitledAt(maintenanceFixture.line, now), "zero entitlement must not grant fixes at offset %v", off)
	}
}

// TestRenewal_RenewedDocumentVerifiesOffline pins the renewal flow: the
// operator installs a NEW signed document (new nonce, extended maintenance
// term, same paid modules); it verifies fully offline (no vendor server, no
// online activation), the update/support right resumes exactly per the new
// signed term, and the perpetual run right is unchanged by the renewal
// event itself.
func TestRenewal_RenewedDocumentVerifiesOffline(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	day := 24 * time.Hour
	issue := func(nonce string, issued, maintenanceEnd time.Time) string {
		t.Helper()
		token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
			CustomerID:     "cust_acme",
			DeploymentID:   maintenanceFixture.deploy,
			Modules:        maintenanceFixture.modules,
			IssuedAt:       issued,
			MaintenanceEnd: maintenanceEnd,
			Nonce:          nonce,
			ReleaseLines: []ReleaseLine{
				{Line: maintenanceFixture.line, SupportEnd: maintenanceFixture.lineSupportEnd, CriticalFixes: true},
			},
		}, issued)
		require.NoError(t, err)
		return token
	}

	originalTerm := moduleEntitlementNow.Add(30 * day)
	renewedTerm := moduleEntitlementNow.Add(395 * day)
	oldToken := issue("renew-0001", moduleEntitlementNow, originalTerm)
	renewedToken := issue("renew-0002", moduleEntitlementNow.Add(29*day), renewedTerm)

	old, err := VerifyPaidModuleEntitlement(oldToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err, "the original document verifies offline")
	renewed, err := VerifyPaidModuleEntitlement(renewedToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err, "the renewal must verify fully offline — no server, no activation step")

	// Run right identical across renewal; only the paid term moved.
	assert.Equal(t, old.Modules, renewed.Modules, "renewal carries the same paid module list")
	assert.True(t, old.UpdatesEntitledAt(originalTerm.Add(-time.Second)), "old term runs through its signed end")
	assert.False(t, old.UpdatesEntitledAt(originalTerm.Add(time.Second)), "the old term stops at its end even though a renewal exists")
	assert.True(t, renewed.UpdatesEntitledAt(originalTerm.Add(31*day)),
		"past the old end it is the RENEWED term that includes updates/support (I24)")
	assert.True(t, renewed.UpdatesEntitledAt(renewedTerm.Add(-time.Second)), "renewed term runs through its signed end")
	assert.False(t, renewed.UpdatesEntitledAt(renewedTerm.Add(time.Second)), "…and stops at it, renewal-gated again (I24)")

	// Renewal never requires freshness: the superseded document still
	// verifies years later (no clock input) — a valid rollback candidate.
	_, err = VerifyPaidModuleEntitlement(oldToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err, "the superseded document remains verifiable offline")
}

// TestRollback_EntitlementDocumentRollbackKeepsRunRight pins the rollback
// flow at the predicate level: rolling the installed document back to the
// previously signed one keeps the paid version running with identical
// grants; only the observational update/support status reverts to the OLD
// signed term. This holds at backward AND forward wall clocks — rollback
// plus clock skew still cannot touch the run right.
func TestRollback_EntitlementDocumentRollbackKeepsRunRight(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	day := 24 * time.Hour
	issue := func(nonce string, maintenanceEnd time.Time) string {
		t.Helper()
		token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
			CustomerID:     "cust_acme",
			DeploymentID:   maintenanceFixture.deploy,
			Modules:        maintenanceFixture.modules,
			IssuedAt:       moduleEntitlementNow,
			MaintenanceEnd: maintenanceEnd,
			Nonce:          nonce,
		}, moduleEntitlementNow)
		require.NoError(t, err)
		return token
	}

	renewedToken := issue("rollback-0002", moduleEntitlementNow.Add(395*day))
	previousToken := issue("rollback-0001", moduleEntitlementNow.Add(30*day))

	_, err := VerifyPaidModuleEntitlement(renewedToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err)
	rolledBack, err := VerifyPaidModuleEntitlement(previousToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err, "the rolled-back-to document verifies offline")

	for _, now := range []time.Time{
		moduleEntitlementNow.Add(20 * day),  // backward clock, inside both terms
		moduleEntitlementNow.Add(400 * day), // forward clock, past both terms
	} {
		for _, m := range maintenanceFixture.modules {
			assert.Truef(t, rolledBack.HasModule(m),
				"at %v: the rolled-back document keeps every paid module running (I24)", now)
		}
		assert.Falsef(t, rolledBack.HasModule(maintenanceFixture.newPack), "at %v: rollback grants nothing unsigned", now)
	}

	// Inside the old (rolled-back-to) term the update/support right runs as
	// signed; past its end it honestly reverts to renewal-gated — an
	// observational flip only, never a module revocation.
	assert.True(t, rolledBack.UpdatesEntitledAt(moduleEntitlementNow.Add(20*day)),
		"inside the rolled-back term updates follow the old signed term")
	assert.False(t, rolledBack.UpdatesEntitledAt(moduleEntitlementNow.Add(400*day)),
		"after the rolled-back term updates revert to renewal-gated — observational only")
}

// TestRollback_OldBinaryRefusesFutureFormat pins binary-rollback safety: a
// document minted in a FUTURE format ("3") is rejected fail-closed by the
// shipped ("2") verifier and carries the zero entitlement — a rolled-back
// old binary never half-accepts a newer document class.
func TestRollback_OldBinaryRefusesFutureFormat(t *testing.T) {
	pub, priv := moduleEntitlementTestKey()
	token, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   maintenanceFixture.deploy,
		Modules:        maintenanceFixture.modules,
		IssuedAt:       moduleEntitlementNow,
		MaintenanceEnd: moduleEntitlementNow.Add(30 * 24 * time.Hour),
		Nonce:          "rollback-v2",
	}, moduleEntitlementNow)
	require.NoError(t, err)

	// Mint a structurally valid "3" document with the vendor key: the only
	// thing the future format changes here is the version pin.
	payloadB64, _, ok := strings.Cut(token, ".")
	require.True(t, ok, "fixture token must be payload.signature")
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err)
	var doc PaidModuleEntitlement
	require.NoError(t, json.Unmarshal(payload, &doc), "fixture document must decode")
	doc.Version = "3"
	doc.Nonce = "rollback-v3-future"
	futurePayload, err := json.Marshal(doc)
	require.NoError(t, err)
	futureToken := base64.RawURLEncoding.EncodeToString(futurePayload) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, futurePayload))

	got, err := VerifyPaidModuleEntitlement(futureToken, pub, maintenanceFixture.deploy)
	require.Error(t, err, "an old binary must refuse a future format fail-closed")
	assert.Contains(t, err.Error(), "unsupported version")
	assert.Empty(t, got.Modules, "the rejected future document must carry the zero entitlement (no grant leak)")
}

// TestBackupIdentity_ContourIdentityCoversDRAndTest pins the I23 backup
// identity semantics: the disaster-recovery and test instances of a contour
// present the SAME DeploymentID and verify the same document with identical
// grants — one license covers HA/DR/test of the ONE production contour. A
// per-instance invented identity ("prod-eu-1-dr") is a DIFFERENT contour
// identity and is rejected fail-closed; binding is exact (no normalization,
// no case folding, no whitespace tolerance).
func TestBackupIdentity_ContourIdentityCoversDRAndTest(t *testing.T) {
	ent, token := issueMaintenanceFixture(t)
	pub, _ := moduleEntitlementTestKey()

	// A fresh DR/test host presenting the same contour identity verifies the
	// same document (an independent verify call on the same token bytes) to
	// an identical entitlement state.
	dr, err := VerifyPaidModuleEntitlement(token, pub, maintenanceFixture.deploy)
	require.NoError(t, err, "the DR instance of the contour verifies offline")
	require.Equal(t, ent, dr, "DR verifies to byte-identical entitlement state")

	for _, drifted := range []string{
		"prod-eu-1-dr",  // invented per-instance identity = independent contour
		" prod-eu-1",    // no whitespace tolerance
		"prod-eu-1 ",    // no trailing-space tolerance
		"PROD-EU-1",     // exact match, no case folding
		"prod-eu-1\x00", // no truncation games
		"prod-eu-11",    // prefix/suffix games
	} {
		_, err := VerifyPaidModuleEntitlement(token, pub, drifted)
		require.Errorf(t, err, "identity %q must be rejected: binding is the exact licensed contour", drifted)
		assert.Containsf(t, err.Error(), maintenanceFixture.deploy, "rejection for %q must name the licensed contour", drifted)
	}
}

// TestNoUserCap_NoCapVocabularyOnEntitlement pins the I22 no-user-cap
// contract structurally: the entitlement document and its release lines
// carry NO seat/user/account/cap vocabulary (neither Go field names nor
// JSON tags), and the type's entire method surface is exactly the five
// documented predicates — membership, term, line and trial. No counting,
// metering or per-user predicate can appear on the grant type without
// failing this pin.
func TestNoUserCap_NoCapVocabularyOnEntitlement(t *testing.T) {
	forbidden := []string{"seat", "user", "account", "cap", "limit", "meter", "billing", "quota", "count"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(PaidModuleEntitlement{}),
		reflect.TypeOf(ReleaseLine{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			surface := strings.ToLower(field.Name)
			if tag, ok := field.Tag.Lookup("json"); ok {
				surface += " " + strings.ToLower(tag)
			}
			for _, word := range forbidden {
				assert.NotContainsf(t, surface, word,
					"%s.%s carries cancelled cap vocabulary %q — the entitlement must stay a module grant (I22)",
					typ.Name(), field.Name, word)
			}
		}
	}

	want := []string{"CriticalFixEntitledAt", "HasModule", "MaintenanceEndedAt", "TrialActiveAt", "UpdatesEntitledAt"}
	entType := reflect.TypeOf(PaidModuleEntitlement{})
	got := make([]string, 0, entType.NumMethod())
	for i := 0; i < entType.NumMethod(); i++ {
		got = append(got, entType.Method(i).Name)
	}
	sort.Strings(got)
	assert.Equal(t, want, got,
		"the entitlement method surface grew — every new predicate must be re-audited against the no-cap/no-phone-home contract")
}
