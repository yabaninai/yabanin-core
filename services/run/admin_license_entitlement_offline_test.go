package run

// N11-P05-T04 verification layer at the admin entry point seam, on top of
// the N11-P05-T03 wiring tests: renewal and document rollback as pure
// offline file swaps, backup contour identity (I23), the local-sink-only
// status report (no mandatory telemetry), and a source audit of the wiring
// file itself (no phone-home surface, no clock on the enforcement path).
// No production code is changed; every pin verifies shipped behavior.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/license"
)

// TestModuleEntitlementOffline_RenewalAndRollbackAtEntryPoint pins the
// renewal and rollback flows at the entry point: BOTH are pure local file
// swaps plus a restart of the resolve path — no vendor server, no online
// activation step. The renewed document extends the paid term; rolling back
// to the previous document keeps every paid module running (I24) and only
// the observational update status reverts to the old signed term.
func TestModuleEntitlementOffline_RenewalAndRollbackAtEntryPoint(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	modules := []string{"protection-pack-av", "internal-loop"}
	originalPath := writeEntitlementToken(t, priv, modules, now.Add(-time.Hour), now.Add(30*day))
	renewedPath := writeEntitlementToken(t, priv, modules, now.Add(-time.Hour), now.Add(395*day))
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	// Original term: updates run through the signed end only.
	t.Setenv(licenseModuleEntitlementFileEnv, originalPath)
	primary, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, primary)
	assert.True(t, primary.UpdatesEntitledAt(now), "inside the paid term updates are included")
	assert.False(t, primary.UpdatesEntitledAt(now.Add(31*day)), "past the original term updates turn renewal-gated")

	// Renewal: the operator installs the new signed document — a file swap,
	// nothing else. It resolves fully offline.
	t.Setenv(licenseModuleEntitlementFileEnv, renewedPath)
	renewed, err := resolveModuleEntitlement()
	require.NoError(t, err, "renewal must be a pure offline file swap — no server step at the entry point")
	require.NotNil(t, renewed)
	assert.Equal(t, primary.Modules, renewed.Modules, "renewal carries the same paid module list")
	assert.True(t, renewed.UpdatesEntitledAt(now.Add(31*day)),
		"the renewed term covers the window past the old end (I24)")

	// Rollback: the operator restores the previous document — equally
	// offline. Paid modules keep running; only the update status honestly
	// reverts to the old signed term (observational, never an enforcement
	// failure and never a lost module).
	t.Setenv(licenseModuleEntitlementFileEnv, originalPath)
	rolledBack, err := resolveModuleEntitlement()
	require.NoError(t, err, "rolling back to the previous document must resolve offline")
	require.NotNil(t, rolledBack)
	assert.Equal(t, primary.Modules, rolledBack.Modules, "rollback keeps every paid module running (I24)")
	assert.True(t, rolledBack.HasModule("internal-loop"), "rollback never revokes a paid module")
	assert.False(t, rolledBack.UpdatesEntitledAt(now.Add(31*day)),
		"rollback reverts the update status to the old signed term — observational only")
}

// TestModuleEntitlementOffline_BackupIdentityAndContourDrift pins I23 at the
// entry point: the disaster-recovery/test instance of the contour presents
// the SAME deployment identity and resolves the SAME document to
// byte-identical grants. Whitespace around the env value is operator-config
// noise, not identity (the signed document still binds the exact contour,
// so trimming cannot alias an independent contour); semantic identity drift
// is rejected fail-closed.
func TestModuleEntitlementOffline_BackupIdentityAndContourDrift(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	tokenPath := writeEntitlementToken(t, priv,
		[]string{"internal-loop", "media-persistence"}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	t.Setenv(licenseModuleEntitlementFileEnv, tokenPath)

	// Primary contour.
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	primary, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, primary)

	// The DR/test instance: same identity (padded with config noise), fresh
	// resolve, identical entitlement state.
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "  prod-eu-1\t")
	dr, err := resolveModuleEntitlement()
	require.NoError(t, err, "the DR/test instance of the same contour resolves the same document (I23)")
	require.NotNil(t, dr)
	assert.Equal(t, primary, dr, "the backup instance verifies to byte-identical entitlement state")

	// Independent contours and drifted identities stay fail-closed.
	for _, drift := range []string{
		"PROD-EU-1",    // no case folding
		"prod-eu-1-dr", // an invented per-instance identity is its own contour
		"prod-eu-2",    // a different contour needs its own license
		"prod-eu-1\nx", // inner noise is not trimmable — no normalization games
		" prod-eu-11",  // prefix/suffix games
	} {
		t.Setenv(licenseModuleEntitlementDeploymentEnv, drift)
		ent, err := resolveModuleEntitlement()
		require.Errorf(t, err, "identity %q must be rejected: binding is the exact licensed contour", drift)
		assert.Nilf(t, ent, "no entitlement object may appear for drifted identity %q", drift)
		assert.Containsf(t, err.Error(), "prod-eu-1", "rejection for %q names the licensed contour", drift)
	}
}

// TestModuleEntitlementStatus_LocalSinkOnly pins the no-mandatory-telemetry
// contract for the startup report: logModuleEntitlementStatus writes ONLY to
// the handed-in slog logger — a local sink the operator owns and can point
// anywhere (or nowhere); it emits no network write, contains no endpoint,
// and a nil entitlement produces no output at all. The status is visible,
// offline-derived metadata (I24), never an enforcement input.
func TestModuleEntitlementStatus_LocalSinkOnly(t *testing.T) {
	ended := &license.PaidModuleEntitlement{
		DeploymentID:   "prod-eu-1",
		Modules:        []string{"internal-loop", "media-persistence"},
		MaintenanceEnd: time.Now().Add(-24 * time.Hour),
		TrialEnd:       time.Now().Add(24 * time.Hour),
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logModuleEntitlementStatus(logger, ended)

	out := buf.String()
	assert.Contains(t, out, "paid-module entitlement verified (offline)",
		"the report states the offline verification posture to the operator")
	assert.Contains(t, out, "deployment=prod-eu-1")
	assert.Contains(t, out, "modules=2", "the report counts MODULES, never users/seats (I22)")
	assert.Contains(t, out, "maintenance_ended=true")
	assert.Contains(t, out, "updates_entitled=false", "renewal status is reported, not enforced")
	assert.Contains(t, out, "trial_active=true", "the signed trial state is reported explicitly")
	assert.NotContains(t, out, "http", "no endpoint or callback can appear in the report — it stays a local log line")
	assert.Equal(t, 1, strings.Count(out, "paid-module entitlement verified"),
		"exactly one status record per call")

	// Nil entitlement: no output at all — an unconfigured contour stays silent.
	var silent bytes.Buffer
	logModuleEntitlementStatus(slog.New(slog.NewTextHandler(&silent, nil)), nil)
	assert.Empty(t, silent, "a nil entitlement must produce no status record")
}

// TestModuleEntitlementOffline_EntryPointSourceAudit_NoPhoneHomeNoTelemetry
// audits the REAL wiring source (admin_license_entitlement.go) so the
// offline posture is pinned to the file, not to a description of it:
//   - imports are exactly {fmt, log/slog, os, strings, time, license} — no
//     network, no exec, no observability stack;
//   - no selector reaches net/tls/exec/http and no string literal contains
//     a URL (no phone-home endpoint anywhere in the wiring);
//   - os usage is exactly two Getenv reads plus one local ReadFile;
//   - the license surface is exactly VendorPublicKey, VerifyPaidModuleEntitlement
//     and PaidModuleEntitlement — no legacy per-seat Claims type can re-enter
//     through the wiring (I22);
//   - the file has exactly the three shipped declarations (const block +
//     resolver + status report), so any new function must re-enter this audit;
//   - the enforcement path (resolveModuleEntitlement) contains NO time
//     reference — verification never consults a clock (I24); time exists
//     only inside the observational status report.
func TestModuleEntitlementOffline_EntryPointSourceAudit_NoPhoneHomeNoTelemetry(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "admin_license_entitlement.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err, "the wiring source must be parseable from the package dir")

	// Exact import set.
	var imports []string
	for _, imp := range f.Imports {
		path := imp.Path.Value
		imports = append(imports, path[1:len(path)-1])
	}
	sort.Strings(imports)
	assert.Equal(t, []string{
		"fmt",
		"github.com/reireirei/yabanin/pkg/license",
		"log/slog",
		"os",
		"strings",
		"time",
	}, imports, "the wiring import set changed — re-audit the offline posture before touching this pin")

	// Every qualified reference in the file.
	var refs []string
	var literals []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if x, ok := node.X.(*ast.Ident); ok {
				refs = append(refs, x.Name+"."+node.Sel.Name)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				literals = append(literals, node.Value)
			}
		}
		return true
	})

	for _, ref := range refs {
		for _, pkg := range []string{"net", "tls", "exec", "http"} {
			isPkgRef := ref == pkg || strings.HasPrefix(ref, pkg+".")
			assert.Falsef(t, isPkgRef,
				"the wiring references %q — the offline entitlement entry point must not reach the network", ref)
		}
	}
	for _, lit := range literals {
		assert.NotContainsf(t, lit, "http://", "URL literal in the wiring — no phone-home endpoint may exist")
		assert.NotContainsf(t, lit, "https://", "URL literal in the wiring — no phone-home endpoint may exist")
	}

	countRef := func(name string) int {
		count := 0
		for _, ref := range refs {
			if ref == name {
				count++
			}
		}
		return count
	}
	assert.Equal(t, 2, countRef("os.Getenv"), "the wiring reads exactly the two entitlement env vars")
	assert.Equal(t, 1, countRef("os.ReadFile"), "the wiring reads exactly one local file — the entitlement token")
	assert.Equal(t, 3, strings.Count(strings.Join(refs, " "), "os."),
		"os usage beyond Getenv×2 + ReadFile×1 appeared — re-audit the file boundary")
	assert.Equal(t, 1, countRef("license.VerifyPaidModuleEntitlement"))
	assert.Equal(t, 1, countRef("license.VendorPublicKey"))
	assert.Equal(t, 2, countRef("license.PaidModuleEntitlement"),
		"the return and report types — no other license symbol (e.g. legacy per-seat Claims) may appear (I22)")
	assert.Equal(t, 4, strings.Count(strings.Join(refs, " "), "license."),
		"the license surface grew — re-audit against the no-cap/no-phone-home contract")

	// Exactly the shipped declarations: import block, const block, resolver,
	// status report. Any new declaration must re-enter this audit.
	require.Len(t, f.Decls, 4, "the wiring gained a declaration — re-run this audit for it")
	require.IsType(t, &ast.FuncDecl{}, f.Decls[2])
	require.IsType(t, &ast.FuncDecl{}, f.Decls[3])
	assert.Equal(t, "resolveModuleEntitlement", f.Decls[2].(*ast.FuncDecl).Name.Name)
	assert.Equal(t, "logModuleEntitlementStatus", f.Decls[3].(*ast.FuncDecl).Name.Name)

	// Clock confinement: the enforcement path has no time reference; the
	// status report is the only clock consumer (observational).
	var resolverTimeRefs, statusTimeRefs []string
	ast.Inspect(f.Decls[2], func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" {
				resolverTimeRefs = append(resolverTimeRefs, sel.Sel.Name)
			}
		}
		return true
	})
	assert.Empty(t, resolverTimeRefs,
		"resolveModuleEntitlement must not consult a clock: verification is time-free (I24)")
	ast.Inspect(f.Decls[3], func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" {
				statusTimeRefs = append(statusTimeRefs, sel.Sel.Name)
			}
		}
		return true
	})
	assert.Contains(t, statusTimeRefs, "Now",
		"the status report derives the renewal state from a real instant — the only clock consumer in the wiring")
}
