package trcli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// NEXT-13: preflight is read-only and classifies checks honestly. These
// tests inject the environment so outcomes are deterministic.
func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		in   string
		min  [3]int
		want bool
	}{
		{"go version go1.26.6 darwin/arm64", [3]int{1, 26, 0}, true},
		{"go version go1.24.0 linux/amd64", [3]int{1, 26, 0}, false},
		{"v22.13.0", [3]int{22, 13, 0}, true},
		{"v22.12.9", [3]int{22, 13, 0}, false},
		{"Python 3.9.6", [3]int{3, 9, 0}, true},
		{"Python 3.8.1", [3]int{3, 9, 0}, false},
		{"no version here", [3]int{1, 0, 0}, false},
		{"v26.3.0", [3]int{22, 13, 0}, true},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.in, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q, %v) = %v, want %v", c.in, c.min, got, c.want)
		}
	}
}

func TestBuildPreflightChecks_Classification(t *testing.T) {
	// Everything broken: required fail, advisory warn.
	checks := buildPreflightChecks(struct {
		tool   func(bin string, args ...string) (string, bool, bool)
		tcp    func(addr string, d time.Duration) bool
		stat   func(path string) (os.FileInfo, error)
		getenv func(string) string
	}{
		func(string, ...string) (string, bool, bool) { return "", false, false },
		func(string, time.Duration) bool { return false },
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(string) string { return "" },
	})
	if len(checks) == 0 {
		t.Fatal("no checks produced")
	}
	requiredFails := 0
	for _, c := range checks {
		switch c.Severity {
		case severityRequired:
			if c.Status != "fail" {
				t.Errorf("required check %s: status %s, want fail", c.Name, c.Status)
			} else {
				requiredFails++
			}
			if c.Fix == "" {
				t.Errorf("required check %s must carry a fix hint", c.Name)
			}
		case severityAdvisory:
			if c.Status == "fail" {
				t.Errorf("advisory check %s must not fail hard", c.Name)
			}
		default:
			t.Errorf("unknown severity %q on %s", c.Severity, c.Name)
		}
	}
	if requiredFails != 4 {
		t.Errorf("required fails = %d, want 4 (go/node/python/docker)", requiredFails)
	}
}

func TestBuildPreflightChecks_SecretsNeverLeak(t *testing.T) {
	// A set key reports presence only — the value must not appear anywhere.
	const secret = "yb_SUPERSECRETVALUE"
	checks := buildPreflightChecks(struct {
		tool   func(bin string, args ...string) (string, bool, bool)
		tcp    func(addr string, d time.Duration) bool
		stat   func(path string) (os.FileInfo, error)
		getenv func(string) string
	}{
		func(string, ...string) (string, bool, bool) { return "", false, false },
		func(string, time.Duration) bool { return false },
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(k string) string {
			if k == "YABANIN_STAND_NEBIUS_KEY" {
				return secret
			}
			return ""
		},
	})
	for _, c := range checks {
		if c.Detail == secret || c.Fix == secret {
			t.Fatalf("secret value leaked in check output: %+v", c)
		}
	}
	found := false
	for _, c := range checks {
		if c.Name == "Nebius stand key (stand env)" && c.Status == "ok" {
			found = true
		}
	}
	if !found {
		t.Error("set key should report ok")
	}
}

// runPreflight/runBootstrap cores (NEXT-13 coverage): hermetic via injected
// probes and an output buffer.
func brokenProbes() preflightProbes {
	return preflightProbes{
		tool:   func(string, ...string) (string, bool, bool) { return "", false, false },
		tcp:    func(string, time.Duration) bool { return false },
		stat:   func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		getenv: func(string) string { return "" },
	}
}

func TestRunPreflight_RequiredFailures(t *testing.T) {
	var buf strings.Builder
	err := runPreflight(brokenProbes(), false, &buf)
	if err == nil {
		t.Fatal("broken environment must fail preflight")
	}
	if !strings.Contains(err.Error(), "4 required check(s) failed") {
		t.Errorf("want 4 required failures, got: %v", err)
	}
	if !strings.Contains(buf.String(), "✗") {
		t.Error("report must mark failures")
	}
}

func TestRunPreflight_JSON(t *testing.T) {
	var buf strings.Builder
	if err := runPreflight(brokenProbes(), true, &buf); err == nil {
		t.Fatal("json mode still reports required failures")
	}
	var checks []preflightCheck
	if err := json.Unmarshal([]byte(buf.String()), &checks); err != nil {
		t.Fatalf("json output invalid: %v", err)
	}
	if len(checks) != 10 {
		t.Errorf("json checks = %d, want 10", len(checks))
	}
}

func TestRunBootstrap_DryRunDefault(t *testing.T) {
	var buf strings.Builder
	if err := runBootstrap(false, &buf); err != nil {
		t.Fatalf("dry run must succeed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Dry run (no changes)") {
		t.Error("dry run must say so")
	}
	if !strings.Contains(out, "npm -g") && strings.Contains(out, "npm install -g") {
		t.Error("plan must never use npm -g")
	}
	for _, forbidden := range []string{"brew ", "npm install -g", "upgrade node"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("plan contains forbidden global-toolchain action: %q", forbidden)
		}
	}
	if len(bootstrapSteps()) != 8 {
		t.Errorf("steps = %d, want 8", len(bootstrapSteps()))
	}
	// TP-22: the plan shows the LOCKED installer (npm ci), never bare
	// `npm install` for packages with a committed lockfile.
	if !strings.Contains(out, "npm --prefix web/dashboard ci") {
		t.Error("plan must use npm ci for locked packages")
	}
	for _, s := range bootstrapSteps() {
		if strings.HasSuffix(s.cmd, " install") && strings.HasPrefix(s.cmd, "npm --prefix") {
			t.Errorf("locked package must install via npm ci, got %q", s.cmd)
		}
	}
}

// --- TP-22: bootstrap respects locked npm installation. ---

// fixtureNpmApp writes a minimal app with package.json + package-lock.json
// under <root>/app; bootstrap runs `npm --prefix app ci` against it, never
// touching the main tree.
func fixtureNpmApp(t *testing.T, root, pkgJSON, lockJSON string) {
	t.Helper()
	app := filepath.Join(root, "app")
	if err := os.MkdirAll(app, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "package-lock.json"), []byte(lockJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapNpmCiLockedAndDesynced(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not in PATH")
	}
	const syncedPkg = `{"name":"fixture-app","version":"1.0.0","dependencies":{}}`
	const syncedLock = `{"name":"fixture-app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"fixture-app","version":"1.0.0"}}}`
	// Desync: package.json demands left-pad, the lockfile never recorded it.
	const desyncPkg = `{"name":"fixture-app","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}`

	run := func(pkgJSON string) (string, string, string, error) {
		root := t.TempDir()
		writeFixtureRegistry(t, root, []string{"npm --prefix app ci"})
		fixtureNpmApp(t, root, pkgJSON, syncedLock)
		steps, err := bootstrapStepsFromRegistry(filepath.Join(root, "scripts", "quality", "commands.json"))
		if err != nil {
			t.Fatal(err)
		}
		var buf strings.Builder
		err = executeBootstrap(steps, root, true, &buf)
		pkg, _ := os.ReadFile(filepath.Join(root, "app", "package.json"))       //nolint:gosec // G304: fixture path built from t.TempDir
		lock, _ := os.ReadFile(filepath.Join(root, "app", "package-lock.json")) //nolint:gosec // G304: fixture path built from t.TempDir
		return string(pkg), string(lock), buf.String(), err
	}

	// Synced lockfile: installs clean, package/lock untouched.
	pkg, lock, out, err := run(syncedPkg)
	if err != nil {
		t.Fatalf("synced lockfile must install: %v\n%s", err, out)
	}
	if pkg != syncedPkg || lock != syncedLock {
		t.Error("npm ci must not modify package.json or the lockfile")
	}

	// Desynced lockfile: loud failure — that is the point of npm ci.
	_, _, out, err = run(desyncPkg)
	if err == nil {
		t.Fatalf("desynced lockfile must fail, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "step failed") {
		t.Errorf("failure must surface as a step failure, got: %v", err)
	}
}

func TestToolVersionProbes(t *testing.T) {
	if v, found, ran := toolVersion("go", "version"); !found || !ran || !strings.Contains(v, "go version") {
		t.Errorf("go probe = (%q, %v, %v), want version string", v, found, ran)
	}
	if _, found, _ := toolVersion("yb-definitely-missing-bin-xyz"); found {
		t.Error("missing binary must not resolve")
	}
	// TP-20: a present binary whose probe fails is found-but-not-ran — the
	// resolved path must NOT be returned in place of a version (that is how
	// a down docker daemon used to pass as "ok").
	if v, found, ran := toolVersion("go", "--definitely-bogus-flag"); !found || ran || v != "" {
		t.Errorf("failing probe = (%q, %v, %v), want present-but-failed with no output", v, found, ran)
	}
}

// TP-20 acceptance: docker daemon is required, and the three outcomes are
// distinct — missing binary, present-but-failing probe, healthy daemon.
func TestPreflightDockerProbeTriState(t *testing.T) {
	dockerProbe := func(out string, found, ran bool) []preflightCheck {
		return buildPreflightChecks(struct {
			tool   func(bin string, args ...string) (string, bool, bool)
			tcp    func(addr string, d time.Duration) bool
			stat   func(path string) (os.FileInfo, error)
			getenv func(string) string
		}{
			func(bin string, _ ...string) (string, bool, bool) {
				if bin == "docker" {
					return out, found, ran
				}
				return "stub", true, true
			},
			func(string, time.Duration) bool { return false },
			func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			func(string) string { return "" },
		})
	}
	find := func(checks []preflightCheck) *preflightCheck {
		for i := range checks {
			if checks[i].Name == "docker daemon" {
				return &checks[i]
			}
		}
		t.Fatal("docker daemon check missing")
		return nil
	}

	// Stub probe exit 1 (daemon down): failure, not ok.
	c := find(dockerProbe("", true, false))
	if c.Status != "fail" || !strings.Contains(c.Detail, "daemon unreachable") {
		t.Errorf("daemon-down = (%s, %q), want fail/daemon unreachable", c.Status, c.Detail)
	}
	// Binary missing: its own understandable failure.
	c = find(dockerProbe("", false, false))
	if c.Status != "fail" || !strings.Contains(c.Detail, "not found in PATH") {
		t.Errorf("missing CLI = (%s, %q), want fail/not found in PATH", c.Status, c.Detail)
	}
	// Healthy daemon: ok with the daemon version.
	c = find(dockerProbe("27.3.1", true, true))
	if c.Status != "ok" || c.Detail != "daemon 27.3.1" {
		t.Errorf("healthy = (%s, %q), want ok/daemon 27.3.1", c.Status, c.Detail)
	}
}

// TP-20 acceptance: the Go minimum matches go.mod (1.27.1) in every message,
// and suffix/devel version strings never produce a false success.
func TestPreflightGoMinimumAndSuffixParsing(t *testing.T) {
	min := [3]int{1, 27, 1}
	cases := []struct {
		in   string
		want bool
	}{
		{"go version go1.27.1 darwin/arm64", true},
		{"go version go1.27.2 linux/amd64", true},
		{"go version go1.27.0 linux/amd64", false}, // equal minor, below patch
		{"go version go1.26.9 linux/amd64", false},
		{"1.27", false}, // two-part form means 1.27.0
		{"go version go1.26.9-dev linux/amd64", false}, // -dev suffix must not bump
		{"go version go1.26.0rc1 linux/amd64", false},  // rc must not bump
		{"devel go1.28-215dbf2e01 Tue Sep 30", true},   // devel above minimum passes
		{"go version go1.26.0 X:go1.27.1", false},      // binary version, not the toolchain hint
	}
	for _, c := range cases {
		if got := versionAtLeast(c.in, min); got != c.want {
			t.Errorf("versionAtLeast(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	// The check itself rejects a below-minimum toolchain with a message
	// naming the actual go.mod minimum.
	checks := buildPreflightChecks(struct {
		tool   func(bin string, args ...string) (string, bool, bool)
		tcp    func(addr string, d time.Duration) bool
		stat   func(path string) (os.FileInfo, error)
		getenv func(string) string
	}{
		func(bin string, _ ...string) (string, bool, bool) {
			if bin == "go" {
				return "go version go1.26.0 linux/amd64", true, true
			}
			return "stub", true, true
		},
		func(string, time.Duration) bool { return false },
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		func(string) string { return "" },
	})
	for _, c := range checks {
		if c.Name != "go toolchain" {
			continue
		}
		if c.Status != "fail" {
			t.Fatalf("below-minimum go = %s, want fail", c.Status)
		}
		if !strings.Contains(c.Detail, ">= 1.27.1") || !strings.Contains(c.Fix, "1.27.1") {
			t.Errorf("messages must name the go.mod minimum: detail=%q fix=%q", c.Detail, c.Fix)
		}
	}
}

func TestTCPReachable(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if !tcpReachable(ln.Addr().String(), time.Second) {
		t.Error("live listener must be reachable")
	}
	if tcpReachable("127.0.0.1:1", 250*time.Millisecond) {
		t.Error("closed port must not be reachable")
	}
}

// TestBootstrapStepsMatchRegistry: the hardcoded mirror and the protected
// registry are the SAME list — drift is a bug (NEXT-10 single source).
func TestBootstrapStepsMatchRegistry(t *testing.T) {
	root := repoRoot(t)
	steps, err := bootstrapStepsFromRegistry(filepath.Join(root, "scripts/quality/commands.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	mirror := bootstrapSteps()
	if len(steps) != len(mirror) {
		t.Fatalf("registry has %d steps, mirror has %d", len(steps), len(mirror))
	}
	for i := range steps {
		if steps[i].cmd != mirror[i].cmd {
			t.Errorf("step %d: registry %q != mirror %q", i, steps[i].cmd, mirror[i].cmd)
		}
	}
}

// --- TP-21: registry-based root resolution and explicit bootstrap cwd. ---

// writeFixtureRegistry builds a minimal fixture project (protected registry
// at scripts/quality/commands.json) so resolver/cwd tests never install
// anything on the real tree.
func writeFixtureRegistry(t *testing.T, root string, cmds []string) {
	t.Helper()
	dir := filepath.Join(root, "scripts", "quality")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(cmds))
	for i, c := range cmds {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		quoted[i] = string(b)
	}
	doc := `{"schema_version":1,"profiles":{"bootstrap":{"exact":[` + strings.Join(quoted, ",") + `]}}}`
	if err := os.WriteFile(filepath.Join(dir, "commands.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Root, pkg/trcli AND the nested sdks/go module must resolve the SAME
// registry and the SAME execution root (the old first-go.mod resolver
// latched onto nested roots).
func TestResolveRegistryPath_NestedModuleSameRoot(t *testing.T) {
	proj := t.TempDir()
	writeFixtureRegistry(t, proj, []string{"true"})
	// Nested module trap: its own go.mod must NOT become the root marker.
	if err := os.MkdirAll(filepath.Join(proj, "sdks", "go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proj, "pkg", "trcli"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "sdks", "go", "go.mod"), []byte("module example.com/nested\n\ngo 1.27.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantReg := filepath.Join(proj, "scripts", "quality", "commands.json")
	for _, from := range []string{proj, filepath.Join(proj, "pkg", "trcli"), filepath.Join(proj, "sdks", "go")} {
		t.Chdir(from)
		reg, err := resolveRegistryPath()
		if err != nil {
			t.Fatalf("from %s: %v", from, err)
		}
		if reg != wantReg {
			t.Fatalf("from %s: registry %s, want %s", from, reg, wantReg)
		}
		if got := bootstrapRoot(reg); got != proj {
			t.Fatalf("from %s: root %s, want %s", from, got, proj)
		}
	}
}

// A directory with no registry above it is an explicit error, and dry run
// still changes nothing.
func TestBootstrapMissingRegistryAndDryRun(t *testing.T) {
	outside := t.TempDir()
	t.Chdir(outside)
	var buf strings.Builder
	if err := runBootstrap(false, &buf); err == nil || !strings.Contains(err.Error(), "registry not found") {
		t.Fatalf("missing registry must error, got: %v", err)
	}

	// Dry run over a fixture registry prints the plan (with the explicit
	// root) and executes nothing.
	proj := t.TempDir()
	writeFixtureRegistry(t, proj, []string{"pwd", "touch executed-marker.txt"})
	t.Chdir(proj)
	buf.Reset()
	if err := runBootstrap(false, &buf); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Dry run (no changes)") || !strings.Contains(out, proj) {
		t.Errorf("dry run must print the plan and the project root: %q", out)
	}
	if _, err := os.Stat(filepath.Join(proj, "executed-marker.txt")); err == nil {
		t.Error("dry run must not execute steps")
	}
}

// executeBootstrap runs steps with the registry root as the explicit cwd:
// `pwd` reports the root even though the test process sits in a subdir.
func TestExecuteBootstrap_ExplicitRootCwd(t *testing.T) {
	proj := t.TempDir()
	writeFixtureRegistry(t, proj, []string{"pwd"})
	subdir := filepath.Join(proj, "pkg", "trcli") // caller CWD != project root
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(subdir)
	steps, err := bootstrapStepsFromRegistry(filepath.Join(proj, "scripts", "quality", "commands.json"))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	if err := executeBootstrap(steps, proj, true, &buf); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), proj) {
		t.Errorf("steps must run with cwd=%s, output: %q", proj, buf.String())
	}
	if !strings.Contains(buf.String(), "project root: "+proj) {
		t.Errorf("plan must state the execution root: %q", buf.String())
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repo root not found")
	return ""
}
