// Package trcli: NEXT-13 dev preflight doctor.
//
// `yb preflight` is strictly READ-ONLY: it inspects the development
// environment (toolchains, locked dependencies, optional stand services)
// and never installs anything. `yb bootstrap` is the separate, EXPLICIT
// installer for locked project dependencies — it prints a plan and requires
// --yes; it never touches the global toolchain (no brew, no go/node/npm
// upgrades, no npm -g) and only uses the repository's own blessed targets.
package trcli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Check severity: required failures set the exit code; advisory failures do
// not (they gate optional profiles: browser, analysis tools, local stand).
type checkSeverity string

const (
	severityRequired checkSeverity = "required"
	severityAdvisory checkSeverity = "advisory"
)

type preflightCheck struct {
	Name     string        `json:"name"`
	Severity checkSeverity `json:"severity"`
	Status   string        `json:"status"` // ok | fail | warn | skip
	Detail   string        `json:"detail,omitempty"`
	Fix      string        `json:"fix,omitempty"`
}

// probe abstracts the environment so tests can inject outcomes.
type probe func() (status string, detail string)

var (
	versionRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
)

// The Go minimum mirrors go.mod's `go` directive. One source for the
// comparison, the failure detail and the fix hint (TP-20: they previously
// disagreed with each other and with go.mod).
var (
	goVersionMinimum       = [3]int{1, 27, 1}
	goVersionMinimumString = fmt.Sprintf("%d.%d.%d", goVersionMinimum[0], goVersionMinimum[1], goVersionMinimum[2])
)

// toolVersion resolves bin in PATH and runs its version probe. The two
// booleans separate executable discovery from probe success (TP-20):
//   - found=false: the binary is not in PATH at all;
//   - found=true, ran=false: the binary exists but the probe failed (e.g.
//     docker CLI without a running daemon) — a present-but-failing probe
//     must never masquerade as success, and the resolved path is never
//     returned in place of a version;
//   - found=true, ran=true: out carries the probe output ("" allowed).
func toolVersion(bin string, args ...string) (out string, found, ran bool) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := exec.CommandContext(ctx, path, args...).Output() //nolint:gosec // version probes take fixed args
	if err != nil {
		return "", true, false
	}
	return strings.TrimSpace(string(o)), true, true
}

// versionAtLeast parses the first x.y[.z] in s and compares to min.
func versionAtLeast(s string, min [3]int) bool {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	parts := [3]int{}
	for i := 1; i <= 3 && i < len(m); i++ {
		if n, err := strconv.Atoi(m[i]); err == nil {
			parts[i-1] = n
		}
	}
	for i := 0; i < 3; i++ {
		if parts[i] != min[i] {
			return parts[i] > min[i]
		}
	}
	return true
}

func tcpReachable(addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func buildPreflightChecks(p struct {
	tool   func(bin string, args ...string) (string, bool, bool)
	tcp    func(addr string, d time.Duration) bool
	stat   func(path string) (os.FileInfo, error)
	getenv func(string) string
}) []preflightCheck {
	var checks []preflightCheck
	add := func(name string, sev checkSeverity, pr probe, fix string) {
		st, d := pr()
		checks = append(checks, preflightCheck{Name: name, Severity: sev, Status: st, Detail: d, Fix: fix})
	}

	// --- Required: core toolchain for the quality gates. ---
	add("go toolchain", severityRequired, func() (string, string) {
		v, found, ran := p.tool("go", "version")
		if !found {
			return "fail", "go not found in PATH"
		}
		if !ran {
			return "fail", "go present but `go version` probe failed"
		}
		if !versionAtLeast(v, goVersionMinimum) {
			return "fail", v + " (go.mod requires >= " + goVersionMinimumString + ")"
		}
		return "ok", v
	}, "install Go >= "+goVersionMinimumString+" yourself (preflight never changes the global toolchain)")

	add("node runtime", severityRequired, func() (string, string) {
		v, found, ran := p.tool("node", "--version")
		if !found {
			return "fail", "node not found in PATH"
		}
		if !ran {
			return "fail", "node present but `node --version` probe failed"
		}
		if !versionAtLeast(v, [3]int{22, 13, 0}) {
			return "fail", v + " (subscription-bridge requires >= 22.13)"
		}
		return "ok", v
	}, "install Node >= 22.13 yourself")

	add("python3 runtime", severityRequired, func() (string, string) {
		v, found, ran := p.tool("python3", "--version")
		if !found {
			return "fail", "python3 not found in PATH"
		}
		if !ran {
			return "fail", "python3 present but `python3 --version` probe failed"
		}
		if !versionAtLeast(v, [3]int{3, 9, 0}) {
			return "fail", v + " (quality runner requires >= 3.9)"
		}
		return "ok", v
	}, "install Python >= 3.9 yourself")

	add("docker daemon", severityRequired, func() (string, string) {
		v, found, ran := p.tool("docker", "version", "--format", "{{.Server.Version}}")
		if !found {
			return "fail", "docker CLI not found in PATH"
		}
		if !ran {
			// TP-20: the CLI being present is NOT daemon health — a failing
			// probe is a failure of its own, distinct from a missing binary.
			return "fail", "docker CLI present but daemon unreachable (probe failed)"
		}
		if v == "" {
			return "fail", "docker CLI ran but reported no daemon version"
		}
		return "ok", "daemon " + v
	}, "start Docker Desktop / the daemon")

	// --- Advisory: optional profiles. ---
	add("golangci-lint (analysis tools)", severityAdvisory, func() (string, string) {
		v, found, ran := p.tool("golangci-lint", "version")
		if !found || !ran {
			// The repo's make targets invoke it from GOBIN (~/go/bin), which
			// is often absent from interactive PATHs — check there too.
			if gobin := p.getenv("HOME") + "/go/bin/golangci-lint"; gobin != "/go/bin/golangci-lint" {
				if _, err := p.stat(gobin); err == nil {
					return "ok", gobin + " (not in PATH)"
				}
			}
			return "warn", "not found (make install-analysis-tools installs it into GOBIN)"
		}
		return "ok", v
	}, "make install-analysis-tools")

	add("playwright chromium (browser gate)", severityAdvisory, func() (string, string) {
		cache := strings.TrimSpace(p.getenv("PLAYWRIGHT_BROWSERS_PATH"))
		if cache == "" {
			if h := os.Getenv("HOME"); h != "" {
				cache = h + "/Library/Caches/ms-playwright"
			}
		}
		if cache == "" {
			return "skip", "no HOME to locate the playwright cache"
		}
		if _, err := p.stat(cache); err != nil {
			return "warn", "no browser cache at " + cache + " (browser gate will exit 77/skip)"
		}
		return "ok", cache
	}, "npx playwright install chromium")

	add("llama.cpp local model (:8081)", severityAdvisory, func() (string, string) {
		if p.tcp("127.0.0.1:8081", 2*time.Second) {
			return "ok", "reachable"
		}
		return "warn", "not reachable (qwen-local arm unavailable)"
	}, "start the local llama.cpp server")

	add("opencode stand gateway (:18082)", severityAdvisory, func() (string, string) {
		if p.tcp("127.0.0.1:18082", 2*time.Second) {
			return "ok", "reachable"
		}
		return "warn", "not reachable (legacy local check; the local dev stand is retired — wire agents to the public stand instead)"
	}, "make opencode-remote-wire")

	// --- Advisory: secrets presence WITHOUT value disclosure. ---
	for _, kv := range [][2]string{
		{"Z.AI stand key", "YABANIN_STAND_ZAI_KEY"},
		{"Nebius stand key", "YABANIN_STAND_NEBIUS_KEY"},
	} {
		name, env := kv[0], kv[1]
		add(name+" (stand env)", severityAdvisory, func() (string, string) {
			if strings.TrimSpace(p.getenv(env)) != "" {
				return "ok", "set in environment (value not inspected)"
			}
			// The stand keeps its keys in a private env file, not the shell.
			envFile := p.getenv("HOME") + "/.yabanin-opencode-stand/env"
			//nolint:gosec // G304 false positive: fixed private stand path
			// ($HOME + constant suffix), read-only, values never printed.
			if data, err := os.ReadFile(envFile); err == nil && strings.Contains(string(data), env+"=") {
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, env+"=") && strings.TrimSpace(line[len(env)+1:]) != "" {
						return "ok", "set in " + envFile + " (value not inspected)"
					}
				}
			}
			return "warn", env + " not set — provider models not seeded"
		}, "make opencode-remote-wire (YABANIN_GATEWAY_API_KEY)")
	}
	return checks
}

// preflightProbes bundles the environment surface (same shape the tests
// inject).
type preflightProbes struct {
	tool   func(bin string, args ...string) (string, bool, bool)
	tcp    func(addr string, d time.Duration) bool
	stat   func(path string) (os.FileInfo, error)
	getenv func(string) string
}

func defaultProbes() preflightProbes {
	return preflightProbes{toolVersion, tcpReachable, os.Stat, os.Getenv}
}

// runPreflight is the testable core: writes the report, returns an error
// when any required check failed.
func runPreflight(p preflightProbes, asJSON bool, w io.Writer) error {
	checks := buildPreflightChecks(struct {
		tool   func(bin string, args ...string) (string, bool, bool)
		tcp    func(addr string, d time.Duration) bool
		stat   func(path string) (os.FileInfo, error)
		getenv func(string) string
	}{p.tool, p.tcp, p.stat, p.getenv})

	failed := 0
	for _, c := range checks {
		if c.Severity == severityRequired && c.Status == "fail" {
			failed++
		}
	}
	if asJSON {
		out, _ := json.MarshalIndent(checks, "", "  ")
		_, _ = fmt.Fprintln(w, string(out))
	} else {
		_, _ = fmt.Fprintln(w, "Yabanin preflight (read-only)")
		_, _ = fmt.Fprintln(w, "============================")
		for _, c := range checks {
			mark := map[string]string{"ok": "✓", "fail": "✗", "warn": "!", "skip": "-"}[c.Status]
			_, _ = fmt.Fprintf(w, "  %s %-38s [%s] %s\n", mark, c.Name, c.Severity, c.Detail)
			if c.Status != "ok" && c.Fix != "" {
				_, _ = fmt.Fprintf(w, "      fix: %s\n", c.Fix)
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d required check(s) failed", failed)
	}
	return nil
}

// bootstrapRegistryPath points at the protected command registry; relative
// paths resolve against the repository root (found via the registry itself),
// so the CLI works from any CWD.
var bootstrapRegistryPath = "scripts/quality/commands.json"

// resolveRegistryPath finds the protected command registry by walking up
// from the CWD (TP-21: the OLD resolver stopped at the first go.mod, so
// running from a nested module like sdks/go latched onto the wrong root).
// The registry itself is the root marker: every directory on the chain that
// lacks scripts/quality/commands.json is not the project root. Missing
// registry is an explicit error, never a silent fallback.
func resolveRegistryPath() (string, error) {
	if filepath.IsAbs(bootstrapRegistryPath) {
		return bootstrapRegistryPath, nil
	}
	start, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot determine CWD: %w", err)
	}
	dir := start
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, bootstrapRegistryPath)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		dir = filepath.Dir(dir)
	}
	return "", fmt.Errorf("protected command registry not found above %s (run from the repository, or pass an absolute registry)", start)
}

// bootstrapRoot derives the project root from the registry path
// (<root>/scripts/quality/commands.json). TP-21: bootstrap steps run with
// this as their EXPLICIT working directory, not the caller's CWD.
func bootstrapRoot(registryPath string) string {
	return filepath.Dir(filepath.Dir(filepath.Dir(registryPath)))
}

// bootstrapStep is one locked-dependency install action.
type bootstrapStep struct{ desc, cmd string }

// bootstrapStepsFromRegistry reads the locked install steps from the
// NEXT-10 protected command registry (single source of truth; the plan and
// the registry cannot drift). Missing/malformed registry = explicit error.
func bootstrapStepsFromRegistry(registryPath string) ([]bootstrapStep, error) {
	raw, err := os.ReadFile(registryPath) //nolint:gosec // repo-local trusted registry
	if err != nil {
		return nil, fmt.Errorf("protected command registry: %w", err)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Profiles      map[string]struct {
			Exact []string `json:"exact"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("registry malformed: %w", err)
	}
	if doc.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported registry schema %d", doc.SchemaVersion)
	}
	cmds := doc.Profiles["bootstrap"].Exact
	if len(cmds) == 0 {
		return nil, fmt.Errorf("registry has no bootstrap profile")
	}
	steps := make([]bootstrapStep, 0, len(cmds))
	for i, c := range cmds {
		steps = append(steps, bootstrapStep{fmt.Sprintf("registry step %d", i+1), c})
	}
	return steps, nil
}

func bootstrapSteps() []bootstrapStep {
	// Test helper: static mirror of the registry bootstrap profile. The
	// TestBootstrapStepsMatchRegistry test forbids drift.
	return []bootstrapStep{
		{"go module cache (root)", "go mod download"},
		{"go module cache (nested modules)", "for d in sdks/go deploy/mock-provider deploy/mock-embedder scripts/loadtest/http; do (cd $d && go mod download); done"},
		{"dashboard deps", "npm --prefix web/dashboard ci"},
		{"site deps", "npm --prefix web/site ci"},
		{"node sdk deps", "npm --prefix sdks/node ci"},
		{"subscription-bridge deps", "npm --prefix services/subscription-bridge ci"},
		{"playwright chromium", "npx playwright install chromium"},
		{"analysis tools (golangci-lint -> GOBIN)", "make install-analysis-tools"},
	}
}

// runBootstrap prints the plan; with yes it executes the steps — always
// from the registry's project root, whatever the caller's CWD is (TP-21).
func runBootstrap(yes bool, w io.Writer) error {
	regPath, err := resolveRegistryPath()
	if err != nil {
		return err
	}
	steps, err := bootstrapStepsFromRegistry(regPath)
	if err != nil {
		return err
	}
	return executeBootstrap(steps, bootstrapRoot(regPath), yes, w)
}

// executeBootstrap runs the locked steps with root as the explicit working
// directory. Steps stay exactly the registry's argv (no user-supplied task
// strings) — the cwd fix only makes relative targets (`npm --prefix …`,
// `cd sdks/go && …`) resolve against the repository instead of the caller's
// directory.
func executeBootstrap(steps []bootstrapStep, root string, yes bool, w io.Writer) error {
	_, _ = fmt.Fprintln(w, "Yabanin bootstrap — locked dependencies only")
	_, _ = fmt.Fprintln(w, "===========================================")
	_, _ = fmt.Fprintf(w, "  project root: %s\n", root)
	for i, s := range steps {
		_, _ = fmt.Fprintf(w, "  %d. %s\n     $ %s\n", i+1, s.desc, s.cmd)
	}
	if !yes {
		_, _ = fmt.Fprintln(w, "\nDry run (no changes). Re-run with --yes to execute.")
		return nil
	}
	_, _ = fmt.Fprintln(w, "\nExecuting…")
	for _, s := range steps {
		_, _ = fmt.Fprintf(w, "==> %s\n", s.desc)
		ctx := context.Background()                        // bootstrap steps may be long; Ctrl-C cancels
		cmd := exec.CommandContext(ctx, "sh", "-c", s.cmd) //nolint:gosec // steps are the fixed registry plan
		cmd.Dir = root                                     // TP-21: registry root, not the caller's CWD
		cmd.Stdout, cmd.Stderr = w, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("step failed (%s): %w — fix and re-run; completed steps are idempotent", s.desc, err)
		}
	}
	_, _ = fmt.Fprintln(w, "Bootstrap complete.")
	return nil
}

func preflightCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Read-only development environment checks (NEXT-13)",
		Long: `Preflight inspects the development environment: toolchains, locked
dependencies and optional stand services. It is strictly READ-ONLY — it never
installs anything and never prints secret values. Required-check failures set
the exit code; advisory failures gate optional profiles only.

For locked dependency installation use the separate, explicit command:
  yb bootstrap          # prints the plan
  yb bootstrap --yes    # executes it`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPreflight(defaultProbes(), asJSON, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}

// bootstrapCmd is the SEPARATE explicit installer (NEXT-13): locked project
// dependencies only, never the global toolchain. Default is a dry-run plan;
// --yes is required to execute.
func bootstrapCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Explicitly install locked project dependencies (NEXT-13)",
		Long: `Installs ONLY locked, project-scoped dependencies using the repository's
own blessed targets. It never installs or upgrades go/node/python/docker and
never uses npm -g. Without --yes it prints the plan and exits (dry run).`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runBootstrap(yes, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "execute the plan (default: dry run)")
	return cmd
}
