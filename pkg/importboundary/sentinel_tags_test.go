package importboundary

// Sentinel build-tag matrix (E01-P05-W01-C03, trigger ③ of the E01-P04
// entry obligations): the standing sentinel (sentinel_test.go) closes the
// import graph over ONE build configuration — the tagless closure that
// `go list -deps -json ./...` reports. That closure has a known blind spot:
// a file guarded by a build constraint the host platform does not satisfy
// (the trigger's example: `//go:build plan9`) is INVISIBLE to the tagless
// listing, so a designated-path import living only in such a file would
// smuggle itself past the boundary check. This file closes that gap three
// ways:
//
//  1. TestSentinelTagMatrixClosuresClean re-runs the standing boundary law
//     over a TAG MATRIX — the tagless baseline plus every sentinel tag
//     (today: plan9) — against the real module, so a tagged designated
//     import can no longer escape an unchecked closure.
//  2. TestPlan9TaggedImportEscapesTaglessClosure pins the escape
//     deterministically on a scratch module built in t.TempDir() (never in
//     the repository tree, no residue): tagless the import is invisible
//     (the gap, reproduced red-by-construction), under the sentinel tag the
//     violation IS caught with a witness chain (the red hand under the tag,
//     deterministic on every run).
//  3. TestGoModTidyDiffRider is the card's tidy rider: `go mod tidy -diff`
//     at the module root must report NO drift (exit 0, empty output) —
//     go.mod/go.sum stay exactly as committed. The rider catches any
//     accidental dependency drift the tagged files could introduce, using
//     the same tool `go mod tidy` uses to decide whether a tagged-only
//     dependency is still required.
//
// Mandatory variants for this card:
//   - allowed: both matrix closures of the real module are clean;
//   - empty/unavailable upstream: unreadable policy / broken module layout
//     hard-fail (standing sentinel semantics, reused here);
//   - rights/cross-org: N/A — a static import-boundary check has no
//     principal, credential or org dimension; the org-scoping law lives in
//     pkg/secevents (schema.go org_id validation) and is pinned there;
//   - replay/delay: deterministic by construction — the matrix enumeration
//     is a pure function of the tree (idempotent re-runs pinned in the
//     scratch arm by asserting both closures twice);
//   - rollback: N/A — additive test-only file; reverting the card is
//     deleting it, no product or migration state exists.
//
// N/A cross-tree branches (card text): the sentinel walks the Go import
// graph of the SINGLE module — there is no second import tree to coordinate
// (the pkg/migrate/migrations mirror tree is SQL-only and outside the
// import graph), so no cross-tree arm exists for this package.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sentinelTagMatrix is the build-tag matrix the boundary law closes over.
// "" is the tagless baseline (bit-identical in scope to the standing
// sentinel); every additional entry is a sentinel tag under which files
// guarded by that build constraint join the closure. plan9 is the escape
// vector named by trigger ③ (a plan9-guarded file is invisible on every
// CI host platform, yet is legitimate shipped code for plan9 ports).
//
// Adding a tag here is deliberate and reviewed: the tag must be
// additive-only on the CI host platform (it may ADD files to the closure;
// it must not EXCLUDE files the tagless closure sees, or the matrix leg
// would stop covering them). plan9 qualifies: on linux GOOS, `-tags plan9`
// only includes files explicitly constrained `plan9`.
var sentinelTagMatrix = []string{"", "plan9"}

// TestSentinelTagMatrixClosuresClean re-runs the standing dependency-
// direction law over every closure of the tag matrix: no module package
// outside the designated prefixes may reach a designated package —
// directly, transitively or through test imports — under ANY matrix tag.
func TestSentinelTagMatrixClosuresClean(t *testing.T) {
	root := findModuleRoot(t)
	prefixes := designatedPrefixes(t, root)
	if len(prefixes) == 0 {
		t.Skipf("importboundary: %s designates no enterprise paths; boundary green by definition", policyFile)
	}
	module := readModulePath(t, root)
	for _, tag := range sentinelTagMatrix {
		t.Run(closureName(tag), func(t *testing.T) {
			packages := goListDepsTagged(t, root, tag)
			modulePrefix := module + "/"
			var starts, designatedCount int
			for importPath := range packages {
				isModule := importPath == module || strings.HasPrefix(importPath, modulePrefix)
				if !isModule {
					continue
				}
				if designatedByAny(importPath, prefixes, module) {
					designatedCount++
					continue
				}
				starts++
				if target, parent := firstReachableDesignated(importPath, packages, prefixes, module); target != "" {
					chain := witnessChain(importPath, target, parent)
					t.Fatalf("importboundary: package reaches a designated path under tag %q: %s", tag, strings.Join(chain, " -> "))
				}
			}
			t.Logf("importboundary: tag %q: %d module package(s) checked, %d designated package(s) present, zero violations",
				tag, starts, designatedCount)
		})
	}
}

// closureName renders a matrix tag as a test subtest name ("" → "tagless").
func closureName(tag string) string {
	if tag == "" {
		return "tagless"
	}
	return "tag-" + tag
}

// TestPlan9TaggedImportEscapesTaglessClosure pins the trigger-③ escape and
// its closure deterministically on a scratch module (t.TempDir — never the
// repository tree; removed with the test, no residue by construction):
//
//   - tagless closure: the plan9-guarded import of the designated package
//     is INVISIBLE — the violation is NOT found (the standing sentinel's
//     blind spot, reproduced red-by-construction);
//   - sentinel-tag closure (-tags plan9): the file joins the closure, the
//     designated import becomes visible and the boundary check FINDS the
//     violation with the full witness chain — the red hand under the tag,
//     deterministic on every run (asserted twice for replay determinism).
func TestPlan9TaggedImportEscapesTaglessClosure(t *testing.T) {
	root := t.TempDir()
	writeScratchFile(t, filepath.Join(root, "go.mod"),
		"module example.com/sentinel-scratch\n\ngo 1.27\n")
	writeScratchFile(t, filepath.Join(root, "enterprise", "ent", "ent.go"),
		"package ent // the designated closed path\n")
	writeScratchFile(t, filepath.Join(root, "core", "c", "c.go"),
		"package c // no imports: the plan9-guarded file below is the ONLY edge\n")
	writeScratchFile(t, filepath.Join(root, "core", "c", "c_plan9.go"),
		"//go:build plan9\n\npackage c\n\nimport _ \"example.com/sentinel-scratch/enterprise/ent\"\n")

	const (
		scratchModule = "example.com/sentinel-scratch"
		corePkg       = scratchModule + "/core/c"
		entPkg        = scratchModule + "/enterprise/ent"
	)
	prefixes := []string{"enterprise"}

	// The gap: tagless, the designated edge is invisible to the closure.
	for run := 1; run <= 2; run++ {
		tagless := goListDepsTagged(t, root, "")
		if c, ok := tagless[corePkg]; !ok {
			t.Fatalf("run %d: scratch core package missing from tagless closure", run)
		} else {
			for _, imp := range edges(c) {
				if imp == entPkg {
					t.Fatalf("run %d: tagged-only import visible tagless — scratch no longer reproduces the escape", run)
				}
			}
		}
		if target, _ := firstReachableDesignated(corePkg, tagless, prefixes, scratchModule); target != "" {
			t.Fatalf("run %d: violation found tagless — the standing sentinel had no such blind spot at pin time", run)
		}
	}

	// The closure: under the sentinel tag the edge is visible and caught.
	for run := 1; run <= 2; run++ {
		tagged := goListDepsTagged(t, root, "plan9")
		c, ok := tagged[corePkg]
		if !ok {
			t.Fatalf("run %d: scratch core package missing from tagged closure", run)
		}
		sawEdge := false
		for _, imp := range edges(c) {
			if imp == entPkg {
				sawEdge = true
			}
		}
		if !sawEdge {
			t.Fatalf("run %d: -tags plan9 did not surface the plan9-guarded import — scratch is broken", run)
		}
		target, parent := firstReachableDesignated(corePkg, tagged, prefixes, scratchModule)
		if target != entPkg {
			t.Fatalf("run %d: boundary check under the sentinel tag found %q, want the designated %q", run, target, entPkg)
		}
		chain := witnessChain(corePkg, target, parent)
		want := corePkg + " -> " + entPkg
		if got := strings.Join(chain, " -> "); got != want {
			t.Fatalf("run %d: witness chain %q, want %q", run, got, want)
		}
	}
}

// writeScratchFile creates path's parents and writes content with tight
// permissions (scratch module files; test-only, inside t.TempDir()).
func writeScratchFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("importboundary: scratch dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("importboundary: scratch file: %v", err)
	}
}

// TestGoModTidyDiffRider is the card's `go mod tidy -diff` rider: the
// committed go.mod/go.sum must be exactly what tidy would produce (exit 0,
// empty output — go1.27 semantics: drift prints a diff and exits 1). This
// lane fences go.mod/go.sum to zero edits; the rider turns that fence into
// a regression pin, and it is the same instrument that decides whether a
// dependency used only under build tags stays required (depcheck platform
// scope, scripts/quality/depcheck.py) — so tagged-only dependency creep
// cannot land silently next to the tag matrix. A scratch-module negative
// control pins the drift contract itself: unused require ⇒ rc!=0 with the
// diff on stdout.
func TestGoModTidyDiffRider(t *testing.T) {
	root := findModuleRoot(t)
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("importboundary: go tool not found in PATH: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "mod", "tidy", "-diff") //nolint:gosec // G204: goTool resolves via LookPath and the arguments are literals; test-only rider
	cmd.Dir = root
	// Only stdout carries the drift diff; stderr holds cold-cache
	// "go: downloading" chatter that must not fail a tidy tree.
	var diff, chatter bytes.Buffer
	cmd.Stdout = &diff
	cmd.Stderr = &chatter
	if err := cmd.Run(); err != nil {
		t.Fatalf("importboundary: go mod tidy -diff reported drift or failed (rc=%v):\n%s\n%s", err, diff.String(), chatter.String())
	}
	if drift := diff.String(); drift != "" {
		t.Fatalf("importboundary: go mod tidy -diff output must be empty on a tidy tree:\n%s", drift)
	}

	// Negative control: deliberate drift — an unused require resolved by a
	// local replace, so the probe is fully offline — must exit non-zero with
	// the diff on stdout, the same channel the positive arm pins as empty.
	t.Run("scratch drift surfaces on stdout", func(t *testing.T) {
		dir := t.TempDir()
		writeScratchFile(t, filepath.Join(dir, "go.mod"),
			"module example.com/tidy-drift-scratch\n\ngo 1.27\n\nrequire example.com/unused v0.0.0\n\nreplace example.com/unused => ./unused\n")
		writeScratchFile(t, filepath.Join(dir, "unused", "go.mod"),
			"module example.com/unused\n\ngo 1.27\n")
		writeScratchFile(t, filepath.Join(dir, "unused", "unused.go"), "package unused\n")
		writeScratchFile(t, filepath.Join(dir, "main.go"), "package scratch\n")

		cmd := exec.CommandContext(ctx, goTool, "mod", "tidy", "-diff")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOPROXY=off", "GOWORK=off")
		var drift, chatter bytes.Buffer
		cmd.Stdout = &drift
		cmd.Stderr = &chatter
		if err := cmd.Run(); err == nil {
			t.Fatalf("importboundary: drifted scratch passed tidy -diff (rc=0); negative control is broken")
		}
		if !strings.Contains(drift.String(), "require example.com/unused") {
			t.Fatalf("importboundary: drift diff must remove the unused require on stdout:\n%s\n%s", drift.String(), chatter.String())
		}
	})
}

// goListDepsTagged is goListDeps (sentinel_test.go) with a build-tag
// argument: tag "" lists the tagless closure (identical invocation); a
// non-empty tag appends -tags so files guarded by that constraint join
// the closure.
func goListDepsTagged(t *testing.T, root, tag string) map[string]*goPackage {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("importboundary: go tool not found in PATH: %v", err)
	}
	args := []string{"list", "-deps", "-json"}
	if tag != "" {
		args = append(args, "-tags", tag)
	}
	args = append(args, "./...")
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, args...) //nolint:gosec // G204: goTool resolves via LookPath; arguments are the literal list plus the matrix tag under test
	cmd.Dir = root
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("importboundary: cannot pipe go list: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("importboundary: go list failed to start: %v", err)
	}
	packages := make(map[string]*goPackage)
	dec := json.NewDecoder(bufio.NewReader(stdout))
	for {
		var p goPackage
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("importboundary: malformed go list output: %v", err)
		}
		if p.ImportPath == "" || synthesized(p.ImportPath) {
			continue
		}
		packages[p.ImportPath] = &p
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("importboundary: go list -deps -json %s ./... failed: %v", strings.Join(args[3:], " "), err)
	}
	return packages
}
