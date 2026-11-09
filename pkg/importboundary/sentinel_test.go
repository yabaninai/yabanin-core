// Package importboundary is a test-only package: it carries standing
// trust-boundary tests and ships no product code.
//
// The sentinel below turns the repository's dependency-direction law into a
// regression test: packages designated as closed (enterprise) paths in
// scripts/quality/license-policy.json may never be imported — directly,
// transitively, or from test files — by any other package of the module.
// Composition direction is strictly one-way: enterprise code composes over
// the open Apache core, never the other way around. The designated-path list
// is read from the license policy because that file is the single source of
// truth for closed paths; an empty list means nothing is designated and the
// boundary is green by definition (the checker scripts under
// scripts/quality follow the same semantics).
package importboundary

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// policyFile is the single source of truth for designated closed paths.
const policyFile = "scripts/quality/license-policy.json"

// listTimeout bounds the single `go list` invocation; the graph walk itself
// is in-process and fast.
const listTimeout = 10 * time.Minute

type goPackage struct {
	ImportPath   string   `json:"ImportPath"`
	Imports      []string `json:"Imports"`
	TestImports  []string `json:"TestImports"`
	XTestImports []string `json:"XTestImports"`
}

// edges returns every dependency edge of p, including test-file edges: on
// current toolchains `go list -deps -json` populates TestImports/XTestImports
// without the -test flag, so an import living only in a _test.go file is
// still visible here. The XTestImports self-reference external test packages
// carry is skipped: it is not a crossing.
func edges(p *goPackage) []string {
	out := make([]string, 0, len(p.Imports)+len(p.TestImports)+len(p.XTestImports))
	out = append(out, p.Imports...)
	out = append(out, p.TestImports...)
	out = append(out, p.XTestImports...)
	filtered := out[:0]
	for _, imp := range out {
		if imp != p.ImportPath {
			filtered = append(filtered, imp)
		}
	}
	return filtered
}

// synthesized reports test-main packages synthesized by the list machinery
// (paths ending in ".test" or containing " [" variants); they duplicate
// imports already carried by the real package.
func synthesized(importPath string) bool {
	return strings.HasSuffix(importPath, ".test") || strings.Contains(importPath, " [")
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("importboundary: cannot determine working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("importboundary: no go.mod found upward from %s", dir)
		}
		dir = parent
	}
}

func readModulePath(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // G304: root is the repo root located via runtime.Caller, and the filename is a literal; no test input reaches the path
	if err != nil {
		t.Fatalf("importboundary: cannot read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "module "); ok {
			module := strings.TrimSpace(after)
			if module == "" {
				t.Fatalf("importboundary: go.mod has an empty module path")
			}
			return module
		}
	}
	t.Fatalf("importboundary: go.mod has no module directive")
	return ""
}

// designatedPrefixes mirrors the policy contract of the checker scripts: the
// field must be a list of non-empty path strings; an unreadable or invalid
// policy is a hard failure, an empty list designates nothing.
func designatedPrefixes(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyFile))) //nolint:gosec // G304: root is the runtime.Caller repo root and policyFile is a compile-time constant relative path inside the repo
	if err != nil {
		t.Fatalf("importboundary: license policy unreadable: %v", err)
	}
	var policy struct {
		EnterprisePaths []string `json:"enterprise_paths"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatalf("importboundary: license policy is not valid JSON: %v", err)
	}
	prefixes := make([]string, 0, len(policy.EnterprisePaths))
	for _, p := range policy.EnterprisePaths {
		p = strings.TrimSpace(strings.Trim(p, "/"))
		if p == "" {
			t.Fatalf("importboundary: enterprise_paths contains an empty entry")
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

// designated reports whether importPath is the designated directory itself
// or lies underneath it, for either the bare prefix (as the policy states it)
// or the module-qualified form (as the import graph states it).
func designated(importPath string, prefix, module string) bool {
	for _, candidate := range []string{prefix, module + "/" + prefix} {
		if importPath == candidate || strings.HasPrefix(importPath, candidate+"/") {
			return true
		}
	}
	return false
}

func goListDeps(t *testing.T, root string) map[string]*goPackage {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("importboundary: go tool not found in PATH: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "list", "-deps", "-json", "./...") //nolint:gosec // G204: goTool resolves to the toolchain's own binary via runtime.GOROOT and the arguments are literals
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
		t.Fatalf("importboundary: go list -deps -json ./... failed: %v", err)
	}
	return packages
}

// witnessChain rebuilds the import path from the BFS parent map.
func witnessChain(start, target string, parent map[string]string) []string {
	chain := []string{target}
	for cur := target; cur != start; {
		next, ok := parent[cur]
		if !ok {
			break
		}
		chain = append([]string{next}, chain...)
		cur = next
	}
	return chain
}

// TestCoreNeverImportsDesignatedEnterprisePaths asserts that no module
// package outside the designated (closed) prefixes reaches, directly or
// transitively, through product imports or test imports, any designated
// package. Failures list every violating start package with a full witness
// chain so the offending edge can be located immediately.
func TestCoreNeverImportsDesignatedEnterprisePaths(t *testing.T) {
	root := findModuleRoot(t)
	prefixes := designatedPrefixes(t, root)
	if len(prefixes) == 0 {
		t.Skipf("importboundary: %s designates no enterprise paths; boundary green by definition", policyFile)
	}
	module := readModulePath(t, root)
	packages := goListDeps(t, root)

	modulePrefix := module + "/"
	var starts, designatedCount int
	violations := make([]string, 0)
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
			violations = append(violations, strings.Join(chain, " -> "))
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("importboundary: core package reaches a designated path: %s", v)
		}
		t.Fatalf("importboundary: %d core package(s) reach designated path(s) %v (direct, transitive, or test imports); dependency direction must stay enterprise -> core",
			len(violations), prefixes)
	}
	t.Logf("importboundary: %d module package(s) checked, %d designated package(s) present, zero core -> designated edges over prefixes %v",
		starts, designatedCount, prefixes)
}

func designatedByAny(importPath string, prefixes []string, module string) bool {
	for _, prefix := range prefixes {
		if designated(importPath, prefix, module) {
			return true
		}
	}
	return false
}

// firstReachableDesignated walks the import graph breadth-first from start.
// Only module packages are traversed: an external module cannot import this
// module's packages (the Go toolchain rejects module import cycles), so
// stepping outside the module can never lead into a designated path. Returns
// the first designated package reached together with the parent map needed
// to rebuild the witness chain.
func firstReachableDesignated(start string, packages map[string]*goPackage, prefixes []string, module string) (string, map[string]string) {
	modulePrefix := module + "/"
	parent := make(map[string]string)
	visited := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		pkg, ok := packages[cur]
		if !ok {
			continue
		}
		for _, imp := range edges(pkg) {
			if visited[imp] {
				continue
			}
			visited[imp] = true
			parent[imp] = cur
			if designatedByAny(imp, prefixes, module) {
				return imp, parent
			}
			if imp == module || strings.HasPrefix(imp, modulePrefix) {
				queue = append(queue, imp)
			}
		}
	}
	return "", parent
}
