// SPDX-License-Identifier: Apache-2.0
//go:build ignore

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type unit struct {
	Name      string   `json:"name"`
	Recv      string   `json:"recv,omitempty"`
	Start     int      `json:"start"`
	End       int      `json:"end"`
	Hash      string   `json:"hash"`
	Kind      string   `json:"kind,omitempty"`
	Symbols   []string `json:"symbols,omitempty"`
	Flags     []string `json:"flags,omitempty"`
	Refs      []string `json:"refs,omitempty"`
	SelRefs   []string `json:"selrefs,omitempty"`
	FloorRefs []string `json:"floor_refs,omitempty"`
	Lits      []string `json:"lits,omitempty"`
}

type fileUnits struct {
	Path       string   `json:"path"`
	Units      []unit   `json:"units"`
	Directives string   `json:"directives,omitempty"`
	Matched    []bool   `json:"matched,omitempty"`
	Resolution []string `json:"resolution,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// request accepts either a bare path list (legacy callers) or an object with
// per-build-mode tag sets; only the object form reports mode applicability.
type request struct {
	Paths []string   `json:"paths"`
	Modes [][]string `json:"modes"`
}

func readRequest() ([]string, [][]string, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(os.Stdin).Decode(&raw); err != nil {
		return nil, nil, err
	}
	var paths []string
	if err := json.Unmarshal(raw, &paths); err == nil {
		return paths, nil, nil
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, nil, err
	}
	return req.Paths, req.Modes, nil
}

func run() error {
	paths, modes, err := readRequest()
	if err != nil {
		return err
	}
	files, table, err := parse(paths)
	if err != nil {
		return err
	}
	budget, err := remainingAnalysisBudget()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	res := analyze(files, paths, modes, ctx)
	result := make([]fileUnits, 0, len(files))
	for _, item := range files {
		out, err := scan(item, table, modes, res)
		if err != nil {
			return err
		}
		result = append(result, out)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

type parsedFile struct {
	path string
	src  []byte
	fs   *token.FileSet
	file *ast.File
}

// parse reads every file once and resolves a shared package-name table so a
// unit's references can be matched against identifiers declared anywhere in
// the analyzed file set (production and test files together).
func parse(paths []string) ([]parsedFile, map[string]bool, error) {
	files := make([]parsedFile, 0, len(paths))
	table := map[string]bool{}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		fs := token.NewFileSet()
		file, err := parser.ParseFile(fs, path, src, 0)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, parsedFile{path: path, src: src, fs: fs, file: file})
		declareNames(file, table)
	}
	return files, table, nil
}

func declareNames(file *ast.File, table map[string]bool) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			table[d.Name.Name] = true
		case *ast.GenDecl:
			declareSpecNames(d, table)
		}
	}
}

func declareSpecNames(gen *ast.GenDecl, table map[string]bool) {
	for _, spec := range gen.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			table[s.Name.Name] = true
		case *ast.ValueSpec:
			for _, name := range s.Names {
				table[name.Name] = true
			}
		case *ast.ImportSpec:
			// Blank and dot imports widen the name space; "_" and "." are not
			// referenceable identifiers, so they stay out of the table.
			if s.Name != nil && s.Name.Name != "_" && s.Name.Name != "." {
				table[s.Name.Name] = true
			}
		}
	}
}

func scan(item parsedFile, table map[string]bool, modes [][]string, res *resolution) (fileUnits, error) {
	out := fileUnits{Path: item.path, Units: []unit{}, Directives: directiveDigest(item.src)}
	if modes != nil {
		out.Matched = matchModes(item.path, modes)
	}
	for _, decl := range item.file.Decls {
		scanUnit, err := declaration(item.fs, decl, table, res)
		if err != nil {
			return out, err
		}
		out.Units = append(out.Units, scanUnit)
	}
	out.Resolution = sortedNames(res.fileNotes[item.path])
	return out, nil
}

// matchModes reports for each build mode (tag set) whether the go tool would
// compile this file: filename GOOS/GOARCH suffixes and //go:build constraints
// included, so target counting can never exceed what a build actually sees.
// A file that cannot be evaluated counts as excluded; its targets then fail
// the coverage guard instead of silently passing.
func matchModes(path string, modes [][]string) []bool {
	dir, base := filepath.Split(path)
	matched := make([]bool, len(modes))
	for index, tags := range modes {
		ctxt := build.Default
		ctxt.BuildTags = tags
		match, err := ctxt.MatchFile(filepath.Clean(dir), base)
		matched[index] = err == nil && match
	}
	return matched
}

func declaration(fs *token.FileSet, decl ast.Decl, table map[string]bool, res *resolution) (unit, error) {
	item := unit{Start: fs.Position(decl.Pos()).Line, End: fs.Position(decl.End()).Line}
	node := ast.Node(decl)
	if fn, ok := decl.(*ast.FuncDecl); ok {
		item.Name = fn.Name.Name
		item.Recv = canonicalRecv(res.perDecl[decl], receiverName(fn.Recv))
		item.Kind = "func"
		item.Symbols = []string{fn.Name.Name}
		item.Flags, item.Lits = dispatchShape(fn)
		copy := *fn
		copy.Name = &ast.Ident{Name: "_"}
		node = &copy
	} else {
		item.Kind, item.Symbols, item.Flags = describe(decl)
	}
	hash, err := fingerprint(node)
	item.Hash = hash
	item.Refs, item.SelRefs, item.FloorRefs = references(decl, table, item.Name, res)
	return item, err
}

// receiverName reports the receiver's base type identifier: (a A), (a *A)
// and (a A[P]) all report "A". Go forbids redeclaring a method name on one
// base type, so (name, receiver) identifies a method where the bare name
// cannot; functions without a receiver report "".
func receiverName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	typ := recv.List[0].Type
	for {
		switch node := typ.(type) {
		case *ast.StarExpr:
			typ = node.X
		case *ast.ParenExpr:
			typ = node.X
		case *ast.IndexExpr:
			typ = node.X
		case *ast.IndexListExpr:
			typ = node.X
		case *ast.Ident:
			return node.Name
		default:
			return ""
		}
	}
}

// dynamicSelectors are reflect-style member lookups whose target is a runtime
// string; a removed name behind one of them is invisible to reference counts.
var dynamicSelectors = map[string]bool{
	"MethodByName":    true,
	"FieldByName":     true,
	"FieldByNameFunc": true,
}

// dispatchShape flags dynamic member lookup inside a function. Literal
// argument strings stay bindable; any other argument shape is unresolved and
// makes the whole package conservative on name removal.
func dispatchShape(fn *ast.FuncDecl) ([]string, []string) {
	names, flags := map[string]bool{}, map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			noteDispatchCall(call, names, flags)
		}
		return true
	})
	return sortedNames(flags), sortedNames(names)
}

func noteDispatchCall(call *ast.CallExpr, names, flags map[string]bool) {
	if len(call.Args) == 0 || !isDispatchSelector(call.Fun) {
		return
	}
	name, ok := stringLiteral(call.Args[0])
	if !ok {
		flags["dynamic_dispatch_unresolved"] = true
		return
	}
	names[name] = true
	flags["dynamic_dispatch"] = true
}

func isDispatchSelector(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	return ok && dynamicSelectors[sel.Sel.Name]
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

func fingerprint(node ast.Node) (string, error) {
	var buf bytes.Buffer
	fs := token.NewFileSet()
	fs.AddFile("canonical", 1, 1<<30)
	if err := printer.Fprint(&buf, fs, node); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// describe classifies a non-function declaration for impact selection.
func describe(decl ast.Decl) (string, []string, []string) {
	gen, ok := decl.(*ast.GenDecl)
	if !ok {
		return "decl", nil, nil
	}
	kind := map[token.Token]string{
		token.IMPORT: "import", token.TYPE: "type", token.VAR: "var", token.CONST: "const",
	}[gen.Tok]
	symbols := specSymbols(gen)
	flags := indirectFlags(gen)
	if gen.Tok == token.IMPORT && hasDefaultImport(gen) {
		flags = append(flags, "default_import")
	}
	return kind, symbols, flags
}

// hasDefaultImport reports whether an import declaration contains a spec
// without an explicit local name. For those the declared package name
// cannot be safely inferred from syntax or path alone (versioned paths,
// packages named differently from their path base), so the selector treats
// changes of such declarations conservatively instead of inferring an alias.
func hasDefaultImport(gen *ast.GenDecl) bool {
	for _, spec := range gen.Specs {
		if s, ok := spec.(*ast.ImportSpec); ok && s.Name == nil {
			return true
		}
	}
	return false
}

func specSymbols(gen *ast.GenDecl) []string {
	symbols := []string{}
	for _, spec := range gen.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			symbols = append(symbols, s.Name.Name)
		case *ast.ValueSpec:
			for _, name := range s.Names {
				symbols = append(symbols, name.Name)
			}
		case *ast.ImportSpec:
			if s.Name != nil {
				symbols = append(symbols, s.Name.Name)
			} else {
				symbols = append(symbols, importName(s.Path.Value))
			}
		}
	}
	return symbols
}

func importName(path string) string {
	trimmed := strings.Trim(path, `"`)
	if index := strings.LastIndex(trimmed, "/"); index >= 0 {
		return trimmed[index+1:]
	}
	return trimmed
}

// indirectFlags reports interface and function-typed shapes inside a
// declaration; selection treats either as unresolved indirect dispatch.
func indirectFlags(gen *ast.GenDecl) []string {
	found := map[string]bool{}
	ast.Inspect(gen, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.InterfaceType:
			found["interface"] = true
		case *ast.FuncType, *ast.FuncLit:
			found["func_type"] = true
		}
		return true
	})
	flags := make([]string, 0, len(found))
	for flag := range found {
		flags = append(flags, flag)
	}
	sort.Strings(flags)
	return flags
}

// references returns merged per-mode type-checked decisions for one
// declaration, falling back to the name-based algorithm whenever the
// type evidence is missing: never less evidence than the committed baseline.
// The third result reports the spellings contributed by the floor. Every
// floor spelling is also in refs, so refs stays checked-union-floor, while
// floor_refs marks which spellings only broad lookup vouches for. A
// spelling can appear in both when one mode checked it and another fell
// back; consumers must read the sets independently and never derive the
// checked portion by subtraction.
func references(decl ast.Decl, table map[string]bool, own string, res *resolution) ([]string, []string, []string) {
	if d := res.perDecl[decl]; d != nil {
		refs, selrefs, floor := d.refs, d.selrefs, d.floorRefs
		if d.floor {
			floorRefs, floorSel := nameBasedReferences(decl, table, own)
			refs = unionNames(refs, setOf(floorRefs))
			selrefs = unionNames(selrefs, setOf(floorSel))
			floor = unionNames(floor, setOf(floorRefs))
		}
		return sortedNames(refs), sortedNames(selrefs), sortedNames(floor)
	}
	floorRefs, floorSel := nameBasedReferences(decl, table, own)
	return floorRefs, floorSel, sortedNames(setOf(floorRefs))
}

// setOf converts a sorted slice back into a set for unioning.
func setOf(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// nameBasedReferences lists package-level identifiers a declaration mentions.
// Matching is name-based without scope analysis, so shadowing can only add
// spurious references, never hide a real one; the consumer is conservative
// selection. Selector-position identifiers (x.Name, qualified pkg.Name and
// composite literal keys) are reported separately because they may denote
// dispatch. It is the fail-closed floor when per-mode checks cannot certify.
func nameBasedReferences(decl ast.Decl, table map[string]bool, own string) ([]string, []string) {
	selectorPosition := map[*ast.Ident]bool{}
	ast.Inspect(decl, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			selectorPosition[v.Sel] = true
		case *ast.KeyValueExpr:
			// A key is either a struct field or a map key expression; without
			// type information both readings must stay visible.
			if id, ok := v.Key.(*ast.Ident); ok {
				selectorPosition[id] = true
			}
		}
		return true
	})
	refs, selrefs := map[string]bool{}, map[string]bool{}
	for id := range selectorPosition {
		selrefs[id.Name] = true
		// Composite-literal keys double as bare references so a constant used
		// only as a map key never disappears from consumer binding.
		if table[id.Name] {
			refs[id.Name] = true
		}
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && !selectorPosition[id] && id.Name != own && table[id.Name] {
			refs[id.Name] = true
		}
		return true
	})
	return sortedNames(refs), sortedNames(selrefs)
}

// decisions carries one declaration's merged evidence across modes. floor
// marks a declaration the type checks could not fully certify: its final
// output unions the name-based fallback in, never less evidence. floorRefs
// collects spellings recorded as broad lookup rather than checked evidence
// — an unparsable method receiver — so the fallback stays distinguishable
// from a checked package-level function reference. recv holds the
// receiver's canonical base type name from the type checker, so method
// declarations and method selections spell one identity even through an
// alias; the AST spelling alone would key `type A = B` receivers as
// "A.name" while every call resolves to "B.name".
type decisions struct {
	refs      map[string]bool
	selrefs   map[string]bool
	floorRefs map[string]bool
	floor     bool
	recv      string
}

// resolution is the per-run container for type-checked decisions and the
// per-file evidence notes explaining any fail-closed fallback.
type resolution struct {
	perDecl   map[ast.Decl]*decisions
	fileNotes map[string]map[string]bool
}

// note records one evidence line for a file.
func (r *resolution) note(path, text string) {
	if r.fileNotes[path] == nil {
		r.fileNotes[path] = map[string]bool{}
	}
	r.fileNotes[path][text] = true
}

// analysisBudget bounds the whole analysis pipeline: every nested go
// list subprocess and type check shares ONE deadline so the helper stays
// inside the Python caller's 120s timeout with cleanup margin. A breach
// kills the child process group and every remaining mode fails closed.
const analysisBudget = 90 * time.Second

// remainingAnalysisBudget derives the analysis budget from the caller's
// forwarded remaining shared unit budget. An absent
// YABANIN_UNIT_REMAINING_NS keeps the analysisBudget default; a valid
// positive remainder bounds the analysis by that default; a malformed
// value fails the run closed; and a nonpositive remainder means the
// caller's budget is already exhausted, so the request resolves to the
// complete conservative floor without starting go-list work.
func remainingAnalysisBudget() (time.Duration, error) {
	raw, present := os.LookupEnv("YABANIN_UNIT_REMAINING_NS")
	if !present {
		return analysisBudget, nil
	}
	ns, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid YABANIN_UNIT_REMAINING_NS %q", raw)
	}
	if ns <= 0 {
		return 0, nil
	}
	budget := time.Duration(ns) * time.Nanosecond
	if budget > analysisBudget {
		budget = analysisBudget
	}
	return budget, nil
}

// analyze type-checks the requested files once per build mode with a
// module-aware export-data importer and merges decisions by union. Any
// failing mode keeps that mode's declarations on the name-based floor.
func analyze(files []parsedFile, paths []string, modes [][]string, ctx context.Context) *resolution {
	res := &resolution{perDecl: map[ast.Decl]*decisions{}, fileNotes: map[string]map[string]bool{}}
	modeList := modes
	if modeList == nil {
		modeList = [][]string{nil}
	}
	dir := filepath.Dir(paths[0])
	for _, item := range files {
		if filepath.Dir(item.path) != dir {
			res.note(item.path, "resolution-fallback: paths span multiple directories")
			return res
		}
	}
	okAny := false
	deadlineFloored := false
	for _, mode := range modeList {
		if ctx.Err() != nil {
			markFloor(res, files, nil, "resolution-fallback: analysis deadline exceeded")
			deadlineFloored = true
			break
		}
		if analyzeMode(files, dir, mode, res, ctx) {
			okAny = true
		}
	}
	// Expiry inside the last mode — after the loop-top gate has passed
	// for the final time — must still floor the whole request: the
	// per-group floor covers only its own files and no later iteration
	// exists to propagate it. Note set-semantics keeps it single.
	if ctx.Err() != nil && !deadlineFloored {
		markFloor(res, files, nil, "resolution-fallback: analysis deadline exceeded")
	}
	if !okAny {
		for _, item := range files {
			res.note(item.path, "resolution-fallback: no mode type-checked")
		}
	}
	return res
}

// analyzeMode checks one build mode coherently: fresh FileSet, per-mode
// export map, internal and external test packages kept separate. It
// returns false when the mode cannot certify anything; every failure
// leaves the mode's matched files on the name-based floor.
func analyzeMode(files []parsedFile, dir string, mode []string, res *resolution, ctx context.Context) bool {
	matched := matchedFiles(files, mode)
	exports, err := goListExports(dir, mode, ctx)
	if err != nil {
		markFloor(res, files, matched, "resolution-fallback: mode go list failed: "+err.Error())
		return false
	}
	internal, external, err := groupFiles(files, matched, mode, ctx)
	if err != nil {
		markFloor(res, files, matched, "resolution-fallback: grouping failed: "+err.Error())
		return false
	}
	if !checkGroup(internal, exports, res, nil, ctx) {
		// The internal group already floored its own files. Checking the
		// external group now would resolve the target package from
		// production export data instead of the failed internal test
		// package, so the external files floor with it and the mode
		// reports failure.
		if external != nil {
			markFloor(res, external.items, nil, "resolution-fallback: internal test check failed")
		}
		return false
	}
	if external != nil && !checkGroup(external, exports, res, internal.pkg, ctx) {
		markFloor(res, external.items, nil, "resolution-fallback: external test check failed")
	}
	return true
}

// matchedFiles reports which files the mode's build tags select; the
// ambient run (nil mode) selects everything passed, like parse itself.
func matchedFiles(files []parsedFile, mode []string) map[string]bool {
	matched := map[string]bool{}
	if mode == nil {
		for _, item := range files {
			matched[item.path] = true
		}
		return matched
	}
	for _, item := range files {
		ctxt := build.Default
		ctxt.BuildTags = mode
		dir, base := filepath.Split(item.path)
		hit, err := ctxt.MatchFile(filepath.Clean(dir), base)
		matched[item.path] = err == nil && hit
	}
	return matched
}

// markFloor flags every matched file's declarations as uncertified so the
// final output unions the name-based fallback back in.
func markFloor(res *resolution, files []parsedFile, matched map[string]bool, note string) {
	for _, item := range files {
		if matched != nil && !matched[item.path] {
			continue
		}
		res.note(item.path, note)
		for _, decl := range item.file.Decls {
			d := res.perDecl[decl]
			if d == nil {
				d = &decisions{refs: map[string]bool{}, selrefs: map[string]bool{}, floorRefs: map[string]bool{}}
				res.perDecl[decl] = d
			}
			d.floor = true
		}
	}
}

// fileGroup is one coherently checkable package: its files, parsed ASTs
// and import path.
type fileGroup struct {
	items      []parsedFile
	importPath string
	pkg        *types.Package
}

// goListExports builds the per-mode export-data map for the module rooted
// at dir. The subprocess runs under the shared analysis deadline in its
// own process group, and the resulting map belongs to this invocation's
// tree only: a failing or expired listing yields no map, never a stale
// or foreign one. Missing export data fails the mode closed.
func goListExports(dir string, mode []string, ctx context.Context) (map[string]string, error) {
	// -test pulls in test-only dependencies (e.g. testing) so groups
	// containing _test.go files can type-check against real export data.
	// -e tolerates build-tagged package-clause twins in one directory —
	// strict listing rejects the directory as a whole — while selection
	// stays fail-closed. The fixed third marker column reports whether
	// go list recorded a load error for the record; raw template error
	// text could span lines and silently corrupt record parsing, so the
	// marker never interpolates it. ANY errored record — the selected
	// package or any dependency, whatever the output order — fails the
	// listing closed: an unevaluated load such as an assembler error in
	// a .s file that type checking never sees must not certify a mode.
	// Valid tagged twins carry no marker, and a dependency whose export
	// data is merely absent still fails at import time as before.
	args := []string{"list", "-e", "-deps", "-export", "-test", "-f", "{{.ImportPath}}\t{{.Export}}\t{{if .Error}}1{{else}}0{{end}}"}
	if len(mode) > 0 {
		args = append(args, "-tags", strings.Join(mode, ","))
	}
	args = append(args, ".")
	out, err := runGoList(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	exports := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "\t")
		if len(parts) != 3 {
			return nil, fmt.Errorf("unexpected output")
		}
		if parts[2] == "1" {
			return nil, fmt.Errorf("package load error: %s", parts[0])
		}
		if parts[1] != "" {
			exports[parts[0]] = parts[1]
		}
	}
	if len(exports) == 0 {
		return nil, fmt.Errorf("empty export map")
	}
	return exports, nil
}

// runGoList runs one bounded go list subprocess in its own process
// group so a deadline breach kills the whole child tree (go list plus
// the compiler workers it spawned), not just the parent process. This
// helper is the child's exclusive reaper: after a successful Start it
// blocks in waitid(P_PID, WEXITED|WNOWAIT) until the direct child has
// exited but is still waitable, then — while its numeric identity is
// still reserved and cannot be reused — signals the owned group before
// the single Cmd.Wait reaps the leader. Cancellation and the final
// signal serialize on one per-command mutex behind an armed flag: an
// in-flight signal completes before reaping, and a late Cancel returns
// os.ErrProcessDone instead of signaling a reused PID. Ownership is
// established by waitid alone, never by probing kill(pid, 0). A failed
// Start or a failed observation sends no group signal: ECHILD means
// ownership cannot be established and the lifecycle failure surfaces
// even if the command exited zero; any other observation failure still
// terminates the direct child through Process.Kill before Wait and
// surfaces likewise. The completion signal cleans up toolchain or
// wrapper grandchildren — ESRCH just means no target remained; their
// reaping belongs to the process they were reparented to, and
// WaitDelay bounds inherited-pipe drainage, since Linux promises no
// hard reap bound for tasks in uninterruptible sleep.
func runGoList(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var mu sync.Mutex
	armed := true
	cmd.Cancel = func() error {
		mu.Lock()
		defer mu.Unlock()
		if !armed {
			return os.ErrProcessDone
		}
		// Read the PID inside the callback: the context watcher can
		// run before Start returns.
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("%v: %s", err, firstLine(stderr.String()))
	}
	if err := waitExited(cmd.Process.Pid); err != nil {
		mu.Lock()
		armed = false
		mu.Unlock()
		if err != syscall.ECHILD {
			_ = cmd.Process.Kill()
		}
		werr := cmd.Wait()
		return "", fmt.Errorf("lifecycle: waitid: %v: wait: %v", err, werr)
	}
	var sigErr error
	mu.Lock()
	if armed {
		sigErr = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		armed = false
	}
	mu.Unlock()
	werr := cmd.Wait()
	if werr != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("deadline exceeded: %w", ctx.Err())
		}
		return "", fmt.Errorf("%v: %s", werr, firstLine(stderr.String()))
	}
	if sigErr != nil && sigErr != syscall.ESRCH {
		return "", fmt.Errorf("group cleanup failed: %v", sigErr)
	}
	return stdout.String(), nil
}

// waitIDTypePID is Linux's P_PID id type for waitid(2); the syscall
// package does not export it.
const waitIDTypePID = 1

// waitExited blocks until the direct child pid has exited while
// leaving it waitable for the caller's single Wait. WNOWAIT keeps the
// numeric identity reserved — the PID cannot be reused before the
// owned group has been signaled. EINTR retries.
func waitExited(pid int) error {
	var info [16]uint64
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID,
			uintptr(waitIDTypePID), uintptr(pid),
			uintptr(unsafe.Pointer(&info[0])),
			uintptr(syscall.WEXITED|syscall.WNOWAIT), 0, 0)
		switch errno {
		case 0:
			return nil
		case syscall.EINTR:
			continue
		default:
			return errno
		}
	}
}

// firstLine trims multi-line command errors to their first line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// groupFiles splits the mode-matched files into the production package
// (internal test files merge into it, one compiler package) and the
// external test package. The split uses the production package's Name
// from go list resolved with the mode's own build tags, never an
// import-path basename: pkg/gateway is package cli, so its external
// tests are cli_test, not gateway_test.
func groupFiles(files []parsedFile, matched map[string]bool, mode []string, ctx context.Context) (internal, external *fileGroup, err error) {
	importPath, pkgName, err := goListPackageInfo(filepath.Dir(files[0].path), mode, ctx)
	if err != nil {
		return nil, nil, err
	}
	internal = &fileGroup{importPath: importPath}
	for _, item := range files {
		if !matched[item.path] {
			continue
		}
		if isExternalTest(item, pkgName) {
			if external == nil {
				external = &fileGroup{importPath: importPath + "_test"}
			}
			external.items = append(external.items, item)
			continue
		}
		internal.items = append(internal.items, item)
	}
	if len(internal.items) == 0 {
		return nil, nil, fmt.Errorf("no files match the mode")
	}
	return internal, external, nil
}

// isExternalTest reports whether a file belongs to the external test
// package: _test.go with the clause <productionName>_test.
func isExternalTest(item parsedFile, pkgName string) bool {
	return strings.HasSuffix(item.path, "_test.go") && item.file.Name.Name == pkgName+"_test"
}

// goListPackageInfo resolves the analyzed package's import path and
// production package name from its own module snapshot, using the same
// build tags as the export listing so tagged package-clause twins group
// per mode. -export forces go list to evaluate the package — without a
// build, load errors such as a broken .s file stay invisible — and the
// fixed third marker column reports them without interpolating
// multiline error text into the record; any errored record fails closed
// here, before a group is certified. -e still keeps the listing usable
// when the directory also holds files other modes select. The shared
// analysis deadline bounds the subprocess.
func goListPackageInfo(dir string, mode []string, ctx context.Context) (string, string, error) {
	args := []string{"list", "-e", "-export", "-f", "{{.ImportPath}}\t{{.Name}}\t{{if .Error}}1{{else}}0{{end}}"}
	if len(mode) > 0 {
		args = append(args, "-tags", strings.Join(mode, ","))
	}
	args = append(args, ".")
	out, err := runGoList(ctx, dir, args...)
	if err != nil {
		return "", "", fmt.Errorf("go list package info: %v", err)
	}
	parts := strings.SplitN(strings.TrimSpace(out), "\t", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("go list package info: unexpected output")
	}
	if parts[2] == "1" {
		return "", "", fmt.Errorf("go list package info: package load error: %s", parts[0])
	}
	return parts[0], parts[1], nil
}

// checkGroup type-checks one package group with a coherent FileSet, the
// gc export-data importer for dependencies and, for external test groups,
// the in-memory checked package for the target import. Type errors and a
// breached analysis deadline — before or during the check — fail the
// group closed onto the name-based floor with no partial certification:
// the check runs in one worker goroutine, the parent floors and returns
// without joining it on expiry, and the abandoned in-memory check dies
// with the process. Decisions bind members of the analyzed production
// package — the internal group's own checked package, or the in-memory
// target it handed the external group — and, for external groups, the
// group's own package-level declarations reached by bare references.
func checkGroup(group *fileGroup, exports map[string]string, res *resolution, checked *types.Package, ctx context.Context) bool {
	if ctx.Err() != nil {
		markFloor(res, group.items, nil, "resolution-fallback: analysis deadline exceeded")
		return false
	}
	fset := token.NewFileSet()
	asts, ok := reparseGroup(group, fset, res)
	if !ok {
		return false
	}
	var imp types.Importer = exporterFor(fset, exports)
	if checked != nil {
		imp = targetImporter{target: checked, fallback: imp}
	}
	var errs []string
	conf := types.Config{Importer: imp, FakeImportC: true,
		Error: func(e error) { errs = append(errs, e.Error()) }}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{},
		Defs:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{}}
	// conf.Check is synchronous, so one worker goroutine runs it and
	// publishes a single buffered outcome; the parent selects that
	// outcome against the deadline and rechecks the context after
	// receipt, so a late result can never certify.
	type checkOutcome struct {
		pkg  *types.Package
		done bool
	}
	outcome := make(chan checkOutcome, 1)
	go func() {
		pkg, _ := conf.Check(group.importPath, fset, asts, info)
		outcome <- checkOutcome{pkg: pkg, done: true}
	}()
	result := checkOutcome{}
	select {
	case result = <-outcome:
	case <-ctx.Done():
	}
	if !result.done || ctx.Err() != nil {
		markFloor(res, group.items, nil, "resolution-fallback: analysis deadline exceeded")
		return false
	}
	pkg := result.pkg
	if len(errs) > 0 {
		markFloor(res, group.items, nil, "resolution-fallback: type errors: "+firstLine(errs[0]))
		return false
	}
	group.pkg = pkg
	target := pkg
	if checked != nil {
		target = checked
	}
	decls := groupDeclarations(pkg, target, info)
	for i, item := range group.items {
		collectDecisions(item, asts[i], target, decls, info, res)
	}
	return true
}

// groupDeclarations indexes the checked external group's package-level
// source identity: every object info.Defs binds to a declaration
// identifier at package scope in this group's reparsed files — and
// every method those files declare on the group's own types, which
// never sit at package scope — across all of them. A bare reference or
// a concrete method selection binds a helper only through object
// identity with one of these declarations — never by name and never
// through scope shape alone. Internal groups (pkg == target) need no
// index: their globals and methods already bind through the production
// branch, so they get nil.
func groupDeclarations(pkg, target *types.Package, info *types.Info) map[types.Object]bool {
	var decls map[types.Object]bool
	if !samePackage(pkg, target) {
		scope := pkg.Scope()
		decls = make(map[types.Object]bool, len(info.Defs))
		for _, obj := range info.Defs {
			if obj != nil && (obj.Parent() == scope || isGroupMethod(obj, pkg)) {
				decls[obj] = true
			}
		}
	}
	return decls
}

// reparseGroup re-reads the group's files into the group's own coherent
// FileSet: the parse-time ASTs belong to other FileSets and the checker
// panics on positions it does not know. Any read or parse failure floors
// the group.
func reparseGroup(group *fileGroup, fset *token.FileSet, res *resolution) ([]*ast.File, bool) {
	asts := make([]*ast.File, 0, len(group.items))
	for _, item := range group.items {
		content, err := os.ReadFile(item.path)
		if err != nil {
			markFloor(res, group.items, nil, "resolution-fallback: reparse failed: "+err.Error())
			return nil, false
		}
		fresh, err := parser.ParseFile(fset, item.path, content, 0)
		if err != nil {
			markFloor(res, group.items, nil, "resolution-fallback: reparse failed: "+firstLine(err.Error()))
			return nil, false
		}
		asts = append(asts, fresh)
	}
	return asts, true
}

// exporterFor builds the stdlib gc importer over the per-mode export map.
func exporterFor(fset *token.FileSet, exports map[string]string) types.Importer {
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if f, ok := exports[path]; ok {
			return os.Open(f)
		}
		return nil, fmt.Errorf("no export data for %s", path)
	})
}

// targetImporter resolves the analyzed package itself from memory for
// external test groups and everything else from export data.
type targetImporter struct {
	target   *types.Package
	fallback types.Importer
}

// Import returns the in-memory target or delegates to export data.
func (t targetImporter) Import(path string) (*types.Package, error) {
	if path == t.target.Path() {
		return t.target, nil
	}
	return t.fallback.Import(path)
}

// collectDecisions walks one file's declarations into per-decl decisions
// using the type-checked facts: exact binds for concrete members and
// package globals, widening for genuine interface dispatch. Members bind
// against target, the analyzed production package — the group's own
// checked package, or the in-memory target an external test group
// imported — and decls carries the external group's package-level
// source-declaration identity so bare helper references and concrete
// helper methods bind the declaration's own object. Decisions are keyed
// by the ORIGINAL parse-time declaration nodes (same source, same order
// as the fresh reparse) because fingerprinting and scanning use those
// nodes.
func collectDecisions(item parsedFile, fresh *ast.File, target *types.Package, decls map[types.Object]bool, info *types.Info, res *resolution) {
	if len(fresh.Decls) != len(item.file.Decls) {
		markFloor(res, []parsedFile{item}, nil, "resolution-fallback: reparse declaration mismatch")
		return
	}
	for i, decl := range fresh.Decls {
		orig := item.file.Decls[i]
		d := &decisions{refs: map[string]bool{}, selrefs: map[string]bool{}, floorRefs: map[string]bool{}}
		walkSelectors(decl, target, decls, info, d)
		walkIdents(decl, target, decls, info, d)
		if fn, ok := decl.(*ast.FuncDecl); ok {
			d.recv = checkedRecv(fn, info)
		}
		storeDecisions(res, orig, d)
	}
}

// storeDecisions merges one declaration's decisions across modes.
func storeDecisions(res *resolution, orig ast.Decl, d *decisions) {
	if prior := res.perDecl[orig]; prior != nil {
		prior.refs = unionNames(prior.refs, d.refs)
		prior.selrefs = unionNames(prior.selrefs, d.selrefs)
		prior.floorRefs = unionNames(prior.floorRefs, d.floorRefs)
		if prior.recv == "" {
			prior.recv = d.recv
		}
	} else {
		res.perDecl[orig] = d
	}
}

// checkedRecv reports the receiver's canonical base type name from the
// type checker: the Named object the receiver spelling denotes. The
// method's own checked signature (info.Defs binds the declaration name
// to its object) carries the receiver type, so no receiver AST walking
// is needed. Alias receivers — `type A = B` and `type A = *B` alike —
// canonicalize to B exactly like the selections methodRefName records;
// a plain named receiver denotes itself. Empty when no receiver or no
// named type is recoverable — the caller then keeps the AST spelling and
// the floor fan still reaches the method twins.
func checkedRecv(fn *ast.FuncDecl, info *types.Info) string {
	obj, _ := info.Defs[fn.Name].(*types.Func)
	sig, _ := obj.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return ""
	}
	named := recvNamedType(sig.Recv().Type())
	if named == nil {
		return ""
	}
	return named.Obj().Name()
}

// recvNamedType normalizes one method receiver's type to the Named type
// whose declaration binds the method — the one shared normalization for
// declaration identity (checkedRecv) and call keys (methodRefName,
// methodDeclPkg). Alias nodes unalias first: Go's alias type carries the
// alias TypeName, not the type it denotes. A pointer receiver then peels
// to its element, and alias-of-pointer (`type A = *B`) unaliases the
// element too. Nil when no named base type is recoverable.
func recvNamedType(recv types.Type) *types.Named {
	recv = types.Unalias(recv)
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	named, _ := recv.(*types.Named)
	return named
}

// canonicalRecv prefers the type-checked receiver spelling over the AST
// one: checked evidence canonicalizes alias receivers, unchecked or
// unparsable declarations keep the syntactic name.
func canonicalRecv(d *decisions, astName string) string {
	if d == nil || d.recv == "" {
		return astName
	}
	return d.recv
}

// walkSelectors classifies every selector expression in the declaration.
func walkSelectors(decl ast.Decl, target *types.Package, decls map[types.Object]bool, info *types.Info, d *decisions) {
	ast.Inspect(decl, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			selectorDecision(sel, target, decls, info, d)
		}
		return true
	})
}

// walkIdents classifies bare identifiers that are not selector parts:
// selector qualifiers and members are handled by walkSelectors.
func walkIdents(decl ast.Decl, target *types.Package, decls map[types.Object]bool, info *types.Info, d *decisions) {
	skip := map[*ast.Ident]bool{}
	ast.Inspect(decl, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			// A qualifier that names an import is excluded from bare-ident
			// handling, but the alias itself stays a reference: import
			// change binding resolves the using units through it, exactly
			// as the name-based floor always recorded it. Every other
			// qualifier is a value (a global receiver included) and stays
			// a bare ident.
			if q, ok := sel.X.(*ast.Ident); ok {
				if pn, isPkg := info.Uses[q].(*types.PkgName); isPkg {
					d.refs[pn.Name()] = true
					skip[q] = true
				}
			}
			skip[sel.Sel] = true
		}
		return true
	})
	ast.Inspect(decl, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && !skip[id] {
			identDecision(id, target, decls, info, d)
		}
		return true
	})
}

// selectorDecision binds one selector with type facts: interface
// receivers widen, concrete receivers (pointer indirection included) bind
// exactly, func-typed field selections stay dynamic uncertainty in every
// position, qualified foreign members never bind to local names.
func selectorDecision(sel *ast.SelectorExpr, target *types.Package, decls map[types.Object]bool, info *types.Info, d *decisions) {
	if s, ok := info.Selections[sel]; ok {
		selectorMemberDecision(sel, s, target, decls, d)
		return
	}
	q, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	pn, ok := info.Uses[q].(*types.PkgName)
	if !ok {
		return
	}
	if samePackage(pn.Imported(), target) {
		memberDecision(info.Uses[sel.Sel], d)
	}
}

// selectorMemberDecision splits a checked method or field selection.
// Foreign members never bind: a concrete foreign method is not a
// reference to a local name, however precisely typed; only methods
// declared in the analyzed package — or, for an external test group,
// methods that group's own files declare on its types, bound by object
// identity through the source-declaration index — produce exact refs.
// Instantiated methods resolve through their origin, so a generic
// group type's probe[int] spelling binds the one probe[T] declaration.
// Both branches record under the receiver-qualified key (probe.allow):
// two same-named methods on distinct receivers are distinct helpers,
// never one bare name. Interface dispatch (including promotion through
// embedded interfaces) widens by name, matching the consumer's
// conservative semantics. A func-typed field keeps dynamic uncertainty
// in every position: capture, direct call and parenthesized call all
// leave which function runs unresolved.
func selectorMemberDecision(sel *ast.SelectorExpr, s *types.Selection, target *types.Package, decls map[types.Object]bool, d *decisions) {
	switch obj := s.Obj().(type) {
	case *types.Func:
		if methodOnInterface(obj) {
			d.selrefs[sel.Sel.Name] = true
		} else if samePackage(methodDeclPkg(obj), target) || decls[obj.Origin()] {
			recordMethodRef(obj, d)
		}
	case *types.Var:
		if isSignature(obj.Type()) {
			d.selrefs[sel.Sel.Name] = true
		}
	}
}

// recordMethodRef records one selected concrete method helper reference
// under its receiver-qualified key. When the declaring receiver cannot be
// recovered the bare name is recorded instead and marked as floor: bare
// then means broad lookup, never a checked package-level function, and
// the consumer fans such a spelling to every same-named twin.
func recordMethodRef(obj *types.Func, d *decisions) {
	if key, ok := methodRefName(obj); ok {
		d.refs[key] = true
		return
	}
	name := obj.Origin().Name()
	d.refs[name] = true
	d.floorRefs[name] = true
}

// methodRefName is the reference key of one selected concrete method
// helper: receiver base type plus method name, the same form the unit
// scanner reports in a method declaration's recv field. Both an
// instantiated method and its origin spell one key — probe[int] and
// probe[T] both report probe.allow. The second result reports whether a
// named receiver was recovered; without one the bare name is not a
// qualified identity and the caller must treat it as floor.
func methodRefName(fn *types.Func) (string, bool) {
	origin := fn.Origin()
	sig, ok := origin.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return origin.Name(), false
	}
	// Alias receivers — value or pointer spelling — normalize through
	// recvNamedType, so a method declared as `func (a A) M()` keys
	// "B.M" exactly like every call through B; without unaliasing the
	// alias node would key "A.M" and methodDeclPkg would drop the
	// selection entirely.
	if named := recvNamedType(sig.Recv().Type()); named != nil {
		return named.Obj().Name() + "." + origin.Name(), true
	}
	return origin.Name(), false
}

// samePackage reports whether two packages share one import path. The
// external test group resolves the analyzed production package from
// memory and binds its members by that path identity, not by pointer:
// separate checker instances of one import path are one target.
func samePackage(a, b *types.Package) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Path() == b.Path()
}

// methodDeclPkg returns the package whose type declares the method;
// promoted and instantiated methods resolve to their declaration site.
// Alias receivers normalize through recvNamedType like every identity.
func methodDeclPkg(fn *types.Func) *types.Package {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	if named := recvNamedType(sig.Recv().Type()); named != nil {
		return named.Obj().Pkg()
	}
	return nil
}

// isGroupMethod reports whether obj is a method declared on a type of
// package pkg. Method objects never sit at package scope — a method's
// scope parent is nil — so the group's source-identity index admits
// them through the receiver type's declaration package instead.
func isGroupMethod(obj types.Object, pkg *types.Package) bool {
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	return samePackage(methodDeclPkg(fn), pkg)
}

// methodOnInterface reports whether the found method is declared on an
// interface type: that includes methods promoted into a struct through an
// embedded interface, which stay dynamic. Unparsable signatures widen.
func methodOnInterface(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return true
	}
	_, iface := sig.Recv().Type().Underlying().(*types.Interface)
	return iface
}

// memberDecision records a qualified reference to the analyzed package.
func memberDecision(obj types.Object, d *decisions) {
	switch obj.(type) {
	case *types.Func, *types.Var, *types.Const, *types.TypeName:
		d.refs[obj.Name()] = true
	}
}

// identDecision records bare identifiers that resolve to the analyzed
// package's own globals and — for an external test group — to a helper
// that is one of that group's package-level source declarations, bound
// by object identity through the group's Defs index. Locals, universe
// names, dot-imported production names (already bound above) and
// foreign objects never bind here.
func identDecision(id *ast.Ident, target *types.Package, decls map[types.Object]bool, info *types.Info, d *decisions) {
	obj := info.Uses[id]
	if obj == nil {
		return
	}
	if samePackage(obj.Pkg(), target) && obj.Parent() == target.Scope() {
		memberDecision(obj, d)
		return
	}
	if decls[obj] {
		memberDecision(obj, d)
	}
}

// isSignature reports whether a type is function-shaped.
func isSignature(t types.Type) bool {
	_, ok := t.Underlying().(*types.Signature)
	return ok
}

// unionNames merges two name sets without mutating either.
func unionNames(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func sortedNames(values map[string]bool) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// directiveDigest fingerprints compiler/build directive comments. Pure
// comments never enter AST identity; //go: and legacy // +build directives
// are compiler-visible and keep their own file-level fingerprint.
func directiveDigest(src []byte) string {
	var directives []string
	fs := token.NewFileSet()
	file := fs.AddFile("directives", 1, len(src))
	var scanner_ scanner.Scanner
	scanner_.Init(file, src, nil, scanner.ScanComments)
	for {
		position, tok, literal := scanner_.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT && isDirective(literal) {
			directives = append(directives, fmt.Sprintf("%d:%s", fs.Position(position).Line, literal))
		}
	}
	if len(directives) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(directives, "\n")))
	return hex.EncodeToString(sum[:])
}

func isDirective(literal string) bool {
	return strings.HasPrefix(literal, "//go:") || strings.HasPrefix(literal, "// +build")
}
