// go_funcscan.go is the AST backend for the Go complexity differential
// analyzer (go_complexity.py). It is deliberately a single stdlib-only file
// so `go run <abs-path>/go_funcscan.go` works from inside any repository or
// temp directory without a module context.
//
// Output contract (stable JSON, deterministic for identical inputs):
//
//	{"go_version": "...", "files": [{"path": ..., "parse_ok": bool,
//	  "error": "...", "functions": [{"name", "line", "body_sha256",
//	  "cyclomatic", "cognitive"}]}]}
//
// body_sha256 identifies a function by signature-without-name plus body:
//
//	sha256( canonical(Recv) NUL canonical(FuncType) NUL canonical(Body) )
//
// where canonical() prints the AST through go/printer against a synthetic
// file set that maps every position to line 1. This makes the printed form
// independent of source formatting and line breaks, and comments are not
// attached to sub-nodes so they are dropped: two functions with identical
// code hash identically even after reformatting or a rename, which is what
// the differential analyzer relies on to detect moved/renamed functions.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"runtime"
)

// canonicalSpan bounds the synthetic file so every real position in any
// parsed source (files here are far below 1 GiB) resolves to line 1.
const canonicalSpan = 1 << 30

// scannedFunction is one package-level function, method or package-level
// closure. Cyclomatic/Cognitive are nil only for bodyless declarations
// (e.g. assembly-backed stubs): there is no body to measure.
type scannedFunction struct {
	Name       string `json:"name"`
	Line       int    `json:"line"`
	BodySHA256 string `json:"body_sha256"`
	Cyclomatic *int   `json:"cyclomatic"`
	Cognitive  *int   `json:"cognitive"`
}

type fileResult struct {
	Path      string            `json:"path"`
	ParseOK   bool              `json:"parse_ok"`
	Error     string            `json:"error,omitempty"`
	Functions []scannedFunction `json:"functions"`
}

type scanResult struct {
	GoVersion string       `json:"go_version"`
	Files     []fileResult `json:"files"`
}

func main() {
	// Files starts as an empty (not nil) slice so zero input paths emit
	// "files": [] per the output contract instead of JSON null, which
	// would crash consumers iterating the field (e.g. a diff with no
	// measured Go files).
	result := scanResult{GoVersion: runtime.Version(), Files: []fileResult{}}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		path := scanner.Text()
		if path != "" {
			result.Files = append(result.Files, scanFile(path))
		}
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(&result); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "go_funcscan:", err)
	os.Exit(1)
}

func scanFile(path string) fileResult {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return fileResult{Path: path, Error: err.Error()}
	}
	result := fileResult{Path: path, ParseOK: true, Functions: []scannedFunction{}}
	for _, decl := range file.Decls {
		switch node := decl.(type) {
		case *ast.FuncDecl:
			result.Functions = append(result.Functions, newFunc(fset, node))
		case *ast.GenDecl:
			result.Functions = append(result.Functions, varFuncs(fset, node)...)
		}
	}
	return result
}

// newFunc measures one FuncDecl. The hash covers receiver, signature
// (without the name, so a pure rename still matches) and body.
func newFunc(fset *token.FileSet, decl *ast.FuncDecl) scannedFunction {
	entry := scannedFunction{
		Name: qualName(decl),
		Line: fset.Position(decl.Pos()).Line,
	}
	entry.BodySHA256 = signatureHash(decl)
	if decl.Body != nil {
		cyc := cyclomatic(decl.Body)
		cog := cognitive(decl.Name.Name, decl.Body)
		entry.Cyclomatic, entry.Cognitive = &cyc, &cog
	}
	return entry
}

// varFuncs reports package-level `var f = func(...){...}` closures; they are
// gate-relevant callbacks that a FuncDecl-only scan would miss.
func varFuncs(fset *token.FileSet, decl *ast.GenDecl) []scannedFunction {
	var found []scannedFunction
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok || len(value.Values) == 0 {
			continue
		}
		for index, name := range value.Names {
			if index >= len(value.Values) {
				break
			}
			lit, ok := value.Values[index].(*ast.FuncLit)
			if !ok {
				continue
			}
			found = append(found, newClosure(fset, name.Name, lit))
		}
	}
	return found
}

func newClosure(fset *token.FileSet, name string, lit *ast.FuncLit) scannedFunction {
	entry := scannedFunction{
		Name: "var:" + name,
		Line: fset.Position(lit.Pos()).Line,
	}
	digest := sha256.New()
	digest.Write([]byte(canonical(lit.Type)))
	digest.Write([]byte{0})
	digest.Write([]byte(canonical(lit.Body)))
	entry.BodySHA256 = hex.EncodeToString(digest.Sum(nil))
	cyc := cyclomatic(lit.Body)
	cog := cognitive(name, lit.Body)
	entry.Cyclomatic, entry.Cognitive = &cyc, &cog
	return entry
}

// qualName returns "Func", "recv.Method" or "pkg.Type.Method" style names;
// the receiver distinguishes methods from same-named free functions.
func qualName(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return decl.Name.Name
	}
	return canonical(decl.Recv.List[0].Type) + "." + decl.Name.Name
}

// signatureHash digests receiver + signature-without-name + body so a pure
// rename keeps its identity while any signature or body change does not.
func signatureHash(decl *ast.FuncDecl) string {
	parts := make([]string, 0, 3)
	if decl.Recv != nil {
		parts = append(parts, canonical(decl.Recv))
	}
	parts = append(parts, canonical(decl.Type))
	if decl.Body != nil {
		parts = append(parts, canonical(decl.Body))
	}
	return digestParts(parts)
}

func digestParts(parts []string) string {
	digest := sha256.New()
	for index, part := range parts {
		if index > 0 {
			digest.Write([]byte{0})
		}
		digest.Write([]byte(part))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// canonical prints a node through go/printer against a synthetic single-line
// file set (see the package comment for why this normalizes formatting).
func canonical(node ast.Node) string {
	if node == nil || node.End() > token.Pos(canonicalSpan) {
		return "canonical-overflow"
	}
	fset := token.NewFileSet()
	fset.AddFile("canonical.go", -1, canonicalSpan)
	var buffer bytes.Buffer
	if err := printer.Fprint(&buffer, fset, node); err != nil {
		return "canonical-error"
	}
	return buffer.String()
}

// cyclomatic counts independent control-flow paths (gocyclo-style rules):
// 1 + #if + #for + #case clause + #select comm clause + #&& + #||
// Default clauses count as clauses (a default is a *ast.CaseClause with an
// empty value list, matching gocyclo); else adds nothing, a clause with
// several listed values adds 1, and func literals count toward the
// enclosing function so closures are measured rather than skipped.
func cyclomatic(body ast.Node) int {
	score := 1
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			score++
		case *ast.BinaryExpr:
			if isLogicalOp(n.Op) {
				score++
			}
		}
		return true
	})
	return score
}

func isLogicalOp(op token.Token) bool {
	return op == token.LAND || op == token.LOR
}

// cognitive implements Sonar-style cognitive complexity adapted to Go.
// Counting rules (documented in the analyzer report):
//   - if / for / range / switch / type-switch / select: +1 +nesting level
//   - else: +1 flat; "else if" is an if at the same nesting level
//   - labeled break/continue and goto: +1 flat
//   - each maximal run of the same && / || operator in one expression: +1 flat
//   - direct call to the enclosing function's name: +1 flat (recursion)
//   - nesting increases inside if/loop/switch/select bodies and func literals
//   - everything inside a switch/select body counts as nesting+1
type cognitiveVisitor struct {
	total  int
	fnName string
}

func cognitive(name string, body *ast.BlockStmt) int {
	visitor := &cognitiveVisitor{fnName: name}
	visitor.children(body, 0)
	return visitor.total
}

func (v *cognitiveVisitor) visit(node ast.Node, nesting int) {
	switch n := node.(type) {
	case *ast.IfStmt:
		v.ifStmt(n, nesting)
	case *ast.ForStmt:
		v.loop([]ast.Node{n.Init, n.Cond, n.Post}, n.Body, nesting)
	case *ast.RangeStmt:
		v.loop([]ast.Node{n.Key, n.Value, n.X}, n.Body, nesting)
	case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		v.structure(n, nesting)
	case *ast.FuncLit:
		v.block(nil, n.Body, nesting)
	case *ast.BinaryExpr:
		v.logical(n, nesting)
	case *ast.CallExpr:
		v.call(n, nesting)
	case *ast.BranchStmt:
		v.branch(n)
	default:
		v.children(node, nesting)
	}
}

// children visits each direct child of node exactly once; each child then
// recurses through visit with its own nesting, which ast.Inspect's flat
// walk cannot track on its own.
func (v *cognitiveVisitor) children(node ast.Node, nesting int) {
	ast.Inspect(node, func(child ast.Node) bool {
		if child == nil || child == node {
			return true
		}
		v.visit(child, nesting)
		return false
	})
}

// block walks non-body parts at the current nesting and the body one level
// deeper.
func (v *cognitiveVisitor) block(parts []ast.Node, body *ast.BlockStmt, nesting int) {
	for _, part := range parts {
		if part != nil {
			v.children(part, nesting)
		}
	}
	v.children(body, nesting+1)
}

func (v *cognitiveVisitor) loop(parts []ast.Node, body *ast.BlockStmt, nesting int) {
	v.total += 1 + nesting
	v.block(parts, body, nesting)
}

// structure scores switch/type-switch/select (+1 +nesting) and walks the
// whole clause list one level deeper.
func (v *cognitiveVisitor) structure(node ast.Node, nesting int) {
	v.total += 1 + nesting
	v.children(bodyOf(node), nesting+1)
}

func bodyOf(node ast.Node) ast.Node {
	switch n := node.(type) {
	case *ast.SwitchStmt:
		return n.Body
	case *ast.TypeSwitchStmt:
		return n.Body
	case *ast.SelectStmt:
		return n.Body
	}
	return node
}

func (v *cognitiveVisitor) ifStmt(node *ast.IfStmt, nesting int) {
	v.total += 1 + nesting
	v.block([]ast.Node{node.Init, node.Cond}, node.Body, nesting)
	v.elseBranch(node.Else, nesting)
}

func (v *cognitiveVisitor) elseBranch(elseNode ast.Node, nesting int) {
	if elseNode == nil {
		return
	}
	if nested, ok := elseNode.(*ast.IfStmt); ok {
		v.visit(nested, nesting)
		return
	}
	v.total++
	v.children(elseNode, nesting)
}

func (v *cognitiveVisitor) branch(node *ast.BranchStmt) {
	if node.Label != nil {
		v.total++
	}
}

func (v *cognitiveVisitor) call(node *ast.CallExpr, nesting int) {
	if calleeName(node.Fun) == v.fnName {
		v.total++
	}
	v.children(node, nesting)
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// logical scores one maximal-run-per-operator (+1 each) and then walks only
// the non-logical operands so nested operators are not counted twice.
func (v *cognitiveVisitor) logical(node *ast.BinaryExpr, nesting int) {
	v.total += logicalRuns(node)
	v.operand(node.X, nesting)
	v.operand(node.Y, nesting)
}

func (v *cognitiveVisitor) operand(node ast.Node, nesting int) {
	if binary, ok := node.(*ast.BinaryExpr); ok && isLogicalOp(binary.Op) {
		return
	}
	v.visit(node, nesting)
}

func logicalRuns(root *ast.BinaryExpr) int {
	ops := logicalOps(root, nil)
	runs, previous := 0, token.ILLEGAL
	for _, op := range ops {
		if op != previous {
			runs++
		}
		previous = op
	}
	return runs
}

func logicalOps(node ast.Expr, ops []token.Token) []token.Token {
	binary, ok := node.(*ast.BinaryExpr)
	if !ok || !isLogicalOp(binary.Op) {
		return ops
	}
	ops = logicalOps(binary.X, ops)
	return logicalOps(binary.Y, append(ops, binary.Op))
}
