// SPDX-License-Identifier: Apache-2.0
//go:build ignore

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"os"
	"sort"
	"strings"
)

type unit struct {
	Name    string   `json:"name"`
	Start   int      `json:"start"`
	End     int      `json:"end"`
	Hash    string   `json:"hash"`
	Kind    string   `json:"kind,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
	Flags   []string `json:"flags,omitempty"`
	Refs    []string `json:"refs,omitempty"`
	SelRefs []string `json:"selrefs,omitempty"`
}

type fileUnits struct {
	Path       string `json:"path"`
	Units      []unit `json:"units"`
	Directives string `json:"directives,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run() error {
	var paths []string
	if err := json.NewDecoder(os.Stdin).Decode(&paths); err != nil {
		return err
	}
	files, table, err := parse(paths)
	if err != nil {
		return err
	}
	result := make([]fileUnits, 0, len(files))
	for _, item := range files {
		out, err := scan(item, table)
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

func scan(item parsedFile, table map[string]bool) (fileUnits, error) {
	out := fileUnits{Path: item.path, Units: []unit{}, Directives: directiveDigest(item.src)}
	for _, decl := range item.file.Decls {
		scanUnit, err := declaration(item.fs, decl, table)
		if err != nil {
			return out, err
		}
		out.Units = append(out.Units, scanUnit)
	}
	return out, nil
}

func declaration(fs *token.FileSet, decl ast.Decl, table map[string]bool) (unit, error) {
	item := unit{Start: fs.Position(decl.Pos()).Line, End: fs.Position(decl.End()).Line}
	node := ast.Node(decl)
	if fn, ok := decl.(*ast.FuncDecl); ok {
		item.Name = fn.Name.Name
		item.Kind = "func"
		item.Symbols = []string{fn.Name.Name}
		copy := *fn
		copy.Name = &ast.Ident{Name: "_"}
		node = &copy
	} else {
		item.Kind, item.Symbols, item.Flags = describe(decl)
	}
	hash, err := fingerprint(node)
	item.Hash = hash
	item.Refs, item.SelRefs = references(decl, table, item.Name)
	return item, err
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
	return kind, symbols, indirectFlags(gen)
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

// references lists package-level identifiers a declaration mentions. Matching
// is name-based without scope analysis, so shadowing can only add spurious
// references, never hide a real one; the consumer is conservative selection.
// Selector-position identifiers (x.Name, qualified pkg.Name and composite
// literal keys) are reported separately because they may denote dispatch.
func references(decl ast.Decl, table map[string]bool, own string) ([]string, []string) {
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
