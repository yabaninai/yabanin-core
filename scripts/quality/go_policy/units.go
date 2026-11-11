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
	"go/token"
	"os"
)

type unit struct {
	Name  string `json:"name"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Hash  string `json:"hash"`
}

type fileUnits struct {
	Path  string `json:"path"`
	Units []unit `json:"units"`
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
	result := make([]fileUnits, 0, len(paths))
	for _, path := range paths {
		item, err := scan(path)
		if err != nil {
			return err
		}
		result = append(result, item)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func scan(path string) (fileUnits, error) {
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, path, nil, 0)
	out := fileUnits{Path: path, Units: []unit{}}
	if err != nil {
		return out, err
	}
	for _, decl := range file.Decls {
		item, err := declaration(fs, decl)
		if err != nil {
			return out, err
		}
		out.Units = append(out.Units, item)
	}
	return out, nil
}

func declaration(fs *token.FileSet, decl ast.Decl) (unit, error) {
	item := unit{Start: fs.Position(decl.Pos()).Line, End: fs.Position(decl.End()).Line}
	node := ast.Node(decl)
	if fn, ok := decl.(*ast.FuncDecl); ok {
		item.Name = fn.Name.Name
		copy := *fn
		copy.Name = &ast.Ident{Name: "_"}
		node = &copy
	}
	hash, err := fingerprint(node)
	item.Hash = hash
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
