package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCommittedBundlesReproduce(t *testing.T) {
	raw, err := os.ReadFile("../golden_routing.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	files, err := bundles(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, generated := range files {
		committed, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(generated, committed) {
			t.Errorf("%s differs from its deterministic public inputs", name)
		}
	}
}
