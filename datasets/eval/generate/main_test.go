package main

import (
	"bytes"
	"os"
	"testing"
)

func TestCommittedBundlesReproduce(t *testing.T) {
	root, err := os.OpenRoot("..")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	raw, err := root.ReadFile("golden_routing.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	files, err := bundles(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, generated := range files {
		committed, err := root.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(generated, committed) {
			t.Errorf("%s differs from its deterministic public inputs", name)
		}
	}
}
