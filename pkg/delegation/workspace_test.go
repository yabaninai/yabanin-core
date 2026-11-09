package delegation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfineWorkspace_ResolvesAndRejectsFile(t *testing.T) {
	dir := t.TempDir()
	got, err := ConfineWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertInside(got, dir); err != nil {
		t.Fatalf("confined %q not equivalent to %q: %v", got, dir, err)
	}
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ConfineWorkspace(f); err == nil {
		t.Fatal("expected error for file workspace")
	}
}

func TestAssertInside_BlocksSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := AssertInside(root, filepath.Join(link, "secret.txt")); err == nil {
		t.Fatal("symlink escape must be rejected")
	}
	inside := filepath.Join(root, "ok.go")
	if err := os.WriteFile(inside, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AssertInside(root, inside); err != nil {
		t.Fatal(err)
	}
}

func TestAssertInside_BlocksDotDot(t *testing.T) {
	root := t.TempDir()
	if err := AssertInside(root, filepath.Join(root, "..", "nope")); err == nil {
		t.Fatal("expected escape")
	}
}
