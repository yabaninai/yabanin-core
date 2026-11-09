package credstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRun struct {
	name  string
	args  []string
	stdin string
	out   string
	paths map[string]bool
}

func (f *fakeRun) Run(_ context.Context, stdin []byte, name string, args ...string) (string, error) {
	f.name = name
	f.args = append([]string(nil), args...)
	f.stdin = string(stdin)
	return f.out, nil
}

func (f *fakeRun) LookPath(file string) (string, error) {
	if f.paths[file] {
		return "/usr/bin/" + file, nil
	}
	return "", os.ErrNotExist
}

func TestKeychainPutKeepsKeyOffArgv(t *testing.T) {
	// The keychain type is compiled on every platform; the Runner is injected,
	// so the argv/stdin contract is checked against a fake helper instead of a
	// real keychain on non-darwin platforms.
	run := &fakeRun{out: "stored-secret"}
	store := keychain{run: run}
	ref, warning, err := store.Put(context.Background(), "default", `stored-secret"`)
	if err != nil || warning != "" || ref != "keychain:default" {
		t.Fatalf("ref %q warning %q err %v", ref, warning, err)
	}
	if run.name != "security" || len(run.args) != 1 || run.args[0] != "-i" {
		t.Fatalf("args %#v", run.args)
	}
	if strings.Contains(strings.Join(run.args, " "), "stored-secret") {
		t.Fatal("key leaked into argv")
	}
	if !strings.Contains(run.stdin, `add-generic-password`) || !strings.Contains(run.stdin, `\"`) {
		t.Fatalf("stdin %q", run.stdin)
	}
	got, err := store.Get(context.Background(), "default")
	if err != nil || got != "stored-secret" {
		t.Fatalf("get %q %v args %#v", got, err, run.args)
	}
	joined := strings.Join(run.args, " ")
	if strings.Contains(joined, "stored-secret") || !strings.Contains(joined, "find-generic-password") {
		t.Fatalf("get args %q", joined)
	}
}

func TestSecretToolPutKeepsKeyOffArgv(t *testing.T) {
	run := &fakeRun{out: "stored-secret"}
	store := secretTool{run: run}
	ref, _, err := store.Put(context.Background(), "default", "stored-secret")
	if err != nil || ref != "secret-tool:default" {
		t.Fatalf("ref %q err %v", ref, err)
	}
	if run.name != "secret-tool" || strings.Contains(strings.Join(run.args, " "), "stored-secret") {
		t.Fatalf("args %#v", run.args)
	}
	if run.stdin != "stored-secret" {
		t.Fatalf("stdin %q", run.stdin)
	}
}

func TestFileFallbackPermissions(t *testing.T) {
	home := t.TempDir()
	store := fileStore{home: home, warn: true}
	ref, warning, err := store.Put(context.Background(), "default", "stored-secret")
	if err != nil || ref != "file:default" || warning == "" {
		t.Fatalf("ref %q warning %q err %v", ref, warning, err)
	}
	info, err := os.Stat(store.path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", info.Mode().Perm())
	}
	dir, err := os.Stat(home + "/.yabanin")
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dir.Mode().Perm())
	}
	got, err := store.Get(context.Background(), "default")
	if err != nil || got != "stored-secret" {
		t.Fatalf("get %q %v", got, err)
	}
}

func TestFileFallbackDeleteRoundTrip(t *testing.T) {
	store := fileStore{home: t.TempDir()}
	if err := store.Delete(context.Background(), "absent"); err != nil {
		t.Fatalf("delete with no credentials file: %v", err)
	}
	if _, _, err := store.Put(context.Background(), "a", "va"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Put(context.Background(), "b", "vb"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "a"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("get deleted entry: %v", err)
	}
	if got, err := store.Get(context.Background(), "b"); err != nil || got != "vb" {
		t.Fatalf("get surviving entry %q %v", got, err)
	}
}

func TestFileFallbackCorruptFileErrors(t *testing.T) {
	store := fileStore{home: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(store.path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "a"); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("get on corrupt file: %v", err)
	}
	if err := store.Delete(context.Background(), "a"); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delete on corrupt file: %v", err)
	}
}

func TestFileFallbackPutRejectsFileHome(t *testing.T) {
	// A regular file where the credentials directory must live makes
	// MkdirAll fail, and Put must surface that error instead of writing.
	home := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(home, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := fileStore{home: home}
	if _, _, err := store.Put(context.Background(), "a", "va"); err == nil {
		t.Fatal("put into a file-shaped home must fail")
	}
}
