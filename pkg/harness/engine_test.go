package harness

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyRollbackRoundTrip(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "app.toml")
	before := []byte("owner = \"me\"\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	after := []byte("# >>> yabanin:codex:top (managed by `yb harness`; undo: `yb harness disconnect codex`) >>>\nmodel_provider = \"yabanin\"\n# <<< yabanin:codex:top <<<\nowner = \"me\"\n")
	eng := &Engine{Home: home, Now: func() time.Time { return time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC) }}
	if _, err := eng.Apply(Plan{Tool: "codex", Changes: []Change{{
		Path: path, Kind: KindEdit, Before: before, After: after,
		Managed: Managed{Blocks: []string{"codex:top"}},
	}}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(home, ".yabanin", "harness", "backups"))
	if err != nil {
		t.Fatal(err)
	}
	_ = info
	orig := filepath.Join(home, ".yabanin", "harness", "backups")
	var mode os.FileMode
	_ = filepath.Walk(orig, func(p string, st os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".orig") {
			mode = st.Mode().Perm()
		}
		return nil
	})
	if mode != 0o600 {
		t.Fatalf("backup mode %o", mode)
	}
	report, err := eng.Rollback("codex", nil)
	if err != nil || report.Status != "rolled_back" {
		t.Fatalf("%+v %v", report, err)
	}
	got := readTemp(path)
	if !bytes.Equal(got, before) {
		t.Fatalf("got %q", got)
	}
}

func TestRollbackDeletesCreatedFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "new.toml")
	eng := &Engine{Home: home}
	if _, err := eng.Apply(Plan{Tool: "codex", Changes: []Change{{
		Path: path, Kind: KindCreate, After: []byte("a=1\n"),
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Rollback("codex", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file remains %v", err)
	}
}

func TestSurgicalRollbackKeepsUserLines(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "app.toml")
	before := []byte("owner = \"me\"\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	after := []byte("# >>> yabanin:codex:top (managed) >>>\nmodel_provider = \"yabanin\"\n# <<< yabanin:codex:top <<<\nowner = \"me\"\n")
	eng := &Engine{Home: home}
	if _, err := eng.Apply(Plan{Tool: "codex", Changes: []Change{{
		Path: path, Before: before, After: after, Managed: Managed{Blocks: []string{"codex:top"}},
	}}}); err != nil {
		t.Fatal(err)
	}
	edited := append(after, []byte("user = \"kept\"\n")...)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := eng.Rollback("codex", func(_ string, current []byte, m Managed) ([]byte, error) {
		return RemoveManagedBlocks(current, m.Blocks), nil
	})
	if err != nil || report.Files[0].Action != "unapplied" {
		t.Fatalf("%+v %v", report, err)
	}
	got := readTemp(path)
	if bytes.Contains(got, []byte("yabanin:codex")) || !bytes.Contains(got, []byte("user = \"kept\"")) || !bytes.Contains(got, []byte("owner = \"me\"")) {
		t.Fatalf("%s", got)
	}
	st, err := eng.Status()
	if err != nil || len(st) != 1 || st[0].Status != "rolled_back" {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestSecondWriteFailureRestoresFirst(t *testing.T) {
	home := t.TempDir()
	first := filepath.Join(home, "a.txt")
	second := filepath.Join(home, "b.txt")
	if err := os.WriteFile(first, []byte("A"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{Home: home, FS: failPathFS{fail: second}}
	_, err := eng.Apply(Plan{Tool: "t", Changes: []Change{
		{Path: first, Before: []byte("A"), After: []byte("A2")},
		{Path: second, Kind: KindCreate, After: []byte("B")},
	}})
	if err == nil || err.Error() != "injected" {
		t.Fatalf("%v", err)
	}
	got := readTemp(first)
	if string(got) != "A" {
		t.Fatalf("first %q", got)
	}
	if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("second was left behind")
	}
}

func TestLockBusy(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".yabanin", "harness"), 0o700); err != nil {
		t.Fatal(err)
	}
	release, err := acquireLock(filepath.Join(home, ".yabanin", "harness", ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	eng := &Engine{Home: home}
	_, err = eng.Apply(Plan{Tool: "t", Changes: []Change{{Path: filepath.Join(home, "n.txt"), Kind: KindCreate, After: []byte("x")}}})
	if !errors.Is(err, errLockBusy) {
		t.Fatalf("%v", err)
	}
}

func TestStatusDrift(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "a.txt")
	eng := &Engine{Home: home}
	if _, err := eng.Apply(Plan{Tool: "t", Changes: []Change{{Path: path, Kind: KindCreate, After: []byte("v1")}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := eng.Status()
	if err != nil || !st[0].Drift || st[0].Status != "applied" {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestSymlinkWritesTarget(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "real.txt")
	link := filepath.Join(home, "link.txt")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{Home: home}
	if _, err := eng.Apply(Plan{Tool: "t", Changes: []Change{{Path: link, Before: []byte("old"), After: []byte("new")}}}); err != nil {
		t.Fatal(err)
	}
	got := readTemp(target)
	if string(got) != "new" {
		t.Fatalf("target %q", got)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
}

func TestMaskAndJSON(t *testing.T) {
	diff := Diff("c.yml", []byte("api_key: super\n"), []byte("api_key: other\n"))
	if bytes.Contains([]byte(diff), []byte("super")) || bytes.Contains([]byte(diff), []byte("other")) || !bytes.Contains([]byte(diff), []byte("***")) {
		t.Fatalf("%s", diff)
	}
	doc := map[string]any{"env": map[string]any{"A": "1"}}
	prev, existed := SetPath(doc, "env.A", "2")
	if prev != "1" || !existed || doc["env"].(map[string]any)["A"] != "2" {
		t.Fatalf("%#v", doc)
	}
	RestorePath(doc, "env.A", prev, existed)
	if doc["env"].(map[string]any)["A"] != "1" {
		t.Fatalf("%#v", doc)
	}
	out := RestoreDisabled([]byte("# yabanin-disabled: model_provider = \"openai\"\n"), []string{`model_provider = "openai"`})
	if string(out) != "model_provider = \"openai\"\n" {
		t.Fatalf("%q", out)
	}
}

type failPathFS struct {
	osFS
	fail string
}

func (f failPathFS) AtomicWrite(path string, data []byte, perm os.FileMode) error {
	if path == f.fail {
		return errors.New("injected")
	}
	return f.osFS.AtomicWrite(path, data, perm)
}

func readTemp(path string) []byte {
	body, err := os.ReadFile(path) //nolint:gosec // G304: path is a file under t.TempDir created by this test
	if err != nil {
		return nil
	}
	return body
}
