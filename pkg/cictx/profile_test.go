package cictx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/labels"
)

func TestProfileUnknownFieldAndBadRegex(t *testing.T) {
	dir := t.TempDir()
	unknown := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(unknown, []byte("version: 1\nextra: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(unknown); err == nil {
		t.Fatal("unknown field")
	}
	bad := filepath.Join(dir, "regex.yml")
	body := "version: 1\nlabels:\n  extract:\n    - {label: issue, from: [branch], regex: '(', template: '$1'}\n"
	if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(bad); err == nil {
		t.Fatal("bad regex")
	}
}

func TestBuildMissingFailAndFlagWins(t *testing.T) {
	profile := &Profile{Version: 1, Require: []string{"issue"}, OnMissing: "fail", Labels: ProfileLabels{Static: map[string]string{"team": "payments"}}}
	_, _, missing, err := Build(Context{Labels: labels.Set{}}, profile, MapEnv{}, nil)
	var exit *ExitError
	if err == nil || !asExit(err, &exit) || exit.Code != 3 || len(missing) != 1 {
		t.Fatalf("err %v missing %#v", err, missing)
	}
	flags := labels.Set{"team": "platform", "issue": "PAY-2"}
	got, dropped, missing, err := Build(Context{Labels: labels.Set{"team": "ci"}}, profile, MapEnv{}, flags)
	if err != nil || len(missing) != 0 || got["team"] != "platform" || got["issue"] != "PAY-2" {
		t.Fatalf("got %#v dropped %#v missing %#v err %v", got, dropped, missing, err)
	}
}

func TestFindProfileOrder(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	repoProfile := filepath.Join(root, ".yabanin.yml")
	if err := os.WriteFile(repoProfile, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := FindProfile(MapEnv{}, root, "")
	if err != nil || got != repoProfile {
		t.Fatalf("repo %q %v", got, err)
	}
	flag := filepath.Join(root, "other.yml")
	if err := os.WriteFile(flag, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = FindProfile(MapEnv{"YABANIN_PROFILE": repoProfile}, root, flag)
	if err != nil || got != flag {
		t.Fatalf("flag %q %v", got, err)
	}
	if _, err := FindProfile(MapEnv{}, t.TempDir(), ""); err != nil {
		t.Fatal(err)
	}
}

func asExit(err error, target **ExitError) bool {
	exit, ok := err.(*ExitError)
	if ok {
		*target = exit
	}
	return ok
}
