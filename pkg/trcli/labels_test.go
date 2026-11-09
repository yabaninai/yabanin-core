package trcli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
)

func TestLabelsShowFormats(t *testing.T) {
	dir := t.TempDir()
	cases := []string{"header", "json", "env", "github", "gitlab"}
	for _, format := range cases {
		t.Run(format, func(t *testing.T) {
			got, err := runTr(t, "labels", "show", "--dir", dir, "--format", format, "--label", "team=payments", "--label", "issue=PAY-1")
			if err != nil {
				t.Fatal(err)
			}
			want := readGolden(t, "labels_"+format+".golden")
			if got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}

func TestLabelsShowEnvQuotesSpecialChars(t *testing.T) {
	dir := t.TempDir()
	got, err := runTr(t, "labels", "show", "--dir", dir, "--format", "env", "--label", "note=a b'c")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "export YABANIN_LABELS='") || strings.Contains(got, "a b") {
		t.Fatalf("not shell-quoted: %q", got)
	}
	if !strings.Contains(got, `'\''`) && !strings.Contains(got, "%27") {
		t.Fatalf("quote not escaped: %q", got)
	}
}

func TestLabelsExplainFlagBeatsProfile(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "p.yml")
	body := "version: 1\nlabels:\n  static:\n    team: payments\n    issue: NO\n"
	if err := os.WriteFile(profile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := runTr(t, "labels", "explain", "--dir", dir, "--profile", profile, "--label", "issue=PAY-9")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "issue | PAY-9 | flag | ok") || !strings.Contains(got, "team | payments | profile.static | ok") {
		t.Fatalf("%s", got)
	}
}

func TestLabelsExplainServerPolicy(t *testing.T) {
	dir := t.TempDir()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/yabanin/label-policy" || r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(labels.Policy{AllowedKeys: []string{"team"}, OnInvalid: "drop", OnMissing: "allow"})
	}))
	defer okSrv.Close()
	got, err := runTr(t, "--base-url", okSrv.URL, "--api-key", "test-key", "labels", "explain", "--dir", dir, "--label", "team=payments", "--label", "issue=PAY-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "server keeps:") || !strings.Contains(got, "team | payments | server | ok") || !strings.Contains(got, "issue |  | server | dropped:not_allowed") {
		t.Fatalf("%s", got)
	}

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer missing.Close()
	got, err = runTr(t, "--base-url", missing.URL, "--api-key", "test-key", "labels", "explain", "--dir", dir, "--label", "team=payments")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "server policy unknown (gateway without AT-15)") {
		t.Fatalf("%s", got)
	}
}

func TestLabelsShowMissingRequiredExitCode(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "p.yml")
	body := "version: 1\nrequire: [issue]\non_missing: fail\n"
	if err := os.WriteFile(profile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runTr(t, "labels", "show", "--dir", dir, "--profile", profile)
	var exit *cictx.ExitError
	if err == nil || !asExit(err, &exit) || exit.Code != 3 {
		t.Fatalf("err %v", err)
	}
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: testdata fixture basename, not user input
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		return string(raw) + "\n"
	}
	return string(raw)
}

func asExit(err error, target **cictx.ExitError) bool {
	exit, ok := err.(*cictx.ExitError)
	if ok {
		*target = exit
	}
	return ok
}
