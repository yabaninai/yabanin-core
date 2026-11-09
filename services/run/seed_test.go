package run

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
)

func TestParseSeedFlags_Flags(t *testing.T) {
	flags, err := ParseSeedFlags([]string{
		"--profile", "provider",
		"--admin-email=admin@example.com",
		"--upstream-key-file", "/tmp/k",
		"--upstream-url", "https://api.example.com/v1",
		"--model", "m1",
		"--org-name", "Acme Org",
		"--admin-password-stdin",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := SeedFlags{
		Profile:            "provider",
		AdminEmail:         "admin@example.com",
		UpstreamKeyFile:    "/tmp/k",
		UpstreamURL:        "https://api.example.com/v1",
		ModelName:          "m1",
		OrgName:            "Acme Org",
		AdminPasswordStdin: true,
	}
	if flags != want {
		t.Fatalf("got %+v, want %+v", flags, want)
	}
}

func TestParseSeedFlags_MissingValue(t *testing.T) {
	for _, args := range [][]string{
		{"--profile"},
		{"--admin-email"},
		{"--upstream-key-file"},
	} {
		if _, err := ParseSeedFlags(args); err == nil {
			t.Fatalf("args %v: expected error for missing value", args)
		}
	}
}

func TestParseSeedFlags_UnknownFlag(t *testing.T) {
	if _, err := ParseSeedFlags([]string{"--frobnicate"}); err == nil {
		t.Fatal("expected unknown flag error")
	}
}

func TestParseSeedFlags_InlineBoolRejected(t *testing.T) {
	if _, err := ParseSeedFlags([]string{"--admin-password-stdin=true"}); err == nil {
		t.Fatal("--admin-password-stdin must not take a value")
	}
}

func TestParseSeedFlags_EnvDefaults(t *testing.T) {
	t.Setenv("SEED_PROFILE", "mock")
	t.Setenv("SEED_ADMIN_EMAIL", "env@example.com")
	t.Setenv("SEED_ORG_NAME", "Env Org")
	t.Setenv("SEED_UPSTREAM_URL", "http://env-upstream:1234")
	t.Setenv("SEED_UPSTREAM_KEY_FILE", "/env/key")
	t.Setenv("SEED_MODEL", "env-model")

	flags, err := ParseSeedFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if flags.Profile != "mock" || flags.AdminEmail != "env@example.com" ||
		flags.OrgName != "Env Org" || flags.UpstreamURL != "http://env-upstream:1234" ||
		flags.UpstreamKeyFile != "/env/key" || flags.ModelName != "env-model" {
		t.Fatalf("env defaults not applied: %+v", flags)
	}

	// A flag wins over the environment default.
	flags, err = ParseSeedFlags([]string{"--admin-email", "flag@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if flags.AdminEmail != "flag@example.com" {
		t.Fatalf("flag must override env, got %q", flags.AdminEmail)
	}
}

func TestSeedFlagsResolve_MockDefaults(t *testing.T) {
	opts, err := SeedFlags{Profile: "mock", AdminEmail: "a@b.c"}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	// The mock default is the quickstart compose pin (deploy/quickstart/
	// docker-compose.yml): a literal IP, because the gateway's D-4 egress
	// posture refuses DNS names resolving into reserved ranges.
	if opts.ModelName != "mock-model" || opts.Provider != "openai-compat" ||
		opts.UpstreamURL != "http://10.207.0.9:8081" || opts.UpstreamKeyPlaintext != nil {
		t.Fatalf("unexpected mock plan: %+v", opts)
	}
	if opts.Slug != "seed" || opts.OrgName != "Seed" {
		t.Fatalf("unexpected org defaults: %+v", opts)
	}
}

func TestSeedFlagsResolve_ProviderRequiresKeyAndURL(t *testing.T) {
	if _, err := (SeedFlags{Profile: "provider", AdminEmail: "a@b.c"}).resolve(); err == nil {
		t.Fatal("provider profile without --upstream-key-file must fail")
	}
	if _, err := (SeedFlags{
		Profile: "provider", AdminEmail: "a@b.c", UpstreamKeyFile: "seed_test.go",
	}).resolve(); err == nil {
		t.Fatal("provider profile without --upstream-url must fail")
	}

	opts, err := SeedFlags{
		Profile:         "provider",
		AdminEmail:      "a@b.c",
		UpstreamKeyFile: "seed_test.go",
		UpstreamURL:     "https://api.example.com/v1",
	}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if opts.UpstreamKeyPlaintext == nil || !strings.HasPrefix(*opts.UpstreamKeyPlaintext, "package run") {
		t.Fatalf("upstream key must be read from the file, got %+v", opts.UpstreamKeyPlaintext)
	}
	if opts.ModelName != "seed-model" {
		t.Fatalf("default provider model, got %q", opts.ModelName)
	}
}

func TestSeedFlagsResolve_ProviderKeyFileMissing(t *testing.T) {
	if _, err := (SeedFlags{
		Profile:         "provider",
		AdminEmail:      "a@b.c",
		UpstreamKeyFile: filepath.Join(t.TempDir(), "absent"),
		UpstreamURL:     "https://api.example.com/v1",
	}).resolve(); err == nil {
		t.Fatal("missing key file must fail")
	}
}

func TestSeedFlagsResolve_Validation(t *testing.T) {
	cases := []SeedFlags{
		{AdminEmail: "a@b.c"},                         // no profile
		{Profile: "staging", AdminEmail: "a@b.c"},     // bad profile
		{Profile: "mock"},                             // no email
		{Profile: "mock", AdminEmail: "not-an-email"}, // email without @
	}
	for i, f := range cases {
		if _, err := f.resolve(); err == nil {
			t.Fatalf("case %d (%+v): expected validation error", i, f)
		}
	}
}

func TestSeedSlug(t *testing.T) {
	cases := map[string]string{
		"Seed":              "seed",
		"Acme Org":          "acme-org",
		"  Weird -- Name! ": "weird-name",
		"Орг":               "seed-org", // non-ASCII collapses away
		"!!!":               "seed-org",
	}
	for name, want := range cases {
		if got := seedSlug(name); got != want {
			t.Errorf("seedSlug(%q) = %q, want %q", name, got, want)
		}
	}
	long := seedSlug(strings.Repeat("x", 100))
	if len(long) > 60 {
		t.Errorf("slug must be capped at 60 chars, got %d", len(long))
	}
}

func TestResolveAdminPassword_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", path)

	pw, supplied, err := resolveAdminPassword(SeedFlags{}, strings.NewReader("ignored"))
	if err != nil {
		t.Fatal(err)
	}
	if !supplied || pw != "s3cret" {
		t.Fatalf("got (%q, %v), want trimmed file password", pw, supplied)
	}
}

func TestResolveAdminPassword_StdinWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", path)

	pw, supplied, err := resolveAdminPassword(SeedFlags{AdminPasswordStdin: true}, strings.NewReader("from-stdin\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !supplied || pw != "from-stdin" {
		t.Fatalf("got (%q, %v), want stdin password without trailing CR/LF", pw, supplied)
	}
}

func TestResolveAdminPassword_NoneSupplied(t *testing.T) {
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", "")
	pw, supplied, err := resolveAdminPassword(SeedFlags{}, strings.NewReader(""))
	if err != nil || supplied {
		t.Fatalf("no source configured: got (%q, %v, %v), want (\"\", false, nil)", pw, supplied, err)
	}

	if _, _, err := resolveAdminPassword(SeedFlags{AdminPasswordStdin: true}, strings.NewReader("\n")); err == nil {
		t.Fatal("empty stdin password must fail")
	}
}

// TestSeedRunner_NoEmailIsNoOp pins the compose gate: without any admin email
// the runner must not require a database and must succeed quietly.
func TestSeedRunner_NoEmailIsNoOp(t *testing.T) {
	var out bytes.Buffer
	err := Seed(t.Context(), config.All{}, slog.Default(),
		SeedFlags{}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("seed without email must be a no-op success, got %v", err)
	}
	if strings.Contains(out.String(), "API key") {
		t.Fatal("no-op seed must not print a key")
	}
}
