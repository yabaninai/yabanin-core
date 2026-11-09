package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAdminPassword_Stdin(t *testing.T) {
	got, err := readAdminPassword(true, strings.NewReader("correct-horse\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "correct-horse" {
		t.Fatalf("got %q", got)
	}
}

func TestReadAdminPassword_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("correct-horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", path)
	got, err := readAdminPassword(false, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if got != "correct-horse" {
		t.Fatalf("got %q", got)
	}
}

func TestReadAdminPassword_Missing(t *testing.T) {
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", "")
	_, err := readAdminPassword(false, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("got %v", err)
	}
}
