package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

func TestAdminCreateUser_EmailFlagRemainsRequired(t *testing.T) {
	root := &cobra.Command{Use: "yabanin"}
	AddAdminCreateUserCommand(root)

	var createCmd *cobra.Command
	for _, sub := range root.Commands() {
		if sub.Name() == "admin" {
			for _, leaf := range sub.Commands() {
				if leaf.Name() == "create-user" {
					createCmd = leaf
				}
			}
		}
	}
	if createCmd == nil {
		t.Fatal("admin create-user command is not registered")
	}
	flag := createCmd.Flags().Lookup("email")
	if flag == nil {
		t.Fatal(`flag "email" is not registered`)
	}
	if flag.Annotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Fatal(`flag "email" lost its required registration`)
	}
}

func TestConnectDB_RejectsInvalidPoolConfigBeforeDial(t *testing.T) {
	// pool_max_conns=0 is rejected by pgx parse-time validation before any
	// network I/O, so the test needs no database server on 127.0.0.1.
	pool, err := connectDB("postgres://user:pass@127.0.0.1/db?pool_max_conns=0")
	if pool != nil {
		t.Cleanup(func() { pool.Close() })
		t.Fatal("connectDB returned a pool for an invalid URI")
	}
	if err == nil {
		t.Fatal("expected pool config validation error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "parse pg_uri") || !strings.Contains(msg, "pool_max_conns") {
		t.Fatalf("expected pre-dial pool_max_conns rejection, got %q", msg)
	}
	if strings.Contains(msg, "ping database") {
		t.Fatalf("invalid pool config must be rejected before Ping, got %q", msg)
	}
}
