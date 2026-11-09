package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
)

// TestServiceDispatch_KnownCommands confirms every documented subcommand maps
// to an in-process runner (I6). If a service regresses to exec-based dispatch
// or a subcommand is dropped, this fails.
func TestServiceDispatch_KnownCommands(t *testing.T) {
	cfg := config.All{}
	ctx := context.Background()

	for _, sub := range []string{"gateway", "admin", "loggerd", "mcp", "migrate", "seed"} {
		t.Run(sub, func(t *testing.T) {
			runner, ok := serviceDispatch(ctx, cfg, slog.Default(), sub)
			if !ok {
				t.Fatalf("subcommand %q must dispatch to an in-process runner", sub)
			}
			if runner == nil {
				t.Fatalf("subcommand %q returned nil runner", sub)
			}
			// Do NOT invoke the runner: it would start real servers. The contract
			// under test is dispatch resolution, not execution.
		})
	}
}

// TestServiceDispatch_UnknownCommand confirms unknown subcommands are rejected
// by the dispatch table (the caller falls back to cobra / usage error).
func TestServiceDispatch_UnknownCommand(t *testing.T) {
	for _, sub := range []string{"", "frobnicate", "Gateway", "license", "license issue"} {
		t.Run("sub="+sub, func(t *testing.T) {
			if _, ok := serviceDispatch(context.Background(), config.All{}, slog.Default(), sub); ok {
				t.Fatalf("subcommand %q must NOT be a known service", sub)
			}
		})
	}
}

// TestParseServiceArgs_AdminRunsServer confirms a bare `admin` selects the
// server runner, and that the runner can be replaced without listening.
func TestParseServiceArgs_AdminRunsServer(t *testing.T) {
	mode, err := parseServiceArgs([]string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "admin" {
		t.Fatalf("mode %q, want admin", mode)
	}
	called := false
	prev := adminRunner
	adminRunner = func(context.Context) error {
		called = true
		return nil
	}
	t.Cleanup(func() { adminRunner = prev })
	runner, ok := serviceDispatch(context.Background(), config.All{}, slog.Default(), mode)
	if !ok || runner == nil {
		t.Fatal("admin must dispatch to the server runner")
	}
	if err := runner(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("substituted admin runner was not called")
	}
}

func TestParseServiceArgs_CreateUser(t *testing.T) {
	mode, err := parseServiceArgs([]string{"admin", "create-user", "--email", "a@b", "--password-stdin"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != adminCreateUserMode {
		t.Fatalf("mode %q, want %s", mode, adminCreateUserMode)
	}
}

func TestParseServiceArgs_PasswordArgumentRejected(t *testing.T) {
	for _, args := range [][]string{
		{"admin", "create-user", "--email", "a@b", "--password", "secret"},
		{"admin", "create-user", "--email", "a@b", "--password=secret"},
	} {
		_, err := parseServiceArgs(args)
		if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
			t.Fatalf("args %q: got %v, want a hint to use --password-stdin", args, err)
		}
	}
}

// TestIsLicenseCommand confirms license commands are recognized without loading
// config.yaml (activation runs before any service config exists).
func TestIsLicenseCommand(t *testing.T) {
	cases := map[string]bool{
		"license":        true,
		"license issue":  true,
		"licenseinspect": false, // must be a distinct token, not a prefix string
		"gateway":        false,
		"":               false,
	}
	for sub, want := range cases {
		if got := isLicenseCommand(sub); got != want {
			t.Errorf("isLicenseCommand(%q) = %v, want %v", sub, got, want)
		}
	}
}

func TestParseDevArgs(t *testing.T) {
	flags, err := parseDevArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if flags.Migrate || flags.NoAdmin || flags.NoLoggerd {
		t.Fatalf("empty args must start every service, got %+v", flags)
	}

	flags, err = parseDevArgs([]string{"--no-loggerd", "--migrate", "--no-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !flags.Migrate || !flags.NoAdmin || !flags.NoLoggerd {
		t.Fatalf("flags not applied, got %+v", flags)
	}

	if _, err := parseDevArgs([]string{"--migrate=true"}); err == nil {
		t.Fatal("expected unknown flag to be rejected")
	}
}
