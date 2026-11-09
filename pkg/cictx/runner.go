package cictx

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// Runner runs a command. dir is the working directory. stdin may be nil.
// Implementations must honor ctx and must not invoke a shell.
type Runner interface {
	Run(ctx context.Context, dir string, stdin []byte, name string, args ...string) (string, error)
}

// ExecRunner runs git. The executable is the literal git binary, not a shell.
type ExecRunner struct{}

// Run executes git. Any other name is rejected.
func (ExecRunner) Run(ctx context.Context, dir string, stdin []byte, name string, args ...string) (string, error) {
	if name != "git" {
		return "", errNoRunner
	}
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // G204: executable is the literal git binary; args are git subcommands
	if dir != "" {
		cmd.Dir = dir
	}
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
