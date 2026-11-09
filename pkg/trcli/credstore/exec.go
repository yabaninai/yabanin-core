package credstore

import (
	"bytes"
	"context"
	"os/exec"
)

// ExecRunner runs security or secret-tool. It does not start a shell.
type ExecRunner struct{}

// Run executes a credential helper. Only security and secret-tool are allowed.
func (ExecRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (string, error) {
	switch name {
	case "security":
		return runLiteral(ctx, "security", stdin, args)
	case "secret-tool":
		return runLiteral(ctx, "secret-tool", stdin, args)
	default:
		return "", exec.ErrNotFound
	}
}

// LookPath reports whether a helper binary is installed.
func (ExecRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func runLiteral(ctx context.Context, bin string, stdin []byte, args []string) (string, error) {
	var cmd *exec.Cmd
	switch bin {
	case "security":
		cmd = exec.CommandContext(ctx, "security", args...) //nolint:gosec // G204: executable is the literal security binary; args are fixed keychain subcommands, not a shell
	default:
		cmd = exec.CommandContext(ctx, "secret-tool", args...) //nolint:gosec // G204: executable is the literal secret-tool binary; args are fixed subcommands, not a shell
	}
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
