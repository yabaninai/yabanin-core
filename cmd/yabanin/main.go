// Package main provides a unified entry point for all yabanin services via
// subcommand dispatch (e.g. "yabanin gateway", "yabanin admin", etc.).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/config"
	cli "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/reireirei/yabanin/pkg/license"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/reireirei/yabanin/pkg/migrate"
	"github.com/reireirei/yabanin/services/run"
)

// isLicenseCommand reports whether the raw first argument addresses the license
// tooling. License commands must not require config.yaml (they run before any
// service config exists, e.g. during initial activation).
func isLicenseCommand(subCmd string) bool {
	return subCmd == "license" || strings.HasPrefix(subCmd, "license ")
}

// adminRunner starts the admin server. Tests replace it to prove that a bare
// `yabanin admin` resolves to the server without actually listening.
var adminRunner = run.AdminServer

const adminCreateUserMode = "admin create-user"

// parseServiceArgs classifies argv after the program name.
// `admin` with no subcommand is the admin server. `admin create-user` is the
// bootstrap command. A password on the command line is rejected so it cannot
// land in shell history or the process list.
func parseServiceArgs(args []string) (string, error) {
	if len(args) == 0 {
		return "gateway", nil
	}
	if args[0] != "admin" {
		return args[0], nil
	}
	if len(args) == 1 {
		return "admin", nil
	}
	if args[1] != "create-user" {
		return "", fmt.Errorf("unknown admin subcommand %q", args[1])
	}
	if err := rejectInlinePassword(args[2:]); err != nil {
		return "", err
	}
	return adminCreateUserMode, nil
}

func rejectInlinePassword(args []string) error {
	for _, arg := range args {
		name := arg
		if strings.HasPrefix(name, "--") {
			name, _, _ = strings.Cut(name, "=")
		}
		if name == "--password" || name == "-password" {
			return fmt.Errorf("refusing a password on the command line (it is visible in shell history and process listings); use --password-stdin or YABANIN_ADMIN_PASSWORD_FILE")
		}
	}
	return nil
}

// serviceDispatch maps a subcommand to its in-process runner (I6). All services
// run in-process, including migrate (see runMigrate). The bool result reports
// whether the subcommand is a known service.
func serviceDispatch(ctx context.Context, cfg config.All, l *slog.Logger, subCmd string) (func() error, bool) {
	switch subCmd {
	case "gateway":
		return func() error { return run.Gateway(ctx) }, true
	case "admin":
		return func() error { return adminRunner(ctx) }, true
	case "loggerd":
		return func() error { return run.Loggerd(ctx) }, true
	case "mcp":
		return func() error { return run.MCP() }, true
	case "migrate":
		return func() error { return runMigrate(ctx, cfg, l) }, true
	case "seed":
		return func() error {
			flags, err := run.ParseSeedFlags(os.Args[2:])
			if err != nil {
				return err
			}
			return run.Seed(ctx, cfg, l, flags, os.Stdin, os.Stdout)
		}, true
	}
	return nil, false
}

// parseDevArgs reads flags after `yabanin dev`. Unknown flags are rejected so a
// typo cannot silently start a partial stack.
func parseDevArgs(args []string) (run.DevFlags, error) {
	var flags run.DevFlags
	for _, arg := range args {
		switch arg {
		case "--migrate":
			flags.Migrate = true
		case "--no-admin":
			flags.NoAdmin = true
		case "--no-loggerd":
			flags.NoLoggerd = true
		default:
			return run.DevFlags{}, fmt.Errorf("unknown dev flag %q", arg)
		}
	}
	return flags, nil
}

// startDev runs gateway, loggerd, and admin in this process. Config is the one
// already loaded by main. Each runner keeps its own single-command behavior.
func startDev(ctx context.Context, cfg config.All, l *slog.Logger, flags run.DevFlags) error {
	return run.Dev(ctx, flags, run.DevRunners{
		Migrate: func(ctx context.Context) error {
			return runMigrate(ctx, cfg, l.With("service", "migrate"))
		},
		Gateway:        run.Gateway,
		Loggerd:        run.Loggerd,
		Admin:          adminRunner,
		Log:            l,
		GatewayAddr:    cfg.Gateway.ListenAddr,
		GatewayOpsAddr: cfg.Gateway.AdminListen,
		LoggerdAddr:    cfg.Loggerd.ListenAddr,
		AdminAddr:      cfg.Admin.ListenAddr,
	})
}

func main() {
	// Build a cobra root command so we can expose "yabanin license …".
	rootCmd := &cobra.Command{
		Use:   "yabanin <command>",
		Short: "Yabanin unified binary — gateway, admin, license verification",
		Long: "Yabanin — Your Agnostic Bridge Across Numerous Inference Networks " +
			"(the YABANIN backronym).\nUnified binary: gateway, admin, license verification.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Only apply license check for service subcommands.
			if cmd.Name() == "license" || len(args) == 0 {
				return
			}
			requireLicenseVerification()
		},
	}

	invocation, parseErr := parseServiceArgs(os.Args[1:])
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", parseErr)
		os.Exit(1)
	}
	if invocation == adminCreateUserMode {
		cli.AddAdminCreateUserCommand(rootCmd)
		rootCmd.SetArgs(os.Args[1:])
		if err := rootCmd.Execute(); err != nil {
			os.Exit(1)
		}
		return
	}

	subCmd := invocation

	// Don't require config.yaml for license verification commands
	if isLicenseCommand(subCmd) {
		// Register and run license subcommands directly without loading config.
		license.AddLicenseCommands(rootCmd)
		rootCmd.SetArgs(os.Args[1:])
		if err := rootCmd.Execute(); err != nil {
			os.Exit(1)
		}
		return
	}

	// Kubernetes deployments configure the service entirely through
	// environment variables (configMapRef + secrets). A missing config file
	// with YABANIN_CONFIG unset is only an error when no config file exists
	// at the default location — i.e. env-only setups load defaults+env.
	cfgFile := config.PathFromEnv()
	if cfgFile == "" {
		if _, statErr := os.Stat("config.yaml"); statErr == nil {
			cfgFile = "config.yaml"
		} else {
			cfgFile = "" // env-only: defaults, then env overlays
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l := logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat)

	if subCmd == "dev" {
		flags, flagErr := parseDevArgs(os.Args[2:])
		if flagErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", flagErr)
			os.Exit(1)
		}
		sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if runErr := startDev(sigCtx, cfg, l, flags); runErr != nil {
			l.Error("dev exited with error", "error", runErr)
			os.Exit(1)
		}
		return
	}

	// Register license management subcommands.
	license.AddLicenseCommands(rootCmd)

	// Run the service subcommand in-process (no exec of sibling binaries).
	runner, known := serviceDispatch(ctx, cfg, l, subCmd)
	if !known {
		// If the user typed an unknown command that isn't a license subcommand,
		// let cobra handle the error.
		if cmd, _, _ := rootCmd.Find([]string{subCmd}); cmd != nil {
			rootCmd.SetArgs(os.Args[1:])
			if err := rootCmd.Execute(); err != nil {
				os.Exit(1)
			}
			return
		}
		logging.New(cfg.Gateway.LogLevel, cfg.Gateway.LogFormat).Error("unknown subcommand", "subcommand", subCmd, "usage", "yabanin [gateway|admin|loggerd|mcp|migrate|dev|seed|license]")
		os.Exit(1)
	}

	if runErr := runner(); runErr != nil {
		l.Error("service exited with error", "error", runErr)
		os.Exit(1)
	}
}

// requireLicenseVerification checks for license env vars and verifies the
// license chain at startup. If any required var is set, all must be present
// and the license must verify successfully — otherwise the service refuses to start (fail-closed).
func requireLicenseVerification() {
	lic := config.LicenseFromEnv()
	licensePath, rootPubHex, crlPath := lic.File, lic.RootPubKey, lic.CRLFile

	// Fail-closed: if EITHER is set, BOTH must be set.
	if licensePath != "" && rootPubHex == "" {
		fmt.Fprintf(os.Stderr, "FATAL: YABANIN_LICENSE_ROOT_PUBKEY is required when YABANIN_LICENSE_FILE is set\n")
		os.Exit(1)
	}
	if rootPubHex != "" && licensePath == "" {
		fmt.Fprintf(os.Stderr, "FATAL: YABANIN_LICENSE_FILE is required when YABANIN_LICENSE_ROOT_PUBKEY is set\n")
		os.Exit(1)
	}

	if licensePath == "" || rootPubHex == "" {
		return // not enforcing license mode
	}

	if err := license.VerifyLicenseChain(licensePath, rootPubHex, crlPath); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: LICENSE INVALID — %v — service cannot start without a valid license\n", err)
		os.Exit(1)
	}
	fmt.Println("License verified successfully")
}

// runMigrate runs the migration runner in-process (I6) via pkg/migrate, the
// same embedded migrations and logic the standalone yabanin-migrate tool uses.
func runMigrate(ctx context.Context, cfg config.All, l *slog.Logger) error {
	if cfg.Gateway.PGURI == "" {
		return errors.New("pg_uri is required for migrate (set YABANIN_PG_URI or gateway.pg_uri)")
	}
	region := cfg.Gateway.Region
	if region == "" {
		return errors.New("region is required for migrate (set YABANIN_REGION or gateway.region)")
	}

	res, err := migrate.Run(ctx, cfg.Gateway.PGURI, region)
	if err != nil {
		return err
	}
	l.Info("migrations applied", "region", res.Region, "applied", res.Applied, "version", res.Version, "duration", res.Duration)
	return nil
}
