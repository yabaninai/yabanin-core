package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
)

// AddAdminCreateUserCommand registers `yabanin admin create-user`.
// The password is never a command-line argument: --password-stdin or
// YABANIN_ADMIN_PASSWORD_FILE (the operator _FILE secret convention).
func AddAdminCreateUserCommand(root *cobra.Command) {
	var email, displayName string
	var isRoot, passwordStdin bool

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Admin maintenance commands",
	}
	cmd := &cobra.Command{
		Use:   "create-user",
		Short: "Create a new admin user (for initial bootstrap only)",
		Long: `Creates an admin user by connecting directly to PostgreSQL.
This command is intended for one-time bootstrap — it will fail if the
user already exists. In production, use the admin panel instead.

The password is read from stdin (--password-stdin) or from the file named
by YABANIN_ADMIN_PASSWORD_FILE. It is not accepted as a flag value.

Example:
  printf '%s' "$PW" | yabanin admin create-user --email=admin@example.com --password-stdin --root`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}
			password, err := readAdminPassword(passwordStdin, cmd.InOrStdin())
			if err != nil {
				return err
			}

			// Read PG_URI from env (same as services do at startup)
			pgURI := config.AdminBootstrapPGURI()
			if pgURI == "" {
				return fmt.Errorf("YABANIN_PG_URI or YABANIN_GATEWAY_PG_URI environment variable is required")
			}

			// Connect to database
			pool, err := connectDB(pgURI)
			if err != nil {
				return fmt.Errorf("connect to database: %w", err)
			}
			defer pool.Close()

			ctx := context.Background()

			// Create admin store (nil encryptor for CLI — no encryption needed)
			store := adminstore.New(pool, slog.Default(), nil)

			// Check if user already exists
			existing, err := store.GetAdminUserByEmail(ctx, email)
			if err == nil && existing != nil {
				return fmt.Errorf("admin user %q already exists (id: %s)", email, existing.ID)
			}

			// Hash password using same bcrypt cost as adminauth
			hashedPassword, err := adminauth.HashPassword(password)
			if err != nil {
				return fmt.Errorf("hash password: %w", err)
			}

			// Create the user
			user, err := store.CreateAdminUser(ctx, email, displayName, hashedPassword, isRoot)
			if err != nil {
				return fmt.Errorf("create admin user: %w", err)
			}

			fmt.Printf("Admin user created successfully:\n")
			fmt.Printf("  ID:       %s\n", user.ID)
			fmt.Printf("  Email:    %s\n", user.Email)
			fmt.Printf("  Name:     %s\n", user.DisplayName)
			fmt.Printf("  Root:     %t\n", user.IsRoot)
			fmt.Printf("  Active:   %t\n", user.Active)

			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "Admin user email (required)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read the password from stdin")
	cmd.Flags().StringVar(&displayName, "display-name", "Admin User", "Display name")
	cmd.Flags().BoolVar(&isRoot, "root", false, "Grant root privileges")

	if err := cmd.MarkFlagRequired("email"); err != nil {
		fmt.Fprintf(os.Stderr, "error: mark email required: %v\n", err)
		os.Exit(1)
	}

	adminCmd.AddCommand(cmd)
	root.AddCommand(adminCmd)
}

// readAdminPassword loads the bootstrap password from stdin or from
// YABANIN_ADMIN_PASSWORD_FILE. The password itself is never taken from argv.
func readAdminPassword(fromStdin bool, stdin io.Reader) (string, error) {
	if fromStdin {
		body, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		password := strings.TrimRight(string(body), "\r\n")
		if password == "" {
			return "", fmt.Errorf("password from --password-stdin is empty")
		}
		return password, nil
	}
	path := config.AdminPasswordFile()
	if path == "" {
		return "", fmt.Errorf("password must be supplied with --password-stdin or YABANIN_ADMIN_PASSWORD_FILE")
	}
	//nolint:gosec // G304: path is the operator's YABANIN_ADMIN_PASSWORD_FILE, not request input
	body, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read YABANIN_ADMIN_PASSWORD_FILE: %w", err)
	}
	password := strings.TrimRight(string(body), "\r\n")
	if password == "" {
		return "", fmt.Errorf("YABANIN_ADMIN_PASSWORD_FILE is empty")
	}
	return password, nil
}

func connectDB(pgURI string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		return nil, fmt.Errorf("parse pg_uri: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}
