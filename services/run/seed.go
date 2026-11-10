package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/encryption"
)

// Seed profiles. mock points the seeded model at the compose mock-openai
// service (no upstream credential); provider points it at a real upstream
// base URL from the environment with the key from --upstream-key-file,
// stored enc:-encrypted exactly like the admin models API (pkg/adminstore).
const (
	SeedProfileMock     = "mock"
	SeedProfileProvider = "provider"

	seedKeyName          = "seed"
	seedAdminDisplayName = "Seed Admin"
	seedCreditsCents     = 100000 // starting grant, quickstart parity ($1,000)
	seedBudgetUSD        = 50     // monthly team budget, quickstart parity (hard stop)
)

// SeedFlags carries the `yabanin seed` invocation. Flag values win over the
// SEED_* environment defaults, so the docker-compose one-shot service and a
// direct CLI run share one parser.
type SeedFlags struct {
	Profile            string
	AdminEmail         string
	AdminPasswordStdin bool
	UpstreamKeyFile    string
	UpstreamURL        string
	ModelName          string
	OrgName            string
}

// ParseSeedFlags parses the argv after `yabanin seed`, accepting both
// "--flag value" and "--flag=value" (the same surface the cobra-based
// `admin create-user` exposes). SEED_* environment variables provide the
// defaults so the compose seed service needs no shell quoting.
func ParseSeedFlags(args []string) (SeedFlags, error) {
	f := SeedFlags{
		Profile:         strings.TrimSpace(os.Getenv("SEED_PROFILE")),
		AdminEmail:      strings.TrimSpace(os.Getenv("SEED_ADMIN_EMAIL")),
		OrgName:         strings.TrimSpace(os.Getenv("SEED_ORG_NAME")),
		UpstreamURL:     strings.TrimSpace(os.Getenv("SEED_UPSTREAM_URL")),
		UpstreamKeyFile: strings.TrimSpace(os.Getenv("SEED_UPSTREAM_KEY_FILE")),
		ModelName:       strings.TrimSpace(os.Getenv("SEED_MODEL")),
	}

	for i := 0; i < len(args); i++ {
		name, inline, hasInline := strings.Cut(args[i], "=")
		readValue := func(what string) (string, error) {
			if hasInline {
				return inline, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s requires a value (%s)", name, what)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--profile":
			v, err := readValue("mock|provider")
			if err != nil {
				return SeedFlags{}, err
			}
			f.Profile = strings.TrimSpace(v)
		case "--admin-email":
			v, err := readValue("operator email for the seeded root admin")
			if err != nil {
				return SeedFlags{}, err
			}
			f.AdminEmail = strings.TrimSpace(v)
		case "--admin-password-stdin":
			if hasInline {
				return SeedFlags{}, fmt.Errorf("flag --admin-password-stdin does not take a value")
			}
			f.AdminPasswordStdin = true
		case "--upstream-key-file":
			v, err := readValue("path of the upstream provider key file")
			if err != nil {
				return SeedFlags{}, err
			}
			f.UpstreamKeyFile = strings.TrimSpace(v)
		case "--upstream-url":
			v, err := readValue("upstream base URL")
			if err != nil {
				return SeedFlags{}, err
			}
			f.UpstreamURL = strings.TrimSpace(v)
		case "--model":
			v, err := readValue("model name to register")
			if err != nil {
				return SeedFlags{}, err
			}
			f.ModelName = strings.TrimSpace(v)
		case "--org-name":
			v, err := readValue("organization display name")
			if err != nil {
				return SeedFlags{}, err
			}
			f.OrgName = strings.TrimSpace(v)
		default:
			return SeedFlags{}, fmt.Errorf("unknown seed flag %q", args[i])
		}
	}
	return f, nil
}

// SeedOptions is the validated, profile-resolved seed plan. It is the input
// of the testable applySeed core.
type SeedOptions struct {
	OrgName     string
	Slug        string
	ModelName   string
	Provider    string
	UpstreamURL string
	// UpstreamKeyPlaintext is nil for the mock profile and when the provider
	// key file was not supplied.
	UpstreamKeyPlaintext *string
	AdminEmail           string
	// AdminPassword is nil when no password was supplied (the admin is then
	// only skipped if it already exists).
	AdminPassword *string
}

// SeedResult reports what applySeed actually did (inserted vs already there)
// plus the plaintext key on the run that issued it.
type SeedResult struct {
	OrgID        string
	TeamID       string
	APIKeyID     string
	KeyIssued    bool
	KeyPlaintext string
	ModelName    string
	AdminCreated bool
	AdminExists  bool
}

// Seed is the `yabanin seed` runner: validate flags, connect with the service
// config (PG URI and encryption key honor the _FILE secret convention), and
// bootstrap the stand. With no admin email configured at all (no --admin-email,
// no SEED_ADMIN_EMAIL) it is a loud no-op so the compose seed service can sit
// in the stack until the operator opts in.
func Seed(ctx context.Context, cfg config.All, l *slog.Logger, flags SeedFlags, stdin io.Reader, stdout io.Writer) error {
	if l == nil {
		l = slog.Default()
	}
	if flags.AdminEmail == "" {
		l.Info("seed: SEED_ADMIN_EMAIL/--admin-email not set; seed disabled, nothing to do")
		return nil
	}

	opts, err := flags.resolve()
	if err != nil {
		return err
	}
	password, supplied, err := resolveAdminPassword(flags, stdin)
	if err != nil {
		return err
	}
	if supplied {
		opts.AdminPassword = &password
	}

	if cfg.Gateway.PGURI == "" {
		return errors.New("seed: pg_uri is required (set YABANIN_PG_URI or gateway.pg_uri)")
	}

	// The upstream key must decrypt at serve time: mirror the admin models API
	// and refuse a plaintext write without a configured encryptor outside the
	// dev/test escape hatch.
	var enc *encryption.Encryptor
	if opts.UpstreamKeyPlaintext != nil && cfg.Gateway.EncryptionKey != "" {
		enc, err = encryption.New(cfg.Gateway.EncryptionKey)
		if err != nil {
			return fmt.Errorf("seed: encryptor: %w", err)
		}
	}

	pool, err := openSeedPool(ctx, cfg.Gateway.PGURI)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	defer pool.Close()

	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := ApplySeed(runCtx, pool, enc, opts, l, stdout)
	if err != nil {
		return err
	}
	if res.AdminCreated {
		l.Info("seed: root admin created", "email", opts.AdminEmail)
	}
	return nil
}

// flags.resolve validates the invocation and derives the profile-specific
// seed plan. It does not touch the network or the database.
func (f SeedFlags) resolve() (SeedOptions, error) {
	switch f.Profile {
	case SeedProfileMock, SeedProfileProvider:
		// ok
	case "":
		return SeedOptions{}, fmt.Errorf("--profile is required (mock|provider) or set SEED_PROFILE")
	default:
		return SeedOptions{}, fmt.Errorf("--profile must be %q or %q, got %q", SeedProfileMock, SeedProfileProvider, f.Profile)
	}
	if f.AdminEmail == "" || !strings.Contains(f.AdminEmail, "@") {
		return SeedOptions{}, fmt.Errorf("--admin-email must be a valid email (got %q)", f.AdminEmail)
	}

	opts := SeedOptions{
		AdminEmail: f.AdminEmail,
		OrgName:    f.OrgName,
	}
	if opts.OrgName == "" {
		opts.OrgName = "Seed"
	}
	opts.Slug = seedSlug(opts.OrgName)

	switch f.Profile {
	case SeedProfileMock:
		opts.ModelName = orDefault(f.ModelName, "mock-model")
		opts.Provider = "openai-compat"
		// Default matches the quickstart compose pin (deploy/quickstart/
		// docker-compose.yml): a literal IP, because the gateway's D-4
		// egress posture waives the reserved-range refusal only for exact
		// IP pins — a compose DNS name in a private range is refused.
		opts.UpstreamURL = orDefault(f.UpstreamURL, "http://10.207.0.9:8081")
	case SeedProfileProvider:
		if f.UpstreamKeyFile == "" {
			return SeedOptions{}, fmt.Errorf("--upstream-key-file is required with --profile provider (or set SEED_UPSTREAM_KEY_FILE)")
		}
		if f.UpstreamURL == "" {
			return SeedOptions{}, fmt.Errorf("--upstream-url is required with --profile provider (or set SEED_UPSTREAM_URL)")
		}
		opts.ModelName = orDefault(f.ModelName, "seed-model")
		opts.Provider = "openai-compat"
		opts.UpstreamURL = f.UpstreamURL
		key, err := readSeedSecretFile(f.UpstreamKeyFile)
		if err != nil {
			return SeedOptions{}, err
		}
		opts.UpstreamKeyPlaintext = &key
	}
	return opts, nil
}

// resolveAdminPassword applies the admin create-user convention: the password
// arrives via --admin-password-stdin or YABANIN_ADMIN_PASSWORD_FILE, never as
// a command-line value. supplied=false means "not configured".
func resolveAdminPassword(flags SeedFlags, stdin io.Reader) (password string, supplied bool, err error) {
	if flags.AdminPasswordStdin {
		body, err := io.ReadAll(stdin)
		if err != nil {
			return "", false, fmt.Errorf("read admin password from stdin: %w", err)
		}
		password := strings.TrimRight(string(body), "\r\n")
		if password == "" {
			return "", false, fmt.Errorf("admin password from --admin-password-stdin is empty")
		}
		return password, true, nil
	}
	if path := config.AdminPasswordFile(); path != "" {
		password, err := readSeedSecretFile(path)
		if err != nil {
			return "", false, fmt.Errorf("read YABANIN_ADMIN_PASSWORD_FILE: %w", err)
		}
		return password, true, nil
	}
	return "", false, nil
}

// readSeedSecretFile reads a key/password file (docker _FILE convention) and
// trims the surrounding whitespace.
func readSeedSecretFile(path string) (string, error) {
	//nolint:gosec // G304: path is the operator's own secret file (flag or _FILE env), not request input
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(body))
	if secret == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return secret, nil
}

func openSeedPool(ctx context.Context, pgURI string) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		return nil, fmt.Errorf("parse pg_uri: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// seedSlug derives the org slug from the display name: lowercase, runs of
// non-alphanumeric characters collapsed to '-', trimmed, capped at 60 chars.
func seedSlug(name string) string {
	var b strings.Builder
	lastDash := true // suppress a leading dash
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 60 {
			break
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		return "seed-org"
	}
	return slug
}

// orDefault returns fallback when v is empty.
func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ApplySeed bootstraps the stand idempotently: org, default team, budget,
// seed API key, model, starting credits, and the root admin. Every insert is
// ON CONFLICT DO NOTHING keyed by its natural unique constraint, so a second
// run is a no-op — and the API key plaintext is printed only on the run that
// issued it (the database stores its sha256 only). Consolidates
// scripts/quickstart/seed.sql and scripts/stand-opencode/main.go.
func ApplySeed(ctx context.Context, pool *pgxpool.Pool, enc *encryption.Encryptor, opts SeedOptions, l *slog.Logger, out io.Writer) (SeedResult, error) {
	if l == nil {
		l = slog.Default()
	}
	var res SeedResult

	orgID, err := seedOrg(ctx, pool, opts)
	if err != nil {
		return res, err
	}
	res.OrgID = orgID

	teamID, err := seedTeam(ctx, pool, orgID)
	if err != nil {
		return res, err
	}
	res.TeamID = teamID

	if _, err := pool.Exec(ctx, `
		INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
		VALUES ($1, $2, true)
		ON CONFLICT (team_id) DO NOTHING`, teamID, seedBudgetUSD); err != nil {
		return res, fmt.Errorf("seed budget: %w", err)
	}

	if err := seedModel(ctx, pool, enc, opts, l); err != nil {
		return res, err
	}
	res.ModelName = opts.ModelName

	if _, err := pool.Exec(ctx, `
		WITH opening AS (
			INSERT INTO org_credits (org_id, balance_cents)
			VALUES ($1, $2)
			ON CONFLICT (org_id) DO NOTHING
			RETURNING org_id, balance_cents
		)
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, invoice_ref, amount_micro_usd)
		SELECT org_id, balance_cents, balance_cents, 'topup', 'seed-opening-balance', balance_cents * 10000
		FROM opening`, orgID, seedCreditsCents); err != nil {
		return res, fmt.Errorf("seed credits: %w", err)
	}

	// W-CRED: the beta starter grant rides on both org-creation paths — here
	// and on the admin create-org API. Exactly one "beta-starter-grant"
	// ledger row per org; BETA_STARTER_CREDITS_CENTS sets the amount
	// (default 5000), zero or less disables.
	if grant := credits.StarterGrantCents(); grant > 0 {
		if _, err := credits.EnsureStarterGrant(ctx, pool, orgID, grant); err != nil {
			return res, fmt.Errorf("seed starter grant: %w", err)
		}
	}

	keyID, keyPlaintext, issued, err := seedAPIKey(ctx, pool, orgID, teamID, out)
	if err != nil {
		return res, err
	}
	res.APIKeyID = keyID
	res.KeyIssued = issued
	res.KeyPlaintext = keyPlaintext

	adminCreated, adminExists, err := seedAdmin(ctx, pool, opts, orgID)
	if err != nil {
		return res, err
	}
	res.AdminCreated = adminCreated
	res.AdminExists = adminExists

	if res.KeyIssued {
		// The only place the plaintext key is ever printed. A failed write
		// must fail the run: the operator would otherwise never see the key.
		if _, err := fmt.Fprintf(out, "API key (shown once, store it now): %s\n", res.KeyPlaintext); err != nil {
			return res, fmt.Errorf("seed: write api key to output: %w", err)
		}
	}
	if _, err := fmt.Fprintf(out, "seed ok: org=%s (id %s) team=default model=%s admin=%s\n",
		opts.Slug, orgID, opts.ModelName, opts.AdminEmail); err != nil {
		return res, fmt.Errorf("seed: write summary: %w", err)
	}
	return res, nil
}

func seedOrg(ctx context.Context, pool *pgxpool.Pool, opts SeedOptions) (string, error) {
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, cache_mode)
		VALUES ($1, $2, $3, 'off')
		ON CONFLICT (slug) DO NOTHING`,
		uuid.New(), opts.OrgName, opts.Slug); err != nil {
		return "", fmt.Errorf("seed org: %w", err)
	}
	var orgID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM organizations WHERE slug = $1`, opts.Slug).Scan(&orgID); err != nil {
		return "", fmt.Errorf("seed org lookup: %w", err)
	}
	return orgID, nil
}

func seedTeam(ctx context.Context, pool *pgxpool.Pool, orgID string) (string, error) {
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations_teams (id, org_id, name, slug)
		VALUES ($1, $2, 'Default', 'default')
		ON CONFLICT (org_id, slug) DO NOTHING`, uuid.New(), orgID); err != nil {
		return "", fmt.Errorf("seed team: %w", err)
	}
	var teamID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM organizations_teams WHERE org_id = $1::uuid AND slug = 'default'`,
		orgID).Scan(&teamID); err != nil {
		return "", fmt.Errorf("seed team lookup: %w", err)
	}
	return teamID, nil
}

func seedModel(ctx context.Context, pool *pgxpool.Pool, enc *encryption.Encryptor, opts SeedOptions, l *slog.Logger) error {
	var encKey *string
	if opts.UpstreamKeyPlaintext != nil {
		stored, err := prepareSeedUpstreamKey(enc, *opts.UpstreamKeyPlaintext, l)
		if err != nil {
			return err
		}
		encKey = stored
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO models_registry (
			model_name, display_name, tier, provider, upstream_url, upstream_api_key,
			failover_models, tier_pool, upstream_timeout_ms, enabled
		) VALUES ($1, $2, 'smart', $3, NULLIF($4, ''), $5, '{}', '{easy,medium,hard}', 180000, true)
		ON CONFLICT (model_name) DO NOTHING`,
		opts.ModelName, opts.ModelName+" (via Yabanin)", opts.Provider, opts.UpstreamURL, encKey); err != nil {
		return fmt.Errorf("seed model %s: %w", opts.ModelName, err)
	}
	return nil
}

// prepareSeedUpstreamKey mirrors pkg/adminstore's production fail-closed
// contract: an upstream key is stored enc:-encrypted, or — only under the
// explicit dev/test escape hatch — as plaintext with a loud warning.
func prepareSeedUpstreamKey(enc *encryption.Encryptor, plaintext string, l *slog.Logger) (*string, error) {
	if enc != nil {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt upstream key: %w", err)
		}
		return &ct, nil
	}
	if encryption.PlaintextWritesAllowed() {
		l.Warn("provider API key stored as PLAINTEXT: no encryption_key configured (dev/test fallback; production refuses this)")
		return &plaintext, nil
	}
	return nil, fmt.Errorf("refusing to store provider API key as plaintext: encryption_key is not configured; set encryption_key (YABANIN_ENCRYPTION_KEY) before writing provider credentials")
}

// seedAPIKey issues the stand's smoke key. When a seed key already exists for
// the org it is reused and no plaintext is produced — the plaintext is shown
// exactly once, on the run that minted it.
func seedAPIKey(ctx context.Context, pool *pgxpool.Pool, orgID, teamID string, out io.Writer) (string, string, bool, error) {
	var existing string
	err := pool.QueryRow(ctx,
		`SELECT id::text FROM api_keys WHERE org_id = $1::uuid AND name = $2 ORDER BY created_at LIMIT 1`,
		orgID, seedKeyName).Scan(&existing)
	if err == nil {
		if _, err := fmt.Fprintf(out, "seed: API key already exists (id %s); plaintext is not shown again\n", existing); err != nil {
			return "", "", false, fmt.Errorf("seed api key notice: %w", err)
		}
		return existing, "", false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, fmt.Errorf("seed api key lookup: %w", err)
	}

	plaintext, err := auth.GeneratePersonalKey()
	if err != nil {
		return "", "", false, fmt.Errorf("generate api key: %w", err)
	}
	tag, err := pool.Exec(ctx, `
		INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
		VALUES ($1, $2, $3::uuid, $4, true, $5::uuid)
		ON CONFLICT (key_hash) DO NOTHING`,
		uuid.New(), auth.HashKey(plaintext), orgID, seedKeyName, teamID)
	if err != nil {
		return "", "", false, fmt.Errorf("seed api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// A different caller minted the same 32-byte random key: impossible in
		// practice, and silently reporting success would hide it.
		return "", "", false, fmt.Errorf("seed api key: generated key hash already exists (collision)")
	}
	var keyID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM api_keys WHERE key_hash = $1`, auth.HashKey(plaintext)).Scan(&keyID); err != nil {
		return "", "", false, fmt.Errorf("seed api key lookup: %w", err)
	}
	return keyID, plaintext, true, nil
}

func seedAdmin(ctx context.Context, pool *pgxpool.Pool, opts SeedOptions, orgID string) (created, exists bool, err error) {
	if opts.AdminPassword == nil {
		var existsRow bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM admin_users WHERE email = $1)`, opts.AdminEmail).Scan(&existsRow); err != nil {
			return false, false, fmt.Errorf("seed admin lookup: %w", err)
		}
		if !existsRow {
			return false, false, fmt.Errorf("seed admin: %s does not exist and no password was supplied; use --admin-password-stdin or YABANIN_ADMIN_PASSWORD_FILE", opts.AdminEmail)
		}
		// Re-run: converge stands seeded before this membership existed.
		if err := seedAdminOrgMembership(ctx, pool, opts.AdminEmail, orgID); err != nil {
			return false, true, err
		}
		return false, true, nil
	}

	hash, err := adminauth.HashPassword(*opts.AdminPassword)
	if err != nil {
		return false, false, fmt.Errorf("seed admin password hash: %w", err)
	}
	tag, err := pool.Exec(ctx, `
		INSERT INTO admin_users (email, password_hash, display_name, is_root, active)
		VALUES ($1, $2, $3, true, true)
		ON CONFLICT (email) DO NOTHING`,
		opts.AdminEmail, hash, seedAdminDisplayName)
	if err != nil {
		return false, false, fmt.Errorf("seed admin user: %w", err)
	}
	if err := seedAdminOrgMembership(ctx, pool, opts.AdminEmail, orgID); err != nil {
		return false, false, err
	}
	if tag.RowsAffected() == 0 {
		return false, true, nil
	}
	return true, false, nil
}

// seedAdminOrgMembership pins the seeded root admin as org-admin of the seeded org.
func seedAdminOrgMembership(ctx context.Context, pool *pgxpool.Pool, adminEmail, orgID string) error {
	var adminID string
	if err := pool.QueryRow(ctx,
		`SELECT id FROM admin_users WHERE email = $1`, adminEmail).Scan(&adminID); err != nil {
		return fmt.Errorf("seed admin id lookup: %w", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_org_memberships (user_id, org_id, role)
		VALUES ($1, $2, 'org-admin')
		ON CONFLICT (user_id, org_id) DO NOTHING`,
		adminID, orgID); err != nil {
		return fmt.Errorf("seed admin org membership: %w", err)
	}
	return nil
}
