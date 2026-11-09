package trcli

// pipelines. Git declarations (deploy/policies/<org-slug>/<policy>.yaml) are
// the single source of truth; this command plans the diff against the
// policystore (OP-0b API, consumed as-is) and — with --apply — converges the
// database onto git.
//
// Drift semantics (owner decision recorded here): GIT WINS + DRIFT REPORT.
// A DB-side edit made past git (a version authored outside git whose content
// differs from the declaration) is reported as DRIFT and — under --apply —
// overwritten by a NEW version carrying the git content and sha. Nothing is
// destroyed: versions are immutable, so the diverged UI edit stays in
// history for its author to port into a PR (§2.3: "a UI policy edit produces
// a declaration for a PR"). No --force flag exists on purpose: git-wins
// keeps one canonical flow, and the dry-run plan is the confirmation
// surface. This closes the two failure modes the plan calls out — Bifrost's
// silent UI↔config drift (every divergence is reported, never merged
// silently) and Portkey's policy bypass (the store is the only enforcement
// source and git is the only intended writer).
//
// DRY-RUN BY DEFAULT: without --apply nothing is written — the command only
// prints the plan (add/update/activate/enable/disable/attachments/delete).
//
// bumps the OP-8 version key `policystore:ver:<orgID>` (the
// adminstore.PolicyVersionKeyPrefix contract — decimal UnixNano, 7-day TTL)
// for every org it converged, so a running gateway reloads its compiled
// pipelines immediately instead of waiting out its probe TTL. The bump rides
// the shared Redis (--redis-addr, default $YABANIN_REDIS_ADDR then
// localhost:6379); a failed/unreachable Redis is a WARNING, never a
// reconcile failure — the gateway's TTL fallback bounds the staleness.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	// policiesDefaultDir is the repository declaration root (workflow:
	// deploy/policies/README.md).
	policiesDefaultDir = "deploy/policies"
	// policiesPackDir is the pack namespace: declarations that apply to
	// every org in scope, only when --include-pack is set (the
	// sovereign-default pack ships OFF — owner decision 2026-10-06).
	policiesPackDir = "_pack"
	// policiesNamespacePrefix marks namespace directories (never orgs).
	policiesNamespacePrefix = "_"
	// policiesDefaultPriority matches the admin API attachment default.
	policiesDefaultPriority = 100
	// policiesMaxPriority matches the admin API attachment bound.
	policiesMaxPriority = 1_000_000
	// policiesCreatedBy is the default actor recorded on reconciled
	// versions (created_by).
	policiesCreatedBy = "policies-reconcile"
	// policiesTimeout bounds one reconcile run.
	policiesTimeout = 60 * time.Second
	// policiesBumpTimeout bounds one org's cache-version bump: a hung Redis
	// must not hold the reconcile (the gateway TTL fallback covers the
	// staleness either way).
	policiesBumpTimeout = 5 * time.Second
	// policiesDefaultRedisAddr is the --redis-addr fallback when
	// $YABANIN_REDIS_ADDR is unset (pkg/config defaultRedisAddr parity).
	policiesDefaultRedisAddr = "localhost:6379"
)

// policiesRedisAddrDefault resolves the --redis-addr flag default:
// $YABANIN_REDIS_ADDR, then localhost:6379 (the deployment env contract).
func policiesRedisAddrDefault() string {
	if v := os.Getenv("YABANIN_REDIS_ADDR"); v != "" {
		return v
	}
	return policiesDefaultRedisAddr
}

func policiesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "Reconcile git policy declarations into the policystore (config-as-code)",
	}
	cmd.AddCommand(policiesReconcileCmd())
	cmd.AddCommand(policiesValidateCmd())
	cmd.AddCommand(policiesDiffCmd())
	cmd.AddCommand(policiesRollbackCmd())
	return cmd
}

// policiesValidateCmd is the CI gate (owner decision 2026-11-04 (c)): every
// declaration is parsed with the SAME strict pkg/pipeline schema the gateway
// compiles, before anything reaches the policystore. No database, no git —
// it is safe on any checkout, which is exactly what makes it CI-able.
func policiesValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Strictly validate the git policy declarations (no database) — the CI gate",
		Long: `Validate the deploy/policies declarations WITHOUT touching the database.

Every file is parsed with the strict pkg/pipeline schema (unknown fields are
errors, with file:line) — the same parser the gateway compiles at load time —
plus the reconcile block (attachment bounds, enabled shape). The command is
read-only: safe on any checkout, exits non-zero on the first invalid file.

  yb policies validate                                   # the whole tree
  yb policies validate --org acme                        # one org directory
  yb policies validate --dir deploy/policies --include-pack

This is what CI runs on every PR touching deploy/policies (G1: a broken
declaration fails the build before it can reach a policystore).`,
		RunE: runPoliciesValidateCmd,
	}
	cmd.Flags().String("dir", policiesDefaultDir, "Policy declarations directory")
	cmd.Flags().String("org", "", "Validate one organization directory (default: every directory under --dir)")
	cmd.Flags().Bool("include-pack", false, "Also validate the _pack declarations")
	return cmd
}

// policiesDiffCmd is the human plan preview: exactly the dry-run reconcile
// (the plan IS the diff between git and the policystore), minus the apply
// flag so the two verbs stay honest about what they can do.
func policiesDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff the git declarations against the policystore (dry-run plan)",
		Long: `Print the plan the next reconcile would apply: the git ↔ policystore diff.

Same output and drift report as ` + "`yb policies reconcile`" + ` without --apply —
add (new declaration), update (content changed), activate/enable/disable/
attachments, delete (--prune). Nothing is written.

  yb policies diff --pg-uri postgres://...              # whole tree
  yb policies diff --pg-uri ... --org acme --prune      # one org, incl. deletes`,
		RunE: runPoliciesDiffCmd,
	}
	cmd.Flags().String("pg-uri", "", "Postgres URI (required)")
	cmd.Flags().String("dir", policiesDefaultDir, "Policy declarations directory")
	cmd.Flags().String("org", "", "Organization slug (default: every directory under --dir)")
	cmd.Flags().Bool("prune", false, "Also plan deletion of database policies not covered by declarations")
	cmd.Flags().Bool("include-pack", false, "Include the _pack declarations")
	_ = cmd.MarkFlagRequired("pg-uri")
	return cmd
}

// policiesRollbackCmd activates an older version of one policy — the CLI
// counterpart of the admin API's version activation (the immutable-version
// model: rollback never rewrites or deletes anything, it only moves the
// current_version pointer).
func policiesRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Activate an older version of one policy (CLI parity with the UI rollback)",
		Long: `Point one policy's current_version at an older version.

Without --to the target is the newest version OLDER than the active one
(the previous version). --to selects an explicit version; it must exist and
be older than the active version. Versions are immutable: nothing is
rewritten or deleted, only the active pointer moves.

On success the gateway cache version key is bumped (--redis-addr, default
$YABANIN_REDIS_ADDR then localhost:6379) so the running gateway reloads
immediately; a Redis failure only warns (the TTL fallback bounds staleness).

  yb policies rollback --pg-uri ... --org acme --policy pii-guard
  yb policies rollback --pg-uri ... --org acme --policy pii-guard --to 2`,
		RunE: runPoliciesRollbackCmd,
	}
	cmd.Flags().String("pg-uri", "", "Postgres URI (required)")
	cmd.Flags().String("org", "", "Organization slug (required)")
	cmd.Flags().String("policy", "", "Policy name (required)")
	cmd.Flags().Int("to", 0, "Explicit target version (default: the previous version)")
	cmd.Flags().String("redis-addr", policiesRedisAddrDefault(), "Redis address for the gateway cache invalidation bump (default: $YABANIN_REDIS_ADDR, then localhost:6379)")
	_ = cmd.MarkFlagRequired("pg-uri")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

func runPoliciesValidateCmd(cmd *cobra.Command, _ []string) error {
	dir, err := cmd.Flags().GetString("dir")
	if err != nil {
		return err
	}
	org, err := cmd.Flags().GetString("org")
	if err != nil {
		return err
	}
	includePack, err := cmd.Flags().GetBool("include-pack")
	if err != nil {
		return err
	}
	return runPoliciesValidate(cmd.OutOrStdout(), policiesValidateOptions{
		Dir: dir, Org: org, IncludePack: includePack,
	})
}

func runPoliciesDiffCmd(cmd *cobra.Command, _ []string) error {
	pgURI, err := cmd.Flags().GetString("pg-uri")
	if err != nil {
		return err
	}
	dir, err := cmd.Flags().GetString("dir")
	if err != nil {
		return err
	}
	org, err := cmd.Flags().GetString("org")
	if err != nil {
		return err
	}
	prune, err := cmd.Flags().GetBool("prune")
	if err != nil {
		return err
	}
	includePack, err := cmd.Flags().GetBool("include-pack")
	if err != nil {
		return err
	}
	opts := policiesReconcileOptions{
		PGURI: pgURI, Dir: dir, Org: org, Prune: prune, IncludePack: includePack,
		// diff never writes: Apply stays false and the mode line says so.
		Diff: true,
	}
	sha, err := resolveGitSHA(cmd.Context(), opts.Dir)
	if err != nil {
		return fmt.Errorf("resolve git sha: %w", err)
	}
	opts.GitSHA = sha
	return connectAndReconcile(cmd.Context(), opts, cmd.OutOrStdout())
}

type policiesValidateOptions struct {
	Dir         string
	Org         string
	IncludePack bool
}

// runPoliciesValidate is the pure validate core: load (== strictly parse)
// every declaration and report. Exit code rides the returned error.
func runPoliciesValidate(out io.Writer, opts policiesValidateOptions) error {
	scanned, err := loadPolicyDeclarations(opts.Dir, opts.Org, opts.IncludePack)
	if err != nil {
		return err
	}
	files := 0
	for _, g := range scanned.orgs {
		for _, d := range g.decls {
			_, _ = fmt.Fprintf(out, "ok   %s (org %s, policy %s, mode %s)\n", d.Path, d.OrgSlug, d.Policy.Name, d.Policy.Mode)
			files++
		}
	}
	for _, d := range scanned.pack {
		_, _ = fmt.Fprintf(out, "ok   %s (pack, policy %s, mode %s)\n", d.Path, d.Policy.Name, d.Policy.Mode)
		files++
	}
	_, _ = fmt.Fprintf(out, "policies validate: dir=%s files=%d orgs=%d pack=%d — all declarations parse (strict pkg/pipeline schema)\n",
		opts.Dir, files, len(scanned.orgs), len(scanned.pack))
	if files == 0 {
		_, _ = fmt.Fprintf(out, "policies validate: no declarations under %s (nothing to validate; CI gate passes vacuously)\n", opts.Dir)
	}
	return nil
}

// --- rollback -----------------------------------------------------------------

// policiesRollbackOptions carries the rollback flags plus the same
// VersionBumper contract as reconcile (an activation IS a runtime-visible
// change — the gateway must reload its compiled pipeline immediately).
type policiesRollbackOptions struct {
	PGURI  string
	Org    string // slug
	Policy string // name
	To     int    // explicit target; 0 = the previous version
	// RedisAddr is the --redis-addr flag value (gateway cache invalidation).
	RedisAddr string
	// VersionBumper: nil = skip (unit fakes); a failed bump is a warning.
	VersionBumper adminstore.PolicyVersionBumper
}

// runPoliciesRollback is the pure rollback core: resolve org and policy,
// pick the target version (explicit --to or the previous one), activate.
// Immutable-version semantics: nothing is rewritten or deleted — only the
// current_version pointer moves (the same operation the admin API and the
// UI rollback use, so CLI and UI converge on one runtime).
func runPoliciesRollback(ctx context.Context, store policiesReconcileStore, opts policiesRollbackOptions, out io.Writer) error {
	o, err := store.GetOrganizationBySlug(ctx, opts.Org)
	if err != nil {
		return fmt.Errorf("org %q: %w", opts.Org, err)
	}
	policies, err := store.ListPolicies(ctx, o.ID)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	var policy *adminstore.PolicyPipeline
	for i := range policies {
		if policies[i].Name == opts.Policy {
			policy = &policies[i]
			break
		}
	}
	if policy == nil {
		return fmt.Errorf("policy %q not found in org %q", opts.Policy, opts.Org)
	}
	versions, err := store.ListPolicyVersions(ctx, o.ID, policy.ID)
	if err != nil {
		return fmt.Errorf("policy %q: list versions: %w", opts.Policy, err)
	}
	if len(versions) == 0 {
		return fmt.Errorf("policy %q: no versions (inconsistent store state)", opts.Policy)
	}
	active := policy.CurrentVersion
	if active == 0 {
		return fmt.Errorf("policy %q has no active version (nothing to roll back)", opts.Policy)
	}

	target := 0
	if opts.To > 0 {
		exists := false
		for _, v := range versions {
			if v.Version == opts.To {
				exists = true
				break
			}
		}
		if !exists {
			return fmt.Errorf("target version %d does not exist for policy %q", opts.To, opts.Policy)
		}
		if opts.To >= active {
			return fmt.Errorf("target version %d is not older than the active version %d (rollback never rolls forward)", opts.To, active)
		}
		target = opts.To
	} else {
		for _, v := range versions { // newest first (store contract)
			if v.Version < active {
				target = v.Version
				break
			}
		}
		if target == 0 {
			return fmt.Errorf("policy %q has no version older than the active version %d", opts.Policy, active)
		}
	}

	if _, err := store.SetActivePolicyVersion(ctx, o.ID, policy.ID, target); err != nil {
		return fmt.Errorf("activate version %d: %w", target, err)
	}
	_, _ = fmt.Fprintf(out, "rolled back %s (org %s): version %d → %d\n", opts.Policy, opts.Org, active, target)

	// Gateway cache invalidation — identical contract to reconcile's apply
	// bump: bounded, warning-only (the TTL fallback bounds staleness).
	if opts.VersionBumper != nil {
		bumpCtx, cancel := context.WithTimeout(ctx, policiesBumpTimeout)
		bumpErr := opts.VersionBumper.SetPolicyVersion(bumpCtx, o.ID, time.Now().UnixNano())
		cancel()
		if bumpErr != nil {
			_, _ = fmt.Fprintf(out, "WARNING: gateway cache bump failed: %v — the gateway picks the rollback up via its TTL fallback\n", bumpErr)
		} else {
			_, _ = fmt.Fprintf(out, "cache: %s%s bumped (gateway reloads its pipelines now)\n", adminstore.PolicyVersionKeyPrefix, o.ID)
		}
	}
	return nil
}

func runPoliciesRollbackCmd(cmd *cobra.Command, _ []string) error {
	pgURI, err := cmd.Flags().GetString("pg-uri")
	if err != nil {
		return err
	}
	org, err := cmd.Flags().GetString("org")
	if err != nil {
		return err
	}
	policy, err := cmd.Flags().GetString("policy")
	if err != nil {
		return err
	}
	to, err := cmd.Flags().GetInt("to")
	if err != nil {
		return err
	}
	redisAddr, err := cmd.Flags().GetString("redis-addr")
	if err != nil {
		return err
	}
	opts := policiesRollbackOptions{PGURI: pgURI, Org: org, Policy: policy, To: to, RedisAddr: redisAddr}
	if opts.To < 0 {
		return fmt.Errorf("--to must be a positive version number")
	}

	rdb := redis.NewClient(&redis.Options{Addr: opts.RedisAddr})
	defer func() { _ = rdb.Close() }()
	opts.VersionBumper = adminstore.NewPolicyVersionCache(rdb, slog.Default())

	ctx, cancel := context.WithTimeout(cmd.Context(), policiesTimeout)
	defer cancel()
	pool, err := pgxpool.New(ctx, opts.PGURI)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	store := adminstore.New(pool, slog.Default(), nil)
	return runPoliciesRollback(ctx, store, opts, cmd.OutOrStdout())
}

func policiesReconcileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Plan (dry-run) or apply the git → policystore policy reconciliation",
		Long: `Converge the policystore onto the git declarations (deploy/policies).

DRY-RUN BY DEFAULT: prints a human-readable plan (add/update/activate/
enable/disable/attachments/delete) and writes nothing. Pass --apply to apply.

DRIFT SEMANTICS — GIT WINS: a database edit made past git (a version
authored outside git whose content differs from the declaration) is reported
as DRIFT and overwritten by a new version under --apply. The diverged version
stays in immutable history (port it to a PR or lose it on the next apply).
No --force: the dry-run plan is the confirmation surface.

--prune plans deletion of database policies that no declaration covers
(danger: with --apply they are deleted — review the dry-run first).
--include-pack adds the _pack declarations (sovereign-default; ships OFF).

  yb policies reconcile --pg-uri postgres://...            # plan
  yb policies reconcile --pg-uri ... --apply               # converge
  yb policies reconcile --pg-uri ... --org acme --apply    # one org (slug)
  yb policies reconcile --pg-uri ... --apply --prune       # also delete

A successful --apply also bumps policystore:ver:<orgID> in Redis
(--redis-addr, default $YABANIN_REDIS_ADDR then localhost:6379) so the
gateway reloads its compiled pipelines immediately; a Redis failure only
warns — the gateway then reloads via its TTL fallback.`,
		RunE: runPoliciesReconcileCmd,
	}
	cmd.Flags().String("pg-uri", "", "Postgres URI (required)")
	cmd.Flags().String("dir", policiesDefaultDir, "Policy declarations directory")
	cmd.Flags().String("org", "", "Organization slug to reconcile (default: every directory under --dir)")
	cmd.Flags().Bool("apply", false, "Apply the plan (default: dry-run)")
	cmd.Flags().Bool("prune", false, "Delete database policies not covered by declarations (danger: effective with --apply)")
	cmd.Flags().Bool("include-pack", false, "Include the _pack declarations (sovereign-default pack; default OFF)")
	cmd.Flags().String("git-sha", "", "Source revision recorded on reconciled versions (default: git rev-parse --short HEAD in --dir)")
	cmd.Flags().String("created-by", policiesCreatedBy, "Actor recorded on reconciled versions")
	cmd.Flags().String("redis-addr", policiesRedisAddrDefault(), "Redis address for the gateway cache invalidation bump (default: $YABANIN_REDIS_ADDR, then localhost:6379)")
	_ = cmd.MarkFlagRequired("pg-uri")
	return cmd
}

type policiesReconcileOptions struct {
	PGURI       string
	Dir         string
	Org         string
	Apply       bool
	Prune       bool
	IncludePack bool
	GitSHA      string
	CreatedBy   string
	// Diff renders the mode line as a diff (policies diff — the dry-run
	// reconcile under a second verb); it never writes.
	Diff bool
	// RedisAddr is the --redis-addr flag value (gateway cache invalidation).
	RedisAddr string
	// VersionBumper invalidates the gateway's compiled-pipeline cache after
	// a successful apply (OP-0b → OP-8 contract: policystore:ver:<orgID>).
	// The command wires adminstore.NewPolicyVersionCache over --redis-addr;
	// nil = skip (unit fakes, dry-runs never bump anyway). A failed bump is
	// a warning — the gateway's TTL fallback bounds the staleness.
	VersionBumper adminstore.PolicyVersionBumper
}

// policiesReconcileStore is the narrow surface reconciliation needs: the
// OP-0b policy pipeline contract plus the org slug lookup. *adminstore.Store
// satisfies it (compile pin below) — no adminstore changes.
type policiesReconcileStore interface {
	adminstore.PolicyPipelineStore
	GetOrganizationBySlug(ctx context.Context, slug string) (*adminstore.Organization, error)
}

var _ policiesReconcileStore = (*adminstore.Store)(nil)

// runPoliciesReconcileCmd parses flags, connects and delegates to the pure
// core (runPoliciesReconcile).
func runPoliciesReconcileCmd(cmd *cobra.Command, _ []string) error {
	pgURI, err := cmd.Flags().GetString("pg-uri")
	if err != nil {
		return err
	}
	dir, err := cmd.Flags().GetString("dir")
	if err != nil {
		return err
	}
	org, err := cmd.Flags().GetString("org")
	if err != nil {
		return err
	}
	apply, err := cmd.Flags().GetBool("apply")
	if err != nil {
		return err
	}
	prune, err := cmd.Flags().GetBool("prune")
	if err != nil {
		return err
	}
	includePack, err := cmd.Flags().GetBool("include-pack")
	if err != nil {
		return err
	}
	gitSHA, err := cmd.Flags().GetString("git-sha")
	if err != nil {
		return err
	}
	createdBy, err := cmd.Flags().GetString("created-by")
	if err != nil {
		return err
	}
	redisAddr, err := cmd.Flags().GetString("redis-addr")
	if err != nil {
		return err
	}
	opts := policiesReconcileOptions{
		PGURI: pgURI, Dir: dir, Org: org, Apply: apply, Prune: prune,
		IncludePack: includePack, GitSHA: gitSHA, CreatedBy: createdBy,
		RedisAddr: redisAddr,
	}
	if opts.GitSHA == "" {
		sha, err := resolveGitSHA(cmd.Context(), opts.Dir)
		if err != nil {
			return fmt.Errorf("resolve git sha (pass --git-sha to override): %w", err)
		}
		opts.GitSHA = sha
	}

	// (policystore:ver:<orgID>, the OP-0b contract). The client connects
	// lazily; an unreachable Redis surfaces as a per-org bump warning, not a
	// reconcile failure. Dry-runs never construct it — they touch nothing.
	if opts.Apply {
		rdb := redis.NewClient(&redis.Options{Addr: opts.RedisAddr})
		defer func() { _ = rdb.Close() }()
		opts.VersionBumper = adminstore.NewPolicyVersionCache(rdb, slog.Default())
	}

	return connectAndReconcile(cmd.Context(), opts, cmd.OutOrStdout())
}

// connectAndReconcile opens the postgres pool and runs the pure core —
// shared by reconcile and diff (diff constructs its options itself).
func connectAndReconcile(ctx context.Context, opts policiesReconcileOptions, out io.Writer) error {
	runCtx, cancel := context.WithTimeout(ctx, policiesTimeout)
	defer cancel()

	pool, err := pgxpool.New(runCtx, opts.PGURI)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(runCtx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	store := adminstore.New(pool, slog.Default(), nil)
	return runPoliciesReconcile(runCtx, store, opts, out)
}

// resolveGitSHA records the source revision (stored on every reconciled
// version as git_sha — the drift detector's anchor). Short form: it labels
// the intent, and the content comparison is byte-exact anyway.
func resolveGitSHA(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--short", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse in %s: %w", dir, err)
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", fmt.Errorf("git rev-parse in %s returned an empty revision", dir)
	}
	return sha, nil
}

// runPoliciesReconcile is the pure core: load declarations, plan per org,
// apply when requested, render the plan. A declaration/parse error anywhere
// fails the run BEFORE any write (the CI validation gate).
func runPoliciesReconcile(ctx context.Context, store policiesReconcileStore, opts policiesReconcileOptions, out io.Writer) error {
	scanned, err := loadPolicyDeclarations(opts.Dir, opts.Org, opts.IncludePack)
	if err != nil {
		return err
	}
	if len(scanned.orgs) == 0 {
		_, _ = fmt.Fprintf(out, "policies reconcile: no organization declarations under %s (nothing to do)\n", opts.Dir)
		return nil
	}
	if opts.IncludePack && len(scanned.pack) > 0 && len(scanned.orgs) == 0 {
		_, _ = fmt.Fprintf(out, "policies reconcile: --include-pack set but no organizations in scope (pack skipped)\n")
	}

	orgs, orgErrs := resolveOrgs(ctx, store, scanned.orgs, opts.Org)
	groupBySlug := make(map[string]policyDeclGroup, len(scanned.orgs))
	for _, g := range scanned.orgs {
		groupBySlug[g.slug] = g
	}
	orgPlans := make([]orgPlan, 0, len(orgs))
	var summary reconcileSummary
	for _, o := range orgs {
		plans, err := planOrgPolicies(ctx, store, o, effectiveDecls(groupBySlug[o.slug], scanned.pack), opts)
		if err != nil {
			orgErrs = append(orgErrs, fmt.Errorf("org %s: %w", o.slug, err))
			continue
		}
		op := orgPlan{org: o, plans: plans}
		summary.accumulate(plans)
		if opts.Apply {
			var applyErr error
			op.applied, op.failedPolicy, op.notAttempted, applyErr = applyOrgPlans(ctx, store, o, plans, opts)
			if applyErr != nil {
				orgErrs = append(orgErrs, fmt.Errorf("org %s: %w", o.slug, applyErr))
				op.applyErr = applyErr
			} else if opts.VersionBumper != nil && orgPlansMutations(plans) > 0 {
				// request — the bump drops its compiled-pipeline caches now.
				// Value/TTL per the OP-0b contract (UnixNano, 7d) live inside
				// NewPolicyVersionCache; the bump is bounded separately so a
				// hung Redis cannot hold the reconcile, and it never fails
				// the run (the TTL fallback bounds gateway staleness).
				bumpCtx, bumpCancel := context.WithTimeout(ctx, policiesBumpTimeout)
				bumpErr := opts.VersionBumper.SetPolicyVersion(bumpCtx, o.id, time.Now().UnixNano())
				bumpCancel()
				if bumpErr != nil {
					op.bumpErr = bumpErr
				} else {
					op.cacheBumped = true
				}
			}
		}
		orgPlans = append(orgPlans, op)
	}

	mode := "dry-run (pass --apply to converge)"
	if opts.Apply {
		mode = "apply"
	} else if opts.Diff {
		mode = "diff (dry-run — nothing written; apply with `policies reconcile --apply`)"
	}
	_, _ = fmt.Fprintf(out, "policies reconcile: dir=%s git-sha=%s mode=%s\n", opts.Dir, opts.GitSHA, mode)
	renderReconcilePlan(out, orgPlans, scanned, summary, opts)

	if len(orgErrs) > 0 {
		var b strings.Builder
		for i, e := range orgErrs {
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.Error())
		}
		return errors.New(b.String())
	}
	if !opts.Apply {
		_, _ = fmt.Fprintf(out, "dry-run: nothing written (pass --apply to converge)\n")
	}
	return nil
}

// --- declaration model -------------------------------------------------------

// policyDeclAttachment mirrors the policystore attachment row (the replace-all
// set): key_label "" = every key of the org. Priority defaults to 100 (the
// admin API default) when omitted.
type policyDeclAttachment struct {
	KeyLabel     string `yaml:"key_label"`
	ModelPattern string `yaml:"model_pattern"`
	Endpoint     string `yaml:"endpoint"`
	Priority     *int   `yaml:"priority"`
}

// policyDeclMeta is the optional SECOND YAML document of a declaration — the
// reconcile block. It is never stored as policy content (the stored YAML is
// the first document verbatim, exactly what the gateway compiles). enabled/
// attachments omitted = keep the database value (an existing policy never
// flips by omission).
type policyDeclMeta struct {
	Enabled     *bool                   `yaml:"enabled"`
	Attachments *[]policyDeclAttachment `yaml:"attachments"`
}

// policyDeclaration is one parsed declaration file.
type policyDeclaration struct {
	Path string
	// OrgSlug is the declaring directory ("" for pack declarations, which
	// are org-agnostic until --include-pack binds them to every org in
	// scope).
	OrgSlug string
	Policy  pipeline.Policy
	// PolicyYAML is the first document VERBATIM (comments preserved) —
	// exactly what reconciliation stores and what byte-exact idempotency
	// compares against.
	PolicyYAML string
	Meta       policyDeclMeta
	Pack       bool
}

// policyDecl is a parsed declaration grouped under its org directory.
type policyDeclGroup struct {
	slug  string
	decls []policyDeclaration
}

// scannedDeclarations is the parsed --dir tree.
type scannedDeclarations struct {
	orgs []policyDeclGroup
	pack []policyDeclaration
}

// loadPolicyDeclarations scans dir: one directory per org slug, one file per
// policy. Directories starting with "_" are namespaces (never orgs): _pack
// is read only when includePack is set. A direct .yaml file under dir is an
// error (a declaration without an org is meaningless — the same reason the
// Portkey per-request bypass is off the table).
func loadPolicyDeclarations(dir, orgFilter string, includePack bool) (scannedDeclarations, error) {
	var scanned scannedDeclarations
	entries, err := readDirSorted(dir)
	if err != nil {
		return scanned, err
	}
	foundFilter := false
	for _, e := range entries {
		name := e.name
		if !e.dir {
			if isYAMLFile(name) {
				return scanned, fmt.Errorf("%s: declaration files must live in an organization directory (<org-slug>/<policy-name>.yaml)", filepath.Join(dir, name))
			}
			continue // README and friends live here by design
		}
		if strings.HasPrefix(name, policiesNamespacePrefix) {
			if name == policiesPackDir && includePack {
				pack, err := loadOrgDeclarations(dir, name, "", orgFilter)
				if err != nil {
					return scanned, err
				}
				scanned.pack = pack.decls
			}
			continue // namespace directory: never an org
		}
		if orgFilter != "" && name != orgFilter {
			continue
		}
		if name == orgFilter {
			foundFilter = true
		}
		group, err := loadOrgDeclarations(dir, name, name, orgFilter)
		if err != nil {
			return scanned, err
		}
		scanned.orgs = append(scanned.orgs, group)
	}
	if orgFilter != "" && !foundFilter {
		return scanned, fmt.Errorf("org directory %q not found under %s (--org)", orgFilter, dir)
	}
	return scanned, nil
}

// loadOrgDeclarations reads one org (or pack) directory's yaml files.
func loadOrgDeclarations(dir, name, slug, orgFilter string) (policyDeclGroup, error) {
	group := policyDeclGroup{slug: slug}
	entries, err := readDirSorted(filepath.Join(dir, name))
	if err != nil {
		return group, err
	}
	for _, e := range entries {
		path := filepath.Join(dir, name, e.name)
		if e.dir {
			return group, fmt.Errorf("%s: nested directories are not allowed (one policy per file: <org-slug>/<policy-name>.yaml)", path)
		}
		if !isYAMLFile(e.name) {
			continue
		}
		raw, err := readFileLimited(path)
		if err != nil {
			return group, err
		}
		decl, err := parsePolicyDeclaration(path, raw, slug, slug == "")
		if err != nil {
			return group, err
		}
		group.decls = append(group.decls, decl)
	}
	return group, nil
}

// parsePolicyDeclaration parses one file: document 1 is the policy (strict
// pipeline schema, stored verbatim), document 2 is the optional reconcile
// block. Errors carry the file path (and line, via the YAML decoder) — the
// CI validation gate depends on actionable messages.
func parsePolicyDeclaration(path string, raw []byte, slug string, pack bool) (policyDeclaration, error) {
	var decl policyDeclaration
	docs, err := splitYAMLDocuments(path, raw)
	if err != nil {
		return decl, err
	}
	pol, err := pipeline.ParsePolicy(docs[0])
	if err != nil {
		return decl, fmt.Errorf("%s: %w", path, err)
	}
	stem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if stem != pol.Name {
		return decl, fmt.Errorf("%s: policy name %q must match the file stem %q", path, pol.Name, stem)
	}
	decl = policyDeclaration{
		Path:       path,
		OrgSlug:    slug,
		Policy:     pol,
		PolicyYAML: string(docs[0]),
		Pack:       pack,
	}
	if len(docs) > 1 {
		dec := yaml.NewDecoder(bytes.NewReader(docs[1]))
		dec.KnownFields(true)
		if err := dec.Decode(&decl.Meta); err != nil {
			return decl, fmt.Errorf("%s: reconcile block (second document): %w", path, err)
		}
		if err := validateDeclMeta(decl.Meta); err != nil {
			return decl, fmt.Errorf("%s: reconcile block: %w", path, err)
		}
	}
	return decl, nil
}

// splitYAMLDocuments splits a file into its YAML documents on top-level
// "---" separators (a column-0 document marker per the YAML spec), keeping
// the raw bytes of each document so the stored policy stays verbatim.
func splitYAMLDocuments(path string, raw []byte) ([][]byte, error) {
	const sep = "\n---"
	var docs [][]byte
	for i, part := range strings.Split(string(raw), sep) {
		trimmed := strings.TrimSpace(part)
		// A leading separator (or a BOM-free empty head) is fine; an empty
		// document in the middle is a broken file.
		if trimmed == "" {
			if i == 0 {
				continue
			}
			return nil, fmt.Errorf("%s: empty YAML document %d", path, i+1)
		}
		docs = append(docs, []byte(trimmed))
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%s: declaration file is empty", path)
	}
	if len(docs) > 2 {
		return nil, fmt.Errorf("%s: at most two documents expected (policy + optional reconcile block), got %d", path, len(docs))
	}
	return docs, nil
}

// validateDeclMeta applies the attachment bounds (admin API parity: required
// fields, priority 0..1000000).
func validateDeclMeta(m policyDeclMeta) error {
	if m.Attachments == nil {
		return nil
	}
	for _, a := range *m.Attachments {
		if strings.TrimSpace(a.ModelPattern) == "" {
			return errors.New("attachment model_pattern is required")
		}
		if strings.TrimSpace(a.Endpoint) == "" {
			return errors.New("attachment endpoint is required")
		}
		if a.Priority != nil && (*a.Priority < 0 || *a.Priority > policiesMaxPriority) {
			return fmt.Errorf("attachment priority must be between 0 and %d", policiesMaxPriority)
		}
	}
	return nil
}

// --- planning ----------------------------------------------------------------

// policyPlanAction is one planned step for a policy.
type policyPlanAction string

const (
	planAdd         policyPlanAction = "add"         // create policy + v1 + activate
	planUpdate      policyPlanAction = "update"      // append the git content as a new version
	planActivate    policyPlanAction = "activate"    // point current_version at the latest version
	planEnable      policyPlanAction = "enable"      // enabled -> true (declared)
	planDisable     policyPlanAction = "disable"     // enabled -> false (declared)
	planAttachments policyPlanAction = "attachments" // replace-all attachment set
	planDelete      policyPlanAction = "delete"      // prune: not in git
)

// policyDrift reports a database state that diverged from git (see the
// file-level comment for the git-wins semantics).
type policyDrift struct {
	Reason      string
	DBVersion   int
	DBGitSHA    string
	DBCreatedBy string
}

// policyPlan is the per-policy outcome. The Actions slice is the display
// truth; the Decl/Desired* fields are the execution truth filled by the
// planner.
type policyPlan struct {
	Name     string
	PolicyID string // existing pipeline id ("" for add)
	Path     string // declaration path ("" for prune candidates)
	Actions  []policyPlanAction
	Drift    *policyDrift

	PruneCandidate bool
	Decl           *policyDeclaration
	DesiredVersion int                           // activate target (0 = n/a)
	DesiredEnabled *bool                         // enable/disable target
	DesiredAtts    []adminstore.PolicyAttachment // replace-all set
}

// orgRef is one resolved organization scope.
type orgRef struct {
	slug string
	id   string
}

// orgPlan is one org's plan (or its resolution/apply failure).
type orgPlan struct {
	org      orgRef
	plans    []policyPlan
	applyErr error
	// apply outcome bookkeeping (mixed-state disclosure): policies whose
	// plans were fully applied, the policy whose apply failed midway (some
	// of its steps may have landed — that IS the mixed state), and the
	// policies the run never attempted because it stopped at the failure.
	applied      []string
	failedPolicy string
	notAttempted []string
	// when the org's policystore:ver key was bumped after a successful
	// apply; bumpErr carries a failed/unreachable Redis (a WARNING, never a
	// reconcile failure — the gateway's TTL fallback bounds the staleness).
	cacheBumped bool
	bumpErr     error
}

// reconcileSummary totals the plan for the closing line.
type reconcileSummary struct {
	orgs      int
	add       int
	update    int
	activate  int
	enable    int
	disable   int
	attach    int
	del       int
	drift     int
	unchanged int
}

func (s *reconcileSummary) accumulate(plans []policyPlan) {
	s.orgs++
	for _, p := range plans {
		if p.PruneCandidate {
			continue // reported in the listing; counted only when prune plans a delete
		}
		if len(p.Actions) == 0 {
			s.unchanged++
			continue
		}
		for _, a := range p.Actions {
			switch a {
			case planAdd:
				s.add++
			case planUpdate:
				s.update++
			case planActivate:
				s.activate++
			case planEnable:
				s.enable++
			case planDisable:
				s.disable++
			case planAttachments:
				s.attach++
			case planDelete:
				s.del++
			}
		}
		if p.Drift != nil {
			s.drift++
		}
	}
}

// effectiveDecls merges the pack declarations (org-agnostic) into one org's
// scope. Pack files sort together with org files by policy name, so the
// plan output is deterministic.
func effectiveDecls(o policyDeclGroup, pack []policyDeclaration) []policyDeclaration {
	if len(pack) == 0 {
		return o.decls
	}
	out := make([]policyDeclaration, 0, len(o.decls)+len(pack))
	out = append(out, o.decls...)
	for _, d := range pack {
		d.OrgSlug = o.slug
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Policy.Name < out[j].Policy.Name })
	return out
}

// resolveOrgs resolves every declaration slug to an org id. An unknown slug
// is reported per org (not fatal) unless it was explicitly requested via
// --org (then it fails the run).
func resolveOrgs(ctx context.Context, store policiesReconcileStore, groups []policyDeclGroup, orgFilter string) ([]orgRef, []error) {
	var (
		resolved []orgRef
		errs     []error
	)
	for _, g := range groups {
		o, err := store.GetOrganizationBySlug(ctx, g.slug)
		switch {
		case err == nil:
			resolved = append(resolved, orgRef{slug: g.slug, id: o.ID})
		case orgFilter != "":
			errs = append(errs, fmt.Errorf("org %q requested via --org: %w", g.slug, err))
		default:
			errs = append(errs, fmt.Errorf("org %q: %w (declaration directory without an organization; create the org or move the directory)", g.slug, err))
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].slug < resolved[j].slug })
	return resolved, errs
}

// planOrgPolicies diffs one org's declarations against its policystore rows.
// Deterministic: declarations sorted by policy name, prune candidates
// appended sorted by name.
func planOrgPolicies(ctx context.Context, store policiesReconcileStore, o orgRef, decls []policyDeclaration, opts policiesReconcileOptions) ([]policyPlan, error) {
	dbPolicies, err := store.ListPolicies(ctx, o.id)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	byName := make(map[string]adminstore.PolicyPipeline, len(dbPolicies))
	for _, p := range dbPolicies {
		byName[p.Name] = p
	}
	matched := make(map[string]bool, len(decls))

	plans := make([]policyPlan, 0, len(decls))
	for i := range decls {
		decl := decls[i]
		name := decl.Policy.Name
		matched[name] = true
		existing, ok := byName[name]
		if !ok {
			// add is composite: policy + v1 + activate + declared
			// enabled/attachments (applied by the canonical create
			// sequence; the store defaults cover the rest).
			plan := policyPlan{
				Name: name, Path: decl.Path, Actions: []policyPlanAction{planAdd},
				Decl: &decl,
			}
			if decl.Meta.Enabled != nil && *decl.Meta.Enabled {
				enabled := true
				plan.DesiredEnabled = &enabled
			}
			if decl.Meta.Attachments != nil {
				plan.DesiredAtts = desiredAttachments(decl.Meta.Attachments)
			}
			plans = append(plans, plan)
			continue
		}

		versions, err := store.ListPolicyVersions(ctx, o.id, existing.ID)
		if err != nil {
			return nil, fmt.Errorf("policy %q: list versions: %w", name, err)
		}
		if len(versions) == 0 {
			return nil, fmt.Errorf("policy %q: pipeline %s has no versions (inconsistent store state)", name, existing.ID)
		}
		latest := versions[0] // newest first (store contract)

		plan := policyPlan{Name: name, PolicyID: existing.ID, Path: decl.Path, Decl: &decl}
		desiredVersion := latest.Version
		if latest.YAML != decl.PolicyYAML {
			if latest.GitSHA == "" {
				plan.Drift = &policyDrift{
					Reason:      driftReason(versions),
					DBVersion:   latest.Version,
					DBGitSHA:    latest.GitSHA,
					DBCreatedBy: latest.CreatedBy,
				}
			}
			plan.Actions = append(plan.Actions, planUpdate)
			desiredVersion = latest.Version + 1
		}
		if existing.CurrentVersion != desiredVersion {
			plan.Actions = append(plan.Actions, planActivate)
			plan.DesiredVersion = desiredVersion
		}
		if decl.Meta.Enabled != nil && *decl.Meta.Enabled != existing.Enabled {
			if *decl.Meta.Enabled {
				plan.Actions = append(plan.Actions, planEnable)
			} else {
				plan.Actions = append(plan.Actions, planDisable)
			}
			enabled := *decl.Meta.Enabled
			plan.DesiredEnabled = &enabled
		}
		if decl.Meta.Attachments != nil {
			dbAtts, err := store.ListPolicyAttachments(ctx, o.id, existing.ID)
			if err != nil {
				return nil, fmt.Errorf("policy %q: list attachments: %w", name, err)
			}
			desired := desiredAttachments(decl.Meta.Attachments)
			if !attachmentsEqual(dbAtts, desired) {
				plan.Actions = append(plan.Actions, planAttachments)
				plan.DesiredAtts = desired
			}
		}
		plans = append(plans, plan)
	}

	// Uncovered database rows: prune candidates (deleted only with
	// --prune --apply — git is the complete truth only when prune is on).
	var uncovered []adminstore.PolicyPipeline
	for _, p := range dbPolicies {
		if !matched[p.Name] {
			uncovered = append(uncovered, p)
		}
	}
	sort.Slice(uncovered, func(i, j int) bool { return uncovered[i].Name < uncovered[j].Name })
	for _, p := range uncovered {
		plan := policyPlan{Name: p.Name, PolicyID: p.ID, PruneCandidate: true}
		if opts.Prune {
			plan.Actions = []policyPlanAction{planDelete}
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// driftReason distinguishes "never reconciled" (UI-native policy) from
// "edited outside git" (a git-managed policy that someone changed via the
// UI/API — the Bifrost failure mode this detector exists for).
func driftReason(versions []adminstore.PolicyVersion) string {
	for _, v := range versions {
		if v.GitSHA != "" {
			return "edited outside git after a reconcile (latest version authored outside git)"
		}
	}
	return "policy never reconciled from git (all versions authored outside git)"
}

// desiredAttachments normalizes declaration attachments into store rows
// (default priority 100).
func desiredAttachments(decls *[]policyDeclAttachment) []adminstore.PolicyAttachment {
	out := make([]adminstore.PolicyAttachment, 0, len(*decls))
	for _, a := range *decls {
		priority := policiesDefaultPriority
		if a.Priority != nil {
			priority = *a.Priority
		}
		out = append(out, adminstore.PolicyAttachment{
			KeyLabel:     a.KeyLabel,
			ModelPattern: a.ModelPattern,
			Endpoint:     a.Endpoint,
			Priority:     priority,
		})
	}
	return out
}

// attachmentsEqual compares the database set with the desired set
// order-insensitively (the store lists by priority; declarations are a set).
func attachmentsEqual(db, desired []adminstore.PolicyAttachment) bool {
	if len(db) != len(desired) {
		return false
	}
	key := func(a adminstore.PolicyAttachment) string {
		return a.KeyLabel + "\x00" + a.ModelPattern + "\x00" + a.Endpoint + "\x00" + strconv.Itoa(a.Priority)
	}
	keys := make([]string, 0, len(db))
	for _, a := range db {
		keys = append(keys, key(a))
	}
	sort.Strings(keys)
	want := make([]string, 0, len(desired))
	for _, a := range desired {
		want = append(want, key(a))
	}
	sort.Strings(want)
	for i := range keys {
		if keys[i] != want[i] {
			return false
		}
	}
	return true
}

// --- apply -------------------------------------------------------------------

// applyOrgPlans executes one org's plan. Execution order per policy is
// canonical (create/version → activate → enabled → attachments → delete) and
// matches the admin create/update semantics, so a repeated run plans zero
// actions (idempotency).
//
// Mixed-state contract (card N16-P01-T02 negative acceptance): a failure
// NEVER leaves an unreported mixed state. The run stops at the first failing
// policy and reports exactly what landed: applied (fully converged), the
// failed policy (possibly partially applied — e.g. a version appended but
// not activated), and notAttempted (untouched). Version history is the
// forensic record; a re-run after the fix is the resume path (idempotent).
func applyOrgPlans(ctx context.Context, store policiesReconcileStore, o orgRef, plans []policyPlan, opts policiesReconcileOptions) (applied []string, failedPolicy string, notAttempted []string, err error) {
	for i, plan := range plans {
		if aerr := applyPolicyPlan(ctx, store, o.id, plan, opts); aerr != nil {
			failedPolicy = plan.Name
			err = fmt.Errorf("policy %q: %w", plan.Name, aerr)
			for _, rest := range plans[i+1:] {
				notAttempted = append(notAttempted, rest.Name)
			}
			return applied, failedPolicy, notAttempted, err
		}
		applied = append(applied, plan.Name)
	}
	return applied, "", notAttempted, nil
}

// applyPolicyPlan converges one policy. Every branch re-reads what it needs
// from the plan (filled during planning) — the applier never re-decides.
func applyPolicyPlan(ctx context.Context, store policiesReconcileStore, orgID string, plan policyPlan, opts policiesReconcileOptions) error {
	if len(plan.Actions) == 0 {
		return nil
	}
	has := func(a policyPlanAction) bool {
		for _, x := range plan.Actions {
			if x == a {
				return true
			}
		}
		return false
	}

	switch {
	case has(planAdd):
		p, v, err := store.CreatePolicy(ctx, orgID, plan.Decl.Policy.Name, plan.Decl.PolicyYAML, opts.GitSHA, opts.CreatedBy)
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		plan.PolicyID = p.ID
		plan.DesiredVersion = v.Version
	case has(planUpdate):
		v, err := store.CreatePolicyVersion(ctx, orgID, plan.PolicyID, plan.Decl.PolicyYAML, opts.GitSHA, opts.CreatedBy)
		if err != nil {
			return fmt.Errorf("append version: %w", err)
		}
		plan.DesiredVersion = v.Version
	}
	if plan.DesiredVersion > 0 {
		if _, err := store.SetActivePolicyVersion(ctx, orgID, plan.PolicyID, plan.DesiredVersion); err != nil {
			return fmt.Errorf("activate version %d: %w", plan.DesiredVersion, err)
		}
	}
	if plan.DesiredEnabled != nil {
		if _, err := store.UpdatePolicy(ctx, orgID, plan.PolicyID, *plan.DesiredEnabled); err != nil {
			return fmt.Errorf("set enabled=%t: %w", *plan.DesiredEnabled, err)
		}
	}
	if plan.DesiredAtts != nil {
		if _, err := store.SetPolicyAttachments(ctx, orgID, plan.PolicyID, plan.DesiredAtts); err != nil {
			return fmt.Errorf("set attachments: %w", err)
		}
	}
	if has(planDelete) {
		if err := store.DeletePolicy(ctx, orgID, plan.PolicyID); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
	}
	return nil
}

// --- rendering -----------------------------------------------------------------

// orgPlansMutations counts the planned store mutations for one org (0 = the
// org is in sync — a no-op apply must not invalidate the gateway cache).
func orgPlansMutations(plans []policyPlan) int {
	n := 0
	for i := range plans {
		n += len(plans[i].Actions)
	}
	return n
}

// renderReconcilePlan prints the human-readable plan: per org, per policy —
// drift blocks first, then actions, then prune candidates.
func renderReconcilePlan(out io.Writer, orgPlans []orgPlan, scanned scannedDeclarations, summary reconcileSummary, opts policiesReconcileOptions) {
	unresolved := 0
	for _, op := range orgPlans {
		_, _ = fmt.Fprintf(out, "org %s (%s):\n", op.org.slug, op.org.id)
		if op.applyErr != nil {
			_, _ = fmt.Fprintf(out, "  apply FAILED: %v\n", op.applyErr)
			// Mixed-state disclosure (never leave it unreported): what
			// landed, what half-landed, what was never attempted — plus the
			// idempotent resume path.
			if len(op.applied) > 0 {
				_, _ = fmt.Fprintf(out, "  applied (live now): %s\n", strings.Join(op.applied, ", "))
			}
			if op.failedPolicy != "" {
				_, _ = fmt.Fprintf(out, "  PARTIALLY APPLIED: %q — some steps may have landed; the version/attachment history shows exactly what\n", op.failedPolicy)
			}
			if len(op.notAttempted) > 0 {
				_, _ = fmt.Fprintf(out, "  NOT APPLIED: %s\n", strings.Join(op.notAttempted, ", "))
			}
			_, _ = fmt.Fprintf(out, "  resume: fix the error and re-run reconcile — the plan is idempotent (applied steps report \"in sync\", the rest replays)\n")
		}
		switch {
		case op.cacheBumped:
			_, _ = fmt.Fprintf(out, "  cache: %s%s bumped (gateway reloads its pipelines now)\n",
				adminstore.PolicyVersionKeyPrefix, op.org.id)
		case op.bumpErr != nil:
			_, _ = fmt.Fprintf(out, "  WARNING: gateway cache bump failed: %v — the gateway picks the changes up via its TTL fallback\n", op.bumpErr)
		}
		if len(op.plans) == 0 {
			_, _ = fmt.Fprintf(out, "  (no declarations)\n")
			continue
		}
		for _, p := range op.plans {
			if p.Drift != nil {
				_, _ = fmt.Fprintf(out, "  DRIFT  %s: %s (db version %d, created_by=%q, git_sha=%q) — git wins on apply\n",
					p.Name, p.Drift.Reason, p.Drift.DBVersion, p.Drift.DBCreatedBy, p.Drift.DBGitSHA)
			}
			if p.PruneCandidate {
				if opts.Prune {
					_, _ = fmt.Fprintf(out, "  delete %s (not covered by git)\n", p.Name)
				} else {
					_, _ = fmt.Fprintf(out, "  -      %s (not covered by git; pass --prune to delete)\n", p.Name)
				}
				continue
			}
			if len(p.Actions) == 0 {
				_, _ = fmt.Fprintf(out, "  -      %s (in sync)\n", p.Name)
				continue
			}
			actions := make([]string, 0, len(p.Actions))
			for _, a := range p.Actions {
				actions = append(actions, string(a))
			}
			detail := ""
			if p.Path != "" {
				detail = " (" + p.Path + ")"
			}
			_, _ = fmt.Fprintf(out, "  %-6s %s%s\n", strings.Join(actions, "+"), p.Name, detail)
		}
	}
	unresolved = len(scanned.orgs) - len(orgPlans)
	if unresolved > 0 {
		_, _ = fmt.Fprintf(out, "(%d org(s) skipped: slug not found in the database)\n", unresolved)
	}
	_, _ = fmt.Fprintf(out, "summary: orgs=%d add=%d update=%d activate=%d enable=%d disable=%d attachments=%d delete=%d drift=%d unchanged=%d\n",
		summary.orgs, summary.add, summary.update, summary.activate, summary.enable, summary.disable,
		summary.attach, summary.del, summary.drift, summary.unchanged)
}

// --- small fs helpers ----------------------------------------------------------

type dirEntryLite struct {
	name string
	dir  bool
}

// readDirSorted lists dir with deterministic order (sorted names).
func readDirSorted(dir string) ([]dirEntryLite, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}
	out := make([]dirEntryLite, 0, len(entries))
	for _, e := range entries {
		out = append(out, dirEntryLite{name: e.Name(), dir: e.IsDir()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// isYAMLFile reports whether name carries a yaml extension.
func isYAMLFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// policyDeclMaxBytes bounds one declaration file (DoS bound, not a feature
// limit — the admin API body cap parity).
const policyDeclMaxBytes = 128 * 1024

// readFileLimited reads path under the declaration size cap.
func readFileLimited(path string) ([]byte, error) {
	// G304: path comes from walking the operator's own --dir (a config-as-code
	// checkout), never from request data — reading it is the tool's purpose.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied declaration path (see above)
	if err != nil {
		return nil, fmt.Errorf("read declaration %s: %w", path, err)
	}
	if len(raw) > policyDeclMaxBytes {
		return nil, fmt.Errorf("declaration %s is %d bytes (cap %d)", path, len(raw), policyDeclMaxBytes)
	}
	return raw, nil
}
