// Package trcli: NEXT-08 controller CLI. Runs delegated episodes through
// the FakeExecutor ONLY — the card forbids wiring a paid agent API here.
// The live MCP Orchestrator is untouched; this CLI shares the state format
// via pkg/delegation/controller.
package trcli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // register the pgx database/sql driver (audit chain)
	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/reireirei/yabanin/pkg/delegation"
	"github.com/reireirei/yabanin/pkg/delegation/controller"
	"github.com/reireirei/yabanin/pkg/jitaccess"
)

func delegateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delegate",
		Short: "Control delegated agent episodes (NEXT-08; fake executor)",
		Long: `Drive delegated episodes through the persistent controller.

State lives in <workspace>/.yabanin/delegate/ as one JSON file per episode,
written atomically and fenced by a lease (generation) so two controller
processes cannot corrupt each other. run/resume are idempotent per step:
a crashed run leaves done steps on disk and resume replays only the tail.

This CLI uses the in-process FakeExecutor by design — the same state format
is what a future executor-backed controller will consume.`,
	}
	var workspace string
	cmd.PersistentFlags().StringVar(&workspace, "workspace", ".", "workspace root (state under .yabanin/delegate/)")

	holder := fmt.Sprintf("%s:%d", hostName(), os.Getpid())
	newController := func() (*controller.Controller, error) {
		store, err := controller.NewStore(workspace + "/.yabanin/delegate")
		if err != nil {
			return nil, err
		}
		// NEXT-12 (owner decision 2026-09-18): low-risk analyze episodes
		// (all steps passed, zero writes) may close automatically with
		// recorded provenance. TP-17 refines the criteria: auto-accept
		// requires a COMPLETE successful final result — and the hermetic
		// FakeExecutor honestly reports validation "skipped", so its
		// episodes stop at awaiting_review for an explicit review decision.
		// Implement episodes always stop at awaiting_review.
		return controller.New(store, delegation.NewFakeExecutor("codex"), holder, 30*time.Second).
			WithAutoAccept(true), nil
	}

	var implement bool
	var sourceRepo string
	run := &cobra.Command{
		Use:   "run <id> <task>",
		Short: "Start (or resume) an episode and drive it to completion",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			ctl, err := newController()
			if err != nil {
				return err
			}
			taskMode := delegation.ModeAnalyze
			if implement {
				taskMode = delegation.ModeImplement
			}
			e, err := ctl.Start(args[0], args[1], taskMode, delegation.ProviderAuto)
			if err != nil {
				return err
			}
			// NEXT-09: with --repo the episode runs in an isolated git
			// worktree (cross-process locked); the ACTUAL diff is reported
			// from git, never from executor claims.
			var ws *controller.Workspace
			if sourceRepo != "" {
				mgr, err := controller.NewWorkspaceManager(workspace + "/.yabanin/worktrees")
				if err != nil {
					return err
				}
				ws, err = mgr.Acquire(args[0], sourceRepo)
				if err != nil {
					return err
				}
				defer func() { _ = ws.Release() }()
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			var runErr error
			e, runErr = ctl.Run(ctx, e)
			printEpisode(cmd.OutOrStdout(), e)
			evErr := writeEpisodeEvidence(cmd.OutOrStdout(), ctl, e)
			if ws != nil {
				changed, stat, derr := ws.Diff()
				if derr != nil {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  diff:     unavailable (%v)\n", derr)
				} else if len(changed) == 0 {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  diff:     none (no files changed)")
				} else {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  diff:     %s\n", strings.Join(changed, ", "))
					if stat != "" {
						_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  diffstat:")
						for _, l := range strings.Split(stat, "\n") {
							_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", l)
						}
					}
				}
			}
			// TP-18: an evidence write failure is a CLI error, not a
			// printed footnote; the execution error (if any) is preserved.
			if runErr != nil && evErr != nil {
				return fmt.Errorf("%w; evidence: %w", runErr, evErr)
			}
			if evErr != nil {
				return fmt.Errorf("evidence: %w", evErr)
			}
			return runErr
		},
	}
	run.Flags().BoolVar(&implement, "implement", false, "implement mode (analyze is default)")
	run.Flags().StringVar(&sourceRepo, "repo", "", "source git repo: run the episode in an isolated worktree of it")

	status := &cobra.Command{
		Use:   "status <id>",
		Short: "Show one episode's persisted state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := controller.NewStore(workspace + "/.yabanin/delegate")
			if err != nil {
				return err
			}
			e, err := store.Load(args[0])
			if err != nil {
				return err
			}
			printEpisode(cmd.OutOrStdout(), e)
			return nil
		},
	}

	resume := &cobra.Command{
		Use:   "resume <id>",
		Short: "Take over a crashed/expired episode and finish it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctl, err := newController()
			if err != nil {
				return err
			}
			e, err := ctl.Store().Load(args[0])
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			e, runErr := ctl.Run(ctx, e)
			printEpisode(cmd.OutOrStdout(), e)
			// TP-18: keep both errors when they both happen.
			if evErr := writeEpisodeEvidence(cmd.OutOrStdout(), ctl, e); evErr != nil {
				if runErr != nil {
					return fmt.Errorf("%w; evidence: %w", runErr, evErr)
				}
				return fmt.Errorf("evidence: %w", evErr)
			}
			return runErr
		},
	}

	cancelCmd := &cobra.Command{
		Use:   "cancel <id> [reason]",
		Short: "Cancel a non-terminal episode",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctl, err := newController()
			if err != nil {
				return err
			}
			e, err := ctl.Store().Load(args[0])
			if err != nil {
				return err
			}
			reason := "operator cancel"
			if len(args) > 1 {
				reason = args[1]
			}
			e, err = ctl.Cancel(e, reason)
			printEpisode(cmd.OutOrStdout(), e)
			return err
		},
	}

	// NEXT-12: review bundle + approve/reject with actor/hash/time.
	review := &cobra.Command{
		Use:   "review <id>",
		Short: "Show the review bundle, or record approve/reject",
		Long: `Without a subcommand: render the review bundle — the episode card,
step results, the ACTUAL workspace diff (with --repo) and the NEXT-10
evidence verification status. The reviewer sees everything, not a summary.

  yb delegate review <id> --repo .                  # inspect the bundle
  yb delegate review approve <id> --actor <name> [--note ...]
  yb delegate review reject <id> --actor <name> [--note ...]

Approvals record actor, time and the state-file hash; auto-accept is
deliberately absent (a separate owner decision per NEXT-12).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctl, err := newController()
			if err != nil {
				return err
			}
			e, err := ctl.Store().Load(args[0])
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			printEpisode(w, e)
			// Evidence verification status (tamper check).
			// TP-18: a failed verification (missing binding, unreadable
			// registry, envelope/state mismatch) must also fail the command;
			// "none written yet" stays a soft display note. One exception: a
			// recorded review decision or cancel legitimately evolves the
			// state AFTER the envelope was written — that is a stale
			// envelope, not tampering, and is displayed honestly.
			regPath, rerr := resolveRegistryPath()
			if rerr != nil {
				return rerr
			}
			ev, verr := ctl.Store().VerifyEvidence(args[0], regPath)
			legitEvolved := e.Review != nil || e.CancelReason != ""
			switch {
			case verr != nil && errors.Is(verr, fs.ErrNotExist):
				_, _ = fmt.Fprintln(w, "  evidence:  none written yet")
			case verr != nil && legitEvolved:
				_, _ = fmt.Fprintln(w, "  evidence:  stale (state evolved after the envelope was written)")
			case verr != nil:
				_, _ = fmt.Fprintf(w, "  evidence:  MISMATCH (%v)\n", verr)
				return fmt.Errorf("evidence verification failed: %w", verr)
			default:
				_, _ = fmt.Fprintf(w, "  evidence:  verified (state %s…, outcome %s)\n", ev.StateSHA256[:12], ev.Outcome)
			}
			// The actual diff, when a repo is provided.
			if src, _ := cmd.Flags().GetString("repo"); src != "" {
				mgr, merr := controller.NewWorkspaceManager(workspace + "/.yabanin/worktrees")
				if merr != nil {
					return merr
				}
				ws, aerr := mgr.Acquire(args[0], src)
				if aerr != nil {
					return aerr
				}
				defer func() { _ = ws.Release() }()
				changed, stat, derr := ws.Diff()
				if derr != nil {
					_, _ = fmt.Fprintf(w, "  diff:      unavailable (%v)\n", derr)
				} else if len(changed) == 0 {
					_, _ = fmt.Fprintln(w, "  diff:      none")
				} else {
					_, _ = fmt.Fprintf(w, "  diff:      %s\n", strings.Join(changed, ", "))
					if stat != "" {
						_, _ = fmt.Fprintln(w, "  diffstat:")
						for _, l := range strings.Split(stat, "\n") {
							_, _ = fmt.Fprintf(w, "    %s\n", l)
						}
					}
				}
			}
			if e.Review != nil {
				_, _ = fmt.Fprintf(w, "  review:    %s by %s at %s (state %s…)\n",
					e.Review.Decision, e.Review.Actor, e.Review.At.Format(time.RFC3339), shortHash(e.Review.StateSHA))
			} else {
				_, _ = fmt.Fprintln(w, "  review:    not decided — use `review <id> approve|reject --actor <name>`")
			}
			return nil
		},
	}
	review.Flags().String("repo", "", "source repo to render the actual worktree diff")

	var actor, note string
	decision := func(dec string) *cobra.Command {
		d := &cobra.Command{
			Use:   dec + " <id>",
			Short: "record the " + dec + " decision",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				decision := map[string]string{"approve": "approved", "reject": "rejected"}[dec]
				ctl, err := newController()
				if err != nil {
					return err
				}
				e, err := ctl.Store().Load(args[0])
				if err != nil {
					return err
				}
				e, err = ctl.Review(e, decision, actor, note)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "review recorded: %s by %s (state %s…) → %s\n",
					e.Review.Decision, e.Review.Actor, shortHash(e.Review.StateSHA), e.State)
				return nil
			},
		}
		d.Flags().StringVar(&actor, "actor", "", "reviewer identity (required)")
		_ = d.MarkFlagRequired("actor")
		d.Flags().StringVar(&note, "note", "", "free-form decision note")
		return d
	}
	review.AddCommand(decision("approve"), decision("reject"))

	cmd.AddCommand(run, status, resume, cancelCmd, review, jitCmd())
	return cmd
}

// state machine (D7: API/DB-first; trcli is the operator surface, the
// dashboard queue is a later card).
func jitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jit",
		Short: "JIT elevation approval queue (R036; Postgres-backed operator surface)",
		Long: `Operate the just-in-time elevation state machine directly against
Postgres. State machine (R036 D2): pending -> approved | denied; an aged
pending request (24h) and an expired approval (1h TTL) flip to the terminal
expired status via the planned sweep (jit expire).

Every decision is bound to the immutable request digest printed at request
time: quote it verbatim (--digest) or the decision fails closed (R036 D3).
Only active root operators other than the requester may decide (R036 D1),
and every decision writes an APPROVE/DENY audit row with the actor, IP and
request digest (R036 D5).`,
	}
	cmd.AddCommand(jitRequestCmd(), jitShowCmd(), jitApproveCmd(), jitDenyCmd(), jitListCmd(), jitExpireCmd())
	return cmd
}

// jitStores bundles the two driver faces of the same Postgres database:
// pgxpool for the jitaccess state machine, database/sql for the
// tamper-evident audit chain (the same bridge pkg/auditlog tests use).
type jitStores struct {
	mgr   *jitaccess.Manager
	audit *auditlog.Writer
	pool  *pgxpool.Pool
}

// openJITStores connects both faces and returns a cleanup func.
func openJITStores(ctx context.Context, pgURI string) (*jitStores, func(), error) {
	pool, err := pgxpool.New(ctx, pgURI)
	if err != nil {
		return nil, nil, fmt.Errorf("connect postgres: %w", err)
	}
	sqlDB, err := sql.Open("pgx", pgURI)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("open audit connection: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		_ = sqlDB.Close()
		pool.Close()
		return nil, nil, fmt.Errorf("ping postgres: %w", err)
	}
	st := &jitStores{
		mgr:   jitaccess.NewManager(pool),
		audit: auditlog.NewWriter(sqlDB),
		pool:  pool,
	}
	return st, func() { _ = sqlDB.Close(); pool.Close() }, nil
}

func jitRequestCmd() *cobra.Command {
	var pgURI, admin, role, reason string
	cmd := &cobra.Command{
		Use:   "request --admin <id> --role <role>",
		Short: "Create a pending elevation request (auto-expires in 24h)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, closeStores, err := openJITStores(ctx, pgURI)
			if err != nil {
				return err
			}
			defer closeStores()
			return runJITRequest(ctx, cmd.OutOrStdout(), st, admin, role, reason)
		},
	}
	cmd.Flags().StringVar(&pgURI, "pg-uri", "", "Postgres URI (required)")
	cmd.Flags().StringVar(&admin, "admin", "", "requesting admin id (uuid, required)")
	cmd.Flags().StringVar(&role, "role", "", "requested role (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "why the elevation is needed")
	_ = cmd.MarkFlagRequired("pg-uri")
	_ = cmd.MarkFlagRequired("admin")
	_ = cmd.MarkFlagRequired("role")
	return cmd
}

func jitShowCmd() *cobra.Command {
	var pgURI string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one request with the digest a decision must quote",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, closeStores, err := openJITStores(ctx, pgURI)
			if err != nil {
				return err
			}
			defer closeStores()
			return runJITShow(ctx, cmd.OutOrStdout(), st, args[0])
		},
	}
	cmd.Flags().StringVar(&pgURI, "pg-uri", "", "Postgres URI (required)")
	_ = cmd.MarkFlagRequired("pg-uri")
	return cmd
}

func jitApproveCmd() *cobra.Command {
	var o jitDecisionOpts
	cmd := &cobra.Command{
		Use:   "approve <id> --approver <id> --digest <sha256>",
		Short: "Approve a pending request (root, different human, bound digest)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.decision = "approve"
			o.requestID = args[0]
			return o.run(cmd)
		},
	}
	o.bindFlags(cmd)
	return cmd
}

func jitDenyCmd() *cobra.Command {
	var o jitDecisionOpts
	cmd := &cobra.Command{
		Use:   "deny <id> --approver <id> --digest <sha256> [--reason ...]",
		Short: "Deny a pending request (root, different human, bound digest)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.decision = "deny"
			o.requestID = args[0]
			return o.run(cmd)
		},
	}
	o.bindFlags(cmd)
	return cmd
}

// jitDecisionOpts carries the shared decision flags. digest is the request
type jitDecisionOpts struct {
	decision  string
	requestID string
	approver  string
	digest    string
	reason    string
	adminName string
	ip        string
	pgURI     string
}

func (o *jitDecisionOpts) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.pgURI, "pg-uri", "", "Postgres URI (required)")
	cmd.Flags().StringVar(&o.approver, "approver", "", "deciding admin id (uuid, required)")
	cmd.Flags().StringVar(&o.digest, "digest", "", "request digest quoted from jit request/show (required)")
	cmd.Flags().StringVar(&o.reason, "reason", "", "decision note")
	cmd.Flags().StringVar(&o.adminName, "admin-name", "", "display name for the audit row")
	cmd.Flags().StringVar(&o.ip, "ip", "", "operator source IP for the audit row")
	_ = cmd.MarkFlagRequired("pg-uri")
	_ = cmd.MarkFlagRequired("approver")
	_ = cmd.MarkFlagRequired("digest")
}

func (o *jitDecisionOpts) run(cmd *cobra.Command) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, closeStores, err := openJITStores(ctx, o.pgURI)
	if err != nil {
		return err
	}
	defer closeStores()
	return runJITDecision(ctx, cmd.OutOrStdout(), st, *o)
}

func jitListCmd() *cobra.Command {
	var pgURI string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the pending approval queue (oldest first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, closeStores, err := openJITStores(ctx, pgURI)
			if err != nil {
				return err
			}
			defer closeStores()
			return runJITList(ctx, cmd.OutOrStdout(), st)
		},
	}
	cmd.Flags().StringVar(&pgURI, "pg-uri", "", "Postgres URI (required)")
	_ = cmd.MarkFlagRequired("pg-uri")
	return cmd
}

func jitExpireCmd() *cobra.Command {
	var pgURI string
	cmd := &cobra.Command{
		Use:   "expire",
		Short: "Run the sweep: aged pending and expired approvals become terminal expired",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, closeStores, err := openJITStores(ctx, pgURI)
			if err != nil {
				return err
			}
			defer closeStores()
			return runJITExpire(ctx, cmd.OutOrStdout(), st)
		},
	}
	cmd.Flags().StringVar(&pgURI, "pg-uri", "", "Postgres URI (required)")
	_ = cmd.MarkFlagRequired("pg-uri")
	return cmd
}

func printJITRecord(w io.Writer, r *jitaccess.JITRecord) {
	_, _ = fmt.Fprintf(w, "request %s\n  admin:  %s\n  role:   %s\n  reason: %s\n",
		r.ID, r.AdminID, r.Role, r.Reason)
	if r.ApproverID != nil {
		_, _ = fmt.Fprintf(w, "  decided by %s at %s\n", *r.ApproverID, r.ExpiresAt.Format(time.RFC3339))
	}
	_, _ = fmt.Fprintf(w, "  status: %s (expires_at %s, created %s)\n  digest: %s\n",
		r.Status, r.ExpiresAt.Format(time.RFC3339), r.CreatedAt.Format(time.RFC3339), r.Binds.ParamsDigest)
}

func runJITRequest(ctx context.Context, w io.Writer, st *jitStores, admin, role, reason string) error {
	rec, err := st.mgr.Request(ctx, admin, role, reason)
	if err != nil {
		return err
	}
	printJITRecord(w, rec)
	_, _ = fmt.Fprintln(w, "  quote the digest verbatim (--digest) to approve or deny")
	return nil
}

func runJITShow(ctx context.Context, w io.Writer, st *jitStores, requestID string) error {
	rec, err := st.mgr.Get(ctx, requestID)
	if err != nil {
		return err
	}
	printJITRecord(w, rec)
	return nil
}

// runJITDecision is the pure decision flow behind jit approve|deny: load the
// request, verify the quoted digest, apply the state transition and record
// the APPROVE/DENY audit row (actor, IP, digest). A rejected attempt also
// writes a DENY row — nothing fails silently.
func runJITDecision(ctx context.Context, w io.Writer, st *jitStores, o jitDecisionOpts) error {
	rec, err := st.mgr.Get(ctx, o.requestID)
	if err != nil {
		return err
	}
	quoted := strings.TrimSpace(o.digest)
	if rec.Binds.ParamsDigest != quoted {
		// negative scenario. The stored digest is journaled, not the
		// operator's quoted value.
		if derr := st.audit.AppendEntry(ctx, auditlog.DenyEntry(
			o.approver, o.adminName, o.ip, rec.ID, rec.Binds.ParamsDigest, "digest mismatch")); derr != nil {
			return fmt.Errorf("%w: quoted %s, want %s; audit: %w",
				jitaccess.ErrDigestMismatch, shortHash(quoted), shortHash(rec.Binds.ParamsDigest), derr)
		}
		return fmt.Errorf("%w: quoted %s, want %s",
			jitaccess.ErrDigestMismatch, shortHash(quoted), shortHash(rec.Binds.ParamsDigest))
	}

	after, err := decideJIT(ctx, st, o, rec.Binds)
	if err != nil {
		// The decision was refused by the state machine (self-approval,
		// non-root, replay, concurrent flip): record the refusal and fail.
		if derr := st.audit.AppendEntry(ctx, auditlog.DenyEntry(
			o.approver, o.adminName, o.ip, rec.ID, rec.Binds.ParamsDigest, jitDenyReason(err))); derr != nil {
			return errors.Join(err, derr)
		}
		return err
	}

	entry := auditlog.ApprovalEntry(o.approver, o.adminName, o.ip, after.ID, after.Binds.ParamsDigest)
	if o.decision == "deny" {
		entry = auditlog.DenyEntry(o.approver, o.adminName, o.ip, after.ID, after.Binds.ParamsDigest, o.reason)
	}
	if aerr := st.audit.AppendEntry(ctx, entry); aerr != nil {
		// The transition is already terminal: never hide the audit gap.
		return fmt.Errorf("%s applied to %s but the audit write failed: %w", o.decision, after.ID, aerr)
	}

	verb := "approved"
	if o.decision == "deny" {
		verb = "denied"
	}
	_, _ = fmt.Fprintf(w, "%s: %s\n  approver: %s\n  digest:   %s\n  audit:    %s written\n",
		verb, after.ID, o.approver, after.Binds.ParamsDigest, strings.ToUpper(o.decision))
	if o.decision == "approve" {
		_, _ = fmt.Fprintf(w, "  active:   until %s (1h TTL)\n", after.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func decideJIT(ctx context.Context, st *jitStores, o jitDecisionOpts, binds jitaccess.ApprovalBinds) (*jitaccess.JITRecord, error) {
	if o.decision == "deny" {
		return st.mgr.Deny(ctx, o.requestID, o.approver, binds)
	}
	return st.mgr.Approve(ctx, o.requestID, o.approver, binds)
}

// jitDenyReason maps a refused decision to a stable audit reason string.
func jitDenyReason(err error) string {
	switch {
	case errors.Is(err, jitaccess.ErrSelfApproval):
		return "self-approval blocked"
	case errors.Is(err, jitaccess.ErrApproverNotRoot):
		return "approver not root"
	case errors.Is(err, jitaccess.ErrNotPending):
		return "request not pending"
	case errors.Is(err, jitaccess.ErrDigestMismatch):
		return "digest mismatch"
	default:
		return "decision rejected"
	}
}

func runJITList(ctx context.Context, w io.Writer, st *jitStores) error {
	queue, err := st.mgr.PendingRequests(ctx)
	if err != nil {
		return err
	}
	if len(queue) == 0 {
		_, _ = fmt.Fprintln(w, "pending queue: empty")
		return nil
	}
	_, _ = fmt.Fprintf(w, "pending queue: %d\n", len(queue))
	for i := range queue {
		r := &queue[i]
		_, _ = fmt.Fprintf(w, "  %s  admin=%s role=%s created=%s digest=%s\n",
			r.ID, r.AdminID, r.Role, r.CreatedAt.Format(time.RFC3339), r.Binds.ParamsDigest)
	}
	return nil
}

func runJITExpire(ctx context.Context, w io.Writer, st *jitStores) error {
	flipped, err := st.mgr.ExpirePast(ctx)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "sweep: %d request(s) flipped to expired\n", flipped)
	return nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// writeEpisodeEvidence persists the NEXT-10 v2 envelope when the episode
// reached a terminal/review state (tamper-evidence for the NEXT-12 review).
// TP-18: the registry path resolves via the same repo-root resolver as
// review (works from any CWD), and a write failure is returned so the CLI
// exits non-zero instead of printing a footnote.
func writeEpisodeEvidence(w io.Writer, ctl *controller.Controller, e *controller.Episode) error {
	if !e.State.Terminal() && e.State != controller.StateAwaiting {
		return nil
	}
	regPath, err := resolveRegistryPath()
	if err != nil {
		_, _ = fmt.Fprintf(w, "  evidence:  unavailable (%v)\n", err)
		return err
	}
	if _, err := ctl.Store().WriteEvidence(e, regPath); err != nil {
		_, _ = fmt.Fprintf(w, "  evidence:  unavailable (%v)\n", err)
		return err
	}
	_, _ = fmt.Fprintln(w, "  evidence:  written (state + command-registry hashes)")
	return nil
}

func hostName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	return h
}

func printEpisode(w io.Writer, e *controller.Episode) {
	_, _ = fmt.Fprintf(w, "episode %s\n  state:    %s\n  mode:     %s\n  task:     %.60s\n", e.ID, e.State, e.Mode, e.Task)
	for _, s := range e.Steps {
		mark := "…"
		switch s.Status {
		case "done":
			mark = "✓"
		case "failed":
			mark = "✗"
		}
		_, _ = fmt.Fprintf(w, "  %s step %d %-10s %s\n", mark, s.Index, s.Name, noteForResult(s.Result))
	}
	if e.CancelReason != "" {
		_, _ = fmt.Fprintf(w, "  cancel:   %s\n", e.CancelReason)
	}
}

func noteForResult(r *delegation.Result) string {
	if r == nil {
		return ""
	}
	if r.Error != "" {
		return r.Error
	}
	return r.Status
}
