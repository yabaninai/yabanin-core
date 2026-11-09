package historyops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Runner executes the operation-specific work for one job. Runners are
// registered per operation by the wiring layer (preview/plan in this package;
// concrete destructive runners in the follow-up lane cards — archive/retention
// 05/06, purge 07, redact 08).
//
// Contract (managed-job semantics, backlog AC-02):
//
//   - VerifySnapshot runs before planning: it re-checks the operation inside
//     one consistent snapshot (e.g. REPEATABLE READ) and MUST return a
//     Refusal (digest_mismatch, protected_family, …) when the world drifted
//     from what the digest committed to. Fail-closed: a refusal before the
//     first batch touches zero rows.
//   - Plan returns the ordered id-precise batches. It must derive everything
//     from its own snapshot — the plan is captured into the checkpoint BEFORE
//     the first batch, so a restart resumes the captured plan and never
//     re-plans against drifted data.
//   - ExecuteBatch applies exactly one captured batch and MUST be idempotent
//     per (job, batch index, ids): the engine executes a batch at least once
//     (crash between execution and checkpoint), so idempotent application is
//     what upgrades at-least-once execution into exactly-once effect. The
//     engine renews the lease at every checkpoint (checkpoint = progress =
//     renewal), so LeaseTTL bounds the duration of ONE batch, not the whole
//     job; a batch that can outlive LeaseTTL must additionally stay safe
//     under CONCURRENT invocation, or LeaseTTL must be sized to bound it.
//
// A returned Refusal stops the job fail-closed with that refusal; other
// errors are treated as transient (retry with backoff until MaxAttempts).
type Runner interface {
	VerifySnapshot(ctx context.Context, job *Job) error
	Plan(ctx context.Context, job *Job) ([][]string, error)
	ExecuteBatch(ctx context.Context, job *Job, batchIndex int, ids []string) (FamilyCounts, error)
}

// BatchGuard is re-consulted immediately before EVERY batch (02-PREVIEW-
// OPERATION-DESIGN §5.4): a payload grant revoked between enqueue and batch N
// must stop the job before that batch (active_grant), not after. Implementations
// return a Refusal to refuse fail-closed — zero rows of the batch are touched.
type BatchGuard interface {
	BatchAllowed(ctx context.Context, job *Job, ids []string) error
}

// PlanReporter is an optional Runner extension for archive operations: right
// after planning, the runner may record protected rows (requests skipped
// because a payload grant is still live) into the captured checkpoint, so a
// restart-resumed job keeps the same report and an operator can always see
// WHY selected requests were left alone. Identifiers only — never payload
// content. A reporting failure is a runner failure (fail-closed: the
// checkpoint with the report is saved before the first batch).
type PlanReporter interface {
	PlanReport(ctx context.Context, job *Job, cp *Checkpoint) error
}

// EngineConfig tunes the engine. Zero values fall back to the defaults of
// DefaultEngineConfig.
type EngineConfig struct {
	// LeaseTTL is how long a claim holds before another worker may recover
	// the job from its checkpoint. Default 30s.
	LeaseTTL time.Duration
	// MaxAttempts caps transient retries before a job fails terminally.
	// Refusals never retry regardless of this setting. Default 5.
	MaxAttempts int
	// Interval is the Run loop tick. Default 1s.
	Interval time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Stamp produces the schema stamp for enqueue digests. Nil = the zero
	// stamp with this package's FamiliesSchemaVersion.
	Stamp func(ctx context.Context) (SchemaStamp, error)
	// Logger receives non-fatal journal degradation notices. Nil = slog.Default.
	Logger *slog.Logger
}

// DefaultEngineConfig returns the engine defaults.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		LeaseTTL:    30 * time.Second,
		MaxAttempts: 5,
		Interval:    time.Second,
	}
}

func (c EngineConfig) withDefaults() EngineConfig {
	def := DefaultEngineConfig()
	if c.LeaseTTL <= 0 {
		c.LeaseTTL = def.LeaseTTL
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = def.MaxAttempts
	}
	if c.Interval <= 0 {
		c.Interval = def.Interval
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Stamp == nil {
		c.Stamp = func(context.Context) (SchemaStamp, error) {
			return SchemaStamp{FamiliesSchemaVersion: FamiliesSchemaVersion}, nil
		}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// EnqueueRequest is one job submission. Caller applies to interactive
// (user-actor) enqueues; service actors skip caller authorization because the
// policy that authorized them was checked at configuration time and the job
// journalls actor + policy version (03-RIGHTS-MODEL §6).
type EnqueueRequest struct {
	OrgID string
	Op    Operation
	// Selection must be the validated selection from a prior preview; its
	// digest is recomputed here and must match PresentedDigest.
	Selection       Selection
	PresentedDigest string
	// Destination is required for archive operations; other operations
	// ignore it.
	Destination string
	// IdempotencyKey makes the submission replayable: a repeated key returns
	// the existing job instead of creating a second cleanup.
	IdempotencyKey string
	// Confirmation is the purge token: the literal digest echo of a fresh
	// preview (ENT-HIST-07 AC-1). Purge enqueues go through enqueuePurge,
	// which verifies it against a freshly recomputed digest and forces the
	// single-use idempotency key (the digest itself); other operations
	// ignore it.
	Confirmation string
	Actor        JobActor
	Caller       Caller
}

// Engine is the managed-job executor. One engine serves many orgs; every
// lookup and mutation is org-scoped.
type Engine struct {
	store   JobStore
	journal Journaler
	runners map[Operation]Runner
	guard   BatchGuard
	cfg     EngineConfig
}

// NewEngine builds an engine over a job store and a journaler (journaling is
// mandatory per the rights model — pass MemoryJournaler in tests).
func NewEngine(store JobStore, journal Journaler, cfg EngineConfig) *Engine {
	return &Engine{
		store:   store,
		journal: journal,
		runners: make(map[Operation]Runner),
		cfg:     cfg.withDefaults(),
	}
}

// RegisterRunner wires the operation-specific runner.
func (e *Engine) RegisterRunner(op Operation, r Runner) { e.runners[op] = r }

// SetBatchGuard wires the per-batch authorization guard (revoked-grant
// re-check). Nil disables guarding (tests only).
func (e *Engine) SetBatchGuard(g BatchGuard) { e.guard = g }

// Enqueue validates, digests and records a job. The flow is refusal-first:
// every refusal happens BEFORE the job row is created, so a refused enqueue
// leaves no partial state (03-RIGHTS-MODEL §5). A repeated idempotency key
// returns the existing job unchanged — the idempotent replay.
func (e *Engine) Enqueue(ctx context.Context, req EnqueueRequest) (*Job, error) {
	actor, err := validatedActor(req.Actor, req.Caller)
	if err != nil {
		return nil, err
	}
	if !ValidOperation(req.Op) {
		return nil, fmt.Errorf("%w: unknown operation %q", ErrInvalidRequest, req.Op)
	}
	// Rights gate: interactive actors need the caller; service actors were
	// authorized by the policy version they must carry.
	if actor.Type == ActorUser {
		if err := AuthorizeEnqueue(req.Op, req.Caller); err != nil {
			e.journalDenial(ctx, req, actor, err)
			return nil, err
		}
	}
	// Idempotent replay: same (org, key) → same job, never a second cleanup.
	// The replay precedes per-request validation so a repeated submit returns
	// the stored job even when transient fields (destination, digest echo)
	// differ from the original — replaying the key replays the original
	// decision.
	existing, err := e.store.JobByIdempotencyKey(ctx, req.OrgID, req.IdempotencyKey)
	if err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// Purge has its own enqueue flow: confirmation-token gate plus the
	// digest-bound single-use idempotency key (ENT-HIST-07 AC-1).
	if req.Op == OpPurge {
		return e.enqueuePurge(ctx, req, actor)
	}
	if err := req.Selection.Validate(e.cfg.Now()); err != nil {
		return nil, err
	}
	if err := e.validateDestination(req); err != nil {
		e.journalDenial(ctx, req, actor, err)
		return nil, err
	}
	stamp, err := e.cfg.Stamp(ctx)
	if err != nil {
		return nil, fmt.Errorf("historyops: schema stamp: %w", err)
	}
	expected, err := SelectionDigest(req.Op, req.Selection, stamp)
	if err != nil {
		return nil, err
	}
	if req.PresentedDigest != expected {
		err := Refuse(RefusalDigestMismatch,
			"presented digest does not match a fresh preview; run the preview again")
		e.journalDenial(ctx, req, actor, err)
		return nil, err
	}
	job := &Job{
		OrgID:           req.OrgID,
		Op:              req.Op,
		Selection:       req.Selection,
		SelectionDigest: expected,
		Stamp:           stamp,
		Destination:     req.Destination,
		IdempotencyKey:  req.IdempotencyKey,
		Confirmed:       FamilyCounts{},
		Actor:           actor.Normalized(),
	}
	if err := e.store.CreateJob(ctx, job); err != nil {
		if errors.Is(err, ErrDuplicateJob) {
			// Lost a create race against an identical submission — the
			// idempotent answer is the stored job.
			return e.store.JobByIdempotencyKey(ctx, req.OrgID, req.IdempotencyKey)
		}
		return nil, err
	}
	e.journalEntry(ctx, Entry{
		Action: JournalAction(req.Op, ActionStarted),
		OrgID:  job.OrgID,
		JobID:  job.ID,
		Op:     job.Op,
		Actor:  job.Actor,
		Details: detailf(
			"digest", job.SelectionDigest,
			"families", strings.Join(familyNames(job.Selection.Families), ","),
			"actor_type", string(job.Actor.Type),
			"policy_version", job.Actor.PolicyVersion,
		),
	})
	return job, nil
}

// validatedActor validates the actor fields. Service actors bypass caller
// authorization by design; everything else needs a validated human caller.
func validatedActor(actor JobActor, caller Caller) (JobActor, error) {
	if err := actor.Validate(); err != nil {
		return JobActor{}, err
	}
	actor = actor.Normalized()
	if actor.Type == ActorUser && actor.Author == "" {
		actor.Author = caller.UserID
	}
	if actor.Author == "" {
		return JobActor{}, fmt.Errorf("%w: actor author is required", ErrInvalidRequest)
	}
	return actor, nil
}

// validateDestination enforces the archive destination rules. The rules
// themselves live in validateArchiveDestination (archive.go) — the single
// source of truth shared with the runners, which re-validate at run time:
// a job never touches a namespace enqueue would have refused.
func (e *Engine) validateDestination(req EnqueueRequest) error {
	if !req.Op.needsDestination() {
		return nil
	}
	return validateArchiveDestination(req.Op, req.OrgID, req.Destination)
}

// Status returns the org-scoped job view. Forged or foreign ids are
// ErrNotFound — indistinguishable from unknown, zero leakage.
func (e *Engine) Status(ctx context.Context, orgID, jobID string) (*Job, error) {
	return e.store.JobByID(ctx, orgID, jobID)
}

// RequestCancel records a cancel request (org-admin). The job stops BEFORE
// its next batch; already-applied rows stay applied and the terminal state
// carries confirmed counts only (02-PREVIEW-OPERATION-DESIGN §6).
func (e *Engine) RequestCancel(ctx context.Context, caller Caller, orgID, jobID string) error {
	if err := AuthorizeCancel(caller); err != nil {
		return err
	}
	return e.store.RequestCancel(ctx, orgID, jobID, e.cfg.Now())
}

// ExecuteNext claims and processes at most one job. Returns whether a job
// was claimed (false = queue empty). Errors from runners are handled inside
// (refusals finalize the job; transient errors release it for retry) — the
// returned error only reflects engine/store wiring failures.
func (e *Engine) ExecuteNext(ctx context.Context, workerID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	job, err := e.store.ClaimNext(ctx, workerID, e.cfg.LeaseTTL)
	if err != nil {
		if errors.Is(err, ErrQueueEmpty) {
			return false, nil
		}
		return false, fmt.Errorf("historyops: claim job: %w", err)
	}
	e.execute(ctx, job)
	return true, nil
}

// Run claims and processes jobs until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, workerID string) error {
	ticker := time.NewTicker(e.cfg.Interval)
	defer ticker.Stop()
	for {
		if _, err := e.ExecuteNext(ctx, workerID); err != nil {
			return err
		}
		if _, err := e.store.RecoverExpiredLeases(ctx); err != nil {
			return fmt.Errorf("historyops: recover leases: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// execute drives one claimed job through its lifecycle. Every terminal exit
// path journals exactly one terminal entry per verb.
func (e *Engine) execute(ctx context.Context, job *Job) {
	runner := e.runners[job.Op]
	if runner == nil {
		// Wiring bug — poison the job instead of silently looping forever.
		e.finalizeFailed(ctx, job, nil, "no runner registered for operation "+string(job.Op))
		return
	}
	cp := job.Checkpoint
	if !cp.Planned {
		// Snapshot verification BEFORE planning: drift between preview and
		// replay refuses fail-closed (digest gate, 04-ACCEPTANCE §2).
		if err := runner.VerifySnapshot(ctx, job); err != nil {
			e.handleRunnerError(ctx, job, err, "verify snapshot")
			return
		}
		plan, err := runner.Plan(ctx, job)
		if err != nil {
			e.handleRunnerError(ctx, job, err, "plan")
			return
		}
		cp = Checkpoint{Planned: true, Plan: plan}
		// Protected-row reporting rides the captured checkpoint (see
		// PlanReporter): it lands in the same SaveCheckpoint that persists
		// the plan, including on the empty-plan no-op path below.
		if reporter, ok := runner.(PlanReporter); ok {
			if err := reporter.PlanReport(ctx, job, &cp); err != nil {
				e.handleRunnerError(ctx, job, err, "plan report")
				return
			}
		}
		if len(plan) == 0 {
			// Empty selection: a valid no-op completion — rows zero. Persist
			// the (empty) captured plan first so the planned flag survives.
			if err := e.store.SaveCheckpoint(ctx, job.ID, job.WorkerID, e.cfg.LeaseTTL, cp, job.Confirmed); err != nil {
				e.handleStoreError(ctx, job, err, "save checkpoint")
				return
			}
			e.finalizeCompleted(ctx, job, cp)
			return
		}
		if err := e.store.SaveCheckpoint(ctx, job.ID, job.WorkerID, e.cfg.LeaseTTL, cp, job.Confirmed); err != nil {
			e.handleStoreError(ctx, job, err, "save checkpoint")
			return
		}
	}
	for i := cp.NextBatch; i < len(cp.Plan); i++ {
		// Reload for cancel + lease identity: the cancel check must happen
		// before every batch so a cancel request always stops the NEXT batch,
		// never mid-batch.
		fresh, err := e.store.JobByID(ctx, job.OrgID, job.ID)
		if err != nil {
			e.handleStoreError(ctx, job, err, "reload job")
			return
		}
		// Lease fence at the effect boundary: the reload must confirm this
		// worker still owns the job with a live lease before any batch runs.
		// Without it, a worker whose lease expired and was taken over (another
		// worker's claim after recovery) would re-execute the batch the new
		// owner is executing, and its failure paths below would finalize or
		// release using the NEW owner's worker id — store transitions guarded
		// by hold() would then succeed against the new owner's lease. A stale
		// worker stops without any store mutation; the new owner drives the
		// job from its own claim.
		if !leaseHeld(job, fresh, e.cfg.Now()) {
			e.cfg.Logger.Info("historyops: lease lost before batch, stopping",
				"job", job.ID, "worker", job.WorkerID, "batch", i)
			return
		}
		// Fence passed: adopt the reloaded job so every subsequent store
		// transition and error path carries the verified claimant identity.
		// If the lease is lost between here and a transition, the store's
		// hold() guard refuses it with ErrLeaseLost — never the new owner.
		job = fresh
		if !job.CancelRequested.IsZero() {
			e.finalizeCanceled(ctx, job, cp)
			return
		}
		if e.guard != nil {
			if err := e.guard.BatchAllowed(ctx, job, cp.Plan[i]); err != nil {
				e.handleRunnerError(ctx, job, err, "batch guard")
				return
			}
		}
		counts, err := runner.ExecuteBatch(ctx, job, i, cp.Plan[i])
		if err != nil {
			e.handleRunnerError(ctx, job, err, fmt.Sprintf("batch %d", i))
			return
		}
		cp.NextBatch = i + 1
		confirmed := job.Confirmed.Clone()
		confirmed.Add(counts)
		if err := e.store.SaveCheckpoint(ctx, job.ID, job.WorkerID, e.cfg.LeaseTTL, cp, confirmed); err != nil {
			e.handleStoreError(ctx, job, err, "save checkpoint")
			return
		}
		e.journalEntry(ctx, Entry{
			Action: JournalAction(job.Op, ActionBatch),
			OrgID:  job.OrgID,
			JobID:  job.ID,
			Op:     job.Op,
			Actor:  job.Actor,
			Details: detailf(
				"batch", int64(i),
				"digest", job.SelectionDigest,
				"rows", confirmed.Total(),
				"rows_by_family", familyCountsDetail(confirmed),
			),
		})
	}
	e.finalizeCompleted(ctx, job, cp)
}

// leaseHeld reports whether the reloaded job still belongs to the claiming
// worker with a live lease — the engine-side effect-boundary fence that
// complements the store's hold() CAS on every guarded transition (worker id
// AND status AND lease liveness, not a single preliminary time check). A
// false result means another worker owns the job and the caller must stop
// without effecting, checkpointing, releasing or finalizing it.
func leaseHeld(claimant, fresh *Job, now time.Time) bool {
	return fresh.Status == JobProcessing &&
		fresh.WorkerID == claimant.WorkerID &&
		fresh.LeaseUntil.After(now)
}

// handleRunnerError classifies a runner failure: refusals finalize the job
// fail-closed (no retry); other errors release the job for retry until
// MaxAttempts is exhausted.
func (e *Engine) handleRunnerError(ctx context.Context, job *Job, err error, stage string) {
	if refusal, ok := RefusalOf(err); ok {
		e.finalizeFailed(ctx, job, refusal, refusal.Error())
		e.journalDenialEntry(ctx, job, refusal)
		return
	}
	e.retryOrFail(ctx, job, fmt.Errorf("%s: %w", stage, err))
}

func (e *Engine) handleStoreError(ctx context.Context, job *Job, err error, stage string) {
	e.cfg.Logger.Error("historyops: store failure", "job", job.ID, "stage", stage, "err", err)
	e.retryOrFail(ctx, job, fmt.Errorf("%s: %w", stage, err))
}

// retryOrFail releases a transiently failed job for another attempt, or
// fails it terminally once attempts are exhausted.
func (e *Engine) retryOrFail(ctx context.Context, job *Job, err error) {
	if job.Attempts >= e.cfg.MaxAttempts {
		e.finalizeFailed(ctx, job, nil, err.Error())
		return
	}
	next := e.cfg.Now().Add(e.cfg.Interval)
	if rerr := e.store.ReleaseForRetry(ctx, job.ID, job.WorkerID, next, err.Error()); rerr != nil {
		e.cfg.Logger.Error("historyops: release for retry failed", "job", job.ID, "err", rerr)
		e.finalizeFailed(ctx, job, nil, err.Error())
	}
}

// finalizeCompleted marks the job completed and journals the terminal entry
// with the final confirmed counts (re-read so the checkpoint state, not a
// stale local copy, is what the terminal state reports).
func (e *Engine) finalizeCompleted(ctx context.Context, job *Job, cp Checkpoint) {
	fresh, err := e.store.JobByID(ctx, job.OrgID, job.ID)
	if err != nil {
		e.cfg.Logger.Error("historyops: reload before completion failed", "job", job.ID, "err", err)
		fresh = job
	}
	confirmed := fresh.Confirmed.Clone()
	if err := e.store.Finalize(ctx, job.ID, job.WorkerID, JobCompleted, confirmed, nil, ""); err != nil {
		e.cfg.Logger.Error("historyops: finalize completed failed", "job", job.ID, "err", err)
		return
	}
	e.journalEntry(ctx, Entry{
		Action: JournalAction(job.Op, ActionCompleted),
		OrgID:  job.OrgID,
		JobID:  job.ID,
		Op:     job.Op,
		Actor:  job.Actor,
		Details: detailf(
			"digest", job.SelectionDigest,
			"rows", confirmed.Total(),
			"batches", int64(cp.NextBatch),
			"rows_by_family", familyCountsDetail(confirmed),
		),
	})
}

func (e *Engine) finalizeCanceled(ctx context.Context, job *Job, cp Checkpoint) {
	confirmed := job.Confirmed.Clone()
	if err := e.store.Finalize(ctx, job.ID, job.WorkerID, JobCanceled, confirmed, nil, "canceled by org-admin"); err != nil {
		e.cfg.Logger.Error("historyops: finalize canceled failed", "job", job.ID, "err", err)
		return
	}
	e.journalEntry(ctx, Entry{
		Action: JournalAction(job.Op, ActionCanceled),
		OrgID:  job.OrgID,
		JobID:  job.ID,
		Op:     job.Op,
		Actor:  job.Actor,
		Details: detailf(
			"digest", job.SelectionDigest,
			"rows", confirmed.Total(),
			"batches", int64(cp.NextBatch),
		),
	})
}

func (e *Engine) finalizeFailed(ctx context.Context, job *Job, refusal *Refusal, lastErr string) {
	if err := e.store.Finalize(ctx, job.ID, job.WorkerID, JobFailed, job.Confirmed.Clone(), refusal, lastErr); err != nil {
		e.cfg.Logger.Error("historyops: finalize failed failed", "job", job.ID, "err", err)
	}
}

// journalDenial journals an enqueue refusal against the submitted scope (the
// job does not exist yet — org and op only).
func (e *Engine) journalDenial(ctx context.Context, req EnqueueRequest, actor JobActor, err error) {
	code := ""
	if refusal, ok := RefusalOf(err); ok {
		code = string(refusal.Code)
	}
	e.journalEntry(ctx, Entry{
		Action: JournalAction(req.Op, ActionDenied),
		OrgID:  req.OrgID,
		JobID:  "",
		Op:     req.Op,
		Actor:  actor.Normalized(),
		Details: detailf(
			"refusal", code,
			"stage", "enqueue",
		),
	})
}

// journalDenialEntry journals a mid-run refusal (batch guard, snapshot
// verification) against the existing job.
func (e *Engine) journalDenialEntry(ctx context.Context, job *Job, refusal *Refusal) {
	e.journalEntry(ctx, Entry{
		Action: JournalAction(job.Op, ActionDenied),
		OrgID:  job.OrgID,
		JobID:  job.ID,
		Op:     job.Op,
		Actor:  job.Actor,
		Details: detailf(
			"refusal", string(refusal.Code),
			"stage", "run",
			"batches", int64(job.Checkpoint.NextBatch),
		),
	})
}

// journal swallows journal failures by design: a degraded audit path must
// never turn a refusal into an allow or abort a sanctioned operation — the
// adminstore-backed adapter degrades durably (outbox), so reaching this
// point means the adapter itself failed. The failure is logged loudly.
func (e *Engine) journalEntry(ctx context.Context, entry Entry) {
	if e.journal == nil {
		return
	}
	if err := e.journal.Journal(ctx, entry); err != nil {
		e.cfg.Logger.Error("historyops: journal degraded", "action", entry.Action, "job", entry.JobID, "err", err)
	}
}

func familyNames(families []Family) []string {
	out := make([]string, len(families))
	for i, f := range families {
		out[i] = string(f)
	}
	return out
}

// familyCountsDetail flattens counts into scalar pairs (journal details stay
// JSON-marshalled flat maps).
func familyCountsDetail(counts FamilyCounts) map[string]int64 {
	out := make(map[string]int64, len(counts))
	for _, name := range counts.Names() {
		out[name] = counts[Family(name)]
	}
	return out
}
