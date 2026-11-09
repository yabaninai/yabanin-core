package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/delegation"
)

// Steps per mode. The controller executes them in order; every completed
// step is persisted, so a resume replays ONLY the unfinished tail.
func stepsForMode(m delegation.Mode) []string {
	if m == delegation.ModeImplement {
		return []string{"plan", "implement", "validate"}
	}
	return []string{"analyze"}
}

// Controller drives episodes over an Executor (FakeExecutor in tests).
// It composes with pkg/delegation — the Orchestrator is untouched.
type Controller struct {
	store      *Store
	exec       delegation.Executor
	holder     string
	leaseTTL   time.Duration
	now        func() time.Time
	autoAccept AutoAcceptPolicy
}

// New binds a store and an executor. holder identifies this process in the
// lease (host:pid at the CLI layer).
func New(store *Store, exec delegation.Executor, holder string, leaseTTL time.Duration) *Controller {
	if leaseTTL <= 0 {
		leaseTTL = 30 * time.Second
	}
	return &Controller{store: store, exec: exec, holder: holder, leaseTTL: leaseTTL, now: time.Now}
}

// WithAutoAccept enables or disables the low-risk auto-accept policy.
func (c *Controller) WithAutoAccept(enabled bool) *Controller {
	c.autoAccept = AutoAcceptPolicy{Enabled: enabled}
	return c
}

// Store exposes the underlying store (CLI resume/cancel load episodes
// through it without re-deriving paths).
func (c *Controller) Store() *Store { return c.store }

// Start creates a pending episode (idempotent: an existing episode with the
// same id is returned unchanged — never silently reset).
func (c *Controller) Start(id, task string, mode delegation.Mode, provider delegation.ProviderName) (*Episode, error) {
	if existing, err := c.store.Load(id); err == nil {
		return existing, nil
	} else if !_notExist(err) {
		return nil, fmt.Errorf("load episode %s: %w", id, err)
	}
	if mode == "" {
		mode = delegation.ModeAnalyze
	}
	if provider == "" {
		provider = delegation.ProviderAuto
	}
	names := stepsForMode(mode)
	steps := make([]StepRecord, len(names))
	for i, n := range names {
		steps[i] = StepRecord{Index: i, Name: n, Status: "pending"}
	}
	e := &Episode{
		SchemaVersion: stateSchemaVersion,
		ID:            id,
		Task:          task,
		Mode:          mode,
		Provider:      provider,
		State:         StatePending,
		Steps:         steps,
		CurrentStep:   0,
		Generation:    0,
		CreatedAt:     c.now(),
		UpdatedAt:     c.now(),
	}
	if err := c.store.SaveFenced(e, ""); err != nil {
		return nil, fmt.Errorf("create episode: %w", err)
	}
	return e, nil
}

// Run drives the episode to a terminal or review state. It is safe to call
// again after a crash (resume semantics): finished steps are skipped, the
// lease is renewed while work is in flight, and a foreign live lease is an
// error rather than a fight.
//
// TP-16 lifecycle contract: when Run returns, the renewal worker has exited
// (Stop alone does not close the ticker channel) and the executor context is
// canceled — losing the lease fences this controller out and stops the
// in-flight executor instead of letting it run to completion orphaned.
//
// The fencing sentinel Run surfaces is not pinned: a takeover that lands a
// strictly newer generation rejects the next renewal with ErrFenced, while
// a stale write (a takeover that lags a stall and drags the generation
// backward, or a raw write that bypassed the store) leaves the on-disk
// generation at or below the worker's and rejects with ErrLeaseHeld
// (foreign live lease). Both mean the same thing — lease loss — so callers
// must match errors.Is against either sentinel, never exactly one.
func (c *Controller) Run(ctx context.Context, e *Episode) (*Episode, error) {
	if e == nil {
		return nil, fmt.Errorf("episode is required")
	}
	if e.State.Terminal() {
		return e, nil
	}
	// Idempotent re-entry (TP-17): an episode that finished all steps and
	// already sits in awaiting_review has nothing to run. Replaying it is a
	// no-op, not a transition error — resume must be safe on every state.
	if e.State == StateAwaiting && e.NextPendingStep() < 0 {
		return e, nil
	}
	if err := c.store.AcquireLease(e, c.holder, c.leaseTTL); err != nil {
		return e, fmt.Errorf("acquire lease: %w", err)
	}
	var episodeMu sync.Mutex
	defer func() {
		episodeMu.Lock()
		defer episodeMu.Unlock()
		_ = c.store.ReleaseLease(e)
	}()

	// The executor runs under a context this controller owns: any Run exit
	// path — including lease loss reported by the renewal worker — cancels
	// the in-flight executor rather than leaving it on the caller's context.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	if e.State == StatePending {
		episodeMu.Lock()
		err := e.Transition(StateRunning)
		if err == nil {
			err = c.store.SaveFenced(e, c.holder)
		}
		episodeMu.Unlock()
		if err != nil {
			return e, err
		}
	}

	renew := time.NewTicker(c.leaseTTL / 2)
	renewErr := make(chan error, 1)
	stopRenew := make(chan struct{})
	workerDone := make(chan struct{})
	go func() {
		// TP-16: the worker must terminate with Run. Waiting on workerDone
		// below guarantees no renewal goroutine outlives the episode run.
		defer close(workerDone)
		for {
			select {
			case <-stopRenew:
				return
			case <-renew.C:
				episodeMu.Lock()
				err := c.store.RenewLease(e, c.leaseTTL)
				episodeMu.Unlock()
				if err != nil {
					// Lease lost: stop the executor first (Run may be
					// blocked inside it and cannot reach the select below),
					// then surface the renewal failure.
					cancelRun()
					renewErr <- err
					return
				}
			}
		}
	}()
	defer func() {
		close(stopRenew)
		renew.Stop()
		<-workerDone
	}()

	for {
		select {
		case err := <-renewErr:
			return e, fmt.Errorf("lease renewal failed: %w", err)
		case <-ctx.Done():
			// Leave the episode in running with done steps persisted; the
			// lease expires and a later resume takes over (fenced).
			return e, ctx.Err()
		default:
		}

		episodeMu.Lock()
		i := e.NextPendingStep()
		if i < 0 {
			episodeMu.Unlock()
			break
		}
		step := &e.Steps[i]
		step.Status = "pending"
		step.StartedAt = c.now()
		err := c.store.SaveFenced(e, c.holder)
		episodeMu.Unlock()
		if err != nil {
			return e, err
		}

		res, runErr := c.exec.Run(runCtx, delegation.Request{
			Task:     fmt.Sprintf("%s\n\n[controller step %d/%d: %s]", e.Task, i+1, len(e.Steps), step.Name),
			Mode:     e.Mode,
			Provider: e.Provider,
			Timeout:  0,
		})
		// TP-17: a nil Go error is transport success only. A step is done
		// exclusively on an explicit ok result status; empty, unknown or
		// error statuses fail the step honestly instead of sliding through.
		if runErr == nil && res.Status != "ok" {
			runErr = fmt.Errorf("executor returned result status %q", res.Status)
		}
		episodeMu.Lock()
		step.FinishedAt = c.now()
		if runErr != nil {
			step.Status = "failed"
			step.Error = runErr.Error()
			resCopy := res
			step.Result = &resCopy
		} else {
			step.Status = "done"
			resCopy := res
			step.Result = &resCopy
		}
		e.CurrentStep = i + 1
		err = c.store.SaveFenced(e, c.holder)
		if err == nil && runErr != nil {
			if terr := e.Transition(StateFailed); terr != nil {
				err = terr
			} else {
				e.FinalResult = step.Result
				err = c.store.SaveFenced(e, c.holder)
			}
		}
		episodeMu.Unlock()
		if err != nil {
			return e, err
		}
		if runErr != nil {
			return e, fmt.Errorf("step %q failed: %w", step.Name, runErr)
		}
	}

	episodeMu.Lock()
	target := StateDone
	// Both modes land in awaiting_review; auto-accept may then close
	// low-risk analyze episodes without human review (NEXT-12).
	if e.Mode == delegation.ModeImplement || e.Mode == delegation.ModeAnalyze {
		target = StateAwaiting
	}
	err := e.Transition(target)
	// TP-17: a legacy/corrupt step record without a result must not panic;
	// a nil FinalResult simply keeps the episode out of auto-accept.
	if err == nil && len(e.Steps) > 0 {
		if last := e.Steps[len(e.Steps)-1].Result; last != nil {
			fr := *last
			e.FinalResult = &fr
		}
	}
	if err == nil {
		err = c.store.SaveFenced(e, c.holder)
	}
	auto := err == nil && c.autoAccept.ShouldAutoAccept(e)
	episodeMu.Unlock()
	if err != nil {
		return e, err
	}
	if auto {
		episodeMu.Lock()
		defer episodeMu.Unlock()
		return c.Review(e, "approved", "auto-accept:low-risk", "analyze-mode, no writes, all steps passed")
	}
	return e, nil
}

// Cancel moves a non-terminal episode to canceled. Canceling a terminal
// episode is an explicit error, not a silent no-op.
func (c *Controller) Cancel(e *Episode, reason string) (*Episode, error) {
	if err := e.Transition(StateCanceled); err != nil {
		return e, err
	}
	e.CancelReason = reason
	err := c.store.SaveFenced(e, "")
	return e, err
}

// Approve closes an awaiting_review episode (kept for compatibility; Review
// records provenance per NEXT-12).
func (c *Controller) Approve(e *Episode) (*Episode, error) {
	return c.Review(e, "approved", "approver", "")
}

// Review records an approve/reject decision with actor/time/state-hash and
// performs the transition (NEXT-12). Only valid from awaiting_review; no
// anonymous approvals; a rejected episode lands in canceled with the
// reviewer recorded. The decision pins the state-file hash — if the state
// changes after the reviewer inspected it, the recorded hash no longer
// matches and the provenance exposes the mismatch.
func (c *Controller) Review(e *Episode, decision, actor, note string) (*Episode, error) {
	if decision != "approved" && decision != "rejected" {
		return e, fmt.Errorf("decision must be approved or rejected")
	}
	if actor == "" {
		return e, fmt.Errorf("reviewer actor is required (no anonymous approvals)")
	}
	if e.State != StateAwaiting {
		return e, fmt.Errorf("%w: review requires %s, episode is %s", ErrTransition, StateAwaiting, e.State)
	}
	if decision == "rejected" {
		if err := e.Transition(StateCanceled); err != nil {
			return e, err
		}
		if e.CancelReason == "" {
			e.CancelReason = "rejected by " + actor
		}
	} else if err := e.Transition(StateDone); err != nil {
		return e, err
	}
	stateSHA := ""
	if raw, rerr := os.ReadFile(c.store.path(e.ID)); rerr == nil {
		sum := sha256.Sum256(raw)
		stateSHA = fmt.Sprintf("%x", sum)
	}
	e.Review = &ReviewRecord{
		Decision: decision,
		Actor:    actor,
		At:       c.now().UTC(),
		StateSHA: stateSHA,
		Note:     note,
	}
	if err := c.store.SaveFenced(e, ""); err != nil {
		return e, err
	}
	return e, nil
}

func _notExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// AutoAcceptPolicy defines when an awaiting_review episode may be
// auto-accepted without human review (NEXT-12 owner decision 2026-09-18).
// The policy is conservative by design: only analyze-mode episodes with
// all steps passing and zero workspace changes qualify.
type AutoAcceptPolicy struct {
	// Enabled turns on auto-accept globally. Default false.
	Enabled bool
}

// ShouldAutoAccept returns true when the episode meets the low-risk
// criteria: analyze mode (read-only by construction), awaiting review, a
// COMPLETE successful final result (explicit ok status, no skipped
// validation, no writes) and every step done. TP-17: nil episodes/results,
// empty/unknown/error statuses and skipped validation must never become a
// false acceptance — an episode that did not fully succeed stays in
// awaiting_review for an explicit decision.
func (p AutoAcceptPolicy) ShouldAutoAccept(e *Episode) bool {
	if !p.Enabled {
		return false
	}
	if e == nil {
		return false
	}
	if e.Mode != delegation.ModeAnalyze {
		return false
	}
	if e.State != StateAwaiting {
		return false
	}
	if e.FinalResult == nil {
		return false
	}
	if e.FinalResult.Status != "ok" {
		return false
	}
	if e.FinalResult.Wrote || len(e.FinalResult.ChangedFiles) > 0 {
		return false
	}
	// "skipped" is the honest marker of fake/simulated execution: it must
	// survive verbatim and must not self-certify as a fully successful run.
	if e.FinalResult.Validation == "skipped" {
		return false
	}
	for _, s := range e.Steps {
		if s.Status != "done" {
			return false
		}
	}
	return true
}
