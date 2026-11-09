package batchstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// LineRunner executes one batch request body for the owning org and returns
// the HTTP-ish result. The gateway wires the real one through its chat
// pipeline so batch lines bill through the same admission/reservation/
// settlement path as interactive traffic (ratified D4).
type LineRunner func(ctx context.Context, b *Batch, ln Line) LineResult

// LineResult is one executed line's outcome: Status is the HTTP status the
// pipeline produced (0 with Err set for runner-level failures), Body the
// response payload.
type LineResult struct {
	Status int
	Body   []byte
	Err    error
}

// Executor defaults (single worker; conservative first release).
const (
	DefaultLease          = 10 * time.Minute
	DefaultMaxAttempts    = 5
	DefaultPollInterval   = 5 * time.Second
	DefaultRetentionEvery = time.Hour
	// DefaultOrphanGrace is how long an unreferenced purpose=batch upload
	// is kept before the executor's orphan sweep reclaims it (conservative
	// default; referenced uploads keep the D3 30-day window).
	DefaultOrphanGrace = 24 * time.Hour
)

// Executor drains batch_jobs: claim/lease lifecycle, per-line execution with
// crash resume (durable batch_lines statuses + deterministic request ids),
// result-file assembly, the retention sweep and the orphan-upload sweep.
type Executor struct {
	store          *Store
	run            LineRunner
	log            *slog.Logger
	lease          time.Duration
	maxAttempts    int
	pollInterval   time.Duration
	retentionEvery time.Duration
	orphanGrace    time.Duration
	lastRetention  time.Time
}

// NewExecutor builds the worker. A nil runner makes every line fail fast —
// wiring must always provide the gateway pipeline runner.
func NewExecutor(store *Store, run LineRunner, l *slog.Logger) *Executor {
	if l == nil {
		l = slog.Default()
	}
	return &Executor{
		store:          store,
		run:            run,
		log:            l,
		lease:          DefaultLease,
		maxAttempts:    DefaultMaxAttempts,
		pollInterval:   DefaultPollInterval,
		retentionEvery: DefaultRetentionEvery,
		orphanGrace:    DefaultOrphanGrace,
	}
}

// WithOrphanSweep overrides the orphan-upload grace and returns the executor
// (chainable wiring knob). A grace <= 0 disables the orphan sweep entirely —
// the exact pre-orphan-sweep behavior.
func (e *Executor) WithOrphanSweep(grace time.Duration) *Executor {
	e.orphanGrace = grace
	return e
}

// Start runs the poll loop until ctx ends.
func (e *Executor) Start(ctx context.Context) {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
				e.log.Warn("batch executor tick failed", "error", err.Error())
			}
		}
	}
}

// Tick runs one pass: crash recovery, retention + orphan sweeps
// (cadence-gated), then drain claimable batches one at a time.
func (e *Executor) Tick(ctx context.Context) error {
	if err := e.store.RecoverExpiredLeases(ctx, e.maxAttempts); err != nil {
		return err
	}
	if now := time.Now(); now.Sub(e.lastRetention) >= e.retentionEvery {
		if err := e.store.RetentionSweep(ctx); err != nil {
			e.log.Warn("batch retention sweep failed", "error", err.Error())
		}
		if e.orphanGrace > 0 {
			if n, err := e.store.SweepOrphanUploads(ctx, e.orphanGrace); err != nil {
				e.log.Warn("batch orphan upload sweep failed", "error", err.Error())
			} else if n > 0 {
				e.log.Info("batch orphan uploads reclaimed", "count", n, "grace", e.orphanGrace.String())
			}
		}
		e.lastRetention = now
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		b, err := e.store.ClaimBatch(ctx, e.lease, e.maxAttempts)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := e.process(ctx, b); err != nil {
			if !errors.Is(err, context.Canceled) {
				e.log.Error("batch processing failed", "batch_id", b.ID, "error", err.Error())
				if ferr := e.store.MarkBatchFailed(ctx, b.ID, b.Attempts, err.Error()); ferr != nil {
					e.log.Warn("mark batch failed did not apply", "batch_id", b.ID, "error", ferr.Error())
				}
			}
			// Shutdown mid-batch: release so another worker resumes fast.
			if errors.Is(err, context.Canceled) {
				if rerr := e.store.ReleaseLease(context.WithoutCancel(ctx), b.ID, b.Attempts); rerr != nil {
					e.log.Warn("release batch lease failed", "batch_id", b.ID, "error", rerr.Error())
				}
			}
			return err
		}
	}
}

// process executes every pending line of the claimed batch, then finalizes.
// b.Attempts is this worker's lease fencing token: every terminal store write
// is conditioned on it, so a worker whose lease died mid-batch cannot
// finalize, fail or release a batch another claim already owns — the new
// owner's generation wins and the re-executed lines dedupe on their
// conditional per-line updates.
func (e *Executor) process(ctx context.Context, b *Batch) error {
	lines, err := e.store.PendingLines(ctx, b.ID)
	if err != nil {
		return err
	}
	cancelled := false
	for _, ln := range lines {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Ownership re-check between lines, against the current row:
		//   cancelling           — org cancel arrived; finalize the executed
		//                          prefix as cancelled.
		//   cancelled/expired    — recovery already terminalized the batch
		//                          (dead lease + cancel request or retention
		//                          window); nothing left to finalize, and a
		//                          competing finalize would fight recovery.
		//   validating, or the
		//   claim token moved on — our lease died and the batch was re-queued
		//                          or re-claimed; stop competing, the current
		//                          owner finalizes (line writes so far stay
		//                          deduped by their conditional updates).
		// A still-owned batch with an expired but not-yet-recovered lease
		// keeps executing; its finalize then fails on the live-lease check
		// and recovery re-queues the remainder — bounded, logged waste, no
		// duplicate settlement.
		cur, err := e.store.getBatchInternal(ctx, b.ID)
		if err != nil {
			return err
		}
		switch {
		case cur.Status == StatusCancelling:
			cancelled = true
		case cur.Status == StatusCancelled, cur.Status == StatusExpired,
			cur.Status == StatusValidating, cur.Attempts != b.Attempts:
			return nil
		}
		if cancelled {
			break
		}
		res := e.runLine(ctx, b, ln)
		status := LineDone
		var errMsg []byte
		if res.Err != nil || res.Status >= 400 {
			status = LineFailed
			msg := fmt.Sprintf("request failed with status %d", res.Status)
			if res.Err != nil {
				msg = res.Err.Error()
			}
			errMsg = []byte(msg)
		}
		if err := e.store.CompleteLine(ctx, b.ID, ln.LineNo, status, res.Status, res.Body, errMsg); err != nil {
			return err
		}
	}
	output, errOut, err := e.assembleResults(ctx, b.ID)
	if err != nil {
		return err
	}
	_, err = e.store.FinalizeBatch(ctx, b.ID, b.Attempts, cancelled, output, errOut)
	return err
}

// runLine shields the runner: a panicking or broken runner fails the line,
// never the worker.
func (e *Executor) runLine(ctx context.Context, b *Batch, ln Line) (res LineResult) {
	defer func() {
		if r := recover(); r != nil {
			res = LineResult{Status: 500, Err: fmt.Errorf("line runner panicked: %v", r)}
		}
	}()
	if e.run == nil {
		return LineResult{Status: 500, Err: errors.New("no line runner wired")}
	}
	return e.run(ctx, b, ln)
}

// assembleResults builds the OpenAI-shaped JSONL outputs: successful lines
// to the output file, failed lines to the error file.
func (e *Executor) assembleResults(ctx context.Context, batchID string) (output, errLines []byte, err error) {
	lines, err := e.store.AllLines(ctx, batchID)
	if err != nil {
		return nil, nil, err
	}
	for _, ln := range lines {
		if ln.Status == LinePending {
			continue
		}
		if ln.Status == LineDone {
			entry := map[string]any{
				"id":        ln.RequestID,
				"custom_id": ln.CustomID,
				"response": map[string]any{
					"status_code": ln.ResponseCode,
					"request_id":  ln.RequestID,
					"body":        json.RawMessage(ln.ResponseBody),
				},
				"error": nil,
			}
			raw, merr := json.Marshal(entry)
			if merr != nil {
				return nil, nil, fmt.Errorf("marshal output line %d: %w", ln.LineNo, merr)
			}
			output = append(output, raw...)
			output = append(output, '\n')
			continue
		}
		entry := map[string]any{
			"id":        ln.RequestID,
			"custom_id": ln.CustomID,
			"response":  nil,
			"error":     map[string]any{"message": ln.Error},
		}
		raw, merr := json.Marshal(entry)
		if merr != nil {
			return nil, nil, fmt.Errorf("marshal error line %d: %w", ln.LineNo, merr)
		}
		errLines = append(errLines, raw...)
		errLines = append(errLines, '\n')
	}
	return output, errLines, nil
}
