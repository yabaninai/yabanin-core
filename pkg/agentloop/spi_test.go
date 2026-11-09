package agentloop

import (
	"context"
	"errors"
	"testing"
)

// stubExecutor is the documented stub used to pin ExecutorSPI's exact
// method set at compile time: if the interface signature ever drifts from
// the contract (docs/api/AGENT-LOOP-SPI.md §3 row 1), the var assignment
// in TestExecutorSPIExistsAndSatisfiesContract stops compiling. Behavior
// mirrors the seam's fail-closed posture: a cancelled ctx is honored as a
// failed step carrying the ctx error, never as a fabricated success.
type stubExecutor struct{}

func (stubExecutor) ExecuteStep(ctx context.Context, op Operation, req StepRequest) (StepResult, error) {
	if err := ctx.Err(); err != nil {
		return StepResult{StepIndex: req.StepIndex, Outcome: StepFailed}, err
	}
	return StepResult{StepIndex: req.StepIndex, Outcome: StepCompleted}, nil
}

// TestExecutorSPIExistsAndSatisfiesContract is the compile-level pin for
// review finding F1: ExecutorSPI must exist in the package with exactly
// the documented signature
// ExecuteStep(ctx, Operation, StepRequest) (StepResult, error) — the
// interface cannot be implemented by anything else without breaking this
// test's build.
func TestExecutorSPIExistsAndSatisfiesContract(t *testing.T) {
	// Compile-level pin: signature drift breaks the build right here.
	var _ ExecutorSPI = stubExecutor{}

	executor := stubExecutor{}
	got, err := executor.ExecuteStep(context.Background(), Operation{ID: "op"}, StepRequest{StepIndex: 2})
	if err != nil {
		t.Fatalf("ExecuteStep returned unexpected error: %v", err)
	}
	if got.StepIndex != 2 || got.Outcome != StepCompleted {
		t.Errorf("ExecuteStep = (%+v, %v), want StepIndex 2, outcome completed", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = executor.ExecuteStep(ctx, Operation{ID: "op"}, StepRequest{StepIndex: 3})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ctx: ExecuteStep error = %v, want context.Canceled", err)
	}
	if got.Outcome != StepFailed {
		t.Errorf("cancelled ctx: outcome = %q, want failed (never a fabricated success)", got.Outcome)
	}
}
