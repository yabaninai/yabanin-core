package lua

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// Budget verdicts surfaced through the VM's context-abort path; the VM raises
// them as ordinary Lua errors ("when:1: <Err().Error()>"), unrolled through
// the pcall barriers exactly like the previous deadline aborts.
var (
	errStepBudget  = errors.New("instruction budget exceeded")
	errWallCeiling = errors.New("wall-clock budget exceeded")
)

// budgetContext enforces the deterministic step budget and the wall-clock
// ceiling for one evaluation. gopher-lua's context-enabled main loop calls
// ctx.Done() exactly once per VM instruction dispatch (mainLoopWithContext)
// and never caches the channel, so counting Done() calls yields an
// instruction budget enforced by the VM itself — the same abort point as the
// old deadline, but independent of machine speed, GC pauses and runner load.
//
// Concurrency: Done/steps run on the VM goroutine only; finish may also be
// called from the ceiling timer. Coroutines are not part of the sandbox and
// would derive contexts via context.WithCancel, which would skew the count.
type budgetContext struct {
	parent     context.Context
	parentDone <-chan struct{}
	done       chan struct{}
	steps      atomic.Int64 // remaining dispatches; negative = unlimited
	tripped    atomic.Bool
	errValue   atomic.Pointer[error]
	ceiling    *time.Timer
}

// newBudgetContext returns the same object twice, like context.WithTimeout
// returns (ctx, cancel): the context.Context form is what the VM (and
// context-analyzer tooling) sees as derived from parent; the concrete
// handle carries Err/stop for the caller's epilogue.
func newBudgetContext(parent context.Context, maxSteps int64, ceiling time.Duration) (context.Context, *budgetContext) {
	b := &budgetContext{
		parent:     parent,
		parentDone: parent.Done(), // stable for standard contexts; nil never fires
		done:       make(chan struct{}),
	}
	if maxSteps > 0 {
		b.steps.Store(maxSteps)
	} else {
		b.steps.Store(-1)
	}
	if ceiling > 0 {
		b.ceiling = time.AfterFunc(ceiling, func() { b.finish(errWallCeiling) })
	}
	return b, b
}

// Done counts one VM instruction dispatch. Caller cancellation is checked
// first so the reported cause stays the caller when both race.
func (b *budgetContext) Done() <-chan struct{} {
	select {
	case <-b.parentDone:
		b.finish(b.parent.Err())
	default:
	}
	if b.steps.Load() >= 0 && b.steps.Add(-1) < 0 {
		b.finish(errStepBudget)
	}
	return b.done
}

func (b *budgetContext) Err() error {
	if err := b.errValue.Load(); err != nil {
		return *err
	}
	return nil
}

func (b *budgetContext) Deadline() (time.Time, bool) { return b.parent.Deadline() }

func (b *budgetContext) Value(key any) any { return b.parent.Value(key) }

// stop releases the ceiling timer after the evaluation returns.
func (b *budgetContext) stop() {
	if b.ceiling != nil {
		b.ceiling.Stop()
	}
}

// finish records the first verdict and closes done exactly once. The error
// store happens before close so the VM's post-close Err().Error() is safe.
func (b *budgetContext) finish(err error) {
	if b.tripped.CompareAndSwap(false, true) {
		b.errValue.Store(&err)
		close(b.done)
	}
}
