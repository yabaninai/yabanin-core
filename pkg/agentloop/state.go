package agentloop

import (
	"fmt"
)

// OperationState is the durable lifecycle state of one loop operation. The
// legal transitions below are the ONE piece of loop logic core owns: every
// implementation — the Enterprise engine, BYO executors, tests, tooling —
// shares these semantics through CanTransition/Apply instead of re-encoding
// them.
//
// Legal transition table (v1, explicit and closed):
//
//	created          → running
//	running          → awaiting_approval | cancelled | expired | failed | completed
//	awaiting_approval → running           | cancelled | expired
//	cancelled        → (terminal)
//	expired          → (terminal)
//	failed           → (terminal)
//	completed        → (terminal)
//
// Notes the table encodes deliberately:
//
//   - There is NO "approved" OperationState. A human approval is a decision
//     (ApprovalDecision) and an ApprovalState, never an operation state: an
//     approved step resumes by awaiting_approval → running, where the
//     mandatory rights/credentials/policy recheck happens. No transition
//     jumps from awaiting_approval straight to completed or failed — that
//     would be a self-approval/recheck bypass expressed as a state shortcut.
//   - Expired is reachable from running (active wall-time / operation TTL)
//     and from awaiting_approval (approval TTL, I59), and is terminal: a
//     late approval cannot revive an expired operation; a new operation is
//     required.
//   - cancelled is reachable from running and from awaiting_approval
//     (explicit cancel or rejected approval) and is terminal.
//   - Terminal states have no outgoing transitions — completed in
//     particular cannot be re-entered, extended or "reopened".
type OperationState string

const (
	// StateCreated is the persisted initial state; the operation exists but
	// has not started executing.
	StateCreated OperationState = "created"
	// StateRunning is active execution of bounded steps.
	StateRunning OperationState = "running"
	// StateAwaitingApproval is parked on a durable human decision (I56).
	// Client disconnect does not cancel it (I58); its TTL is the approval
	// TTL (I59).
	StateAwaitingApproval OperationState = "awaiting_approval"
	// StateCancelled is terminal: explicit cancel or a rejected approval.
	StateCancelled OperationState = "cancelled"
	// StateExpired is terminal: operation TTL exceeded or approval TTL
	// passed (I59).
	StateExpired OperationState = "expired"
	// StateFailed is terminal: a known failure ended the operation.
	StateFailed OperationState = "failed"
	// StateCompleted is terminal: the loop finished and the result is
	// available regardless of client connectivity (I58).
	StateCompleted OperationState = "completed"
)

// transitionTable is the v1 legal-transition data. Declaration order is
// meaningful: LegalTransitions and AllStates surface it in this order.
// The table is read-only package data — no locking is required, and
// accessors return copies so callers cannot mutate shared semantics.
var transitionTable = map[OperationState][]OperationState{
	StateCreated: {
		StateRunning,
	},
	StateRunning: {
		StateAwaitingApproval,
		StateCancelled,
		StateExpired,
		StateFailed,
		StateCompleted,
	},
	StateAwaitingApproval: {
		// approved → running: resume into RUNNING, where the mandatory
		// recheck (rights, credentials, policy) runs before any further
		// step (I56–I58). No direct awaiting_approval → completed/failed
		// edge exists — approval must not shortcut the machine.
		StateRunning,
		// rejected → cancelled.
		StateCancelled,
		// approval TTL passed → expired (I59); terminal, non-revivable.
		StateExpired,
	},
	StateCancelled: {},
	StateExpired:   {},
	StateFailed:    {},
	StateCompleted: {},
}

// allStates lists every v1 state in declaration order (table order for the
// row keys). Enum values are append-only in v1.x and never renumbered or
// reused.
var allStates = []OperationState{
	StateCreated,
	StateRunning,
	StateAwaitingApproval,
	StateCancelled,
	StateExpired,
	StateFailed,
	StateCompleted,
}

// AllStates returns every v1 OperationState value in declaration order. The
// returned slice is a copy.
func AllStates() []OperationState {
	out := make([]OperationState, len(allStates))
	copy(out, allStates)
	return out
}

// IsValidState reports whether s is a defined v1 state.
func IsValidState(s OperationState) bool {
	_, ok := transitionTable[s]
	return ok
}

// IsTerminal reports whether s is a terminal state (no outgoing
// transitions). Unknown states are not terminal — they are invalid.
func IsTerminal(s OperationState) bool {
	return len(transitionTable[s]) == 0 && IsValidState(s)
}

// CanTransition reports whether the from→to state change is legal under the
// shared v1 table. Unknown states never transition.
func CanTransition(from, to OperationState) bool {
	for _, legal := range transitionTable[from] {
		if legal == to {
			return true
		}
	}
	return false
}

// LegalTransitions returns the legal target states from from, in table
// (declaration) order. The returned slice is a copy; unknown states yield
// nil.
func LegalTransitions(from OperationState) []OperationState {
	targets := transitionTable[from]
	if targets == nil {
		return nil
	}
	out := make([]OperationState, len(targets))
	copy(out, targets)
	return out
}

// Apply validates the from→to transition against the shared table and
// returns to when legal. Invariant: an illegal transition never yields a new
// state — the returned state is from and the error wraps
// ErrIllegalTransition, so a caller that ignores the error still cannot
// advance past a terminal state or bypass awaiting_approval.
func Apply(from, to OperationState) (OperationState, error) {
	if !CanTransition(from, to) {
		return from, fmt.Errorf("%w: %s → %s", ErrIllegalTransition, from, to)
	}
	return to, nil
}
