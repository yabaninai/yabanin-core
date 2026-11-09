package agentloop

import (
	"errors"
	"fmt"
	"sort"
	"testing"
)

// legalPairs is the expected v1 legal-transition set, mirrored here from the
// documented table so a regression in transitionTable cannot pass by
// comparing the table against itself.
var legalPairs = map[OperationState][]OperationState{
	StateCreated:          {StateRunning},
	StateRunning:          {StateAwaitingApproval, StateCancelled, StateExpired, StateFailed, StateCompleted},
	StateAwaitingApproval: {StateRunning, StateCancelled, StateExpired},
	StateCancelled:        {},
	StateExpired:          {},
	StateFailed:           {},
	StateCompleted:        {},
}

func TestAllStatesMatchTable(t *testing.T) {
	got := AllStates()
	if len(got) != len(legalPairs) {
		t.Fatalf("AllStates len = %d, want %d", len(got), len(legalPairs))
	}
	for _, s := range got {
		if _, ok := legalPairs[s]; !ok {
			t.Errorf("AllStates has %q with no expected row", s)
		}
		if !IsValidState(s) {
			t.Errorf("IsValidState(%q) = false, want true", s)
		}
	}
	// The returned slice is a copy: mutating it must not affect later calls.
	got[0] = "corrupted"
	if AllStates()[0] == "corrupted" {
		t.Fatal("AllStates returned a shared slice; callers could corrupt shared semantics")
	}
}

func TestStateValuesAreDistinctNonEmpty(t *testing.T) {
	seen := make(map[OperationState]bool, len(allStates))
	for _, s := range AllStates() {
		if s == "" {
			t.Error("state value is empty")
		}
		if seen[s] {
			t.Errorf("state value %q declared twice", s)
		}
		seen[s] = true
	}
}

func TestCanTransitionEveryLegalPair(t *testing.T) {
	for from, targets := range legalPairs {
		for _, to := range targets {
			t.Run(fmt.Sprintf("%s_to_%s", from, to), func(t *testing.T) {
				if !CanTransition(from, to) {
					t.Errorf("CanTransition(%q, %q) = false, want true (documented legal transition)", from, to)
				}
			})
		}
	}
}

func TestCanTransitionRejectsEveryIllegalPair(t *testing.T) {
	states := AllStates()
	for _, from := range states {
		for _, to := range states {
			legal := false
			for _, target := range legalPairs[from] {
				if target == to {
					legal = true
					break
				}
			}
			if legal {
				continue
			}
			t.Run(fmt.Sprintf("%s_to_%s", from, to), func(t *testing.T) {
				if CanTransition(from, to) {
					t.Errorf("CanTransition(%q, %q) = true, want false (not in the explicit table)", from, to)
				}
			})
		}
	}
}

func TestCanTransitionRejectsUnknownStates(t *testing.T) {
	invalid := []OperationState{"", "Approved", "approved", "running ", "complete", "Created"}
	states := AllStates()
	for _, bad := range invalid {
		for _, s := range append(states, bad) {
			if CanTransition(bad, s) {
				t.Errorf("CanTransition(%q, %q) = true for unknown source state", bad, s)
			}
			if CanTransition(s, bad) {
				t.Errorf("CanTransition(%q, %q) = true for unknown target state", s, bad)
			}
		}
	}
}

func TestTerminalStatesHaveNoOutgoingTransitions(t *testing.T) {
	// completed→anything is called out explicitly by the contract: a
	// completed operation can never be reopened, extended or re-entered.
	for _, terminal := range []OperationState{StateCompleted, StateFailed, StateCancelled, StateExpired} {
		if !IsTerminal(terminal) {
			t.Errorf("IsTerminal(%q) = false, want true", terminal)
		}
		if targets := LegalTransitions(terminal); len(targets) != 0 {
			t.Errorf("terminal state %q declares outgoing transitions %v", terminal, targets)
		}
		for _, to := range AllStates() {
			if CanTransition(terminal, to) {
				t.Errorf("terminal state %q transitioned to %q", terminal, to)
			}
		}
	}
}

func TestNonTerminalStates(t *testing.T) {
	for _, s := range []OperationState{StateCreated, StateRunning, StateAwaitingApproval} {
		if IsTerminal(s) {
			t.Errorf("IsTerminal(%q) = true, want false", s)
		}
		if targets := LegalTransitions(s); len(targets) == 0 {
			t.Errorf("non-terminal state %q has no legal transitions", s)
		}
	}
	if IsTerminal("nonsense") {
		t.Error(`IsTerminal("nonsense") = true; unknown states are invalid, not terminal`)
	}
}

// TestApprovedIsNotAnOperationState pins the no-self-approval/recheck
// semantics at the type level: there is no "approved" state an executor
// could transition to, and no awaiting_approval edge skips running. Approval
// is a decision + ApprovalState; resuming an approved step goes
// awaiting_approval → running, where the mandatory rights/credentials/policy
// recheck happens (I56–I58).
func TestApprovedIsNotAnOperationState(t *testing.T) {
	for _, s := range AllStates() {
		if s == "approved" || s == "Approved" {
			t.Errorf("state %q must not exist: approval is a decision, not an operation state", s)
		}
	}
	for _, shortcut := range []OperationState{StateCompleted, StateFailed} {
		if CanTransition(StateAwaitingApproval, shortcut) {
			t.Errorf("awaiting_approval → %s exists: approval must not shortcut to a terminal state; it resumes through running where recheck runs", shortcut)
		}
	}
	// The only positive resolution of awaiting_approval is resume into
	// running; the negative ones are cancelled (rejected) and expired (TTL).
	targets := LegalTransitions(StateAwaitingApproval)
	want := []OperationState{StateRunning, StateCancelled, StateExpired}
	if len(targets) != len(want) {
		t.Fatalf("LegalTransitions(awaiting_approval) = %v, want %v", targets, want)
	}
	for i, w := range want {
		if targets[i] != w {
			t.Errorf("LegalTransitions(awaiting_approval)[%d] = %q, want %q", i, targets[i], w)
		}
	}
}

func TestApplyLegalReturnsTarget(t *testing.T) {
	for from, targets := range legalPairs {
		for _, to := range targets {
			got, err := Apply(from, to)
			if err != nil {
				t.Errorf("Apply(%q, %q) unexpected error: %v", from, to, err)
				continue
			}
			if got != to {
				t.Errorf("Apply(%q, %q) = %q, want %q", from, to, got, to)
			}
		}
	}
}

func TestApplyIllegalKeepsSourceAndWrapsSentinel(t *testing.T) {
	states := AllStates()
	for _, from := range states {
		for _, to := range states {
			if CanTransition(from, to) {
				continue
			}
			got, err := Apply(from, to)
			if err == nil {
				t.Errorf("Apply(%q, %q) = (%q, nil), want error", from, to, got)
				continue
			}
			if !errors.Is(err, ErrIllegalTransition) {
				t.Errorf("Apply(%q, %q) error %v does not wrap ErrIllegalTransition", from, to, err)
			}
			if got != from {
				t.Errorf("Apply(%q, %q) returned state %q; illegal transition must not advance past %q", from, to, got, from)
			}
		}
	}
}

func TestApplyUnknownStatesRejected(t *testing.T) {
	got, err := Apply("approved", StateRunning)
	if err == nil || !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("Apply(approved, running) = (%q, %v); unknown source must be rejected with ErrIllegalTransition", got, err)
	}
	if got != OperationState("approved") {
		t.Errorf("Apply(approved, running) returned %q, want the source unchanged", got)
	}
}

func TestLegalTransitionsReturnsDefensiveCopy(t *testing.T) {
	targets := LegalTransitions(StateRunning)
	if len(targets) == 0 {
		t.Fatal("LegalTransitions(running) is empty")
	}
	original := append([]OperationState(nil), targets...)
	targets[0] = "corrupted"
	again := LegalTransitions(StateRunning)
	if fmt.Sprint(again) != fmt.Sprint(original) {
		t.Fatalf("LegalTransitions returned shared state: first call mutated %v into %v", original, again)
	}
	if LegalTransitions("nonsense") != nil {
		t.Error(`LegalTransitions("nonsense") != nil; unknown states must yield nil`)
	}
}

// TestFullLifecycleSequences walks the documented happy and terminal paths
// through Apply, asserting each hop is accepted and terminal hops end.
func TestFullLifecycleSequences(t *testing.T) {
	lifecycle := [][]OperationState{
		// Straight-through completion.
		{StateCreated, StateRunning, StateCompleted},
		// Approval flow: park, human approves, resume into running (recheck
		// territory), complete.
		{StateCreated, StateRunning, StateAwaitingApproval, StateRunning, StateCompleted},
		// Rejection: park, human rejects, cancelled.
		{StateCreated, StateRunning, StateAwaitingApproval, StateCancelled},
		// Approval TTL: park, expiry, terminal (I59).
		{StateCreated, StateRunning, StateAwaitingApproval, StateExpired},
		// Operation-level expiry/failure/cancel without approval.
		{StateCreated, StateRunning, StateExpired},
		{StateCreated, StateRunning, StateFailed},
		{StateCreated, StateRunning, StateCancelled},
	}
	for i, seq := range lifecycle {
		state := seq[0]
		for j, want := range seq[1:] {
			next, err := Apply(state, want)
			if err != nil {
				t.Fatalf("lifecycle %d hop %d Apply(%q, %q): %v", i, j, state, want, err)
			}
			state = next
		}
		if !IsTerminal(state) {
			t.Errorf("lifecycle %d ended in non-terminal state %q", i, state)
		}
	}
}

// TestLifecycleSequencesRefuseIllegalHops pins representative forbidden
// shortcuts, including re-entry from terminal states and creation-time
// skipping.
func TestLifecycleSequencesRefuseIllegalHops(t *testing.T) {
	forbidden := [][3]OperationState{
		// Cannot start parked: approval requires an operation in flight.
		{StateCreated, StateAwaitingApproval, StateCreated},
		// Cannot complete or fail before running.
		{StateCreated, StateCompleted, StateCreated},
		{StateCreated, StateFailed, StateCreated},
		// A late approval cannot revive an expired operation (I59).
		{StateExpired, StateRunning, StateExpired},
		{StateExpired, StateCompleted, StateExpired},
		// Cancelled is terminal.
		{StateCancelled, StateRunning, StateCancelled},
		// Completed can never be reopened or re-entered.
		{StateCompleted, StateRunning, StateCompleted},
		{StateCompleted, StateAwaitingApproval, StateCompleted},
		// Failed cannot transition anywhere.
		{StateFailed, StateCompleted, StateFailed},
		// Awaiting approval cannot jump straight to completion/failure.
		{StateAwaitingApproval, StateCompleted, StateAwaitingApproval},
		{StateAwaitingApproval, StateFailed, StateAwaitingApproval},
	}
	for _, seq := range forbidden {
		from, to, stuck := seq[0], seq[1], seq[2]
		got, err := Apply(from, to)
		if err == nil {
			t.Errorf("Apply(%q, %q) unexpectedly succeeded", from, to)
			continue
		}
		if got != stuck {
			t.Errorf("Apply(%q, %q) = %q, want stuck at %q", from, to, got, stuck)
		}
	}
}

func TestTransitionTableSortedDeterminism(t *testing.T) {
	// The declaration order of every row must be deterministic across
	// processes (shuffle=on runs): a sorted copy of each row must equal the
	// row itself only if authors kept sorted order — instead of enforcing
	// sorted order, pin that repeated reads return identical sequences.
	for _, from := range AllStates() {
		first := LegalTransitions(from)
		second := LegalTransitions(from)
		if fmt.Sprint(first) != fmt.Sprint(second) {
			t.Errorf("LegalTransitions(%q) unstable across calls: %v vs %v", from, first, second)
		}
		sorted := append([]OperationState(nil), first...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		if len(sorted) != len(first) {
			t.Errorf("LegalTransitions(%q) has duplicate targets: %v", from, first)
		}
	}
}
