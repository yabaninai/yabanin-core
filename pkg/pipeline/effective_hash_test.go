package pipeline

import "testing"

func TestEffectivePolicyHashIncludesVersionAndIsStable(t *testing.T) {
	policy := Policy{Name: "p", Steps: []StepSpec{{ID: "s", When: `true`}}}
	pins := map[string]string{"prompt@1": "1", "other@2": "2"}
	one := EffectivePolicyHash(1, policy, pins)
	if one == "" {
		t.Fatal("hash is empty")
	}
	if got := EffectivePolicyHash(1, policy, map[string]string{"other@2": "2", "prompt@1": "1"}); got != one {
		t.Fatalf("map iteration/order changed hash: %q != %q", got, one)
	}
	if got := EffectivePolicyHash(2, policy, pins); got == one {
		t.Fatal("policy version did not change effective hash")
	}
	policy.Steps[0].When = `false`
	if got := EffectivePolicyHash(1, policy, pins); got == one {
		t.Fatal("policy rule change did not change effective hash")
	}
	policy.Steps[0].When = `true`
	pins["prompt@1"] = "2"
	if got := EffectivePolicyHash(1, policy, pins); got == one {
		t.Fatal("prompt pin change did not change effective hash")
	}
}

// TestEffectivePolicyHashNilPinsMatchEmptyPins pins the cross-consumer
// parity contract: the gateway runtime normalizes absent prompt pins to an
// empty map, while a simulator or CLI consumer holds the same state as a nil
// map. Both forms must produce one identical hash or the consumers diverge
// on an unchanged snapshot.
func TestEffectivePolicyHashNilPinsMatchEmptyPins(t *testing.T) {
	policy := Policy{Name: "p", Steps: []StepSpec{{ID: "s", When: `Meta.Model == 'm'`}}}
	zero := EffectivePolicyHash(1, policy, nil)
	empty := EffectivePolicyHash(1, policy, map[string]string{})
	if zero == "" || empty == "" {
		t.Fatalf("hash empty: nil=%q empty=%q", zero, empty)
	}
	if zero != empty {
		t.Fatalf("nil and empty pin maps diverged: %q != %q", zero, empty)
	}
}

// TestEffectivePolicyHashEmptySnapshotStable is the empty-consumer contract:
// a consumer with no policies (version 0, no rules, no pins) gets a stable,
// non-degenerate identity, so "no policies" is representable and comparable
// across runtime, simulator and CLI instead of an error or a random value.
func TestEffectivePolicyHashEmptySnapshotStable(t *testing.T) {
	first := EffectivePolicyHash(0, Policy{}, nil)
	if first == "" {
		t.Fatal("empty-state hash is empty")
	}
	for range 3 {
		if got := EffectivePolicyHash(0, Policy{}, map[string]string{}); got != first {
			t.Fatalf("empty-state hash unstable: %q != %q", got, first)
		}
	}
	nonEmpty := EffectivePolicyHash(0, Policy{Name: "p"}, nil)
	if nonEmpty == first {
		t.Fatal("a named policy hashed like the empty snapshot")
	}
}
