package toolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// gatesLoader is a fixed-rows (or fixed-error) loader for the
// HasResponseGates controls.
type gatesLoader struct {
	policies []Policy
	err      error
}

func (l *gatesLoader) ListEnabled(context.Context, string) ([]Policy, error) {
	return l.policies, l.err
}

// TestEngineHasResponseGates pins the response-gate predicate: deny rows
// gate, allow rows with declared-args checks gate, allow rows whose rules
// fail to compile gate (fail-closed defense in depth), plain allow rows
// and empty orgs do not, and a loader outage fails open. The contrast
// with HasDenyPolicies is pinned too: args checks live on allow rows,
// which the deny-only predicate cannot see.
func TestEngineHasResponseGates(t *testing.T) {
	ctx := context.Background()
	allowRow := func(rules json.RawMessage) Policy {
		return Policy{OrgID: "o", Name: "row", Subject: "*", Tool: "*", Action: ActionAllow, Enabled: true, Rules: rules}
	}

	t.Run("no rows", func(t *testing.T) {
		e := NewEngine(&gatesLoader{}, time.Minute)
		if e.HasResponseGates(ctx, "o") {
			t.Fatal("an org with no rows has no gates")
		}
	})

	t.Run("plain allow row", func(t *testing.T) {
		e := NewEngine(&gatesLoader{policies: []Policy{allowRow(nil)}}, time.Minute)
		if e.HasResponseGates(ctx, "o") {
			t.Fatal("a plain allow row is not a gate")
		}
	})

	t.Run("deny row", func(t *testing.T) {
		e := NewEngine(&gatesLoader{policies: []Policy{{
			OrgID: "o", Name: "d", Subject: "*", Tool: "*", Action: ActionDeny, Enabled: true,
		}}}, time.Minute)
		if !e.HasResponseGates(ctx, "o") {
			t.Fatal("a deny row is a gate")
		}
	})

	t.Run("allow row with args deny_regex", func(t *testing.T) {
		e := NewEngine(&gatesLoader{policies: []Policy{
			allowRow(json.RawMessage(`{"args":{"deny_regex":["SECRET"]}}`)),
		}}, time.Minute)
		if !e.HasResponseGates(ctx, "o") {
			t.Fatal("an allow row with args checks is a gate")
		}
		if e.HasDenyPolicies(ctx, "o") {
			t.Fatal("HasDenyPolicies must stay false for an args-only allow row (the gap HasResponseGates closes)")
		}
	})

	t.Run("allow row with max_bytes only", func(t *testing.T) {
		e := NewEngine(&gatesLoader{policies: []Policy{
			allowRow(json.RawMessage(`{"args":{"max_bytes":10}}`)),
		}}, time.Minute)
		if !e.HasResponseGates(ctx, "o") {
			t.Fatal("a max_bytes rule is a gate")
		}
	})

	t.Run("allow row with schema only", func(t *testing.T) {
		e := NewEngine(&gatesLoader{policies: []Policy{
			allowRow(json.RawMessage(`{"args":{"schema":{"type":"object"}}}`)),
		}}, time.Minute)
		if !e.HasResponseGates(ctx, "o") {
			t.Fatal("a schema rule is a gate")
		}
	})

	t.Run("compile-error row", func(t *testing.T) {
		e := NewEngine(&gatesLoader{policies: []Policy{
			allowRow(json.RawMessage(`{"args":{"deny_regex":["["]}}`)),
		}}, time.Minute)
		if !e.HasResponseGates(ctx, "o") {
			t.Fatal("a row whose rules fail to compile is a gate (fail-closed)")
		}
	})

	t.Run("loader outage fails open", func(t *testing.T) {
		e := NewEngine(&gatesLoader{err: errors.New("store down")}, time.Minute)
		if e.HasResponseGates(ctx, "o") {
			t.Fatal("a loader outage must report no gates (fail open)")
		}
	})
}
