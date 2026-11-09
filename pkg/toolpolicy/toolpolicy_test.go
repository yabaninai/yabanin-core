package toolpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memLoader struct {
	policies []Policy
	err      error
}

func (m *memLoader) ListEnabled(_ context.Context, _ string) ([]Policy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policies, nil
}

// countingLoader counts ListEnabled calls (concurrency dedup assertions).
type countingLoader struct {
	policies []Policy
	calls    atomic.Int64
}

func (m *countingLoader) ListEnabled(_ context.Context, _ string) ([]Policy, error) {
	m.calls.Add(1)
	return m.policies, nil
}

func pol(name, subject, tool, action string, prio int) Policy {
	return Policy{OrgID: "org-1", Name: name, Subject: subject, Tool: tool, Action: action, Priority: prio, Enabled: true}
}

func TestDecide_NoPolicies_DefaultAllow(t *testing.T) {
	e := NewEngine(&memLoader{}, time.Second)
	d := e.Decide(context.Background(), "org-1", "agent-1", "web_fetch")
	if d.Action != ActionAllow || d.Policy != nil {
		t.Fatalf("empty registry must implicitly allow, got %+v", d)
	}
}

func TestDecide_LoaderError_FailsOpen(t *testing.T) {
	e := NewEngine(&memLoader{err: errors.New("db down")}, time.Second)
	if d := e.Decide(context.Background(), "org-1", "a", "x"); d.Action != ActionAllow {
		t.Fatalf("loader error must not deny traffic, got %+v", d)
	}
}

func TestDecide_Specificity(t *testing.T) {
	cases := []struct {
		name     string
		policies []Policy
		subject  string
		tool     string
		want     string
		wantPol  string // name of the winning policy
	}{
		{
			name:     "exact beats wildcard beats star",
			policies: []Policy{pol("deny-web", "*", "web_*", ActionDeny, 100), pol("deny-all", "*", "*", ActionDeny, 100), pol("allow-search", "*", "web_search", ActionAllow, 100)},
			tool:     "web_search",
			want:     ActionAllow,
			wantPol:  "allow-search",
		},
		{
			name:     "longer wildcard beats shorter",
			policies: []Policy{pol("deny-web", "*", "web_*", ActionDeny, 100), pol("deny-web-fetch", "*", "web_fetch*", ActionDeny, 100)},
			tool:     "web_fetch_v2",
			want:     ActionDeny,
			wantPol:  "deny-web-fetch",
		},
		{
			name:     "agent-specific subject beats org-wide",
			policies: []Policy{pol("deny-org", "*", "web_fetch", ActionDeny, 100), pol("allow-agent-9", "agent-9", "web_fetch", ActionAllow, 100)},
			subject:  "agent-9",
			tool:     "web_fetch",
			want:     ActionAllow,
			wantPol:  "allow-agent-9",
		},
		{
			name:     "agent policy does not leak to other agents",
			policies: []Policy{pol("deny-org", "*", "web_fetch", ActionDeny, 100), pol("allow-agent-9", "agent-9", "web_fetch", ActionAllow, 100)},
			subject:  "agent-7",
			tool:     "web_fetch",
			want:     ActionDeny,
			wantPol:  "deny-org",
		},
		{
			name:     "priority breaks same-specificity ties (lower wins)",
			policies: []Policy{pol("deny-p100", "*", "web_fetch", ActionDeny, 100), pol("allow-p10", "*", "web_fetch", ActionAllow, 10)},
			tool:     "web_fetch",
			want:     ActionAllow,
			wantPol:  "allow-p10",
		},
		{
			name:     "disabled rows are ignored",
			policies: []Policy{{OrgID: "org-1", Name: "deny", Subject: "*", Tool: "*", Action: ActionDeny, Enabled: false}},
			tool:     "anything",
			want:     ActionAllow,
			wantPol:  "",
		},
		{
			name:     "non-matching tool falls through to default",
			policies: []Policy{pol("deny-web", "*", "web_*", ActionDeny, 100)},
			tool:     "filesystem_read",
			want:     ActionAllow,
			wantPol:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(&memLoader{policies: tc.policies}, time.Second)
			d := e.Decide(context.Background(), "org-1", tc.subject, tc.tool)
			if d.Action != tc.want {
				t.Fatalf("action: got %q, want %q", d.Action, tc.want)
			}
			gotName := ""
			if d.Policy != nil {
				gotName = d.Policy.Name
			}
			if gotName != tc.wantPol {
				t.Fatalf("winning policy: got %q, want %q", gotName, tc.wantPol)
			}
		})
	}
}

func TestEngine_CacheAndInvalidate(t *testing.T) {
	loader := &memLoader{policies: []Policy{pol("deny", "*", "web_fetch", ActionDeny, 100)}}
	e := NewEngine(loader, time.Minute)
	if d := e.Decide(context.Background(), "org-1", "a", "web_fetch"); d.Action != ActionDeny {
		t.Fatal("first decide must deny")
	}
	// Change the backing data: the cached decision must hold within the TTL…
	loader.policies = nil
	if d := e.Decide(context.Background(), "org-1", "a", "web_fetch"); d.Action != ActionDeny {
		t.Fatal("TTL cache must hold the stale decision")
	}
	// …and Invalidate must drop it immediately.
	e.Invalidate("org-1")
	if d := e.Decide(context.Background(), "org-1", "a", "web_fetch"); d.Action != ActionAllow {
		t.Fatal("after invalidate the new data must apply")
	}
}

func TestEngine_ConcurrentDecideAndInvalidate(t *testing.T) {
	loader := &countingLoader{policies: []Policy{pol("deny", "*", "web_fetch", ActionDeny, 100)}}
	e := NewEngine(loader, time.Minute)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				org := fmt.Sprintf("org-%d", (g+i)%8)
				_ = e.Decide(context.Background(), org, "agent-1", "web_fetch")
				if i%25 == 0 {
					e.Invalidate(org)
				}
				_ = e.HasDenyPolicies(context.Background(), org)
			}
		}(g)
	}
	wg.Wait()
	if loader.calls.Load() == 0 {
		t.Fatal("loader must be consulted at least once")
	}
}

func TestEngine_CacheBounded(t *testing.T) {
	loader := &memLoader{policies: []Policy{pol("deny", "*", "*", ActionDeny, 1)}}
	e := NewEngine(loader, time.Minute)
	e.maxEntries = 8
	for i := 0; i < 100; i++ {
		e.Decide(context.Background(), fmt.Sprintf("org-%d", i), "a", "x")
	}
	e.mu.RLock()
	size := len(e.cache)
	e.mu.RUnlock()
	if size > 8 {
		t.Fatalf("cache must stay bounded, size = %d", size)
	}
}

func TestEngine_EvictionRemovesExpiredFirst(t *testing.T) {
	loader := &memLoader{policies: []Policy{pol("deny", "*", "*", ActionDeny, 1)}}
	e := NewEngine(loader, time.Minute)
	e.maxEntries = 4
	base := time.Now()
	clock := base
	e.now = func() time.Time { return clock }
	for i := 0; i < 4; i++ {
		e.Decide(context.Background(), fmt.Sprintf("org-%d", i), "a", "x")
	}
	// Everything expires, then a new org arrives: the expired entries must
	// be reclaimed instead of live ones.
	clock = base.Add(2 * time.Minute)
	e.Decide(context.Background(), "org-new", "a", "x")
	e.mu.RLock()
	size := len(e.cache)
	_, hasNew := e.cache["org-new"]
	e.mu.RUnlock()
	if size != 1 || !hasNew {
		t.Fatalf("expired entries must be evicted first, size = %d (org-new present: %v)", size, hasNew)
	}
}

func TestValidate(t *testing.T) {
	if err := ValidateName("deny-web-2"); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	if err := ValidateName("Bad Name"); err == nil {
		t.Fatal("invalid name accepted")
	}
	for _, p := range []string{"*", "web_*", "web_fetch", "mcp:github:*"} {
		if err := ValidatePattern(p); err != nil {
			t.Fatalf("pattern %q rejected: %v", p, err)
		}
	}
	for _, p := range []string{"", "we*b", "*web", "*x*"} {
		if err := ValidatePattern(p); err == nil {
			t.Fatalf("pattern %q must be rejected", p)
		}
	}
	if err := ValidateAction(ActionDeny); err != nil {
		t.Fatal("deny must be valid")
	}
	if err := ValidateAction("maybe"); err == nil {
		t.Fatal("unknown action must be rejected")
	}
}

func TestPresets(t *testing.T) {
	for _, p := range Presets() {
		if len(p.Policies) == 0 {
			t.Fatalf("preset %q is empty", p.ID)
		}
		for _, tpl := range p.Policies {
			if err := ValidatePattern(tpl.Tool); err != nil {
				t.Fatalf("preset %q tool pattern %q invalid: %v", p.ID, tpl.Tool, err)
			}
			if err := ValidateAction(tpl.Action); err != nil {
				t.Fatalf("preset %q action %q invalid: %v", p.ID, tpl.Action, err)
			}
		}
	}
	if _, ok := LookupPreset(PresetInternalOnly); !ok {
		t.Fatal("internal-only preset must exist")
	}
	if _, ok := LookupPreset("nope"); ok {
		t.Fatal("unknown preset must not resolve")
	}
	// The internal-only posture must actually evaluate as advertised.
	e := NewEngine(&memLoader{policies: presetAsPolicies(t, PresetInternalOnly)}, time.Second)
	if d := e.Decide(context.Background(), "o", "a", "filesystem_read"); d.Action != ActionDeny {
		t.Fatalf("internal-only must deny ordinary tools, got %q", d.Action)
	}
	if d := e.Decide(context.Background(), "o", "a", "yabanin:web_fetch"); d.Action != ActionAllow {
		t.Fatalf("internal-only must allow the server-side executor, got %q", d.Action)
	}
}

func presetAsPolicies(t *testing.T, id string) []Policy {
	t.Helper()
	p, ok := LookupPreset(id)
	if !ok {
		t.Fatal("preset")
	}
	var out []Policy
	for i, tpl := range p.Policies {
		out = append(out, Policy{
			OrgID: "o", Name: p.ID + "-" + string(rune('a'+i)),
			Subject: tpl.Subject, Tool: tpl.Tool, Action: tpl.Action,
			Priority: tpl.Priority, Enabled: true,
		})
	}
	return out
}
