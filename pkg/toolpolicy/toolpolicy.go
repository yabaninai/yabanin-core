// Package toolpolicy implements TOOL-01 and the OP-6 tool-call guardrails:
// the org-scoped tool-call policy engine. A policy binds a subject (an
// agent key id, or '*' = every agent of the org), optionally an MCP server
// pattern, and a tool pattern (exact name, trailing-'*' wildcard, or '*')
// to an action (allow/deny) and optional guard rules (args JSON-schema /
// max-size / deny-regex, result post-checks).
//
// Decide() picks the most specific match: server class > tool class
// (exact > longest wildcard > '*'); within one specificity level the
// agent-specific subject beats '*', then the lower priority number wins.
// Guard RULES (GuardArgs/GuardResult) do NOT follow the winner: every
// matching enabled rule applies — UNION + MOST-RESTRICTIVE composition,
// mirroring the policy-pipeline wave (findings union, verdict =
// most-restrictive deny > mask > flag). Rules are purely restrictive: no
// rule can loosen another's restriction, which is what makes the union
// unambiguous across org → server → tool → subject specificity levels and
// composable with the OP-8 pipeline (pipeline.Action.Rank order).
//
// Fail modes are per rule ("closed" default, "open" for perf-sensitive
// guards). The org posture is the most protective fail mode of its enabled
// rules, kept STICKY across cache invalidations: a policy-store outage
// denies guarded invokes once the org declared any fail-closed rule.
//
// An org with no enabled policies allows everything — wiring the engine is
// a no-op for deployments that define no policies.
package toolpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Credential-mode constraint values (N05-P02-T04). They live inside the
// rules document (`rules.credential_mode`) and select WHICH credential layer
// may serve a matching call: "service" = the org's service credential only,
// "delegated" = the user's delegated credential only, "auto" = explicitly no
// constraint (the server's connection-config mode governs). "" (absent) =
// the row carries no constraint and does not participate in the mode
// ranking. The values are intentionally identical to pkg/mcpagg's CredMode*
// vocabulary (migration 0016) — the equality is pinned in pkg/mcpagg tests
// (importing it here would cycle).
const (
	CredentialModeAuto      = "auto"
	CredentialModeService   = "service"
	CredentialModeDelegated = "delegated"
)

// CredentialModes is the closed vocabulary ValidateCredentialMode accepts.
var CredentialModes = []string{
	CredentialModeAuto,
	CredentialModeService,
	CredentialModeDelegated,
}

// ValidateCredentialMode checks a credential-mode constraint value: "" (no
// constraint) or one of CredentialModes.
func ValidateCredentialMode(mode string) error {
	switch mode {
	case "":
		return nil
	case CredentialModeAuto, CredentialModeService, CredentialModeDelegated:
		return nil
	default:
		return fmt.Errorf("toolpolicy: credential mode must be one of %v", CredentialModes)
	}
}

// Policy is one row of the tool_policies registry. Server scopes the row to
// one MCP aggregator server ('*' = every server, 'prefix*' = a name family):
// server-qualified rows are MCP-invoke-scoped and INVISIBLE to the chat-path
// Decide (which passes server="*"). Rules carries the OP-6 guard rules
// (args schema/regex/max-size, result post-checks) — nil for plain
// allow/deny rows.
type Policy struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"org_id"`
	Name      string          `json:"name"`
	Subject   string          `json:"subject"` // agent key id or '*'
	Server    string          `json:"server"`  // '*' | exact | 'prefix*' (mcp server name)
	Tool      string          `json:"tool"`    // exact, 'prefix*' or '*'
	Action    string          `json:"action"`  // allow | deny
	Rules     json.RawMessage `json:"rules,omitempty"`
	Priority  int             `json:"priority"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Decision is the outcome of Decide: the action plus the policy that
// produced it (nil for the implicit default allow).
type Decision struct {
	Action  string
	Policy  *Policy
	Matched string // the pattern that matched (diagnostics)
}

// ErrNotFound is returned by store getters for missing rows.
var ErrNotFound = errors.New("toolpolicy: policy not found")

// ValidateName bounds the registry name (same convention as mcp_servers).
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("toolpolicy: name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("toolpolicy: name must be at most 64 characters")
	}
	for i, r := range name {
		body := r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')
		head := r >= '0' && r <= '9' || r >= 'a' && r <= 'z'
		if !body || (i == 0 && !head) {
			return fmt.Errorf("toolpolicy: name must be lowercase letters, digits, '-' and '_'")
		}
	}
	return nil
}

// ValidatePattern checks a subject/tool pattern: non-empty, '*' alone, or a
// trailing-star wildcard on a sane base (no interior '*').
func ValidatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("toolpolicy: pattern is required")
	}
	if p == "*" {
		return nil
	}
	if i := strings.IndexByte(p, '*'); i >= 0 {
		if i != len(p)-1 {
			return fmt.Errorf("toolpolicy: pattern %q: '*' is only supported as a trailing wildcard", p)
		}
		base := p[:i]
		if base == "" {
			return fmt.Errorf("toolpolicy: pattern %q: use '*' alone for match-all", p)
		}
	}
	return nil
}

// ValidateAction accepts the two documented actions.
func ValidateAction(a string) error {
	if a != ActionAllow && a != ActionDeny {
		return fmt.Errorf("toolpolicy: action must be %q or %q", ActionAllow, ActionDeny)
	}
	return nil
}

// matches reports whether pattern matches tool ('*' alone, trailing
// wildcard, or exact).
func matches(pattern, tool string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(tool, pattern[:len(pattern)-1])
	}
	return pattern == tool
}

// specificity ranks how tightly a pattern matches tool: 2 = exact,
// 1 = wildcard, 0 = '*'/no match. Used only for a pattern that DID match.
func specificity(pattern, tool string) int {
	switch {
	case pattern == tool:
		return 2
	case pattern != "*" && strings.HasSuffix(pattern, "*"):
		return 1
	default:
		return 0
	}
}

// defaultMaxCacheEntries bounds the per-org policy cache: Decide is on the
// chat hot path, but the cache must not grow without limit across orgs.
const defaultMaxCacheEntries = 4096

// Engine evaluates policies for one org. Rows are fetched through the
// Loader and memoized per org with a small TTL — the chat-response hot path
// consults Decide per tool call, so a synchronous DB round-trip per call is
// not acceptable; a short staleness window is (policy changes land within
// the TTL, mirroring the key-revocation cache discipline).
type Engine struct {
	loader Loader
	ttl    time.Duration
	now    func() time.Time

	// cache: orgID → {policies, compiled, expiry}. Guarded by mu: Decide runs on
	// concurrent request goroutines while admin CRUD calls Invalidate.
	// postures is the sticky per-org fail-closed stance (see load).
	mu         sync.RWMutex
	cache      map[string]cachedPolicies
	postures   map[string]bool
	maxEntries int
}

type cachedPolicies struct {
	policies []Policy
	// compiled is parallel to policies: the guard rules compiled at load
	// time (nil rules for plain allow/deny rows; err = defense-in-depth for
	// a row whose rules fail to compile — the admin CRUD validates writes,
	// a hand-inserted bad row is fail-closed in GuardArgs).
	compiled []compiledRules
	expires  time.Time
}

type compiledRules struct {
	rules *Rules
	err   error
}

// Loader loads the org's enabled policies newest-last (order irrelevant —
// Decide sorts).
type Loader interface {
	ListEnabled(ctx context.Context, orgID string) ([]Policy, error)
}

// NewEngine builds an engine over a loader. ttl <= 0 defaults to 5s.
func NewEngine(loader Loader, ttl time.Duration) *Engine {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Engine{
		loader: loader, ttl: ttl, now: time.Now,
		cache: map[string]cachedPolicies{}, postures: map[string]bool{},
		maxEntries: defaultMaxCacheEntries,
	}
}

// Decide resolves the action for (subject, tool) in an org — the CHAT-path
// entry point: only rows with Server == '*' participate (server-qualified
// rows are MCP-invoke-scoped). Evaluation: highest tool specificity wins;
// within it, subject-specific rows beat '*'; within that, the lowest
// priority number wins; a stable name order breaks the last tie. No
// matching row → implicit allow.
func (e *Engine) Decide(ctx context.Context, orgID, subject, tool string) Decision {
	return e.decide(ctx, orgID, subject, "*", tool)
}

// DecideTool resolves the action for one MCP tool call against
// (subject, server, tool). OP-6 ranking (fixed, see the package comment on
// composition): the SERVER specificity class ranks above the tool class —
// exact server > 'prefix*' > '*' — then the shipped tool-class order
// (exact > longer wildcard > '*'), then subject-specific beats '*', then
// the lower priority number, then the stable name order. Guard RULES never
// follow the winner: every matching enabled rule applies (union,
// most-restrictive) — see GuardArgs/GuardResult.
func (e *Engine) DecideTool(ctx context.Context, orgID, subject, server, tool string) Decision {
	return e.decide(ctx, orgID, subject, server, tool)
}

// DecideCredMode resolves the policy-selected credential mode for one call
// (N05-P02-T04): the specificity winner among ENABLED rows that carry a
// credential_mode constraint and match (subject, server, tool) — the same
// betterThan ranking as the allow/deny decision, restricted to
// mode-carrying rows so an unconstrained row can never loosen a constrained
// one. Returns ("", nil, nil) when no matching row constrains the mode: the
// server's connection-config credential mode then governs (auto semantics).
//
// FAIL-CLOSED on policy-store outages and on matching rows with
// uncompilable rules: unlike the allow/deny decide() (which fails open into
// the caller's posture machinery), a credential-mode decision is an
// authorization input — silently dropping the constraint would let a call
// that the policy pinned to the user's delegated credential run on the
// org's (stronger) service credential. The caller must refuse the invoke.
func (e *Engine) DecideCredMode(ctx context.Context, orgID, subject, server, tool string) (mode string, policy *Policy, err error) {
	cached, err := e.load(ctx, orgID)
	if err != nil {
		return "", nil, fmt.Errorf("toolpolicy: load credential-mode policies: %w", err)
	}
	var best *Policy
	for i := range cached.policies {
		p := cached.policies[i]
		if !p.Enabled {
			continue
		}
		if p.Subject != "*" && p.Subject != subject {
			continue
		}
		if !matches(p.Server, server) || !matches(p.Tool, tool) {
			continue
		}
		cr := cached.compiled[i]
		if cr.rules == nil {
			if cr.err != nil {
				// A matching rule row that failed to compile is
				// unenforceable — fail closed (GuardArgs parity: the
				// admin CRUD validates writes; this is defense in depth
				// for out-of-band edits).
				return "", nil, fmt.Errorf("toolpolicy: policy %q has uncompilable guard rules; refusing credential-mode decision", p.Name)
			}
			continue // no rules → no constraint from this row
		}
		m := cr.rules.CredentialMode()
		if m == "" {
			continue // unconstrained rows never participate
		}
		if best == nil || betterThan(&p, best, subject, server, tool) {
			best = &p
			mode = m
		}
	}
	if best == nil {
		return "", nil, nil
	}
	return mode, best, nil
}

func (e *Engine) decide(ctx context.Context, orgID, subject, server, tool string) Decision {
	cached, err := e.load(ctx, orgID)
	if err != nil {
		// Fail OPEN on a loader error, loudly: a broken policy store must
		// not take down chat traffic — but it is logged by the caller via
		// the error. Chat-side callers treat this as "no policies" and
		// allow; the invoke paths surface the error (GuardArgs applies the
		// org's fail-closed posture on top of this default).
		return Decision{Action: ActionAllow}
	}
	best := Decision{Action: ActionAllow}
	ranked := false
	for i := range cached.policies {
		p := cached.policies[i]
		if !p.Enabled {
			continue
		}
		if p.Subject != "*" && p.Subject != subject {
			continue
		}
		if !matches(p.Server, server) {
			continue
		}
		if !matches(p.Tool, tool) {
			continue
		}
		if !ranked || betterThan(&p, best.Policy, subject, server, tool) {
			best = Decision{Action: p.Action, Policy: &p, Matched: p.Tool}
			ranked = true
		}
	}
	return best
}

// betterThan reports whether candidate p beats the incumbent for
// (subject, server, tool) under the documented specificity order: exact >
// longer wildcard prefix > shorter wildcard > '*' — evaluated SERVER first,
// then TOOL; then subject-specific beats '*'; then lower priority number;
// then stable name order.
func betterThan(p, incumbent *Policy, subject, server, tool string) bool {
	if incumbent == nil {
		return true
	}
	// 1) server specificity class (exact=2, wildcard=1, star=0).
	sp, si := specificity(p.Server, server), specificity(incumbent.Server, server)
	if sp != si {
		return sp > si
	}
	// 1a) within the server wildcard class, the longer prefix is more
	// specific.
	if sp == 1 {
		lp, li := prefixLen(p.Server), prefixLen(incumbent.Server)
		if lp != li {
			return lp > li
		}
	}
	// 2) tool specificity class (exact=2, wildcard=1, star=0).
	sp, si = specificity(p.Tool, tool), specificity(incumbent.Tool, tool)
	if sp != si {
		return sp > si
	}
	// 2b) within the wildcard class, the longer prefix is more specific.
	if sp == 1 {
		lp, li := prefixLen(p.Tool), prefixLen(incumbent.Tool)
		if lp != li {
			return lp > li
		}
	}
	// 3) subject specificity: an exact subject beats '*'.
	ps, is := subjectRank(p.Subject, subject), subjectRank(incumbent.Subject, subject)
	if ps != is {
		return ps > is
	}
	// 4) priority (lower wins), 5) stable name order.
	if p.Priority != incumbent.Priority {
		return p.Priority < incumbent.Priority
	}
	return p.Name < incumbent.Name
}

// prefixLen is the base length of a trailing-star pattern (0 for '*' alone).
func prefixLen(pattern string) int {
	if strings.HasSuffix(pattern, "*") {
		return len(pattern) - 1
	}
	return 0
}

func subjectRank(pattern, subject string) int {
	if pattern == subject {
		return 1
	}
	return 0 // '*'
}

func (e *Engine) load(ctx context.Context, orgID string) (*cachedPolicies, error) {
	now := e.now()
	e.mu.RLock()
	if c, ok := e.cache[orgID]; ok && now.Before(c.expires) {
		e.mu.RUnlock()
		return &c, nil
	}
	e.mu.RUnlock()
	policies, err := e.loader.ListEnabled(ctx, orgID)
	if err != nil {
		return nil, err
	}
	// The engine owns its copy: a Loader may return a slice backed by an
	// array it hands to concurrent callers (test loaders do), and the
	// in-place sort + server normalization below must never write through
	// to it (pinned by the concurrent Decide/Invalidate race test).
	policies = append([]Policy(nil), policies...)
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	for i := range policies {
		// Load-time normalization: "" (hand-built Policy values, legacy
		// callers) behaves as '*'; the store column default is also '*'.
		if policies[i].Server == "" {
			policies[i].Server = "*"
		}
	}
	compiled := make([]compiledRules, len(policies))
	anyFailClosed := false
	for i := range policies {
		if len(policies[i].Rules) == 0 {
			continue
		}
		rules, cerr := CompileRules(policies[i].Rules)
		compiled[i] = compiledRules{rules: rules, err: cerr}
		if cerr == nil && rules.failClosed {
			anyFailClosed = true
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Re-check under the write lock: a concurrent load may have refreshed
	// this org while this one was fetching.
	if c, ok := e.cache[orgID]; ok && now.Before(c.expires) {
		return &c, nil
	}
	if _, ok := e.cache[orgID]; !ok && len(e.cache) >= e.maxEntries {
		e.evictLocked(now)
	}
	e.cache[orgID] = cachedPolicies{policies: policies, compiled: compiled, expires: now.Add(e.ttl)}
	// The fail posture is STICKY per org: once an org declares a
	// fail-closed rule, a later loader outage stays fail-closed even across
	// Invalidate (dropping the posture on a transient cache miss would
	// silently fail open exactly when the store is unhealthy). Bounded by
	// the same maxEntries with arbitrary eviction (a lost posture degrades
	// to the fail-open default, never to a wrong deny).
	if anyFailClosed {
		if _, ok := e.postures[orgID]; !ok && len(e.postures) >= e.maxEntries {
			for k := range e.postures {
				delete(e.postures, k)
				break
			}
		}
		e.postures[orgID] = true
	}
	c := e.cache[orgID]
	return &c, nil
}

// guardPosture reports the org's last-known fail-closed stance.
func (e *Engine) guardPosture(orgID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.postures[orgID]
}

// evictLocked bounds the cache: expired entries go first, then — if the
// cache is still full — the entry nearest expiry (it would be refetched
// soonest anyway). Caller holds the write lock.
func (e *Engine) evictLocked(now time.Time) {
	for id, c := range e.cache {
		if !now.Before(c.expires) {
			delete(e.cache, id)
		}
	}
	if len(e.cache) < e.maxEntries {
		return
	}
	oldestID := ""
	var oldest time.Time
	for id, c := range e.cache {
		if oldestID == "" || c.expires.Before(oldest) {
			oldestID, oldest = id, c.expires
		}
	}
	if oldestID != "" {
		delete(e.cache, oldestID)
	}
}

// Invalidate drops the cached rows for an org (called by the admin CRUD so
// a policy edit lands immediately).
func (e *Engine) Invalidate(orgID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.cache, orgID)
}

// HasDenyPolicies reports whether the org defines ANY enabled deny policy.
// Response-surface gating consults it as a hot-path fast skip: orgs
// without deny rows pay one cached map lookup, not a scan per tool call.
func (e *Engine) HasDenyPolicies(ctx context.Context, orgID string) bool {
	cached, err := e.load(ctx, orgID)
	if err != nil {
		return false
	}
	for i := range cached.policies {
		if cached.policies[i].Action == ActionDeny {
			return true
		}
	}
	return false
}
