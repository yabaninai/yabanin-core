package evaluator

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Rule represents a routing rule from the database.
type Rule struct {
	ID          string
	OrgID       string
	MatchExpr   string
	TargetModel string
	Priority    int
	Enabled     bool
}

// Context holds request-level context used for rule evaluation.
type Context struct {
	OrgID          string
	ModelRequested string
	SessionID      string
	ClientIP       string
	UserAgent      string
}

// compiledRule is a Rule with its match expression parsed once. The AST is
// built when the owning Snapshot is created; evaluation never re-parses.
type compiledRule struct {
	rule Rule
	ast  node // nil when the expression is empty or malformed: never matches
}

// Snapshot is an immutable, per-org set of compiled routing rules. A snapshot
// belongs to exactly one organization: Evaluate refuses contexts from any
// other org, and later rule replacements never mutate an existing snapshot
// (the rule list is copied at creation). Snapshots are safe for concurrent
// use; they have no mutable state.
type Snapshot struct {
	orgID string
	rules []compiledRule // priority DESC, stable order for equal priorities
}

// NewSnapshot compiles rules into an immutable snapshot for orgID. The input
// slice is copied, so later mutation of the caller's slice does not affect
// the snapshot. Rules of a foreign org and disabled rules are dropped. Rules
// are ordered by priority (highest first); rules with equal priority keep
// their input order. A rule whose expression is empty or malformed is kept
// with a nil AST and never matches; parsing never panics.
func NewSnapshot(orgID string, rules []Rule) *Snapshot {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled || r.OrgID != orgID {
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, ast: parseExpression(r.MatchExpr)})
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].rule.Priority > compiled[j].rule.Priority
	})
	return &Snapshot{orgID: orgID, rules: compiled}
}

// OrgID returns the organization this snapshot belongs to.
func (s *Snapshot) OrgID() string {
	if s == nil {
		return ""
	}
	return s.orgID
}

// Evaluate finds the target of the highest-priority enabled rule whose
// compiled expression evaluates to true against ctx. A context from a
// different organization never matches (the snapshot is org-owned). Rules
// with empty or malformed expressions never match.
func (s *Snapshot) Evaluate(ctx Context, modelRequested string) string {
	// Single selection path: EvaluateMatch owns selection, so recorded rule
	// identity (CORE-TRACE-04) can never drift from what Evaluate returns.
	model, _ := s.EvaluateMatch(ctx, modelRequested)
	return model
}

// snapshotEntry is one cached org snapshot with its rules revision.
type snapshotEntry struct {
	snap     *Snapshot
	revision uint64
	expires  time.Time
	lastUsed atomic.Int64 // unix nanos, for LRU eviction
}

const (
	defaultSnapshotTTL        = 10 * time.Minute
	defaultSnapshotMaxEntries = 4096
)

// SnapshotCache caches compiled rule snapshots per organization so an
// unchanged rule set is parsed once, not per request. The lifecycle is
// bounded on three axes:
//   - revision: an entry is reused only while the rule contents hash matches,
//     so changed rules rebuild the snapshot without any explicit signal;
//   - TTL: entries expire after ttl even if unchanged;
//   - size: at most maxEntries orgs are cached (LRU evicted).
//
// Invalidate drops an org's entry explicitly; call it when an org's rules are
// known to have changed. A missed call is still correct: the revision hash
// rebuilds the snapshot as soon as the rule store returns different rules.
type SnapshotCache struct {
	mu         sync.RWMutex
	entries    map[string]*snapshotEntry
	ttl        time.Duration
	maxEntries int
	now        func() time.Time // injectable for tests
}

// NewSnapshotCache applies defaults for zero values: ttl=10m, maxEntries=4096.
func NewSnapshotCache(ttl time.Duration, maxEntries int) *SnapshotCache {
	if ttl <= 0 {
		ttl = defaultSnapshotTTL
	}
	if maxEntries <= 0 {
		maxEntries = defaultSnapshotMaxEntries
	}
	return &SnapshotCache{
		entries:    make(map[string]*snapshotEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Get returns the compiled snapshot for orgID, rebuilding it when the rules
// revision changed, the entry expired, or there is no entry yet. The returned
// snapshot is immutable and safe to use for the rest of the request.
func (c *SnapshotCache) Get(orgID string, rules []Rule) *Snapshot {
	rev := rulesRevision(orgID, rules)

	now := c.now()
	c.mu.RLock()
	e, ok := c.entries[orgID]
	c.mu.RUnlock()
	if ok && e.revision == rev && now.Before(e.expires) {
		e.lastUsed.Store(now.UnixNano())
		return e.snap
	}

	snap := NewSnapshot(orgID, rules)
	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under the write lock: a concurrent Get may have inserted the
	// same revision while this one was compiling.
	if cur, ok := c.entries[orgID]; ok && cur.revision == rev && now.Before(cur.expires) {
		cur.lastUsed.Store(now.UnixNano())
		return cur.snap
	}
	if len(c.entries) >= c.maxEntries {
		c.evictOneLocked()
	}
	entry := &snapshotEntry{snap: snap, revision: rev, expires: now.Add(c.ttl)}
	entry.lastUsed.Store(now.UnixNano())
	c.entries[orgID] = entry
	return snap
}

// Invalidate drops the cached snapshot for orgID (no-op for unknown orgs).
func (c *SnapshotCache) Invalidate(orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, orgID)
}

// evictOneLocked removes the least recently used entry. Caller holds the
// write lock; the cache is full.
func (c *SnapshotCache) evictOneLocked() {
	oldestID := ""
	var oldestUsed int64
	for id, e := range c.entries {
		used := e.lastUsed.Load()
		if oldestID == "" || used < oldestUsed {
			oldestID, oldestUsed = id, used
		}
	}
	if oldestID != "" {
		delete(c.entries, oldestID)
	}
}

// rulesRevision hashes the org's rule contents so a changed rule set gets a
// new revision (and thus a rebuilt snapshot) even without explicit
// invalidation.
func rulesRevision(orgID string, rules []Rule) uint64 {
	h := fnv.New64a()
	writeField := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0x1f})
	}
	writeField(orgID)
	writeField(strconv.Itoa(len(rules)))
	for _, r := range rules {
		writeField(r.ID)
		writeField(r.OrgID)
		writeField(r.MatchExpr)
		writeField(r.TargetModel)
		writeField(strconv.Itoa(r.Priority))
		if r.Enabled {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte{0x1e})
	}
	return h.Sum64()
}

// Match evaluates a single match_expr against the given context and model.
func Match(matchExpr string, ctx Context, modelRequested string) bool {
	n := parseExpression(matchExpr)
	if n == nil {
		return false
	}
	return n.evaluate(ctx, modelRequested)
}

// --- AST nodes ---

type node interface {
	evaluate(ctx Context, modelRequested string) bool
}

type compareNode struct {
	field    string
	operator string
	value    string
}

func (n *compareNode) evaluate(ctx Context, modelRequested string) bool {
	fm := fieldMap(ctx, modelRequested)
	actual, ok := fm[n.field]
	if !ok {
		return false
	}
	return evalCmp(actual, n.operator, n.value)
}

type andNode struct {
	left  node
	right node
}

func (n *andNode) evaluate(ctx Context, modelRequested string) bool {
	return n.left.evaluate(ctx, modelRequested) && n.right.evaluate(ctx, modelRequested)
}

type orNode struct {
	left  node
	right node
}

func (n *orNode) evaluate(ctx Context, modelRequested string) bool {
	return n.left.evaluate(ctx, modelRequested) || n.right.evaluate(ctx, modelRequested)
}

// --- Parser ---

func parseExpression(expr string) node {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	return parseOr(expr)
}

func parseOr(expr string) node {
	idx := findLogicalOp(expr, "||")
	if idx < 0 {
		return parseAnd(expr)
	}
	left := strings.TrimSpace(expr[:idx])
	right := strings.TrimSpace(expr[idx+2:])
	// NEXT-20: a dangling operator ("a == b || ") must yield an unparseable
	// tree (nil), NOT a tree with nil children — nil children evaluated to
	// a runtime panic on malformed DB-stored expressions.
	ln, rn := parseOr(left), parseOr(right)
	if ln == nil || rn == nil {
		return nil
	}
	return &orNode{left: ln, right: rn}
}

func parseAnd(expr string) node {
	idx := findLogicalOp(expr, "&&")
	if idx < 0 {
		return parseCompare(expr)
	}
	left := strings.TrimSpace(expr[:idx])
	right := strings.TrimSpace(expr[idx+2:])
	ln, rn := parseAnd(left), parseAnd(right)
	if ln == nil || rn == nil {
		return nil
	}
	return &andNode{left: ln, right: rn}
}

func findLogicalOp(s, op string) int {
	inQuote := false
	qc := byte(0)
	for i := 0; i <= len(s)-len(op); i++ {
		ch := s[i]
		if inQuote {
			if ch == qc {
				inQuote = false
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = true
			qc = ch
			continue
		}
		if s[i:i+len(op)] == op {
			return i
		}
	}
	return -1
}

func parseCompare(expr string) node {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	for _, op := range []string{" != ", " == ", " contains ", " starts_with ", " ends_with "} {
		idx := strings.Index(expr, op)
		if idx > 0 {
			return &compareNode{
				field:    strings.TrimSpace(expr[:idx]),
				operator: op,
				value:    unquote(strings.TrimSpace(expr[idx+len(op):])),
			}
		}
	}
	for _, op := range []string{" in ", " not_in "} {
		idx := strings.Index(expr, op)
		if idx > 0 {
			return &compareNode{
				field:    strings.TrimSpace(expr[:idx]),
				operator: op,
				value:    strings.TrimSpace(expr[idx+len(op):]),
			}
		}
	}
	return nil
}

// --- Helpers ---

func fieldMap(ctx Context, modelRequested string) map[string]string {
	return map[string]string{
		"org_id":          ctx.OrgID,
		"model_requested": modelRequested,
		"session_id":      ctx.SessionID,
		"client_ip":       ctx.ClientIP,
		"user_agent":      ctx.UserAgent,
	}
}

func evalCmp(actual, operator, expected string) bool {
	switch operator {
	case " == ":
		return actual == expected
	case " != ":
		return actual != expected
	case " contains ":
		return strings.Contains(actual, expected)
	case " starts_with ":
		return strings.HasPrefix(actual, expected)
	case " ends_with ":
		return strings.HasSuffix(actual, expected)
	case " in ":
		return strIn(actual, splitCSV(expected))
	case " not_in ":
		return !strIn(actual, splitCSV(expected))
	}
	return false
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)

	var parts []string

	// Check if the entire value is a single quoted string like "gpt-4,gpt-3.5"
	// vs multiple quoted strings like "gpt-4","gpt-3.5"
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		inner := s[1 : len(s)-1]
		// Count quotes inside the inner content — if there are any, it's multiple quoted values
		if strings.Count(inner, string(s[0])) > 0 {
			parts = strings.Split(s, ",")
		} else {
			parts = strings.Split(inner, ",")
		}
	} else {
		parts = strings.Split(s, ",")
	}

	result := make([]string, 0, len(parts))
	for _, p := range parts {
		c := unquote(strings.TrimSpace(p))
		if c != "" {
			result = append(result, c)
		}
	}
	return result
}

func strIn(s string, list []string) bool {
	for _, item := range list {
		if s == item {
			return true
		}
	}
	return false
}
