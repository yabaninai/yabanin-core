package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
	"github.com/reireirei/yabanin/pkg/rulestore"
)

// RT-01 handler regressions: the chat request path must evaluate each org's
// rules from a per-request immutable org snapshot — concurrent org A/B
// requests must each land on their own rule target, an org whose rules are
// empty must never inherit another org's rules, and a rule-store failure must
// degrade explicitly (log + no rule overrides), never silently via stale
// shared rule state.
//
// The X-Org-Id header stands in for the trusted identity the auth middleware
// injects in production; these tests exercise routing isolation, not auth.

// rt01Upstream is a mock provider that records the routed model per request
// marker (the first message's content).
type rt01Upstream struct {
	mu     sync.Mutex
	models map[string]string
	srv    *httptest.Server
	calls  int
}

func newRT01Upstream(t *testing.T) *rt01Upstream {
	t.Helper()
	u := &rt01Upstream{models: make(map[string]string)}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Content interface{} `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode upstream body: %v", err)
		}
		marker := "unknown"
		if len(body.Messages) > 0 {
			if s, ok := body.Messages[0].Content.(string); ok {
				marker = s
			}
		}
		u.mu.Lock()
		u.models[marker] = body.Model
		u.calls++
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *rt01Upstream) modelFor(marker string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.models[marker]
}

// rt01RuleDB implements rulestore's dbConn: rules per org, optional shared
// barrier so concurrent requests interleave their rule loads, optional error.
type rt01RuleDB struct {
	mu      sync.Mutex
	rules   map[string][]evaluator.Rule
	err     error
	barrier *sync.WaitGroup
}

func (d *rt01RuleDB) Query(_ context.Context, _ string, args ...interface{}) (pgx.Rows, error) {
	orgID, _ := args[0].(string)
	if d.barrier != nil {
		d.barrier.Done()
		d.barrier.Wait()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	rows := &rt01Rows{}
	for _, r := range d.rules[orgID] {
		rows.data = append(rows.data, []interface{}{r.ID, r.OrgID, r.MatchExpr, r.TargetModel, r.Priority, r.Enabled})
	}
	return rows, nil
}

// rt01Rows implements pgx.Rows over in-memory rule rows (scan order matches
// rulestore.loadFromDB: id, org_id, match_expr, target_model, priority, enabled).
type rt01Rows struct {
	data [][]interface{}
	idx  int
}

func (r *rt01Rows) Next() bool { r.idx++; return r.idx <= len(r.data) }
func (r *rt01Rows) Scan(dest ...interface{}) error {
	if r.idx == 0 || r.idx > len(r.data) {
		return pgx.ErrNoRows
	}
	row := r.data[r.idx-1]
	for i, d := range dest {
		if i >= len(row) {
			break
		}
		switch p := d.(type) {
		case *string:
			*p = row[i].(string)
		case *int:
			*p = row[i].(int)
		case *bool:
			*p = row[i].(bool)
		}
	}
	return nil
}
func (r *rt01Rows) Err() error                                   { return nil }
func (r *rt01Rows) Close()                                       {}
func (r *rt01Rows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *rt01Rows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *rt01Rows) Conn() *pgx.Conn                              { return nil }
func (r *rt01Rows) RawValues() [][]byte                          { return nil }
func (r *rt01Rows) Values() ([]any, error)                       { return nil, nil }

func rt01Gateway(t *testing.T, db *rt01RuleDB, log *slog.Logger) (*gateway, *rt01Upstream) {
	t.Helper()
	u := newRT01Upstream(t)
	gw := streamTestGateway(u.srv.URL)
	gw.ruleStore = rulestore.New(db, nil, 0, nil, slog.New(slog.DiscardHandler))
	// RT-01: gw.eng (snapshot cache) is left nil on purpose — the request
	// path must fall back to compiling a fresh per-org snapshot, which keeps
	// the handler test independent of cache wiring.
	if log != nil {
		gw.log = log
	}
	return gw, u
}

func rt01ChatRequest(t *testing.T, gw *gateway, orgID, marker string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"shared-model","messages":[{"role":"user","content":"` + marker + `"}]}`
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", orgID)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

func rt01Rule(org, target string) evaluator.Rule {
	return evaluator.Rule{
		ID:          "r-" + org,
		OrgID:       org,
		MatchExpr:   `model_requested == "shared-model"`,
		TargetModel: target,
		Priority:    10,
		Enabled:     true,
	}
}

func TestRT01_Chat_BarrierInterleave_EachOrgUsesOwnRules(t *testing.T) {
	db := &rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-a": {rt01Rule("org-a", "target-a")},
		"org-b": {rt01Rule("org-b", "target-b")},
	}}
	gw, upstream := rt01Gateway(t, db, nil)

	// Repeat the barrier interleave: each iteration force-loads both orgs'
	// rules before either evaluation proceeds, so a shared Update→Evaluate
	// engine loses one org's snapshot. Post-RT-01 every iteration must route
	// each org to its own target.
	for i := 0; i < 200; i++ {
		db.barrier = &sync.WaitGroup{}
		db.barrier.Add(2)

		var wg sync.WaitGroup
		var recA, recB *httptest.ResponseRecorder
		wg.Add(2)
		go func() {
			defer wg.Done()
			recA = rt01ChatRequest(t, gw, "org-a", "org-a")
		}()
		go func() {
			defer wg.Done()
			recB = rt01ChatRequest(t, gw, "org-b", "org-b")
		}()
		wg.Wait()

		require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
		require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())
		assert.Equal(t, "target-a", upstream.modelFor("org-a"),
			"iteration %d: org A request must land on org A's rule target", i)
		assert.Equal(t, "target-b", upstream.modelFor("org-b"),
			"iteration %d: org B request must land on org B's rule target", i)
		if t.Failed() {
			return
		}
	}
}

func TestRT01_Chat_EmptyRulesOrgDoesNotUseForeignRules(t *testing.T) {
	db := &rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-b": {rt01Rule("org-b", "target-b")},
		"org-a": {}, // org A has no routing rules at all
	}}
	gw, upstream := rt01Gateway(t, db, nil)

	recB := rt01ChatRequest(t, gw, "org-b", "org-b")
	require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())

	recA := rt01ChatRequest(t, gw, "org-a", "org-a")
	require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())

	assert.Equal(t, "target-b", upstream.modelFor("org-b"))
	assert.Equal(t, "shared-model", upstream.modelFor("org-a"),
		"an org with empty rules must never be routed by another org's rules")
}

func TestRT01_Chat_RuleLoadError_DegradesExplicitly(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	db := &rt01RuleDB{err: assert.AnError}
	gw, upstream := rt01Gateway(t, db, logger)

	rec := rt01ChatRequest(t, gw, "org-a", "org-a")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "shared-model", upstream.modelFor("org-a"),
		"degraded request must continue on the requested model, without rule overrides")
	assert.Contains(t, logBuf.String(), "degrading without rule overrides",
		"rule load failure must be an explicitly logged degradation")
}

// CORE-TRACE-04 live stamping: a rule_override decision on the wire must
// carry the matched rule's identity (namespace routing, rule id, content
// version captured at match time) in the X-Yabanin-Decision header, and an
// org whose rules do not match must never carry a fabricated rule ref.
func TestRT01_Chat_DecisionCarriesRuleIdentity(t *testing.T) {
	db := &rt01RuleDB{rules: map[string][]evaluator.Rule{
		"org-a": {rt01Rule("org-a", "target-a")}, // matches model_requested == "shared-model"
		"org-b": {},                              // no rules at all → unstamped decision
	}}
	gw, upstream := rt01Gateway(t, db, nil)
	gw.cfg.DecisionHeaderEnabled = true

	rule := rt01Rule("org-a", "target-a")

	recA := rt01ChatRequest(t, gw, "org-a", "org-a")
	require.Equal(t, http.StatusOK, recA.Code, recA.Body.String())
	assert.Equal(t, "target-a", upstream.modelFor("org-a"), "rule override must still route to the rule target")

	hdrA := recA.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, hdrA, "decision header must be present on the rule-override path")
	assert.Contains(t, hdrA, `"rule":`, "stamped decision must carry the rule key on the wire")
	var decA routingDecision
	require.NoError(t, json.Unmarshal([]byte(hdrA), &decA), "header must parse: %q", hdrA)
	assert.Equal(t, decisionSourceRuleOverride, decA.Source)
	require.NotNil(t, decA.Rule, "a matched rule must stamp cc.dec.Rule")
	assert.Equal(t, evaluator.NamespaceRouting, decA.Rule.Namespace)
	assert.Equal(t, rule.ID, decA.Rule.ID)
	assert.Equal(t, rule.ContentVersion(), decA.Rule.Version,
		"stamped version must be the rule's content version, not a mutable counter")

	recB := rt01ChatRequest(t, gw, "org-b", "org-b")
	require.Equal(t, http.StatusOK, recB.Code, recB.Body.String())
	hdrB := recB.Header().Get(decisionHeaderKey)
	require.NotEmpty(t, hdrB, "decision header must be present on the passthrough path")
	assert.NotContains(t, hdrB, `"rule":`, "an org without rules must never carry a rule ref")
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *rt01Rows) TypeMap() *pgtype.Map { return nil }
