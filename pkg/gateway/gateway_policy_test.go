package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/gateway/internal/policydecide"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"gopkg.in/yaml.v3"
)

// --- fakes -------------------------------------------------------------------

// fakePolicyStore is an in-memory PolicyPipelineReader.
type fakePolicyStore struct {
	mu           sync.Mutex
	policies     map[string][]adminstore.PolicyPipeline
	versions     map[string]map[string]map[int]string
	atts         map[string]map[string][]adminstore.PolicyAttachment
	listErr      error
	listCtxBlock bool
	listStarted  chan struct{}
}

func newFakePolicyStore() *fakePolicyStore {
	return &fakePolicyStore{
		policies: map[string][]adminstore.PolicyPipeline{},
		versions: map[string]map[string]map[int]string{},
		atts:     map[string]map[string][]adminstore.PolicyAttachment{},
	}
}

func (f *fakePolicyStore) add(org string, p adminstore.PolicyPipeline, yamls map[int]string, atts []adminstore.PolicyAttachment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[org] = append(f.policies[org], p)
	if f.versions[org] == nil {
		f.versions[org] = map[string]map[int]string{}
	}
	f.versions[org][p.ID] = yamls
	if f.atts[org] == nil {
		f.atts[org] = map[string][]adminstore.PolicyAttachment{}
	}
	f.atts[org][p.ID] = atts
}

func (f *fakePolicyStore) ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	f.mu.Lock()
	block, started := f.listCtxBlock, f.listStarted
	err := f.listErr
	policies := append([]adminstore.PolicyPipeline(nil), f.policies[orgID]...)
	f.mu.Unlock()
	if block {
		if started != nil {
			started <- struct{}{}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func (f *fakePolicyStore) GetPolicyVersion(_ context.Context, orgID, policyID string, version int) (adminstore.PolicyVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	y, ok := f.versions[orgID][policyID][version]
	if !ok {
		return adminstore.PolicyVersion{}, adminstore.ErrNotFound
	}
	return adminstore.PolicyVersion{PolicyID: policyID, OrgID: orgID, Version: version, YAML: y}, nil
}

func (f *fakePolicyStore) ListPolicyAttachments(_ context.Context, orgID, policyID string) ([]adminstore.PolicyAttachment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]adminstore.PolicyAttachment(nil), f.atts[orgID][policyID]...), nil
}

// fakePolicyVersions is an in-memory PolicyVersionReader.
type fakePolicyVersions struct {
	mu  sync.Mutex
	v   int64
	err error
}

func (f *fakePolicyVersions) GetPolicyVersion(context.Context, string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.v, f.err
}

func (f *fakePolicyVersions) bump() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v = time.Now().UnixNano()
}

// fakeOrgPolicyVersions models the tenant-scoped Redis version key.
type fakeOrgPolicyVersions struct {
	mu       sync.Mutex
	versions map[string]int64
}

func (f *fakeOrgPolicyVersions) GetPolicyVersion(_ context.Context, orgID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.versions[orgID], nil
}

func (f *fakeOrgPolicyVersions) bump(orgID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions[orgID]++
}

// chatAttachment is the org-wide chat attachment the pack ships.
func chatAttachment(priority int) adminstore.PolicyAttachment {
	return adminstore.PolicyAttachment{KeyLabel: "", ModelPattern: "*", Endpoint: "chat", Priority: priority}
}

func newTestRuntime(t *testing.T, store PolicyPipelineReader, versions PolicyVersionReader, mode PolicyMode) *PolicyRuntime {
	t.Helper()
	rt, err := NewPolicyRuntime(store, versions, mode, nil, testLogger())
	if err != nil {
		t.Fatalf("NewPolicyRuntime: %v", err)
	}
	return rt
}

func testHookGateway(rt *PolicyRuntime) *gateway {
	return &gateway{policyRuntime: rt, log: testLogger()}
}

func policyRequest(body string) (*httptest.ResponseRecorder, *http.Request) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("X-Org-Id", testOrg)
	r.Header.Set("X-API-Key-Id", "key-1")
	return httptest.NewRecorder(), r
}

// captureEvents installs the event observer and returns a getter.
func captureEvents(t *testing.T) func() []*eventpub.Event {
	t.Helper()
	var mu sync.Mutex
	var seen []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, e)
	})
	t.Cleanup(restore)
	return func() []*eventpub.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*eventpub.Event(nil), seen...)
	}
}

// parseDecisions decodes an Event.Policy payload (the OP-9 contract shape).
func parseDecisions(t *testing.T, raw string) []policyDecision {
	t.Helper()
	if raw == "" {
		return nil
	}
	var out []policyDecision
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("policy payload is not a JSON array: %v\n%s", err, raw)
	}
	return out
}

const testOrg = "org-1"

// --- kill-switch resolution ---------------------------------------------------

func TestResolvePolicyMode(t *testing.T) {
	cases := []struct {
		in   string
		want PolicyMode
		note bool
	}{
		{"", PolicyModeOff, false},
		{"off", PolicyModeOff, false},
		{"shadow", PolicyModeShadow, false},
		{"enforce", PolicyModeEnforce, false},
		{"  enforce ", PolicyModeEnforce, false},
		{"banana", PolicyModeOff, true},
	}
	for _, tc := range cases {
		mode, note := ResolvePolicyMode(tc.in)
		if mode != tc.want {
			t.Errorf("ResolvePolicyMode(%q) = %q, want %q", tc.in, mode, tc.want)
		}
		if (note != "") != tc.note {
			t.Errorf("ResolvePolicyMode(%q) note = %q, want note=%v", tc.in, note, tc.note)
		}
	}
}

// --- engine registries ---------------------------------------------------------

func TestNewPolicyEngine_Registries(t *testing.T) {
	eng, err := newPolicyEngine(nil, testLogger())
	if err != nil {
		t.Fatalf("newPolicyEngine: %v", err)
	}
	steps := eng.Steps().Names()
	for _, want := range []string{
		"builtin/national-pii", "builtin/secrets", "builtin/injection", "builtin/contains",
		"llm_judge", "builtin/toolpolicy", "decide", "route_hint",
	} {
		found := false
		for _, s := range steps {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("step %q not registered (have %v)", want, steps)
		}
	}
	scripts := eng.Scripts().Names()
	if len(scripts) != 3 || scripts[0] != "expr" {
		t.Errorf("condition engines = %v, want [expr lua starlark] with expr first (owner TODO)", scripts)
	}
}

func TestNewPolicyEngine_CalloutRequiresAllowList(t *testing.T) {
	eng, err := newPolicyEngine([]string{"detector.internal"}, testLogger())
	if err != nil {
		t.Fatalf("callout engine: %v", err)
	}
	if _, ok := eng.Steps().Factory("callout"); !ok {
		t.Fatal("callout factory missing with an allow-list configured")
	}
	empty, err := newPolicyEngine(nil, testLogger())
	if err != nil {
		t.Fatalf("no-allowlist engine: %v", err)
	}
	if _, ok := empty.Steps().Factory("callout"); ok {
		t.Fatal("callout factory must be absent without an allow-list (no silent egress)")
	}
}

// --- the sovereign-default pack (the shipped artifact) -------------------------

// loadPack reads the shipped declaration and extracts its policy document.
// The second document is reconcile metadata, not part of the policy stored by
// reconciliation; validate it here so this fixture tracks that shipped format.
func loadPack(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/policies/_pack/sovereign-default.yaml")
	if err != nil {
		t.Fatalf("read sovereign-default pack: %v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var policy pipeline.Policy
	if err := dec.Decode(&policy); err != nil {
		t.Fatalf("decode sovereign-default policy document: %v", err)
	}
	var metadata struct {
		Enabled     bool `yaml:"enabled"`
		Attachments []struct {
			KeyLabel     string `yaml:"key_label"`
			ModelPattern string `yaml:"model_pattern"`
			Endpoint     string `yaml:"endpoint"`
			Priority     int    `yaml:"priority"`
		} `yaml:"attachments"`
	}
	if err := dec.Decode(&metadata); err != nil {
		t.Fatalf("decode sovereign-default reconcile metadata: %v", err)
	}
	if metadata.Enabled || len(metadata.Attachments) != 2 {
		t.Fatalf("unexpected sovereign-default reconcile metadata: enabled=%t attachments=%d", metadata.Enabled, len(metadata.Attachments))
	}
	endpoints := map[string]bool{}
	for _, attachment := range metadata.Attachments {
		if attachment.KeyLabel != "" || attachment.ModelPattern != "*" || attachment.Priority != 10 {
			t.Fatalf("unexpected sovereign-default attachment metadata: %+v", attachment)
		}
		endpoints[attachment.Endpoint] = true
	}
	if !endpoints["chat"] || !endpoints["messages"] {
		t.Fatalf("sovereign-default attachments = %v, want chat and messages", endpoints)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("sovereign-default declaration has extra YAML documents: %v", err)
	}
	policyYAML, err := yaml.Marshal(&policy)
	if err != nil {
		t.Fatalf("encode sovereign-default policy fixture: %v", err)
	}
	return string(policyYAML)
}

// TestPolicyRuntime_SovereignPack_PIIRecordedNotBlocked is the e2e against the
// shipped pack: a PII request gets findings recorded (shadow never blocks),
// the decision record carries the pack identity and the finding categories.
func TestPolicyRuntime_SovereignPack_PIIRecordedNotBlocked(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "pack-1", OrgID: testOrg, Name: "sovereign-default", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: loadPack(t)}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)
	events := captureEvents(t)

	requestBody := []byte(`{"model":"m","messages":[{"role":"user","content":"inn 7707083893 please"}]}`)
	w, r := policyRequest(string(requestBody))
	body, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", requestBody)
	if !ok {
		t.Fatalf("shadow pack must never block, code=%d body=%s", w.Code, w.Body.String())
	}
	if string(body) != string(requestBody) {
		t.Fatal("shadow pack must never mutate the payload")
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1 (%s)", len(decisions), policyEvent)
	}
	d := decisions[0]
	if d.PolicyID != "pack-1" || d.Name != "sovereign-default" || d.Version != 1 {
		t.Errorf("decision identity = %+v", d)
	}
	if d.Mode != "shadow" {
		t.Errorf("decision mode = %q, want shadow (the pack ships shadow)", d.Mode)
	}
	var categories []string
	for _, f := range d.Findings {
		categories = append(categories, f.Category)
	}
	if !strings.Contains(strings.Join(categories, ","), "innsnils") {
		t.Errorf("findings categories = %v, want innsnils recorded", categories)
	}

	// The shadow path publishes no denial event.
	for _, ev := range events() {
		if ev.EventType == "request.invalid" {
			t.Errorf("shadow pack published a denial event: %+v", ev)
		}
	}
}

// TestPolicyRuntime_EnforceDeny is the enforce-path e2e: a deny verdict
// answers 400 content_policy_violation and publishes the decision record.
func TestPolicyRuntime_EnforceDeny(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "deny-1", OrgID: testOrg, Name: "deny-sec", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("deny-sec", "forbidden-secret")}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)
	events := captureEvents(t)

	body := []byte(`{"messages":[{"role":"user","content":"give me the forbidden-secret"}]}`)
	w, r := policyRequest(string(body))
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	if ok {
		t.Fatal("enforce deny must answer terminally")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("denial is not the error envelope: %v (%s)", err, w.Body.String())
	}
	if envelope.Error.Code != policyDenyErrorCode {
		t.Errorf("denial code = %q, want %q", envelope.Error.Code, policyDenyErrorCode)
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 || decisions[0].Verdict != "deny" {
		t.Fatalf("decisions = %+v, want one deny", decisions)
	}

	var denial *eventpub.Event
	for _, ev := range events() {
		if ev.EventType == "request.invalid" {
			denial = ev
		}
	}
	if denial == nil {
		t.Fatal("no denial event published")
	}
	if parseDecisions(t, denial.Policy) == nil {
		t.Errorf("denial event carries no decision record: %q", denial.Policy)
	}
}

// TestPolicyRuntime_MaskVerdictProceeds: a mask verdict (no mutator steps are
// registered yet — OP-5) proceeds with an unchanged body and records the
// decision.
func TestPolicyRuntime_MaskVerdictProceeds(t *testing.T) {
	maskYAML := `
apiVersion: ypp/v1
kind: Policy
name: mask-words
mode: enforce
hooks:
  - pre_upstream
steps:
  - id: word
    detector: builtin/contains
    params:
      words: ["masked-word"]
      action: mask
`
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "mask-1", OrgID: testOrg, Name: "mask-words", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: maskYAML}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	orig := []byte(`{"messages":[{"role":"user","content":"the masked-word appears"}]}`)
	w, r := policyRequest(string(orig))
	body, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", orig)
	if !ok {
		t.Fatalf("mask verdict must proceed, code=%d", w.Code)
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 || decisions[0].Verdict != "mask" {
		t.Fatalf("decisions = %+v, want one mask", decisions)
	}
	if string(body) != string(orig) {
		t.Error("no mutator steps exist yet — body must be unchanged")
	}
}

// TestPolicyRuntime_PostUpstreamDeny: post_upstream policies gate the
// upstream response body.
func TestPolicyRuntime_PostUpstreamDeny(t *testing.T) {
	postYAML := `
apiVersion: ypp/v1
kind: Policy
name: post-guard
mode: enforce
hooks:
  - post_upstream
steps:
  - id: resp
    detector: builtin/contains
    params:
      words: ["leaked-ssn"]
      action: deny
`
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "post-1", OrgID: testOrg, Name: "post-guard", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: postYAML}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	_, r := policyRequest("")
	_, policyEvent, denied := gw.policyPostUpstream(r, "chat", "m", "openai",
		[]byte(`{"choices":[{"message":{"content":"here is the leaked-ssn"}}]}`))
	if !denied {
		t.Fatal("post-upstream deny expected")
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 || decisions[0].Verdict != "deny" || decisions[0].Mode != "enforce" {
		t.Fatalf("decisions = %+v", decisions)
	}
}

// TestPolicyRuntime_GlobalShadowDowngrade: kill-switch=shadow downgrades an
// enforce policy at compile time — findings recorded, never a block.
func TestPolicyRuntime_GlobalShadowDowngrade(t *testing.T) {
	enforceYAML := denyWordYAML("strict", "danger")
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "strict-1", OrgID: testOrg, Name: "strict", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: enforceYAML}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeShadow)
	gw := testHookGateway(rt)

	w, r := policyRequest("")
	body := []byte(`{"messages":[{"role":"user","content":"danger zone"}]}`)
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	if !ok {
		t.Fatal("global shadow must never block")
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 || decisions[0].Mode != "shadow" || decisions[0].Verdict == "deny" {
		t.Fatalf("decisions = %+v, want one shadow-mode non-deny decision", decisions)
	}
}

// TestPolicyRuntime_GlobalShadowDowngradeEnvelope: CORE-TRACE-05 — the
// kill-switch shadow decision must not look like a real block. The verdict
// stays allow while the envelope carries the would-have action explicitly
// (effective_action=deny, applied_action=allow), so no reader has to guess
// from finding actions whether traffic was blocked.
func TestPolicyRuntime_GlobalShadowDowngradeEnvelope(t *testing.T) {
	enforceYAML := denyWordYAML("strict", "danger")
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "strict-1", OrgID: testOrg, Name: "strict", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: enforceYAML}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeShadow)
	gw := testHookGateway(rt)

	w, r := policyRequest("")
	body := []byte(`{"messages":[{"role":"user","content":"danger zone"}]}`)
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	if !ok {
		t.Fatal("global shadow must never block")
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 1 {
		t.Fatalf("decisions = %+v, want one", decisions)
	}
	d := decisions[0]
	if d.Mode != "shadow" || d.Verdict != "allow" {
		t.Errorf("mode/verdict = %s/%s, want shadow/allow (never reads as a block)", d.Mode, d.Verdict)
	}
	if d.EffectiveAction != "deny" {
		t.Errorf("effective_action = %q, want deny (the would-have action)", d.EffectiveAction)
	}
	if d.AppliedAction != "allow" {
		t.Errorf("applied_action = %q, want allow (shadow never applies)", d.AppliedAction)
	}
	if d.Matched == nil || !*d.Matched {
		t.Errorf("matched = %+v, want true (detector triggered)", d.Matched)
	}
	if d.EnvelopeVersion != decisionEnvelopeVersion || d.Hook != "pre_upstream" || d.RuleNamespace != "policy" {
		t.Errorf("envelope identity = v%d hook=%s ns=%s, want v%d pre_upstream policy",
			d.EnvelopeVersion, d.Hook, d.RuleNamespace, decisionEnvelopeVersion)
	}
	if d.TraceCompleteness != "full" {
		t.Errorf("trace_completeness = %q, want full", d.TraceCompleteness)
	}
}

// TestPolicyRuntime_DecisionEnvelopeContract: CORE-TRACE-05 envelope per
// scenario — evaluation split (matched vs not), the applied/effective split,
// and the early-deny step trace (an early deny shows its successors as
// skipped, never as absent).
func TestPolicyRuntime_DecisionEnvelopeContract(t *testing.T) {
	t.Run("early deny skips later steps", func(t *testing.T) {
		twoStep := "apiVersion: ypp/v1\nkind: Policy\nname: two-step\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n" +
			"  - id: first_deny\n    detector: builtin/contains\n    params:\n      words: [\"forbidden-secret\"]\n      action: deny\n" +
			"  - id: second_flag\n    detector: builtin/contains\n    params:\n      words: [\"audit-me\"]\n      action: flag\n"
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "two-1", OrgID: testOrg, Name: "two-step", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: twoStep}, []adminstore.PolicyAttachment{chatAttachment(10)})
		rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		gw := testHookGateway(rt)

		w, r := policyRequest("")
		body := []byte(`{"messages":[{"role":"user","content":"the forbidden-secret plus audit-me"}]}`)
		_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
		if ok {
			t.Fatal("enforce deny must answer terminally")
		}
		d := parseDecisions(t, policyEvent)[0]
		if d.Verdict != "deny" || d.EffectiveAction != "deny" || d.AppliedAction != "deny" {
			t.Errorf("verdict/effective/applied = %s/%s/%s, want deny/deny/deny", d.Verdict, d.EffectiveAction, d.AppliedAction)
		}
		if len(d.Steps) != 2 {
			t.Fatalf("steps = %+v, want both compiled steps traced", d.Steps)
		}
		if d.Steps[0].Step != "first_deny" || d.Steps[0].Outcome != "ran" {
			t.Errorf("step[0] = %+v, want first_deny ran", d.Steps[0])
		}
		if d.Steps[1].Step != "second_flag" || d.Steps[1].Outcome != "skipped" {
			t.Errorf("step[1] = %+v, want second_flag skipped (early deny shows the tail)", d.Steps[1])
		}
		if d.StepsTotal != 2 || d.StepsTruncated || d.TraceCompleteness != "full" {
			t.Errorf("totals/completeness = %d/%v/%q, want 2/false/full", d.StepsTotal, d.StepsTruncated, d.TraceCompleteness)
		}
		if d.Matched == nil || !*d.Matched {
			t.Errorf("matched = %+v, want true", d.Matched)
		}
	})
	t.Run("flag observation", func(t *testing.T) {
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "flag-1", OrgID: testOrg, Name: "flag-sec", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: flagWordYAML("flag-sec", "audit-me")}, []adminstore.PolicyAttachment{chatAttachment(10)})
		rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		gw := testHookGateway(rt)

		w, r := policyRequest("")
		body := []byte(`{"messages":[{"role":"user","content":"please audit-me"}]}`)
		_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
		if !ok {
			t.Fatal("flag verdict must never block")
		}
		d := parseDecisions(t, policyEvent)[0]
		if d.Verdict != "flag" || d.EffectiveAction != "flag" || d.AppliedAction != "flag" {
			t.Errorf("verdict/effective/applied = %s/%s/%s, want flag/flag/flag", d.Verdict, d.EffectiveAction, d.AppliedAction)
		}
		if d.Matched == nil || !*d.Matched {
			t.Errorf("matched = %+v, want true (finding recorded)", d.Matched)
		}
	})
	t.Run("clean allow is evaluated but not matched", func(t *testing.T) {
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "flag-1", OrgID: testOrg, Name: "flag-sec", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: flagWordYAML("flag-sec", "audit-me")}, []adminstore.PolicyAttachment{chatAttachment(10)})
		rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		gw := testHookGateway(rt)

		w, r := policyRequest("")
		body := []byte(`{"messages":[{"role":"user","content":"nothing to see"}]}`)
		_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
		if !ok {
			t.Fatal("clean policy must never block")
		}
		d := parseDecisions(t, policyEvent)[0]
		if d.Verdict != "allow" || d.EffectiveAction != "allow" || d.AppliedAction != "allow" {
			t.Errorf("verdict/effective/applied = %s/%s/%s, want allow/allow/allow", d.Verdict, d.EffectiveAction, d.AppliedAction)
		}
		if d.Matched == nil || *d.Matched {
			t.Errorf("matched = %+v, want explicit false (evaluated, not triggered)", d.Matched)
		}
		if len(d.Steps) != 1 || d.Steps[0].Outcome != "ran" {
			t.Errorf("steps = %+v, want the single step ran", d.Steps)
		}
	})
	t.Run("mask verdict without mutation degrades to flag applied", func(t *testing.T) {
		maskNoMutator := "apiVersion: ypp/v1\nkind: Policy\nname: mask-sec\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n" +
			"  - id: word\n    detector: builtin/contains\n    params:\n      words: [\"secret\"]\n      action: mask\n"
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "mask-1", OrgID: testOrg, Name: "mask-sec", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: maskNoMutator}, []adminstore.PolicyAttachment{chatAttachment(10)})
		rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		gw := testHookGateway(rt)

		w, r := policyRequest("")
		body := []byte(`{"messages":[{"role":"user","content":"the secret plan"}]}`)
		_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
		if !ok {
			t.Fatal("mask verdict must never block")
		}
		d := parseDecisions(t, policyEvent)[0]
		if d.Verdict != "mask" || d.EffectiveAction != "mask" {
			t.Errorf("verdict/effective = %s/%s, want mask/mask", d.Verdict, d.EffectiveAction)
		}
		if d.AppliedAction != "flag" {
			t.Errorf("applied_action = %q, want flag (nothing mutated — traffic proceeded observed, not redacted)", d.AppliedAction)
		}
	})
}

// TestDecisionEnvelopeBounds: the producer clips bounded lists with honest
// totals — a truncated list never reads as the full one (CORE-TRACE-05).
func TestDecisionEnvelopeBounds(t *testing.T) {
	findings := make([]pipeline.Finding, policyMaxDecisionFindings+3)
	for i := range findings {
		findings[i] = pipeline.Finding{Step: "s", Category: "c", Severity: "low", Action: pipeline.ActionFlag}
	}
	out, total, truncated := decisionFindings(findings)
	if total != len(findings) || !truncated || len(out) != policyMaxDecisionFindings {
		t.Errorf("decisionFindings = len %d total %d truncated %v, want len %d total %d true",
			len(out), total, truncated, policyMaxDecisionFindings, len(findings))
	}
	if one, oneTotal, oneTrunc := decisionFindings(findings[:1]); oneTotal != 1 || oneTrunc || len(one) != 1 {
		t.Errorf("single finding: len %d total %d truncated %v, want len 1 total 1 false", len(one), oneTotal, oneTrunc)
	}

	trace := make([]pipeline.StepTrace, policyMaxTraceSteps+2)
	for i := range trace {
		trace[i] = pipeline.StepTrace{Step: fmt.Sprintf("step-%d", i), Outcome: pipeline.StepRan, Duration: time.Millisecond}
	}
	steps, stepsTotal, stepsTruncated := decisionStepsFromTrace(trace)
	if stepsTotal != len(trace) || !stepsTruncated || len(steps) != policyMaxTraceSteps {
		t.Errorf("decisionStepsFromTrace = len %d total %d truncated %v, want len %d total %d true",
			len(steps), stepsTotal, stepsTruncated, policyMaxTraceSteps, len(trace))
	}
	if long := boundTraceField(strings.Repeat("x", policyMaxTraceFieldLen+10)); len(long) != policyMaxTraceFieldLen {
		t.Errorf("boundTraceField clipped to %d, want %d", len(long), policyMaxTraceFieldLen)
	}
	if empty, total, trunc := decisionStepsFromTrace(nil); empty != nil || total != 0 || trunc {
		t.Errorf("empty trace: %+v/%d/%v, want nil/0/false", empty, total, trunc)
	}
}

// TestPolicyRuntime_RecursionExemption: an inbound judge marker is an
// unsupported HTTP re-entry, while internal judge metadata remains valid.
func TestPolicyRuntime_RecursionExemption(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "deny-1", OrgID: testOrg, Name: "deny-sec", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyEverythingYAML()}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	body := []byte(`{"messages":[{"role":"user","content":"give me the forbidden-secret"}]}`)
	w, r := policyRequest(string(body))
	r.Header.Set("X-Yabanin-Judge", "true")
	got, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	if ok || w.Code != http.StatusBadRequest {
		t.Fatalf("marked HTTP request = (ok=%v, status=%d), want terminal 400", ok, w.Code)
	}
	if policyEvent != "" {
		t.Errorf("re-entry rejection must have no decision record, got %q", policyEvent)
	}
	if !strings.Contains(w.Body.String(), "judge_reentry_unsupported") || strings.Contains(w.Body.String(), "true") {
		t.Errorf("re-entry response must have a stable generic code without marker value, body=%s", w.Body.String())
	}
	if string(got) != string(body) {
		t.Error("terminal re-entry result must leave the input body untouched")
	}

	// The meta-level twin: llmjudge.IsJudgeMeta is the canonical check the
	// middleware contract names.
	if !llmjudge.IsJudgeMeta(&pipeline.RequestMeta{Org: testOrg, Labels: map[string]string{llmjudge.MetaLabelJudge: llmjudge.JudgeLabelValue}}) {
		t.Fatal("judge-marked meta must be exempt")
	}
	if llmjudge.IsJudgeMeta(&pipeline.RequestMeta{Org: testOrg}) {
		t.Fatal("plain meta must not be exempt")
	}
}

// TestPolicyRuntime_KillSwitchOff: runtime nil = every hook is a no-op and the
// body passes through untouched (bit-for-bit pre-OP-8 behavior).
func TestPolicyRuntime_KillSwitchOff(t *testing.T) {
	gw := testHookGateway(nil)
	orig := []byte(`{"messages":[{"role":"user","content":"give me the forbidden-secret"}]}`)

	w, r := policyRequest(string(orig))
	body, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", orig)
	if !ok || policyEvent != "" || string(body) != string(orig) || w.Code != http.StatusOK {
		t.Fatal("off-mode pre hook must be a no-op")
	}

	respBody, postEvent, denied := gw.policyPostUpstream(r, "chat", "m", "openai", orig)
	if denied || postEvent != "" || string(respBody) != string(orig) {
		t.Fatal("off-mode post hook must be a no-op")
	}
}

// TestPolicyRuntime_VersionKeyInvalidation: a version bump drops the compiled
// cache and the new policy content governs the next request.
func TestPolicyRuntime_VersionKeyInvalidation(t *testing.T) {
	store := newFakePolicyStore()
	vers := &fakePolicyVersions{}
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "inv-1", OrgID: testOrg, Name: "deny-sec", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("deny-sec", "marker-v1"), 2: denyWordYAML("deny-sec", "marker-v2")},
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, vers, PolicyModeEnforce)
	gw := testHookGateway(rt)

	body := []byte(`{"messages":[{"role":"user","content":"marker-v2"}]}`)

	// Under v1: marker-v2 traffic is untouched (v1 denies marker-v1 only).
	w1, r1 := policyRequest("")
	if _, _, ok := gw.policyPreUpstream(w1, r1, "chat", "m", "openai", body); !ok {
		t.Fatalf("v1 policy should not deny marker-v2 traffic: code=%d", w1.Code)
	}

	// The admin plane bumps: new active version + version-key bump.
	store.mu.Lock()
	store.policies[testOrg][0].CurrentVersion = 2
	store.mu.Unlock()
	vers.bump()

	w2, r2 := policyRequest("")
	if _, _, ok := gw.policyPreUpstream(w2, r2, "chat", "m", "openai", body); ok {
		t.Fatal("v2 policy (marker-v2 deny) must deny after the version bump")
	}
	if w2.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w2.Code)
	}

	// The v2 content keeps governing (cache coherent, no version flicker).
	w3, r3 := policyRequest("")
	if _, _, ok := gw.policyPreUpstream(w3, r3, "chat", "m", "openai", body); ok {
		t.Fatal("v2 policy must keep governing")
	}
}

func TestPolicyRuntime_TenantIsolationBeforeTTL(t *testing.T) {
	const orgA, orgB = "tenant-a", "tenant-b"
	store := newFakePolicyStore()
	store.add(orgA, adminstore.PolicyPipeline{
		ID: "tenant-a-policy", OrgID: orgA, Name: "tenant-a-policy", Enabled: true, CurrentVersion: 1,
	}, map[int]string{
		1: denyWordYAML("tenant-a-policy", "tenant-a-v1"),
		2: denyWordYAML("tenant-a-policy", "tenant-a-v2"),
	}, []adminstore.PolicyAttachment{chatAttachment(10)})
	store.add(orgB, adminstore.PolicyPipeline{
		ID: "tenant-b-policy", OrgID: orgB, Name: "tenant-b-policy", Enabled: true, CurrentVersion: 1,
	}, map[int]string{
		1: denyWordYAML("tenant-b-policy", "tenant-b-v1"),
	}, []adminstore.PolicyAttachment{chatAttachment(10)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{orgA: 7, orgB: 19}}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	base := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	now := base
	rt.now = func() time.Time { return now }
	gw := testHookGateway(rt)
	assertOutcome := func(orgID, marker string, wantDenied bool) {
		t.Helper()
		body := []byte(`{"messages":[{"role":"user","content":"` + marker + `"}]}`)
		w, r := policyRequest(string(body))
		r.Header.Set("X-Org-Id", orgID)
		_, _, proceeds := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
		if !wantDenied {
			if !proceeds {
				t.Fatalf("org %s unexpectedly answered marker %q with status %d: %s", orgID, marker, w.Code, w.Body.String())
			}
			if w.Code != http.StatusOK || w.Body.Len() != 0 {
				t.Fatalf("org %s allow for marker %q wrote an error: status=%d body=%s", orgID, marker, w.Code, w.Body.String())
			}
			return
		}
		if proceeds {
			t.Fatalf("org %s allowed denied marker %q", orgID, marker)
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("org %s denial for marker %q status = %d, want %d: %s", orgID, marker, w.Code, http.StatusBadRequest, w.Body.String())
		}
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("org %s denial for marker %q is not an error envelope: %v (%s)", orgID, marker, err, w.Body.String())
		}
		if envelope.Error.Code != policyDenyErrorCode {
			t.Fatalf("org %s denial for marker %q code = %q, want %q", orgID, marker, envelope.Error.Code, policyDenyErrorCode)
		}
	}

	assertOutcome(orgA, "tenant-a-v1", true)
	assertOutcome(orgB, "tenant-b-v1", true)
	assertOutcome(orgA, "tenant-b-v1", false)
	assertOutcome(orgB, "tenant-a-v1", false)
	entryA, entryB := rt.orgs[orgA], rt.orgs[orgB]
	if entryA == nil || entryB == nil || entryA.loadedAt != base || entryB.loadedAt != base {
		t.Fatalf("initial tenant entries = A:%+v B:%+v, want both loaded at %v", entryA, entryB, base)
	}
	if entryA.version != 7 || entryB.version != 19 || !entryA.haveVer || !entryB.haveVer {
		t.Fatalf("initial tenant version snapshots = A:%+v B:%+v, want 7 and 19", entryA, entryB)
	}
	bPlanID, bPlanVersion := entryB.plans[0].policyID, entryB.plans[0].version

	store.mu.Lock()
	store.policies[orgA][0].CurrentVersion = 2
	store.mu.Unlock()
	versions.bump(orgA)
	now = base.Add(time.Second)
	if now.Sub(base) >= policyCacheTTL {
		t.Fatal("test update must remain before the runtime TTL")
	}
	assertOutcome(orgA, "tenant-a-v2", true)
	assertOutcome(orgA, "tenant-a-v1", false)
	updatedA := rt.orgs[orgA]
	if updatedA == entryA || updatedA.loadedAt != now || updatedA.version != 8 || len(updatedA.plans) != 1 || updatedA.plans[0].version != 2 {
		t.Fatalf("org A cache after scoped bump = %+v, want refreshed v2 at %v", updatedA, now)
	}

	assertOutcome(orgB, "tenant-b-v1", true)
	assertOutcome(orgB, "tenant-a-v2", false)
	assertOutcome(orgB, "tenant-b-v2", false)
	if rt.orgs[orgB] != entryB || entryB.loadedAt != base || entryB.version != 19 || len(entryB.plans) != 1 || entryB.plans[0].policyID != bPlanID || entryB.plans[0].version != bPlanVersion {
		t.Fatalf("org B cached snapshot changed after org A bump: entry=%+v, plan=%+v", rt.orgs[orgB], entryB.plans)
	}
	if got, _ := versions.GetPolicyVersion(context.Background(), orgB); got != 19 {
		t.Fatalf("org B version key changed after org A bump: got %d, want 19", got)
	}
}

// TestPolicyRuntime_HardTTLBoundary proves equal/missing version probes and a
// load-time unknown version cannot renew the successful store-load timestamp.
func TestPolicyRuntime_HardTTLBoundary(t *testing.T) {
	base := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	newRuntime := func(t *testing.T, versionErr error) (*PolicyRuntime, *fakePolicyVersions) {
		t.Helper()
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "ttl-1", OrgID: testOrg, Name: "ttl", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: denyWordYAML("ttl", "ttl-marker")}, []adminstore.PolicyAttachment{chatAttachment(10)})
		versions := &fakePolicyVersions{v: 7, err: versionErr}
		rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
		rt.now = func() time.Time { return base }
		return rt, versions
	}

	t.Run("unchanged readable version expires at boundary", func(t *testing.T) {
		rt, _ := newRuntime(t, nil)
		initial := rt.entry(context.Background(), testOrg)
		if !initial.haveVer || initial.loadedAt != base {
			t.Fatalf("initial entry = %+v, want known version loaded at %v", initial, base)
		}

		now := base.Add(policyCacheTTL - time.Nanosecond)
		rt.now = func() time.Time { return now }
		before := rt.entry(context.Background(), testOrg)
		if before != initial || before.loadedAt != base {
			t.Fatalf("fresh same-version probe renewed/replaced entry: got %p at %v, want %p at %v", before, before.loadedAt, initial, base)
		}

		now = base.Add(policyCacheTTL)
		after := rt.entry(context.Background(), testOrg)
		if after == initial || after.loadedAt != now {
			t.Fatalf("entry at exact TTL = %p at %v, want refreshed entry at %v", after, after.loadedAt, now)
		}
		now = now.Add(policyCacheTTL + time.Nanosecond)
		afterBeyond := rt.entry(context.Background(), testOrg)
		if afterBeyond == after || afterBeyond.loadedAt != now {
			t.Fatalf("entry beyond TTL = %p at %v, want refreshed entry at %v", afterBeyond, afterBeyond.loadedAt, now)
		}
	})

	t.Run("missing key version zero expires at boundary", func(t *testing.T) {
		rt, versions := newRuntime(t, nil)
		versions.mu.Lock()
		versions.v = 0
		versions.mu.Unlock()
		initial := rt.entry(context.Background(), testOrg)
		if !initial.haveVer || initial.version != 0 {
			t.Fatalf("initial entry = %+v, want readable missing-key version zero", initial)
		}

		now := base.Add(policyCacheTTL - time.Nanosecond)
		rt.now = func() time.Time { return now }
		if got := rt.entry(context.Background(), testOrg); got != initial || got.loadedAt != base {
			t.Fatalf("fresh version-zero probe changed entry/timestamp: got %p at %v, want %p at %v", got, got.loadedAt, initial, base)
		}
		now = base.Add(policyCacheTTL)
		after := rt.entry(context.Background(), testOrg)
		if after == initial || after.loadedAt != now {
			t.Fatalf("entry at exact TTL = %p at %v, want refresh at %v", after, after.loadedAt, now)
		}
		now = now.Add(policyCacheTTL + time.Nanosecond)
		afterBeyond := rt.entry(context.Background(), testOrg)
		if afterBeyond == after || afterBeyond.loadedAt != now {
			t.Fatalf("entry beyond TTL = %p at %v, want refresh at %v", afterBeyond, afterBeyond.loadedAt, now)
		}
	})

	t.Run("unknown load-time version gets the same TTL", func(t *testing.T) {
		rt, versions := newRuntime(t, errors.New("version probe unavailable"))
		initial := rt.entry(context.Background(), testOrg)
		if initial == nil || initial.haveVer || initial.loadedAt != base {
			t.Fatalf("initial entry = %+v, want cached plans with unknown version at %v", initial, base)
		}
		versions.mu.Lock()
		versions.err = nil
		versions.mu.Unlock()

		now := base.Add(policyCacheTTL - time.Nanosecond)
		rt.now = func() time.Time { return now }
		if got := rt.entry(context.Background(), testOrg); got != initial || got.loadedAt != base {
			t.Fatalf("healthy probe before TTL replaced/renewed unknown-version entry: got %p at %v, want %p at %v", got, got.loadedAt, initial, base)
		}
		now = base.Add(policyCacheTTL)
		after := rt.entry(context.Background(), testOrg)
		if after == initial || !after.haveVer || after.loadedAt != now {
			t.Fatalf("entry at exact TTL = %+v, want refreshed known-version entry at %v", after, now)
		}
		now = now.Add(policyCacheTTL + time.Nanosecond)
		afterBeyond := rt.entry(context.Background(), testOrg)
		if afterBeyond == after || afterBeyond.loadedAt != now {
			t.Fatalf("entry beyond TTL = %+v, want refresh at %v", afterBeyond, now)
		}
	})

	t.Run("two runtimes apply stored changes at the hard TTL", func(t *testing.T) {
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "ttl-shared", OrgID: testOrg, Name: "ttl-shared", Enabled: true, CurrentVersion: 1,
		}, map[int]string{
			1: denyWordYAML("ttl-shared", "ttl-v1"),
			2: denyWordYAML("ttl-shared", "ttl-v2"),
			3: denyWordYAML("ttl-shared", "ttl-v3"),
		}, []adminstore.PolicyAttachment{chatAttachment(10)})
		versions := &fakePolicyVersions{v: 41}
		runtimes := []*PolicyRuntime{
			newTestRuntime(t, store, versions, PolicyModeEnforce),
			newTestRuntime(t, store, versions, PolicyModeEnforce),
		}
		now := base
		for _, rt := range runtimes {
			rt.now = func() time.Time { return now }
		}
		denies := func(rt *PolicyRuntime, marker string) bool {
			w, r := policyRequest(`{"messages":[{"role":"user","content":"` + marker + `"}]}`)
			_, _, proceeds := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"`+marker+`"}]}`))
			return !proceeds && w.Code == http.StatusBadRequest
		}
		for i, rt := range runtimes {
			if !denies(rt, "ttl-v1") {
				t.Fatalf("runtime %d did not initially enforce v1", i)
			}
		}
		initial := []*orgPolicyEntry{runtimes[0].orgs[testOrg], runtimes[1].orgs[testOrg]}

		store.mu.Lock()
		store.policies[testOrg][0].CurrentVersion = 2
		store.mu.Unlock()
		now = base.Add(policyCacheTTL - time.Nanosecond)
		for i, rt := range runtimes {
			if denies(rt, "ttl-v2") || !denies(rt, "ttl-v1") {
				t.Fatalf("runtime %d did not keep v1 policy just before TTL", i)
			}
			if rt.orgs[testOrg] != initial[i] || rt.orgs[testOrg].loadedAt != base {
				t.Fatalf("runtime %d renewed load timestamp under unchanged version", i)
			}
		}

		now = base.Add(policyCacheTTL)
		for i, rt := range runtimes {
			if !denies(rt, "ttl-v2") || denies(rt, "ttl-v1") {
				t.Fatalf("runtime %d did not switch to stored v2 policy at exact TTL", i)
			}
			if rt.orgs[testOrg] == initial[i] || rt.orgs[testOrg].loadedAt != now {
				t.Fatalf("runtime %d did not refresh at exact TTL", i)
			}
		}

		store.mu.Lock()
		store.policies[testOrg][0].CurrentVersion = 3
		store.mu.Unlock()
		now = now.Add(time.Nanosecond)
		for i, rt := range runtimes {
			if denies(rt, "ttl-v3") || !denies(rt, "ttl-v2") {
				t.Fatalf("runtime %d did not keep v2 before its next TTL", i)
			}
		}
		now = base.Add(2*policyCacheTTL + time.Nanosecond)
		for i, rt := range runtimes {
			if !denies(rt, "ttl-v3") || denies(rt, "ttl-v2") {
				t.Fatalf("runtime %d did not switch to stored v3 beyond TTL", i)
			}
		}
	})

	t.Run("version GET error uses hard TTL", func(t *testing.T) {
		rt, versions := newRuntime(t, nil)
		if denied := func() bool {
			w, r := policyRequest(`{"messages":[{"role":"user","content":"ttl-marker"}]}`)
			_, _, proceeds := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"ttl-marker"}]}`))
			return !proceeds && w.Code == http.StatusBadRequest
		}(); !denied {
			t.Fatal("initial policy did not deny its marker")
		}
		store := rt.store.(*fakePolicyStore)
		store.mu.Lock()
		store.policies[testOrg][0].CurrentVersion = 2
		store.versions[testOrg]["ttl-1"][2] = denyWordYAML("ttl", "ttl-next")
		store.mu.Unlock()
		versions.mu.Lock()
		versions.err = errors.New("version GET failed")
		versions.mu.Unlock()
		initial := rt.orgs[testOrg]
		check := func(marker string) bool {
			w, r := policyRequest(`{"messages":[{"role":"user","content":"` + marker + `"}]}`)
			_, _, proceeds := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"`+marker+`"}]}`))
			return !proceeds && w.Code == http.StatusBadRequest
		}
		now := base.Add(policyCacheTTL - time.Nanosecond)
		rt.now = func() time.Time { return now }
		if check("ttl-next") || !check("ttl-marker") || rt.orgs[testOrg] != initial || initial.loadedAt != base {
			t.Fatal("version GET error before TTL did not preserve the old cached policy and timestamp")
		}
		now = base.Add(policyCacheTTL)
		if !check("ttl-next") || check("ttl-marker") || rt.orgs[testOrg] == initial || rt.orgs[testOrg].loadedAt != now {
			t.Fatal("version GET error at TTL did not refresh from the store")
		}
	})

	t.Run("failed store refresh keeps stale policy and retries next request", func(t *testing.T) {
		rt, _ := newRuntime(t, nil)
		check := func(marker string) bool {
			w, r := policyRequest(`{"messages":[{"role":"user","content":"` + marker + `"}]}`)
			_, _, proceeds := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"`+marker+`"}]}`))
			return !proceeds && w.Code == http.StatusBadRequest
		}
		if !check("ttl-marker") {
			t.Fatal("initial policy did not deny its marker")
		}
		store := rt.store.(*fakePolicyStore)
		store.mu.Lock()
		store.policies[testOrg][0].CurrentVersion = 2
		store.versions[testOrg]["ttl-1"][2] = denyWordYAML("ttl", "ttl-recovered")
		store.listErr = errors.New("temporary policy store failure")
		store.mu.Unlock()
		initial := rt.orgs[testOrg]
		now := base.Add(policyCacheTTL)
		rt.now = func() time.Time { return now }
		if check("ttl-recovered") || !check("ttl-marker") || rt.orgs[testOrg] != initial || initial.loadedAt != base {
			t.Fatal("failed refresh did not preserve the old policy and successful-load timestamp")
		}
		store.mu.Lock()
		store.listErr = nil
		store.mu.Unlock()
		if !check("ttl-recovered") || check("ttl-marker") || rt.orgs[testOrg] == initial || rt.orgs[testOrg].loadedAt != now {
			t.Fatal("next request did not retry and install the recovered policy")
		}
	})

	t.Run("known changed version refreshes immediately", func(t *testing.T) {
		rt, versions := newRuntime(t, nil)
		initial := rt.entry(context.Background(), testOrg)
		now := base.Add(time.Second)
		rt.now = func() time.Time { return now }
		versions.mu.Lock()
		versions.v++
		versions.mu.Unlock()
		after := rt.entry(context.Background(), testOrg)
		if after == initial || !after.haveVer || after.loadedAt != now {
			t.Fatalf("changed version entry = %+v, want immediate refresh at %v", after, now)
		}
	})

	t.Run("canceled expired refresh keeps old policy and retries", func(t *testing.T) {
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "cancel-refresh", OrgID: testOrg, Name: "cancel-refresh", Enabled: true, CurrentVersion: 1,
		}, map[int]string{
			1: denyWordYAML("cancel-refresh", "cancel-v1"),
			2: denyWordYAML("cancel-refresh", "cancel-v2"),
		}, []adminstore.PolicyAttachment{chatAttachment(10)})
		versions := &fakePolicyVersions{v: 23}
		rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
		now := base
		rt.now = func() time.Time { return now }
		initial := rt.entry(context.Background(), testOrg)
		if initial == nil || initial.loadedAt != base {
			t.Fatalf("initial entry = %+v, want successful load at %v", initial, base)
		}
		store.mu.Lock()
		store.policies[testOrg][0].CurrentVersion = 2
		store.listCtxBlock = true
		store.listStarted = make(chan struct{}, 1)
		started := store.listStarted
		store.mu.Unlock()
		now = base.Add(policyCacheTTL)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan *orgPolicyEntry, 1)
		go func() { result <- rt.entry(ctx, testOrg) }()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("expired refresh did not reach the context-aware store")
		}
		cancel()
		var afterCancel *orgPolicyEntry
		select {
		case afterCancel = <-result:
		case <-time.After(2 * time.Second):
			t.Fatal("refresh did not return after its context was canceled")
		}
		if afterCancel != initial || rt.orgs[testOrg] != initial || initial.loadedAt != base {
			var gotAt time.Time
			if afterCancel != nil {
				gotAt = afterCancel.loadedAt
			}
			t.Fatalf("canceled refresh changed cached entry/timestamp: got %p at %v, want %p at %v", afterCancel, gotAt, initial, base)
		}
		denies := func(marker string) bool {
			w, r := policyRequest(`{"messages":[{"role":"user","content":"` + marker + `"}]}`)
			_, _, proceeds := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"`+marker+`"}]}`))
			return !proceeds && w.Code == http.StatusBadRequest
		}
		// Before the hard boundary, the cached v1 plan remains effective even
		// though a canceled refresh attempt did not renew its load timestamp.
		now = base.Add(policyCacheTTL - time.Nanosecond)
		if !denies("cancel-v1") || denies("cancel-v2") {
			t.Fatal("canceled refresh did not keep the old effective policy")
		}

		store.mu.Lock()
		store.listCtxBlock = false
		store.mu.Unlock()
		now = base.Add(policyCacheTTL)
		if !denies("cancel-v2") || denies("cancel-v1") {
			t.Fatal("next uncanceled request did not retry and install the new policy")
		}
		if rt.orgs[testOrg] == initial || rt.orgs[testOrg].loadedAt != now {
			t.Fatalf("recovery entry = %p at %v, want a refreshed entry at %v", rt.orgs[testOrg], rt.orgs[testOrg].loadedAt, now)
		}
	})
}

// TestPolicyRuntime_PriorityOrder: smaller attachment priority runs first, the
// deny short-circuits the rest.
func TestPolicyRuntime_PriorityOrder(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "p-low", OrgID: testOrg, Name: "first", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: flagWordYAML("first", "shared-word")}, []adminstore.PolicyAttachment{chatAttachment(5)})
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "p-high", OrgID: testOrg, Name: "second", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("second", "shared-word")}, []adminstore.PolicyAttachment{chatAttachment(50)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	w, r := policyRequest("")
	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai",
		[]byte(`{"messages":[{"role":"user","content":"shared-word"}]}`))
	if ok {
		t.Fatal("deny policy must answer terminally")
	}
	decisions := parseDecisions(t, policyEvent)
	if len(decisions) != 2 {
		t.Fatalf("decisions = %d, want 2 (flag policy ran, then deny)", len(decisions))
	}
	if decisions[0].Name != "first" || decisions[0].Verdict != "flag" {
		t.Errorf("first decision = %+v, want first/flag (priority 5 before 50)", decisions[0])
	}
	if decisions[1].Name != "second" || decisions[1].Verdict != "deny" {
		t.Errorf("second decision = %+v, want second/deny", decisions[1])
	}
}

// TestPolicyRuntime_AttachmentScoping: endpoint and model-pattern mismatches
// do not run the policy.
func TestPolicyRuntime_AttachmentScoping(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "scope-1", OrgID: testOrg, Name: "scoped", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("scoped", "scoped-word")},
		[]adminstore.PolicyAttachment{
			{KeyLabel: "", ModelPattern: "gpt-*", Endpoint: "chat", Priority: 10},
		})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	body := []byte(`{"messages":[{"role":"user","content":"scoped-word here"}]}`)

	w1, r1 := policyRequest("")
	if _, ev, ok := gw.policyPreUpstream(w1, r1, "chat", "m", "openai", body); !ok || ev != "" {
		t.Errorf("model mismatch must skip the policy (ok=%v event=%q)", ok, ev)
	}
	w2, r2 := policyRequest("")
	if _, _, ok := gw.policyPreUpstream(w2, r2, "chat", "gpt-4o", "openai", body); ok {
		t.Error("matching attachment must run the policy")
	}
	w3, r3 := policyRequest("")
	if _, ev, ok := gw.policyPreUpstream(w3, r3, "messages", "gpt-4o", "anthropic", body); !ok || ev != "" {
		t.Errorf("endpoint mismatch must skip the policy (ok=%v event=%q)", ok, ev)
	}
}

// TestPolicyRuntime_BrokenPolicySkipped: a broken active policy rejects the
// whole candidate instead of installing a valid sibling as a partial set.
func TestPolicyRuntime_BrokenPolicySkipped(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "bad-1", OrgID: testOrg, Name: "broken", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: "apiVersion: ypp/v1\nkind: Garbage\n"}, []adminstore.PolicyAttachment{chatAttachment(1)})
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "good-1", OrgID: testOrg, Name: "deny-sec", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("deny-sec", "forbidden-secret")}, []adminstore.PolicyAttachment{chatAttachment(2)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	plans, _, err := rt.load(context.Background(), testOrg)
	if err == nil {
		t.Fatal("invalid active policy candidate must fail as a whole")
	}
	if len(plans) != 0 {
		t.Fatalf("invalid candidate returned %d partial plans, want none", len(plans))
	}
}

// --- decide DSL -----------------------------------------------------------------

func decideStep(t *testing.T, src string) pipeline.Step {
	t.Helper()
	st, err := policydecide.Factory(map[string]any{"expr": src})
	if err != nil {
		t.Fatalf("decide factory: %v", err)
	}
	return st
}

func runDecide(t *testing.T, src string, findings ...pipeline.Finding) pipeline.Action {
	t.Helper()
	st := decideStep(t, src)
	out := &pipeline.Result{Verdict: pipeline.ActionAllow, Findings: findings}
	if err := st.Run(context.Background(), &pipeline.Pipeline{}, nil, out); err != nil {
		t.Fatalf("run: %v", err)
	}
	return out.Verdict
}

func TestPolicyDecide_PackGrammar(t *testing.T) {
	src := "deny  if findings.any(f -> f.category matches 'secrets.*' and f.severity == 'high')\n" +
		"mask  if findings.any(f -> f.action == 'mask')\n" +
		"flag  otherwise\n"
	if got := runDecide(t, src, pipeline.Finding{Category: "secrets.aws-key", Severity: "high", Action: pipeline.ActionFlag}); got != pipeline.ActionDeny {
		t.Errorf("high secret finding → %s, want deny", got)
	}
	if got := runDecide(t, src, pipeline.Finding{Category: "innsnils", Severity: "medium", Action: pipeline.ActionMask}); got != pipeline.ActionMask {
		t.Errorf("mask finding → %s, want mask", got)
	}
	if got := runDecide(t, src); got != pipeline.ActionFlag {
		t.Errorf("no findings → %s, want flag (otherwise)", got)
	}
	if got := runDecide(t, src, pipeline.Finding{Category: "innsnils", Severity: "high", Action: pipeline.ActionFlag}); got != pipeline.ActionFlag {
		t.Errorf("high non-secret finding → %s, want flag (category pattern must not match)", got)
	}
}

func TestPolicyDecide_FactoryErrors(t *testing.T) {
	for _, src := range []string{
		"",
		"explode if findings.any(f -> f.x == 'y')",
		"deny if findings.any(f -> f.bogus == 'x')",
		"deny unless nothing",
		"deny  if findings.any(f -> f.severity == 'high'\n",
	} {
		if _, err := policydecide.Factory(map[string]any{"expr": src}); err == nil {
			t.Errorf("src %q: want a factory (load) error", src)
		}
	}
}

// TestEventPolicyContractShape pins the OP-9 contract: the Event.Policy field
// decodes as a JSON array of decision objects.
func TestEventPolicyContractShape(t *testing.T) {
	raw := marshalPolicyDecisions([]policyDecision{{
		PolicyID: "p1", Name: "pack", Version: 2, EffectiveHash: strings.Repeat("a", 64), Mode: "shadow", Verdict: "flag",
		Findings:   []policyFinding{{Step: "scan.pii", Category: "innsnils", Severity: "high", Action: "deny"}},
		DurationMs: 3,
	}})
	decisions := parseDecisions(t, raw)
	if len(decisions) != 1 || decisions[0].PolicyID != "p1" || decisions[0].Version != 2 || decisions[0].EffectiveHash != strings.Repeat("a", 64) ||
		decisions[0].Mode != "shadow" || decisions[0].Verdict != "flag" || decisions[0].DurationMs != 3 ||
		len(decisions[0].Findings) != 1 || decisions[0].Findings[0].Category != "innsnils" {
		t.Fatalf("contract round-trip failed: %s (%+v)", raw, decisions)
	}
	if marshalPolicyDecisions(nil) != "" {
		t.Fatal("no decisions must marshal to an empty payload")
	}
	if got := appendPolicyEvents(`[{"policy_id":"a"}]`, `[{"policy_id":"b"}]`); !strings.Contains(got, `"a"`) || !strings.Contains(got, `"b"`) {
		t.Errorf("appendPolicyEvents merge failed: %s", got)
	}
	if got := appendPolicyEvents("not-json", `[{"policy_id":"b"}]`); got != `[{"policy_id":"b"}]` {
		t.Errorf("appendPolicyEvents must degrade to the newer payload: %s", got)
	}
}

// --- YAML helpers ----------------------------------------------------------------

func denyWordYAML(name, word string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: word\n    detector: builtin/contains\n    params:\n      words: [\"" + word + "\"]\n      action: deny\n"
}

func flagWordYAML(name, word string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: word\n    detector: builtin/contains\n    params:\n      words: [\"" + word + "\"]\n      action: flag\n"
}

func denyEverythingYAML() string {
	return denyWordYAML("deny-sec", "forbidden-secret")
}

// fakePromptStudio is the prompt-studio seam double: per-org prompt templates
// and partial bodies, keyed by "<org>|<ref>". JudgePromptSource/PartialsLookup
// hand out org-scoped views, mirroring adminstore.Store's methods.
type fakePromptStudio struct {
	mu       sync.Mutex
	prompts  map[string]string // "<org>|<name>@<label>" → template body
	versions map[string]string // "<org>|<name>@<label>" → template version identifier
	partials map[string]map[string]string
}

func newFakePromptStudio() *fakePromptStudio {
	return &fakePromptStudio{prompts: map[string]string{}, versions: map[string]string{}, partials: map[string]map[string]string{}}
}

func (f *fakePromptStudio) setPrompt(org, ref, body string) {
	f.setPromptVersion(org, ref, "1", body)
}

// setPromptVersion stores the template with an explicit version identifier —
// the value a store-backed source reports for the bound immutable version
// (the D2 X-Policy-Judge-Version header input).
func (f *fakePromptStudio) setPromptVersion(org, ref, version, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := org + "|" + ref
	f.prompts[key] = body
	f.versions[key] = version
}

func (f *fakePromptStudio) setPartial(org, name, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.partials[org] == nil {
		f.partials[org] = map[string]string{}
	}
	f.partials[org][name] = body
}

func (f *fakePromptStudio) JudgePromptSource(orgID string) llmjudge.PromptSource {
	return fakeOrgPrompts{f: f, orgID: orgID}
}

func (f *fakePromptStudio) PartialsLookup(orgID string) adminstore.PartialsSource {
	return fakeOrgPartials{f: f, orgID: orgID}
}

// fakeOrgPrompts resolves the org: prefix grammar like adminstore's
// orgJudgePrompts; non-org refs fall through to the embedded source.
type fakeOrgPrompts struct {
	f     *fakePromptStudio
	orgID string
}

func (p fakeOrgPrompts) Load(ctx context.Context, ref string) (llmjudge.Prompt, error) {
	if !strings.HasPrefix(ref, adminstore.OrgPromptRefPrefix) {
		return llmjudge.EmbeddedPromptSource{}.Load(ctx, ref)
	}
	body := strings.TrimPrefix(ref, adminstore.OrgPromptRefPrefix)
	at := strings.LastIndex(body, "@")
	if at <= 0 || at == len(body)-1 {
		return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: want <name>@<label>", ref)
	}
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	key := p.orgID + "|" + body
	tpl, ok := p.f.prompts[key]
	if !ok {
		if _, parseErr := strconv.Atoi(body[at+1:]); parseErr == nil {
			return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: immutable version %s for prompt %q is missing in this org", ref, body[at+1:], body[:at])
		}
		return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: no prompt with label %q in this org", ref, body[at+1:])
	}
	return llmjudge.Prompt{Ref: ref, Version: p.f.versions[key], Body: tpl}, nil
}

type fakeOrgPartials struct {
	f     *fakePromptStudio
	orgID string
}

func (l fakeOrgPartials) Get(_ context.Context, name string) (string, bool, error) {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	body, ok := l.f.partials[l.orgID][name]
	return body, ok, nil
}

// captureJudgeClient records every judge call's system prompt and answers
// with a fixed empty-findings verdict (allow, no findings).
type captureJudgeClient struct {
	mu       sync.Mutex
	response string
	systems  []string
}

func (c *captureJudgeClient) JudgeChat(_ context.Context, req llmjudge.ChatRequest) (llmjudge.ChatResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(req.Messages) > 0 {
		c.systems = append(c.systems, req.Messages[0].Content)
	}
	return llmjudge.ChatResponse{Content: c.response, Model: "stub-judge"}, nil
}

func (c *captureJudgeClient) systemPrompts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.systems...)
}

func orgJudgeYAML(name, promptRef string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: judge\n    llm_judge:\n      model: \"$(sovereign-classifier)\"\n      prompt_ref: \"" + promptRef + "\"\n    on_error: fail_open+flag\n"
}

func partialsSubstituteYAML(name string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: partials\n    mutator: builtin/partials-substitute\n    params:\n      on_missing: error\n"
}

// stub judge client installed (as buildPolicyRuntime does when the structural
// assertion passes). The store is the reader interface so snapshot-reading
func wiredRuntime(t *testing.T, store PolicyPipelineReader, versions PolicyVersionReader, studio *fakePromptStudio, judge llmjudge.JudgeClient) *PolicyRuntime {
	t.Helper()
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	rt.sources = studio
	rt.orgJudgeDeps = llmjudge.Deps{Client: judge}
	return rt
}

// wiredRuntimeLogged is wiredRuntime over a buffered slog logger, for
func wiredRuntimeLogged(t *testing.T, store PolicyPipelineReader, versions PolicyVersionReader, studio *fakePromptStudio, judge llmjudge.JudgeClient, buf *bytes.Buffer) *PolicyRuntime {
	t.Helper()
	rt, err := NewPolicyRuntime(store, versions, PolicyModeEnforce, nil, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatalf("NewPolicyRuntime: %v", err)
	}
	rt.sources = studio
	rt.orgJudgeDeps = llmjudge.Deps{Client: judge}
	return rt
}

func chatJudgeQuery() (policyQuery, *pipeline.Payload) {
	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	meta := policyMeta(testOrg, "key-1", "gpt-4o", "openai")
	q := policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "gpt-4o"}
	return q, policyRequestPayload("chat", body, meta)
}

// TestPolicyRuntimeOrgJudgePromptWired pins the acceptance criterion: with the
// sources wired, the judge system prompt is the org template rendered over the
// actual request input, byte-stable across requests, and only re-rendered from
// new template bytes after the version-key reload.
func TestPolicyRuntimeOrgJudgePromptWired(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "Classify this input for toxicity: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	capture := &captureJudgeClient{response: `{"findings":[]}`}
	rt := wiredRuntime(t, store, versions, studio, capture)

	q, in := chatJudgeQuery()
	want := "Classify this input for toxicity: hello"

	decisions, _, denied := rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 {
		t.Fatalf("wired org judge: denied=%v decisions=%d, want one allow decision", denied, len(decisions))
	}
	if got := capture.systemPrompts(); len(got) != 1 || got[0] != want {
		t.Fatalf("judge saw system prompts %q, want exactly [%q]", got, want)
	}

	// Second request on the same compiled policy: byte-identical prompt.
	rt.evaluate(context.Background(), testOrg, q, in)
	got := capture.systemPrompts()
	if len(got) != 2 || got[1] != want {
		t.Fatalf("second request rendered %q, want identical %q", got, want)
	}

	// Prompt movement alone and a policy reload do NOT change the immutable
	// activation snapshot.
	studio.setPrompt(testOrg, "toxicity@active", "Classify v2: {{ .Input }}")
	rt.evaluate(context.Background(), testOrg, q, in)
	if got := capture.systemPrompts(); len(got) != 3 || got[2] != want {
		t.Fatalf("re-promotion without reload rendered %q, want still pinned %q", got, want)
	}
	versions.bump(testOrg)
	decisions, _, denied = rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 {
		t.Fatalf("reloaded org judge: denied=%v decisions=%d, want one allow decision", denied, len(decisions))
	}
	if got := capture.systemPrompts(); len(got) != 4 || got[3] != want {
		t.Fatalf("post-reload rendered prompts %q, want activation-pinned bytes", got)
	}
	store.mu.Lock()
	store.policies[testOrg][0].CurrentVersion = 2
	store.versions[testOrg]["org-judge"][2] = orgJudgeYAML("org-judge", "org:toxicity@active")
	store.mu.Unlock()
	versions.bump(testOrg)
	rt.evaluate(context.Background(), testOrg, q, in)
	if got := capture.systemPrompts(); len(got) != 5 || got[4] != "Classify v2: hello" {
		t.Fatalf("reactivated prompt rendered %q, want explicitly re-resolved bytes", got)
	}
}

// TestPolicyRuntimeOrgJudgeRefUnknownFailsLoad proves the org prompt source is
// actually consulted at compile time (the G1 hole would compile fine against
// the embedded defaults): an unknown label — or a prompt that exists only in
// another org — rejects the candidate as invalidPolicyConfig(step_compile)
// with no plans.
func TestPolicyRuntimeOrgJudgeRefUnknownFailsLoad(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:ghost@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt("org-2", "ghost@active", "foreign-org template") // exists, but in another org
	rt := wiredRuntime(t, store, &fakePolicyVersions{}, studio, &captureJudgeClient{response: `{"findings":[]}`})

	plans, _, err := rt.load(context.Background(), testOrg)
	if len(plans) != 0 || err == nil {
		t.Fatalf("unknown/foreign org ref: plans=%d err=%v, want load failure with no plans", len(plans), err)
	}
	var cfgErr *policyConfigError
	if !errors.As(err, &cfgErr) || cfgErr.stage != policyConfigStageStepCompile {
		t.Fatalf("error = %v (%T), want invalidPolicyConfig(step_compile)", err, err)
	}
}

func TestPolicyRuntimeMissingImmutablePromptVersionReportsCause(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{ID: "missing-prompt-version", OrgID: testOrg, Name: "missing-prompt-version", Enabled: true, CurrentVersion: 1},
		map[int]string{1: orgJudgeYAML("missing-prompt-version", "org:toxicity@99")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := wiredRuntime(t, store, &fakePolicyVersions{}, newFakePromptStudio(), &captureJudgeClient{response: `{"findings":[]}`})
	plans, _, err := rt.load(context.Background(), testOrg)
	if len(plans) != 0 || err == nil || !strings.Contains(err.Error(), "immutable version 99") {
		t.Fatalf("missing immutable prompt version: plans=%d err=%v, want activation failure with precise version reason", len(plans), err)
	}
}

// TestPolicyRuntimePartialsSourceInjected pins the other wiring half: with
// sources wired, builtin/partials-substitute receives the org partials source
// through the step "source" param and substitutes bodies at run time.
func TestPolicyRuntimePartialsSourceInjected(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "partials", OrgID: testOrg, Name: "partials", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: partialsSubstituteYAML("partials")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPartial(testOrg, "greeting", "HELLO")
	rt := wiredRuntime(t, store, &fakePolicyVersions{}, studio, &captureJudgeClient{response: `{"findings":[]}`})

	q := policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "gpt-4o"}
	in := &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Body:     []byte("Hi {{partials.greeting}}"),
		Meta:     policyMeta(testOrg, "key-1", "gpt-4o", "openai"),
	}
	_, mutated, denied := rt.evaluate(context.Background(), testOrg, q, in)
	if denied {
		t.Fatal("partials substitution must not deny")
	}
	if mutated == nil || string(mutated.Body) != "Hi HELLO" {
		got := "<nil>"
		if mutated != nil {
			got = string(mutated.Body)
		}
		t.Fatalf("mutated body = %q, want %q", got, "Hi HELLO")
	}
}

// default on_missing=skip the NoopPartials stub resolves nothing, so partials
// tokens pass through verbatim; nothing denied, nothing mutated. (With an
// explicit on_missing=error the CURRENT unwired behavior is a fail-closed
func TestPolicyRuntimePartialsUnwiredStaysNoop(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "partials", OrgID: testOrg, Name: "partials", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: "apiVersion: ypp/v1\nkind: Policy\nname: partials\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n  - id: partials\n    mutator: builtin/partials-substitute\n"}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce) // sources stay nil

	q := policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "gpt-4o"}
	in := &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Body:     []byte("Hi {{partials.greeting}}"),
		Meta:     policyMeta(testOrg, "key-1", "gpt-4o", "openai"),
	}
	_, mutated, denied := rt.evaluate(context.Background(), testOrg, q, in)
	if denied || mutated != nil {
		t.Fatalf("unwired runtime: denied=%v mutated=%v, want no-op pass-through", denied, mutated)
	}
}

// TestPromptStudioSourcesAssertion pins the structural-assertion seam
// semantics: nil is feature-off; a zero adminstore store asserts the surface
// (also covered compile-time by the var _ promptStudioSources guard).
func TestPromptStudioSourcesAssertion(t *testing.T) {
	if srcs, ok := promptStudioSourcesFrom(nil); ok || srcs != nil {
		t.Fatalf("nil store: (%v, %v), want feature-off", srcs, ok)
	}
	if _, ok := promptStudioSourcesFrom(&adminstore.Store{}); !ok {
		t.Fatal("*adminstore.Store must assert the prompt-studio surface")
	}
}

// TestPolicyRuntimeJudgePromptVersionSurfaced pins the D2 runtime surface: the
// version identifier resolved at compile time is cached with the org entry,
// stays stable across requests, and follows the version-key reload (a label
// re-point to a new template version) exactly like the compiled template
// bytes. Orgs whose candidate has no judge — and unknown orgs — report "".
func TestPolicyRuntimeJudgePromptVersionSurfaced(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	store.add("org-plain", adminstore.PolicyPipeline{
		ID: "plain", OrgID: "org-plain", Name: "plain", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("plain", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPromptVersion(testOrg, "toxicity@active", "7", "v7: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	rt := wiredRuntime(t, store, versions, studio, &captureJudgeClient{response: `{"findings":[]}`})

	if got := rt.judgePromptVersion(context.Background(), testOrg); got != "7" {
		t.Fatalf("judgePromptVersion = %q, want the resolved template version %q", got, "7")
	}
	if got := rt.judgePromptVersion(context.Background(), testOrg); got != "7" {
		t.Fatalf("cached judgePromptVersion = %q, want stable %q", got, "7")
	}
	if got := rt.judgePromptVersion(context.Background(), "org-plain"); got != "" {
		t.Fatalf("judge-less org judgePromptVersion = %q, want empty", got)
	}
	if got := rt.judgePromptVersion(context.Background(), "org-unknown"); got != "" {
		t.Fatalf("unknown org judgePromptVersion = %q, want empty", got)
	}
	if got := rt.judgePromptVersion(context.Background(), ""); got != "" {
		t.Fatalf("empty org judgePromptVersion = %q, want empty", got)
	}

	// Label re-point and a policy cache reload do not change the activated
	// prompt snapshot. A new policy version represents explicit re-activation.
	studio.setPromptVersion(testOrg, "toxicity@active", "8", "v8: {{ .Input }}")
	if got := rt.judgePromptVersion(context.Background(), testOrg); got != "7" {
		t.Fatalf("re-point without reload = %q, want still pinned %q", got, "7")
	}
	versions.bump(testOrg)
	if got := rt.judgePromptVersion(context.Background(), testOrg); got != "7" {
		t.Fatalf("post-reload judgePromptVersion = %q, want pinned %q", got, "7")
	}
	store.mu.Lock()
	store.policies[testOrg][0].CurrentVersion = 2
	store.versions[testOrg]["org-judge"][2] = orgJudgeYAML("org-judge", "org:toxicity@active")
	store.mu.Unlock()
	versions.bump(testOrg)
	if got := rt.judgePromptVersion(context.Background(), testOrg); got != "8" {
		t.Fatalf("reactivated judgePromptVersion = %q, want %q", got, "8")
	}
}

// TestPolicyRuntimeJudgePromptVersionWiring pins the absence-when-unwired
// contract and the embedded fall-through: an embedded judge ref resolved
// through a WIRED org source surfaces its parsed ref version; the same
// policy on an UNWIRED runtime keeps the value empty (pre-D2 behavior
// bit-for-bit). A cold-unavailable runtime never reports a version either.
func TestPolicyRuntimeJudgePromptVersionWiring(t *testing.T) {
	newEmbeddedJudgeOrg := func() *fakePolicyStore {
		store := newFakePolicyStore()
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: "embedded-judge", OrgID: testOrg, Name: "embedded-judge", Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: orgJudgeYAML("embedded-judge", "judges/toxicity@2")}, []adminstore.PolicyAttachment{chatAttachment(1)})
		return store
	}

	rt := wiredRuntime(t, newEmbeddedJudgeOrg(), &fakePolicyVersions{}, newFakePromptStudio(), &captureJudgeClient{response: `{"findings":[]}`})
	if got := rt.judgePromptVersion(context.Background(), testOrg); got != "2" {
		t.Fatalf("wired embedded judge version = %q, want %q", got, "2")
	}

	unwired := newTestRuntime(t, newEmbeddedJudgeOrg(), &fakePolicyVersions{}, PolicyModeEnforce)
	if got := unwired.judgePromptVersion(context.Background(), testOrg); got != "" {
		t.Fatalf("unwired runtime judge version = %q, want empty (header absent)", got)
	}
	cold := newUnavailablePolicyRuntime(PolicyModeEnforce, PolicyColdFailureFailClosed, testLogger())
	if got := cold.judgePromptVersion(context.Background(), testOrg); got != "" {
		t.Fatal("cold-unavailable runtime must report no judge version")
	}
}

// TestChatResponseJudgeVersionHeader drives the actual response emission: the
// header carries the org's resolved judge template version and is ABSENT
// (never set empty) when no judge resolved or the runtime is off/unwired.
func TestChatResponseJudgeVersionHeader(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPromptVersion(testOrg, "toxicity@active", "11", "v11: {{ .Input }}")
	rt := wiredRuntime(t, store, &fakeOrgPolicyVersions{versions: map[string]int64{}}, studio, &captureJudgeClient{response: `{"findings":[]}`})

	rec := httptest.NewRecorder()
	testHookGateway(rt).setJudgeVersionHeader(context.Background(), rec, testOrg)
	if got := rec.Header().Get(judgeVersionHeaderKey); got != "11" {
		t.Fatalf("%s = %q, want %q", judgeVersionHeaderKey, got, "11")
	}

	rec = httptest.NewRecorder()
	testHookGateway(rt).setJudgeVersionHeader(context.Background(), rec, "org-plain")
	if got := rec.Header().Get(judgeVersionHeaderKey); got != "" {
		t.Fatalf("judge-less org header = %q, want absent", got)
	}

	unwired := testHookGateway(newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{}, PolicyModeEnforce))
	rec = httptest.NewRecorder()
	unwired.setJudgeVersionHeader(context.Background(), rec, testOrg)
	if got := rec.Header().Get(judgeVersionHeaderKey); got != "" {
		t.Fatalf("unwired runtime header = %q, want absent", got)
	}

	rec = httptest.NewRecorder()
	testHookGateway(nil).setJudgeVersionHeader(context.Background(), rec, testOrg)
	if got := rec.Header().Get(judgeVersionHeaderKey); got != "" {
		t.Fatalf("nil runtime header = %q, want absent", got)
	}
}

// setActiveVersion moves the org's active pointer for one stored policy (the
// admin "promote version" operation a reload observes).
func (f *fakePolicyStore) setActiveVersion(org, policyID string, version int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.policies[org] {
		if f.policies[org][i].ID == policyID {
			f.policies[org][i].CurrentVersion = version
		}
	}
}

// setVersionYAML stores one immutable version's YAML for a policy.
func (f *fakePolicyStore) setVersionYAML(org, policyID string, version int, y string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.versions[org] == nil {
		f.versions[org] = map[string]map[int]string{}
	}
	if f.versions[org][policyID] == nil {
		f.versions[org][policyID] = map[int]string{}
	}
	f.versions[org][policyID][version] = y
}

// ctxHonoringStore models a snapshot reader that honors ctx before reading
// (the adminstore contract); the bare fake ignores a canceled context.
type ctxHonoringStore struct{ *fakePolicyStore }

func (s ctxHonoringStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return adminstore.PolicyPipelineSnapshot{}, err
	}
	return s.fakePolicyStore.LoadPolicySnapshot(ctx, orgID)
}

// TestPolicyRuntimeOrgJudgeBrokenReloadKeepsStaleThenRecovers pins the error
// contract end to end: a promoted candidate whose org ref cannot resolve
// never replaces the cached plans — the stale pinned judge template keeps
// serving through repeated requests — and the fix goes live only through the
// version-key reload. Partial/unknown state is never counted as success.
func TestPolicyRuntimeOrgJudgeBrokenReloadKeepsStaleThenRecovers(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{
		1: orgJudgeYAML("org-judge", "org:toxicity@active"),
		2: orgJudgeYAML("org-judge", "org:ghost@active"),
	}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "v1: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	capture := &captureJudgeClient{response: `{"findings":[]}`}
	rt := wiredRuntime(t, store, versions, studio, capture)
	q, in := chatJudgeQuery()

	decisions, _, denied := rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 || decisions[0].Version != 1 {
		t.Fatalf("warm: denied=%v decisions=%+v, want one judge v1 decision", denied, decisions)
	}

	store.setActiveVersion(testOrg, "org-judge", 2)
	versions.bump(testOrg)
	for i := 0; i < 2; i++ {
		decisions, _, denied = rt.evaluate(context.Background(), testOrg, q, in)
		if denied || len(decisions) != 1 || decisions[0].Version != 1 {
			t.Fatalf("broken reload %d: denied=%v decisions=%+v, want stale judge v1", i, denied, decisions)
		}
	}
	if got := capture.systemPrompts(); len(got) != 3 || got[2] != "v1: hello" {
		t.Fatalf("prompts during broken window %q, want stale v1 bytes", got)
	}

	studio.setPrompt(testOrg, "toxicity@active", "v2: {{ .Input }}")
	store.setVersionYAML(testOrg, "org-judge", 3, orgJudgeYAML("org-judge", "org:toxicity@active"))
	store.setActiveVersion(testOrg, "org-judge", 3)
	versions.bump(testOrg)
	decisions, _, denied = rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 || decisions[0].Version != 3 {
		t.Fatalf("recovered: denied=%v decisions=%+v, want judge v3", denied, decisions)
	}
	if got := capture.systemPrompts(); len(got) != 4 || got[3] != "v2: hello" {
		t.Fatalf("prompts after fix %q, want recovered v2 bytes", got)
	}
}

// TestPolicyRuntimeOrgJudgeCandidateAllOrNothing proves the candidate is
// atomic: one member with an unresolvable org ref rejects the whole reload,
// so the valid member is never adopted without its broken sibling — both
// stale plans (including the broken policy's own last-good version) keep
// serving until a fully valid candidate loads.
func TestPolicyRuntimeOrgJudgeCandidateAllOrNothing(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "judge-a", OrgID: testOrg, Name: "judge-a", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("judge-a", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "judge-b", OrgID: testOrg, Name: "judge-b", Enabled: true, CurrentVersion: 1,
	}, map[int]string{
		1: orgJudgeYAML("judge-b", "org:safety@active"),
		2: orgJudgeYAML("judge-b", "org:ghost@active"),
	}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "toxicity: {{ .Input }}")
	studio.setPrompt(testOrg, "safety@active", "safety: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	rt := wiredRuntime(t, store, versions, studio, &captureJudgeClient{response: `{"findings":[]}`})
	q, in := chatJudgeQuery()

	decisions, _, denied := rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 2 {
		t.Fatalf("warm: denied=%v decisions=%d, want two allows", denied, len(decisions))
	}

	store.setActiveVersion(testOrg, "judge-b", 2)
	versions.bump(testOrg)
	decisions, _, denied = rt.evaluate(context.Background(), testOrg, q, in)
	if denied {
		t.Fatal("stale retention must not deny")
	}
	ids := map[string]int{}
	for _, d := range decisions {
		ids[d.PolicyID] = d.Version
	}
	if len(ids) != 2 || ids["judge-a"] != 1 || ids["judge-b"] != 1 {
		t.Fatalf("stale decisions %v, want judge-a v1 AND judge-b v1 (no partial adoption)", ids)
	}
}

// TestPolicyRuntimeOrgJudgeMalformedRefFailsLoad covers the invalid-input
// boundary: an org ref without a <name>@<label> tail is a compile-time load
// error (step_compile), never a silent skip or a request-time surprise.
func TestPolicyRuntimeOrgJudgeMalformedRefFailsLoad(t *testing.T) {
	for name, ref := range map[string]string{
		"no label":    "org:nolabel",
		"empty name":  "org:@active",
		"trailing at": "org:name@",
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakePolicyStore()
			store.add(testOrg, adminstore.PolicyPipeline{
				ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
			}, map[int]string{1: orgJudgeYAML("org-judge", ref)}, []adminstore.PolicyAttachment{chatAttachment(1)})
			studio := newFakePromptStudio()
			rt := wiredRuntime(t, store, &fakePolicyVersions{}, studio, &captureJudgeClient{response: `{"findings":[]}`})

			plans, _, err := rt.load(context.Background(), testOrg)
			if len(plans) != 0 || err == nil {
				t.Fatalf("ref %q: plans=%d err=%v, want load failure with no plans", ref, len(plans), err)
			}
			var cfgErr *policyConfigError
			if !errors.As(err, &cfgErr) || cfgErr.stage != policyConfigStageStepCompile {
				t.Fatalf("ref %q: error %v (%T), want invalidPolicyConfig(step_compile)", ref, err, err)
			}
		})
	}
}

// TestPolicyRuntimePartialsCycleSinglePass pins the cycle boundary (contract
// §4.3): a partial whose body names itself is inserted once, verbatim, and
// never rescanned — no recursion, no hang, no on_missing error.
func TestPolicyRuntimePartialsCycleSinglePass(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "partials", OrgID: testOrg, Name: "partials", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: partialsSubstituteYAML("partials")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPartial(testOrg, "a", "a={{partials.a}}")
	rt := wiredRuntime(t, store, &fakePolicyVersions{}, studio, &captureJudgeClient{response: `{"findings":[]}`})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q := policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "gpt-4o"}
	in := &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Body:     []byte("X {{partials.a}} Y"),
		Meta:     policyMeta(testOrg, "key-1", "gpt-4o", "openai"),
	}
	_, mutated, denied := rt.evaluate(ctx, testOrg, q, in)
	if denied {
		t.Fatal("cycle boundary must not deny")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("substitution did not terminate within the context bound: %v", err)
	}
	if mutated == nil || string(mutated.Body) != "X a={{partials.a}} Y" {
		got := "<nil>"
		if mutated != nil {
			got = string(mutated.Body)
		}
		t.Fatalf("cycle body = %q, want single verbatim insertion %q", got, "X a={{partials.a}} Y")
	}
}

// TestPolicyRuntimeLoadCanceledColdCachesNothing pins the interruption
// boundary on a cold org: a canceled context during load is not a success —
// no verdict, nothing cached — the failure is classified context_canceled in
// the load-failure record, and the org recovers on the next healthy request.
func TestPolicyRuntimeLoadCanceledColdCachesNothing(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "v1: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	var buf bytes.Buffer
	rt := wiredRuntimeLogged(t, ctxHonoringStore{store}, versions, studio, &captureJudgeClient{response: `{"findings":[]}`}, &buf)
	q, in := chatJudgeQuery()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decisions, mutated, denied := rt.evaluate(ctx, testOrg, q, in)
	if denied || decisions != nil || mutated != nil {
		t.Fatalf("canceled cold load: denied=%v decisions=%v mutated=%v, want no verdict", denied, decisions, mutated)
	}
	if rt.hasSnapshot(testOrg) {
		t.Fatal("interrupted load must not cache a candidate")
	}
	for _, want := range []string{"policy load failed", "failure_class=context_canceled", "cache_state=cold"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("load-failure record missing %q in:\n%s", want, buf.String())
		}
	}

	decisions, _, denied = rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 {
		t.Fatalf("recovery after cancel: denied=%v decisions=%d, want one allow", denied, len(decisions))
	}
}

// TestPolicyRuntimeLoadCanceledWarmKeepsStale pins availability under
// interruption: with a usable cached entry, a version bump whose reload is
// canceled by the request context keeps serving the stale pinned template —
// a failed refresh never evicts or replaces a usable stale entry.
func TestPolicyRuntimeLoadCanceledWarmKeepsStale(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "v1: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	capture := &captureJudgeClient{response: `{"findings":[]}`}
	rt := wiredRuntime(t, ctxHonoringStore{store}, versions, studio, capture)
	q, in := chatJudgeQuery()

	decisions, _, denied := rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 {
		t.Fatalf("warm: denied=%v decisions=%d, want one allow", denied, len(decisions))
	}

	versions.bump(testOrg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decisions, _, denied = rt.evaluate(ctx, testOrg, q, in)
	if denied || len(decisions) != 1 || decisions[0].PolicyID != "org-judge" || decisions[0].Version != 1 {
		t.Fatalf("canceled reload: denied=%v decisions=%+v, want stale judge v1 served", denied, decisions)
	}
	if got := capture.systemPrompts(); len(got) != 1 {
		t.Fatalf("judge calls %q, want only the warm one (the engine skips steps on a canceled request context)", got)
	}

	decisions, _, denied = rt.evaluate(context.Background(), testOrg, q, in)
	if denied || len(decisions) != 1 || decisions[0].Version != 1 {
		t.Fatalf("reload after interruption: denied=%v decisions=%+v, want judge v1", denied, decisions)
	}
	if got := capture.systemPrompts(); len(got) != 2 || got[1] != "v1: hello" {
		t.Fatalf("prompts after interrupted reload %q, want the pinned v1 bytes", got)
	}
}

// TestPolicyRuntimeLoadFailureRecordHasStage pins the diagnosable-cause
// contract for the wired failure path: an unresolvable org ref is logged as
// failure_class=invalid_config with the compile stage and the stale cache
// state — a diagnosable failure cause, never a silent skip.
func TestPolicyRuntimeLoadFailureRecordHasStage(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{
		1: orgJudgeYAML("org-judge", "org:toxicity@active"),
		2: orgJudgeYAML("org-judge", "org:ghost@active"),
	}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "v1: {{ .Input }}")
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{}}
	var buf bytes.Buffer
	rt := wiredRuntimeLogged(t, store, versions, studio, &captureJudgeClient{response: `{"findings":[]}`}, &buf)
	q, in := chatJudgeQuery()

	if decisions, _, denied := rt.evaluate(context.Background(), testOrg, q, in); denied || len(decisions) != 1 {
		t.Fatalf("warm: denied=%v decisions=%d, want one allow", denied, len(decisions))
	}
	store.setActiveVersion(testOrg, "org-judge", 2)
	versions.bump(testOrg)
	if _, _, denied := rt.evaluate(context.Background(), testOrg, q, in); denied {
		t.Fatal("stale retention must not deny")
	}
	for _, want := range []string{"policy load failed", "failure_class=invalid_config", "stage=step_compile", "cache_state=stale"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("load-failure record missing %q in:\n%s", want, buf.String())
		}
	}
}
