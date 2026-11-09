package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

type countingPolicyReader struct {
	PolicyPipelineReader
	listCalls atomic.Int64
}

type faultPolicyReader struct {
	PolicyPipelineReader
	listErr        error
	versionErr     error
	attachmentsErr error
}

func (s *faultPolicyReader) ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.PolicyPipelineReader.ListPolicies(ctx, orgID)
}

func (s *faultPolicyReader) GetPolicyVersion(ctx context.Context, orgID, policyID string, version int) (adminstore.PolicyVersion, error) {
	if s.versionErr != nil {
		return adminstore.PolicyVersion{}, s.versionErr
	}
	return s.PolicyPipelineReader.GetPolicyVersion(ctx, orgID, policyID, version)
}

func (s *faultPolicyReader) ListPolicyAttachments(ctx context.Context, orgID, policyID string) ([]adminstore.PolicyAttachment, error) {
	if s.attachmentsErr != nil {
		return nil, s.attachmentsErr
	}
	return s.PolicyPipelineReader.ListPolicyAttachments(ctx, orgID, policyID)
}

func (s *countingPolicyReader) ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	s.listCalls.Add(1)
	return s.PolicyPipelineReader.ListPolicies(ctx, orgID)
}

func TestPolicyRuntime_InvalidCandidateIsAtomic(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "valid-1", OrgID: testOrg, Name: "valid", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("valid", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	prior := rt.refreshWithOutcome(context.Background(), testOrg, nil, rt.now()).entry
	if prior == nil {
		t.Fatal("valid initial policy candidate was not installed")
	}

	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "invalid-1", OrgID: testOrg, Name: "invalid", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: "apiVersion: ypp/v1\nkind: Garbage\n"}, []adminstore.PolicyAttachment{chatAttachment(2)})

	plans, _, err := rt.load(context.Background(), testOrg)
	if err == nil {
		t.Fatal("invalid active member must reject the candidate")
	}
	if len(plans) != 0 {
		t.Fatalf("invalid candidate returned %d partial plans, want none", len(plans))
	}

	refresh := rt.refreshWithOutcome(context.Background(), testOrg, prior, prior.loadedAt.Add(rt.ttl))
	if refresh.loadErr == nil || !refresh.stale {
		t.Fatalf("invalid refresh outcome = %+v, want load error retaining stale snapshot", refresh)
	}
	if refresh.entry != prior {
		t.Fatal("invalid refresh replaced the last-good snapshot")
	}
	rt.mu.Lock()
	installed := rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != prior {
		t.Fatal("invalid refresh published a partial candidate")
	}
}

func TestPolicyRuntime_UnknownStepCompileRejectsCandidate(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "valid-1", OrgID: testOrg, Name: "valid", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("valid", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	unknownStep := strings.Replace(
		denyWordYAML("invalid-step", "marker"),
		"builtin/contains", "builtin/not-registered", 1,
	)
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "invalid-step", OrgID: testOrg, Name: "invalid-step", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: unknownStep}, []adminstore.PolicyAttachment{chatAttachment(2)})

	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	plans, _, err := rt.load(context.Background(), testOrg)
	if err == nil {
		t.Fatal("unknown step in an attached active policy must reject the candidate")
	}
	var configErr *policyConfigError
	if !errors.As(err, &configErr) || configErr.stage != policyConfigStageStepCompile {
		t.Fatalf("unknown step error = %T %v, want bounded step_compile classification", err, err)
	}
	if len(plans) != 0 {
		t.Fatalf("compile-invalid candidate returned %d partial plans, want none", len(plans))
	}
}

func TestPolicyRuntime_EmptyAndNonApplicablePolicySets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies []adminstore.PolicyPipeline
		versions map[int]string
		atts     []adminstore.PolicyAttachment
	}{
		{name: "empty list"},
		{
			name: "disabled attached policy",
			policies: []adminstore.PolicyPipeline{{
				ID: "disabled", OrgID: testOrg, Name: "disabled", Enabled: false, CurrentVersion: 0,
			}},
			versions: map[int]string{},
			atts:     []adminstore.PolicyAttachment{chatAttachment(1)},
		},
		{
			name: "enabled but unattached policy",
			policies: []adminstore.PolicyPipeline{{
				ID: "unattached", OrgID: testOrg, Name: "unattached", Enabled: true, CurrentVersion: 0,
			}},
			versions: map[int]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakePolicyStore()
			if len(tc.policies) > 0 {
				store.add(testOrg, tc.policies[0], tc.versions, tc.atts)
			}
			rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
			loadedAt := time.Unix(5678, 0)
			outcome := rt.refreshWithOutcome(context.Background(), testOrg, nil, loadedAt)
			if outcome.loadErr != nil || outcome.entry == nil {
				t.Fatalf("valid non-applicable set outcome = %+v, want successful empty snapshot", outcome)
			}
			if len(outcome.entry.plans) != 0 || !outcome.entry.loadedAt.Equal(loadedAt) {
				t.Fatalf("empty snapshot = %+v, want zero plans with successful load timestamp", outcome.entry)
			}
		})
	}
}

func TestPolicyRuntime_EnabledAttachedWithoutPositiveVersionIsInvalid(t *testing.T) {
	for _, version := range []int{0, -1} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			store := newFakePolicyStore()
			store.add(testOrg, adminstore.PolicyPipeline{
				ID: "unversioned", OrgID: testOrg, Name: "unversioned", Enabled: true, CurrentVersion: version,
			}, map[int]string{version: denyWordYAML("unversioned", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
			rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
			plans, _, err := rt.load(context.Background(), testOrg)
			if err == nil {
				t.Fatal("enabled attached policy without a positive active version must be invalid")
			}
			var configErr *policyConfigError
			if !errors.As(err, &configErr) || configErr.stage != policyConfigStageActiveReference {
				t.Fatalf("unversioned policy error = %T %v, want active_version_reference classification", err, err)
			}
			if len(plans) != 0 {
				t.Fatalf("unversioned invalid candidate returned %d plans, want none", len(plans))
			}
		})
	}
}

func TestPolicyRuntime_InvalidModeRejectedBeforeShadow(t *testing.T) {
	store := newFakePolicyStore()
	stored := strings.Replace(denyWordYAML("invalid-mode", "marker"), "mode: enforce", "mode: observe", 1)
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "invalid-mode", OrgID: testOrg, Name: "invalid-mode", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: stored}, []adminstore.PolicyAttachment{chatAttachment(1)})

	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeShadow)
	plans, _, err := rt.load(context.Background(), testOrg)
	if err == nil {
		t.Fatal("unknown stored mode must fail before global shadow downgrade")
	}
	if len(plans) != 0 {
		t.Fatalf("invalid-mode candidate returned %d plans, want none", len(plans))
	}
}

func TestPolicyRuntime_InvalidRefreshRetainsLastGood(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "revisioned", OrgID: testOrg, Name: "revisioned", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("revisioned", "good-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	loadedAt := time.Unix(1234, 0)
	first := rt.refreshWithOutcome(context.Background(), testOrg, nil, loadedAt)
	if first.loadErr != nil || first.entry == nil {
		t.Fatalf("initial valid load = %+v, want installed snapshot", first)
	}
	priorPlans := append([]policyPlan(nil), first.entry.plans...)

	store.mu.Lock()
	store.versions[testOrg]["revisioned"][1] = "apiVersion: ypp/v1\nkind: Broken\n"
	store.mu.Unlock()
	refreshed := rt.refreshWithOutcome(context.Background(), testOrg, first.entry, loadedAt.Add(rt.ttl))
	if refreshed.loadErr == nil || !refreshed.stale {
		t.Fatalf("invalid refresh = %+v, want stale load error", refreshed)
	}
	if refreshed.entry != first.entry || !refreshed.entry.loadedAt.Equal(loadedAt) || !reflect.DeepEqual(refreshed.entry.plans, priorPlans) {
		t.Fatal("invalid refresh changed the installed last-good plans or timestamp")
	}
}

func TestPolicyRuntime_MalformedYAMLStageClassification(t *testing.T) {
	store := newFakePolicyStore()
	malformed := "apiVersion: ypp/v1\nkind: deny\nname: [unclosed\n"
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "malformed-1", OrgID: testOrg, Name: "malformed", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: malformed}, []adminstore.PolicyAttachment{chatAttachment(1)})

	// Global shadow must not rescue a parse-broken document: the original
	// stored policy is validated before any downgrade.
	rt := newTestRuntime(t, store, nil, PolicyModeShadow)
	plans, _, err := rt.load(context.Background(), testOrg)
	if err == nil {
		t.Fatal("malformed stored YAML must reject the candidate")
	}
	if len(plans) != 0 {
		t.Fatalf("malformed-YAML candidate returned %d plans, want none", len(plans))
	}
	var configErr *policyConfigError
	if !errors.As(err, &configErr) || configErr.stage != policyConfigStageYAMLDocument {
		t.Fatalf("malformed YAML error = %T %v, want bounded yaml_document classification", err, err)
	}
	if configErr.Error() != errInvalidPolicyConfiguration.Error() {
		t.Fatalf("config error text %q must stay fixed and generic", configErr.Error())
	}
	if strings.Contains(err.Error(), "unclosed") || strings.Contains(err.Error(), "parse policy yaml") {
		t.Fatalf("parser detail leaked through the bounded error: %q", err.Error())
	}
}

func TestPolicyRuntime_ColdInvalidOutcomeByMode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       PolicyMode
		wantStatus int
		wantStop   bool
	}{
		{name: "enforce refuses even when store outage mode is fail open", mode: PolicyModeEnforce, wantStatus: http.StatusServiceUnavailable, wantStop: true},
		{name: "shadow remains nonblocking without installing candidate", mode: PolicyModeShadow, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakePolicyStore()
			store.add(testOrg, adminstore.PolicyPipeline{
				ID: "invalid-1", OrgID: testOrg, Name: "invalid", Enabled: true, CurrentVersion: 1,
			}, map[int]string{1: "apiVersion: ypp/v1\nkind: Broken\nname: policy-yaml-secret-sentinel\n"}, []adminstore.PolicyAttachment{chatAttachment(1)})
			reader := &countingPolicyReader{PolicyPipelineReader: store}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			rt, err := NewPolicyRuntime(reader, nil, tc.mode, nil, logger)
			if err != nil {
				t.Fatalf("NewPolicyRuntime: %v", err)
			}
			rt.coldFailureMode = PolicyColdFailureFailOpen
			gw := testHookGateway(rt)
			gw.log = logger
			w, r := policyRequest(`{"messages":[]}`)
			events := captureEvents(t)
			before := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues(string(tc.mode), "cold"))
			_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if gotStop := !ok; gotStop != tc.wantStop {
				t.Fatalf("upstream stopped = %v, want %v (status=%d body=%s)", gotStop, tc.wantStop, w.Code, w.Body.String())
			}
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.mode == PolicyModeEnforce {
				var envelope struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
					t.Fatalf("invalid-config response is not an API error envelope: %v", err)
				}
				if envelope.Error.Code != "policy_configuration_unavailable" || envelope.Error.Message != "policy configuration unavailable" {
					t.Fatalf("invalid-config response = %+v, want generic policy configuration unavailable", envelope.Error)
				}
			}
			if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues(string(tc.mode), "cold")); after != before+1 {
				t.Fatalf("cold failure counter delta = %v, want exactly 1", after-before)
			}
			if rt.hasSnapshot(testOrg) {
				t.Fatal("cold invalid candidate installed a snapshot")
			}
			if strings.Contains(w.Body.String(), testOrg) || strings.Contains(w.Body.String(), "policy-yaml-secret-sentinel") || strings.Contains(logs.String(), testOrg) || strings.Contains(logs.String(), "policy-yaml-secret-sentinel") {
				t.Fatalf("tenant or raw policy content leaked: body=%q logs=%q", w.Body.String(), logs.String())
			}
			if !strings.Contains(logs.String(), "invalid_config") {
				t.Fatalf("bounded invalid-config class missing from logs: %q", logs.String())
			}
			if !strings.Contains(logs.String(), "stage=schema_mode") {
				t.Fatalf("bounded schema/mode stage missing from logs: %q", logs.String())
			}
			if got := events(); len(got) != 0 {
				t.Fatalf("invalid config emitted %d policy event(s), want none", len(got))
			}
			if tc.mode == PolicyModeShadow {
				store.mu.Lock()
				store.versions[testOrg]["invalid-1"][1] = denyWordYAML("repaired", "repaired-marker")
				store.mu.Unlock()
				w2, r2 := policyRequest(`{"messages":[]}`)
				_, _, ok2 := gw.policyPreUpstream(w2, r2, "chat", "m", "openai", []byte(`{"messages":[]}`))
				if !ok2 || w2.Code != http.StatusOK || !rt.hasSnapshot(testOrg) {
					t.Fatalf("shadow retry did not activate repaired valid candidate: ok=%v status=%d", ok2, w2.Code)
				}
			}
		})
	}
}

func TestPolicyRuntime_ReferenceReadClassification(t *testing.T) {
	for _, tc := range []struct {
		name           string
		listErr        error
		versionErr     error
		attachmentsErr error
		wantStatus     int
		wantClass      string
		wantStage      string
	}{
		{name: "org-scoped missing active version is invalid config", versionErr: adminstore.ErrNotFound, wantStatus: http.StatusServiceUnavailable, wantClass: "invalid_config", wantStage: "active_version_reference"},
		{name: "transient version read remains store outage", versionErr: errors.New("synthetic version timeout"), wantStatus: http.StatusOK, wantClass: "store_read"},
		{name: "transient attachment read remains store outage", attachmentsErr: errors.New("synthetic attachment timeout"), wantStatus: http.StatusOK, wantClass: "store_read"},
		{name: "org-scoped policy list not found remains operational", listErr: adminstore.ErrNotFound, wantStatus: http.StatusOK, wantClass: "store_read"},
		{name: "org-scoped missing attachments is invalid config", attachmentsErr: adminstore.ErrNotFound, wantStatus: http.StatusServiceUnavailable, wantClass: "invalid_config", wantStage: "active_version_reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newFakePolicyStore()
			base.add(testOrg, adminstore.PolicyPipeline{
				ID: "active-1", OrgID: testOrg, Name: "active", Enabled: true, CurrentVersion: 1,
			}, map[int]string{1: denyWordYAML("active", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
			reader := &faultPolicyReader{
				PolicyPipelineReader: base,
				listErr:              tc.listErr,
				versionErr:           tc.versionErr,
				attachmentsErr:       tc.attachmentsErr,
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			rt, err := NewPolicyRuntime(reader, nil, PolicyModeEnforce, nil, logger)
			if err != nil {
				t.Fatalf("NewPolicyRuntime: %v", err)
			}
			rt.coldFailureMode = PolicyColdFailureFailOpen
			gw := testHookGateway(rt)
			gw.log = logger
			w, r := policyRequest(`{"messages":[]}`)
			_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if tc.wantStatus == http.StatusServiceUnavailable && ok {
				t.Fatal("invalid reference continued upstream under fail-open")
			}
			if tc.wantStatus == http.StatusOK && !ok {
				t.Fatal("operational store read failure did not honor fail-open")
			}
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if !strings.Contains(logs.String(), "failure_class="+tc.wantClass) {
				t.Fatalf("failure class missing from logs: %q", logs.String())
			}
			if tc.wantStage != "" && !strings.Contains(logs.String(), "stage="+tc.wantStage) {
				t.Fatalf("invalid-reference stage missing from logs: %q", logs.String())
			}
			if strings.Contains(logs.String(), "synthetic version timeout") || strings.Contains(logs.String(), "synthetic attachment timeout") || strings.Contains(logs.String(), testOrg) {
				t.Fatalf("store details or tenant ID leaked into logs: %q", logs.String())
			}
		})
	}
}

func TestPolicyRuntime_OneOutcomePerRequest(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "invalid-1", OrgID: testOrg, Name: "invalid", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: "apiVersion: ypp/v1\nkind: Broken\n"}, []adminstore.PolicyAttachment{chatAttachment(1)})
	reader := &countingPolicyReader{PolicyPipelineReader: store}
	rt, err := NewPolicyRuntime(reader, nil, PolicyModeShadow, nil, testLogger())
	if err != nil {
		t.Fatalf("NewPolicyRuntime: %v", err)
	}
	gw := testHookGateway(rt)
	w, r := policyRequest(`{"messages":[]}`)
	before := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("shadow", "cold"))
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
	if !ok {
		t.Fatal("shadow-mode invalid config must not stop the request")
	}
	if got := reader.listCalls.Load(); got != 1 {
		t.Fatalf("prehook loaded policies %d times, want 1", got)
	}
	_, _, _ = gw.policyPostUpstream(r, "chat", "m", "openai", []byte(`{"choices":[]}`))
	_ = rt.streamPlans(r.Context(), testOrg, policyQuery{endpoint: "chat", hook: pipeline.HookStreamPrefix, model: "m"})
	_ = rt.streamPlans(r.Context(), testOrg, policyQuery{endpoint: "chat", hook: pipeline.HookStreamFinal, model: "m"})
	if got := reader.listCalls.Load(); got != 1 {
		t.Fatalf("later hooks reloaded the request outcome %d times, want 1 total", got)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("shadow", "cold")); after != before+1 {
		t.Fatalf("same-request hooks recorded %v load failures, want exactly 1", after-before)
	}
}
