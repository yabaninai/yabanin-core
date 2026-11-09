package cli

// N06-P07-T04 unit acceptance: the workload dimension lives in the shared
// admission funnel, so every endpoint that admits (the T03 matrix proves
// they all do) validates, derives and labels the workload identity; a
// malformed explicit key is a 400, an over-cap workload is a fail-closed
// 429, and the derived key rides the request's label context — the channel
// every settle event publishes through. Batch lines synthesize only
// X-Yabanin-Task, so their derived task:<id> workload is pinned here: the
// dimension cannot be bypassed by dropping headers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/money"
)

// presetWorkloadLedger swaps the shared workload ledger for a capped
// instance and restores the default (nil → lazy env build) on cleanup.
func presetWorkloadLedger(t *testing.T, capUSD int64) *budget.WorkloadLedger {
	t.Helper()
	l := budget.NewWorkloadLedger(money.MicroUSD(capUSD), 0)
	workloadLedgerShared.Store(l)
	t.Cleanup(func() { workloadLedgerShared.Store(nil) })
	return l
}

func TestAdmissionCore_WorkloadHeaderValidation(t *testing.T) {
	gw, _, _ := newAdmissionMatrixGateway(t)

	for _, header := range []string{"team a", "team/a", "ключ"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("X-Yabanin-Workload", header)
		_, ok := gw.admissionCore(rec, req, gw.log, admissionCoreInput{Model: "m"})
		require.False(t, ok, "header %q must deny", header)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "invalid_workload_id", rec.Body.String())
	}
}

func TestAdmissionCore_WorkloadHeaderValidationAcrossEndpoints(t *testing.T) {
	gw, hits, _ := newAdmissionMatrixGateway(t)
	endpoints := []struct {
		path, contentType, body string
	}{
		{"/v1/chat/completions", "application/json", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/completions", "application/json", `{"model":"m","prompt":"hi"}`},
		{"/v1/embeddings", "application/json", `{"model":"m","input":"hi"}`},
		{"/v1/moderations", "application/json", `{"model":"m","input":"hi"}`},
	}
	for _, ep := range endpoints {
		rec := postMatrixRequest(t, gw, ep.path, ep.contentType, ep.body,
			map[string]string{"X-Yabanin-Workload": "not valid"})
		require.Equal(t, http.StatusBadRequest, rec.Code, ep.path+": "+rec.Body.String())
		require.Contains(t, rec.Body.String(), "invalid_workload_id", ep.path)
	}
	require.Equal(t, int64(0), hits.Load(), "denied requests must not reach the wire")
}

func TestAdmissionCore_WorkloadDerivationAndLabels(t *testing.T) {
	gw, _, _ := newAdmissionMatrixGateway(t)

	tests := []struct {
		name    string
		headers map[string]string
		ctxLab  labels.Set
		want    string
	}{
		{
			name:    "explicit header wins",
			headers: map[string]string{"X-Agent-Id": "agent-1", "X-Yabanin-Workload": "ci-fleet"},
			want:    "ci-fleet",
		},
		{
			name:    "agent derived",
			headers: map[string]string{"X-Agent-Id": "agent-1"},
			want:    "agent:agent-1",
		},
		{
			name:    "team+task derived",
			headers: map[string]string{"X-Team-Id": "t1", "X-Yabanin-Task": "job"},
			want:    "team:t1.task:job",
		},
		{
			name:    "batch line shape: task only",
			headers: map[string]string{"X-Yabanin-Task": "batch-123"},
			want:    "task:batch-123",
		},
		{
			name: "unattributable",
			want: "",
		},
		{
			name:    "merges with existing labels, never clobbers",
			headers: map[string]string{"X-Agent-Id": "agent-1"},
			ctxLab:  labels.Set{"team": "t1"},
			want:    "agent:agent-1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.ctxLab != nil {
				req = req.WithContext(withLabels(req.Context(), labels.Result{Labels: tt.ctxLab}))
			}
			core, ok := gw.admissionCore(rec, req, gw.log, admissionCoreInput{Model: "m"})
			require.True(t, ok, rec.Body.String())
			require.Equal(t, tt.want, core.WorkloadID)

			got := labelsFrom(req.Context())
			require.Equal(t, tt.want, got["workload"], "the key must ride the label context")
			if tt.ctxLab != nil {
				for k, v := range tt.ctxLab {
					require.Equalf(t, v, got[k], "pre-existing label %q must survive the merge", k)
				}
			}
		})
	}
}

func TestAdmissionCore_WorkloadLabelCopyOnWrite(t *testing.T) {
	gw, _, _ := newAdmissionMatrixGateway(t)

	original := labels.Set{"team": "t1"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Agent-Id", "agent-1")
	req = req.WithContext(withLabels(req.Context(), labels.Result{Labels: original}))

	_, ok := gw.admissionCore(rec, req, gw.log, admissionCoreInput{Model: "m"})
	require.True(t, ok)
	require.Equal(t, "agent:agent-1", labelsFrom(req.Context())["workload"])
	require.NotContains(t, original, "workload", "the pre-existing label map must not be mutated in place")
}

func TestAdmissionCore_WorkloadCapDenied(t *testing.T) {
	gw, hits, _ := newAdmissionMatrixGateway(t)
	ledger := presetWorkloadLedger(t, 100) // 0.0001 USD window cap
	ledger.Charge("", "ci-fleet", money.MicroUSD(100))

	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	rec := postMatrixRequest(t, gw, "/v1/chat/completions", "application/json", body,
		map[string]string{"X-Yabanin-Workload": "ci-fleet"})
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "workload_budget_exceeded", rec.Body.String())
	workloadDeniedEnvelope(t, rec.Body.Bytes())
	require.Equal(t, int64(0), hits.Load(), "a capped workload must not reach the wire")

	// Another workload is unaffected; an unattributable request is a no-op.
	rec = postMatrixRequest(t, gw, "/v1/chat/completions", "application/json", body,
		map[string]string{"X-Yabanin-Workload": "other"})
	require.NotEqual(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
}

// TestAdmissionCore_WorkloadCapOrgIsolated pins the F1 remediation at the
// admission seam: the cap window is namespaced by the authenticated org
// (X-Org-Id as the auth middleware stamps it — client copies are stripped),
// so two tenants that picked the same workload name never share a counter —
// org A's saturation 429s only org A; the identical request under org B is
// unaffected.
func TestAdmissionCore_WorkloadCapOrgIsolated(t *testing.T) {
	gw, _, _ := newAdmissionMatrixGateway(t)
	ledger := presetWorkloadLedger(t, 100) // 0.0001 USD window cap
	ledger.Charge("org-a", "ci", money.MicroUSD(100))

	admit := func(org string) (*httptest.ResponseRecorder, admissionCore, bool) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("X-Org-Id", org)
		req.Header.Set("X-Yabanin-Workload", "ci")
		core, ok := gw.admissionCore(rec, req, gw.log, admissionCoreInput{Model: "m"})
		return rec, core, ok
	}

	// Org A: its "ci" window is saturated → fail-closed 429.
	rec, _, ok := admit("org-a")
	require.False(t, ok)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "workload_budget_exceeded", rec.Body.String())
	workloadDeniedEnvelope(t, rec.Body.Bytes())

	// Same workload name, different org: independent window, no 429.
	rec, core, ok := admit("org-b")
	require.True(t, ok, rec.Body.String())
	require.Equal(t, "ci", core.WorkloadID)
	require.NotEqual(t, http.StatusTooManyRequests, rec.Code, rec.Body.String(),
		"org B's identical workload name must not inherit org A's saturation")

	// The windows themselves stay independent.
	require.Equal(t, money.MicroUSD(100), ledger.Spent("org-a", "ci"))
	require.Equal(t, money.MicroUSD(0), ledger.Spent("org-b", "ci"))
}

func TestAdmissionCore_WorkloadCapDisabledPasses(t *testing.T) {
	gw, _, _ := newAdmissionMatrixGateway(t)
	presetWorkloadLedger(t, 0) // disabled: attribution only, no cap

	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	rec := postMatrixRequest(t, gw, "/v1/chat/completions", "application/json", body,
		map[string]string{"X-Yabanin-Workload": "ci-fleet"})
	require.NotEqual(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
}

func TestPolicyMetaWithTeam_WorkloadStamp(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Team-Id", "t1")
	req.Header.Set("X-Yabanin-Workload", "ci-fleet")

	meta := policyMetaWithTeam(req, "org-1", "m", "openai")
	require.Equal(t, "t1", meta.Labels["team"])
	require.Equal(t, "ci-fleet", meta.Labels["workload"])

	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	meta = policyMetaWithTeam(req, "org-1", "m", "openai")
	require.Nil(t, meta.Labels, "traffic with neither identity keeps meta byte-identical")
}

func TestWorkloadCapFromEnv(t *testing.T) {
	t.Setenv(WorkloadBudgetEnvUSD, "")
	require.Equal(t, money.MicroUSD(0), workloadCapFromEnv(), "unset selects disabled")

	t.Setenv(WorkloadBudgetEnvUSD, "not-a-number")
	require.Equal(t, money.MicroUSD(0), workloadCapFromEnv(), "unparsable selects disabled")

	t.Setenv(WorkloadBudgetEnvUSD, "-3")
	require.Equal(t, money.MicroUSD(0), workloadCapFromEnv(), "non-positive selects disabled")

	t.Setenv(WorkloadBudgetEnvUSD, "1.5")
	require.Equal(t, money.MustFromCents(150), workloadCapFromEnv())
}

// workloadDeniedEnvelope pins the refusal envelope: budget-area denials
// carry their stable identifier in error.type (the same shape the team and
// agent budget refusals use — Write's errType, not the optional code).
func workloadDeniedEnvelope(t *testing.T, body []byte) {
	t.Helper()
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	require.Equal(t, "workload_budget_exceeded", env.Error.Type)
}
