package cli

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policy"
)

type fakeAccess struct {
	allowed bool
	err     error
}

func (f fakeAccess) Check(context.Context, string, string, string) (bool, error) {
	return f.allowed, f.err
}

type fakeTeamBudget struct{ err error }

func (f fakeTeamBudget) CheckBudget(context.Context, string) error { return f.err }

type fakeAgentBudget struct{ err error }

func (f fakeAgentBudget) CheckAgentBudget(context.Context, string) error { return f.err }

type fakeResidency struct{ dec policy.Decision }

func (f fakeResidency) Enforce(context.Context, string, string, policy.Region, string) policy.Decision {
	return f.dec
}

func admitRequest(t *testing.T, headers map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/embeddings", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func errorType(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body %s: %v", rec.Body.String(), err)
	}
	return env.Error.Type
}

func TestAdmit_Paths(t *testing.T) {
	const card = `{"messages":[{"content":"card 4242 4242 4242 4242"}]}`

	tests := []struct {
		name    string
		gw      func() *gateway
		in      admitInput
		headers map[string]string
		status  int
		errType string
		model   string
	}{
		{
			name: "guard deny",
			gw: func() *gateway {
				return &gateway{log: slog.Default(), guardHooks: guardhooks.New(guardhooks.ModeDeny)}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(card)},
			status:  http.StatusBadRequest,
			errType: "guard_denied",
		},
		{
			name: "unknown model reject",
			gw: func() *gateway {
				return &gateway{
					log:                slog.Default(),
					unknownModelPolicy: "reject",
					res:                stubModelResolver{"missing": {ModelName: "fb", Fallback: true}},
				}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "missing", Body: []byte(`{}`)},
			status:  http.StatusNotFound,
			errType: "not_found_error",
		},
		{
			name:    "invalid task id",
			gw:      func() *gateway { return &gateway{log: slog.Default()} },
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`)},
			headers: map[string]string{"X-Yabanin-Task": "bad id"},
			status:  http.StatusBadRequest,
			errType: "invalid_task_id",
		},
		{
			name: "whitelist error",
			gw: func() *gateway {
				return &gateway{log: slog.Default(), wl: fakeAccess{err: errors.New("down")}}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`)},
			status:  http.StatusServiceUnavailable,
			errType: "whitelist_check_unavailable",
		},
		{
			name: "whitelist deny",
			gw: func() *gateway {
				return &gateway{log: slog.Default(), wl: fakeAccess{allowed: false}}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`)},
			status:  http.StatusForbidden,
			errType: "permission_denied_error",
		},
		{
			name: "team budget exceeded",
			gw: func() *gateway {
				return &gateway{log: slog.Default(), budgetEnforcer: fakeTeamBudget{err: budget.ErrBudgetExceeded}}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`)},
			headers: map[string]string{"X-Team-Id": "team-1"},
			status:  http.StatusTooManyRequests,
			errType: "budget_exceeded",
		},
		{
			name: "agent budget missing",
			gw: func() *gateway {
				return &gateway{log: slog.Default(), agentEnforcer: fakeAgentBudget{err: budget.ErrNoAgentBudget}}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`)},
			headers: map[string]string{"X-Agent-Id": "agent-1"},
			status:  http.StatusForbidden,
			errType: "agent_budget_not_configured",
		},
		{
			name: "residency remap blocked",
			gw: func() *gateway {
				return &gateway{
					log: slog.Default(),
					residencyEnforcer: fakeResidency{dec: policy.Decision{
						Allowed: true, Region: "SG", RemappedModel: "local-sg",
					}},
				}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`), NoRemap: true},
			headers: map[string]string{"X-Org-Id": "org-1"},
			status:  http.StatusForbidden,
			errType: "residency_policy_violation",
		},
		{
			name: "residency remap applied",
			gw: func() *gateway {
				return &gateway{
					log: slog.Default(),
					residencyEnforcer: fakeResidency{dec: policy.Decision{
						Allowed: true, Region: "SG", RemappedModel: "local-sg",
					}},
					res: stubModelResolver{"local-sg": {ModelName: "local-sg", Enabled: true}},
				}
			},
			in:      admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{}`)},
			headers: map[string]string{"X-Org-Id": "org-1"},
			model:   "local-sg",
		},
		{
			name:  "happy path",
			gw:    func() *gateway { return &gateway{log: slog.Default()} },
			in:    admitInput{Endpoint: "embeddings", Model: "m", Body: []byte(`{"model":"m"}`)},
			model: "m",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			got, ok := tc.gw().admit(rec, admitRequest(t, tc.headers), tc.in)
			if tc.errType != "" {
				if ok {
					t.Fatal("expected admission to fail")
				}
				if rec.Code != tc.status {
					t.Fatalf("status %d, want %d, body %s", rec.Code, tc.status, rec.Body.String())
				}
				if gotType := errorType(t, rec); gotType != tc.errType {
					t.Fatalf("error.type %q, want %q", gotType, tc.errType)
				}
				return
			}
			if !ok {
				t.Fatalf("admit failed: %d %s", rec.Code, rec.Body.String())
			}
			if got.Info.ModelName != tc.model {
				t.Fatalf("model %q, want %q", got.Info.ModelName, tc.model)
			}
		})
	}
}
