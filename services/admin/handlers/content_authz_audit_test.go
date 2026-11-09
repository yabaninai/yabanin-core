package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

// unavailableAuthzEvaluator simulates a mandatory check that could not run
// (the evaluator/decision source is down). It substitutes the shared
// pipeline evaluator through the package test seam.
type unavailableAuthzEvaluator struct {
	deny pipeline.AuthorizationVerdict
}

func (e unavailableAuthzEvaluator) EvaluateScopedAuthorization(context.Context, []pipeline.ScopedDenyRule, pipeline.ConditionProgram, pipeline.DecisionEnvironment) pipeline.AuthorizationVerdict {
	return e.deny
}

// N02-P03-T03: a mandatory content-authorization check that CANNOT run must
// fail closed WITH a typed reason AND journal an audit event through the
// durable seam — identifiers and failure class only, never content. An
// allowed or evaluated-denied verdict must stay silent (the export path
// already journals those decisions; the list path strips rows instead).
func TestAuthorizeContentUnavailableFailsClosedAndAudits(t *testing.T) {
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	original := newContentAuthorizationEvaluator
	t.Cleanup(func() { newContentAuthorizationEvaluator = original })

	probe := func() pipeline.AuthorizationVerdict {
		return h.authorizeRequestContent(rootPayloadRequest(http.MethodGet, "/api/organizations/org-1/requests/req-1", ""), "org-1", "req-1", true, false)
	}

	t.Run("unavailable check denies with typed class and audits", func(t *testing.T) {
		before := len(store.auditRecords)
		newContentAuthorizationEvaluator = func() contentAuthorizationEvaluator {
			return unavailableAuthzEvaluator{deny: pipeline.UnavailableDeny("mandatory authorization evaluator unavailable", errors.New("evaluator down"))}
		}
		verdict := probe()
		require.False(t, verdict.Allowed, "an unavailable mandatory check must never allow")
		require.Equal(t, pipeline.DecisionClassUnavailable, verdict.Class())
		require.ErrorIs(t, verdict.Err, pipeline.ErrDecisionUnavailable)
		require.NotEmpty(t, verdict.Reason)

		require.Len(t, store.auditRecords, before+1, "the failure must be journalled")
		rec := store.auditRecords[len(store.auditRecords)-1]
		require.Equal(t, "request_content_authz.unavailable", rec.Action)
		require.Equal(t, "organization:org-1", rec.Resource)
		var details requestContentAuthzAuditDetail
		require.NoError(t, json.Unmarshal([]byte(rec.Details), &details))
		require.Equal(t, "org-1", details.OrgID)
		require.Equal(t, "req-1", details.RequestID)
		require.Equal(t, "unavailable", details.Class)
		require.NotEmpty(t, details.Reason)
		require.NotContains(t, rec.Details, "git status", "payload content must never reach the journal")
	})

	t.Run("evaluated denial does not journal the unavailable event", func(t *testing.T) {
		before := len(store.auditRecords)
		newContentAuthorizationEvaluator = func() contentAuthorizationEvaluator {
			return unavailableAuthzEvaluator{deny: pipeline.AuthorizationVerdict{Reason: "scoped deny rule \"explicit_policy_deny\" matched"}}
		}
		verdict := probe()
		require.False(t, verdict.Allowed)
		require.Equal(t, pipeline.DecisionClassDenied, verdict.Class())
		require.Len(t, store.auditRecords, before, "evaluated denials are not availability failures")
	})

	t.Run("allow does not journal the unavailable event", func(t *testing.T) {
		before := len(store.auditRecords)
		newContentAuthorizationEvaluator = func() contentAuthorizationEvaluator {
			return unavailableAuthzEvaluator{deny: pipeline.AuthorizationVerdict{Allowed: true, Reason: "authorization condition allowed"}}
		}
		verdict := probe()
		require.True(t, verdict.Allowed)
		require.Len(t, store.auditRecords, before)
	})
}

// N04-P04-T04: the compiled authorization conditions must express the
// mandatory deny as a SCOPED DENY RULE evaluated through the shared pipeline
// evaluator — a match refuses absolutely (no grant/role override, pinned
// end to end) and the compiled rules use the real Expr engine.
func TestAuthorizeContentScopedDenyRuleIsAbsolute(t *testing.T) {
	h := New(newMockStore(), "", "", nil)
	t.Cleanup(h.Stop)

	denyRules, program, err := defaultContentAuthorizationProgram()
	require.NoError(t, err)
	require.NotNil(t, program)
	require.Len(t, denyRules, 1)
	require.Equal(t, contentDenyRuleExplicit, denyRules[0].Name)
	require.NotNil(t, denyRules[0].Condition)

	// The deny rule evaluates the real compiled Expr condition end to end.
	ctx := context.WithValue(context.Background(), contentAuthzInputKey{}, contentAuthzInput{Denied: true, Grant: true, Own: true, Role: true})
	verdict := (pipeline.Evaluator{}).EvaluateScopedAuthorization(ctx, denyRules, program, pipeline.DecisionEnvironment{
		Principal: pipeline.DecisionPrincipal{
			ID:   pipeline.TrustedAttribute{Value: "admin-root", Source: "admin-session"},
			Kind: pipeline.TrustedAttribute{Value: "human", Source: "authenticated-subject"},
		},
		Action:   pipeline.TrustedAttribute{Value: "requests.read_payloads", Source: "admin-route"},
		Resource: pipeline.DecisionResource{Type: pipeline.TrustedAttribute{Value: "request", Source: "admin-route"}, ID: pipeline.TrustedAttribute{Value: "req-1", Source: "admin-route"}, Organization: pipeline.TrustedAttribute{Value: "org-1", Source: "admin-route"}},
		Context: map[string]pipeline.TrustedAttribute{
			"deny":  {Value: "true", Source: "admin-policy-context"},
			"grant": {Value: "true", Source: "durable-request-grant"},
			"own":   {Value: "true", Source: "authenticated-principal"},
			"role":  {Value: "true", Source: "org-role-store"},
		},
	})
	require.False(t, verdict.Allowed, "mandatory deny must override grant+own+role")
	require.NoError(t, verdict.Err, "a matched deny rule is an evaluated refusal, not an availability failure")
	require.Contains(t, verdict.Reason, contentDenyRuleExplicit)

	// Without the deny flag the same evidence allows (precedence unchanged).
	ctx = context.WithValue(context.Background(), contentAuthzInputKey{}, contentAuthzInput{Grant: true, Own: true, Role: true})
	verdict = h.AuthorizeContent(pipeline.DecisionPrincipal{
		ID:   pipeline.TrustedAttribute{Value: "admin-root", Source: "admin-session"},
		Kind: pipeline.TrustedAttribute{Value: "human", Source: "authenticated-subject"},
	},
		pipeline.TrustedAttribute{Value: "requests.read_payloads", Source: "admin-route"},
		pipeline.DecisionResource{Type: pipeline.TrustedAttribute{Value: "request", Source: "admin-route"}, ID: pipeline.TrustedAttribute{Value: "req-1", Source: "admin-route"}, Organization: pipeline.TrustedAttribute{Value: "org-1", Source: "admin-route"}},
		ctx)
	require.True(t, verdict.Allowed, "grant+own+role without deny must allow: %+v", verdict)
}

// The audit detail type must serialize to valid JSON for hostile request_id
// bytes (the requestExportAuditDetail regression, mirrored here).
func TestContentAuthzAuditDetailIsValidJSONForHostileRequestID(t *testing.T) {
	details, err := json.Marshal(requestContentAuthzAuditDetail{
		OrgID: "org-1", RequestID: "req\x01\x1b\xFF", Class: "unavailable", Reason: "down",
	})
	require.NoError(t, err)
	var back map[string]string
	require.NoError(t, json.Unmarshal(details, &back))
	require.Equal(t, "unavailable", back["class"])
}

// compile-time guard: the store continues to satisfy the grant surface the
// content boundary reads.
var _ requestPayloadGrantStore = (*mockStore)(nil)
