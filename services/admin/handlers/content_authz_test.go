package handlers

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestAuthorizeContentUsesDenyGrantRolePrecedenceAndFailsClosed(t *testing.T) {
	h := New(newMockStore(), "s", "localhost", nil)
	principal := pipeline.DecisionPrincipal{
		ID:   pipeline.TrustedAttribute{Value: "human-1", Source: "session"},
		Kind: pipeline.TrustedAttribute{Value: "human", Source: "session"},
	}
	action := pipeline.TrustedAttribute{Value: "requests.read_payloads", Source: "route"}
	resource := pipeline.DecisionResource{
		Type:         pipeline.TrustedAttribute{Value: "request", Source: "route"},
		ID:           pipeline.TrustedAttribute{Value: "request-1", Source: "route"},
		Organization: pipeline.TrustedAttribute{Value: "org-1", Source: "route"},
	}
	decision := func(input contentAuthzInput) pipeline.AuthorizationVerdict {
		ctx := context.WithValue(context.Background(), contentAuthzInputKey{}, input)
		return h.AuthorizeContent(principal, action, resource, ctx)
	}
	for _, input := range []contentAuthzInput{{Own: true}, {Grant: true}, {Role: true}} {
		if verdict := decision(input); !verdict.Allowed {
			t.Fatalf("allowing evidence was denied: input=%+v verdict=%+v", input, verdict)
		}
	}
	if verdict := decision(contentAuthzInput{Denied: true, Grant: true, Role: true}); verdict.Allowed {
		t.Fatal("explicit deny must override grant and role")
	}
	if verdict := h.AuthorizeContent(pipeline.DecisionPrincipal{}, action, resource, context.Background()); verdict.Allowed || verdict.Err == nil {
		t.Fatalf("untrusted/missing principal attributes must deny with an error: %+v", verdict)
	}
}
