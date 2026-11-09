package mcp

// Failure/boundary tests for the partner MCP surface: a foreign
// tenant or a rejected key must come back as a terse categorized error that
// carries neither the partner key, the admin key, nor the upstream response
// body — on the client AND on the tool output the agent sees. Also pinned:
// the admin key never rides the gateway hop (the mirror of the existing
// admin-hop test), and an interrupted call is an error with a stable safe
// message, never a partial success.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// keyEchoingUpstream answers status with a body that bounces both keys back
// (the hostile-admin/echo leak vector) and records which credentials arrived.
func keyEchoingUpstream(t *testing.T, status int) (*httptest.Server, *string, *string) {
	t.Helper()
	var gotAuth, gotAdminKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAdminKey = r.Header.Get("X-Admin-Key")
		w.WriteHeader(status)
		//nolint:gosec // G705: the mock admin deliberately echoes both keys — the test proves the client and tool handlers redact it
		_, _ = fmt.Fprintf(w, `{"error":"tenant mismatch; credential=%s admin=%s body-detail"}`,
			r.Header.Get("Authorization"), r.Header.Get("X-Admin-Key"))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth, &gotAdminKey
}

func TestGatewayClient_LineageVerify_ForeignTenantErrorRedactsKeys(t *testing.T) {
	const (
		partnerKey = "pk-boundary-partner-3f2b9c"
		adminKey   = "svc-boundary-admin-7d1e44"
	)
	up, gotAuth, gotAdminKey := keyEchoingUpstream(t, http.StatusUnauthorized)
	client := NewGatewayClient("", up.URL, partnerKey, adminKey)

	// Client surface: the error is the status category only.
	_, err := client.LineageVerify(context.Background(), "req-1")
	if err == nil {
		t.Fatal("a foreign-tenant rejection must be an error")
	}
	if !strings.Contains(err.Error(), "gateway 401") {
		t.Errorf("error should retain the hop + status, got %q", err.Error())
	}
	for _, leak := range []string{partnerKey, adminKey, "Bearer", "tenant mismatch", "body-detail"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("lineage verify error exposed %q: %q", leak, err.Error())
		}
	}

	// Tool surface: the agent sees the same terse error, not the echo.
	result, err := handleLineageVerify(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"request_id": "req-1"}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("a foreign-tenant rejection must read as a tool error, never success")
	}
	text := toolText(result)
	if !strings.Contains(text, "gateway 401") {
		t.Errorf("tool error should retain the categorized status, got %q", text)
	}
	for _, leak := range []string{partnerKey, adminKey, "tenant mismatch", "body-detail"} {
		if strings.Contains(text, leak) {
			t.Errorf("tool output exposed %q: %q", leak, text)
		}
	}

	// The documented hop contract: the partner key authenticates this
	// surface as Bearer; the admin key must not ride along.
	if gotAuth != nil && *gotAuth != "Bearer "+partnerKey {
		t.Errorf("lineage hop auth = %q, want the partner Bearer key", *gotAuth)
	}
	if gotAdminKey != nil && *gotAdminKey != "" {
		t.Errorf("lineage hop must not carry X-Admin-Key, got %q", *gotAdminKey)
	}
}

func TestGatewayClient_SetPolicy_ForeignTenantErrorRedactsKeys(t *testing.T) {
	const (
		partnerKey = "pk-boundary-partner-aa11bb"
		adminKey   = "svc-boundary-admin-cc22dd"
	)
	up, _, _ := keyEchoingUpstream(t, http.StatusForbidden)
	client := NewGatewayClient("", up.URL, partnerKey, adminKey)

	_, err := client.SetPolicy(context.Background(), "org-foreign", "auto", 0.5)
	if err == nil {
		t.Fatal("a foreign-org policy rejection must be an error")
	}
	if !strings.Contains(err.Error(), "gateway 403") {
		t.Errorf("error should retain the hop + status, got %q", err.Error())
	}
	for _, leak := range []string{partnerKey, adminKey, "tenant mismatch", "body-detail"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("set policy error exposed %q: %q", leak, err.Error())
		}
	}

	result, err := handleSetPolicy(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"org_id": "org-foreign", "mode": "auto"}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("a foreign-org rejection must read as a tool error, never success")
	}
	text := toolText(result)
	for _, leak := range []string{partnerKey, adminKey, "tenant mismatch", "body-detail"} {
		if strings.Contains(text, leak) {
			t.Errorf("tool output exposed %q: %q", leak, text)
		}
	}
}

// TestGatewayClient_GatewayHopCarriesNoAdminKey pins the mirror of the
// existing admin-hop test: the partner Bearer key authenticates gateway-hop
// calls and the admin service key stays off that surface.
func TestGatewayClient_GatewayHopCarriesNoAdminKey(t *testing.T) {
	var gotAdminKey, gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAdminKey = r.Header.Get("X-Admin-Key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	t.Cleanup(up.Close)

	client := NewGatewayClient(up.URL, "", "pa_partner-key", "svc-admin-key")
	if _, err := client.Route(context.Background(), "model", "prompt"); err != nil {
		t.Fatalf("Route: %v", err)
	}
	if gotAdminKey != "" {
		t.Errorf("gateway hop must not carry X-Admin-Key, got %q", gotAdminKey)
	}
	if gotAuth != "Bearer pa_partner-key" {
		t.Errorf("gateway hop auth = %q, want the partner Bearer key", gotAuth)
	}
}

// TestGatewayClient_CancelledContext_FailsClosedEverywhere: an interrupted
// hop is a transport error wrapping context.Canceled with the stable safe
// message (no URL, no keys), and the tool handlers surface it as an error —
// a partial/unknown state never reads as success.
func TestGatewayClient_CancelledContext_FailsClosedEverywhere(t *testing.T) {
	const (
		partnerKey = "pk-boundary-partner-cancel"
		adminKey   = "svc-boundary-admin-cancel"
	)
	up, _, _ := keyEchoingUpstream(t, http.StatusOK)
	client := NewGatewayClient(up.URL, up.URL, partnerKey, adminKey)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name  string
		label string
		call  func() (map[string]any, error)
	}{
		{
			name:  "route",
			label: "gateway",
			call: func() (map[string]any, error) {
				return client.Route(ctx, "model", "prompt")
			},
		},
		{
			name:  "spend_report",
			label: "admin",
			call: func() (map[string]any, error) {
				return client.SpendReport(ctx, "org-1", 7)
			},
		},
		{
			name:  "set_policy",
			label: "gateway",
			call: func() (map[string]any, error) {
				return client.SetPolicy(ctx, "org-1", "auto", 0.5)
			},
		},
		{
			name:  "lineage_verify",
			label: "gateway",
			call: func() (map[string]any, error) {
				return client.LineageVerify(ctx, "req-1")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.call()
			if err == nil {
				t.Fatal("a cancelled hop must fail")
			}
			if resp != nil {
				t.Errorf("a cancelled hop must not return a partial response: %v", resp)
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancel must stay diagnosable via errors.Is, got %v", err)
			}
			if got := err.Error(); got != tc.label+" transport error" {
				t.Errorf("cancelled hop message = %q, want the stable safe label", got)
			}
			for _, leak := range []string{partnerKey, adminKey, up.URL} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("cancelled hop error exposed %q", leak)
				}
			}
		})
	}

	// Tool surface for one representative hop: error result, no material.
	result, err := handleLineageVerify(client)(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"request_id": "req-1"}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("a cancelled tool call must read as an error, never success")
	}
	text := toolText(result)
	if !strings.Contains(text, "transport error") {
		t.Errorf("tool error should keep the stable transport category, got %q", text)
	}
	for _, leak := range []string{partnerKey, adminKey, up.URL} {
		if strings.Contains(text, leak) {
			t.Errorf("tool output exposed %q: %q", leak, text)
		}
	}
}
