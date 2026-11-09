package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func toolText(result *mcp.CallToolResult) string {
	var text string
	for _, content := range result.Content {
		if item, ok := content.(mcp.TextContent); ok {
			text += item.Text
		}
	}
	return text
}

func TestHandleRoute_ErrorDoesNotExposeCredentialEcho(t *testing.T) {
	const credential = "synthetic-partner-secret-marker"
	var gotAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream echoed " + credential))
	}))
	defer upstream.Close()

	client := NewGatewayClient(upstream.URL, "", credential, "")
	result, err := handleRoute(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"model": "test-model", "prompt": "hello"}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an MCP tool error for upstream failure")
	}
	text := toolText(result)
	if !strings.Contains(text, "gateway 502") {
		t.Error("tool error should retain the gateway status")
	}
	if strings.Contains(text, credential) || strings.Contains(text, "upstream echoed") {
		t.Error("tool error exposed upstream response content")
	}
	if gotAuthorization != "Bearer "+credential {
		t.Error("gateway request did not use the configured credential")
	}
}

func TestHandleSpendReport_ErrorDoesNotExposeCredentialEcho(t *testing.T) {
	const credential = "synthetic-admin-secret-marker"
	var gotAdminKey, gotAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAdminKey = r.Header.Get("X-Admin-Key")
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("admin echoed " + credential))
	}))
	defer upstream.Close()

	client := NewGatewayClient("", upstream.URL, "partner-key", credential)
	result, err := handleSpendReport(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"org_id": "org-test", "days": float64(7)}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an MCP tool error for upstream failure")
	}
	text := toolText(result)
	if !strings.Contains(text, "admin 403") {
		t.Error("tool error should retain the admin status")
	}
	if strings.Contains(text, credential) || strings.Contains(text, "admin echoed") {
		t.Error("tool error exposed upstream response content")
	}
	if gotAdminKey != credential || gotAuthorization != "" {
		t.Error("admin request used unexpected credentials")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestGatewayClient_TransportErrorIsSafeAndUnwraps(t *testing.T) {
	const marker = "synthetic-url-query-secret"
	cause := errors.New("dial failed for https://example.invalid/path?token=" + marker)
	client := NewGatewayClient("https://example.invalid/path?token="+marker, "", "key", "")
	client.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, cause
	})}
	_, err := client.Route(context.Background(), "model", "prompt")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !errors.Is(err, cause) {
		t.Error("transport error should preserve errors.Is")
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "example.invalid") {
		t.Error("transport error exposed request URL details")
	}
	if got := err.Error(); got != "gateway transport error" {
		t.Error("transport error should use a stable safe message")
	}
}

func TestHandleRoute_Success(t *testing.T) {
	// Mock gateway that returns a valid OpenAI-shaped response.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"}}]}`))
	}))
	defer mockServer.Close()

	client := NewGatewayClient(mockServer.URL, "", "pa_test-key", "svc-key")
	resp, err := client.Route(context.Background(), "test-model", "hello")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if resp == nil || resp["choices"] == nil {
		t.Errorf("expected choices in response, got %v", resp)
	}
}

func TestHandleRoute_GatewayDown(t *testing.T) {
	client := NewGatewayClient("http://127.0.0.1:1", "", "", "") // unreachable
	resp, err := client.Route(context.Background(), "model", "prompt")
	if err == nil {
		t.Error("expected error for unreachable gateway")
	}
	if resp != nil {
		t.Errorf("expected nil response on error, got %v", resp)
	}
}

func TestHandleRoute_MissingKey(t *testing.T) {
	client := NewGatewayClient("", "", "", "")
	resp, err := client.Route(context.Background(), "model", "prompt")
	if err == nil {
		t.Error("expected error when API key not set")
	}
	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestGatewayClient_SpendReport(t *testing.T) {
	var gotPath, gotAdminKey, gotAuth string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		gotAdminKey = r.Header.Get("X-Admin-Key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"total_cost": 1.23}`))
	}))
	defer mockServer.Close()

	client := NewGatewayClient("", mockServer.URL, "pa_test-key", "svc-key")
	resp, err := client.SpendReport(context.Background(), "org-1", 7)
	if err != nil {
		t.Fatalf("SpendReport: %v", err)
	}
	if resp["total_cost"] != float64(1.23) {
		t.Errorf("expected total_cost=1.23, got %v", resp)
	}
	// The admin surface for machine callers is the stateless /internal group:
	// session-cookie dashboard routes are unreachable for the MCP bridge, so
	// the request must hit /internal/analytics/cost with X-Admin-Key and must
	// not leak the partner Bearer key into the admin hop.
	if gotPath != "/internal/analytics/cost?org_id=org-1&days=7" {
		t.Errorf("expected /internal/analytics/cost route, got %s", gotPath)
	}
	if gotAdminKey != "svc-key" {
		t.Errorf("expected X-Admin-Key=svc-key, got %q", gotAdminKey)
	}
	if gotAuth != "" {
		t.Errorf("admin hop must not carry an Authorization header, got %q", gotAuth)
	}
}

func TestGatewayClient_LineageVerify(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"valid": true}`))
	}))
	defer mockServer.Close()

	client := NewGatewayClient("", mockServer.URL, "pa_test-key", "svc-key")
	resp, err := client.LineageVerify(context.Background(), "req-123")
	if err != nil {
		t.Fatalf("LineageVerify: %v", err)
	}
	if resp["valid"] != true {
		t.Errorf("expected valid=true, got %v", resp)
	}
}

func TestNewGatewayClient_Defaults(t *testing.T) {
	client := NewGatewayClient("http://gw:8082", "http://admin:9090", "pa_test", "svc-test")
	if client.BaseURL != "http://gw:8082" {
		t.Errorf("BaseURL: %s", client.BaseURL)
	}
	if client.AdminURL != "http://admin:9090" {
		t.Errorf("AdminURL: %s", client.AdminURL)
	}
	if client.APIKey != "pa_test" {
		t.Errorf("APIKey: %s", client.APIKey)
	}
	if client.AdminKey != "svc-test" {
		t.Errorf("AdminKey: %s", client.AdminKey)
	}
}

func TestHandlerSSE_NilPanic(t *testing.T) {
	client := NewGatewayClient("", "", "", "")
	s := HandlerSSE(client)
	if s == nil {
		t.Error("HandlerSSE should not return nil")
	}
}

func TestServeStdio_NoPanic(t *testing.T) {
	client := NewGatewayClient("", "", "", "")
	if client == nil {
		t.Error("client should not be nil")
	}

	// Verify HandlerSSE returns a non-nil server.
	s := HandlerSSE(client)
	if s == nil {
		t.Error("HandlerSSE should return non-nil server")
	}
}

func TestGatewayClient_SetPolicy(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"routing_mode":"auto"}`))
	}))
	defer mockServer.Close()

	client := NewGatewayClient("", mockServer.URL, "pa_test-key", "svc-key")
	resp, err := client.SetPolicy(context.Background(), "org-1", "auto", 0.5)
	if err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if resp["routing_mode"] != "auto" {
		t.Errorf("expected routing_mode=auto, got %v", resp)
	}
}

func TestGatewayClient_BadResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer mockServer.Close()

	client := NewGatewayClient(mockServer.URL, "", "pa_test-key", "svc-key")
	resp, err := client.Route(context.Background(), "model", "prompt")
	if err == nil {
		t.Error("expected error for 500 response")
	}
	if resp != nil {
		t.Errorf("expected nil on error, got %v", resp)
	}
}

func TestGatewayClient_AuthHeader(t *testing.T) {
	var capturedAuth string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer mockServer.Close()

	client := NewGatewayClient(mockServer.URL, "", "pa_test-key", "svc-key")
	_, _ = client.Route(context.Background(), "model", "prompt")
	if !strings.HasPrefix(capturedAuth, "Bearer pa_test-key") {
		t.Errorf("expected 'Bearer pa_test-key', got %q", capturedAuth)
	}
}
