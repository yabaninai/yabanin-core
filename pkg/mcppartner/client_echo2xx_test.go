package mcp

// partner bridge — a hostile or misconfigured peer answering 2xx with a body
// that is not the expected JSON object (echoing both credentials into
// garbage). The boundary behavior covers non-2xx bodies and
// transport errors; the decode refusal of a malformed SUCCESS response was
// unpinned. Both hops (partner Bearer on the gateway hop, X-Admin-Key on the
// admin hop) and both surfaces (client error, tool output) must stay free of
// the body content and the key material while remaining diagnosable.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestGatewayClient_Hostile2xxBody_DecodeErrorCarriesNoMaterial(t *testing.T) {
	const (
		partnerKey = "pk-lifecycle-partner-9f8e7d"
		adminKey   = "svc-lifecycle-admin-2b3c4a"
		bodyMarker = "HOSTILE-ECHO-BODY"
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(bodyMarker + " partner=" + partnerKey + " admin=" + adminKey))
	}))
	t.Cleanup(up.Close)
	client := NewGatewayClient(up.URL, up.URL, partnerKey, adminKey)

	leaks := []string{partnerKey, adminKey, bodyMarker, up.URL}

	// Client surface, gateway hop: the decode refusal is diagnosable and
	// carries neither the body nor the keys nor the URL.
	_, err := client.Route(context.Background(), "model", "prompt")
	if err == nil {
		t.Fatal("a non-JSON 2xx body must be an error")
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Errorf("the decode refusal must stay diagnosable, got %q", err.Error())
	}
	for _, leak := range leaks {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("route decode error exposed %q: %q", leak, err.Error())
		}
	}

	// Tool surface, gateway hop: a tool error with the same guarantees.
	result, err := handleRoute(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"model": "model", "prompt": "prompt"}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("a malformed success body must read as a tool error, never success")
	}
	text := toolText(result)
	if !strings.Contains(text, "route failed") {
		t.Errorf("tool error should retain the categorized failure, got %q", text)
	}
	for _, leak := range leaks {
		if strings.Contains(text, leak) {
			t.Errorf("route tool output exposed %q: %q", leak, text)
		}
	}

	// Client surface, admin hop: the same decode refusal on the X-Admin-Key
	// surface.
	_, err = client.SpendReport(context.Background(), "org-1", 7)
	if err == nil {
		t.Fatal("a non-JSON 2xx body on the admin hop must be an error")
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Errorf("the admin decode refusal must stay diagnosable, got %q", err.Error())
	}
	for _, leak := range leaks {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("spend report decode error exposed %q: %q", leak, err.Error())
		}
	}

	// Tool surface, admin hop.
	result, err = handleSpendReport(client)(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"org_id": "org-1"}},
	})
	if err != nil {
		t.Fatalf("tool handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("a malformed admin success body must read as a tool error, never success")
	}
	text = toolText(result)
	if !strings.Contains(text, "spend report failed") {
		t.Errorf("tool error should retain the categorized failure, got %q", text)
	}
	for _, leak := range leaks {
		if strings.Contains(text, leak) {
			t.Errorf("spend report tool output exposed %q: %q", leak, text)
		}
	}
}
