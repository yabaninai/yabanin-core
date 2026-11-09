package mcpserver

// JSON-RPC 2.0 wire layer for the MCP Streamable HTTP transport. Error code
// handling follows the spec: -32700 (parse), -32600 (invalid request),
// -32601 (method not found), -32602 (invalid params), -32603 (internal);
// gateway-level tool-call failures ride the server-error range (-32000)
// with the structured code in the error data.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 error codes (transport protocol errors).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	// serverErrorCode carries gateway tool-call failures (mcp_tool_blocked,
	// mcp_auth_required, not_found, …); the specifics live in Error.Data.
	serverErrorCode = -32000
)

// rpcRequest is one inbound JSON-RPC 2.0 message. ID is kept raw so the
// exact value (string/number) is echoed back; IDSet distinguishes a
// notification (no id member) from a request with an explicitly null id
// (which the MCP transport forbids).
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
	IDSet   bool            `json:"-"`
	Params  json.RawMessage `json:"params"`
}

// UnmarshalJSON captures ID presence alongside the value.
func (r *rpcRequest) UnmarshalJSON(data []byte) error {
	type alias struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
		Params  json.RawMessage `json:"params"`
	}
	var a alias
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&a); err != nil {
		return err
	}
	r.JSONRPC, r.Method, r.ID, r.Params = a.JSONRPC, a.Method, a.ID, a.Params
	r.IDSet = a.ID != nil
	return nil
}

// isNotification reports whether the message is a notification (no id
// member). An explicit `"id": null` is NOT a notification — JSON-RPC 2.0
// discourages it and MCP forbids it; it is rejected as an invalid request.
func (r *rpcRequest) isNotification() bool {
	return !r.IDSet
}

// rpcError is the JSON-RPC error object. Data carries the structured
// gateway error (code/message/kind/url) for server-error-range failures.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// rpcResponse is one outbound JSON-RPC 2.0 response. Exactly one of
// Result/Error is set (the constructors enforce it).
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func newRPCResult(id json.RawMessage, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func newRPCError(id json.RawMessage, code int, message string, data any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message, Data: data}}
}

// validateEnvelope checks the JSON-RPC 2.0 request envelope: jsonrpc must be
// exactly "2.0", method non-empty, and an explicit null id rejected.
func (r *rpcRequest) validateEnvelope() error {
	if r.JSONRPC != "2.0" {
		return fmt.Errorf("jsonrpc member must be %q", "2.0")
	}
	if r.Method == "" {
		return fmt.Errorf("method member is required")
	}
	if r.IDSet && isNullJSON(r.ID) {
		return fmt.Errorf("id must not be null")
	}
	return nil
}

func isNullJSON(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
