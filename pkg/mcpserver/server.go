package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Transport header names. The supported protocol version matrix and the
// version consts (protocolVersionLatest/protocolVersionPrevious) live in
// version.go — the single source of truth for initialize negotiation and
// the follow-up MCP-Protocol-Version header check.
const (
	sessionHeader         = "Mcp-Session-Id"
	protocolVersionHeader = "MCP-Protocol-Version"
)

// defaults for zero Config values.
const (
	defaultMaxBodyBytes = 1 << 20 // 1 MiB, the invoke endpoint's body cap
	defaultPageSize     = 100
	defaultSessionTTL   = 12 * time.Hour
)

// Server is the native MCP Streamable HTTP endpoint. Mount it behind the
// gateway auth middleware (agent keys) and the shared key rate limiter.
type Server struct {
	cfg     Config
	backend Backend
	log     *slog.Logger
	session *sessionSigner
}

// New builds the endpoint. backend is the gateway aggregator surface; log
// may be nil (discarded); secret seeds the session HMAC (nil = generated).
func New(cfg Config, backend Backend, log *slog.Logger, secret []byte) *Server {
	if backend == nil {
		panic("mcpserver: nil backend")
	}
	if log == nil {
		log = slog.New(discardHandler{})
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "yabanin-mcp-gateway"
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "1.0.0"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxJSONDepth <= 0 {
		cfg.MaxJSONDepth = defaultMaxJSONDepth
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	return &Server{cfg: cfg, backend: backend, log: log, session: newSessionSigner(secret, cfg.SessionTTL)}
}

// discardHandler is a slog.Handler that drops everything (tests, silent ops).
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool { return false }
func (discardHandler) Handle(context.Context, slog.Record) error {
	return nil
}
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}
func (h discardHandler) WithGroup(string) slog.Handler { return h }

// ServeHTTP routes the Streamable HTTP transport: POST carries JSON-RPC
// messages; GET would be the server→client SSE stream (not offered — 405,
// spec-allowed, so the only reconnect path is a fresh initialize); DELETE
// terminates a session server-side — later requests carrying the cancelled
// id get the spec's 404 re-initialize signal.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.servePost(w, r)
	case http.MethodGet:
		w.Header().Set("Allow", "POST, DELETE")
		countRequest("stream", "method_not_allowed")
		http.Error(w, "GET /mcp (server-initiated SSE) is not offered; use POST", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		s.serveDelete(w, r)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		countRequest("stream", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveDelete terminates a session (the spec's client-initiated cancel):
// a valid session is revoked and every later request carrying it is 404 —
// the same re-initialize signal as an unknown session. An invalid session
// is 404 (nothing to terminate). No session header is a no-op ack (204) —
// stateless clients hold nothing to terminate. When the revocation registry
// is exhausted the termination is refused with 500 instead of acknowledged
// falsely: the client learns the cancel did not complete and recovers by
// simply dropping the id and re-initializing (or retrying later).
func (s *Server) serveDelete(w http.ResponseWriter, r *http.Request) {
	if sid := r.Header.Get(sessionHeader); sid != "" {
		if err := s.session.revoke(sid); err != nil {
			if errors.Is(err, errRevocationExhausted) {
				countRequest("delete", "internal")
				http.Error(w, "session termination temporarily unavailable", http.StatusInternalServerError)
				return
			}
			countSession("rejected")
			countRequest("delete", "protocol_error")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		countSession("cancelled")
	}
	countRequest("delete", "ok")
	w.WriteHeader(http.StatusNoContent)
}

// servePost handles one JSON-RPC message.
func (s *Server) servePost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Auth first: the principal is gateway-verified (middleware) and
	// agent-only — the same 401/403 shape as POST /api/mcp/invoke. Failures
	// are transport-level, before any JSON-RPC parsing.
	p, perr := s.principal(r)
	if perr != nil {
		countRequest("auth", "unauthorized")
		writePrincipalError(w, perr)
		return
	}

	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		countRequest("parse_error", "protocol_error")
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Session + protocol-version validation for follow-up requests. A
	// session is REQUIRED to be valid when presented but MAY be absent
	// (stateless clients stay compatible; the header is issued at
	// initialize and my smoke client always presents it).
	if sid := r.Header.Get(sessionHeader); sid != "" {
		if err := s.session.validate(sid); err != nil {
			countSession("rejected")
			countRequest("session", "protocol_error")
			// 404 is the spec's "session expired/unknown — re-initialize".
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	if v := r.Header.Get(protocolVersionHeader); v != "" && !supportedProtocolVersion(v) {
		countRequest("session", "protocol_error")
		http.Error(w, fmt.Sprintf("unsupported MCP-Protocol-Version %q", v), http.StatusBadRequest)
		return
	}

	// Bounded read: oversized bodies are rejected before parsing.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		countRequest("parse_error", "protocol_error")
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	s.handleMessage(w, r, p, body, start)
}

// handleMessage parses one JSON-RPC message and dispatches it. JSON-RPC
// error responses ride HTTP 200 (they are valid RPC replies); only
// transport-level failures use error statuses.
func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request, p Principal, body []byte, start time.Time) {
	// Batching was removed in the 2025-06-18 transport; an array body is an
	// invalid request (checked before decoding — an array never decodes into
	// a single message).
	if isJSONArray(body) {
		countRequest("parse_error", "protocol_error")
		s.writeRPC(w, r, newRPCError(nil, codeInvalidRequest, "Invalid Request: batch messages are not supported", nil))
		return
	}
	// Parse error (-32700): the body is not valid JSON.
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		countRequest("parse_error", "protocol_error")
		s.writeRPC(w, r, newRPCError(nil, codeParseError, "Parse error: "+err.Error(), nil))
		return
	}
	// Depth abuse guard (byte-level; a valid document nests a few levels).
	if d := jsonMaxDepth(body); d < 0 || d > s.cfg.MaxJSONDepth {
		countRequest("parse_error", "protocol_error")
		s.writeRPC(w, r, newRPCError(nil, codeInvalidRequest,
			fmt.Sprintf("Invalid Request: JSON nesting depth exceeds %d", s.cfg.MaxJSONDepth), nil))
		return
	}

	// Not-a-request messages are acknowledged per spec, not dispatched:
	// notifications (no id — initialized/cancelled land here) and
	// client→server responses (id, no method; nothing is pending in this
	// minimal request/response flow).
	if req.isNotification() || req.Method == "" {
		s.logRequest(r, p, req.Method, "accepted", start)
		countRequest(methodLabel(req.Method), "ok")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	// Envelope validation applies to requests only.
	if err := req.validateEnvelope(); err != nil {
		countRequest("parse_error", "protocol_error")
		s.writeRPC(w, r, newRPCError(req.ID, codeInvalidRequest, "Invalid Request: "+err.Error(), nil))
		return
	}

	s.dispatch(w, r, p, &req, start)
}

// dispatch routes one JSON-RPC request (has id) to its handler.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, p Principal, req *rpcRequest, start time.Time) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(w, r, req)
	case "tools/list":
		s.handleToolsList(w, r, p, req)
	case "tools/call":
		s.handleToolsCall(w, r, p, req, start)
	case "ping":
		countRequest("ping", "ok")
		s.writeRPC(w, r, newRPCResult(req.ID, struct{}{}))
	default:
		countRequest("unknown", "protocol_error")
		s.writeRPC(w, r, newRPCError(req.ID, codeMethodNotFound,
			fmt.Sprintf("Method not found: %q", req.Method), nil))
	}
}

// initializeParams is the client's initialize request payload.
type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

// handleInitialize negotiates the protocol version and issues a session.
func (s *Server) handleInitialize(w http.ResponseWriter, r *http.Request, req *rpcRequest) {
	var params initializeParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			countRequest("initialize", "protocol_error")
			s.writeRPC(w, r, newRPCError(req.ID, codeInvalidParams, "Invalid params: "+err.Error(), nil))
			return
		}
	}
	version := negotiateProtocolVersion(params.ProtocolVersion)
	sid := s.session.issue()
	countSession("created")
	countRequest("initialize", "ok")
	w.Header().Set(sessionHeader, sid)
	s.writeRPC(w, r, newRPCResult(req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    s.cfg.ServerName,
			"version": s.cfg.ServerVersion,
		},
		"instructions": "Tools are the ones granted to this agent key on the Yabanin gateway. " +
			"Call them with tools/call using the exact catalog names; every call passes the gateway guardrails.",
	}))
}

// handleToolsList serves the grant- and policy-filtered catalog with cursor
// pagination (opaque base64 offsets into the backend's stable ordering).
func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, p Principal, req *rpcRequest) {
	var params struct {
		Cursor string `json:"cursor"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			countRequest("tools/list", "protocol_error")
			s.writeRPC(w, r, newRPCError(req.ID, codeInvalidParams, "Invalid params: "+err.Error(), nil))
			return
		}
	}
	offset := 0
	if params.Cursor != "" {
		var err error
		raw, err := base64.RawURLEncoding.DecodeString(params.Cursor)
		if err == nil {
			offset, err = strconv.Atoi(string(raw))
		}
		if err != nil || offset < 0 {
			countRequest("tools/list", "protocol_error")
			s.writeRPC(w, r, newRPCError(req.ID, codeInvalidParams, "Invalid params: malformed cursor", nil))
			return
		}
	}
	tools, err := s.backend.Tools(r.Context(), p)
	if err != nil {
		countRequest("tools/list", "internal")
		s.log.Error("mcpserver: tools/list backend failed", "error", err)
		s.writeRPC(w, r, newRPCError(req.ID, codeInternal, "Internal error", nil))
		return
	}
	if offset > len(tools) {
		offset = len(tools)
	}
	end := offset + s.cfg.PageSize
	if end > len(tools) {
		end = len(tools)
	}
	page := tools[offset:end]
	next := ""
	if end < len(tools) {
		next = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	countRequest("tools/list", "ok")
	s.writeRPC(w, r, newRPCResult(req.ID, ToolPage{Tools: page, NextCursor: next}))
}

// handleToolsCall proxies one tool call into the backend (the mcpagg invoke
// path with its full guard chain). Guard/auth failures surface as JSON-RPC
// errors carrying the gateway code in error.data.
func (s *Server) handleToolsCall(w http.ResponseWriter, r *http.Request, p Principal, req *rpcRequest, start time.Time) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		countRequest("tools/call", "protocol_error")
		s.writeRPC(w, r, newRPCError(req.ID, codeInvalidParams, "Invalid params: "+err.Error(), nil))
		return
	}
	if params.Name == "" {
		countRequest("tools/call", "protocol_error")
		s.writeRPC(w, r, newRPCError(req.ID, codeInvalidParams, "Invalid params: name is required", nil))
		return
	}
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage(`{}`)
	}
	result, err := s.backend.Call(r.Context(), p, params.Name, params.Arguments)
	if err != nil {
		var callErr *ToolCallError
		if errors.As(err, &callErr) {
			countRequest("tools/call", "denied")
			data := map[string]any{"code": callErr.Code, "message": callErr.Message}
			if callErr.Kind != "" {
				data["kind"] = callErr.Kind
			}
			if callErr.URL != "" {
				data["url"] = callErr.URL
			}
			s.writeRPC(w, r, newRPCError(req.ID, serverErrorCode, callErr.Code, data))
			return
		}
		countRequest("tools/call", "internal")
		s.log.Error("mcpserver: tools/call backend failed", "tool", params.Name, "error", err)
		s.writeRPC(w, r, newRPCError(req.ID, codeInternal, "Internal error", nil))
		return
	}
	countRequest("tools/call", "ok")
	s.logRequest(r, p, "tools/call:"+params.Name, "ok", start)
	s.writeRPC(w, r, newRPCResult(req.ID, normalizeToolResult(result)))
}

// normalizeToolResult passes an upstream MCP CallToolResult through
// verbatim and wraps any other shape as a text result, so clients always
// receive a valid tools/call result object.
func normalizeToolResult(result json.RawMessage) json.RawMessage {
	var probe struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(result, &probe); err == nil && probe.Content != nil {
		return result
	}
	wrapped, err := json.Marshal(map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(result)}},
		"isError": false,
	})
	if err != nil {
		return json.RawMessage(`{"content":[{"type":"text","text":""}],"isError":false}`)
	}
	return wrapped
}

// principal resolves the verified caller (injected reader, else the gateway
// identity headers).
func (s *Server) principal(r *http.Request) (Principal, error) {
	if s.cfg.Principal != nil {
		return s.cfg.Principal(r)
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		return Principal{}, &PrincipalError{Status: http.StatusUnauthorized,
			Code: "authentication", Message: "org resolution failed"}
	}
	agentID := r.Header.Get("X-Agent-Id")
	if agentID == "" {
		return Principal{}, &PrincipalError{Status: http.StatusForbidden,
			Code: "agent_only", Message: "mcp tool-calls require an agent-principal (yag_) key"}
	}
	return Principal{
		OrgID:   orgID,
		AgentID: agentID,
		TeamID:  r.Header.Get("X-Team-Id"),
		TaskID:  r.Header.Get("X-Yabanin-Task"),
	}, nil
}

// writeRPC renders the response in the mode the client's Accept header
// allows: application/json (preferred) or a single-message SSE stream.
func (s *Server) writeRPC(w http.ResponseWriter, r *http.Request, resp *rpcResponse) {
	accept := r.Header.Get("Accept")
	canJSON := accepts(accept, "application/json")
	canSSE := accepts(accept, "text/event-stream")
	if !canJSON && !canSSE {
		http.Error(w, "Accept header must include application/json or text/event-stream", http.StatusNotAcceptable)
		return
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	if canJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	// SSE mode: one `message` event carrying the JSON-RPC response.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", body)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// writePrincipalError renders an auth-layer rejection (invoke-endpoint
// parity: the same status/code shape as /api/mcp/invoke).
func writePrincipalError(w http.ResponseWriter, err error) {
	var pe *PrincipalError
	if !errors.As(err, &pe) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(pe.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"code": pe.Code, "message": pe.Message},
	})
}

// accepts reports whether the Accept header lists the media type (exact
// token or type/*; parameters are ignored).
func accepts(header, mediaType string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, ';'); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		if strings.EqualFold(part, mediaType) {
			return true
		}
	}
	return false
}

// isJSONArray reports whether the body is a JSON array (batch).
func isJSONArray(body []byte) bool {
	for _, c := range body {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// methodLabel maps a method to its metric label (notifications and unknown
// messages collapse into bounded label sets).
func methodLabel(method string) string {
	switch method {
	case "notifications/initialized", "notifications/cancelled", "notifications":
		return "notification"
	case "":
		return "response"
	default:
		if strings.HasPrefix(method, "notifications/") {
			return "notification"
		}
		return "unknown"
	}
}

// logRequest writes the request-log line marked with the endpoint label.
func (s *Server) logRequest(r *http.Request, p Principal, method, outcome string, start time.Time) {
	s.log.Info("mcp streamable request",
		"endpoint", "mcp.streamable",
		"method", r.Method,
		"rpc_method", method,
		"outcome", outcome,
		"org", p.OrgID,
		"agent", p.AgentID,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
