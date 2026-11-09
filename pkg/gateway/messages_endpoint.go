package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
)

func (gw *gateway) messages(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAnthropicStatus(w, http.StatusBadRequest, "request body too large or malformed")
		return
	}
	if r.Header.Get("X-Session-Id") == "" {
		if sid := r.Header.Get("x-claude-code-session-id"); sid != "" && budget.ValidTaskID(sid) {
			r.Header.Set("X-Session-Id", sid)
		}
	}
	var probe struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &probe) == nil {
		// RT-06: probe resolution runs under the request context. A registry
		// outage degrades to the adapted path, where admission re-resolves
		// the candidate and surfaces 503 — the probe never fabricates data.
		if info, resErr := gw.resolveModelInfo(r.Context(), probe.Model); resErr == nil && info.Provider == "anthropic" {
			gw.messagesNative(w, r, body, probe.Model)
			return
		}
	}
	chatBody, meta, ferr := apiformat.AnthropicToChat(body)
	if ferr != nil {
		status := ferr.Status
		if status == 0 {
			status = http.StatusBadRequest
		}
		writeAnthropicFormat(w, status, ferr)
		return
	}
	if len(meta.Dropped) > 0 {
		w.Header().Set("X-Yabanin-Dropped", unsupportedHeader(meta.Dropped))
	}
	r2 := r.Clone(withEndpoint(r.Context(), "messages"))
	r2.Body = io.NopCloser(bytes.NewReader(chatBody))
	r2.ContentLength = int64(len(chatBody))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Del("X-Yabanin-Raw-Body")
	aw := apiformat.NewAnthropicWriter(w, meta, apiformat.AnthropicOptions{})
	gw.chatCompletions(aw, r2)
	aw.Finish()
}

func writeAnthropicFormat(w http.ResponseWriter, status int, ferr *apiformat.FormatError) {
	raw, err := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": ferr.Message,
			"type":    ferr.Type,
			"code":    ferr.Code,
		},
	})
	if err != nil {
		writeAnthropicStatus(w, http.StatusInternalServerError, "failed to encode error")
		return
	}
	body, hdr := apiformat.ToAnthropicError(status, raw)
	writeAnthropicBody(w, status, hdr, body)
}

func writeAnthropicStatus(w http.ResponseWriter, status int, message string) {
	raw, err := json.Marshal(map[string]any{
		"error": map[string]string{"message": message, "type": "invalid_request_error"},
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	body, hdr := apiformat.ToAnthropicError(status, raw)
	writeAnthropicBody(w, status, hdr, body)
}

func writeAnthropicBody(w http.ResponseWriter, status int, hdr http.Header, body []byte) {
	for key, values := range hdr {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// anthropicErrorEnvelope turns an OpenAI error body into an Anthropic error
// after the handler returns. A body that already starts with {"type":"error"
// is left unchanged. Success and streams pass through.
func anthropicErrorEnvelope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ew := &anthEnvelope{ResponseWriter: w}
		next.ServeHTTP(ew, r)
		ew.finish()
	})
}

type anthEnvelope struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	wrote  bool
	hold   bool
}

func (e *anthEnvelope) WriteHeader(code int) {
	if e.wrote || e.hold {
		return
	}
	e.status = code
	if code >= 400 {
		e.hold = true
		return
	}
	e.wrote = true
	e.ResponseWriter.WriteHeader(code)
}

func (e *anthEnvelope) Write(p []byte) (int, error) {
	if !e.wrote && !e.hold {
		e.WriteHeader(http.StatusOK)
	}
	if e.hold {
		return e.buf.Write(p)
	}
	return e.ResponseWriter.Write(p)
}

func (e *anthEnvelope) Flush() {
	if e.hold {
		return
	}
	if f, ok := e.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (e *anthEnvelope) finish() {
	if !e.hold {
		return
	}
	body := e.buf.Bytes()
	code := e.status
	if code == 0 {
		code = http.StatusBadRequest
	}
	hdr := http.Header(nil)
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte(`{"type":"error"`)) {
		body, hdr = apiformat.ToAnthropicError(code, body)
	}
	for key, values := range hdr {
		for _, value := range values {
			e.Header().Add(key, value)
		}
	}
	e.Header().Set("Content-Type", "application/json")
	e.ResponseWriter.WriteHeader(code)
	_, _ = e.ResponseWriter.Write(body)
}
