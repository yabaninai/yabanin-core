package apierrors

import (
	"encoding/json"
	"net/http"
)

// openAIError is the inner error object of the OpenAI/Responses wire
// envelope. Field order (message,type,param,code) is pinned by golden tests.
type openAIError struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param,omitempty"`
	Code    *string `json:"code,omitempty"`
}

// OpenAIEnvelope is the OpenAI wire envelope: {"error":{...}}. param and code
// are omitted when empty (unlike the Responses adapter, which keeps nulls).
type OpenAIEnvelope struct {
	Error openAIError `json:"error"`
}

// OpenAI renders e in the canonical OpenAI error envelope.
func OpenAI(e *E) OpenAIEnvelope {
	env := OpenAIEnvelope{}
	if e == nil {
		return env
	}
	env.Error.Message = e.Message
	env.Error.Type = e.Type
	if e.Param != "" {
		p := e.Param
		env.Error.Param = &p
	}
	if e.Code != "" {
		c := e.Code
		env.Error.Code = &c
	}
	return env
}

// MarshalOpenAI renders e as OpenAI envelope JSON bytes (no trailing newline).
func MarshalOpenAI(e *E) ([]byte, error) {
	return json.Marshal(OpenAI(e))
}

// WriteOpenAI writes the OpenAI JSON error response: status, envelope body,
// and the surface headers (Content-Type with charset, nosniff).
func WriteOpenAI(w http.ResponseWriter, status int, e *E) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(OpenAI(e))
}

// SSEErrorFrame renders the terminal SSE error event, "data: {\"error\":…}\n\n"
// (the same OpenAI envelope riding a data line). The caller writes the
// "data: [DONE]\n\n" terminator afterwards. A non-empty e.Code rides the
// optional "code" field; an empty code leaves the frame byte-identical to
// the code-less form.
func SSEErrorFrame(e *E) []byte {
	var code *string
	if e.Code != "" {
		code = &e.Code
	}
	inner, err := json.Marshal(openAIError{Message: e.Message, Type: e.Type, Code: code})
	if err != nil {
		inner = []byte(`{"message":"encode failed","type":"api_error"}`)
	}
	return []byte("data: {\"error\":" + string(inner) + "}\n\n")
}
