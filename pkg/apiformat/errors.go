package apiformat

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/apierrors"
)

// FormatError is a gateway error independent of the client wire format.
// Status is zero when the value came from a body that does not carry HTTP status.
type FormatError struct {
	Status  int
	Type    string
	Code    string
	Param   string
	Message string
}

// fromFormat lifts a parsed wire error into the canonical typed error.
func (fe FormatError) fromFormat() *apierrors.E {
	return &apierrors.E{Status: fe.Status, Type: fe.Type, Code: fe.Code, Param: fe.Param, Message: fe.Message}
}

// ParseGatewayError reads an OpenAI-shaped error body.
// Status is left zero: the HTTP status is not in the body.
func ParseGatewayError(body []byte) FormatError {
	var wrap struct {
		Error struct {
			Message string          `json:"message"`
			Type    string          `json:"type"`
			Param   json.RawMessage `json:"param"`
			Code    json.RawMessage `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return FormatError{}
	}
	return FormatError{
		Type:    wrap.Error.Type,
		Code:    jsonString(wrap.Error.Code),
		Param:   jsonString(wrap.Error.Param),
		Message: wrap.Error.Message,
	}
}

// GatewayCode returns the code field when set, otherwise a non-standard type.
func GatewayCode(fe FormatError) string {
	return apierrors.GatewayCode(fe.fromFormat())
}

// ToAnthropicError converts a gateway error body into an Anthropic error
// document and the headers A1 §8.1 requires. Retry-After is not copied:
// the signature receives only the body, not the inbound header. Rendering is
func ToAnthropicError(status int, body []byte) ([]byte, http.Header) {
	return apierrors.Anthropic(status, ParseGatewayError(body).fromFormat())
}

// ToResponsesError returns the same OpenAI envelope with param normalised to
// null when the gateway omitted it, and code present (null when empty).
func ToResponsesError(status int, body []byte) []byte {
	fe := ParseGatewayError(body)
	_ = status // preserved by the HTTP response, not this body
	return apierrors.Responses(fe.fromFormat())
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return strings.Trim(string(raw), `"`)
	}
	return s
}
