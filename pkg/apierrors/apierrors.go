// Package apierrors is the single typed gateway error (E) and the per-surface
// wire adapters (OpenAI JSON, SSE frame, Anthropic, Responses, admin JSON).
// rendered by exactly one adapter per client wire format, so the formats
// cannot drift apart. The adapters consolidate the pre-existing behavior of
// pkg/errors, pkg/apiformat and the gateway/admin writers — the wire is
// pinned by golden tests in the owning packages and contracts/api-contract.json.
package apierrors

// Canonical OpenAI-convention error types (A1 §8 / contracts/api-contract.json).
const (
	TypeInvalidRequest     = "invalid_request_error"
	TypeAuthentication     = "authentication_error"
	TypePermissionDenied   = "permission_denied_error"
	TypeRateLimitExceeded  = "rate_limit_exceeded"
	TypeAPI                = "api_error"
	TypeServiceUnavailable = "service_unavailable_error"
	TypeNotFound           = "not_found_error"
)

// standardTypes are the OpenAI error types above. Any other non-empty Type is
// treated as a gateway code when Code itself is empty (A1 §8).
var standardTypes = map[string]struct{}{
	TypeInvalidRequest:     {},
	TypeAuthentication:     {},
	TypePermissionDenied:   {},
	TypeRateLimitExceeded:  {},
	TypeAPI:                {},
	TypeServiceUnavailable: {},
	TypeNotFound:           {},
}

// noRetryCodes are budget and access failures the client must not retry.
var noRetryCodes = map[string]struct{}{
	"budget_exceeded":            {},
	"agent_budget_exceeded":      {},
	"budget_not_configured":      {},
	"permission_denied":          {},
	"residency_policy_violation": {},
	"guard_denied":               {},
}

// E is the wire-format-independent gateway error. Zero Status means the
// caller owns the HTTP status (e.g. body-only conversions).
type E struct {
	Status  int    // HTTP status for the response (0 = caller decides)
	Type    string // error type; surface adapters may remap (Anthropic)
	Code    string // optional stable machine-readable code
	Param   string // optional request parameter the error is about
	Message string // human-readable message, safe to show to clients
}

// New builds an E with the canonical fields. Status is kept for adapters that
// write responses; body-only adapters ignore it.
func New(status int, errType, message string) *E {
	return &E{Status: status, Type: errType, Message: message}
}

// Error implements the error interface; the message is the client-safe text.
func (e *E) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// WithCode sets the stable machine-readable code and returns e for chaining.
func (e *E) WithCode(code string) *E {
	e.Code = code
	return e
}

// WithParam sets the offending request parameter and returns e for chaining.
func (e *E) WithParam(param string) *E {
	e.Param = param
	return e
}

// GatewayCode returns the code field when set, otherwise a non-standard type.
// Mirrors apiformat.GatewayCode (A1 §8): a type outside standardTypes is a
// gateway code (guard_denied, budget_exceeded, …), not a wire type.
func GatewayCode(e *E) string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return e.Code
	}
	if _, std := standardTypes[e.Type]; e.Type != "" && !std {
		return e.Type
	}
	return ""
}
