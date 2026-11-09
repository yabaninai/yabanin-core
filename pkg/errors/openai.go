package errors

import (
	"net/http"

	"github.com/reireirei/yabanin/pkg/apierrors"
)

// APIError represents an OpenAI-compatible error response.
type APIError struct {
	Error ErrorResponse `json:"error"`
}

// ErrorResponse is the top-level error structure matching OpenAI's format.
type ErrorResponse struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param,omitempty"`
	Code    *string `json:"code,omitempty"`
}

// Error type strings (OpenAI convention). Values live in pkg/apierrors — the
const (
	// ErrorCodeInvalidRequest — клиент прислал мусор (400).
	ErrorCodeInvalidRequest = apierrors.TypeInvalidRequest
	// ErrorCodeAuthentication — нет/неверный API key (401).
	ErrorCodeAuthentication = apierrors.TypeAuthentication
	// ErrorCodePermissionDenied — whitelist deny (403).
	ErrorCodePermissionDenied = apierrors.TypePermissionDenied
	// ErrorCodeRateLimitExceeded — throttled (429).
	ErrorCodeRateLimitExceeded = apierrors.TypeRateLimitExceeded
	// ErrorCodeAPI — внутренний сбой (5xx).
	ErrorCodeAPI = apierrors.TypeAPI
	// ErrorCodeServiceUnavailable — upstream/circuit open (503).
	ErrorCodeServiceUnavailable = apierrors.TypeServiceUnavailable
	// ErrorCodeNotFound — ресурс не найден (404).
	ErrorCodeNotFound = apierrors.TypeNotFound
)

// Stable error `code` values (OpenAI optional field) for provider outcomes
// that clients such as OpenCode can branch on.
const (
	CodeProviderNotAuthorized = "provider_not_authorized"
	CodeQuotaExhausted        = "quota_exhausted"
	CodeUnsupportedFeature    = "unsupported_feature"
	// 401 with type authentication_error; clients can renew instead of
	// debugging an unknown-key error.
	CodeKeyExpired = "key_expired"
	// Adapter capability refusal: the model/provider cannot serve the
	// requested feature axis (streaming/tools/media input). Reported 400
	// invalid_request_error before any upstream call; clients must drop the
	// feature or switch models — retrying or failing over cannot help.
	CodeCapabilityNotSupported = "capability_not_supported"
)

// Write writes an OpenAI-shaped JSON error response with the given status, type and message.
// Always sets Content-Type to application/json and X-Content-Type-Options: nosniff.
func Write(w http.ResponseWriter, status int, errType, message string) {
	apierrors.WriteOpenAI(w, status, apierrors.New(status, errType, message))
}

// WriteWithCode is like Write but also sets the optional "code" field.
func WriteWithCode(w http.ResponseWriter, status int, errType, message, code string) {
	apierrors.WriteOpenAI(w, status, apierrors.New(status, errType, message).WithCode(code))
}

// WriteAPIError writes a pre-built APIError with the given status code.
func WriteAPIError(w http.ResponseWriter, status int, apiErr *APIError) {
	e := &apierrors.E{Status: status, Type: apiErr.Error.Type, Message: apiErr.Error.Message}
	if apiErr.Error.Param != nil {
		e.Param = *apiErr.Error.Param
	}
	if apiErr.Error.Code != nil {
		e.Code = *apiErr.Error.Code
	}
	apierrors.WriteOpenAI(w, status, e)
}

// MapUpstreamStatus maps an upstream HTTP status code to a (gateway HTTP status, OpenAI error type) pair.
// Upstream 401 is masked to 502 to avoid leaking upstream auth failures.
func MapUpstreamStatus(upstreamStatus int) (httpStatus int, errType string) {
	switch {
	case upstreamStatus == 401:
		// Mask upstream auth leak — never surface upstream 401 to clients.
		return http.StatusBadGateway, ErrorCodeAPI
	case upstreamStatus == 403:
		return http.StatusForbidden, ErrorCodePermissionDenied
	case upstreamStatus == 404:
		return http.StatusNotFound, ErrorCodeNotFound
	case upstreamStatus == 429:
		return http.StatusTooManyRequests, ErrorCodeRateLimitExceeded
	case upstreamStatus >= 400 && upstreamStatus < 500:
		return http.StatusBadRequest, ErrorCodeInvalidRequest
	case upstreamStatus >= 500:
		return http.StatusBadGateway, ErrorCodeAPI
	default:
		return http.StatusInternalServerError, ErrorCodeAPI
	}
}
