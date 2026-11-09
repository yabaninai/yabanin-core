package validator

import (
	"fmt"
	"math"
	"net/http"

	"github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/openai"
)

const (
	// maxMessages bounds a single chat-completion request. Sized for agent
	// loops (OpenCode/Codex): every tool round-trip adds 3–4 messages, so a
	// long working session legitimately accumulates thousands. 10000 is a
	// sanity cap against runaway clients, not a real working limit.
	maxMessages            = 10000
	maxContentBytes        = 1 << 20 // 1 MiB — OpenCode tool results and file reads
	minTemperature         = -2.0
	maxTemperature         = 2.0
	maxTokensMin           = 1
	maxTokensMax           = 131072 // OpenCode GLM/local models advertise 32k–128k output
	tooManyCode            = "too_many_requests"
	requestValidationError = "validation_error"
)

var validRoles = map[string]bool{
	"user":      true,
	"assistant": true,
	"system":    true,
	"tool":      true,
	"function":  true,
}

// ValidateRequest checks a ChatCompletionRequest against all validation rules.
// Returns an APIError and HTTP status code if invalid, or (nil, 0) if valid.
func ValidateRequest(req openai.ChatCompletionRequest) (*errors.APIError, int) {
	if len(req.Messages) == 0 {
		msg := "messages is required"
		return &errors.APIError{
			Error: errors.ErrorResponse{
				Message: msg,
				Type:    errors.ErrorCodeInvalidRequest,
				Code:    &msg,
			},
		}, http.StatusBadRequest
	}

	if len(req.Messages) > maxMessages {
		msg := fmt.Sprintf("expected at most %d messages, got %d", maxMessages, len(req.Messages))
		param := "messages"
		return &errors.APIError{
			Error: errors.ErrorResponse{
				Message: msg,
				Type:    errors.ErrorCodeInvalidRequest,
				Param:   &param,
				Code:    ptrStr(tooManyCode),
			},
		}, http.StatusBadRequest
	}

	for i, msg := range req.Messages {
		if !validRoles[msg.Role] {
			msg := fmt.Sprintf("invalid message role: %q", msg.Role)
			param := fmt.Sprintf("messages[%d].role", i)
			return &errors.APIError{
				Error: errors.ErrorResponse{
					Message: msg,
					Type:    errors.ErrorCodeInvalidRequest,
					Param:   &param,
				},
			}, http.StatusBadRequest
		}

		if len(msg.Content) > maxContentBytes {
			msg := fmt.Sprintf("message %d content exceeds limit of %d bytes", i, maxContentBytes)
			param := fmt.Sprintf("messages[%d].content", i)
			return &errors.APIError{
				Error: errors.ErrorResponse{
					Message: msg,
					Type:    errors.ErrorCodeInvalidRequest,
					Param:   &param,
				},
			}, http.StatusBadRequest
		}
	}

	if req.Temperature != nil {
		t := *req.Temperature
		if math.IsNaN(t) || math.IsInf(t, 0) {
			msg := "temperature must not be NaN or Inf"
			param := "temperature"
			return &errors.APIError{
				Error: errors.ErrorResponse{
					Message: msg,
					Type:    errors.ErrorCodeInvalidRequest,
					Param:   &param,
				},
			}, http.StatusBadRequest
		}
		if t < minTemperature || t > maxTemperature {
			msg := fmt.Sprintf("temperature must be between %.1f and %.1f", minTemperature, maxTemperature)
			param := "temperature"
			return &errors.APIError{
				Error: errors.ErrorResponse{
					Message: msg,
					Type:    errors.ErrorCodeInvalidRequest,
					Param:   &param,
				},
			}, http.StatusBadRequest
		}
	}

	if req.MaxTokens != nil {
		mt := *req.MaxTokens
		if mt < maxTokensMin || mt > maxTokensMax {
			msg := fmt.Sprintf("max_tokens must be between %d and %d", maxTokensMin, maxTokensMax)
			param := "max_tokens"
			return &errors.APIError{
				Error: errors.ErrorResponse{
					Message: msg,
					Type:    errors.ErrorCodeInvalidRequest,
					Param:   &param,
				},
			}, http.StatusBadRequest
		}
	}

	return nil, 0
}

// WriteError writes an API error as JSON with the given HTTP status code.
func WriteError(w http.ResponseWriter, apiErr *errors.APIError, statusCode int) {
	errors.WriteAPIError(w, statusCode, apiErr)
}

func ptrStr(s string) *string {
	return &s
}
