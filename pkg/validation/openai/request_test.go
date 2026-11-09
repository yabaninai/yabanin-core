package validator

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: build a pointer to a float64 or int for test convenience.
// ---------------------------------------------------------------------------

func ptrF64(v float64) *float64 { return &v }
func ptrInt(v int) *int         { return &v }

// ---------------------------------------------------------------------------
// ValidRequest — the happy path
// ---------------------------------------------------------------------------

func TestValidateRequest_ValidRequest(t *testing.T) {
	t.Run("minimal valid request", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Messages: []openai.ChatMessage{{Role: "user", Content: "hello"}},
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("all valid roles accepted", func(t *testing.T) {
		for _, role := range []string{"user", "assistant", "system", "tool", "function"} {
			req := openai.ChatCompletionRequest{
				Messages: []openai.ChatMessage{{Role: role, Content: "ok"}},
			}
			err, code := ValidateRequest(req)
			assert.Nil(t, err, "role %q should be valid", role)
			assert.Zero(t, code, "role %q should be valid", role)
		}
	})

	t.Run("all fields populated within limits", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Model:       "gpt-4",
			Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
			Stream:      true,
			Temperature: ptrF64(0.5),
			MaxTokens:   ptrInt(100),
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("OpenCode GLM output limit", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
			MaxTokens: ptrInt(32768),
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("10000 messages (boundary)", func(t *testing.T) {
		msgs := make([]openai.ChatMessage, 10000)
		for i := range msgs {
			msgs[i] = openai.ChatMessage{Role: "user", Content: "x"}
		}
		req := openai.ChatCompletionRequest{Messages: msgs}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("temperature at exact min boundary", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
			Temperature: ptrF64(-2.0),
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("temperature at exact max boundary", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
			Temperature: ptrF64(2.0),
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("max_tokens at exact min boundary", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
			MaxTokens: ptrInt(1),
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("max_tokens at exact max boundary", func(t *testing.T) {
		req := openai.ChatCompletionRequest{
			Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
			MaxTokens: ptrInt(131072),
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})

	t.Run("content exactly maxContentBytes bytes", func(t *testing.T) {
		content := make([]byte, 1<<20)
		for i := range content {
			content[i] = 'a'
		}
		req := openai.ChatCompletionRequest{
			Messages: []openai.ChatMessage{{Role: "user", Content: string(content)}},
		}
		err, code := ValidateRequest(req)
		assert.Nil(t, err)
		assert.Zero(t, code)
	})
}

// ---------------------------------------------------------------------------
// Empty / missing messages
// ---------------------------------------------------------------------------

func TestValidateRequest_MessagesRequired(t *testing.T) {
	req := openai.ChatCompletionRequest{Messages: nil}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "messages is required", err.Error.Message)
	assert.Equal(t, errors.ErrorCodeInvalidRequest, err.Error.Type)
}

func TestValidateRequest_EmptyMessagesSlice(t *testing.T) {
	req := openai.ChatCompletionRequest{Messages: []openai.ChatMessage{}}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "messages is required", err.Error.Message)
}

// ---------------------------------------------------------------------------
// Too many messages
// ---------------------------------------------------------------------------

func TestValidateRequest_TooManyMessages(t *testing.T) {
	msgs := make([]openai.ChatMessage, 10001)
	for i := range msgs {
		msgs[i] = openai.ChatMessage{Role: "user", Content: "x"}
	}
	req := openai.ChatCompletionRequest{Messages: msgs}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "expected at most 10000 messages")
	assert.Contains(t, err.Error.Message, "got 10001")
	param := "messages"
	assert.Equal(t, &param, err.Error.Param)
}

func TestValidateRequest_TooManyMessages_HugeNumber(t *testing.T) {
	msgs := make([]openai.ChatMessage, 50000)
	for i := range msgs {
		msgs[i] = openai.ChatMessage{Role: "user", Content: "x"}
	}
	req := openai.ChatCompletionRequest{Messages: msgs}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "got 50000")
}

// ---------------------------------------------------------------------------
// Invalid role
// ---------------------------------------------------------------------------

func TestValidateRequest_InvalidRole(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages: []openai.ChatMessage{{Role: "invalid_role", Content: "hi"}},
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, `invalid message role: "invalid_role"`)
	assert.Equal(t, ptrStr("messages[0].role"), err.Error.Param)
}

func TestValidateRequest_InvalidRoleInMiddleOfList(t *testing.T) {
	msgs := []openai.ChatMessage{
		{Role: "user", Content: "first"},
		{Role: "bad", Content: "second"},
	}
	req := openai.ChatCompletionRequest{Messages: msgs}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, `invalid message role: "bad"`)
	assert.Equal(t, ptrStr("messages[1].role"), err.Error.Param)
}

// ---------------------------------------------------------------------------
// Content size limit
// ---------------------------------------------------------------------------

func TestValidateRequest_ContentExceedsLimit(t *testing.T) {
	content := make([]byte, (1<<20)+1)
	for i := range content {
		content[i] = 'a'
	}
	req := openai.ChatCompletionRequest{
		Messages: []openai.ChatMessage{{Role: "user", Content: string(content)}},
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "exceeds limit of 1048576 bytes")
	assert.Equal(t, ptrStr("messages[0].content"), err.Error.Param)
}

func TestValidateRequest_ContentExceedsLimit_InMiddleMessage(t *testing.T) {
	content := make([]byte, (1<<20)+1)
	for i := range content {
		content[i] = 'a'
	}
	msgs := []openai.ChatMessage{
		{Role: "user", Content: "small"},
		{Role: "assistant", Content: string(content)},
	}
	req := openai.ChatCompletionRequest{Messages: msgs}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "exceeds limit of 1048576 bytes")
	assert.Equal(t, ptrStr("messages[1].content"), err.Error.Param)
}

// ---------------------------------------------------------------------------
// Temperature — NaN / Inf
// ---------------------------------------------------------------------------

func TestValidateRequest_TemperatureNaN(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: ptrF64(math.NaN()),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "NaN")
	assert.Equal(t, ptrStr("temperature"), err.Error.Param)
}

func TestValidateRequest_TemperaturePositiveInf(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: ptrF64(math.Inf(1)),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "Inf")
	assert.Equal(t, ptrStr("temperature"), err.Error.Param)
}

func TestValidateRequest_TemperatureNegativeInf(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: ptrF64(math.Inf(-1)),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "Inf")
	assert.Equal(t, ptrStr("temperature"), err.Error.Param)
}

// ---------------------------------------------------------------------------
// Temperature — out of range
// ---------------------------------------------------------------------------

func TestValidateRequest_TemperatureBelowMin(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: ptrF64(-2.01),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between -2.0 and 2.0")
	assert.Equal(t, ptrStr("temperature"), err.Error.Param)
}

func TestValidateRequest_TemperatureAboveMax(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: ptrF64(2.01),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between -2.0 and 2.0")
	assert.Equal(t, ptrStr("temperature"), err.Error.Param)
}

func TestValidateRequest_TemperatureVeryLarge(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: ptrF64(100.0),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between -2.0 and 2.0")
}

// ---------------------------------------------------------------------------
// MaxTokens — out of range
// ---------------------------------------------------------------------------

func TestValidateRequest_MaxTokensBelowMin(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
		MaxTokens: ptrInt(0),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between 1 and 131072")
	assert.Equal(t, ptrStr("max_tokens"), err.Error.Param)
}

func TestValidateRequest_MaxTokensAboveMax(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
		MaxTokens: ptrInt(131073),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between 1 and 131072")
	assert.Equal(t, ptrStr("max_tokens"), err.Error.Param)
}

func TestValidateRequest_MaxTokensVeryLarge(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
		MaxTokens: ptrInt(200000),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between 1 and 131072")
}

func TestValidateRequest_MaxTokensNegative(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:  []openai.ChatMessage{{Role: "user", Content: "hi"}},
		MaxTokens: ptrInt(-5),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "must be between 1 and 131072")
}

// ---------------------------------------------------------------------------
// Combined / multiple validation failures (first failure wins)
// ---------------------------------------------------------------------------

func TestValidateRequest_FirstFailureWins_EmptyAndInvalidTemp(t *testing.T) {
	// Empty messages triggers first error; temperature is also invalid but should not be reached.
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{},
		Temperature: ptrF64(math.NaN()),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, "messages is required")
}

func TestValidateRequest_FirstFailureWins_InvalidRoleAndBadTemp(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "bogus", Content: "hi"}},
		Temperature: ptrF64(99.0),
	}
	err, code := ValidateRequest(req)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, err.Error.Message, `invalid message role: "bogus"`)
}

// ---------------------------------------------------------------------------
// Edge cases with nil pointer fields (should be ignored / pass)
// ---------------------------------------------------------------------------

func TestValidateRequest_NilTemperatureAndMaxTokens(t *testing.T) {
	req := openai.ChatCompletionRequest{
		Messages:    []openai.ChatMessage{{Role: "user", Content: "hi"}},
		Temperature: nil,
		MaxTokens:   nil,
	}
	err, code := ValidateRequest(req)

	assert.Nil(t, err)
	assert.Zero(t, code)
}

// ---------------------------------------------------------------------------
// WriteError — verifies JSON error response format
// ---------------------------------------------------------------------------

func TestWriteError_SetsCorrectHeadersAndBody(t *testing.T) {
	apiErr := &errors.APIError{
		Error: errors.ErrorResponse{
			Message: "test error",
			Type:    errors.ErrorCodeInvalidRequest,
			Param:   ptrStr("messages"),
			Code:    ptrStr("validation_error"),
		},
	}

	rec := httptest.NewRecorder()
	WriteError(rec, apiErr, http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))

	var resp errors.APIError
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "test error", resp.Error.Message)
	assert.Equal(t, errors.ErrorCodeInvalidRequest, resp.Error.Type)
	assert.Equal(t, ptrStr("messages"), resp.Error.Param)
	assert.Equal(t, ptrStr("validation_error"), resp.Error.Code)
}

func TestWriteError_NoParamNoCode(t *testing.T) {
	apiErr := &errors.APIError{
		Error: errors.ErrorResponse{
			Message: "simple error",
			Type:    errors.ErrorCodeInvalidRequest,
		},
	}

	rec := httptest.NewRecorder()
	WriteError(rec, apiErr, http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp errors.APIError
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Nil(t, resp.Error.Param)
	assert.Nil(t, resp.Error.Code)
}
