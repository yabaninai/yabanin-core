package apiformat

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestToAnthropicError_Table(t *testing.T) {
	body := []byte(`{"error":{"message":"nope","type":"invalid_request_error"}}`)
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, "invalid_request_error"},
		{http.StatusUnprocessableEntity, "invalid_request_error"},
		{http.StatusUnauthorized, "authentication_error"},
		{http.StatusForbidden, "permission_error"},
		{http.StatusNotFound, "not_found_error"},
		{http.StatusRequestEntityTooLarge, "request_too_large"},
		{http.StatusTooManyRequests, "rate_limit_error"},
		{http.StatusServiceUnavailable, "overloaded_error"},
		{http.StatusBadGateway, "api_error"},
		{http.StatusInternalServerError, "api_error"},
		{http.StatusConflict, "invalid_request_error"},
	}
	for _, tc := range cases {
		out, hdr := ToAnthropicError(tc.status, body)
		var doc struct {
			Type  string `json:"type"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("status %d: %v", tc.status, err)
		}
		if doc.Type != "error" || doc.Error.Type != tc.want || doc.Error.Message != "nope" {
			t.Fatalf("status %d: %+v", tc.status, doc)
		}
		switch tc.status {
		case http.StatusBadGateway, http.StatusServiceUnavailable:
			if hdr.Get("x-should-retry") != "true" {
				t.Fatalf("status %d retry = %q", tc.status, hdr.Get("x-should-retry"))
			}
		default:
			if hdr.Get("x-should-retry") != "" {
				t.Fatalf("status %d unexpected retry %q", tc.status, hdr.Get("x-should-retry"))
			}
		}
	}
}

func TestToAnthropicError_GatewayCodeAndRetry(t *testing.T) {
	body := []byte(`{"error":{"message":"blocked","type":"guard_denied"}}`)
	out, hdr := ToAnthropicError(http.StatusForbidden, body)
	var doc struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Error.Message != "[guard_denied] blocked" {
		t.Fatalf("message = %q", doc.Error.Message)
	}
	if hdr.Get("x-should-retry") != "false" {
		t.Fatalf("retry = %q", hdr.Get("x-should-retry"))
	}

	coded := []byte(`{"error":{"message":"slow","type":"rate_limit_exceeded","code":"budget_exceeded"}}`)
	_, hdr = ToAnthropicError(http.StatusTooManyRequests, coded)
	if hdr.Get("x-should-retry") != "false" {
		t.Fatalf("code wins retry = %q", hdr.Get("x-should-retry"))
	}

	_, hdr = ToAnthropicError(http.StatusGatewayTimeout, []byte(`{"error":{"message":"down","type":"api_error"}}`))
	if hdr.Get("x-should-retry") != "true" {
		t.Fatalf("504 retry = %q", hdr.Get("x-should-retry"))
	}
}

func TestToResponsesError_NormalisesParam(t *testing.T) {
	out := ToResponsesError(http.StatusBadRequest, []byte(`{"error":{"message":"bad","type":"invalid_request_error","code":"model_not_found"}}`))
	var doc struct {
		Error struct {
			Message string          `json:"message"`
			Type    string          `json:"type"`
			Param   json.RawMessage `json:"param"`
			Code    string          `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Error.Message != "bad" || doc.Error.Type != "invalid_request_error" || doc.Error.Code != "model_not_found" {
		t.Fatalf("%+v", doc.Error)
	}
	if string(doc.Error.Param) != "null" {
		t.Fatalf("param = %s", doc.Error.Param)
	}

	out = ToResponsesError(http.StatusBadRequest, []byte(`{"error":{"message":"bad","type":"invalid_request_error","param":"model"}}`))
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Error.Param) != `"model"` {
		t.Fatalf("param = %s", doc.Error.Param)
	}
	if !strings.Contains(string(out), `"code":null`) {
		t.Fatalf("missing null code: %s", out)
	}
}

func TestParseGatewayError_Malformed(t *testing.T) {
	fe := ParseGatewayError([]byte(`not-json`))
	if fe.Message != "" || fe.Type != "" || GatewayCode(fe) != "" {
		t.Fatalf("%+v", fe)
	}
}
