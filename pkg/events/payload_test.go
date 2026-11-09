package events

import (
	"encoding/json"
	"testing"
)

func TestPayload_Getters_NilSafe(t *testing.T) {
	var p *Payload

	if v := p.GetEventType(); v != "" {
		t.Errorf("GetEventType() = %q, want empty", v)
	}
	if v := p.GetSource(); v != "" {
		t.Errorf("GetSource() = %q, want empty", v)
	}
	if v := p.GetSessionID(); v != "" {
		t.Errorf("GetSessionID() = %q, want empty", v)
	}
	if v := p.GetPayload(); v != "" {
		t.Errorf("GetPayload() = %q, want empty", v)
	}
	if v := p.GetOrgID(); v != "" {
		t.Errorf("GetOrgID() = %q, want empty", v)
	}
	if v := p.GetModelRequested(); v != "" {
		t.Errorf("GetModelRequested() = %q, want empty", v)
	}
	if v := p.GetModelUsed(); v != "" {
		t.Errorf("GetModelUsed() = %q, want empty", v)
	}
	if v := p.GetUpstreamURL(); v != "" {
		t.Errorf("GetUpstreamURL() = %q, want empty", v)
	}
	if v := p.GetStatusCode(); v != 0 {
		t.Errorf("GetStatusCode() = %d, want 0", v)
	}
	if v := p.GetDurationMs(); v != 0 {
		t.Errorf("GetDurationMs() = %d, want 0", v)
	}
	if v := p.GetTokensIn(); v != 0 {
		t.Errorf("GetTokensIn() = %d, want 0", v)
	}
	if v := p.GetTokensOut(); v != 0 {
		t.Errorf("GetTokensOut() = %d, want 0", v)
	}
	if v := p.GetMethod(); v != "" {
		t.Errorf("GetMethod() = %q, want empty", v)
	}
	if v := p.GetError(); v != "" {
		t.Errorf("GetError() = %q, want empty", v)
	}
	if v := p.GetFirstTokenMs(); v != 0 {
		t.Errorf("GetFirstTokenMs() = %d, want 0", v)
	}
	if v := p.GetAttemptCount(); v != 0 {
		t.Errorf("GetAttemptCount() = %d, want 0", v)
	}
	if v := p.GetRetryCount(); v != 0 {
		t.Errorf("GetRetryCount() = %d, want 0", v)
	}
}

func TestPayload_Getters_NonNil(t *testing.T) {
	p := &Payload{
		EventType:      "request.completed",
		Source:         "gateway",
		SessionID:      "sess-123",
		Payload:        "hello",
		OrgID:          "org-456",
		ModelRequested: "gpt-4o",
		ModelUsed:      "gpt-4o-2024-05-13",
		UpstreamURL:    "https://api.openai.com/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     2500,
		TokensIn:       200,
		TokensOut:      500,
		Method:         "POST",
		Error:          "",
		FirstTokenMs:   312,
		AttemptCount:   2,
		RetryCount:     1,
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"GetEventType", p.GetEventType(), "request.completed"},
		{"GetSource", p.GetSource(), "gateway"},
		{"GetSessionID", p.GetSessionID(), "sess-123"},
		{"GetPayload", p.GetPayload(), "hello"},
		{"GetOrgID", p.GetOrgID(), "org-456"},
		{"GetModelRequested", p.GetModelRequested(), "gpt-4o"},
		{"GetModelUsed", p.GetModelUsed(), "gpt-4o-2024-05-13"},
		{"GetUpstreamURL", p.GetUpstreamURL(), "https://api.openai.com/v1/chat/completions"},
		{"GetStatusCode", p.GetStatusCode(), int64(200)},
		{"GetDurationMs", p.GetDurationMs(), int64(2500)},
		{"GetTokensIn", p.GetTokensIn(), int64(200)},
		{"GetTokensOut", p.GetTokensOut(), int64(500)},
		{"GetMethod", p.GetMethod(), "POST"},
		{"GetError", p.GetError(), ""},
		{"GetFirstTokenMs", p.GetFirstTokenMs(), int64(312)},
		{"GetAttemptCount", p.GetAttemptCount(), 2},
		{"GetRetryCount", p.GetRetryCount(), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %v (%T), want %v (%T)", tt.name, tt.got, tt.got, tt.want, tt.want)
			}
		})
	}
}

func TestPayload_JSONRoundtrip(t *testing.T) {
	original := Payload{
		EventType:      "request.completed",
		Source:         "gateway",
		SessionID:      "sess-roundtrip",
		OrgID:          "org-123",
		ModelRequested: "gpt-4o",
		ModelUsed:      "gpt-4o-2024-05-13",
		UpstreamURL:    "https://api.openai.com/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     2500,
		TokensIn:       200,
		TokensOut:      500,
		Method:         "POST",
	}

	data, err := json.Marshal(&original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Payload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.EventType != original.EventType {
		t.Errorf("EventType: got %q, want %q", decoded.EventType, original.EventType)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID: got %q, want %q", decoded.SessionID, original.SessionID)
	}
	if decoded.OrgID != original.OrgID {
		t.Errorf("OrgID: got %q, want %q", decoded.OrgID, original.OrgID)
	}
	if decoded.ModelRequested != original.ModelRequested {
		t.Errorf("ModelRequested: got %q, want %q", decoded.ModelRequested, original.ModelRequested)
	}
	if decoded.ModelUsed != original.ModelUsed {
		t.Errorf("ModelUsed: got %q, want %q", decoded.ModelUsed, original.ModelUsed)
	}
	if decoded.UpstreamURL != original.UpstreamURL {
		t.Errorf("UpstreamURL: got %q, want %q", decoded.UpstreamURL, original.UpstreamURL)
	}
	if decoded.StatusCode != original.StatusCode {
		t.Errorf("StatusCode: got %d, want %d", decoded.StatusCode, original.StatusCode)
	}
	if decoded.DurationMs != original.DurationMs {
		t.Errorf("DurationMs: got %d, want %d", decoded.DurationMs, original.DurationMs)
	}
	if decoded.TokensIn != original.TokensIn {
		t.Errorf("TokensIn: got %d, want %d", decoded.TokensIn, original.TokensIn)
	}
	if decoded.TokensOut != original.TokensOut {
		t.Errorf("TokensOut: got %d, want %d", decoded.TokensOut, original.TokensOut)
	}
	if decoded.Method != original.Method {
		t.Errorf("Method: got %q, want %q", decoded.Method, original.Method)
	}
}
