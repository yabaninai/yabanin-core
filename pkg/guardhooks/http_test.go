package guardhooks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPDetectorApprovedVersionedRoundTrip(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request HTTPDetectorRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.Version != HTTPDetectorRequestVersion || request.Text != "inspect me" || request.Kind != ContentText {
			t.Errorf("unexpected detector request: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HTTPDetectorResponse{Version: HTTPDetectorRequestVersion, Findings: []Finding{{Category: CatInjection, Start: 0, End: 7, Confidence: 1, Detector: "remote:test"}}})
	}))
	defer server.Close()
	client := server.Client()
	detector, err := NewHTTPDetector(HTTPDetectorConfig{
		Identity: RuleVersion{PackID: "user.pack", PackVersion: "1.0.0", RuleID: "remote", RuleVersion: "1"},
		Endpoint: server.URL, Hosts: []string{"127.0.0.1"}, Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := detector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "inspect me"})
	if err != nil || len(findings) != 1 || findings[0].Detector != "remote:test" {
		t.Fatalf("Detect() = %#v, %v", findings, err)
	}
}

func TestHTTPDetectorRejectsUnapprovedAndMalformed(t *testing.T) {
	identity := RuleVersion{PackID: "user.pack", PackVersion: "1", RuleID: "remote", RuleVersion: "1"}
	if _, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: "http://example.test/scan", Hosts: []string{"example.test"}}); err == nil {
		t.Fatal("expected cleartext endpoint rejection")
	}
	if _, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: "https://example.test/scan", Hosts: []string{"other.test"}}); err == nil {
		t.Fatal("expected unapproved host rejection")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"wrong","findings":[]}`))
	}))
	defer server.Close()
	detector, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: server.URL, Hosts: []string{"127.0.0.1"}, Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"}); err == nil || !strings.Contains(err.Error(), "unsupported response version") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestHTTPDetectorRejectsInvalidInputsAndResponses(t *testing.T) {
	identity := RuleVersion{PackID: "user.pack", PackVersion: "1", RuleID: "remote", RuleVersion: "1"}
	for _, endpoint := range []string{"https://user:pass@example.test/scan", "https://example.test/scan#fragment"} {
		if _, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: endpoint, Hosts: []string{"example.test"}}); err == nil {
			t.Errorf("expected endpoint rejection: %s", endpoint)
		}
	}
	if _, err := NewHTTPDetector(HTTPDetectorConfig{Endpoint: "https://example.test"}); err == nil {
		t.Fatal("expected missing identity rejection")
	}

	for name, response := range map[string]string{
		"bad json":         `not json`,
		"bad span":         `{"version":"guardrails.http.v1","findings":[{"category":"secret","start":0,"end":4,"detector":"x"}]}`,
		"missing detector": `{"version":"guardrails.http.v1","findings":[{"category":"secret","start":0,"end":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(response)) }))
			defer server.Close()
			detector, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: server.URL, Hosts: []string{"127.0.0.1"}, Client: server.Client(), MaxBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := detector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"}); err == nil {
				t.Fatal("expected malformed detector response error")
			}
		})
	}
	tooLarge, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: "https://example.test", Hosts: []string{"example.test"}, MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tooLarge.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "too large"}); err == nil {
		t.Fatal("expected input size rejection")
	}
	if _, err := tooLarge.Detect(Invocation{Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"}); err == nil {
		t.Fatal("expected nil context rejection")
	}
}

func TestHTTPDetectorRejectsRedirectStatusAndOversizedResponse(t *testing.T) {
	identity := RuleVersion{PackID: "user.pack", PackVersion: "1", RuleID: "remote", RuleVersion: "1"}
	for name, handler := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.test", http.StatusFound)
		},
		"oversized":    func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 32))) },
		"server error": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			detector, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: server.URL, Hosts: []string{"127.0.0.1"}, Client: server.Client(), MaxBytes: 10})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := detector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"}); err == nil {
				t.Fatal("expected HTTP detector failure")
			}
		})
	}
}

// TestDetectorProtocolCodec pins the versioned request/response contract
// shared by every adapter speaking guardrails.http.v1 (N02-P04-T02): an
// explicit schema version on both envelopes, loud refusal of unknown versions
// in both directions (an old consumer must error, never misparse a newer
// payload), and span validation against the scanned text length.
func TestDetectorProtocolCodec(t *testing.T) {
	payload, err := EncodeDetectorRequest(PhaseBefore, ContentText, "abc")
	if err != nil {
		t.Fatal(err)
	}
	var decoded HTTPDetectorRequest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != (HTTPDetectorRequest{Version: HTTPDetectorRequestVersion, Phase: PhaseBefore, Kind: ContentText, Text: "abc"}) {
		t.Fatalf("envelope = %+v", decoded)
	}

	// A valid response at the exact text-length boundary decodes.
	ok := `{"version":"guardrails.http.v1","findings":[{"category":"secret","start":0,"end":3,"detector":"d"}]}`
	findings, err := DecodeDetectorResponse([]byte(ok), 3)
	if err != nil || len(findings) != 1 || findings[0].End != 3 {
		t.Fatalf("DecodeDetectorResponse() = %#v, %v", findings, err)
	}
	if fs, err := DecodeDetectorResponse([]byte(`{"version":"guardrails.http.v1"}`), 3); err != nil || fs != nil {
		t.Fatalf("empty findings response: %#v, %v", fs, err)
	}

	for name, tc := range map[string]struct {
		body    string
		textLen int
		wantErr string
	}{
		"older version":     {`{"version":"guardrails.http.v0","findings":[]}`, 3, "unsupported response version"},
		"newer version":     {`{"version":"guardrails.http.v2","findings":[]}`, 3, "unsupported response version"},
		"missing version":   {`{"findings":[]}`, 3, "unsupported response version"},
		"malformed json":    {`{`, 3, "malformed response"},
		"end past text":     {`{"version":"guardrails.http.v1","findings":[{"category":"s","start":0,"end":4,"detector":"d"}]}`, 3, "invalid finding span"},
		"negative start":    {`{"version":"guardrails.http.v1","findings":[{"category":"s","start":-1,"end":1,"detector":"d"}]}`, 3, "invalid finding span"},
		"inverted span":     {`{"version":"guardrails.http.v1","findings":[{"category":"s","start":2,"end":1,"detector":"d"}]}`, 3, "invalid finding span"},
		"missing detector":  {`{"version":"guardrails.http.v1","findings":[{"category":"s","start":0,"end":1}]}`, 3, "no detector id"},
		"span vs nil text?": {`{"version":"guardrails.http.v1","findings":[{"category":"s","start":0,"end":0,"detector":"d"}]}`, 0, ""},
	} {
		t.Run(name, func(t *testing.T) {
			findings, err := DecodeDetectorResponse([]byte(tc.body), tc.textLen)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want contains %q", err, tc.wantErr)
			}
			if findings != nil {
				t.Fatalf("findings = %#v on error path", findings)
			}
		})
	}
}

type panicDetector struct{}

func (panicDetector) Identity() RuleVersion {
	return RuleVersion{PackID: "user.pack", PackVersion: "1", RuleID: "panic", RuleVersion: "1"}
}

func (panicDetector) Detect(Invocation) ([]Finding, error) { panic("broken extension") }

func TestEvaluatorConvertsDetectorPanicToExplicitError(t *testing.T) {
	evaluator, err := NewEvaluator(panicDetector{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = evaluator.Evaluate(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "detector panic") {
		t.Fatalf("expected explicit detector panic error, got %v", err)
	}
}
