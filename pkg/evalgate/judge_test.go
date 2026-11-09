package evalgate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// judgeServerWithContent spins up a mock judge endpoint whose only choice
// carries the given raw content string.
func judgeServerWithContent(t *testing.T, content string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]interface{}{"content": content}},
			},
		}); err != nil {
			t.Errorf("encode error: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestJudge_Evaluate(t *testing.T) {
	server := judgeServerWithContent(t, `{"cheap_quality":0.7,"premium_quality":0.95,"should_upgrade":true,"reason":"medium response missing details"}`)

	judge := NewJudge(server.URL, nil)
	v, err := judge.Evaluate(context.Background(), "Summarize this text", "Short answer", "Detailed analysis with examples")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !v.ShouldUpgrade {
		t.Error("expected should_upgrade=true")
	}
	if v.CheapQuality != 0.7 || v.PremiumQuality != 0.95 {
		t.Errorf("unexpected scores: cheap=%v premium=%v", v.CheapQuality, v.PremiumQuality)
	}
	if v.Reason != "medium response missing details" {
		t.Errorf("unexpected reason: %q", v.Reason)
	}
}

func TestJudge_Evaluate_Non200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	judge := NewJudge(server.URL, nil)
	_, err := judge.Evaluate(context.Background(), "prompt", "cheap", "premium")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

// TestTP03_JudgeVerdictValidation covers the strict verdict contract: a
// malformed, incomplete or out-of-range verdict must surface as an explicit
// error instead of being persisted as a defaulted measurement.
func TestTP03_JudgeVerdictValidation(t *testing.T) {
	cases := []struct {
		name        string
		content     string
		wantErr     string
		wantVerdict *Verdict
	}{
		{
			name:    "malformed json is an error",
			content: `not valid json`,
			wantErr: "judge returned invalid JSON",
		},
		{
			name:    "empty content is an error",
			content: ``,
			wantErr: "judge returned invalid JSON",
		},
		{
			name: "trailing second json document is rejected",
			content: `{"cheap_quality":0.5,"premium_quality":0.5,"should_upgrade":false,"reason":"ok"}` +
				`{"cheap_quality":0.99,"premium_quality":0.1,"should_upgrade":false,"reason":"evil"}`,
			wantErr: "judge returned invalid JSON",
		},
		{
			name:    "missing reason field is an error",
			content: `{"cheap_quality":0.5,"premium_quality":0.5,"should_upgrade":false}`,
			wantErr: `missing field "reason"`,
		},
		{
			name:    "missing score field is an error",
			content: `{"premium_quality":0.5,"should_upgrade":false,"reason":"r"}`,
			wantErr: `missing field "cheap_quality"`,
		},
		{
			name:    "wrong field type is an error",
			content: `{"cheap_quality":0.5,"premium_quality":0.5,"should_upgrade":"yes","reason":"r"}`,
			wantErr: "judge verdict field types invalid",
		},
		{
			name:    "out of range score is an error",
			content: `{"cheap_quality":1.5,"premium_quality":0.5,"should_upgrade":false,"reason":"r"}`,
			wantErr: "out of range [0,1]",
		},
		{
			name:    "negative score is an error",
			content: `{"cheap_quality":-0.1,"premium_quality":0.5,"should_upgrade":false,"reason":"r"}`,
			wantErr: "out of range [0,1]",
		},
		{
			// 1e999 is a valid JSON token; json.Unmarshal rejects the overflow
			// into float64, so non-finite scores are dropped at the typed decode.
			name:    "non-finite score is an error",
			content: `{"cheap_quality":1e999,"premium_quality":0.5,"should_upgrade":false,"reason":"r"}`,
			wantErr: "judge verdict field types invalid",
		},
		{
			name: "unknown extra keys stay tolerated",
			content: `{"cheap_quality":0.4,"premium_quality":0.9,"should_upgrade":true,` +
				`"reason":"thin answer","verbosity":"high"}`,
			wantVerdict: &Verdict{CheapQuality: 0.4, PremiumQuality: 0.9, ShouldUpgrade: true, Reason: "thin answer"},
		},
		{
			name: "boundary scores are valid",
			content: `{"cheap_quality":0,"premium_quality":1,"should_upgrade":true,` +
				`"reason":"bounds"}`,
			wantVerdict: &Verdict{CheapQuality: 0, PremiumQuality: 1, ShouldUpgrade: true, Reason: "bounds"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := judgeServerWithContent(t, tc.content)
			judge := NewJudge(server.URL, nil)

			v, err := judge.Evaluate(context.Background(), "prompt", "cheap", "premium")
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got verdict %+v", tc.wantErr, v)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				if v != nil {
					t.Fatalf("no verdict must be returned alongside an error, got %+v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected valid verdict, got error: %v", err)
			}
			if *v != *tc.wantVerdict {
				t.Fatalf("verdict mismatch: got %+v, want %+v", *v, *tc.wantVerdict)
			}
		})
	}
}
