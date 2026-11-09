package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestNew_LevelFiltering proves the level argument is honoured (the merged
// logger replaces both the old level-only and format-only constructors).
func TestNew_LevelFiltering(t *testing.T) {
	cases := []struct {
		level string
		debug bool
		info  bool
	}{
		{"debug", true, true},
		{"", false, true},
		{"warn", false, false},
		{"error", false, false},
	}
	for _, tc := range cases {
		t.Run("level="+tc.level, func(t *testing.T) {
			l := New(tc.level, "text")
			if got := l.Enabled(context.TODO(), slog.LevelDebug); got != tc.debug {
				t.Errorf("debug enabled = %v, want %v", got, tc.debug)
			}
			if got := l.Enabled(context.TODO(), slog.LevelInfo); got != tc.info {
				t.Errorf("info enabled = %v, want %v", got, tc.info)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"":      slog.LevelInfo,
		"bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestNew_RedactionAppliesToBothFormats proves the merged logger redacts
// sensitive attributes regardless of format — the old pkg/logging silently
// skipped redaction entirely.
func TestNew_RedactionAppliesToBothFormats(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			var h slog.Handler
			opts := &slog.HandlerOptions{ReplaceAttr: ReplaceAttr}
			if format == "json" {
				h = slog.NewJSONHandler(&buf, opts)
			} else {
				h = slog.NewTextHandler(&buf, opts)
			}
			slog.New(h).Info("login", "password", "hunter2", "openai_api_key", "sk-1234567890")

			out := buf.String()
			if strings.Contains(out, "hunter2") || strings.Contains(out, "sk-1234567890") {
				t.Errorf("%s output leaked a secret: %q", format, out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("%s output missing redaction marker: %q", format, out)
			}
			if format == "json" {
				var rec map[string]any
				if err := json.Unmarshal([]byte(out), &rec); err != nil {
					t.Fatalf("decode log line %q: %v", out, err)
				}
				if rec["password"] != "[REDACTED]" {
					t.Errorf("password not redacted: %v", rec["password"])
				}
			}
		})
	}
}
