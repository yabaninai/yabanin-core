package config

import (
	"os"
	"strings"
	"testing"
)

// unsetEnv removes key for the duration of the test and restores the
// previous state afterwards (t.Setenv cannot express "unset").
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		}
	})
}

// resetEmbedderEnv clears every embedder variable so a test observes only
// what it sets itself — required for deterministic -shuffle runs.
func resetEmbedderEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"YABANIN_EMBEDDER_ENABLED",
		"YABANIN_EMBEDDER_BASE_URL",
		"YABANIN_EMBEDDER_MODEL",
		"YABANIN_EMBEDDER_API_KEY",
		"YABANIN_EMBEDDER_TIMEOUT",
		"YABANIN_EMBEDDER_MAX_CHARS",
		"YABANIN_EMBEDDER_ENDPOINT",
		"YABANIN_EMBEDDER_QUERY_PREFIX",
	} {
		unsetEnv(t, k)
	}
}

// strconv parsing as the other numeric env fields — "5x" must not parse as
// 5 (the old fmt.Sscanf silently read the prefix). A malformed value keeps
// the default and the warning names the variable and the value.
func TestNewEmbedderConfig_NumericFieldsStrictParse(t *testing.T) {
	cases := []struct {
		name     string
		key      string
		value    string
		unset    bool
		want     int
		wantWarn bool
	}{
		{"unset keeps default", "YABANIN_EMBEDDER_TIMEOUT", "", true, 30, false},
		{"empty keeps default", "YABANIN_EMBEDDER_TIMEOUT", "", false, 30, false},
		{"valid value parses", "YABANIN_EMBEDDER_TIMEOUT", "45", false, 45, false},
		{"surrounding space tolerated", "YABANIN_EMBEDDER_TIMEOUT", " 45 ", false, 45, false},
		{"trailing garbage rejected", "YABANIN_EMBEDDER_TIMEOUT", "5x", false, 30, true},
		{"garbage rejected", "YABANIN_EMBEDDER_TIMEOUT", "abc", false, 30, true},
		{"max_chars valid parses", "YABANIN_EMBEDDER_MAX_CHARS", "4096", false, 4096, false},
		{"max_chars trailing garbage rejected", "YABANIN_EMBEDDER_MAX_CHARS", "12abc", false, 8191, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetEmbedderEnv(t)
			t.Setenv("YABANIN_CONFIG_STRICT", "")
			if !tc.unset {
				t.Setenv(tc.key, tc.value)
			}
			warnings := captureEnvWarnings(t)

			cfg := NewEmbedderConfig()

			got, def := cfg.Timeout, 30
			if tc.key == "YABANIN_EMBEDDER_MAX_CHARS" {
				got, def = cfg.MaxChars, 8191
			}
			if got != tc.want {
				t.Fatalf("%s=%q must resolve to %d (default %d), got %d", tc.key, tc.value, tc.want, def, got)
			}
			if !tc.wantWarn {
				if len(*warnings) != 0 {
					t.Fatalf("valid value must not warn, got %v", *warnings)
				}
				return
			}
			if len(*warnings) != 1 {
				t.Fatalf("expected exactly one warning, got %v", *warnings)
			}
			if !strings.Contains((*warnings)[0], tc.key) || !strings.Contains((*warnings)[0], tc.value) {
				t.Fatalf("warning must name the variable and the value, got %q", (*warnings)[0])
			}
		})
	}
}

// Load, so YABANIN_CONFIG_STRICT does not gate them — a malformed value
// warns and keeps the default in strict mode too.
func TestNewEmbedderConfig_StrictEnvDoesNotGateEmbedder(t *testing.T) {
	resetEmbedderEnv(t)
	t.Setenv("YABANIN_CONFIG_STRICT", "1")
	t.Setenv("YABANIN_EMBEDDER_TIMEOUT", "5x")
	warnings := captureEnvWarnings(t)

	cfg := NewEmbedderConfig()

	if cfg.Timeout != 30 {
		t.Fatalf(`"5x" must keep default 30, got %d`, cfg.Timeout)
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "YABANIN_EMBEDDER_TIMEOUT") {
		t.Fatalf("expected one warning naming the variable, got %v", *warnings)
	}
}

// parsing switch.
func TestNewEmbedderConfig_ValidValuesPass(t *testing.T) {
	resetEmbedderEnv(t)
	t.Setenv("YABANIN_CONFIG_STRICT", "1")
	t.Setenv("YABANIN_EMBEDDER_TIMEOUT", "60")
	t.Setenv("YABANIN_EMBEDDER_MAX_CHARS", "2048")
	warnings := captureEnvWarnings(t)

	cfg := NewEmbedderConfig()

	if cfg.Timeout != 60 || cfg.MaxChars != 2048 {
		t.Fatalf("valid values must parse, got timeout=%d max_chars=%d", cfg.Timeout, cfg.MaxChars)
	}
	if len(*warnings) != 0 {
		t.Fatalf("valid values must not warn, got %v", *warnings)
	}
}

// Validate must stay a no-op when the embedder is disabled and enforce the
// BaseURL requirement + model default when enabled.
func TestEmbedderConfigValidate(t *testing.T) {
	t.Run("disabled passes", func(t *testing.T) {
		c := EmbedderConfig{Enabled: false}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil when disabled", err)
		}
	})
	t.Run("enabled without base url fails", func(t *testing.T) {
		c := EmbedderConfig{Enabled: true}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "YABANIN_EMBEDDER_BASE_URL") {
			t.Errorf("Validate() = %v, want missing YABANIN_EMBEDDER_BASE_URL error", err)
		}
	})
	t.Run("enabled fills model default", func(t *testing.T) {
		c := EmbedderConfig{Enabled: true, BaseURL: "http://bge:6006"}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
		if c.Model != "BAAI/bge-small-en-v1.5" {
			t.Errorf("Model = %q, want BAAI/bge-small-en-v1.5 default", c.Model)
		}
	})
	t.Run("explicit model kept", func(t *testing.T) {
		c := EmbedderConfig{Enabled: true, BaseURL: "http://bge:6006", Model: "custom"}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
		if c.Model != "custom" {
			t.Errorf("Model = %q, want custom", c.Model)
		}
	})
}
