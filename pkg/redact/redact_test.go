package redact

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestScrubSecrets_RedactsJSONBearerAndBase64(t *testing.T) {
	marker := strings.Join([]string{"probe", "token", "123"}, "-")
	secret := `{"headers":{"access_token":"` + marker + `"},"query":"public status"}`

	t.Run("json key", func(t *testing.T) {
		got := ScrubSecrets(secret)
		if strings.Contains(got, marker) || !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, "public status") {
			t.Fatalf("scrubbed JSON = %q", got)
		}
	})

	t.Run("bearer", func(t *testing.T) {
		bearer := strings.Join([]string{"probe", "error", "token"}, "-")
		got := ScrubSecrets("request failed: Authorization: Bearer " + bearer)
		if strings.Contains(got, bearer) || !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("bearer token survived: %q", got)
		}
	})

	t.Run("base64 wrapped JSON", func(t *testing.T) {
		wrapped := base64.StdEncoding.EncodeToString([]byte(secret))
		got := ScrubSecrets(wrapped)
		decoded, err := base64.StdEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("scrubbed value is not valid base64: %v", err)
		}
		var value map[string]any
		if err := json.Unmarshal(decoded, &value); err != nil {
			t.Fatalf("decoded scrubbed value is not valid JSON: %v", err)
		}
		if strings.Contains(string(decoded), marker) || !strings.Contains(string(decoded), "[REDACTED]") {
			t.Fatalf("base64-wrapped secret survived: %q", decoded)
		}
	})
}

func TestScrubSecrets_LeavesOrdinaryTextUntouched(t *testing.T) {
	plain := "upstream returned status unavailable; retry later"
	if got := ScrubSecrets(plain); got != plain {
		t.Fatalf("plain diagnostic changed: %q", got)
	}
}
