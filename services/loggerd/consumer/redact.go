package consumer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/redact"
)

// Snapshot cap for the stored (redacted) request payload. 100 chars fit
// neither the model name nor a meaningful prefix — the explorer showed
// nothing usable (user finding 2026-09-15). 4000 keeps rows bounded while
// making the snapshot actually debuggable; PH.1 redaction is unchanged.
const maxResponseChars = 4000

// ScrubSecrets delegates to pkg/redact so the producer side (eventpublisher,
// before the Redis XADD) applies the exact same rules.
func ScrubSecrets(text string) string { return redact.ScrubSecrets(text) }

func debugLogResponse() bool {
	return config.DebugLogResponse()
}

// RedactPrompt hashes the prompt text. Returns SHA-256 hex digest.
func RedactPrompt(text string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(text)))
	return hex.EncodeToString(h[:])
}

// TruncateResponse keeps first N chars of response (for debugging visibility).
func TruncateResponse(text string, maxChars int) string {
	if len(text) <= maxChars {
		return text
	}
	return text[:maxChars] + "... [truncated]"
}

// ResponseForStorage shapes a raw response body into bytes that are always
// valid for a JSONB column. pgx encodes a []byte argument to a json/jsonb
// column verbatim, so the returned bytes MUST themselves be valid JSON:
//
//   - if the (possibly truncated) text is already valid JSON, those bytes are
//     returned as-is (stored as the JSON value);
//   - otherwise (e.g. after truncation, which breaks JSON) the text is
//     JSON-encoded into a JSON string, so the column holds a valid JSON string.
//
// This guarantees the request_logs insert never fails with "invalid input
// syntax for type json". An empty body yields nil (stored as SQL NULL).
func ResponseForStorage(text string) []byte {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal([]byte(text), &v); err == nil {
		// Already valid JSON: store the canonical bytes.
		return []byte(text)
	}
	// Not valid JSON (e.g. truncated mid-object): store as a JSON string so the
	// column always holds a valid JSON value.
	if b, err := json.Marshal(text); err == nil {
		return b
	}
	return nil
}

// shapeUpstream shapes a captured upstream sample (request actually sent /
// bounded model response) for the JSONB columns: same truncation and
// always-valid-JSON guarantees as ResponseForStorage. Empty input → nil
// (SQL NULL), so pre-capture rows and uncaptured streams stay honest.
func shapeUpstream(sample string) interface{} {
	if strings.TrimSpace(sample) == "" {
		return nil
	}
	return ResponseForStorage(TruncateResponse(sample, maxResponseChars))
}
