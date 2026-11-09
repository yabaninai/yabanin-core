package guardhooks

// MC-2 tests: the credential-key redact dictionary — detection (Scan) and
// value replacement (Redact) across the modes, JSON structure preservation,
// and the no-op posture of off/log.

import (
	"strings"
	"testing"
)

func TestCredentialKeyRedact_ReplacesValuesKeepsKeys(t *testing.T) {
	h := New(ModeRedact)
	in := `{"tool":"search","Authorization":"Bearer sk-super-secret","X-Api-Key":"ak-123","limit":5}`
	out := h.Redact(in)
	if strings.Contains(out, "sk-super-secret") || strings.Contains(out, "ak-123") {
		t.Fatalf("credential values not redacted: %s", out)
	}
	for _, want := range []string{`"Authorization":"[REDACTED_CREDENTIAL]"`, `"X-Api-Key":"[REDACTED_CREDENTIAL]"`, `"limit":5`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestCredentialKeyScan_DetectsCategory(t *testing.T) {
	h := New(ModeLog)
	hits := h.Scan(`{"refresh_token":"abc","q":"x"}`)
	found := false
	for _, hit := range hits {
		if hit.Category == CatCredential && hit.Outcome == OutcomeLog {
			found = true
		}
	}
	if !found {
		t.Fatalf("credential category not detected: %+v", hits)
	}
}

func TestCredentialKey_OffAndLogAreNoopOnValues(t *testing.T) {
	in := `{"api_key":"secret-value-1"}`
	if out := New(ModeOff).Redact(in); out != in {
		t.Fatalf("off redact should be noop, got %s", out)
	}
	if out := New(ModeLog).Redact(in); out != in {
		t.Fatalf("log redact should be noop, got %s", out)
	}
}

func TestCredentialKey_InnocentKeysUntouched(t *testing.T) {
	h := New(ModeRedact)
	in := `{"tokenizer":"default","tokens_estimated":42,"passwords_policy":"strict"}`
	if out := h.Redact(in); out != in {
		t.Fatalf("innocent keys must not be rewritten, got %s", out)
	}
}

func TestCredentialKey_OauthPayloadShapes(t *testing.T) {
	h := New(ModeRedact)
	in := `{"client_secret":"cs-xyz","access_token":"at-xyz","id_token":"ey-a.b.c"}`
	out := h.Redact(in)
	for _, leak := range []string{"cs-xyz", "at-xyz", "ey-a.b.c"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%s not redacted: %s", leak, out)
		}
	}
}

func TestCredentialKey_ReDoSSafety_LongInputs(t *testing.T) {
	h := New(ModeRedact)
	// Pathological value bodies (long escapes / long runs) must not hang.
	in := `{"token":"` + strings.Repeat(`\ `, 5000) + `"}`
	_ = h.Redact(in)
	in2 := `{"secret":"` + strings.Repeat("a", 100000) + `"}`
	if out := h.Redact(in2); strings.Contains(out, strings.Repeat("a", 100000)) {
		t.Fatal("long secret value must be redacted")
	}
}
