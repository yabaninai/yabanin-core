package auditlog

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestScrubAuditSecrets_MasksStructuredAndTextCredentials(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "JSON keys nested in objects and arrays",
			input: `{"user":"alice","credentials":{"access_token":"access-secret","AWS_SECRET_ACCESS_KEY":"aws-secret"},"items":[{"private-key":"private-secret"}]}`,
			want:  `{"credentials":{"AWS_SECRET_ACCESS_KEY":"[REDACTED]","access_token":"[REDACTED]"},"items":[{"private-key":"[REDACTED]"}],"user":"alice"}`,
		},
		{
			name:  "JSON string values contain textual credentials",
			input: `{"message":"Authorization: Bearer textual-secret-value"}`,
			want:  `{"message":"Authorization: [REDACTED] [REDACTED]"}`,
		},
		{
			name:  "key value punctuation and mixed-case keys",
			input: `operator note; API-Key = "kv-secret"; Password: 'pw-secret'`,
			want:  `operator note; API-Key = "[REDACTED]"; Password: '[REDACTED]'`,
		},
		{
			name:  "bearer token in prose",
			input: `request used bearer abcdefghijklmnop and completed`,
			want:  `request used bearer [REDACTED] and completed`,
		},
		{
			name:  "ordinary prose remains readable",
			input: `Operator approved routine maintenance for account alice.`,
			want:  `Operator approved routine maintenance for account alice.`,
		},
		{
			name:  "blank text is preserved byte for byte",
			input: " \t\n",
			want:  " \t\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubAuditSecrets(tc.input); got != tc.want {
				t.Errorf("scrubAuditSecrets() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScrubAuditSecrets_Base64WrappedJSON(t *testing.T) {
	input := base64.StdEncoding.EncodeToString([]byte(`{"refresh_token":"wrapped-secret","label":"nightly job"}`))
	got := scrubAuditSecrets(input)
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("scrubbed value is not valid base64: %v", err)
	}
	var value map[string]string
	if err := json.Unmarshal(decoded, &value); err != nil {
		t.Fatalf("decoded scrubbed value is not valid JSON: %v", err)
	}
	if value["refresh_token"] != "[REDACTED]" || value["label"] != "nightly job" {
		t.Fatalf("wrapped audit payload was not selectively scrubbed: %#v", value)
	}
	if strings.Contains(got, "wrapped-secret") {
		t.Fatal("encoded secret remained in scrubbed payload")
	}
}

func TestScrubAuditSecrets_ExactSecretKeyNames(t *testing.T) {
	input := `{"token_count":3,"tokenizer":"byte-pair","access_token":"credential-value"}`
	got := scrubAuditSecrets(input)
	var value map[string]any
	if err := json.Unmarshal([]byte(got), &value); err != nil {
		t.Fatalf("scrubbed value is not valid JSON: %v", err)
	}
	if value["token_count"] != float64(3) || value["tokenizer"] != "byte-pair" {
		t.Fatalf("non-secret token-prefixed keys were altered: %s", got)
	}
	if value["access_token"] != "[REDACTED]" {
		t.Fatalf("access_token was not redacted: %s", got)
	}
}

func TestAppendEntry_ScrubsBeforeAfterAndReasonButPreservesOrdinaryReason(t *testing.T) {
	db := setupTestDB(t)
	writer := NewWriter(db)
	ctx := t.Context()
	entry := Entry{
		ID: "scrub-all-audit-fields", Action: "rotate", Resource: "credential",
		Before: `{"password":"before-password-secret"}`,
		After:  `{"nested":[{"api_key":"after-key-secret"}],"comment":"rotated"}`,
		Reason: "Routine rotation by operator; bearer reason-secret-token",
	}
	if err := writer.AppendEntry(ctx, entry); err != nil {
		t.Fatalf("append entry: %v", err)
	}
	var before, after, reason string
	if err := db.QueryRowContext(ctx,
		`SELECT before_snapshot, after_snapshot, reason FROM admin_audit_logs WHERE id = ?`, entry.ID,
	).Scan(&before, &after, &reason); err != nil {
		t.Fatalf("read stored audit entry: %v", err)
	}
	for _, secret := range []string{"before-password-secret", "after-key-secret", "reason-secret-token"} {
		if strings.Contains(before+after+reason, secret) {
			t.Errorf("secret %q persisted in audit entry: before=%q after=%q reason=%q", secret, before, after, reason)
		}
	}
	if !strings.Contains(before, "[REDACTED]") || !strings.Contains(after, "[REDACTED]") ||
		!strings.Contains(reason, "Routine rotation by operator") || !strings.Contains(reason, "[REDACTED]") {
		t.Fatalf("audit values should mask credentials and retain ordinary text: %q %q %q", before, after, reason)
	}
	verifyIntact(t, db)
}
