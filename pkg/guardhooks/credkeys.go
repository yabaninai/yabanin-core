package guardhooks

// MC-2 (MCP-CREDENTIALS-PLAN-2026-10-05): the credential-key redact
// dictionary. Tool params (and egress bodies) carrying values under
// credential-shaped JSON keys — authorization headers, API keys, oauth
// token material — are treated as secret material:
//   - redact mode replaces the VALUE with [REDACTED_CREDENTIAL], preserving
//     the key and the JSON structure;
//   - deny mode drops the request (the same CatCredential hit flows through
//     the existing mode switch);
//   - log mode counts the hit.
// The pattern is linear (unrolled-loop JSON string body, bounded keys) — the
// package's no-ReDoS constraint holds.

import "regexp"

// CatCredential marks a value stored under a credential-shaped key.
const CatCredential Category = "credential"

// credentialKeys is the redact dictionary: JSON keys whose string values are
// credential material. Matched case-insensitively; separator variants (-/_)
// are covered per entry.
const credentialKeys = `authorization|proxy-authorization|x-api-key|api-key|api-key|apikey|api_key|access-token|access_token|refresh-token|refresh_token|id-token|id_token|client-secret|client_secret|secret|password|passwd|token|credential|credentials`

// credentialValueBody matches a bounded JSON string body: no quotes, escapes
// consume two characters (unrolled loop — linear, no nested quantifiers).
const credentialValueBody = `[^"\\]*(?:\\.[^"\\]*)*` //nolint:gosec // G101: a regex fragment, not a credential

// credentialKeyRe matches "key" : "value" pairs whose key is in the
// dictionary; group 1 is the key name so the replacement can preserve it.
var credentialKeyRe = compileCredentialKeyRe()

func compileCredentialKeyRe() *regexp.Regexp {
	return regexp.MustCompile(`(?i)"(` + credentialKeys + `)"\s*:\s*"` + credentialValueBody + `"`)
}

// credentialReplacement preserves the key, replaces the value.
const credentialReplacement = `"$1":"[REDACTED_CREDENTIAL]"` //nolint:gosec // G101: a redaction token, not a credential

// redactCredentialKeys replaces credential-keyed values (redact mode).
func redactCredentialKeys(text string) string {
	return credentialKeyRe.ReplaceAllString(text, credentialReplacement)
}
