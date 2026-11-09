package validation

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// MaxStringLength returns an error if s is longer than max.
func MaxStringLength(s string, max int, field string) error {
	if len(s) > max {
		return fmt.Errorf("%s exceeds maximum length of %d (%d chars)", field, max, len(s))
	}
	return nil
}

// MaxInt returns an error if v exceeds max.
func MaxInt(v int64, max int64, field string) error {
	if v > max {
		return fmt.Errorf("%s exceeds maximum value %d", field, max)
	}
	return nil
}

// RequiredString returns an error if s is empty.
func RequiredString(s string, field string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

// ValidModelName validates a model name string (alphanumeric, hyphens, underscores, slashes).
var modelNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-_/]{0,127}$`)

// ValidModelName reports whether the model name is well-formed.
// ValidModelName.
func ValidModelName(name string) error {
	if name == "" {
		return fmt.Errorf("model name cannot be empty")
	}
	if len(name) > 128 {
		return fmt.Errorf("model name too long (%d chars, max 128)", len(name))
	}
	if !modelNameRe.MatchString(name) {
		return fmt.Errorf("invalid model name format (allowed: letters, digits, hyphens, underscores, slashes)")
	}
	return nil
}

// ValidOrgSlug validates an organization slug (lowercase alphanumeric + hyphens).
var orgSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{1,63}$`)

// ValidOrgSlug reports whether the org slug is well-formed.
// ValidOrgSlug.
func ValidOrgSlug(slug string) error {
	if slug == "" {
		return fmt.Errorf("organization slug cannot be empty")
	}
	if len(slug) > 64 {
		return fmt.Errorf("organization slug too long (%d chars, max 64)", len(slug))
	}
	if !orgSlugRe.MatchString(slug) {
		return fmt.Errorf("invalid org slug (allowed: lowercase letters, digits, hyphens; must start with letter or digit)")
	}
	return nil
}

// ValidTeamSlug validates a team slug.
var teamSlugRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]{0,63}$`)

// ValidTeamSlug reports whether the team slug is well-formed.
// ValidTeamSlug.
func ValidTeamSlug(slug string) error {
	if slug == "" {
		return fmt.Errorf("team slug cannot be empty")
	}
	if len(slug) > 64 {
		return fmt.Errorf("team slug too long (%d chars, max 64)", len(slug))
	}
	if !teamSlugRe.MatchString(slug) {
		return fmt.Errorf("invalid team slug format")
	}
	return nil
}

// ValidOrgID validates an org/team/api key ID (UUID v4 format).
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ValidUUID reports whether s parses as a canonical UUID.
// ValidUUID.
func ValidUUID(id string) error {
	if id == "" {
		return fmt.Errorf("ID cannot be empty")
	}
	if !uuidRe.MatchString(strings.ToLower(id)) {
		return fmt.Errorf("invalid ID format (expected UUID v4)")
	}
	return nil
}

// ValidEmail validates an email address.
var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ValidEmail reports whether the email address is well-formed.
// ValidEmail.
func ValidEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if len(email) > 254 {
		return fmt.Errorf("email too long (%d chars, max 254)", len(email))
	}
	if !emailRe.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidDisplayName validates a display name.
func ValidDisplayName(name string) error {
	return MaxStringLength(name, 128, "display_name")
}

// SanitizeHTML removes all HTML tags from a string to prevent XSS in log output.
func SanitizeHTML(s string) string {
	// Simple tag stripping — faster than full HTML parsing for log sanitization.
	var result strings.Builder
	inTag := false
	for _, r := range s {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				result.WriteRune(r)
			}
		}
	}
	return result.String()
}

// ValidAPIKey validates an API key token (alphanumeric + hyphens/underscores, 16-256 chars).
var apiKeyRe = regexp.MustCompile(`^[a-zA-Z0-9_\-]{16,256}$`)

// ValidAPIKey reports whether the API key has the expected shape.
// ValidAPIKey.
func ValidAPIKey(key string) error {
	if key == "" {
		return fmt.Errorf("API key cannot be empty")
	}
	if !apiKeyRe.MatchString(key) {
		return fmt.Errorf("invalid API key format (alphanumeric, hyphens, underscores; 16-256 chars)")
	}
	return nil
}

// ValidUpstreamURL validates that a string is a parseable URL with http or https scheme.
func ValidUpstreamURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("upstream URL cannot be empty")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("upstream URL must use http or https scheme")
	}
	return nil
}

// ValidRoutingExpr validates a routing expression (simple format: org_id, model, ip).
func ValidRoutingExpr(expr string) error {
	if expr == "" {
		return fmt.Errorf("routing expression cannot be empty")
	}
	if len(expr) > 512 {
		return fmt.Errorf("routing expression too long (%d chars, max 512)", len(expr))
	}
	// Basic sanity: no null bytes.
	if strings.ContainsRune(expr, '\x00') {
		return fmt.Errorf("routing expression contains invalid characters")
	}
	return nil
}

// ValidPasswordHash checks that a password hash looks reasonable (bcrypt prefix).
func ValidPasswordHash(hash string) error {
	if hash == "" {
		return fmt.Errorf("password hash cannot be empty")
	}
	if len(hash) < 50 || !strings.HasPrefix(hash, "$2") {
		return fmt.Errorf("invalid password hash format (expected bcrypt)")
	}
	return nil
}

// ValidSessionCookie validates the session cookie token.
func ValidSessionCookie(token string) error {
	if token == "" {
		return fmt.Errorf("session token is required")
	}
	if len(token) < 32 || len(token) > 512 {
		return fmt.Errorf("invalid session token length (%d chars)", len(token))
	}
	return nil
}

// ValidDuration parses and validates a duration string.
func ValidDuration(val string) error {
	if val == "" {
		return fmt.Errorf("duration is required")
	}
	if _, err := parseDurationSafe(val); err != nil {
		return fmt.Errorf("invalid duration format: %w", err)
	}
	return nil
}

// ValidIP validates an IPv4 or IPv6 address.
func ValidIP(addr string) error {
	if net.ParseIP(addr) == nil {
		return fmt.Errorf("invalid IP address")
	}
	return nil
}

// parseDurationWithLimit is an alias for time.ParseDuration.
func parseDurationWithLimit(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// parseDurationSafe parses a duration with a reasonable cap (10 years max).
func parseDurationSafe(s string) (int64, error) {
	d, err := parseDurationWithLimit(s)
	if err != nil {
		return 0, err
	}
	const maxDuration = 365 * 24 * time.Hour * 10 // 10 years
	if d > maxDuration || d < -maxDuration {
		return 0, fmt.Errorf("duration out of range")
	}
	return int64(d), nil
}

// ValidRoutePath validates a URL path segment for chi router mounting.
func ValidRoutePath(p string) error {
	if p == "" {
		return fmt.Errorf("route path cannot be empty")
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("route path must start with /")
	}
	if len(p) > 256 {
		return fmt.Errorf("route path too long (%d chars, max 256)", len(p))
	}
	return nil
}
