package validation

import (
	"strings"
	"testing"
)

func TestMaxStringLength(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int
		field   string
		wantErr bool
	}{
		{"exact length", "hello", 5, "field", false},
		{"under max", "hi", 5, "field", false},
		{"over max", "hello world", 5, "field", true},
		{"zero max empty string", "", 0, "field", false},
		{"zero max non-empty", "x", 0, "field", true},
		{"unicode over max", strings.Repeat("你", 4), 3, "field", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MaxStringLength(tt.input, tt.max, tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("MaxStringLength(%q, %d, %q) error = %v, wantErr = %v", tt.input, tt.max, tt.field, err, tt.wantErr)
			}
		})
	}
}

func TestMaxInt(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		max     int64
		field   string
		wantErr bool
	}{
		{"equal to max", 10, 10, "count", false},
		{"below max", 5, 10, "count", false},
		{"above max", 11, 10, "count", true},
		{"negative below max", -5, 10, "count", false},
		{"zero at zero max", 0, 0, "count", false},
		{"one above zero max", 1, 0, "count", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MaxInt(tt.input, tt.max, tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("MaxInt(%d, %d, %q) error = %v, wantErr = %v", tt.input, tt.max, tt.field, err, tt.wantErr)
			}
		})
	}
}

func TestRequiredString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		field   string
		wantErr bool
	}{
		{"non-empty valid", "hello", "name", false},
		{"empty string", "", "name", true},
		{"whitespace only spaces", "   ", "name", true},
		{"whitespace only tabs", "\t\t", "name", true},
		{"whitespace only newlines", "\n\n", "name", true},
		{"mixed whitespace", " \t \n ", "name", true},
		{"single char", "a", "name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequiredString(tt.input, tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("RequiredString(%q, %q) error = %v, wantErr = %v", tt.input, tt.field, err, tt.wantErr)
			}
		})
	}
}

func TestValidModelName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple name", "gpt-4", false},
		{"with underscore", "my_model", false},
		{"with slash", "org/model", false},
		{"alphanumeric", "model123", false},
		{"starts with digit", "1model", false},
		{"too long 129 chars", strings.Repeat("a", 129), true},
		{"special chars invalid", "model@name", true},
		{"spaces", "my model", true},
		{"empty string", "", true},
		{"starts with hyphen", "-model", true},
		{"starts with underscore", "_model", true},
		{"exactly 128 chars", strings.Repeat("a", 128), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidModelName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidModelName(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidOrgSlug(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid slug", "my-org", false},
		{"alphanumeric", "org123", false},
		{"single char digit start", "a", true},
		{"uppercase rejected", "MyOrg", true},
		{"underscore rejected", "my_org", true},
		{"space rejected", "my org", true},
		{"too long 65 chars", strings.Repeat("a", 65), true},
		{"empty string", "", true},
		{"starts with hyphen", "-org", true},
		{"ends with hyphen", "org-", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidOrgSlug(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidOrgSlug(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidTeamSlug(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid slug", "my-team", false},
		{"alphanumeric", "team123", false},
		{"uppercase start", "Team1", false},
		{"single char", "a", false},
		{"too long 65 chars", strings.Repeat("a", 65), true},
		{"empty string", "", true},
		{"starts with hyphen", "-team", true},
		{"underscore rejected", "my_team", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidTeamSlug(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidTeamSlug(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidUUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid v4 lowercase", "550e8400-e29b-41d4-a716-446655440000", false},
		{"valid v4 uppercase", "550E8400-E29B-41D4-A716-446655440000", false},
		{"invalid - wrong version (not 4)", "550e8400-e29b-31d4-a716-446655440000", true},
		{"invalid - wrong variant (b->a)", "550e8400-e29b-41d4-a716-446655440000", false},
		{"empty string", "", true},
		{"not a uuid at all", "not-a-uuid", true},
		{"too short", "550e8400-e29b-4", true},
		{"extra characters", "550e8400-e29b-41d4-a716-4466554400000", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidUUID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidUUID(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "user@example.com", false},
		{"valid with dots", "first.last@example.com", false},
		{"valid with plus", "user+tag@example.com", false},
		{"valid subdomain", "user@mail.example.com", false},
		{"valid with hyphen domain", "user@example-site.com", false},
		{"valid with underscore", "user_name@example.com", false},
		{"too long 255 chars", strings.Repeat("a", 248) + "@b.c", true},
		{"empty string", "", true},
		{"no at sign", "userexample.com", true},
		{"no domain", "user@", true},
		{"no local part", "@example.com", true},
		{"invalid chars in local", "user name@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidEmail(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidEmail(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidDisplayName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"short name", "JD", false},
		{"valid 128 chars", strings.Repeat("a", 128), false},
		{"over max 129 chars", strings.Repeat("a", 129), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidDisplayName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidDisplayName(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeHTML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no tags", "plain text", "plain text"},
		{"single tag", "<b>bold</b>", "bold"},
		{"nested tags", "<div><p>nested</p></div>", "nested"},
		{"script tag removal", "<script>alert('xss')</script>Hello", "alert('xss')Hello"},
		{"unclosed tag", "<b>open text", "open text"},
		{"empty input", "", ""},
		{"tag with attributes", "<img src='x' alt='hi'>text", "text"},
		{"mixed content", "before<script>alert(1)</script>after", "beforealert(1)after"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeHTML(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeHTML(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid 16 chars", "abcdefghijklmnop", false},
		{"valid with hyphens", "abcdefgh-ijklmnop", false},
		{"valid with underscores", "abcdefgh_ijklmnop", false},
		{"valid 256 chars", strings.Repeat("a", 256), false},
		{"too short 15 chars", strings.Repeat("a", 15), true},
		{"too long 257 chars", strings.Repeat("a", 257), true},
		{"special chars rejected", "abc!efghijklmnop", true},
		{"empty string", "", true},
		{"spaces rejected", "abcdefghijklmnop qrs", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidAPIKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidAPIKey(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidUpstreamURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid http", "http://example.com", false},
		{"valid https", "https://example.com", false},
		{"https with path", "https://api.example.com/v1/endpoint", false},
		{"https with port", "https://localhost:8080/path", false},
		{"ftp rejected", "ftp://example.com", true},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"empty string", "", true},
		{"invalid url", "not a url at all", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidUpstreamURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidUpstreamURL(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidRoutingExpr(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"normal expr", "org123,model456,192.168.1.1", false},
		{"simple org only", "my-org", false},
		{"empty string", "", true},
		{"null byte rejection", "org\x00model", true},
		{"too long 513 chars", strings.Repeat("a", 513), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidRoutingExpr(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidRoutingExpr(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidPasswordHash(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid bcrypt 2a", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", false},
		{"valid bcrypt 2b", "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", false},
		{"non-bcrypt rejected", "sha256hashvaluehereXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", true},
		{"too short with prefix", "$2a$10$short", true},
		{"empty string", "", true},
		{"wrong prefix digits", "$x$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidPasswordHash(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidPasswordHash(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidSessionCookie(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"min length 32", strings.Repeat("a", 32), false},
		{"valid 100 chars", strings.Repeat("a", 100), false},
		{"max length 512", strings.Repeat("a", 512), false},
		{"too short 31 chars", strings.Repeat("a", 31), true},
		{"over max 513 chars", strings.Repeat("a", 513), true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidSessionCookie(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidSessionCookie(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidIP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv4 loopback", "127.0.0.1", false},
		{"valid IPv4 all zeros", "0.0.0.0", false},
		{"valid IPv4 all 255s", "255.255.255.255", false},
		{"valid IPv6 loopback", "::1", false},
		{"valid IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"valid IPv6 compressed", "fe80::1", false},
		{"invalid - not an IP", "not-an-ip", true},
		{"invalid - IPv4 out of range", "256.1.1.1", true},
		{"invalid - empty", "", true},
		{"invalid - partial", "192.168", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidIP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidIP(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidRoutePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid root", "/", false},
		{"valid path", "/api/v1/users", false},
		{"valid with trailing slash", "/api/", false},
		{"no leading slash", "api/v1", true},
		{"empty string", "", true},
		{"too long 257 chars", strings.Repeat("/", 257), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidRoutePath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidRoutePath(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
