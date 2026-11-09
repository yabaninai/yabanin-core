package logging

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/config"
)

// sensitiveKeySubstrings — подстроки имён slog-атрибутов, значения которых
// заменяются на "[REDACTED]" целиком. Сравнение case-insensitive.
// Примечание: DSN/URI-ключи (dsn, pg_uri, redis_url, connection_string) сюда НЕ входят —
// их значения обрабатываются паттернами ниже, чтобы сохранять host/port.
var sensitiveKeySubstrings = []string{
	"password", "passwd", "secret", "api_key", "apikey", "token",
	"authorization", "cookie", "set-cookie", "refresh_token",
	"id_token", "access_token", "session", "private_key",
	"hmac",
}

// sensitiveValuePatterns — regex для детекта секретов в произвольных строковых
// значениях (даже если имя атрибута безопасное, например "error" или "url").
var sensitiveValuePatterns = []struct {
	re      *regexp.Regexp
	replace string
}{
	// JWT (header.payload.signature)
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "[REDACTED]"},
	// Bearer token after the keyword
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}`), "Bearer [REDACTED]"},
	// Postgres/MySQL/Redis DSN with embedded password (username optional)
	{regexp.MustCompile(`(?i)(postgres|mysql|redis|mssql)://([^:/@]*):([^@/]+)@`), "${1}://${2}:[REDACTED]@"},
	// OpenAI / Anthropic API keys
	{regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`), "[REDACTED]"},
}

func shouldRedactKey(key string) bool {
	k := strings.ToLower(key)
	for _, sub := range sensitiveKeySubstrings {
		if strings.Contains(k, sub) {
			return true
		}
	}
	return false
}

func redactValue(s string) string {
	out := s
	for _, p := range sensitiveValuePatterns {
		out = p.re.ReplaceAllString(out, p.replace)
	}
	return out
}

// ContentProfileRedactedDiagnostic — фиксированный текст диагностики для
// отключение логирования контента не оставляет контент в ошибках.
const ContentProfileRedactedDiagnostic = "details omitted by content profile"

// contentProfileDiagnosticKeys — имена slog-атрибутов, значения которых под
// строгим process-local профилем заменяются целиком, независимо от вида
// значения (строка, slog.Any error и т.д.). Группы под замену не попадают —
// они рекурсивно обрабатываются ниже.
var contentProfileDiagnosticKeys = []string{
	"error", "panic",
	"payload", "upstream_payload", "upstream_response",
}

func isContentProfileDiagnosticKey(key string) bool {
	k := strings.ToLower(key)
	for _, name := range contentProfileDiagnosticKeys {
		if k == name {
			return true
		}
	}
	return false
}

// localContentProfileStrict reports the process-local content profile
// call, so a process started with a metadata-only declaration can never
// leak the underlying error text through ReplaceAttr.
func localContentProfileStrict() bool {
	return config.LogContentProfileFromEnv() == config.LogContentProfileMetadataOnly
}

// ContentProfileDiagnosticValue renders one diagnostic value under the given
// content profile: legacy keeps the original value untouched; metadata-only
// replaces it with the fixed notice that carries no underlying error text.
func ContentProfileDiagnosticValue(profile config.LogContentProfile, value any) any {
	if profile == config.LogContentProfileMetadataOnly {
		return ContentProfileRedactedDiagnostic
	}
	return value
}

// ReplaceAttr — slog.HandlerOptions.ReplaceAttr, фильтрующий сенситивные пары.
// Маскирует значения по имени атрибута и/или по шаблонам внутри строковых
// значений (JWT, Bearer, DSN, sk-...). Группы рекурсивно обрабатываются.
// явных контентных атрибутов заменяются фиксированным текстом независимо от
// slog-вида значения (кроме групп — рекурсия сохраняется).
func ReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindGroup && isContentProfileDiagnosticKey(a.Key) && localContentProfileStrict() {
		a.Value = slog.StringValue(ContentProfileRedactedDiagnostic)
		return a
	}
	if shouldRedactKey(a.Key) {
		a.Value = slog.StringValue("[REDACTED]")
		return a
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		attrs := a.Value.Group()
		for i := range attrs {
			attrs[i] = ReplaceAttr(groups, attrs[i])
		}
	case slog.KindString:
		redacted := redactValue(a.Value.String())
		if redacted != a.Value.String() {
			a.Value = slog.StringValue(redacted)
		}
	}
	return a
}
