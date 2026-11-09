package logging

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactKey_Password(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("password", "hunter2"))
	assert.Equal(t, "[REDACTED]", a.Value.String())
}

func TestRedactKey_APIKeySubmatch(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("openai_api_key", "sk-1234567890"))
	assert.Equal(t, "[REDACTED]", a.Value.String())
}

func TestRedactKey_Authorization(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("authorization", "Bearer sk-something"))
	assert.Equal(t, "[REDACTED]", a.Value.String())
}

func TestRedactKey_Cookie(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("cookie", "sess=abc123"))
	assert.Equal(t, "[REDACTED]", a.Value.String())
}

func TestRedactKey_CaseInsensitive(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("RefreshToken", "abc.def.ghi"))
	assert.Equal(t, "[REDACTED]", a.Value.String())
}

func TestRedactKey_NonSensitiveUnchanged(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("model", "gpt-4"))
	assert.Equal(t, "gpt-4", a.Value.String())
}

func TestRedactKey_OrgIdUnchanged(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("org_id", "org-123"))
	assert.Equal(t, "org-123", a.Value.String())
}

func TestRedactValue_PostgresDSN(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("dsn", "postgres://user:s3cr3t@db:5432/app"))
	val := a.Value.String()
	assert.Contains(t, val, "[REDACTED]")
	assert.NotContains(t, val, "s3cr3t")
	assert.Contains(t, val, "db:5432")
}

func TestRedactValue_MysqlDSN(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("error", "mysql://root:password123@host:3306/db"))
	val := a.Value.String()
	assert.NotContains(t, val, "password123")
	assert.Contains(t, val, "[REDACTED]")
}

func TestRedactValue_RedisURL(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("redis_url", "redis://:mypw@cache:6379/0"))
	val := a.Value.String()
	assert.NotContains(t, val, "mypw")
	assert.Contains(t, val, "[REDACTED]")
}

func TestRedactValue_JWTInErrorAttribute(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SsignatureHere123456"
	a := ReplaceAttr(nil, slog.String("error", "auth fail header=Bearer "+jwt))
	val := a.Value.String()
	assert.NotContains(t, val, "eyJ")
	assert.Contains(t, val, "[REDACTED]")
}

func TestRedactValue_OpenAIKey(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("upstream_error", "code: sk-abcdefghijklmnopqrstuvwxyz1234567890"))
	val := a.Value.String()
	assert.NotContains(t, val, "sk-abcdefghijklmnopqrstuvwxyz")
	assert.Contains(t, val, "[REDACTED]")
}

func TestRedactValue_AnthropicKey(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("body", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"))
	val := a.Value.String()
	assert.NotContains(t, val, "sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
	assert.Contains(t, val, "[REDACTED]")
}

func TestRedactValue_BearerInMessageAttribute(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("message", "client sent: Bearer abcdef1234567890abcdef1234567890"))
	val := a.Value.String()
	assert.Contains(t, val, "Bearer [REDACTED]")
	assert.NotContains(t, val, "abcdef1234567890abcdef1234567890")
}

func TestRedactValue_PlainBearerTokenMasked(t *testing.T) {
	a := ReplaceAttr(nil, slog.String("error", "Bearer sk-mykey1234567890abcdefghijklmnop"))
	val := a.Value.String()
	assert.NotContains(t, val, "sk-mykey")
}

func TestRedactGroup_Nested(t *testing.T) {
	grp := slog.Attr{Key: "request", Value: slog.GroupValue(
		slog.String("path", "/v1/chat"),
		slog.String("cookie", "sess=abc"),
		slog.String("model", "gpt-4"),
	)}
	out := ReplaceAttr(nil, grp)
	attrs := out.Value.Group()
	require.Len(t, attrs, 3)
	cookieFound := false
	pathFound := false
	modelFound := false
	for _, a := range attrs {
		switch a.Key {
		case "cookie":
			assert.Equal(t, "[REDACTED]", a.Value.String())
			cookieFound = true
		case "path":
			assert.Equal(t, "/v1/chat", a.Value.String())
			pathFound = true
		case "model":
			assert.Equal(t, "gpt-4", a.Value.String())
			modelFound = true
		}
	}
	assert.True(t, cookieFound && pathFound && modelFound)
}

func TestRedactEndToEnd_NoSecretsInOutput(t *testing.T) {
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: ReplaceAttr,
	}
	logger := slog.New(slog.NewTextHandler(&buf, opts))

	logger.Info("chat request",
		"model", "gpt-4",
		"org_id", "org-123",
		"authorization", "Bearer sk-secret1234567890abcdefg",
		"dsn", "postgres://user:hardcoded_pw@db:5432/app",
	)

	out := buf.String()
	assert.Contains(t, out, "model=gpt-4")
	assert.Contains(t, out, "org_id=org-123")
	assert.NotContains(t, out, "sk-secret1234567890")
	assert.NotContains(t, out, "hardcoded_pw")
	assert.Contains(t, out, "[REDACTED]")
}

func TestRedactEndToEnd_JWTLogged(t *testing.T) {
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: ReplaceAttr,
	}
	logger := slog.New(slog.NewTextHandler(&buf, opts))

	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SsignatureHere123456"
	logger.Error("auth failed", "error", "bad token: "+jwt)

	out := buf.String()
	assert.NotContains(t, out, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0",
		"raw JWT must not appear in log output")
}

// captureStdout runs fn with os.Stdout swapped for a pipe and returns
// whatever the production logger (logging.New binds os.Stdout at
// construction) wrote during the call.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	require.NoError(t, w.Close())
	out := <-done
	_ = r.Close()
	return out
}

// notice — including non-string values.
func TestContentProfileDiagnosticValue(t *testing.T) {
	assert.Equal(t, "boom", ContentProfileDiagnosticValue(config.LogContentProfileLegacy, "boom"))
	assert.Equal(t, 42, ContentProfileDiagnosticValue(config.LogContentProfileLegacy, 42))

	strict := ContentProfileDiagnosticValue(config.LogContentProfileMetadataOnly, "boom")
	assert.Equal(t, ContentProfileRedactedDiagnostic, strict)
	assert.Equal(t, ContentProfileRedactedDiagnostic,
		ContentProfileDiagnosticValue(config.LogContentProfileMetadataOnly, 42))
}

// error/panic/content attribute values regardless of slog value kind, while
// groups recurse instead of being blanket-replaced.
func TestReplaceAttr_ContentProfileStrictLocal(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	sentinel := "upstream exploded: TOP SECRET BODY"

	errStr := ReplaceAttr(nil, slog.String("error", sentinel))
	assert.Equal(t, ContentProfileRedactedDiagnostic, errStr.Value.String())
	assert.NotContains(t, errStr.Value.String(), "TOP SECRET")

	errTyped := ReplaceAttr(nil, slog.Attr{Key: "error", Value: slog.AnyValue(assert.AnError)})
	assert.Equal(t, ContentProfileRedactedDiagnostic, errTyped.Value.String())

	panicAttr := ReplaceAttr(nil, slog.String("panic", sentinel))
	assert.Equal(t, ContentProfileRedactedDiagnostic, panicAttr.Value.String())

	payloadAttr := ReplaceAttr(nil, slog.String("payload", sentinel))
	assert.Equal(t, ContentProfileRedactedDiagnostic, payloadAttr.Value.String())

	upstreamResp := ReplaceAttr(nil, slog.String("upstream_response", sentinel))
	assert.Equal(t, ContentProfileRedactedDiagnostic, upstreamResp.Value.String())

	// A group named "error" is not blanket-replaced: recursion must reach
	// the children (sensitive ones still redacted, plain ones preserved).
	grp := ReplaceAttr(nil, slog.Attr{Key: "error", Value: slog.GroupValue(
		slog.String("op", "insert"),
		slog.String("password", "hunter2"),
		slog.String("detail", sentinel),
	)})
	require.Equal(t, slog.KindGroup, grp.Value.Kind())
	attrs := grp.Value.Group()
	require.Len(t, attrs, 3)
	byKey := map[string]slog.Attr{}
	for _, a := range attrs {
		byKey[a.Key] = a
	}
	assert.Equal(t, "insert", byKey["op"].Value.String())
	assert.Equal(t, "[REDACTED]", byKey["password"].Value.String())
	assert.Equal(t, sentinel, byKey["detail"].Value.String(),
		"only the declared diagnostic keys are replaced; a group recurses")
}

// only pattern-redacted (JWT/DSN/keys), never wholesale replaced.
func TestReplaceAttr_ContentProfileLegacyLocal(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	sentinel := "upstream exploded: TOP SECRET BODY"

	errStr := ReplaceAttr(nil, slog.String("error", sentinel))
	assert.Equal(t, sentinel, errStr.Value.String())

	payloadAttr := ReplaceAttr(nil, slog.String("payload", sentinel))
	assert.Equal(t, sentinel, payloadAttr.Value.String())
}

// The production logger (logging.New) in both formats: with the strict
// process-local declaration the sentinel error text can never appear in the
// output, while safe metadata stays intact.
func TestLoggingNew_ContentProfileStrict_HidesSentinelInBothFormats(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	sentinel := "pgx insert failed: SUPER SECRET ROW"

	for _, format := range []string{"json", "text"} {
		out := captureStdout(t, func() {
			logger := New("info", format)
			logger.Error("process message failed",
				slog.String("stream_id", "1-1"),
				slog.String("error", sentinel),
			)
			logger.Info("request log inserted",
				slog.String("request_id", "req-1"),
				slog.String("error", sentinel),
			)
		})
		require.Contains(t, out, "process message failed", format)
		require.Contains(t, out, "req-1", format)
		assert.NotContains(t, out, "SUPER SECRET", format)
		assert.Contains(t, out, ContentProfileRedactedDiagnostic, format)
	}
}

// The legacy logger keeps full error text (no behavioral change without the
// declaration).
func TestLoggingNew_ContentProfileLegacy_KeepsErrorText(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	sentinel := "pgx insert failed: VISIBLE ROW"

	out := captureStdout(t, func() {
		logger := New("info", "json")
		logger.Error("process message failed",
			slog.String("stream_id", "1-1"),
			slog.String("error", sentinel),
		)
	})
	assert.Contains(t, out, "VISIBLE ROW")
}
