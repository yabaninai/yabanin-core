// Package logging provides the single canonical slog constructor for all
// services. It merges the former pkg/log (level + redaction) and the former
// pkg/logging (format selection) into one logger so no service mixes two
// differently-configured sloggers.
package logging

import (
	"log/slog"
	"os"

	"github.com/reireirei/yabanin/pkg/config"
)

// New returns a *slog.Logger writing to stdout. The level ("debug", "warn",
// "error"; anything else = info) and format ("json" or text) are both applied,
// and sensitive attributes (passwords, tokens, JWTs, DSNs) are automatically
// redacted via ReplaceAttr regardless of format. The LOG_FORMAT environment
// variable overrides the provided format when set to "json" or "text".
func New(level, format string) *slog.Logger {
	if env, ok := config.LogFormatOverride(); ok {
		switch env {
		case "json":
			format = "json"
		case "text":
			format = "text"
		}
	}

	opts := &slog.HandlerOptions{
		Level:       parseLevel(level),
		ReplaceAttr: ReplaceAttr,
	}

	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(os.Stdout, opts)
	default:
		h = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(h)
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
