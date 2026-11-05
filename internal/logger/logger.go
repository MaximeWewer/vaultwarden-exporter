// Package logger is the structured logger of the exporter, built on log/slog
// and shared with exporter-toolkit so that every line has the same format.
//
// Logs go to stderr: stdout is reserved for the audit event stream (one JSON
// line per Vaultwarden event), so a log pipeline can tell them apart without
// parsing. The JSON and text handlers escape the values: data coming from the
// database (emails, organization names) cannot forge log lines.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

var (
	level = new(slog.LevelVar)
	log   = newLogger(os.Stderr, "json", "vaultwarden-exporter")
)

// Config holds logger configuration
type Config struct {
	Level     string // debug, info, warn, error
	Format    string // json, console
	Component string // component name for structured logging
}

// InitLogger configures the logger: level, format, standard error output
func InitLogger(cfg Config) error {
	return InitLoggerTo(os.Stderr, cfg)
}

// InitLoggerTo configures the logger to write to w (tests)
func InitLoggerTo(w io.Writer, cfg Config) error {
	level.Set(parseLevel(cfg.Level))
	log = newLogger(w, cfg.Format, cfg.Component)
	return nil
}

func newLogger(w io.Writer, format, component string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "console" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}
	return slog.New(handler).With("component", component)
}

// Slog returns the underlying logger, for libraries such as exporter-toolkit
func Slog() *slog.Logger {
	return log
}

// parseLevel converts a level name, info by default
func parseLevel(name string) slog.Level {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// logAt logs a message of a package with key/value pairs. A disabled level
// returns before building the record.
func logAt(l slog.Level, pkg, message string, args []any) {
	ctx := context.Background()
	if !log.Enabled(ctx, l) {
		return
	}
	log.Log(ctx, l, message, append([]any{"package", pkg}, args...)...)
}

// Debug logs a debug message with key/value pairs
func Debug(pkg, message string, args ...any) {
	logAt(slog.LevelDebug, pkg, message, args)
}

// Info logs an info message with key/value pairs
func Info(pkg, message string, args ...any) {
	logAt(slog.LevelInfo, pkg, message, args)
}

// Warn logs a warning message with key/value pairs
func Warn(pkg, message string, args ...any) {
	logAt(slog.LevelWarn, pkg, message, args)
}

// Error logs an error with key/value pairs
func Error(pkg, message string, err error, args ...any) {
	if err != nil {
		args = append([]any{"error", err.Error()}, args...)
	}
	logAt(slog.LevelError, pkg, message, args)
}

// Startup logs the version and the effective configuration at startup
func Startup(version, commit string, fields map[string]any) {
	args := []any{"version", version, "commit", commit}
	for k, v := range fields {
		args = append(args, k, v)
	}
	logAt(slog.LevelInfo, "main", "Starting vaultwarden-exporter", args)
}

// Shutdown logs the end of the process and its reason
func Shutdown(reason string) {
	logAt(slog.LevelInfo, "main", "Exporter stopped", []any{"reason", reason, "time", time.Now().UTC().Format(time.RFC3339)})
}

// HTTP logs a served request at debug level (scrapes would flood info)
func HTTP(method, path string, status int, duration time.Duration, remote string) {
	logAt(slog.LevelDebug, "server", "HTTP request", []any{"method", method, "path", path, "status", status,
		"duration", duration.String(), "remote", remote})
}
