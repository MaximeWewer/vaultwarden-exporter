package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "WARN": slog.LevelWarn, "warning": slog.LevelWarn,
		"error": slog.LevelError, "info": slog.LevelInfo, "": slog.LevelInfo, "bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		assert.Equal(t, want, parseLevel(in), in)
	}
}

func TestJSONOutputAndLevels(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, InitLoggerTo(&buf, Config{Level: "info", Format: "json", Component: "test"}))

	Debug("pkg", "hidden")
	Info("pkg", "hello", "key", "value")
	Warn("pkg", "careful")
	Error("pkg", "failed", errors.New("boom"), "query", "users")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 3, "debug must be filtered at info level")

	var first map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	assert.Equal(t, "hello", first["msg"])
	assert.Equal(t, "pkg", first["package"])
	assert.Equal(t, "test", first["component"])
	assert.Equal(t, "value", first["key"])

	var last map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[2]), &last))
	assert.Equal(t, "boom", last["error"])
	assert.Equal(t, "ERROR", last["level"])
}

func TestConsoleFormatAndLifecycle(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, InitLoggerTo(&buf, Config{Level: "debug", Format: "console", Component: "test"}))
	Startup("1.0.0", "abc", map[string]any{"go": "go1"})
	Shutdown("graceful")
	Debug("pkg", "visible")
	out := buf.String()
	assert.Contains(t, out, "Starting vaultwarden-exporter")
	assert.Contains(t, out, "reason=graceful")
	assert.Contains(t, out, "visible")
	assert.NotNil(t, Slog())
}
