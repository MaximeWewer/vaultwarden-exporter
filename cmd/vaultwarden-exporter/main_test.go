package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/maximewewer/vaultwarden-exporter/internal/vwtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSyslogOutput(t *testing.T) {
	db := vwtest.New(t)
	db.InsertEvent(t, vwtest.Event{UUID: vwtest.UUID(1), Type: 1005, Date: time.Now().Add(-time.Minute)})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	metrics := false
	cfg := &config.Config{Database: config.DatabaseConfig{URL: "sqlite://" + dbPath(t, db)}}
	cfg.Metrics.Enabled = &metrics
	cfg.Events.Enabled = true
	cfg.Events.StartFrom = config.StartBeginning
	cfg.Events.State.Backend = config.StateMemory
	cfg.Events.Output.Type = config.OutputSyslog
	cfg.Events.Output.Syslog.Address = listener.Addr().String()
	config.ApplyDefaults(cfg)
	require.NoError(t, config.Validate(cfg))
	var stdout bytes.Buffer
	app, err := build(cfg, &stdout)
	require.NoError(t, err)
	defer app.db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.tasks["events"](ctx) }()
	require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(3*time.Second)))
	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())
	assert.Contains(t, scanner.Text(), `vaultwarden-exporter: {"source":"vaultwarden"`)
	assert.Contains(t, scanner.Text(), `"event_name":"UserFailedLogIn"`)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("event task did not stop")
	}
	assert.Empty(t, stdout.String(), "syslog events must not also go to stdout")
}

// syncBuffer is a goroutine-safe buffer (the exporter writes while the test reads)
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestVersionAndFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"--version"}, nil, &out, &errOut))
	assert.Contains(t, out.String(), "vaultwarden-exporter version dev")
	assert.Equal(t, 0, run([]string{"-h"}, nil, &out, &errOut))
	assert.Equal(t, 2, run([]string{"--bogus"}, nil, &out, &errOut))
}

func TestInvalidConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var out, errOut bytes.Buffer
	assert.Equal(t, 1, run(nil, nil, &out, &errOut))
	assert.Contains(t, errOut.String(), "database.url is required")

	t.Setenv("DATABASE_URL", "redis://x")
	errOut.Reset()
	assert.Equal(t, 1, run(nil, nil, &out, &errOut), "unsupported scheme fails at startup")

	t.Setenv("DATABASE_URL", "postgresql://db/vw")
	assert.Equal(t, 1, run([]string{"--web.listen-address", "nope"}, nil, &out, &errOut))
	assert.Equal(t, 1, run([]string{"--config", "/does/not/exist.yaml"}, nil, &out, &errOut))
}

func TestApplyWebFlags(t *testing.T) {
	cfg := &config.Config{}
	require.NoError(t, applyWebFlags(cfg, "/etc/web.yml", ":9100"))
	assert.Equal(t, "0.0.0.0", cfg.Server.Address)
	assert.Equal(t, 9100, cfg.Server.Port)
	assert.Equal(t, "/etc/web.yml", cfg.Server.WebConfigFile)
	require.NoError(t, applyWebFlags(cfg, "", "127.0.0.1:9200"))
	assert.Equal(t, "127.0.0.1", cfg.Server.Address)
	assert.Error(t, applyWebFlags(cfg, "", "127.0.0.1:99999"))
}

func TestFullRunMetricsEventsAndHealthcheck(t *testing.T) {
	db := vwtest.New(t)
	db.Exec(t, `INSERT INTO users (uuid, email, name) VALUES ('u1', 'alice@example.com', 'Alice')`)
	db.InsertEvent(t, vwtest.Event{UUID: vwtest.UUID(1), Type: 1005, User: "u1", Actor: "u1", Device: 9,
		Date: time.Now().Add(-time.Minute)})

	port := freePort(t)
	dir := t.TempDir()
	cfgFile := dir + "/config.yaml"
	require.NoError(t, os.WriteFile(cfgFile, []byte(`
server:
  address: 127.0.0.1
metrics:
  refresh_interval: 1s
events:
  enabled: true
  poll_interval: 100ms
  start_from: beginning
  state:
    backend: file
    path: `+dir+`/state.json
`), 0o600))
	t.Setenv("DATABASE_URL", "sqlite://"+dbPath(t, db))
	t.Setenv("VAULTWARDEN_EXPORTER_PORT", strconv.Itoa(port))

	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	signals := make(chan os.Signal, 2)
	done := make(chan int)
	go func() { done <- run([]string{"--config", cfgFile}, signals, stdout, stderr) }()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	require.Eventually(t, func() bool { return status(base+"/readyz") == http.StatusOK }, 5*time.Second, 50*time.Millisecond,
		"stderr: %s", stderr.String())
	require.Eventually(t, func() bool { return strings.Contains(stdout.String(), `"event_name":"UserFailedLogIn"`) },
		5*time.Second, 50*time.Millisecond)
	assert.NotContains(t, stdout.String(), `"level"`, "logs never go to stdout")

	body := fetch(t, base+"/metrics")
	assert.Contains(t, body, `vaultwarden_users{email_verified="false",enabled="true"} 1`)
	assert.Contains(t, body, `vaultwarden_audit_events_total{event_name="UserFailedLogIn"} 1`)
	assert.Contains(t, body, `vaultwarden_exporter_build_info{commit="unknown",database="sqlite"`)

	var hcErr bytes.Buffer
	assert.Equal(t, 0, run([]string{"--config", cfgFile, "--healthcheck"}, nil, io.Discard, &hcErr), hcErr.String())

	signals <- syscall.SIGTERM
	select {
	case code := <-done:
		assert.Equal(t, 0, code)
	case <-time.After(10 * time.Second):
		t.Fatal("exporter did not stop")
	}
	assert.Contains(t, stderr.String(), `"reason":"graceful"`)
	assert.FileExists(t, dir+"/state.json")

	// The exporter is stopped: the health check fails
	hcErr.Reset()
	assert.Equal(t, 1, run([]string{"--config", cfgFile, "--healthcheck"}, nil, io.Discard, &hcErr))
}

func TestHealthcheckInvalidConfig(t *testing.T) {
	var errOut bytes.Buffer
	assert.Equal(t, 1, runHealthcheck(nil, errors.New("bad"), &errOut))
	assert.Contains(t, errOut.String(), "invalid configuration")
}

func TestWaitAndShutdown(t *testing.T) {
	cancelled := false
	cancel := func() { cancelled = true }

	results := make(chan result, 2)
	results <- result{name: "server", err: errors.New("bind failed")}
	results <- result{name: "metrics"}
	assert.Equal(t, "failed", waitAndShutdown(cancel, nil, results, 2, time.Second))
	assert.True(t, cancelled)

	signals := make(chan os.Signal, 2)
	signals <- syscall.SIGTERM
	signals <- syscall.SIGINT
	assert.Equal(t, "forced", waitAndShutdown(func() {}, signals, make(chan result), 1, time.Second))

	signals <- syscall.SIGTERM
	assert.Equal(t, "timeout", waitAndShutdown(func() {}, signals, make(chan result), 1, 10*time.Millisecond))
}

func dbPath(t *testing.T, db *vwtest.DB) string {
	t.Helper()
	var path string
	require.NoError(t, db.W.QueryRowContext(context.Background(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path))
	return path
}

func status(url string) int {
	resp, err := http.Get(url) //nolint:gosec,noctx // test
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func fetch(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // test
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}
