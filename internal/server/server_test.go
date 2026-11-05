package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() *config.Config {
	cfg := &config.Config{Database: config.DatabaseConfig{URL: "x"}}
	config.ApplyDefaults(cfg)
	return cfg
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestRoutes(t *testing.T) {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "vaultwarden_test", Help: "test"})
	reg.MustRegister(g)
	ready := errors.New("first refresh pending")
	s := New(testConfig(), reg, func() error { return ready })
	h := s.Handler()

	code, body := get(t, h, "/metrics")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "vaultwarden_test 0")

	code, body = get(t, h, "/healthz")
	assert.Equal(t, http.StatusOK, code)
	assert.JSONEq(t, `{"status":"alive"}`, body)

	code, body = get(t, h, "/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.JSONEq(t, `{"status":"not ready","reason":"first refresh pending"}`, body)
	ready = nil
	code, _ = get(t, h, "/readyz")
	assert.Equal(t, http.StatusOK, code)

	code, body = get(t, h, "/")
	assert.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "refreshed every 1m0s")
	assert.Contains(t, body, "Audit events: disabled")

	code, _ = get(t, h, "/nope")
	assert.Equal(t, http.StatusNotFound, code)
}

func TestPanicRecovery(t *testing.T) {
	h := withMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	code, _ := get(t, h, "/")
	assert.Equal(t, http.StatusInternalServerError, code)
	loggerAdapter{}.Println("covered")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestStartAndShutdown(t *testing.T) {
	cfg := testConfig()
	cfg.Server.Address = "127.0.0.1"
	cfg.Server.Port = freePort(t)
	s := New(cfg, prometheus.NewRegistry(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- s.Start(ctx) }()

	url := "http://127.0.0.1:" + strconv.Itoa(cfg.Server.Port) + "/healthz"
	require.Eventually(t, func() bool {
		resp, err := http.Get(url) //nolint:noctx // test
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.Contains(string(b), "alive")
	}, 3*time.Second, 20*time.Millisecond)

	cancel()
	require.NoError(t, <-done)
	require.NoError(t, (&Server{}).Shutdown(context.Background()))
}

func TestStartFailsOnBusyPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	cfg := testConfig()
	cfg.Server.Address = "127.0.0.1"
	cfg.Server.Port = l.Addr().(*net.TCPAddr).Port
	err = New(cfg, prometheus.NewRegistry(), nil).Start(context.Background())
	assert.Error(t, err)
}
