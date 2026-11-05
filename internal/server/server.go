// Package server exposes /metrics, /healthz and /readyz over HTTP, with the
// standard Prometheus web configuration (TLS, basic auth) of exporter-toolkit.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/maximewewer/vaultwarden-exporter/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/exporter-toolkit/web"
)

// ReadinessFunc returns nil when the exporter is ready (first refresh done,
// event state loaded)
type ReadinessFunc func() error

// Server is the HTTP server
type Server struct {
	config    *config.Config
	registry  *prometheus.Registry
	readiness ReadinessFunc
	server    *http.Server
}

// New creates the HTTP server
func New(cfg *config.Config, registry *prometheus.Registry, readiness ReadinessFunc) *Server {
	return &Server{config: cfg, registry: registry, readiness: readiness}
}

// Handler returns the HTTP handler with every route and middleware
func (s *Server) Handler() http.Handler {
	metrics := promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
		ErrorLog:          &loggerAdapter{},
		ErrorHandling:     promhttp.ContinueOnError,
		EnableOpenMetrics: true,
	})
	mux := http.NewServeMux()
	if s.config.MetricsEnabled() || s.config.Events.Enabled {
		mux.Handle("/metrics", metrics)
	}
	mux.HandleFunc("/healthz", s.liveness)
	mux.HandleFunc("/readyz", s.readinessHandler)
	mux.HandleFunc("/", s.index)
	return withMiddleware(mux)
}

func (s *Server) liveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

func (s *Server) readinessHandler(w http.ResponseWriter, _ *http.Request) {
	if s.readiness != nil {
		if err := s.readiness(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "reason": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

var indexTemplate = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head><title>Vaultwarden Exporter</title></head>
<body>
<h1>Vaultwarden Exporter</h1>
<ul>
<li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
<li><a href="/healthz">/healthz</a> - Liveness</li>
<li><a href="/readyz">/readyz</a> - Readiness</li>
</ul>
<p>Metrics: {{if .MetricsEnabled}}refreshed every {{.Metrics.RefreshInterval}}{{else}}disabled{{end}}.
Audit events: {{if .Events.Enabled}}polled every {{.Events.PollInterval}} to {{.Events.Output.Type}}{{else}}disabled{{end}}.</p>
</body>
</html>
`))

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(w, s.config); err != nil {
		logger.Error("server", "Failed to render index", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Start serves until ctx is cancelled
func (s *Server) Start(ctx context.Context) error {
	addr := net.JoinHostPort(s.config.Server.Address, strconv.Itoa(s.config.Server.Port))
	s.server = &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadTimeout:       s.config.Server.ReadTimeout,
		ReadHeaderTimeout: s.config.Server.ReadTimeout,
		WriteTimeout:      s.config.Server.WriteTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	errChan := make(chan error, 1)
	listen := []string{addr}
	systemd := false
	webConfig := s.config.Server.WebConfigFile
	flags := &web.FlagConfig{WebListenAddresses: &listen, WebSystemdSocket: &systemd, WebConfigFile: &webConfig}
	go func() { errChan <- web.ListenAndServe(s.server, flags, logger.Slog().With("package", "server")) }()

	select {
	case <-ctx.Done():
		logger.Info("server", "Shutting down HTTP server")
		return s.Shutdown(context.Background())
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server failed on %s: %w", addr, err)
		}
		return nil
	}
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}
	logger.Info("server", "HTTP server stopped")
	return nil
}

// withMiddleware wraps the handler with request logging and panic recovery
func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("server", "Panic recovered", nil, "panic", fmt.Sprint(rec), "path", r.URL.Path)
				rw.WriteHeader(http.StatusInternalServerError)
			}
			logger.HTTP(r.Method, r.URL.Path, rw.statusCode, time.Since(start), r.RemoteAddr)
		}()
		next.ServeHTTP(rw, r)
	})
}

// responseWriter captures the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// loggerAdapter routes promhttp errors to the exporter logger
type loggerAdapter struct{}

func (loggerAdapter) Println(v ...any) {
	logger.Error("server", "Metrics handler error", nil, "detail", fmt.Sprint(v...))
}
