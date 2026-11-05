// Command vaultwarden-exporter exposes Prometheus metrics computed from the
// Vaultwarden database and streams its audit events as JSON lines.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/maximewewer/vaultwarden-exporter/internal/database"
	"github.com/maximewewer/vaultwarden-exporter/internal/events"
	"github.com/maximewewer/vaultwarden-exporter/internal/logger"
	"github.com/maximewewer/vaultwarden-exporter/internal/server"
	"github.com/maximewewer/vaultwarden-exporter/internal/state"
	"github.com/maximewewer/vaultwarden-exporter/internal/stats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Build information, set with -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=..."
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// shutdownTimeout bounds the graceful shutdown
const shutdownTimeout = 10 * time.Second

func main() {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	code := run(os.Args[1:], sigChan, os.Stdout, os.Stderr)
	signal.Stop(sigChan)
	os.Exit(code)
}

// run starts the exporter and returns the process exit code once a signal or
// a fatal error stops it
func run(args []string, signals <-chan os.Signal, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("vaultwarden-exporter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configFile := flags.String("config", "", "Path to configuration file")
	showVersion := flags.Bool("version", false, "Show version information")
	webConfigFile := flags.String("web.config.file", "", "Path to a Prometheus web configuration file (TLS, basic auth)")
	listenAddress := flags.String("web.listen-address", "", "Address to listen on, e.g. :9776 (overrides server address and port)")
	healthcheck := flags.Bool("healthcheck", false, "Query the local /healthz endpoint and exit (for container health checks)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		_, _ = io.WriteString(stdout, "vaultwarden-exporter version "+version+" (commit "+commit+", built "+buildDate+", "+runtime.Version()+")\n")
		return 0
	}

	cfg, err := loadConfig(*configFile)
	if err == nil {
		err = applyWebFlags(cfg, *webConfigFile, *listenAddress)
	}
	if *healthcheck {
		return runHealthcheck(cfg, err, stderr)
	}
	if err != nil {
		_, _ = io.WriteString(stderr, "Failed to load configuration: "+err.Error()+"\n")
		return 1
	}

	_ = logger.InitLoggerTo(stderr, logger.Config{Level: cfg.Logging.Level, Format: cfg.Logging.Format,
		Component: "vaultwarden-exporter"})
	logger.Startup(version, commit, map[string]any{"build_date": buildDate, "go_version": runtime.Version(),
		"config": cfg.Redacted()})
	for _, warning := range config.Warnings(cfg) {
		logger.Warn("config", warning)
	}

	app, err := build(cfg, stdout)
	if err != nil {
		logger.Error("main", "Startup failed", err)
		return 1
	}
	defer func() { _ = app.db.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan result, len(app.tasks))
	for name, task := range app.tasks {
		go func() { results <- result{name: name, err: task(ctx)} }()
	}

	reason := waitAndShutdown(cancel, signals, results, len(app.tasks), shutdownTimeout)
	logger.Shutdown(reason)
	if reason == "failed" {
		return 1
	}
	return 0
}

// app holds the started components
type app struct {
	db    *database.DB
	tasks map[string]func(context.Context) error
}

// build creates the database handle, the collectors and the HTTP server
func build(cfg *config.Config, stdout io.Writer) (*app, error) {
	db, err := database.Open(cfg.Database.URL, cfg.Database.MaxOpenConns)
	if err != nil {
		return nil, err
	}
	a := &app{db: db, tasks: map[string]func(context.Context) error{}}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "vaultwarden", Subsystem: "exporter",
		Name: "build_info", Help: "Exporter build information."}, []string{"version", "commit", "goversion", "database"})
	buildInfo.WithLabelValues(version, commit, runtime.Version(), db.Dialect.String()).Set(1)
	reg.MustRegister(buildInfo)

	var readiness []func() error

	if cfg.MetricsEnabled() {
		collector, err := stats.New(db, cfg.Database.QueryTimeout, reg)
		if err != nil {
			return nil, err
		}
		reg.MustRegister(collector)
		a.tasks["metrics"] = func(ctx context.Context) error { return collector.Run(ctx, cfg.Metrics.RefreshInterval) }
		readiness = append(readiness, func() error {
			if !collector.Ready() {
				return errors.New("first metrics refresh pending")
			}
			return nil
		})
	}

	if cfg.Events.Enabled {
		store, err := newStore(cfg)
		if err != nil {
			return nil, err
		}
		var sink events.Sink = events.NewWriter(stdout)
		if cfg.Events.Output.Type == config.OutputFile {
			sink = &events.File{Path: cfg.Events.Output.Path}
		}
		poller, err := events.NewPoller(db, cfg.Events, cfg.Database.QueryTimeout, store, sink, reg)
		if err != nil {
			return nil, err
		}
		a.tasks["events"] = poller.Run
		readiness = append(readiness, func() error {
			if !poller.Ready() {
				return errors.New("event state not loaded")
			}
			return nil
		})
	}

	srv := server.New(cfg, reg, func() error {
		for _, ready := range readiness {
			if err := ready(); err != nil {
				return err
			}
		}
		return nil
	})
	a.tasks["server"] = srv.Start
	return a, nil
}

// newStore creates the event state backend
func newStore(cfg *config.Config) (state.Store, error) {
	switch cfg.Events.State.Backend {
	case config.StateKubernetes:
		return state.NewKubernetes(cfg.Events.State.ConfigMap, cfg.Events.State.Namespace,
			map[string]string{"app.kubernetes.io/name": "vaultwarden-exporter"})
	case config.StateMemory:
		return &state.Memory{}, nil
	default:
		return &state.File{Path: cfg.Events.State.Path}, nil
	}
}

type result struct {
	name string
	err  error
}

// waitAndShutdown waits for a signal or for the end of a task, then cancels
// the context and waits for every task to stop. A second signal, or the
// timeout, ends the wait. It returns the shutdown reason.
func waitAndShutdown(cancel context.CancelFunc, signals <-chan os.Signal, results <-chan result, tasks int,
	timeout time.Duration) string {
	reason := "graceful"
	select {
	case sig := <-signals:
		logger.Info("main", "Received shutdown signal", "signal", sig.String())
	case r := <-results:
		tasks--
		if r.err != nil {
			logger.Error("main", "Task failed", r.err, "task", r.name)
			reason = "failed"
		} else {
			logger.Warn("main", "Task stopped", "task", r.name)
		}
	}

	cancel()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for ; tasks > 0; tasks-- {
		select {
		case r := <-results:
			if r.err != nil && !errors.Is(r.err, context.Canceled) {
				logger.Error("main", "Task error during shutdown", r.err, "task", r.name)
			}
		case sig := <-signals:
			logger.Warn("main", "Second signal, forcing shutdown", "signal", sig.String())
			return "forced"
		case <-deadline.C:
			logger.Warn("main", "Shutdown timed out")
			return "timeout"
		}
	}
	return reason
}

// loadConfig loads the YAML file when given, environment variables otherwise
func loadConfig(configFile string) (*config.Config, error) {
	if configFile != "" {
		return config.LoadFromYamlWithEnvOverrides(configFile)
	}
	return config.LoadFromEnvVarsOnly()
}

// applyWebFlags applies the standard Prometheus exporter web flags, which take
// precedence over the configuration file and environment variables
func applyWebFlags(cfg *config.Config, webConfigFile, listenAddress string) error {
	if webConfigFile != "" {
		cfg.Server.WebConfigFile = webConfigFile
	}
	if listenAddress != "" {
		host, port, err := net.SplitHostPort(listenAddress)
		if err != nil {
			return fmt.Errorf("invalid --web.listen-address %q: %w", listenAddress, err)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port in --web.listen-address %q", listenAddress)
		}
		if host == "" {
			host = "0.0.0.0"
		}
		cfg.Server.Address, cfg.Server.Port = host, p
	}
	return nil
}

// runHealthcheck queries the liveness endpoint of the local exporter and
// returns the process exit code. Distroless images have no shell nor wget, so
// container health checks run the exporter binary itself.
func runHealthcheck(cfg *config.Config, cfgErr error, stderr io.Writer) int {
	if cfgErr != nil {
		_, _ = io.WriteString(stderr, "healthcheck: invalid configuration: "+cfgErr.Error()+"\n")
		return 1
	}
	host := cfg.Server.Address
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	hostPort := net.JoinHostPort(host, strconv.Itoa(cfg.Server.Port))
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // loopback health check
	}
	schemes := []string{"http"}
	if cfg.Server.WebConfigFile != "" {
		schemes = []string{"https", "http"}
	}
	var lastErr string
	for _, scheme := range schemes {
		url := scheme + "://" + hostPort + "/healthz"
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		_ = resp.Body.Close()
		// 401 means basic auth is enabled: the exporter is alive
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
			return 0
		}
		lastErr = url + " returned " + resp.Status
	}
	_, _ = io.WriteString(stderr, "healthcheck: "+lastErr+"\n")
	return 1
}
