package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Validate checks the configuration after the defaults are applied. Every
// problem is reported at once.
func Validate(cfg *Config) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if strings.TrimSpace(cfg.Database.URL) == "" {
		add("database.url is required (or database.url_file, VAULTWARDEN_EXPORTER_DATABASE_URL, DATABASE_URL)")
	}
	if cfg.Database.MaxOpenConns < 1 {
		add("database.max_open_conns must be >= 1")
	}
	if cfg.Database.QueryTimeout <= 0 {
		add("database.query_timeout must be > 0")
	}

	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		add("server.port must be between 1 and 65535")
	}
	if cfg.Server.ReadTimeout <= 0 || cfg.Server.WriteTimeout <= 0 {
		add("server.read_timeout and server.write_timeout must be > 0")
	}

	if !slices.Contains([]string{"debug", "info", "warn", "warning", "error"}, strings.ToLower(cfg.Logging.Level)) {
		add("logging.level must be debug, info, warn or error")
	}
	if cfg.Logging.Format != "json" && cfg.Logging.Format != "console" {
		add("logging.format must be json or console")
	}

	if !cfg.MetricsEnabled() && !cfg.Events.Enabled {
		add("nothing to do: enable metrics.enabled and/or events.enabled")
	}
	if cfg.Metrics.RefreshInterval <= 0 {
		add("metrics.refresh_interval must be > 0")
	}

	if cfg.Events.Enabled {
		validateEvents(&cfg.Events, add)
	}

	return errors.Join(errs...)
}

func validateEvents(ev *EventsConfig, add func(string, ...any)) {
	if ev.PollInterval <= 0 {
		add("events.poll_interval must be > 0")
	}
	if ev.BatchSize < 1 || ev.BatchSize > 10000 {
		add("events.batch_size must be between 1 and 10000")
	}
	if ev.LateWindow < 0 {
		add("events.late_window must be >= 0")
	}
	if ev.StartFrom != StartNow && ev.StartFrom != StartBeginning {
		add("events.start_from must be %q or %q", StartNow, StartBeginning)
	}

	switch ev.Output.Type {
	case OutputStdout:
	case OutputFile:
		if ev.Output.Path == "" {
			add("events.output.path is required with events.output.type=file")
		}
	default:
		add("events.output.type must be %q or %q", OutputStdout, OutputFile)
	}

	switch ev.State.Backend {
	case StateFile:
		if ev.State.Path == "" {
			add("events.state.path is required with events.state.backend=file")
		}
	case StateKubernetes:
		if ev.State.ConfigMap == "" {
			add("events.state.configmap is required with events.state.backend=kubernetes")
		}
	case StateMemory:
	default:
		add("events.state.backend must be %q, %q or %q", StateFile, StateKubernetes, StateMemory)
	}

	if len(ev.Filter.Include) > 0 && len(ev.Filter.Exclude) > 0 {
		add("events.filter.include and events.filter.exclude are mutually exclusive")
	}
	if ev.Filter.OrgCopies != "all" && ev.Filter.OrgCopies != "none" {
		add("events.filter.org_copies must be all or none")
	}
}

// Warnings returns non-fatal configuration remarks, logged at startup
func Warnings(cfg *Config) []string {
	var out []string
	if cfg.Events.Enabled && cfg.Events.State.Backend == StateMemory {
		out = append(out, "events.state.backend=memory: the cursor is lost on restart, events are re-read from events.start_from")
	}
	if cfg.Events.Enabled && cfg.Events.LateWindow == 0 {
		out = append(out, "events.late_window=0: events stored late with an older timestamp (client uploads) are missed")
	}
	return out
}
